package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netcasklabs/porymcp/internal/audit"
	"github.com/netcasklabs/porymcp/internal/auth"
	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
	"github.com/netcasklabs/porymcp/internal/webutil"
)

// The tool policy itself is tested against the proxy handler in
// internal/proxy. What these tests are for is the sentence the acceptance
// criterion actually asks for: a blocked call must be "verifiable via GET
// /api/v1/logs?status=blocked". That is not the store — it is api.listLogs
// reading the status query parameter into models.LogFilter, the store turning
// it into `status = ?`, and the whole thing sitting behind admin auth on the
// router main mounts. Asserting the row with st.ListAuditLogs would exercise
// none of it, so these tests go in through newRouter and read the row back
// over HTTP, exactly as an operator would.
//
// Every case also asserts that the stub upstream saw zero requests. A refusal
// that still contacted the upstream would have presented the real credential
// and may already have run the tool, so "blocked" in the log would be a claim
// the traffic contradicts — the hit counter is what makes the row mean what it
// says. Not even a tools/list is allowed out: the gate decides before any
// routing happens, which is also what keeps a denied name and an unknown name
// from being distinguishable by how long the answer took.

// blockStub is a stub MCP upstream that counts every request it is asked to
// serve, whether or not the proxy should have sent it.
type blockStub struct {
	srv  *httptest.Server
	hits atomic.Int32
}

func newBlockStub(t *testing.T) *blockStub {
	t.Helper()
	s := &blockStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		// Lenient on purpose: a body this stub cannot parse is still a
		// request that reached it, and the count above has already recorded it.
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "tools/list" {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"},{"name":"list_issues"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// blockFixture is the router that ships, wired to a real store, the real
// (asynchronous) audit logger and one stub upstream, plus the plaintext
// virtual key a client would send.
type blockFixture struct {
	router http.Handler
	stub   *blockStub
	keyID  string
	key    string // plaintext virtual key, returned only at creation in production
}

// denyDeleteRepo is the group tool_filter the aggregate-endpoint tests use. The
// entry is unscoped, and one unscoped deny entry is now the whole rule: it is
// matched against the tool's own name, so it bites on /{keyID}/mcp — where the
// client writes gh__delete_repo — and on /{keyID}/gh/mcp — where it writes
// delete_repo — alike. The filter stays a parameter of the fixture so a test
// can hand it the scoped spelling instead and show the two forms agree.
const denyDeleteRepo = `{"mode":"deny","tools":["delete_repo"]}`

// newBlockFixture seeds one upstream (id u1, slug gh) and one virtual key
// (id k1) that denies delete_repo. targetType picks which rule does the
// denying: models.TargetGroup puts toolFilter on the group, models.TargetUpstream
// puts delete_repo on the key's own denylist and ignores toolFilter, since it
// creates no group. Both end at the same gate; the audit row is where the two
// are told apart.
//
// The key's denylist is deliberately the bare name. A key bound to a single
// upstream serves that upstream's own tool names, so an unscoped entry names
// the tool exactly — the identity grammar asks nothing more of it, and the
// scoped spelling gh__delete_repo would work just as well.
func newBlockFixture(t *testing.T, targetType, toolFilter string) *blockFixture {
	t.Helper()
	stub := newBlockStub(t)

	encKey, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// The same cfg shape TestRouterTopology uses. PublicURL is what the
	// proxy's host check compares the request Host against, so every request
	// below is made to http://localhost:8080/... rather than to a bare path.
	cfg := &config.Config{AdminAPIKey: "test-admin", EncryptionKey: encKey, PublicURL: "http://localhost:8080"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	t.Cleanup(auditor.Close) // LIFO: the audit logger stops before the store closes

	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "u1", Name: "GitHub", Slug: "gh", URL: stub.srv.URL,
		Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	targetID := "u1"
	var deny []string
	if targetType == models.TargetGroup {
		if err := st.CreateGroup(ctx, &models.Group{
			ID: "g1", Name: "grp", UpstreamIDs: []string{"u1"},
			ToolFilter: json.RawMessage(toolFilter),
			CreatedAt:  now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		targetID = "g1"
	} else {
		deny = []string{"delete_repo"}
	}

	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "k1", Name: "bot", KeyHash: hash, KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: targetType, TargetID: targetID, ToolDenylist: deny, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	return &blockFixture{
		router: newRouter(cfg, st, auditor, log, nil, webutil.EncryptionOK),
		stub:   stub,
		keyID:  "k1",
		key:    plain,
	}
}

// call posts one JSON-RPC request to the per-key aggregate endpoint.
func (f *blockFixture) call(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.post(t, "/"+f.keyID+"/mcp", body)
}

// callMember posts one JSON-RPC request to the endpoint of one group member,
// /{keyID}/{slug}/mcp. slug is passed through unaltered so a test can aim at a
// member that does not exist.
func (f *blockFixture) callMember(t *testing.T, slug, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.post(t, "/"+f.keyID+"/"+slug+"/mcp", body)
}

// post is the one place a client request is built, so the aggregate and the
// member endpoint are exercised by requests that differ in nothing but the
// path — which is the whole claim the member tests make.
func (f *blockFixture) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.key)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// queryLogs runs one GET /api/v1/logs?<query>. admin is the bearer token, or
// "" to send none.
func (f *blockFixture) queryLogs(t *testing.T, query, admin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/v1/logs?"+query, nil)
	if admin != "" {
		req.Header.Set("Authorization", "Bearer "+admin)
	}
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// decodeLogs reads the list envelope api.listLogs writes. The field is "logs";
// renaming it should break this test rather than quietly return nothing.
func decodeLogs(t *testing.T, rr *httptest.ResponseRecorder) []models.AuditLog {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/logs: status %d, body %s", rr.Code, rr.Body.String())
	}
	var env struct {
		Logs []models.AuditLog `json:"logs"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("GET /api/v1/logs: body %s is not the list envelope: %v", rr.Body.String(), err)
	}
	return env.Logs
}

// waitBlocked polls GET /api/v1/logs?status=blocked until it returns want rows
// or two seconds pass. The audit logger writes on its own goroutine —
// audit.Logger.Record is non-blocking and Close gives the caller no way to
// wait for the drain (PORM-36) — so the row a request just produced is not
// readable the instant its response comes back.
func (f *blockFixture) waitBlocked(t *testing.T, want int) []models.AuditLog {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows := decodeLogs(t, f.queryLogs(t, "status=blocked", "test-admin"))
		if len(rows) >= want || time.Now().After(deadline) {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertBlocked pins the client-facing half of a refusal: the call failed, the
// transport did not, the id came back so the client can match the reply, and
// the upstream was never contacted.
func assertBlocked(t *testing.T, f *blockFixture, rr *httptest.ResponseRecorder, wantID string) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`"code":-32602`, `"tool blocked"`, wantID} {
		if !strings.Contains(body, want) {
			t.Errorf("body %s lacks %s", body, want)
		}
	}
	if n := f.stub.hits.Load(); n != 0 {
		t.Fatalf("the upstream served %d requests; a blocked call must never present the real credential, not even for a tools/list", n)
	}
}

// assertBlockedRow pins every field an operator reads off the row the logs API
// returned. wantTool is a parameter because the row records the name the client
// actually sent, which differs by endpoint: gh__delete_repo on the aggregate,
// delete_repo on the member URL and on a single-upstream key.
func assertBlockedRow(t *testing.T, row models.AuditLog, wantTool, wantReason, wantUpstream, wantKeyID string) {
	t.Helper()
	if row.Status != models.StatusBlocked {
		t.Errorf("status=%q want %q", row.Status, models.StatusBlocked)
	}
	if row.Method != "tools/call" {
		t.Errorf("method=%q want tools/call — the JSON-RPC method, not the HTTP verb", row.Method)
	}
	if row.ToolName != wantTool {
		t.Errorf("tool_name=%q want %q", row.ToolName, wantTool)
	}
	// The client is told only "tool blocked"; the row says which rule to edit.
	if row.ErrorMessage != wantReason {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, wantReason)
	}
	if row.UpstreamID != wantUpstream {
		t.Errorf("upstream_id=%q want %q", row.UpstreamID, wantUpstream)
	}
	if row.VirtualKeyID != wantKeyID {
		t.Errorf("virtual_key_id=%q want %q", row.VirtualKeyID, wantKeyID)
	}
}

// AC4, as written: a group tool_filter block is queryable through the logs API.
func TestBlockedCallIsQueryableViaLogsAPI(t *testing.T) {
	f := newBlockFixture(t, models.TargetGroup, denyDeleteRepo)

	// gh__delete_repo, not delete_repo: the aggregate endpoint advertises the
	// identity and answers a bare name with -32602 before any rule is consulted,
	// so a bare name here would exercise the unknown-tool refusal instead of the
	// block this test is about.
	rr := f.call(t, `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"gh__delete_repo","arguments":{}}}`)
	assertBlocked(t, f, rr, `"id":41`)

	rows := f.waitBlocked(t, 1)
	if len(rows) != 1 {
		t.Fatalf("GET /api/v1/logs?status=blocked returned %d rows, want 1: %+v", len(rows), rows)
	}
	// upstream_id is empty because a group block happens before routing: no
	// member was contacted, so there is no upstream to name.
	assertBlockedRow(t, rows[0], "gh__delete_repo", "blocked by group tool_filter", "", f.keyID)

	t.Run("the logs API still needs the admin key", func(t *testing.T) {
		rr := f.queryLogs(t, "status=blocked", "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401; body %s", rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "delete_repo") {
			t.Error("the unauthenticated response leaked the row it refused to serve")
		}
	})

	t.Run("a block is not a success", func(t *testing.T) {
		// The status filter has to discriminate, or ?status=blocked would be a
		// filter that returns everything and proves nothing.
		if rows := decodeLogs(t, f.queryLogs(t, "status=success", "test-admin")); len(rows) != 0 {
			t.Fatalf("?status=success returned %d rows: %+v", len(rows), rows)
		}
	})
}

// The same read path for a key bound straight to an upstream, where the key's
// own denylist does the refusing. Here the upstream is known without contacting
// anything, so the row names it — which is what lets an operator filter blocks
// per upstream.
func TestBlockedSingleUpstreamCallRecordsUpstreamID(t *testing.T) {
	// No group is created for an upstream target, so there is no tool_filter
	// to seed: the key's own denylist is the whole policy.
	f := newBlockFixture(t, models.TargetUpstream, "")

	rr := f.call(t, `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`)
	assertBlocked(t, f, rr, `"id":42`)

	rows := f.waitBlocked(t, 1)
	if len(rows) != 1 {
		t.Fatalf("GET /api/v1/logs?status=blocked returned %d rows, want 1: %+v", len(rows), rows)
	}
	assertBlockedRow(t, rows[0], "delete_repo", "blocked by virtual key denylist", "u1", f.keyID)

	// Control, and it runs last so it cannot disturb the assertions above: a
	// tool no rule names must reach the upstream. Without it, "zero upstream
	// requests" would also pass against a fixture whose upstream was never
	// reachable in the first place.
	allowed := f.call(t, `{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"ok":true`) {
		t.Fatalf("permitted call: status %d, body %s", allowed.Code, allowed.Body.String())
	}
	if n := f.stub.hits.Load(); n != 1 {
		t.Fatalf("the upstream served %d requests, want exactly the one permitted call", n)
	}
}

// The same read path again, this time over /{keyID}/{slug}/mcp, and with the
// scoped spelling of the rule as the contrast to denyDeleteRepo's unscoped one:
// gh__delete_repo names one tool on one member, and the client here writes the
// bare delete_repo the member endpoint advertises. Both spellings reach the same
// verdict on this call, which is the point — the entry is matched against the
// identity, not against the string the client happened to type.
//
// The row is what separates this from the aggregate case: it names the
// upstream, because the URL said which upstream the call was aimed at before
// any policy ran. That is what lets an operator filter blocks per upstream on
// the endpoint shape groups are meant to be used through.
func TestBlockedMemberCallRecordsUpstreamID(t *testing.T) {
	f := newBlockFixture(t, models.TargetGroup, `{"mode":"deny","tools":["gh__delete_repo"]}`)

	rr := f.callMember(t, "gh", `{"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`)
	assertBlocked(t, f, rr, `"id":44`)

	rows := f.waitBlocked(t, 1)
	if len(rows) != 1 {
		t.Fatalf("GET /api/v1/logs?status=blocked returned %d rows, want 1: %+v", len(rows), rows)
	}
	// u1, not "". A block on the aggregate endpoint happens before routing has
	// picked a member, so there is no upstream to name; a member endpoint was
	// told which one in the URL, and the row has to say so or the two shapes
	// of the same key are not comparable in the log.
	assertBlockedRow(t, rows[0], "delete_repo", "blocked by group tool_filter", "u1", f.keyID)

	// Control, and it runs last so it cannot disturb the assertions above: a
	// tool the filter does not name reaches the upstream through the very same
	// endpoint. Without it, "zero upstream requests" would also pass against a
	// member endpoint that was never reachable at all.
	allowed := f.callMember(t, "gh", `{"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"ok":true`) {
		t.Fatalf("permitted call: status %d, body %s", allowed.Code, allowed.Body.String())
	}
	if n := f.stub.hits.Load(); n != 1 {
		t.Fatalf("the upstream served %d requests, want exactly the one permitted call", n)
	}
}

// A slug this key's group does not carry is a 404, and it is audited as
// blocked like every other refusal on the route — one status, so an operator
// reading ?status=blocked sees the policy blocks and the calls aimed at
// endpoints that are not there in the same place. The split is deliberate: the
// client is told only "unknown endpoint" and never which of the misses it was,
// while the row names the slug, so a valid key cannot use the route to find
// out which slugs the deployment has.
func TestUnknownMemberEndpointIsAuditedAsBlocked(t *testing.T) {
	f := newBlockFixture(t, models.TargetGroup, denyDeleteRepo)

	rr := f.callMember(t, "nope", `{"jsonrpc":"2.0","id":46,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404; body %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	// -32000 is the code every proxy-originated transport refusal uses, so a
	// client can tell "this endpoint is not there" from -32602 "tool blocked".
	for _, want := range []string{`"code":-32000`, `"unknown endpoint"`, `"id":46`} {
		if !strings.Contains(body, want) {
			t.Errorf("body %s lacks %s", body, want)
		}
	}
	if strings.Contains(body, "nope") {
		t.Errorf("body %s echoes the slug back; every miss owes the caller the same answer", body)
	}
	if n := f.stub.hits.Load(); n != 0 {
		t.Fatalf("the upstream served %d requests; an endpoint that does not exist must cost none", n)
	}

	rows := f.waitBlocked(t, 1)
	if len(rows) != 1 {
		t.Fatalf("GET /api/v1/logs?status=blocked returned %d rows, want 1: %+v", len(rows), rows)
	}
	// Empty upstream_id here, u1 on the test above: nothing was resolved, so
	// there is nothing to name. The reason carries the slug the caller asked
	// for, which is the half of the answer only the operator gets.
	assertBlockedRow(t, rows[0], "delete_repo", "unknown endpoint: nope", "", f.keyID)
}
