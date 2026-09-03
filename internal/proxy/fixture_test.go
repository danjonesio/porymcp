package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/netcasklabs/porymcp/internal/audit"
	"github.com/netcasklabs/porymcp/internal/auth"
	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
)

// A proxy test almost always has the same two questions: what did the client
// get back, and what did the upstream see. The fixture below answers the
// second one, every stub counts the requests it received per (method, tool),
// so "zero upstream requests" is an assertion rather than an inference. The
// existing tests in proxy_test.go build their own servers by hand and are left
// exactly as they are.

// upstreamSpec describes one stub MCP server.
type upstreamSpec struct {
	Tools    []string // advertised tool names; ignored when RawList != ""
	RawList  string   // verbatim tools/list response body
	ListCT   string   // Content-Type for tools/list (default application/json)
	ListCode int      // HTTP status for tools/list (default 200)
	CallBody string   // response to anything else (default a bare ok result)
	// ListHeaders are extra response headers on tools/list. They exist for the
	// body-integrity headers the list filter has to drop once it has rewritten
	// a body those headers no longer describe.
	ListHeaders map[string]string
	// Bearer, when set, is the real credential stored (encrypted) against this
	// upstream, so a test can prove which token a request carried.
	Bearer string
	// SessionID, when set, is returned as Mcp-Session-Id on every response
	// except tools/list. ListHeaders only reaches the tools/list arm, so this
	// is the only way to give a stub the session header a real MCP server
	// mints on initialize.
	SessionID string
	// AuthType and AuthConfig give an upstream a credential of any of the four
	// kinds the proxy supports. Bearer above is shorthand for the common one;
	// this is the only way to build the three that write the credential into
	// some other header, which is exactly what a redirect would carry off the
	// configured host.
	AuthType   string
	AuthConfig models.AuthConfig
	// RedirectStatus, RedirectTo and RedirectOn make the stub answer with a
	// redirect instead of a result. RedirectOn names the JSON-RPC method that
	// is redirected; "" redirects everything. Location is set only when
	// RedirectTo is non-empty, so a 3xx carrying no Location (which Go never
	// follows, and which the proxy used to relay to the client as a success)
	// is expressible too.
	RedirectStatus int
	RedirectTo     string
	RedirectOn     string
}

// recordedRequest is one request a stub received, kept whole. The counters
// below answer "how many"; this answers "what did the upstream actually see",
// which is the only way to tell a request the proxy composed for itself from
// one it copied off the client.
type recordedRequest struct {
	HTTPMethod string
	Header     http.Header
	Body       []byte
	RPCMethod  string
}

// stub is one httptest upstream plus a per-(method, tool) request counter.
type stub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	counts map[[2]string]int
	total  int
	reqs   []recordedRequest
}

func (s *stub) bump(r *http.Request, body []byte, method, tool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[[2]string{method, tool}]++
	s.total++
	s.reqs = append(s.reqs, recordedRequest{
		HTTPMethod: r.Method,
		Header:     r.Header.Clone(),
		Body:       append([]byte(nil), body...),
		RPCMethod:  method,
	})
}

func newStub(spec upstreamSpec) *stub {
	s := &stub{counts: map[[2]string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		// Deliberately lenient: the counter must record even a request the
		// proxy should never have sent.
		_ = json.Unmarshal(body, &req)
		s.bump(r, body, req.Method, req.Params.Name)

		// The redirect is answered before the tools/list arm, so one stub can
		// redirect both a request the client sent and the catalogue request
		// the proxy composes for itself. A 304 has its body and Content-Type
		// dropped by net/http on the way out; its Location, if the spec set
		// one, survives.
		if spec.RedirectStatus != 0 && (spec.RedirectOn == "" || spec.RedirectOn == req.Method) {
			if spec.RedirectTo != "" {
				w.Header().Set("Location", spec.RedirectTo)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(spec.RedirectStatus)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"redirected":true}}`)
			return
		}

		if req.Method == "tools/list" {
			ct := spec.ListCT
			if ct == "" {
				ct = "application/json"
			}
			w.Header().Set("Content-Type", ct)
			for k, v := range spec.ListHeaders {
				w.Header().Set(k, v)
			}
			if spec.ListCode != 0 {
				w.WriteHeader(spec.ListCode)
			}
			if spec.RawList != "" {
				_, _ = io.WriteString(w, spec.RawList)
				return
			}
			tools := make([]map[string]any, 0, len(spec.Tools))
			for _, n := range spec.Tools {
				tools = append(tools, map[string]any{"name": n})
			}
			out, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"tools": tools},
			})
			_, _ = w.Write(out)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if spec.SessionID != "" {
			w.Header().Set("Mcp-Session-Id", spec.SessionID)
		}
		if spec.CallBody != "" {
			_, _ = io.WriteString(w, spec.CallBody)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	return s
}

// fixture is a proxy handler wired to real stores and stub upstreams, plus the
// one virtual key the test authenticates with.
type fixture struct {
	t     *testing.T
	H     *Handler
	Key   string // the plaintext virtual key
	Store store.Store
	// DBPath is the SQLite file behind Store, for the one kind of test that
	// cannot go through the store: a column corrupted so badly that no
	// exported call could ever write it.
	DBPath string
	Stubs  map[string]*stub // upstream slug -> stub
	// Router is the real chi router with all three proxy patterns on it. A
	// hand-built RouteContext would prove the handler reads a parameter, not
	// that the registered pattern produces one, which is exactly the drift
	// the constants in proxy.go exist to prevent. Tests that care which door
	// was knocked on go through here; do and post do not, so the aggregate
	// tests keep testing the aggregate path.
	Router http.Handler
}

func newFixture(t *testing.T, specs map[string]upstreamSpec, group bool, filter json.RawMessage, allow, deny []string) *fixture {
	t.Helper()
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "p.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	al := audit.New(st, nil)
	t.Cleanup(al.Close) // LIFO: the audit logger stops before the store closes

	now := time.Now().UTC()
	ctx := context.Background()
	f := &fixture{t: t, Store: st, DBPath: dbPath, Stubs: map[string]*stub{}}

	slugs := make([]string, 0, len(specs))
	for s := range specs {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs) // deterministic upstream order

	ids := make([]string, 0, len(slugs))
	for i, slug := range slugs {
		s := newStub(specs[slug])
		t.Cleanup(s.srv.Close)
		f.Stubs[slug] = s
		id := "u" + strconv.Itoa(i+1)
		ids = append(ids, id)
		up := &models.Upstream{
			// Name deliberately differs from Slug: prefixing must come from
			// the slug, as TestGroupAlwaysPrefixesToolNames pins.
			ID: id, Name: strings.ToUpper(slug) + " Renamed", Slug: slug, URL: s.srv.URL,
			Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone,
			Enabled: true, CreatedAt: now, UpdatedAt: now,
		}
		// Bearer is the shorthand; AuthType with an AuthConfig is the long
		// way round, and the only way to build the api_key, header and custom
		// upstreams whose credential rides a header of the upstream's own
		// choosing.
		switch spec := specs[slug]; {
		case spec.Bearer != "":
			enc, err := crypto.NewKeyring(key, nil).Seal([]byte(`{"token":"` + spec.Bearer + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			up.AuthType = models.AuthBearer
			up.AuthConfig = []byte(enc)
		case spec.AuthType != "":
			raw, err := json.Marshal(spec.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			enc, err := crypto.NewKeyring(key, nil).Seal(raw)
			if err != nil {
				t.Fatal(err)
			}
			up.AuthType = spec.AuthType
			up.AuthConfig = []byte(enc)
		}
		if err := st.CreateUpstream(ctx, up); err != nil {
			t.Fatal(err)
		}
	}

	targetType, targetID := models.TargetUpstream, ids[0]
	if group {
		if err := st.CreateGroup(ctx, &models.Group{
			ID: "g1", Name: "grp", UpstreamIDs: ids, ToolFilter: filter,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		targetType, targetID = models.TargetGroup, "g1"
	}

	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "a1", Name: "bot", KeyHash: hash, KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: targetType, TargetID: targetID,
		ToolAllowlist: allow, ToolDenylist: deny, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	f.Key = plain
	f.H = New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080"}, st, al, nil)

	rt := chi.NewRouter()
	rt.HandleFunc("/mcp", f.H.ServeHTTP)
	rt.HandleFunc(KeyRoute, f.H.ServeHTTP)
	rt.HandleFunc(MemberRoute, f.H.ServeMember)
	f.Router = rt
	return f
}

// newGroupFixture builds a group key over members, a map of upstream slug to
// the tool names that upstream advertises.
func newGroupFixture(t *testing.T, members map[string][]string, filter json.RawMessage, allow, deny []string) *fixture {
	specs := map[string]upstreamSpec{}
	for slug, tools := range members {
		specs[slug] = upstreamSpec{Tools: tools}
	}
	return newFixture(t, specs, true, filter, allow, deny)
}

// newSingleFixture builds a key bound to one upstream, with no group. The
// upstream's slug is "solo".
func newSingleFixture(t *testing.T, spec upstreamSpec, allow, deny []string) *fixture {
	return newFixture(t, map[string]upstreamSpec{"solo": spec}, false, nil, allow, deny)
}

// do sends a raw body at the shared /mcp endpoint with the given HTTP method.
// The verb is a parameter because the proxy replays it upstream, so parsing
// and policy have to hold on DELETE and PUT as much as on POST.
func (f *fixture) do(method, rpc string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(method, "http://localhost:8080/mcp", strings.NewReader(rpc))
	req.Header.Set("Authorization", "Bearer "+f.Key)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.H.ServeHTTP(rr, req)
	return rr
}

func (f *fixture) post(rpc string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(http.MethodPost, rpc)
}

// postWith is post with extra client headers. Proving that a client header did
// not reach an upstream means sending one, so the tests that care about which
// request shape the proxy uses upstream go through here.
func (f *fixture) postWith(rpc string, hdr map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/mcp", strings.NewReader(rpc))
	req.Header.Set("Authorization", "Bearer "+f.Key)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.H.ServeHTTP(rr, req)
	return rr
}

// doPath sends a raw body at an absolute URL through the fixture's router. The
// URL is absolute because hostAllowed compares the request's host against
// PublicURL, which the fixture sets to http://localhost:8080.
func (f *fixture) doPath(method, path, rpc string, hdr map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(rpc))
	req.Header.Set("Authorization", "Bearer "+f.Key)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.Router.ServeHTTP(rr, req)
	return rr
}

// postTo is doPath for a POST with no extra headers.
func (f *fixture) postTo(path, rpc string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.doPath(http.MethodPost, path, rpc, nil)
}

// memberURL is the endpoint of one member of the fixture's key. The key id is
// always "a1" (newFixture), a test names only the slug.
func (f *fixture) memberURL(slug string) string {
	return "http://localhost:8080/a1/" + slug + "/mcp"
}

// postMember posts to one member endpoint of the fixture's key.
func (f *fixture) postMember(slug, rpc string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.postTo(f.memberURL(slug), rpc)
}

// postMemberWith is postMember with extra client headers, the session id a
// client sends back on the request after initialize, above all.
func (f *fixture) postMemberWith(slug, rpc string, hdr map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.doPath(http.MethodPost, f.memberURL(slug), rpc, hdr)
}

// requestsTo is every request the named upstream received, in order.
func (f *fixture) requestsTo(slug string) []recordedRequest {
	s := f.Stubs[slug]
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.reqs...)
}

// count is how many requests the named upstream saw for one (method, tool)
// pair. A tool name of "" matches any request without params.name.
func (f *fixture) count(slug, method, tool string) int {
	s := f.Stubs[slug]
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[[2]string{method, tool}]
}

// totalReqs is every request the named upstream saw, whatever it was.
func (f *fixture) totalReqs(slug string) int {
	s := f.Stubs[slug]
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// upstreamsIdle asserts no stub was contacted at all, the property a rejected
// request has to hold, since the whole point is that the credential is never
// presented.
func (f *fixture) upstreamsIdle() bool {
	for slug := range f.Stubs {
		if f.totalReqs(slug) != 0 {
			return false
		}
	}
	return true
}

// waitAudit polls for audit rows matching filter. Records are written on a
// background goroutine, so a test that reads once will read too early.
func (f *fixture) waitAudit(filter models.LogFilter) []models.AuditLog {
	f.t.Helper()
	return f.waitAuditN(filter, 1)
}

// waitAuditN is waitAudit for a test that sent n requests: reading as soon as
// the first row lands would let the rest of them still be in flight.
func (f *fixture) waitAuditN(filter models.LogFilter, n int) []models.AuditLog {
	f.t.Helper()
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		logs, _, err := f.Store.ListAuditLogs(context.Background(), filter)
		if err == nil && len(logs) >= n {
			return logs
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("wanted %d audit rows matching %+v within 2s, got %d (err=%v)", n, filter, len(logs), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// rpcError reads the error member of a JSON-RPC envelope. The id comes back as
// any so a test can tell "id":null from an id that was echoed.
func rpcErrorOf(t *testing.T, body []byte) (code int, msg string, id any) {
	t.Helper()
	var env struct {
		ID    any `json:"id"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	if env.Error == nil {
		t.Fatalf("expected a JSON-RPC error member, got %s", body)
	}
	return env.Error.Code, env.Error.Message, env.ID
}

// listedNames is the sorted tool names in a tools/list response.
func listedNames(t *testing.T, body []byte) []string {
	t.Helper()
	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	out := make([]string, 0, len(env.Result.Tools))
	for _, tl := range env.Result.Tools {
		out = append(out, tl.Name)
	}
	sort.Strings(out)
	return out
}
