package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/go-chi/chi/v5"
)

func TestInjectBearerAndHideVirtualKey(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping"}]}}`)
	}))
	defer up.Close()

	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	enc, err := crypto.NewKeyring(key, nil).Seal([]byte(`{"token":"sk-real-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "u1", Name: "mock", Slug: "mock", URL: up.URL, Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthBearer, AuthConfig: []byte(enc), Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "a1", Name: "bot", KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080", UpstreamGuard: testGuard}
	al := audit.New(st, nil)
	h := New(cfg, st, al, nil)

	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	))
	req.Header.Set("Authorization", "Bearer "+plain)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotAuth != "Bearer sk-real-secret" {
		t.Fatalf("upstream auth=%q", gotAuth)
	}
	if strings.Contains(rr.Body.String(), "sk-real-secret") {
		t.Fatal("real secret leaked to agent")
	}

	// Give the async auditor a moment.
	time.Sleep(50 * time.Millisecond)
	logs, _, err := st.ListAuditLogs(ctx, models.LogFilter{Limit: 10})
	if err != nil || len(logs) == 0 {
		t.Fatalf("expected audit log, err=%v logs=%v", err, logs)
	}
	if logs[0].Method != "tools/list" || logs[0].VirtualKeyID != "a1" {
		t.Fatalf("log=%+v", logs[0])
	}
}

func TestKeyPathMustMatchKey(t *testing.T) {
	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	plain, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUpstream(context.Background(), &models.Upstream{
		ID: "u1", Name: "mock", Slug: "mock", URL: "http://127.0.0.1:9", Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthNone, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(context.Background(), &models.VirtualKey{
		ID: "a1", Name: "bot", KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080", UpstreamGuard: testGuard}, st, nil, nil)
	r := chi.NewRouter()
	r.HandleFunc("/mcp", h.ServeHTTP)
	r.HandleFunc(KeyRoute, h.ServeHTTP)
	r.HandleFunc(MemberRoute, h.ServeMember)

	post := func(url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+plain)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	const ping = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	rr := post("http://localhost:8080/other-id/mcp", ping)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("mismatched path code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "virtual key does not match this endpoint") {
		t.Fatalf("mismatched path body=%s", rr.Body.String())
	}

	// The binding check reads KeyParam, which MemberRoute binds too. If the
	// route and the lookup ever drifted, chi would hand the handler "" and
	// this would fail open, a valid key would reach another key's members.
	rr = post("http://localhost:8080/other-id/mock/mcp", ping)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member path, mismatched key: code=%d body=%s (endpoint binding has failed open)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "virtual key does not match this endpoint") {
		t.Fatalf("member path body=%s", rr.Body.String())
	}

	// The 403 precedes the body read. A batch array is refused by parseRequest
	// with 400, so a body that never parses coming back 403 is the proof that
	// nothing about the request was inspected before the key was bound to its
	// endpoint. Nothing else in the suite pins that ordering.
	const batch = `[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`
	for _, url := range []string{
		"http://localhost:8080/other-id/mcp",
		"http://localhost:8080/other-id/mock/mcp",
	} {
		if rr := post(url, batch); rr.Code != http.StatusForbidden {
			t.Errorf("%s with an unparseable body: code=%d want 403, not 400: the binding check must run before the body is read; body=%s", url, rr.Code, rr.Body.String())
		}
	}
}

// TestProxyURLUnchangedAcrossRename pins the one promise the rename makes to
// running clients: a proxy URL minted before it (/{id}/mcp with the key's id)
// keeps working unchanged. The URL is a hard-coded literal on purpose; it is
// the string a client already holds in its config. The second half asserts
// that the endpoint-binding check still fires under the renamed route
// parameter: the same valid key on the wrong id must get 403, not the
// upstream. If KeyRoute and the KeyParam lookup ever disagreed, chi would
// return "" for the parameter and that check would silently pass every key on
// every path, which nothing else in the suite would notice.
func TestProxyURLUnchangedAcrossRename(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping"}]}}`)
	}))
	defer up.Close()

	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "u1", Name: "mock", Slug: "mock", URL: up.URL, Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthNone, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// The worked example in docs/09-clients.md.
	const id = "77232bc0-dd4a-44d5-8ae7-ef2f679879ec"
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: id, Name: "claude-code", KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080", UpstreamGuard: testGuard}, st, nil, nil)
	r := chi.NewRouter()
	r.HandleFunc("/mcp", h.ServeHTTP)
	r.HandleFunc(KeyRoute, h.ServeHTTP)
	r.HandleFunc(MemberRoute, h.ServeMember)

	call := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		req.Header.Set("Authorization", "Bearer "+plain)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	// 1. The URL a client configured before the rename, verbatim.
	if rr := call("http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ping"`) {
		t.Fatalf("pre-rename proxy URL: code=%d body=%s", rr.Code, rr.Body.String())
	}
	// 2. The same key on another id is still bound to its own endpoint.
	if rr := call("http://localhost:8080/00000000-0000-0000-0000-000000000000/mcp"); rr.Code != http.StatusForbidden {
		t.Fatalf("valid key on the wrong endpoint: code=%d body=%s (endpoint binding has failed open)", rr.Code, rr.Body.String())
	}
	// 3. The registered pattern set is exactly the shared door and KeyRoute.
	seen := map[string]bool{}
	if err := chi.Walk(r, func(_, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		seen[route] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var patterns []string
	for p := range seen {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	if got, want := strings.Join(patterns, " "), "/mcp /{keyID}/mcp /{keyID}/{slug}/mcp"; got != want {
		t.Fatalf("registered patterns %q, want %q", got, want)
	}
	// 4. The member pattern is built from the same constants the handler reads.
	if want := "/{" + KeyParam + "}/{" + SlugParam + "}/mcp"; MemberRoute != want {
		t.Fatalf("MemberRoute=%q want %q", MemberRoute, want)
	}
}

func TestInvalidKeyRejected(t *testing.T) {
	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080", UpstreamGuard: testGuard}, st, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer pory_notarealkey000000000000000000000000000000000000000000000000")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr.Code)
	}
}

// legacyPlain is a recognisable fixture key, not a random one, and legacyHash
// is the hash a build before PORM-44 wrote for it: the row shape a rollback
// verifies. Kept so the proxy is proved to accept a key created before the
// SHA-256 verifier without re-keying (PORM-44 acceptance criterion 4).
const (
	legacyPlain = "pory_cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"
	legacyHash  = "$argon2id$v=19$m=65536,t=3,p=4$Cy+fTutQIvXPS1BJr9VMVA$vzjaTy8ZC4xqaY4UHoCVWU0VmIirIv733H73OI28Z4o"
)

// TestKeyCreatedBeforeSHA256Authenticates is a lookup-path test: the proxy
// finds the row by the digest of the presented token, so a key with a
// pre-PORM-44 key_hash authenticates because its key_lookup was always the
// SHA-256 of the key, and a token one character off misses the lookup.
func TestKeyCreatedBeforeSHA256Authenticates(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	mutateKey(t, f, func(vk *models.VirtualKey) {
		vk.KeyHash = legacyHash
		vk.KeyLookup = auth.LookupDigest(legacyPlain)
	})
	f.Key = legacyPlain
	if rr := f.post(listRequest); rr.Code != http.StatusOK {
		t.Fatalf("legacy key: code=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	// The last character changed: the lookup misses, which is the 401.
	f.Key = legacyPlain[:len(legacyPlain)-1] + "0"
	if rr := f.post(listRequest); rr.Code != http.StatusUnauthorized {
		t.Fatalf("altered key: code=%d want 401; body=%s", rr.Code, rr.Body.String())
	}
}

func TestGroupAlwaysPrefixesToolNames(t *testing.T) {
	mk := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			if req.Method == "tools/list" {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search"}]}}`)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
		}))
	}
	a := mk("alpha")
	b := mk("beta")
	defer a.Close()
	defer b.Close()

	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	ctx := context.Background()
	for _, u := range []models.Upstream{
		// Name and Slug differ on purpose: the assertion below passes only if the
		// tool prefix comes from up.Slug. Do not "tidy" these names back to match
		// the slugs.
		{ID: "u1", Name: "Alpha Renamed", Slug: "alpha", URL: a.URL, Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "Beta Renamed", Slug: "beta", URL: b.URL, Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		cp := u
		if err := st.CreateUpstream(ctx, &cp); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateGroup(ctx, &models.Group{
		ID: "g1", Name: "both", UpstreamIDs: []string{"u1", "u2"}, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, lookup, prefix, _ := auth.GenerateKey()
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "a1", Name: "multi", KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetGroup, TargetID: "g1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080", UpstreamGuard: testGuard}, st, nil, nil)
	r := chi.NewRouter()
	r.HandleFunc("/mcp", h.ServeHTTP)
	r.HandleFunc(KeyRoute, h.ServeHTTP)
	r.HandleFunc(MemberRoute, h.ServeMember)

	list := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		))
		req.Header.Set("Authorization", "Bearer "+plain)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	rr := list("http://localhost:8080/mcp")
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alpha__search") || !strings.Contains(body, "beta__search") {
		t.Fatalf("expected every name to carry its member's slug, got %s", body)
	}

	// The contrast the prefixing exists for. A member endpoint speaks one
	// server, so there is nothing to disambiguate: the client sees the
	// upstream's own name and calls it by that name.
	rr = list("http://localhost:8080/a1/alpha/mcp")
	if rr.Code != 200 {
		t.Fatalf("member path: code=%d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if !strings.Contains(body, `"search"`) {
		t.Fatalf("member path: expected the upstream's own name, got %s", body)
	}
	if strings.Contains(body, "alpha__search") || strings.Contains(body, "beta__search") {
		t.Fatalf("member path: a name was prefixed on a 1:1 endpoint, got %s", body)
	}
}

// PORM-79 security requirements 4 and 11: a refused dial on the MCP door is
// the generic 502 to the agent, the bare class sentence in the row, and one
// Warn line with ids and the class, never the URL or an address.
func TestProxyRefusedDialAudited(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	var logs bytes.Buffer
	cfg := *f.H.cfg
	cfg.UpstreamGuard = netguard.Options{}
	f.H = New(&cfg, f.Store, f.H.audit, slog.New(slog.NewJSONHandler(&logs, nil)))

	rr := f.post(toolCall("1", "ping"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
	}
	code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
	if code != -32000 || msg != "upstream request failed" {
		t.Fatalf("rpc code=%d message=%q, want -32000 upstream request failed", code, msg)
	}
	if strings.Contains(rr.Body.String(), "loopback") {
		t.Fatalf("the agent was told the class: %s", rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
	if row.ErrorMessage != "upstream address denied: loopback" {
		t.Fatalf("error_message=%q, want exactly the class sentence", row.ErrorMessage)
	}
	if strings.Contains(row.ErrorMessage, "127.0.0.1") || strings.Contains(row.ErrorMessage, "http") {
		t.Fatalf("error_message=%q carries the address or the URL", row.ErrorMessage)
	}
	if n := f.totalReqs("solo"); n != 0 {
		t.Fatalf("the loopback stub saw %d requests", n)
	}
	line := logs.String()
	for _, want := range []string{`"msg":"upstream address denied"`, `"class":"loopback"`, `"upstream_id":"`, `"request_id":"`} {
		if !strings.Contains(line, want) {
			t.Errorf("server log lacks %s: %s", want, line)
		}
	}
	for _, leak := range []string{"127.0.0.1", "http://"} {
		if strings.Contains(line, leak) {
			t.Errorf("server log carries %q: %s", leak, line)
		}
	}
}

// PORM-191. The leak markers every row and log assertion below checks for:
// what Go's own *url.Error and read errors carry, and what the stored URL
// carries that must never be copied out of it.
var closedSentenceLeaks = []string{"Post ", "dial tcp", "read tcp", "lookup", "no such host", "context canceled", "/secret-path", "QUERY-MARKER", "parse \""}

// assertNoLeak fails when text carries a closedSentenceLeaks marker or any
// of extra, the needles a single test adds (PORM-72: the fragments of a
// credential an upstream echoed).
func assertNoLeak(t *testing.T, what, text string, extra ...string) {
	t.Helper()
	for _, leak := range append(append([]string(nil), closedSentenceLeaks...), extra...) {
		if strings.Contains(text, leak) {
			t.Errorf("%s carries %q: %s", what, leak, text)
		}
	}
}

// freeAddr is a loopback address nothing listens on: bound, recorded and
// released. The same port-reuse exposure as upstreamSpec.Dead.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	_ = ln.Close()
	return a
}

// failingTransport fails every request with what fail returns. http.Client.Do
// wraps that in a genuine *url.Error{Op: "Post", URL: <the full URL>}, so the
// leak shape is real and no resolver or dial runs.
type failingTransport struct {
	fail func(*http.Request) error
	hits *int32
}

func (ft failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(ft.hits, 1)
	return nil, ft.fail(r)
}

// useFailingTransport swaps the handler's upstream transport for a stub and
// restores it, the shape cancelAfterAnswer uses. The UpstreamTransport wrapper
// stays, as TestProxyClientRefusesRedirectsByConstruction asserts.
func useFailingTransport(t *testing.T, f *fixture, fail func(*http.Request) error) *int32 {
	t.Helper()
	hits := new(int32)
	real := f.H.client.Transport
	f.H.client.Transport = mcpclient.UpstreamTransport{Next: failingTransport{fail: fail, hits: hits}}
	t.Cleanup(func() { f.H.client.Transport = real })
	return hits
}

// listAnswer is the tools/list document a per-request Handler writes for a
// member whose other arms the test controls.
func listAnswer(w http.ResponseWriter, names ...string) {
	tools := make([]map[string]any, 0, len(names))
	for _, n := range names {
		tools = append(tools, map[string]any{"name": n})
	}
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": tools}})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// cutBody answers with more Content-Length than bytes: net/http closes the
// connection after the handler, so the reader sees io.ErrUnexpectedEOF.
func cutBody(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "100")
	_, _ = io.WriteString(w, `{"jsonrpc":`)
}

// resetBody writes the headers and part of the body, then resets the
// connection (linger 0 turns the close into a RST), so the reader gets the
// *net.OpError whose text is "read tcp a->b: connection reset by peer".
func resetBody(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"jsonrpc\":")
	_ = buf.Flush()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

// PORM-191 criteria 1 and 2, security requirements 1, 2, 6, 7 and 8: a
// transport failure on the MCP door is one closed sentence in the row, the
// host at most and never the URL, the path, the query string or an address
// the host resolved to, and the client's 502 does not change.
func TestMCPDoorTransportFailureIsClosedSentence(t *testing.T) {
	const tail = "/secret-path?tok=QUERY-MARKER"
	check := func(t *testing.T, f *fixture, rr *httptest.ResponseRecorder, want string) models.AuditLog {
		t.Helper()
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
		}
		if code, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); code != -32000 || msg != "upstream request failed" {
			t.Fatalf("rpc code=%d message=%q, want -32000 upstream request failed", code, msg)
		}
		row := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
		if row.ErrorMessage != want {
			t.Fatalf("error_message=%q, want %q", row.ErrorMessage, want)
		}
		assertNoLeak(t, "error_message", row.ErrorMessage)
		return row
	}

	t.Run("refused", func(t *testing.T) {
		a := freeAddr(t)
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: "http://" + a + tail}, nil, nil)
		check(t, f, f.post(toolCall("1", "ping")), "cannot connect to "+a)
	})
	// The one case where the registered name and the resolved address differ,
	// so the one that proves the address is absent (security requirement 1).
	t.Run("refused by name", func(t *testing.T) {
		_, port, err := net.SplitHostPort(freeAddr(t))
		if err != nil {
			t.Fatal(err)
		}
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: "http://localhost:" + port + tail}, nil, nil)
		row := check(t, f, f.post(toolCall("1", "ping")), "cannot connect to localhost:"+port)
		for _, addr := range []string{"127.0.0.1", "::1"} {
			if strings.Contains(row.ErrorMessage, addr) {
				t.Errorf("error_message=%q names the resolved address %s", row.ErrorMessage, addr)
			}
		}
	})
	t.Run("dns", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: "http://nx.porm191.test" + tail}, nil, nil)
		useFailingTransport(t, f, func(*http.Request) error {
			return &net.DNSError{Err: "no such host", Name: "nx.porm191.test", IsNotFound: true}
		})
		check(t, f, f.post(toolCall("1", "ping")), "cannot resolve nx.porm191.test")
	})
	t.Run("tls", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: "https://nx.porm191.test" + tail}, nil, nil)
		useFailingTransport(t, f, func(*http.Request) error {
			return &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}
		})
		check(t, f, f.post(toolCall("1", "ping")), "tls handshake with nx.porm191.test failed")
	})
	// Criterion 2, amendment A3: a crafted refusal, because a real dial to a
	// host HostSafe refuses fails DNS, not connect.
	t.Run("unsafe host", func(t *testing.T) {
		if mcpclient.HostSafe("up+stream.test") {
			t.Fatal("up+stream.test is HostSafe; the subtest needs a host it refuses")
		}
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: "http://up+stream.test" + tail}, nil, nil)
		hits := useFailingTransport(t, f, func(*http.Request) error {
			return &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		})
		check(t, f, f.post(toolCall("1", "ping")), "cannot connect to the upstream")
		if n := atomic.LoadInt32(hits); n != 1 {
			t.Fatalf("the stub transport saw %d requests, want 1", n)
		}
	})
	// Security requirement 8, amendment A5.
	t.Run("client went away", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: "http://nx.porm191.test" + tail}, nil, nil)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		useFailingTransport(t, f, func(*http.Request) error {
			cancel()
			return context.Canceled
		})
		check(t, f, f.postCtx(ctx, toolCall("1", "ping")), "client went away before the answer")
	})
	// Security requirement 7: a body that failed while it was read, at
	// serve's own ReadBody. The reset is the case that leaked: its text is
	// "read tcp <local>-><resolved>: connection reset by peer".
	t.Run("cut body", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Handler: func(w http.ResponseWriter, r *http.Request) { cutBody(w) }}, nil, nil)
		check(t, f, f.post(toolCall("1", "ping")), "unexpected EOF")
	})
	t.Run("reset body", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Handler: func(w http.ResponseWriter, r *http.Request) { resetBody(t, w) }}, nil, nil)
		check(t, f, f.post(toolCall("1", "ping")), "upstream connection failed")
	})
	t.Run("member endpoint", func(t *testing.T) {
		a := freeAddr(t)
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search"}},
			"beta":  {Tools: []string{"x"}, URL: "http://" + a + tail},
		}, true, nil, nil, nil)
		row := check(t, f, f.postMember("beta", toolCall("1", "x")), "cannot connect to "+a)
		if row.UpstreamID != f.upstreamID("beta") {
			t.Fatalf("row upstream_id=%q, want beta's %q", row.UpstreamID, f.upstreamID("beta"))
		}
	})
	// The routed call on a group key goes through forwardRead: the member
	// lists, then closes the connection on the call, so Open sees an EOF.
	t.Run("routed call on a group key", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search"}},
			"beta": {Tools: []string{"x"}, Handler: func(w http.ResponseWriter, r *http.Request) {
				switch rpcMethodOf(r) {
				case "tools/list":
					listAnswer(w, "x")
				case "tools/call":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
				default:
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
				}
			}},
		}, true, nil, nil, nil)
		host := mcpclient.RowHost(f.Stubs["beta"].srv.URL)
		row := check(t, f, f.post(toolCall("1", "beta__x")), "cannot reach "+host)
		if row.UpstreamID != f.upstreamID("beta") {
			t.Fatalf("row upstream_id=%q, want beta's %q", row.UpstreamID, f.upstreamID("beta"))
		}
	})
	// The same route, failing at forwardRead's ReadBody (requirement 7).
	t.Run("routed call reset mid-body", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search"}},
			"beta": {Tools: []string{"x"}, Handler: func(w http.ResponseWriter, r *http.Request) {
				switch rpcMethodOf(r) {
				case "tools/list":
					listAnswer(w, "x")
				case "tools/call":
					resetBody(t, w)
				default:
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
				}
			}},
		}, true, nil, nil, nil)
		row := check(t, f, f.post(toolCall("1", "beta__x")), "upstream connection failed")
		if row.UpstreamID != f.upstreamID("beta") {
			t.Fatalf("row upstream_id=%q, want beta's %q", row.UpstreamID, f.upstreamID("beta"))
		}
	})
}

// PORM-191 criterion 3, security requirements 1 and 5: the group member
// skipped line carries the sentence the member's own row would. The member's
// own JSON-RPC message on this line (PORM-72's boundary) is pinned by
// TestGroupListsMemberAnsweringInSSE, "a JSON-RPC error inside a frame".
func TestGroupMemberSkippedLogIsClosedSentence(t *testing.T) {
	a := freeAddr(t)
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"search"}},
		"beta":  {Tools: []string{"x"}, URL: "http://" + a + "/secret-path?tok=QUERY-MARKER"},
	}, true, nil, nil, nil)
	logs := captureLogs(f)
	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200: %s", rr.Code, rr.Body.String())
	}
	w := skipWarnings(t, logs)
	if len(w) != 1 {
		t.Fatalf("%d skip warnings, want exactly 1: %s", len(w), logs.String())
	}
	if slug, _ := w[0]["slug"].(string); slug != "beta" {
		t.Errorf("skip slug=%q want beta", slug)
	}
	if got, _ := w[0]["err"].(string); got != "cannot connect to "+a {
		t.Errorf("skip err=%q, want %q", got, "cannot connect to "+a)
	}
	assertNoLeak(t, "server log", logs.String())

	// The catalogue request failing at listTools's ReadBody (requirement 7).
	t.Run("reset mid-catalogue", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search"}},
			"beta": {Tools: []string{"x"}, Handler: func(w http.ResponseWriter, r *http.Request) {
				if rpcMethodOf(r) == "tools/list" {
					resetBody(t, w)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			}},
		}, true, nil, nil, nil)
		logs := captureLogs(f)
		f.post(listRequest)
		w := skipWarnings(t, logs)
		if len(w) != 1 {
			t.Fatalf("%d skip warnings, want exactly 1: %s", len(w), logs.String())
		}
		if got, _ := w[0]["err"].(string); got != "upstream connection failed" {
			t.Errorf("skip err=%q, want upstream connection failed", got)
		}
		assertNoLeak(t, "server log", logs.String())
	})
}

// PORM-191 amendment A2, security requirement 1: a stored URL that
// http.NewRequestWithContext refuses (only a hand-edited row can hold one;
// the fixture writes straight to the store) records the relay door's
// sentence and never the parse error, which quotes the URL.
func TestUpstreamURLNotUsableIsClosedSentence(t *testing.T) {
	const bad = "http://127.0.0.1:1/secret\x7fpath?tok=QUERY-MARKER"
	t.Run("single key", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, URL: bad}, nil, nil)
		rr := f.post(toolCall("1", "ping"))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
		}
		row := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
		if row.ErrorMessage != "upstream url is not usable" {
			t.Fatalf("error_message=%q, want upstream url is not usable", row.ErrorMessage)
		}
		assertNoLeak(t, "error_message", row.ErrorMessage)
	})
	t.Run("group member", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search"}},
			"beta":  {Tools: []string{"x"}, URL: bad},
		}, true, nil, nil, nil)
		logs := captureLogs(f)
		f.post(listRequest)
		w := skipWarnings(t, logs)
		if len(w) != 1 {
			t.Fatalf("%d skip warnings, want exactly 1: %s", len(w), logs.String())
		}
		if got, _ := w[0]["err"].(string); got != "upstream url is not usable" {
			t.Errorf("skip err=%q, want upstream url is not usable", got)
		}
		assertNoLeak(t, "server log", logs.String())
	})
}
