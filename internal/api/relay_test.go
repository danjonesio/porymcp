package api

// The management API's half of PORM-146: kind and test_path on upstreams, the
// probe-based connection test, http_methods on virtual keys, and the endpoint
// list on a mixed group.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// apiStub is a plain HTTP API that records what it sees and answers with a
// scripted status.
type apiStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	seen   []*http.Request
	status int
}

func newAPIStub(t *testing.T) *apiStub {
	t.Helper()
	s := &apiStub{status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		s.mu.Lock()
		s.seen = append(s.seen, r.Clone(context.Background()))
		status := s.status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"login":"octocat"}`)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *apiStub) requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.seen...)
}

func httpUpstreamBody(name, base, testPath string) map[string]any {
	return map[string]any{
		"name": name, "kind": "http", "url": base, "test_path": testPath,
		"auth_type": "bearer", "auth_config": map[string]any{"token": "stored-token-1"},
	}
}

func wantError(t *testing.T, rr *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	if rr.Code != status || !strings.Contains(rr.Body.String(), `"`+msg+`"`) {
		t.Fatalf("status %d body %s, want %d %q", rr.Code, rr.Body.String(), status, msg)
	}
}

func lastEvent(t *testing.T, st *store.SQLStore, action string) string {
	t.Helper()
	got := eventsFor(adminEvents(t, st), action)
	if len(got) == 0 {
		t.Fatalf("no %s event", action)
	}
	return string(got[0].Details)
}

// TestUpstreamKindAPI covers PORM-146 security requirements 2, 9 and 13 on
// the management API: kind is stored, returned, defaulted and immutable; the
// kind rules refuse a test path on an MCP row, oauth and a base URL with a
// query or userinfo on an HTTP API row, at create and at PATCH.
func TestUpstreamKindAPI(t *testing.T) {
	_, h, st := testAPI(t)
	ctx := context.Background()

	rr, up := newUpstream(t, h, httpUpstreamBody("GitHub API", "https://api.example/v1", "/user"))
	if up == nil {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if up["kind"] != "http" || up["test_path"] != "/user" || up["transport"] != "streamable-http" {
		t.Fatalf("created = %v", up)
	}
	id := up["id"].(string)
	if d := lastEvent(t, st, models.ActionUpstreamCreate); !strings.Contains(d, `"kind":"http"`) {
		t.Errorf("create details = %s, want kind", d)
	}
	// An MCP row reads kind mcp, never "", on create, GET and the list.
	_, mcp := newUpstream(t, h, upstreamBody("Docs", nil))
	if mcp["kind"] != "mcp" || mcp["test_path"] != "" {
		t.Errorf("mcp create = %v", mcp)
	}
	mcpID := mcp["id"].(string)
	if got := getJSON(t, h, "/upstreams/"+mcpID); got["kind"] != "mcp" {
		t.Errorf("GET kind = %v", got["kind"])
	}
	list := getJSON(t, h, "/upstreams")
	for _, u := range list["upstreams"].([]any) {
		if k := u.(map[string]any)["kind"]; k != "mcp" && k != "http" {
			t.Errorf("list kind = %v", k)
		}
	}

	// Create refusals.
	rr, _ = newUpstream(t, h, upstreamBody("grpc", map[string]any{"kind": "grpc"}))
	wantError(t, rr, 400, "invalid kind")
	rr, _ = newUpstream(t, h, upstreamBody("mcp with path", map[string]any{"test_path": "/user"}))
	wantError(t, rr, 400, "test_path applies to an HTTP API upstream")
	rr, _ = newUpstream(t, h, httpUpstreamBody("dots", "https://api.example/v1", "/../x"))
	wantError(t, rr, 400, "test_path must not contain a .. segment")
	rr, _ = newUpstream(t, h, httpUpstreamBody("no slash", "https://api.example/v1", "user"))
	wantError(t, rr, 400, "test_path must begin with /")
	rr, _ = newUpstream(t, h, httpUpstreamBody("query", "https://api.example/v1?key=x", "/user"))
	wantError(t, rr, 400, "url must not carry a query string")
	rr, _ = newUpstream(t, h, httpUpstreamBody("userinfo", "https://u:p@api.example/v1", "/user"))
	wantError(t, rr, 400, "url must not embed credentials")
	oauth := httpUpstreamBody("oauth", "https://api.example/v1", "/user")
	oauth["auth_type"], oauth["auth_config"] = "oauth", map[string]any{}
	rr, _ = newUpstream(t, h, oauth)
	wantError(t, rr, 400, "oauth is not available on an HTTP API upstream")

	// PATCH: kind is immutable, the same value is a no-op, and the rules run
	// on the merged row.
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"kind": "mcp"})
	wantError(t, rr, 400, "kind cannot be changed")
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"kind": "http"})
	if rr.Code != 200 {
		t.Fatalf("same-kind PATCH: %d %s", rr.Code, rr.Body.String())
	}
	if d := lastEvent(t, st, models.ActionUpstreamUpdate); d != "{}" {
		t.Errorf("same-kind PATCH details = %s, want {}", d)
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_type": "oauth"})
	wantError(t, rr, 400, "oauth is not available on an HTTP API upstream")
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"url": "https://api.example/v1?token=x"})
	wantError(t, rr, 400, "url must not carry a query string")
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+mcpID, "test-admin", map[string]any{"test_path": "/x"})
	wantError(t, rr, 400, "test_path applies to an HTTP API upstream")
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"test_path": "/a/../b"})
	wantError(t, rr, 400, "test_path must not contain a .. segment")

	// A test_path change resets the recorded test and lands in fields.
	row, err := st.GetUpstream(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUpstreamTest(ctx, id, time.Now().UTC(), true, row.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if got := getJSON(t, h, "/upstreams/"+id); got["last_test_ok"] != true {
		t.Fatalf("test not recorded: %v", got["last_test_ok"])
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"test_path": "/me"})
	if rr.Code != 200 {
		t.Fatalf("PATCH test_path: %d %s", rr.Code, rr.Body.String())
	}
	got := getJSON(t, h, "/upstreams/"+id)
	if got["test_path"] != "/me" || got["last_test_ok"] != nil || got["last_test_at"] != nil {
		t.Errorf("after PATCH test_path: test_path=%v last_test_ok=%v last_test_at=%v", got["test_path"], got["last_test_ok"], got["last_test_at"])
	}
	if d := lastEvent(t, st, models.ActionUpstreamUpdate); !strings.Contains(d, `"test_path"`) {
		t.Errorf("PATCH details = %s, want test_path in fields", d)
	}
	// null clears it.
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"test_path": nil})
	if rr.Code != 200 || getJSON(t, h, "/upstreams/"+id)["test_path"] != "" {
		t.Errorf("null test_path: %d %s", rr.Code, rr.Body.String())
	}

	// A key bound to a disabled http upstream keeps the /api/ proxy_url with
	// no endpoints, so the URL in the one response with the plaintext never
	// flips as the upstream is toggled.
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"enabled": false})
	if rr.Code != 200 {
		t.Fatalf("disable: %d", rr.Code)
	}
	vk := newVirtualKey(t, h, "upstream", id, nil)
	if !strings.HasSuffix(vk["proxy_url"].(string), "/"+vk["id"].(string)+"/api/") || len(vk["endpoints"].([]any)) != 0 {
		t.Errorf("disabled http target: proxy_url=%v endpoints=%v", vk["proxy_url"], vk["endpoints"])
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"enabled": true})
	if rr.Code != 200 {
		t.Fatalf("enable: %d", rr.Code)
	}
	got = getJSON(t, h, "/virtual-keys/"+vk["id"].(string))
	eps := got["endpoints"].([]any)
	if len(eps) != 1 || eps[0].(map[string]any)["kind"] != "http" || !strings.HasSuffix(eps[0].(map[string]any)["url"].(string), "/api/") {
		t.Errorf("enabled http target endpoints = %v", eps)
	}
	if got["proxy_url"] != eps[0].(map[string]any)["url"] {
		t.Errorf("proxy_url %v != endpoint url %v", got["proxy_url"], eps[0].(map[string]any)["url"])
	}
}

// TestHTTPProbe is the API half of the issue's TestHTTPProbe (PORM-146
// security requirements 2 and 12): both discovery routes probe an HTTP API
// upstream with one GET, record the outcome, and carry kind and http_status.
func TestHTTPProbe(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ctx := context.Background()
	stub := newAPIStub(t)
	_, up := newUpstream(t, h, httpUpstreamBody("API", stub.srv.URL+"/v1", "/user"))
	id := up["id"].(string)

	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	if rr.Code != 200 {
		t.Fatalf("discover: %d %s", rr.Code, rr.Body.String())
	}
	var d map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d["ok"] != true || d["kind"] != "http" || d["http_status"] != float64(200) {
		t.Fatalf("discovery = %v", d)
	}
	if tools, ok := d["tools"].([]any); !ok || len(tools) != 0 || d["tool_count"] != float64(0) {
		t.Errorf("tools = %v", d["tools"])
	}
	for _, absent := range []string{"era", "protocol_version", "server_info"} {
		if _, has := d[absent]; has {
			t.Errorf("%s present on an http probe: %v", absent, d[absent])
		}
	}
	reqs := stub.requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodGet || reqs[0].URL.Path != "/v1/user" {
		t.Fatalf("stub saw %d requests: %+v", len(reqs), reqs)
	}
	if reqs[0].Header.Get("Authorization") != "Bearer stored-token-1" {
		t.Errorf("Authorization = %q", reqs[0].Header.Get("Authorization"))
	}
	if got := getJSON(t, h, "/upstreams/"+id); got["last_test_ok"] != true || got["last_test_at"] == nil {
		t.Errorf("not recorded as ok: %v %v", got["last_test_ok"], got["last_test_at"])
	}

	stub.mu.Lock()
	stub.status = http.StatusUnauthorized
	stub.mu.Unlock()
	rr = doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d["ok"] != false || d["error"] != "upstream rejected the credential (401)" || d["http_status"] != float64(401) || d["kind"] != "http" {
		t.Fatalf("401 discovery = %v", d)
	}
	if got := getJSON(t, h, "/upstreams/"+id); got["last_test_ok"] != false {
		t.Errorf("not recorded as failed: %v", got["last_test_ok"])
	}

	// The unsaved route probes too, persists nothing, and applies the base
	// URL rule.
	stub.mu.Lock()
	stub.status = http.StatusOK
	stub.mu.Unlock()
	before := len(getJSON(t, h, "/upstreams")["upstreams"].([]any))
	rr = doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", httpUpstreamBody("unsaved", stub.srv.URL+"/v1", "/me"))
	if rr.Code != 200 {
		t.Fatalf("unsaved discover: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d["ok"] != true || d["kind"] != "http" {
		t.Fatalf("unsaved discovery = %v", d)
	}
	if reqs := stub.requests(); reqs[len(reqs)-1].URL.Path != "/v1/me" {
		t.Errorf("unsaved probe path %q", reqs[len(reqs)-1].URL.Path)
	}
	if after := len(getJSON(t, h, "/upstreams")["upstreams"].([]any)); after != before {
		t.Errorf("the unsaved route persisted a row")
	}
	rr = doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", httpUpstreamBody("q", stub.srv.URL+"/v1?key=x", "/me"))
	wantError(t, rr, 400, "url must not carry a query string")
	rr = doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin",
		httpUpstreamBody("u", strings.Replace(stub.srv.URL, "http://", "http://u:p@", 1)+"/v1", "/me"))
	wantError(t, rr, 400, "url must not embed credentials")

	// An undecryptable stored credential still answers kind http.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE upstreams SET auth_config = 'garbage' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	db.Close()
	rr = doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d["ok"] != false || d["kind"] != "http" || d["error"] == "" {
		t.Fatalf("undecryptable discovery = %v", d)
	}
	_ = ctx
	_ = st
}

// TestVirtualKeyHTTPMethodsAPI covers PORM-146 security requirement 8 on the
// management API: normalised on write, always present on read, [] clears and
// is recorded, and an unreadable column is reported and repaired by one PATCH.
func TestVirtualKeyHTTPMethodsAPI(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ctx := context.Background()
	_, up := newUpstream(t, h, httpUpstreamBody("API", "https://api.example/v1", ""))
	id := up["id"].(string)

	vk := newVirtualKey(t, h, "upstream", id, map[string]any{"http_methods": []string{"get", "POST"}})
	kid := vk["id"].(string)
	if m := vk["http_methods"]; m == nil || strings.Join(toStrings(m), ",") != "GET,POST" {
		t.Fatalf("create http_methods = %v", m)
	}
	row, err := st.GetVirtualKey(ctx, kid)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(row.HTTPMethods, ",") != "GET,POST" {
		t.Errorf("stored = %v", row.HTTPMethods)
	}
	rr := doJSON(t, h, http.MethodPost, "/virtual-keys", "test-admin", map[string]any{
		"name": "bad", "target_type": "upstream", "target_id": id, "http_methods": []string{"FETCH"}})
	wantError(t, rr, 400, "invalid http_methods: FETCH")

	// Omitted leaves it; [] clears it and is recorded; GET always carries it.
	got := patchVirtualKeyJSON(t, h, kid, map[string]any{"name": "renamed"})
	if strings.Join(toStrings(got["http_methods"]), ",") != "GET,POST" {
		t.Errorf("PATCH without http_methods changed it: %v", got["http_methods"])
	}
	got = patchVirtualKeyJSON(t, h, kid, map[string]any{"http_methods": []string{}})
	if m, ok := got["http_methods"].([]any); !ok || len(m) != 0 {
		t.Errorf("cleared http_methods = %v", got["http_methods"])
	}
	if d := lastEvent(t, st, models.ActionVirtualKeyUpdate); !strings.Contains(d, `"cleared":["http_methods"]`) || !strings.Contains(d, `"http_methods"`) {
		t.Errorf("clear details = %s", d)
	}
	if _, has := getJSON(t, h, "/virtual-keys/"+kid)["http_methods"]; !has {
		t.Errorf("GET omits http_methods")
	}
	for _, k := range getJSON(t, h, "/virtual-keys")["virtual_keys"].([]any) {
		if _, has := k.(map[string]any)["http_methods"]; !has {
			t.Errorf("list omits http_methods")
		}
	}

	// A corrupt column is reported, survives a rename, and is repaired by a
	// PATCH that carries the field; clearing from that state is recorded.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE virtual_keys SET http_methods = 'not json' WHERE id = ?`, kid); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if got := getJSON(t, h, "/virtual-keys/"+kid); got["http_methods_malformed"] != true {
		t.Fatalf("malformed not reported: %v", got)
	}
	patchVirtualKeyJSON(t, h, kid, map[string]any{"name": "renamed again"})
	if got := getJSON(t, h, "/virtual-keys/"+kid); got["http_methods_malformed"] != true {
		t.Fatalf("a rename repaired the column: %v", got)
	}
	got = patchVirtualKeyJSON(t, h, kid, map[string]any{"http_methods": []string{}})
	if _, has := got["http_methods_malformed"]; has {
		t.Errorf("still malformed after a PATCH carrying the field: %v", got)
	}
	if d := lastEvent(t, st, models.ActionVirtualKeyUpdate); !strings.Contains(d, `"cleared":["http_methods"]`) {
		t.Errorf("clear from malformed not recorded: %s", d)
	}
	row, _ = st.GetVirtualKey(ctx, kid)
	if row.MethodsMalformed || row.HTTPMethods == nil || len(row.HTTPMethods) != 0 {
		t.Errorf("stored after repair = %+v", row)
	}

	// Accepted on an MCP-only target too: a group can gain an http member.
	mcpID, _ := mustUpstream(t, h, "Docs", nil)
	mk := newVirtualKey(t, h, "upstream", mcpID, map[string]any{"http_methods": []string{"HEAD"}})
	if strings.Join(toStrings(mk["http_methods"]), ",") != "HEAD" {
		t.Errorf("mcp target http_methods = %v", mk["http_methods"])
	}
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, x.(string))
	}
	return out
}

// TestHTTPGroupMemberEndpoints is the endpoints half of the issue's
// TestHTTPGroupMember: a mixed group lists both kinds, the http entry's URL
// ends in /{slug}/api/, and proxy_url stays the aggregate /mcp door.
func TestHTTPGroupMemberEndpoints(t *testing.T) {
	_, h, _ := testAPI(t)
	alphaID, _ := mustUpstream(t, h, "Alpha", nil)
	_, beta := newUpstream(t, h, httpUpstreamBody("Beta", "https://api.example/v1", ""))
	betaID := beta["id"].(string)
	gid := mustGroup(t, h, "Mixed", []string{alphaID, betaID})
	vk := newVirtualKey(t, h, "group", gid, nil)
	eps := vk["endpoints"].([]any)
	if len(eps) != 2 {
		t.Fatalf("endpoints = %v", eps)
	}
	a, b := eps[0].(map[string]any), eps[1].(map[string]any)
	if a["kind"] != "mcp" || !strings.HasSuffix(a["url"].(string), "/alpha/mcp") {
		t.Errorf("alpha entry = %v", a)
	}
	if b["kind"] != "http" || !strings.HasSuffix(b["url"].(string), "/beta/api/") {
		t.Errorf("beta entry = %v", b)
	}
	if !strings.HasSuffix(vk["proxy_url"].(string), "/mcp") {
		t.Errorf("group proxy_url = %v", vk["proxy_url"])
	}
}
