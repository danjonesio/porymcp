package proxy

// The relay door's tests (PORM-146) and the fixture they share. Everything
// here wraps the MCP fixture in fixture_test.go through what it exports (H,
// Key, Store, DBPath, Router) and never edits it: the criterion that every
// existing proxy test passes unmodified is proved by
// git diff --exit-code <base> -- 'internal/proxy/*_test.go', and this file is
// new.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
)

// httpSpec describes one plain HTTP API upstream for the relay fixture.
type httpSpec struct {
	// Base is appended to the stub's URL as the stored base URL: "/v1", or
	// "" for a host-only base.
	Base     string
	TestPath string
	// Bearer is the stored credential; "" stores auth_type none.
	Bearer string
	// Kind is the stored kind column; "" means models.KindHTTP. A test writes
	// "grpc" or "HTTP" to build the hand-edited row the doors must not serve.
	Kind string
	// Disabled stores the upstream disabled.
	Disabled bool
	// Handler answers every request after it has been recorded. nil answers
	// 200 with a small JSON body and an ETag.
	Handler http.HandlerFunc
}

// apiCall is one request an apiServer received, kept whole in the shape the
// relay must reproduce: the escaped path and the raw query, not the decoded
// ones, because "%2F reaches the upstream still encoded" is one of the rules.
type apiCall struct {
	Method      string
	EscapedPath string
	RawQuery    string
	Host        string
	Header      http.Header
	Body        []byte
}

// apiServer is a plain HTTP API: it records what it sees and answers as
// scripted. It is not an MCP stub and speaks no JSON-RPC.
type apiServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []apiCall
}

func newAPIServer(t testing.TB, handler http.HandlerFunc) *apiServer {
	t.Helper()
	a := &apiServer{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.calls = append(a.calls, apiCall{
			Method: r.Method, EscapedPath: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery,
			Host: r.Host, Header: r.Header.Clone(), Body: append([]byte(nil), body...),
		})
		a.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, `{"login":"octocat"}`)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiServer) requests() []apiCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]apiCall(nil), a.calls...)
}

// relayFixture is the MCP fixture plus HTTP API upstreams and a router that
// carries the relay routes beside the three MCP ones. The key is always "a1".
type relayFixture struct {
	*fixture
	APIs   map[string]*apiServer // http upstream slug -> server
	ids    map[string]string     // http upstream slug -> id
	Router http.Handler
}

// newRelayFixture builds a fixture whose key is bound either to the first
// (sorted) HTTP API upstream in apis (group false) or to a group of every
// mcp member and every HTTP API in apis (group true). mcp may be empty: the
// base fixture is then built over a placeholder member that is taken out of
// the group again, so an all-http group is expressible.
func newRelayFixture(t testing.TB, mcp map[string]upstreamSpec, apis map[string]httpSpec, group bool) *relayFixture {
	t.Helper()
	placeholder := len(mcp) == 0
	if placeholder {
		mcp = map[string]upstreamSpec{"zzplaceholder": {Tools: []string{"p"}}}
	}
	base := newFixture(t, mcp, group, nil, nil, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	f := &relayFixture{fixture: base, APIs: map[string]*apiServer{}, ids: map[string]string{}}

	slugs := make([]string, 0, len(apis))
	for s := range apis {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	httpIDs := make([]string, 0, len(slugs))
	for i, slug := range slugs {
		spec := apis[slug]
		srv := newAPIServer(t, spec.Handler)
		f.APIs[slug] = srv
		id := "h" + strconv.Itoa(i+1)
		f.ids[slug] = id
		httpIDs = append(httpIDs, id)
		up := &models.Upstream{
			ID: id, Name: strings.ToUpper(slug) + " API", Slug: slug, Kind: models.KindHTTP,
			URL: srv.srv.URL + spec.Base, TestPath: spec.TestPath,
			Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone,
			Enabled: !spec.Disabled, CreatedAt: now, UpdatedAt: now,
		}
		if spec.Kind != "" {
			up.Kind = spec.Kind
		}
		if spec.Bearer != "" {
			enc, err := base.H.keys.Seal([]byte(`{"token":"` + spec.Bearer + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			up.AuthType = models.AuthBearer
			up.AuthConfig = []byte(enc)
		}
		if err := base.Store.CreateUpstream(ctx, up); err != nil {
			t.Fatal(err)
		}
	}

	if group {
		g, err := base.Store.GetGroup(ctx, "g1")
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		if !placeholder {
			ids = append(ids, g.UpstreamIDs...)
		}
		g.UpstreamIDs = append(ids, httpIDs...)
		g.UpdatedAt = now
		if err := base.Store.UpdateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	} else if len(httpIDs) > 0 {
		k, err := base.Store.GetVirtualKey(ctx, "a1")
		if err != nil {
			t.Fatal(err)
		}
		k.TargetType, k.TargetID = models.TargetUpstream, httpIDs[0]
		if err := base.Store.UpdateVirtualKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}

	rt := chi.NewRouter()
	rt.HandleFunc("/mcp", base.H.ServeHTTP)
	rt.HandleFunc(KeyRoute, base.H.ServeHTTP)
	rt.HandleFunc(MemberRoute, base.H.ServeMember)
	rt.HandleFunc(HTTPBaseRoute, base.H.ServeRelay)
	rt.HandleFunc(HTTPRoute, base.H.ServeRelay)
	rt.HandleFunc(HTTPMemberBaseRoute, base.H.ServeRelayMember)
	rt.HandleFunc(HTTPMemberRoute, base.H.ServeRelayMember)
	f.Router = rt
	return f
}

// setHTTPMethods stores a normalised method list on the key through the
// store, as the API would.
func (f *relayFixture) setHTTPMethods(methods []string) {
	f.t.Helper()
	ctx := context.Background()
	k, err := f.Store.GetVirtualKey(ctx, "a1")
	if err != nil {
		f.t.Fatal(err)
	}
	k.HTTPMethods = methods
	if err := f.Store.UpdateVirtualKey(ctx, k); err != nil {
		f.t.Fatal(err)
	}
}

// setColumn writes one column of the key's row by hand, for the values no
// exported call would ever store (a malformed http_methods, say).
func (f *relayFixture) setColumn(table, column, id, value string) {
	f.t.Helper()
	db, err := sql.Open("sqlite", f.DBPath)
	if err != nil {
		f.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE `+table+` SET `+column+` = ? WHERE id = ?`, value, id); err != nil {
		f.t.Fatal(err)
	}
}

// send routes one request through the relay fixture's router with the
// fixture's bearer unless hdr overrides Authorization. path is absolute-path
// form ("/a1/api/x?y=1"); the host is the fixture's PublicURL host.
func (f *relayFixture) send(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := routedRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer "+f.Key)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.Router.ServeHTTP(rr, req)
	return rr
}

// routedRequest builds a routed request for the fixture's host. A CONNECT
// target is authority-form to net/http, so an absolute URL would leave the
// path empty and never reach a door; that one is built from the relative
// path with the host set by hand.
func routedRequest(method, path, body string) *http.Request {
	if method == http.MethodConnect {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Host = "localhost:8080"
		return req
	}
	return httptest.NewRequest(method, "http://localhost:8080"+path, strings.NewReader(body))
}

// mcpPost is send for a JSON-RPC body on an MCP door.
func (f *relayFixture) mcpPost(path, rpc string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.send(http.MethodPost, path, rpc, map[string]string{"Content-Type": "application/json"})
}

// listRPC is declared in oauth_test.go and reused here.

// lastRow is the newest audit row for the fixture's key, after at least n
// rows exist.
func (f *relayFixture) lastRow(n int) models.AuditLog {
	f.t.Helper()
	rows := f.waitAuditN(models.LogFilter{VirtualKeyID: "a1"}, n)
	return rows[0]
}

// TestMCPDoorSkipsHTTPUpstreams covers PORM-146 security requirement 9 on
// the MCP doors: an HTTP API upstream, and any row whose kind is not exactly
// "mcp", is never served JSON-RPC and never sees a request from /mcp.
func TestMCPDoorSkipsHTTPUpstreams(t *testing.T) {
	t.Run("a key bound to one http upstream has no /mcp door", func(t *testing.T) {
		f := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1"}}, false)
		rr := f.mcpPost("/a1/mcp", listRPC)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status %d body %s, want 404", rr.Code, rr.Body.String())
		}
		if _, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); msg != "unknown endpoint" {
			t.Fatalf("message %q, want the uniform unknown endpoint", msg)
		}
		if got := f.lastRow(1); got.Status != models.StatusBlocked || got.ErrorMessage != errKindMismatch.Error() {
			t.Fatalf("row = %+v", got)
		}
		if n := len(f.APIs["beta"].requests()); n != 0 {
			t.Fatalf("the HTTP API saw %d requests from the MCP door", n)
		}
	})

	t.Run("a mixed group lists its mcp member only and has no member door for the http one", func(t *testing.T) {
		f := newRelayFixture(t,
			map[string]upstreamSpec{"alpha": {Tools: []string{"a"}}},
			map[string]httpSpec{"beta": {Base: "/v1"}}, true)
		rr := f.mcpPost("/a1/mcp", listRPC)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
		if got := listedNames(t, rr.Body.Bytes()); strings.Join(got, ",") != "alpha__a" {
			t.Fatalf("listed %v, want alpha__a only", got)
		}
		rr = f.mcpPost("/a1/beta/mcp", listRPC)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("member door on an http member: status %d", rr.Code)
		}
		if _, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); msg != "unknown endpoint" {
			t.Fatalf("message %q", msg)
		}
		rr = f.mcpPost("/a1/alpha/mcp", listRPC)
		if rr.Code != http.StatusOK {
			t.Fatalf("member door on the mcp member: status %d", rr.Code)
		}
		if n := len(f.APIs["beta"].requests()); n != 0 {
			t.Fatalf("the HTTP API saw %d requests from the MCP doors", n)
		}
	})

	t.Run("a group whose only enabled member is http answers 400 on /mcp", func(t *testing.T) {
		f := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1"}}, true)
		rr := f.mcpPost("/a1/mcp", listRPC)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status %d body %s, want 400", rr.Code, rr.Body.String())
		}
		if _, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); msg != "group has no MCP members" {
			t.Fatalf("message %q", msg)
		}
		if got := f.lastRow(1); got.Status != models.StatusError || got.ErrorMessage != "group has no MCP members" {
			t.Fatalf("row = %+v", got)
		}
		if n := len(f.APIs["beta"].requests()); n != 0 {
			t.Fatalf("the HTTP API saw %d requests", n)
		}
	})

	t.Run("a hand-edited kind is served on no door", func(t *testing.T) {
		for _, kind := range []string{"grpc", "HTTP", "Mcp"} {
			t.Run(kind, func(t *testing.T) {
				f := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1", Kind: kind}}, false)
				rr := f.mcpPost("/a1/mcp", listRPC)
				if rr.Code != http.StatusNotFound {
					t.Fatalf("kind %q on /mcp: status %d body %s", kind, rr.Code, rr.Body.String())
				}
				if rr := f.send(http.MethodGet, "/a1/api/x", "", nil); rr.Code != http.StatusNotFound {
					t.Fatalf("kind %q on /api/x: status %d body %s", kind, rr.Code, rr.Body.String())
				}
				if n := len(f.APIs["beta"].requests()); n != 0 {
					t.Fatalf("kind %q: the upstream saw %d requests", kind, n)
				}
				// As a group member it is a slug miss, not a served member.
				g := newRelayFixture(t,
					map[string]upstreamSpec{"alpha": {Tools: []string{"a"}}},
					map[string]httpSpec{"beta": {Base: "/v1", Kind: kind}}, true)
				if rr := g.mcpPost("/a1/beta/mcp", listRPC); rr.Code != http.StatusNotFound {
					t.Fatalf("kind %q as a member: status %d", kind, rr.Code)
				}
				if rr := g.mcpPost("/a1/mcp", listRPC); rr.Code != http.StatusOK {
					t.Fatalf("kind %q beside an mcp member: status %d body %s", kind, rr.Code, rr.Body.String())
				} else if got := listedNames(t, rr.Body.Bytes()); strings.Join(got, ",") != "alpha__a" {
					t.Fatalf("kind %q: listed %v", kind, got)
				}
			})
		}
	})
}

// jsonBody decodes a plain JSON error body from the relay door.
func jsonBody(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, b)
	}
	return m
}

// --- The relay door ---

// relayGET is the common shape: one http upstream under /v1 with a bearer.
func relayGET(t *testing.T, handler http.HandlerFunc) *relayFixture {
	t.Helper()
	return newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1", Bearer: "stored-token-42", Handler: handler}}, false)
}

// TestHTTPRelayGET is the issue's first criterion (PORM-146 security
// requirements 3 and 10): the request reaches the base URL with the stored
// credential and nothing carrying the virtual key, the answer comes back with
// its headers, and the row records the verb, the path and a redacted query.
func TestHTTPRelayGET(t *testing.T) {
	f := relayGET(t, nil)
	rr := f.send(http.MethodGet, "/a1/api/repos/x?per_page=2&access_token=x&access_token=y&X-Amz-Signature=c&key=d", "",
		map[string]string{"X-GitHub-Api-Version": "2022-11-28"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != `{"login":"octocat"}` {
		t.Errorf("body %q", rr.Body.String())
	}
	for name, want := range map[string]string{"Content-Type": "application/json", "ETag": `"v1"`, "Cache-Control": "no-store", "Content-Length": "19"} {
		if got := rr.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	reqs := f.APIs["beta"].requests()
	if len(reqs) != 1 {
		t.Fatalf("%d upstream requests, want 1", len(reqs))
	}
	up := reqs[0]
	if up.Method != http.MethodGet || up.EscapedPath != "/v1/repos/x" {
		t.Errorf("upstream saw %s %s", up.Method, up.EscapedPath)
	}
	if up.RawQuery != "per_page=2&access_token=x&access_token=y&X-Amz-Signature=c&key=d" {
		t.Errorf("query relayed as %q", up.RawQuery)
	}
	if got := up.Header.Get("Authorization"); got != "Bearer stored-token-42" {
		t.Errorf("Authorization = %q", got)
	}
	if got := up.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q", got)
	}
	for name, vals := range up.Header {
		for _, v := range vals {
			if strings.Contains(v, "pory_") || strings.Contains(v, f.Key) {
				t.Errorf("%s carried the virtual key upstream: %q", name, v)
			}
		}
	}
	row := f.lastRow(1)
	if row.Method != "GET" || row.ToolName != "/repos/x" || row.Status != models.StatusSuccess || row.UpstreamID != "h1" {
		t.Errorf("row = %+v", row)
	}
	if row.ResponseSizeBytes != 19 {
		t.Errorf("response_size_bytes = %d", row.ResponseSizeBytes)
	}
	var params struct {
		Query        map[string]string `json:"query"`
		ContentType  string            `json:"content_type"`
		RequestBytes int               `json:"request_bytes"`
	}
	if err := json.Unmarshal(row.Params, &params); err != nil {
		t.Fatalf("params %s: %v", row.Params, err)
	}
	want := map[string]string{"per_page": "2", "access_token": "[redacted]", "X-Amz-Signature": "[redacted]", "key": "[redacted]"}
	for k, v := range want {
		if params.Query[k] != v {
			t.Errorf("params.query[%s] = %q want %q (params %s)", k, params.Query[k], v, row.Params)
		}
	}
	if len(params.Query) != len(want) || params.RequestBytes != 0 {
		t.Errorf("params = %s", row.Params)
	}
	if strings.Contains(string(row.Params), "access_token=x") || strings.Contains(string(row.Params), `"x"`) {
		t.Errorf("a query secret reached the row: %s", row.Params)
	}
}

// TestHTTPRelayHostOnlyBase is the plan's own example: a base URL with no
// path (https://api.github.com) works, with and without a remainder.
func TestHTTPRelayHostOnlyBase(t *testing.T) {
	f := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "", Bearer: "b"}}, false)
	if rr := f.send(http.MethodGet, "/a1/api/user", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if rr := f.send(http.MethodGet, "/a1/api", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("base: status %d body %s", rr.Code, rr.Body.String())
	}
	reqs := f.APIs["beta"].requests()
	if len(reqs) != 2 || reqs[0].EscapedPath != "/user" || reqs[1].EscapedPath != "/" {
		t.Fatalf("upstream saw %+v", reqs)
	}
}

// TestHTTPRelayMethodsAndBody covers security requirement 7: the six verbs
// relay byte for byte, HEAD has no body but the upstream's length, and any
// other verb is 405 before authentication with no upstream request.
func TestHTTPRelayMethodsAndBody(t *testing.T) {
	f := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "13")
		w.WriteHeader(http.StatusCreated)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, `{"created":1}`)
		}
	})
	body := `{"title":"x","n":[1,2]}`
	for _, verb := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rr := f.send(verb, "/a1/api/items/1", body, map[string]string{"Content-Type": "application/vnd.api+json"})
		if rr.Code != http.StatusCreated || rr.Body.String() != `{"created":1}` {
			t.Errorf("%s: status %d body %q", verb, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("Content-Length") != "13" {
			t.Errorf("%s: Content-Length %q, want the relayed body's own", verb, rr.Header().Get("Content-Length"))
		}
	}
	reqs := f.APIs["beta"].requests()
	if len(reqs) != 4 {
		t.Fatalf("%d upstream requests, want 4", len(reqs))
	}
	for i, verb := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if reqs[i].Method != verb || string(reqs[i].Body) != body || reqs[i].Header.Get("Content-Type") != "application/vnd.api+json" {
			t.Errorf("%s: upstream saw %s %q %q", verb, reqs[i].Method, reqs[i].Body, reqs[i].Header.Get("Content-Type"))
		}
		if reqs[i].Header.Get("Content-Length") != strconv.Itoa(len(body)) {
			t.Errorf("%s: upstream Content-Length %q", verb, reqs[i].Header.Get("Content-Length"))
		}
	}
	row := f.lastRow(4)
	var params struct {
		RequestBytes int    `json:"request_bytes"`
		ContentType  string `json:"content_type"`
	}
	_ = json.Unmarshal(row.Params, &params)
	if params.RequestBytes != len(body) || params.ContentType != "application/vnd.api+json" || strings.Contains(string(row.Params), "title") {
		t.Errorf("params = %s", row.Params)
	}

	rr := f.send(http.MethodHead, "/a1/api/items/1", "", nil)
	if rr.Code != http.StatusCreated || rr.Body.Len() != 0 {
		t.Errorf("HEAD: status %d body %q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Length") != "13" {
		t.Errorf("HEAD: Content-Length %q, want the upstream's 13", rr.Header().Get("Content-Length"))
	}

	// CONNECT and TRACE are verbs chi routes, so the door's own 405 answers
	// them; a verb chi does not know (PROPFIND, PURGE, a lower-case get) is
	// 405 from the router itself, with no body, before any handler. Either
	// way nothing is authenticated and nothing is dialled.
	for _, verb := range []string{http.MethodConnect, http.MethodTrace, "PROPFIND", "get", "PURGE"} {
		before := len(f.APIs["beta"].requests())
		rr := f.send(verb, "/a1/api/items/1", "", map[string]string{"Authorization": "Bearer wrong"})
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d", verb, rr.Code)
		}
		if after := len(f.APIs["beta"].requests()); after != before {
			t.Errorf("%s reached the upstream", verb)
		}
		if verb != http.MethodConnect && verb != http.MethodTrace {
			continue
		}
		if rr.Header().Get("Allow") != relayAllowedMethods {
			t.Errorf("%s: Allow %q", verb, rr.Header().Get("Allow"))
		}
		m := jsonBody(t, rr.Body.Bytes())
		if m["error"] != "method not allowed" || m["jsonrpc"] != nil {
			t.Errorf("%s: body %s", verb, rr.Body.String())
		}
		if _, has := m["request_id"]; has {
			t.Errorf("%s: a 405 carries no request_id (it is minted after the verb check): %s", verb, rr.Body.String())
		}
	}
}

// TestHTTPPathStaysUnderBase covers security requirement 1 through the door:
// every dot-segment shape and the sibling-prefix case are refused with no
// dial, and an ordinary path (an encoded slash included) reaches the base.
func TestHTTPPathStaysUnderBase(t *testing.T) {
	f := relayGET(t, nil)
	refused := []string{
		"/a1/api/../../admin", "/a1/api/%2e%2e/admin", "/a1/api/x/..%2f..%2fadmin", "/a1/api/%2E%2e",
		"/a1/api/.%2e", "/a1/api/..%5c", "/a1/api/..;/x", "/a1/api/../v1beta/x", "/a1/api/%252e%252e",
		"/a1/api/a%00b", "/a1/api/x/%2e", "/a1/api/./x",
	}
	for _, p := range refused {
		rr := f.send(http.MethodGet, p, "", nil)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d body %s, want 400", p, rr.Code, rr.Body.String())
			continue
		}
		if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "path escapes the upstream base" || m["request_id"] == "" {
			t.Errorf("%s: body %s", p, rr.Body.String())
		}
	}
	if n := len(f.APIs["beta"].requests()); n != 0 {
		t.Fatalf("%d refused paths reached the upstream", n)
	}
	rows := f.waitAuditN(models.LogFilter{VirtualKeyID: "a1", Status: models.StatusError}, len(refused))
	if len(rows) != len(refused) {
		t.Fatalf("%d error rows, want %d", len(rows), len(refused))
	}
	for _, row := range rows {
		if row.ErrorMessage != "path escapes the upstream base" || !strings.HasPrefix(row.ToolName, "/") {
			t.Errorf("row = %+v", row)
		}
	}

	// A base with a trailing slash, a segment with an encoded slash, and a
	// path under a base with no trailing slash.
	g := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1/", Bearer: "b"}}, false)
	if rr := g.send(http.MethodGet, "/a1/api/users", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if rr := g.send(http.MethodGet, "/a1/api/a%2Fb/c", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if rr := g.send(http.MethodGet, "/a1/api/", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	reqs := g.APIs["beta"].requests()
	if len(reqs) != 3 || reqs[0].EscapedPath != "/v1/users" || reqs[1].EscapedPath != "/v1/a%2Fb/c" || reqs[2].EscapedPath != "/v1/" {
		t.Fatalf("upstream saw %q %q %q", reqs[0].EscapedPath, reqs[1].EscapedPath, reqs[2].EscapedPath)
	}
	if rr := f.send(http.MethodGet, "/a1/api/users", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if reqs := f.APIs["beta"].requests(); len(reqs) != 1 || reqs[0].EscapedPath != "/v1/users" {
		t.Fatalf("no-trailing-slash base: upstream saw %+v", reqs)
	}
}

// TestHTTPRelayBaseNoSlash: /{vk}/api and /{vk}/api/ both reach the base
// path as stored, and both record tool_name "/".
func TestHTTPRelayBaseNoSlash(t *testing.T) {
	f := relayGET(t, nil)
	for _, p := range []string{"/a1/api", "/a1/api/"} {
		if rr := f.send(http.MethodGet, p, "", nil); rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d body %s", p, rr.Code, rr.Body.String())
		}
	}
	reqs := f.APIs["beta"].requests()
	if len(reqs) != 2 || reqs[0].EscapedPath != "/v1" || reqs[1].EscapedPath != "/v1" {
		t.Fatalf("upstream saw %q %q, want /v1 twice", reqs[0].EscapedPath, reqs[1].EscapedPath)
	}
	for _, row := range f.waitAuditN(models.LogFilter{VirtualKeyID: "a1"}, 2) {
		if row.ToolName != "/" {
			t.Errorf("tool_name %q, want /", row.ToolName)
		}
	}
}

// TestHTTPRequestHeaderRules covers security requirement 3.
func TestHTTPRequestHeaderRules(t *testing.T) {
	f := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1", Bearer: "stored-token-42"}}, false)
	hdr := map[string]string{
		"Authorization": "Bearer " + f.Key, "X-Api-Key": f.Key, "Cookie": "session=abc",
		"Proxy-Authorization": "Basic x", "X-Forwarded-For": "10.0.0.1", "Accept-Encoding": "br",
		"Connection": "X-Custom", "X-Custom": "hop", "X-HTTP-Method-Override": "DELETE",
		"X-Original-URL": "/admin", "True-Client-IP": "10.0.0.2", "Private-Token": f.Key,
		"X-Notes":              "carries " + f.Key + " inside",
		"X-GitHub-Api-Version": "2022-11-28", "If-None-Match": `"abc"`, "Idempotency-Key": "k1",
		"Accept": "application/vnd.github+json", "Notion-Version": "2022-06-28",
	}
	rr := f.send(http.MethodGet, "/a1/api/user", "", hdr)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	reqs := f.APIs["beta"].requests()
	if len(reqs) != 1 {
		t.Fatalf("%d upstream requests", len(reqs))
	}
	got := reqs[0].Header
	for _, name := range []string{"X-Api-Key", "Cookie", "Proxy-Authorization", "X-Forwarded-For", "Connection", "X-Custom",
		"X-HTTP-Method-Override", "X-Original-URL", "True-Client-IP", "Private-Token", "X-Notes"} {
		if v := got.Values(name); len(v) != 0 {
			t.Errorf("%s reached the upstream: %v", name, v)
		}
	}
	// Accept-Encoding is Go's own, not the client's br.
	if v := got.Get("Accept-Encoding"); v == "br" {
		t.Errorf("client Accept-Encoding crossed: %q", v)
	}
	if got.Get("Host") == "localhost:8080" || reqs[0].Host != strings.TrimPrefix(f.APIs["beta"].srv.URL, "http://") {
		t.Errorf("Host = %q, want the upstream's own", reqs[0].Host)
	}
	for name, want := range map[string]string{"X-GitHub-Api-Version": "2022-11-28", "If-None-Match": `"abc"`, "Idempotency-Key": "k1",
		"Accept": "application/vnd.github+json", "Notion-Version": "2022-06-28", "Authorization": "Bearer stored-token-42"} {
		if v := got.Get(name); v != want {
			t.Errorf("%s = %q, want %q", name, v, want)
		}
	}
	for name, vals := range got {
		for _, v := range vals {
			if strings.Contains(v, f.Key) {
				t.Errorf("%s carried the virtual key: %q", name, v)
			}
		}
	}

	// An underscore-named header never crosses, whatever it carries.
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/a1/api/user", nil)
	req.Header.Set("Authorization", "Bearer "+f.Key)
	req.Header["X_Api_Key"] = []string{"under"}
	req.Header["X_HTTP_Method_Override"] = []string{"DELETE"}
	rec := httptest.NewRecorder()
	f.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	last := f.APIs["beta"].requests()[1].Header
	for name := range last {
		if strings.Contains(name, "_") {
			t.Errorf("underscore header %s crossed", name)
		}
	}

	// A client-sent header with the credential's own name arrives carrying
	// the stored value, on the custom auth type too.
	g := newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1"}}, false)
	enc, err := g.H.keys.Seal([]byte(`{"headers":{"X-Vendor-Key":"stored-vendor"}}`))
	if err != nil {
		t.Fatal(err)
	}
	up, err := g.Store.GetUpstream(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}
	up.AuthType, up.AuthConfig = models.AuthCustom, []byte(enc)
	if err := g.Store.UpdateUpstream(context.Background(), up, false, true); err != nil {
		t.Fatal(err)
	}
	if rr := g.send(http.MethodGet, "/a1/api/user", "", map[string]string{"X-Vendor-Key": "client-value"}); rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if v := g.APIs["beta"].requests()[0].Header.Values("X-Vendor-Key"); len(v) != 1 || v[0] != "stored-vendor" {
		t.Errorf("X-Vendor-Key = %v, want the stored value alone", v)
	}
}

// TestHTTPKeyInRequestRefused: the virtual key in the query or the path is
// refused before any dial, and never reaches the row.
func TestHTTPKeyInRequestRefused(t *testing.T) {
	f := relayGET(t, nil)
	// Every byte of the key percent-encoded: a spelling the literal check
	// misses and the upstream would decode.
	var encoded strings.Builder
	for i := 0; i < len(f.Key); i++ {
		fmt.Fprintf(&encoded, "%%%02X", f.Key[i])
	}
	refused := []string{
		"/a1/api/x?foo=" + f.Key,
		"/a1/api/" + f.Key + "/x",
		"/a1/api/x?foo=" + url.QueryEscape("pre "+f.Key),
		"/a1/api/x?" + f.Key + "=1",                                        // the key as a parameter's name
		"/a1/api/" + encoded.String() + "/x",                               // the key percent-encoded in the path
		"/a1/api/" + strings.Repeat("a", auditFieldBytes-6) + f.Key + "/x", // the key straddling the tool_name bound
	}
	for _, p := range refused {
		rr := f.send(http.MethodGet, p, "", nil)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d body %s", p, rr.Code, rr.Body.String())
			continue
		}
		if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "request carries the virtual key" {
			t.Errorf("body %s", rr.Body.String())
		}
	}
	if n := len(f.APIs["beta"].requests()); n != 0 {
		t.Fatalf("%d requests reached the upstream", n)
	}
	// The key inside a header the door relays (the sweep drops the header
	// from the upstream request, and the row must not keep it either).
	rr := f.send(http.MethodGet, "/a1/api/user", "", map[string]string{"Content-Type": "text/plain; k=" + f.Key})
	if rr.Code != http.StatusOK {
		t.Fatalf("content-type case: status %d body %s", rr.Code, rr.Body.String())
	}
	// A key is pory_ plus hex, so ten bytes of it is a needle nothing else
	// in a row can match, and one that a key cut at the tool_name bound
	// would still leave behind.
	needle := f.Key[:10]
	rows := f.waitAuditN(models.LogFilter{VirtualKeyID: "a1"}, len(refused)+1)
	for _, row := range rows {
		if strings.Contains(string(row.Params), needle) || strings.Contains(row.ToolName, needle) || strings.Contains(row.ErrorMessage, needle) {
			t.Errorf("the key reached a row: %+v", row)
		}
		if strings.Contains(string(row.Params), f.Key[len(f.Key)-10:]) {
			t.Errorf("the key's tail reached a row: %+v", row)
		}
	}
	if got := rows[0]; got.Status != models.StatusSuccess || !strings.Contains(string(got.Params), `"content_type":"[redacted]"`) {
		t.Errorf("content-type row: %+v", got)
	}
	for _, row := range rows[1:] {
		if row.Status != models.StatusError {
			t.Errorf("row status %q: %+v", row.Status, row)
		}
	}
	for _, row := range rows[len(rows)-3:] {
		if row.ToolName != "/x" && row.ToolName != "/[redacted]" {
			t.Errorf("tool_name %q", row.ToolName)
		}
	}
}

// TestHTTPResponseHeaderRules covers security requirement 4.
func TestHTTPResponseHeaderRules(t *testing.T) {
	f := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Set-Cookie", "sid=1")
		h.Set("WWW-Authenticate", "Bearer realm=x")
		h.Set("Access-Control-Allow-Origin", "https://evil.example")
		h.Set("Content-Security-Policy", "default-src *")
		h.Set("Server", "vendor/1")
		h.Set("Cache-Control", "max-age=60")
		h.Set("Refresh", "0; url=https://evil.example")
		h.Set("Clear-Site-Data", `"*"`)
		h.Set("Content-Encoding", "identity")
		h.Add("Vary", "Accept")
		h.Set("ETag", `"v9"`)
		h.Add("Link", `<https://api.example/next>; rel="next"`)
		h.Add("Link", `<https://api.example/last>; rel="last"`)
		h.Set("X-RateLimit-Remaining", "41")
		h.Set("Retry-After", "7")
		h.Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	rr := f.send(http.MethodGet, "/a1/api/user", "", map[string]string{"Origin": "https://app.example"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	h := rr.Header()
	for _, name := range []string{"Set-Cookie", "WWW-Authenticate", "Content-Security-Policy", "Server", "Refresh", "Clear-Site-Data", "Content-Encoding"} {
		if v := h.Values(name); len(v) != 0 {
			t.Errorf("%s reached the client: %v", name, v)
		}
	}
	if got := h.Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("Access-Control-Allow-Origin = %q, want PoryMCP's own", got)
	}
	if got := h.Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Errorf("Vary = %v, want PoryMCP's Origin alone", got)
	}
	if got := h.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	for name, want := range map[string]string{"ETag": `"v9"`, "X-RateLimit-Remaining": "41", "Retry-After": "7", "Content-Type": "application/json"} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if links := h.Values("Link"); len(links) != 2 {
		t.Errorf("Link = %v, want both values", links)
	}

	// No upstream Content-Type: octet-stream, never a sniffed text/html.
	g := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = io.WriteString(w, "<html><script>alert(1)</script></html>")
	})
	rr = g.send(http.MethodGet, "/a1/api/page", "", nil)
	if got := rr.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
}

// TestHTTPRedirectRefusedNotModifiedRelayed covers security requirement 5
// through the door.
func TestHTTPRedirectRefusedNotModifiedRelayed(t *testing.T) {
	f := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/login?code=SECRET_MARKER")
		w.WriteHeader(http.StatusFound)
	})
	rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
	if rr.Code != http.StatusBadGateway || rr.Header().Get("Location") != "" {
		t.Fatalf("status %d Location %q body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "upstream request failed" {
		t.Errorf("body %s", rr.Body.String())
	}
	row := f.lastRow(1)
	if row.Status != models.StatusError || row.ErrorMessage != "upstream redirected to elsewhere.example" {
		t.Errorf("row = %+v", row)
	}

	g := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusNotModified)
	})
	rr = g.send(http.MethodGet, "/a1/api/user", "", map[string]string{"If-None-Match": `"v1"`})
	if rr.Code != http.StatusNotModified || rr.Body.Len() != 0 || rr.Header().Get("ETag") != `"v1"` {
		t.Fatalf("status %d body %q ETag %q", rr.Code, rr.Body.String(), rr.Header().Get("ETag"))
	}
	if row := g.lastRow(1); row.Status != models.StatusSuccess || row.ResponseSizeBytes != 0 {
		t.Errorf("row = %+v", row)
	}
}

// TestHTTPMethodAllowlist covers security requirements 7 and 8.
func TestHTTPMethodAllowlist(t *testing.T) {
	f := relayGET(t, nil)
	f.setHTTPMethods([]string{"GET", "HEAD"})
	rr := f.send(http.MethodPost, "/a1/api/user/repos", "{}", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "method not allowed by virtual key" || m["request_id"] == "" {
		t.Errorf("body %s", rr.Body.String())
	}
	if row := f.lastRow(1); row.Status != models.StatusBlocked || row.ErrorMessage != "blocked by virtual key http_methods" || row.ToolName != "/user/repos" {
		t.Errorf("row = %+v", row)
	}
	if n := len(f.APIs["beta"].requests()); n != 0 {
		t.Fatalf("the refused POST reached the upstream")
	}
	if rr := f.send(http.MethodGet, "/a1/api/user", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("GET: status %d", rr.Code)
	}

	for _, corrupt := range []string{"not json", "", `["FETCH"]`, "null"} {
		g := relayGET(t, nil)
		g.setColumn("virtual_keys", "http_methods", "a1", corrupt)
		rr := g.send(http.MethodGet, "/a1/api/user", "", nil)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%q: status %d", corrupt, rr.Code)
		}
		if row := g.lastRow(1); row.Status != models.StatusBlocked || row.ErrorMessage != "blocked: virtual key http_methods could not be decoded" {
			t.Errorf("%q: row = %+v", corrupt, row)
		}
		if n := len(g.APIs["beta"].requests()); n != 0 {
			t.Errorf("%q: the upstream saw a request", corrupt)
		}
	}
}

// TestHTTPRelayToolListsIgnored: tool rules judge tool names, and a relayed
// request has none, so an unreadable tool list does not touch this door.
func TestHTTPRelayToolListsIgnored(t *testing.T) {
	f := relayGET(t, nil)
	f.setColumn("virtual_keys", "tool_denylist", "a1", `["unterminated`)
	if rr := f.send(http.MethodGet, "/a1/api/user", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if rr := f.mcpPost("/a1/mcp", listRPC); rr.Code == http.StatusOK {
		t.Fatalf("the MCP door served a key bound to an http upstream")
	}
}

// TestHTTPGroupMember covers security requirement 9 through the relay half.
func TestHTTPGroupMember(t *testing.T) {
	f := newRelayFixture(t,
		map[string]upstreamSpec{"alpha": {Tools: []string{"a"}}},
		map[string]httpSpec{"beta": {Base: "/v1", Bearer: "b"}}, true)
	if rr := f.send(http.MethodGet, "/a1/beta/api/x", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("member relay: status %d body %s", rr.Code, rr.Body.String())
	}
	if reqs := f.APIs["beta"].requests(); len(reqs) != 1 || reqs[0].EscapedPath != "/v1/x" {
		t.Fatalf("upstream saw %+v", reqs)
	}
	if row := f.lastRow(1); row.ToolName != "/x" || row.UpstreamID != "h1" || row.Status != models.StatusSuccess {
		t.Errorf("row = %+v", row)
	}
	for _, p := range []string{"/a1/alpha/api/x", "/a1/api/x", "/a1/gamma/api/x", "/a1/beta/api"} {
		rr := f.send(http.MethodGet, p, "", nil)
		want := http.StatusNotFound
		if p == "/a1/beta/api" {
			want = http.StatusOK
		}
		if rr.Code != want {
			t.Errorf("%s: status %d body %s, want %d", p, rr.Code, rr.Body.String(), want)
		}
	}
	if n := f.totalReqs("alpha"); n != 0 {
		t.Errorf("the mcp member saw %d requests through /api/", n)
	}
	if rr := f.send(http.MethodGet, "/a1/beta/api/y", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	rows := f.waitAuditN(models.LogFilter{VirtualKeyID: "a1", Status: models.StatusBlocked}, 3)
	for _, row := range rows {
		if !strings.HasPrefix(row.ToolName, "/") {
			t.Errorf("blocked relay row without the / marker: %+v", row)
		}
	}
}

// TestHTTPGroupKeySingleDoorIs404 covers security requirement 11: a group
// key on the single door is the uniform 404 whatever the group holds, so a
// group with no HTTP API member, or no enabled member, does not show through
// as a 400 carrying the resolver's sentence.
func TestHTTPGroupKeySingleDoorIs404(t *testing.T) {
	f := newRelayFixture(t, map[string]upstreamSpec{"alpha": {Tools: []string{"a"}}}, map[string]httpSpec{}, true)
	rr := f.send(http.MethodGet, "/a1/api/x", "", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "unknown endpoint" {
		t.Errorf("body %s", rr.Body.String())
	}
	if row := f.lastRow(1); row.Status != models.StatusBlocked || row.ToolName != "/x" {
		t.Errorf("row = %+v", row)
	}
}

// TestHTTPRefusalsArePlainJSON covers security requirements 6, 11 and 16.
func TestHTTPRefusalsArePlainJSON(t *testing.T) {
	check := func(t *testing.T, rr *httptest.ResponseRecorder, status int, msg string) {
		t.Helper()
		if rr.Code != status {
			t.Fatalf("status %d body %s, want %d", rr.Code, rr.Body.String(), status)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type %q", ct)
		}
		m := jsonBody(t, rr.Body.Bytes())
		if m["error"] != msg || m["jsonrpc"] != nil {
			t.Errorf("body %s, want error %q and no jsonrpc member", rr.Body.String(), msg)
		}
		if id, _ := m["request_id"].(string); id == "" {
			t.Errorf("no request_id in %s", rr.Body.String())
		}
	}
	f := relayGET(t, nil)
	check(t, f.send(http.MethodGet, "/zz/api/x", "", nil), http.StatusForbidden, "virtual key does not match this endpoint")

	ctx := context.Background()
	k, _ := f.Store.GetVirtualKey(ctx, "a1")
	now := time.Now().UTC()
	k.RevokedAt = &now
	if err := f.Store.UpdateVirtualKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	check(t, f.send(http.MethodGet, "/a1/api/x", "", nil), http.StatusUnauthorized, "virtual key revoked")
	k.RevokedAt = nil
	one := 1
	k.RateLimit = &one
	if err := f.Store.UpdateVirtualKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	f.send(http.MethodGet, "/a1/api/x", "", nil)
	rr := f.send(http.MethodGet, "/a1/api/x", "", nil)
	check(t, rr, http.StatusTooManyRequests, "rate limit exceeded")
	if ra := rr.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After = %q on the relay 429", ra)
	}

	// An upstream body over 16 MiB is 502; a request body over 8 MiB is 413
	// and is seen by no upstream.
	big := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(make([]byte, 16<<20+1))
	})
	check(t, big.send(http.MethodGet, "/a1/api/blob", "", nil), http.StatusBadGateway, "upstream request failed")
	if row := big.lastRow(1); row.ErrorMessage != "upstream body exceeds 16777216 bytes" {
		t.Errorf("row = %+v", row)
	}
	huge := relayGET(t, nil)
	check(t, huge.send(http.MethodPost, "/a1/api/upload", strings.Repeat("x", 8<<20+1), nil), http.StatusRequestEntityTooLarge, "request body too large")
	if n := len(huge.APIs["beta"].requests()); n != 0 {
		t.Errorf("the oversized body reached the upstream")
	}
	if row := huge.lastRow(1); row.Status != models.StatusError || row.ErrorMessage != "request body too large" {
		t.Errorf("row = %+v", row)
	}
	// Exactly the cap is relayed.
	exact := relayGET(t, nil)
	if rr := exact.send(http.MethodPost, "/a1/api/upload", strings.Repeat("x", 8<<20), nil); rr.Code != http.StatusOK {
		t.Errorf("a body of exactly the cap: status %d", rr.Code)
	}
}

// TestHTTPRelayAuditBounds covers security requirements 10 and 11: every
// client-controlled string on a relay row is escaped and bounded, a large
// query is a marker beside the other two members, and no transport error
// text reaches a row.
func TestHTTPRelayAuditBounds(t *testing.T) {
	f := relayGET(t, nil)
	long := strings.Repeat("a", 300)
	var q strings.Builder
	for i := 0; i < 2000; i++ {
		q.WriteString("k" + strconv.Itoa(i) + "=v&")
	}
	rr := f.send(http.MethodGet, "/a1/api/"+long+"/x%0a?"+q.String(), "",
		map[string]string{"X-Request-Id": strings.Repeat("r", 300), "Content-Type": strings.Repeat("c", 300)})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	row := f.lastRow(1)
	if len(row.ToolName) != auditFieldBytes || !strings.HasPrefix(row.ToolName, "/aaa") {
		t.Errorf("tool_name len %d = %q", len(row.ToolName), row.ToolName)
	}
	if len(row.RequestID) != auditFieldBytes {
		t.Errorf("request_id len %d", len(row.RequestID))
	}
	var params struct {
		Query        json.RawMessage `json:"query"`
		ContentType  string          `json:"content_type"`
		RequestBytes *int            `json:"request_bytes"`
	}
	if err := json.Unmarshal(row.Params, &params); err != nil {
		t.Fatalf("params %s: %v", row.Params, err)
	}
	if !strings.Contains(string(params.Query), `"truncated":true`) || len(params.ContentType) != auditFieldBytes || params.RequestBytes == nil {
		t.Errorf("params = %s", row.Params)
	}
	short := f.send(http.MethodGet, "/a1/api/x%0ay", "", nil)
	if short.Code != http.StatusOK {
		t.Fatalf("status %d", short.Code)
	}
	if row := f.lastRow(2); row.ToolName != "/x%0ay" {
		t.Errorf("tool_name %q, want the escaped form", row.ToolName)
	}

	// A dead upstream: one closed sentence, never the outbound URL.
	dead := relayGET(t, nil)
	dead.APIs["beta"].srv.Close()
	rr = dead.send(http.MethodGet, "/a1/api/x?secret=SECRET_MARKER", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rr.Code)
	}
	if row := dead.lastRow(1); !strings.HasPrefix(row.ErrorMessage, "cannot connect to 127.0.0.1:") || strings.Contains(row.ErrorMessage, "SECRET") {
		t.Errorf("row = %+v", row)
	}
}

// TestHTTPRelayBudget: a stub that never answers records the relay's own
// budget sentence, not discovery's ten seconds.
func TestHTTPRelayBudget(t *testing.T) {
	saved := answerBudget
	answerBudget = 150 * time.Millisecond
	t.Cleanup(func() { answerBudget = saved })
	release := make(chan struct{})
	f := relayGET(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	rr := f.send(http.MethodGet, "/a1/api/slow", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rr.Code)
	}
	if row := f.lastRow(1); row.ErrorMessage != "upstream did not answer within 150ms" {
		t.Errorf("row = %+v", row)
	}
}

// TestHTTPRelay1xxIs502: a status outside 200 to 599 is not relayed.
func TestHTTPRelay1xxIs502(t *testing.T) {
	// net/http swallows every 1xx but 101 before the door sees a status, so
	// the one 1xx that can reach the guard is a 101, written raw on the
	// hijacked connection because a handler cannot send one through
	// WriteHeader.
	f := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")
		_ = buf.Flush()
	})
	rr := f.send(http.MethodGet, "/a1/api/x", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "upstream request failed" {
		t.Errorf("body %s", rr.Body.String())
	}
	if row := f.lastRow(1); row.Status != models.StatusError || row.ErrorMessage != "upstream answered 101" {
		t.Errorf("row = %+v", row)
	}
}

// TestHTTPRelayTouchesKey covers security requirement 16's last clause: a
// relayed request stamps the key's last_used_at, as the MCP door does after
// a forwarded call, and a refused one does not.
func TestHTTPRelayTouchesKey(t *testing.T) {
	f := relayGET(t, nil)
	f.setHTTPMethods([]string{"GET"})
	ctx := context.Background()
	if rr := f.send(http.MethodPost, "/a1/api/x", "", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("status %d", rr.Code)
	}
	f.lastRow(1)
	if k, err := f.Store.GetVirtualKey(ctx, "a1"); err != nil || k.LastUsedAt != nil {
		t.Fatalf("a refused request touched the key: %v %+v", err, k.LastUsedAt)
	}
	if rr := f.send(http.MethodGet, "/a1/api/x", "", nil); rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	f.lastRow(2)
	if k, err := f.Store.GetVirtualKey(ctx, "a1"); err != nil || k.LastUsedAt == nil {
		t.Fatalf("a relayed request left last_used_at unset: %v", err)
	}
}

// TestRelayPreflight covers security requirement 14: the relay door's own
// CORS answer, with the MCP door's unchanged beside it.
func TestRelayPreflight(t *testing.T) {
	f := relayGET(t, nil)
	req := httptest.NewRequest(http.MethodOptions, "http://localhost:8080/a1/api/x", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Headers", "Mcp-Param-Foo, X-Anything")
	rr := httptest.NewRecorder()
	f.Router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status %d", rr.Code)
	}
	h := rr.Header()
	if h.Get("Allow") != relayAllowedMethods || h.Get("Access-Control-Allow-Methods") != relayAllowedMethods {
		t.Errorf("Allow %q methods %q", h.Get("Allow"), h.Get("Access-Control-Allow-Methods"))
	}
	if h.Get("Access-Control-Allow-Headers") != relayAllowedHeaders {
		t.Errorf("Access-Control-Allow-Headers %q reflected something", h.Get("Access-Control-Allow-Headers"))
	}
	if h.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("Allow-Credentials set")
	}
	if h.Get("Access-Control-Expose-Headers") != "ETag, Link, Last-Modified, Retry-After, X-Request-Id" {
		t.Errorf("Expose %q", h.Get("Access-Control-Expose-Headers"))
	}
	if n := len(f.APIs["beta"].requests()); n != 0 {
		t.Errorf("a preflight reached the upstream")
	}

	req = httptest.NewRequest(http.MethodOptions, "http://localhost:8080/a1/mcp", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Headers", "Mcp-Param-Foo")
	rr = httptest.NewRecorder()
	f.Router.ServeHTTP(rr, req)
	h = rr.Header()
	if h.Get("Allow") != allowedMethods || h.Get("Access-Control-Allow-Headers") != allowedHeaders+", Mcp-Param-Foo" {
		t.Errorf("MCP preflight changed: Allow %q headers %q", h.Get("Allow"), h.Get("Access-Control-Allow-Headers"))
	}
}

// PORM-79 security requirements 4 and 11 on the relay door: the twin of
// TestProxyRefusedDialAudited. The row goes through upstreamFailureText and
// TransportFailure's first arm; the Warn line is the same helper's.
func TestRelayRefusedDialAudited(t *testing.T) {
	f := relayGET(t, nil)
	var logs bytes.Buffer
	cfg := *f.H.cfg
	cfg.UpstreamGuard = netguard.Options{}
	f.H = New(&cfg, f.Store, f.H.audit, slog.New(slog.NewJSONHandler(&logs, nil)))
	rt := chi.NewRouter()
	rt.HandleFunc(HTTPBaseRoute, f.H.ServeRelay)
	rt.HandleFunc(HTTPRoute, f.H.ServeRelay)
	f.Router = rt

	rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "upstream request failed" {
		t.Errorf("body %s", rr.Body.String())
	}
	row := f.lastRow(1)
	if row.Status != models.StatusError || row.ErrorMessage != "upstream address denied: loopback" {
		t.Fatalf("row = %+v, want the class sentence", row)
	}
	if n := len(f.APIs["beta"].requests()); n != 0 {
		t.Fatalf("the loopback API saw %d requests", n)
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

// PORM-191 amendment A4 on the relay door: a body that fails while it is
// read records the read sentences, the same row the MCP door writes, and
// never the read error's text.
func TestHTTPRelayReadFailureIsClosedSentence(t *testing.T) {
	f := relayGET(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, `{"cut":`)
	})
	logs := captureLogs(f.fixture)
	rr := f.send(http.MethodGet, "/a1/api/x?secret=SECRET_MARKER", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	row := f.lastRow(1)
	if row.ErrorMessage != "unexpected EOF" {
		t.Fatalf("error_message=%q, want unexpected EOF", row.ErrorMessage)
	}
	for _, leak := range []string{"SECRET", "read tcp", "127.0.0.1", "Get "} {
		if strings.Contains(row.ErrorMessage, leak) {
			t.Errorf("error_message=%q carries %q", row.ErrorMessage, leak)
		}
	}
	// warnDenied is reachable on an Open error only; a read error is never a
	// guard refusal.
	if strings.Contains(logs.String(), "upstream address denied") {
		t.Errorf("a read error wrote the guard's Warn line: %s", logs.String())
	}
}

// PORM-191 amendment A5 on the relay door: a client that hangs up before the
// answer is recorded as such, never as an upstream that refused.
func TestHTTPRelayClientWentAwayIsClosedSentence(t *testing.T) {
	f := relayGET(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	useFailingTransport(t, f.fixture, func(*http.Request) error {
		cancel()
		return context.Canceled
	})
	req := routedRequest(http.MethodGet, "/a1/api/x?secret=SECRET_MARKER", "").WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+f.Key)
	rr := httptest.NewRecorder()
	f.Router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	row := f.lastRow(1)
	if row.ErrorMessage != "client went away before the answer" {
		t.Fatalf("error_message=%q, want client went away before the answer", row.ErrorMessage)
	}
	if strings.Contains(row.ErrorMessage, "SECRET") || strings.Contains(row.ErrorMessage, "context canceled") {
		t.Errorf("error_message=%q carries the URL or Go's text", row.ErrorMessage)
	}
}

// relayToken is the stored credential of the PORM-204 relay tests: a
// 12-byte plain bearer that no pattern rule matches (secretLike is false for
// it), so every assertion below proves the literal pass and not the rules.
const relayToken = "abcdefghijkl"

// relayEcho is a relay fixture whose one HTTP API upstream stores relayToken
// and answers with h.
func relayEcho(t *testing.T, h http.HandlerFunc) *relayFixture {
	t.Helper()
	return newRelayFixture(t, nil, map[string]httpSpec{"beta": {Base: "/v1", Bearer: relayToken, Handler: h}}, false)
}

// sentBearer is the bearer the stub was given, read back from the request so
// a test proves the injected value is what gets redacted.
func sentBearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// assertNoHeaderLeak is assertNoLeak over every header name and value.
func assertNoHeaderLeak(t *testing.T, h http.Header, tok string) {
	t.Helper()
	for name, vals := range h {
		assertNoLeak(t, "header name "+name, name, fragments(tok)...)
		for _, v := range vals {
			assertNoLeak(t, "header "+name, v, fragments(tok)...)
		}
	}
}

// TestRelayResponseHeadersRedacted is PORM-204 security requirements 5 and 7
// (amendment A2): every relayed response header value takes the literal pass
// on every status, a header whose name carries the credential is dropped,
// Authorization never crosses, and on HEAD the upstream's Content-Length is
// copied as it is with no body and a row size of 0.
func TestRelayResponseHeadersRedacted(t *testing.T) {
	echo := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sent := sentBearer(r)
			w.Header().Set("X-Echo", "Bearer "+sent)
			w.Header().Set("Authorization", "Bearer "+sent)
			w.Header().Set("X-"+sent, "1")
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", "42")
				w.WriteHeader(status)
				return
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"login":"octocat"}`)
		}
	}
	check := func(t *testing.T, rr *httptest.ResponseRecorder) {
		t.Helper()
		if got := rr.Header().Get("X-Echo"); got != "Bearer [redacted]" {
			t.Errorf("X-Echo = %q, want Bearer [redacted]", got)
		}
		if got := rr.Header().Get("Authorization"); got != "" {
			t.Errorf("Authorization crossed: %q", got)
		}
		if got := rr.Header().Get("X-" + relayToken); got != "" {
			t.Errorf("a header named after the credential crossed: %q", got)
		}
		assertNoHeaderLeak(t, rr.Header(), relayToken)
	}
	t.Run("a 200 answer", func(t *testing.T) {
		f := relayEcho(t, echo(http.StatusOK))
		rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
		if rr.Code != http.StatusOK || rr.Body.String() != `{"login":"octocat"}` {
			t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
		}
		check(t, rr)
	})
	t.Run("a HEAD answered 401", func(t *testing.T) {
		f := relayEcho(t, echo(http.StatusUnauthorized))
		rr := f.send(http.MethodHead, "/a1/api/user", "", nil)
		if rr.Code != http.StatusUnauthorized || rr.Body.Len() != 0 {
			t.Fatalf("status %d body %q, want 401 and no body", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Content-Length"); got != "42" {
			t.Errorf("Content-Length = %q, want the upstream's 42", got)
		}
		check(t, rr)
		row := f.lastRow(1)
		if row.Status != models.StatusError || row.ErrorMessage != "upstream answered 401" || row.ResponseSizeBytes != 0 {
			t.Errorf("row = status %q error %q size %d", row.Status, row.ErrorMessage, row.ResponseSizeBytes)
		}
	})
	// Security requirement 5 on the one header that skips the pass: a HEAD
	// Content-Length crosses only as a single value that parses as a length,
	// because Go's HTTP/2 client leaves a non-numeric or repeated value in
	// the header rather than rejecting it.
	t.Run("a HEAD Content-Length crosses only as one number", func(t *testing.T) {
		for _, c := range []struct {
			name string
			vals []string
			want string
		}{
			{name: "one number", vals: []string{"42"}, want: "42"},
			{name: "text", vals: []string{relayToken}, want: ""},
			{name: "a number and text", vals: []string{"5", relayToken}, want: ""},
			{name: "negative", vals: []string{"-1"}, want: ""},
		} {
			src := http.Header{"Content-Length": c.vals}
			dst := http.Header{}
			copyRelayResponseHeaders(dst, src, true, []string{relayToken})
			if got := dst.Values("Content-Length"); strings.Join(got, ",") != c.want {
				t.Errorf("%s: Content-Length = %q, want %q", c.name, got, c.want)
			}
		}
	})
	// Security requirement 6: the names that describe the upstream's body are
	// dropped when the body was changed, and kept when it was not (the 404 in
	// TestRelayCleanErrorBodyCrossesAsSent).
	t.Run("a rewritten body drops the digest headers", func(t *testing.T) {
		f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"e"`)
			w.Header().Set("Content-Digest", "sha-256=:abc:")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"message":"invalid token `+sentBearer(r)+`"}`)
		})
		rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "[redacted]") {
			t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
		}
		for _, name := range []string{"ETag", "Content-Digest"} {
			if got := rr.Header().Get(name); got != "" {
				t.Errorf("%s = %q survived a rewritten body", name, got)
			}
		}
	})
}

// relayErrorRow asserts the row a redacted or withheld error answer leaves:
// status error, the fixed sentence msg, and a size equal to the bytes the
// client received (PORM-204 security requirements 7 and 8).
func relayErrorRow(t *testing.T, f *relayFixture, rr *httptest.ResponseRecorder, msg string) {
	t.Helper()
	if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length = %q, body is %d bytes", got, rr.Body.Len())
	}
	row := f.lastRow(1)
	if row.Status != models.StatusError || row.ErrorMessage != msg || row.ResponseSizeBytes != rr.Body.Len() {
		t.Errorf("row = status %q error %q size %d, want error %q size %d", row.Status, row.ErrorMessage, row.ResponseSizeBytes, msg, rr.Body.Len())
	}
}

// TestRelayErrorBodyToClientIsRedacted is the issue's first criterion and
// PORM-204 security requirements 1, 2, 7 and 8 (amendment A1): every 4xx and
// 5xx body is scanned whatever its label, the injected credential reads
// [redacted], the status and Content-Type are the upstream's, and
// Content-Length and the row describe the bytes sent. The trace_id case pins
// the over-redaction the issue's Risks section accepts.
func TestRelayErrorBodyToClientIsRedacted(t *testing.T) {
	tok := relayToken
	traceDoc := `{"message":"Not Found","request_id":"8f3c2a1b9d7e4f60a5b3c2d1e0f98765"}`
	cases := []struct {
		name   string
		status int
		ct     string // "" means the stub sends no Content-Type at all
		body   string
		equals string   // the exact client body, when it is one
		wants  []string // substrings the client body must carry
		json   bool     // the client body must still parse
	}{
		{name: "json", status: 401, ct: "application/json", body: `{"message":"invalid token ` + tok + `"}`, equals: `{"message":"invalid token [redacted]"}`, json: true},
		{name: "html", status: 401, ct: "text/html; charset=utf-8", body: `<pre>Authorization: Bearer ` + tok + `</pre>`, wants: []string{"Bearer [redacted]"}},
		{name: "plain", status: 403, ct: "text/plain", body: "invalid token " + tok, equals: "invalid token [redacted]"},
		{name: "problem_json", status: 401, ct: "application/problem+json", body: `{"title":"Unauthorized","detail":"token ` + tok + ` is not valid"}`, wants: []string{"[redacted]", "Unauthorized"}, json: true},
		{name: "trace_id", status: 404, ct: "application/json", body: traceDoc, wants: []string{`"request_id":"[redacted]"`, `"message":"Not Found"`}, json: true},
		{name: "no_label", status: 401, ct: "", body: "invalid token " + tok, equals: "invalid token [redacted]"},
		{name: "jsonrpc_envelope", status: 400, ct: "application/json", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"invalid key","data":"` + tok + `"}}`, wants: []string{"[redacted]", "invalid key"}, json: true},
		{name: "event_stream", status: 401, ct: "text/event-stream", body: "data: invalid token " + tok + "\n\n", equals: "data: invalid token [redacted]\n\n"},
		{name: "invalid_utf8", status: 401, ct: "text/plain", body: "\xff invalid token " + tok, wants: []string{"[redacted]"}},
		{name: "octet_stream", status: 401, ct: "application/octet-stream", body: "invalid token " + tok, equals: "invalid token [redacted]"},
		{name: "xml", status: 401, ct: "application/xml", body: "<error>invalid token " + tok + "</error>", equals: "<error>invalid token [redacted]</error>"},
		{name: "png", status: 400, ct: "image/png", body: "\x89PNG " + tok, wants: []string{"[redacted]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
				if c.ct == "" {
					w.Header()["Content-Type"] = nil // key present: no sniffing, nothing written
				} else {
					w.Header().Set("Content-Type", c.ct)
				}
				w.WriteHeader(c.status)
				_, _ = io.WriteString(w, strings.ReplaceAll(c.body, tok, sentBearer(r)))
			})
			rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
			if rr.Code != c.status {
				t.Fatalf("status %d body %q, want %d", rr.Code, rr.Body.String(), c.status)
			}
			wantCT := c.ct
			if wantCT == "" {
				wantCT = "application/octet-stream"
			}
			if got := rr.Header().Get("Content-Type"); got != wantCT {
				t.Errorf("Content-Type = %q, want %q", got, wantCT)
			}
			body := rr.Body.String()
			if c.equals != "" && body != c.equals {
				t.Errorf("body = %q, want %q", body, c.equals)
			}
			for _, w := range c.wants {
				if !strings.Contains(body, w) {
					t.Errorf("body %q lacks %q", body, w)
				}
			}
			if c.json && !json.Valid(rr.Body.Bytes()) {
				t.Errorf("body no longer parses: %q", body)
			}
			assertNoLeak(t, c.name, body, fragments(tok)...)
			relayErrorRow(t, f, rr, "upstream answered "+strconv.Itoa(c.status))
		})
	}
}

// TestRelayCleanErrorBodyCrossesAsSent is the issue's second criterion as
// amended (A4) and security requirement 10: a 4xx or 5xx body of 64 KiB or
// less with nothing credential-shaped crosses byte for byte with its digest
// headers, and a 2xx body crosses byte for byte even when it echoes the
// credential (PORM-87's scope).
func TestRelayCleanErrorBodyCrossesAsSent(t *testing.T) {
	tok := relayToken
	cases := []struct {
		name   string
		status int
		ct     string
		body   string
	}{
		{name: "clean 404 json", status: 404, ct: "application/json", body: `{"message":"Not Found"}`},
		{name: "clean 500 html", status: 500, ct: "text/html", body: "<p>Server error</p>"},
		{name: "a 200 that echoes the token", status: 200, ct: "application/json", body: `{"echo":"Bearer ` + tok + `"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", c.ct)
				w.Header().Set("ETag", `"e"`)
				w.Header().Set("Content-Digest", "sha-256=:abc:")
				w.WriteHeader(c.status)
				_, _ = io.WriteString(w, strings.ReplaceAll(c.body, tok, sentBearer(r)))
			})
			rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
			if rr.Code != c.status || !bytes.Equal(rr.Body.Bytes(), []byte(c.body)) {
				t.Fatalf("status %d body %q, want %d and %q", rr.Code, rr.Body.String(), c.status, c.body)
			}
			for name, want := range map[string]string{"ETag": `"e"`, "Content-Digest": "sha-256=:abc:", "Content-Length": strconv.Itoa(len(c.body))} {
				if got := rr.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if row := f.lastRow(1); row.ResponseSizeBytes != len(c.body) {
				t.Errorf("response_size_bytes = %d, want %d", row.ResponseSizeBytes, len(c.body))
			}
		})
	}
}

// TestRelayErrorBodyAcrossTheClientBound is PORM-204 security requirements
// 3 and 7 and amendment A4: the literal pass sees the whole body before the
// cut, a clean body over 64 KiB is cut at a value boundary with no marker,
// and a JSON-opening body over the bound with no escape is cut, not
// withheld.
func TestRelayErrorBodyAcrossTheClientBound(t *testing.T) {
	tok := relayToken
	t.Run("a literal straddling the cut", func(t *testing.T) {
		f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, strings.Repeat("x", clientMessageBytes-10)+sentBearer(r)+" tail")
		})
		rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rr.Code)
		}
		assertNoLeak(t, "relay body", rr.Body.String(), fragments(tok)...)
		if rr.Body.Len() > clientMessageBytes+len("[redacted]") {
			t.Errorf("body is %d bytes, want at most the window plus the marker", rr.Body.Len())
		}
		relayErrorRow(t, f, rr, "upstream answered 401")
	})
	t.Run("a clean body over the bound is cut at a boundary", func(t *testing.T) {
		body := strings.Repeat("word ", 40<<10) // 200 KiB
		f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, body)
		})
		rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
		got := rr.Body.String()
		if rr.Code != http.StatusUnauthorized || !strings.HasPrefix(body, got) {
			t.Fatalf("status %d, body is not a prefix of the upstream's", rr.Code)
		}
		if len(got) > clientMessageBytes || len(got) == 0 || got[len(got)-1] != ' ' {
			t.Errorf("cut body is %d bytes ending %q, want at most %d ending at a space", len(got), got[max(0, len(got)-5):], clientMessageBytes)
		}
		if strings.Contains(got, "[redacted]") {
			t.Error("a clean body carries a marker")
		}
		relayErrorRow(t, f, rr, "upstream answered 401")
	})
	t.Run("a JSON opener over the bound with no escape is cut, not withheld", func(t *testing.T) {
		f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "{"+strings.Repeat(" ", clientMessageBytes)+`"`+sentBearer(r)+`"`)
		})
		rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
		if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "withheld") {
			t.Fatalf("status %d body %q, want a cut 401", rr.Code, truncateForLog(rr.Body.Bytes()))
		}
		if rr.Body.Len() > clientMessageBytes || !strings.HasPrefix(rr.Body.String(), "{ ") {
			t.Errorf("body is %d bytes opening %q, want a cut prefix of the upstream's at most %d bytes", rr.Body.Len(), truncateForLog(rr.Body.Bytes()[:min(rr.Body.Len(), 4)]), clientMessageBytes)
		}
		assertNoLeak(t, "relay body", rr.Body.String(), fragments(tok)...)
		relayErrorRow(t, f, rr, "upstream answered 401")
	})
}

// TestRelayUnscannable is PORM-204 security requirement 4 (amendment A3):
// the checks that send an error answer to the withheld branch because
// neither pass could read it, including a coding hidden behind identity on
// a second line or in a list, and a charset behind a malformed label.
func TestRelayUnscannable(t *testing.T) {
	cases := []struct {
		name string
		enc  []string
		ct   string
		ct2  string // a second Content-Type line, when set
		body string
		want bool
	}{
		{name: "plain", ct: "text/plain", body: "x"},
		{name: "identity", enc: []string{"identity"}, ct: "text/plain", body: "x"},
		{name: "gzip", enc: []string{"gzip"}, ct: "text/plain", body: "x", want: true},
		{name: "br", enc: []string{"br"}, ct: "text/plain", body: "x", want: true},
		{name: "identity and br in one value", enc: []string{"identity, br"}, body: "x", want: true},
		{name: "identity then br on two lines", enc: []string{"identity", "br"}, body: "x", want: true},
		{name: "utf-8 charset", ct: "text/plain; charset=utf-8", body: "x"},
		{name: "UTF-16 charset", ct: "text/plain; charset=UTF-16", body: "x", want: true},
		{name: "utf-16le charset", ct: "text/plain; charset=utf-16le", body: "x", want: true},
		{name: "utf-32 charset", ct: "text/plain; charset=utf-32", body: "x", want: true},
		{name: "malformed label naming utf-16", ct: "text/plain; charset=utf-16; x", body: "x", want: true},
		{name: "duplicate charset", ct: "text/plain; charset=utf-16; charset=utf-8", body: "x", want: true},
		{name: "utf16 without the hyphen", ct: "text/plain; charset=utf16", body: "x", want: true},
		{name: "utf_16 with an underscore", ct: "text/plain; charset=utf_16", body: "x", want: true},
		{name: "ucs-2", ct: "text/plain; charset=ucs-2", body: "x", want: true},
		{name: "unicode alias", ct: "text/plain; charset=unicode", body: "x", want: true},
		{name: "unicodefffe alias", ct: "text/plain; charset=unicodeFFFE", body: "x", want: true},
		{name: "ucs-4", ct: "text/plain; charset=ucs-4", body: "x", want: true},
		{name: "utf-16 on a second Content-Type line", ct: "text/plain", ct2: "text/plain; charset=utf-16le", body: "x", want: true},
		{name: "utf-16 BE mark", ct: "text/plain", body: "\xfe\xffx", want: true},
		{name: "utf-16 LE mark", ct: "text/plain", body: "\xff\xfex", want: true},
		{name: "utf-32 BE mark", ct: "text/plain", body: "\x00\x00\xfe\xffx", want: true},
		{name: "utf-32 LE mark", ct: "text/plain", body: "\xff\xfe\x00\x00x", want: true},
		{name: "utf-8 mark is readable", ct: "text/plain", body: "\xef\xbb\xbfx"},
		{name: "no label at all", body: "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			for _, e := range c.enc {
				h.Add("Content-Encoding", e)
			}
			if c.ct != "" {
				h.Set("Content-Type", c.ct)
			}
			if c.ct2 != "" {
				h.Add("Content-Type", c.ct2)
			}
			if got := relayUnscannable(h, []byte(c.body)); got != c.want {
				t.Errorf("relayUnscannable = %v, want %v", got, c.want)
			}
		})
	}
}

// TestRelayErrorBodyWithheld is PORM-204 security requirements 4, 6, 7 and 8
// (amendment A3): a body the pass cannot rewrite or read is withheld under
// the upstream's status with its redacted headers, minus the names that
// described its body, and no byte of the upstream body crosses.
func TestRelayErrorBodyWithheld(t *testing.T) {
	tok := relayToken
	escaped := escapeEvery(tok, 1)
	cases := []struct {
		name   string
		status int
		hdr    map[string]string
		body   func(sent string) string
	}{
		{name: "escaped credential in the window of over-bound JSON", status: 429,
			hdr: map[string]string{"Content-Type": "application/json", "Retry-After": "7", "ETag": `"x"`, "Content-Digest": "sha-256=:abc:"},
			body: func(sent string) string {
				return `{"m":"` + escapeEvery(sent, 1) + `","pad":"` + strings.Repeat("x", clientMessageBytes) + `"}`
			}},
		{name: "an encoding the transport did not decode", status: 401,
			hdr:  map[string]string{"Content-Type": "text/plain", "Content-Encoding": "br"},
			body: func(sent string) string { return "invalid token " + sent }},
		{name: "a utf-16 charset", status: 401,
			hdr:  map[string]string{"Content-Type": "text/plain; charset=utf-16"},
			body: func(sent string) string { return "invalid token " + sent }},
		{name: "a utf-16 byte order mark", status: 401,
			hdr:  map[string]string{"Content-Type": "text/plain"},
			body: func(sent string) string { return "\xff\xfeinvalid token " + sent }},
		{name: "JSON nested past the walk depth", status: 401,
			hdr:  map[string]string{"Content-Type": "application/json"},
			body: func(string) string { return strings.Repeat("[", 40) + strings.Repeat("]", 40) }},
		{name: "JSON the text pass would break", status: 401,
			hdr:  map[string]string{"Content-Type": "application/json"},
			body: func(string) string { return `{"api_key":"k9f2x7q1\"x"}` }}, // the json_escape_after_label row of TestRedactRefusal
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := relayEcho(t, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range c.hdr {
					w.Header().Set(k, v)
				}
				w.WriteHeader(c.status)
				_, _ = io.WriteString(w, c.body(sentBearer(r)))
			})
			rr := f.send(http.MethodGet, "/a1/api/user", "", nil)
			if rr.Code != c.status {
				t.Fatalf("status %d body %q, want the upstream's %d", rr.Code, truncateForLog(rr.Body.Bytes()), c.status)
			}
			var got struct {
				Error     string `json:"error"`
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || got.Error != "upstream error body withheld" || got.RequestID == "" {
				t.Fatalf("body %q, want the withheld sentence with a request id (%v)", truncateForLog(rr.Body.Bytes()), err)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			assertNoLeak(t, "withheld body", rr.Body.String(), append(fragments(tok), fragments(escaped)...)...)
			assertNoHeaderLeak(t, rr.Header(), tok)
			if c.hdr["Retry-After"] != "" && rr.Header().Get("Retry-After") != c.hdr["Retry-After"] {
				t.Errorf("Retry-After = %q, want the upstream's %q", rr.Header().Get("Retry-After"), c.hdr["Retry-After"])
			}
			for _, name := range []string{"ETag", "Content-Digest", "Content-Encoding"} {
				if v := rr.Header().Get(name); v != "" {
					t.Errorf("%s = %q crossed on a withheld body", name, v)
				}
			}
			relayErrorRow(t, f, rr, "upstream answered "+strconv.Itoa(c.status)+", body withheld")
			if row := f.lastRow(1); row.RequestID != got.RequestID {
				t.Errorf("request_id %q in the body, %q on the row", got.RequestID, row.RequestID)
			}
			if k, err := f.Store.GetVirtualKey(context.Background(), "a1"); err != nil || k.LastUsedAt == nil {
				t.Errorf("a withheld answer left last_used_at unset: %v", err)
			}
		})
	}
}
