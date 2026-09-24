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
	if row := g.lastRow(1); row.Status != models.StatusSuccess {
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
