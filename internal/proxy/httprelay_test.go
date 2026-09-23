package proxy

// The relay door's tests (PORM-146) and the fixture they share. Everything
// here wraps the MCP fixture in fixture_test.go through what it exports (H,
// Key, Store, DBPath, Router) and never edits it: the criterion that every
// existing proxy test passes unmodified is proved by
// git diff --exit-code <base> -- 'internal/proxy/*_test.go', and this file is
// new.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/danjonesio/porymcp/internal/models"
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
	req := httptest.NewRequest(method, "http://localhost:8080"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.Key)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.Router.ServeHTTP(rr, req)
	return rr
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
