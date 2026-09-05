package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// TestRouterTopology drives the router that ships rather than a copy of its
// route table. The dashboard is a marker SPA so any response that carries
// SPA-MARKER provably came from the fallback, not the API or the proxy.
func TestRouterTopology(t *testing.T) {
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{AdminAPIKey: "test-admin", EncryptionKey: key, PublicURL: "http://localhost:8080"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	defer auditor.Close()
	spa := webutil.FromFS(fstest.MapFS{
		"index.html":              &fstest.MapFile{Data: []byte("SPA-MARKER root")},
		"virtual-keys/index.html": &fstest.MapFile{Data: []byte("SPA-MARKER virtual-keys")},
	})
	r := newRouter(cfg, st, auditor, log, spa, webutil.EncryptionOK)

	do := func(method, path, admin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://localhost:8080"+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		if admin != "" {
			req.Header.Set("Authorization", "Bearer "+admin)
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	for _, tc := range []struct {
		name, method, path, admin string
		code                      int
		ctPrefix, has, hasNot     string
	}{
		{"removed API path is a JSON 404, not the dashboard", http.MethodGet, "/api/v1/agents", "test-admin", 404, "application/json", `{"error":"not found"}`, "SPA-MARKER"},
		{"removed API path without a key", http.MethodGet, "/api/v1/agents", "", 404, "application/json", `{"error":"not found"}`, "SPA-MARKER"},
		{"known API path enforces auth", http.MethodGet, "/api/v1/virtual-keys", "", 401, "application/json", "", "SPA-MARKER"},
		{"known API path routes", http.MethodGet, "/api/v1/virtual-keys", "test-admin", 200, "application/json", `"virtual_keys"`, "SPA-MARKER"},
		// The two discovery routes, exercised in the assembled router rather
		// than in the API's own table: they are the only management paths
		// that reach out to a third party with a real credential, so the row
		// saying they sit behind the admin gate belongs where the mount
		// order, the middleware and the dashboard fallback all compete.
		{"unauthenticated discovery is refused", http.MethodPost, "/api/v1/upstreams/discover", "", 401, "application/json", "", "SPA-MARKER"},
		// A JSON-RPC body is not an upstream payload, so this reaches the
		// unsaved handler and is turned away for the one field it requires,
		// which is how the row proves the route resolves at all.
		{"unsaved discovery route reaches the API", http.MethodPost, "/api/v1/upstreams/discover", "test-admin", 400, "application/json", `"url is required"`, "SPA-MARKER"},
		{"saved discovery route reaches the API", http.MethodPost, "/api/v1/upstreams/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/discover", "test-admin", 404, "application/json", `{"error":"not found"}`, "SPA-MARKER"},
		{"dashboard page", http.MethodGet, "/virtual-keys/", "", 200, "text/html", "SPA-MARKER virtual-keys", ""},
		{"dashboard fallback for a path that no longer exists", http.MethodGet, "/agents/", "", 200, "text/html", "SPA-MARKER root", ""},
		{"per-key proxy route is owned by the proxy", http.MethodPost, "/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp", "", 401, "", "", "SPA-MARKER"},
		// The member endpoint is three segments and the proxy owns all of it,
		// the 401 included: whether a member URL exists is a question only an
		// authenticated caller may ask, and a dashboard 200 here would answer
		// it for everyone.
		{"member route is owned by the proxy", http.MethodPost, "/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp", "", 401, "application/json", "", "SPA-MARKER"},
		{"shared door is owned by the proxy", http.MethodPost, "/mcp", "", 401, "", "", "SPA-MARKER"},
		// The member analogue of that shared door: chi binds an empty first
		// segment to {keyID}, and the proxy skips its endpoint-binding check
		// when the path id is empty, so //{slug}/mcp is served against the
		// caller's own key. No cross-key reach, but it is a second URL for
		// every member, and it is pinned here so it stays a known one.
		{"keyless member door is owned by the proxy", http.MethodPost, "//github/mcp", "", 401, "application/json", "", "SPA-MARKER"},
		{"a dashboard page named mcp would be shadowed by the proxy", http.MethodGet, "/virtual-keys/mcp", "", 401, "", "", "SPA-MARKER"},
		// /api/v1 is a Mount, so chi resolves it at a static node and never
		// backtracks into {keyID}: everything under the management API keeps
		// its own JSON 404 instead of reaching the three-segment member route.
		// This row is the tripwire for a chi upgrade that changed that
		// precedence, which would hand an unauthenticated proxy 401 to every
		// wrong path under /api/v1 and break no other test here.
		{"the API mount wins over the member route", http.MethodGet, "/api/v1/mcp", "", 404, "application/json", `{"error":"not found"}`, "SPA-MARKER"},
		// The proxy claims exactly two and three segments ending in /mcp; four
		// belong to the dashboard. That is what keeps the route added here
		// from swallowing a future nested dashboard page.
		{"four segments ending in /mcp are not the proxy", http.MethodPost, "/a/b/c/mcp", "", 200, "text/html", "SPA-MARKER root", ""},
		// Known gap, pre-existing and not fixed here: chi does not normalise a
		// trailing slash, so /{id}/mcp/ misses the proxy and falls through to
		// the dashboard. Pinned so that fixing it is a deliberate test change.
		{"trailing slash on the proxy URL falls through to the dashboard", http.MethodPost, "/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp/", "", 200, "text/html", "SPA-MARKER root", ""},
		// The member route inherits that gap unchanged, so PORM-66 now has two
		// URLs to widen to. Pinned for the same reason as the row above:
		// whoever fixes one has to come here and change both.
		{"trailing slash on the member URL falls through to the dashboard", http.MethodPost, "/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp/", "", 200, "text/html", "SPA-MARKER root", ""},
		{"health alias", http.MethodGet, "/health", "", 200, "", `"ok"`, "SPA-MARKER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := do(tc.method, tc.path, tc.admin)
			body := rr.Body.String()
			if rr.Code != tc.code {
				t.Fatalf("%s %s: status %d, want %d; body %q", tc.method, tc.path, rr.Code, tc.code, body)
			}
			if tc.ctPrefix != "" && !strings.HasPrefix(rr.Header().Get("Content-Type"), tc.ctPrefix) {
				t.Errorf("%s %s: content-type %q, want %s", tc.method, tc.path, rr.Header().Get("Content-Type"), tc.ctPrefix)
			}
			if tc.has != "" && !strings.Contains(body, tc.has) {
				t.Errorf("%s %s: body %q lacks %q", tc.method, tc.path, body, tc.has)
			}
			if tc.hasNot != "" && strings.Contains(body, tc.hasNot) {
				t.Errorf("%s %s: body %q must not contain %q", tc.method, tc.path, body, tc.hasNot)
			}
		})
	}

	t.Run("no dashboard built", func(t *testing.T) {
		bare := newRouter(cfg, st, auditor, log, nil, webutil.EncryptionOK)
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/agents/", nil)
		rr := httptest.NewRecorder()
		bare.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("without a dashboard an unknown path should 404, got %d", rr.Code)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{AdminAPIKey: "test-admin", EncryptionKey: key, PublicURL: "http://localhost:8080"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	defer auditor.Close()
	spa := webutil.FromFS(fstest.MapFS{
		"index.html":       &fstest.MapFile{Data: []byte("<html><script>self.__next_f.push([1,\"x\"])</script></html>")},
		"login/index.html": &fstest.MapFile{Data: []byte("<html><script>self.__next_f.push([1,\"login\"])</script></html>")},
	})
	r := newRouter(cfg, st, auditor, log, spa, webutil.EncryptionOK)

	wantHeaders := []string{
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"X-Frame-Options",
		"Permissions-Policy",
	}
	for _, path := range []string{"/", "/login/", "/api/v1/health"} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080"+path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		for _, name := range wantHeaders {
			if rr.Header().Get(name) == "" {
				t.Errorf("%s: missing %s", path, name)
			}
		}
		if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options=%q", path, rr.Header().Get("X-Content-Type-Options"))
		}
		if rr.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: Referrer-Policy=%q", path, rr.Header().Get("Referrer-Policy"))
		}
		if rr.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: X-Frame-Options=%q", path, rr.Header().Get("X-Frame-Options"))
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "base-uri 'none'") {
			t.Errorf("%s: CSP missing frame-ancestors/base-uri: %s", path, csp)
		}
		if src := webutil.ScriptSrc(csp); strings.Contains(src, "unsafe-inline") {
			t.Errorf("%s: script-src has unsafe-inline: %s", path, src)
		}
	}

	// Proxy CORS must still expose the session header after the new middleware.
	req := httptest.NewRequest(http.MethodOptions, "http://localhost:8080/mcp", nil)
	req.Header.Set("Origin", "https://claude.ai")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	expose := rr.Header().Get("Access-Control-Expose-Headers")
	if !strings.Contains(expose, "Mcp-Session-Id") {
		t.Fatalf("proxy CORS clobbered: %v", rr.Header())
	}
	// Retry-After is on the response allowlist (PORM-98) and is not
	// CORS-safelisted, so a browser client can read it only if it is named here.
	if !strings.Contains(expose, "Retry-After") {
		t.Fatalf("Access-Control-Expose-Headers=%q does not name Retry-After", expose)
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("OPTIONS /mcp should still carry security headers")
	}
}
