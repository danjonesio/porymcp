package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PORM-98. The 1:1 forward path copies back three upstream response headers
// and no others. The stub answers with every header the issue names as a
// leak plus the three that must pass, and the assertions read through
// Header.Values or Header.Get, never by indexing the map: the spellings below
// are not all canonical (Last-Event-ID, WWW-Authenticate) and only the
// accessors canonicalise. Values, not Get, is what sees the duplicate the old
// loop produced beside applyCORS's own Access-Control-Allow-Origin; Get
// returns the first value and passed on the bug.
//
// X-Frame-Options, Content-Security-Policy and X-Content-Type-Options are
// asserted absent here rather than single: the fixture router runs without
// webutil.SecurityHeaders, so the proxy handler never writes them, and
// absence proves the copy dropped the upstream's. TestSecurityHeaders in
// cmd/server proves the middleware writes each of them once.
//
// The session round-trip contract lives in TestPerUpstreamSessionRoundTrips;
// the Mcp-Session-Id assertion is here because acceptance criterion 1 names
// it. Security requirements 1, 2, 3, 4, 5, 7 and 9 of the plan.
func TestUpstreamResponseHeadersAreAllowlisted(t *testing.T) {
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	origin := map[string]string{"Origin": "https://claude.ai"}
	upstream := upstreamSpec{
		Tools: []string{"ping_tool"},
		RespHeaders: map[string]string{
			"Set-Cookie":                       "sid=abc",
			"WWW-Authenticate":                 `Bearer resource_metadata="https://idp.example/.well-known/x"`,
			"Server":                           "nginx",
			"X-Powered-By":                     "Express",
			"X-Request-Id":                     "up-1",
			"Via":                              "1.1 edge",
			"Alt-Svc":                          `h3=":443"`,
			"Access-Control-Allow-Origin":      "*",
			"Access-Control-Allow-Credentials": "true",
			"Access-Control-Expose-Headers":    "*",
			"Vary":                             "Authorization",
			"X-Frame-Options":                  "DENY",
			"Content-Security-Policy":          "default-src *",
			"X-Content-Type-Options":           "nosniff",
			"ETag":                             `"v1"`,
			"Cache-Control":                    "public, max-age=600",
			"Mcp-Protocol-Version":             "2025-06-18",
			"Last-Event-ID":                    "7",
			"Retry-After":                      "3",
			"Mcp-Session-Id":                   "sess-1",
			"Content-Type":                     "application/json; charset=utf-8",
		},
	}

	check := func(t *testing.T, rr *httptest.ResponseRecorder) {
		t.Helper()
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		h := rr.Header()
		// The three names that pass. The Content-Type is a value no stub arm
		// writes on its own, so it proves the copy ran rather than the
		// application/json default.
		for k, want := range map[string]string{
			"Mcp-Session-Id": "sess-1",
			"Retry-After":    "3",
			"Content-Type":   "application/json; charset=utf-8",
		} {
			if got := h.Get(k); got != want {
				t.Errorf("%s=%q want %q", k, got, want)
			}
		}
		// Everything else the upstream set stops at the proxy.
		for _, k := range []string{
			"Set-Cookie", "WWW-Authenticate", "Server", "X-Powered-By", "X-Request-Id",
			"Via", "Alt-Svc", "Access-Control-Allow-Credentials", "X-Frame-Options",
			"Content-Security-Policy", "X-Content-Type-Options", "ETag",
			"Mcp-Protocol-Version", "Last-Event-ID",
		} {
			if vs := h.Values(k); len(vs) != 0 {
				t.Errorf("%s=%q reached the client", k, vs)
			}
		}
		// PoryMCP's own CORS block is single valued and is PoryMCP's.
		if vs := h.Values("Access-Control-Allow-Origin"); len(vs) != 1 || vs[0] != "https://claude.ai" {
			t.Errorf("Access-Control-Allow-Origin=%q want exactly [https://claude.ai]", vs)
		}
		if vs := h.Values("Vary"); len(vs) != 1 || vs[0] != "Origin" {
			t.Errorf("Vary=%q want exactly [Origin]", vs)
		}
		if vs := h.Values("Access-Control-Expose-Headers"); len(vs) != 1 || !strings.Contains(vs[0], "Retry-After") || strings.Contains(vs[0], "*") {
			t.Errorf("Access-Control-Expose-Headers=%q want one value naming Retry-After and not *", vs)
		}
		// The upstream's cache directive never reaches the client; the proxy's
		// own no-store does.
		if vs := h.Values("Cache-Control"); len(vs) != 1 || vs[0] != "no-store" {
			t.Errorf("Cache-Control=%q want exactly [no-store]", vs)
		}
	}

	t.Run("key endpoint", func(t *testing.T) {
		f := newSingleFixture(t, upstream, nil, nil)
		check(t, f.doPath(http.MethodPost, "http://localhost:8080/a1/mcp", initialize, origin))
	})

	t.Run("member endpoint", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": upstream,
			"beta":  {Tools: []string{"other"}},
		}, true, nil, nil, nil)
		check(t, f.postMemberWith("alpha", initialize, origin))
	})
}
