package webutil

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/netcasklabs/porymcp/web"
)

func TestInlineScriptHashes(t *testing.T) {
	body := []byte("self.__next_f.push([1,\"hello\"])")
	html := []byte(`<!doctype html><script src="/app.js"></script><script>` + string(body) + `</script><script type="application/json">{"x":1}</script>`)
	fsys := fstest.MapFS{
		"index.html":       {Data: html},
		"login/index.html": {Data: html},
		"skip.txt":         {Data: []byte(`<script>not-html</script>`)},
		"nested/page.HTML": {Data: []byte(`<SCRIPT>abc</SCRIPT>`)},
	}
	hashes := InlineScriptHashes(fsys)
	if len(hashes) != 3 {
		t.Fatalf("hashes=%v", hashes)
	}
	sum := sha256.Sum256(body)
	want := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	found := false
	for _, h := range hashes {
		if h == want {
			found = true
		}
		if !strings.HasPrefix(h, "sha256-") {
			t.Fatalf("not a sha256 token: %s", h)
		}
	}
	if !found {
		t.Fatalf("missing hash for known body: %v", hashes)
	}
}

func TestContentSecurityPolicyNoUnsafeInline(t *testing.T) {
	fsys := fstest.MapFS{"index.html": {Data: []byte(`<html><script>alert(1)</script></html>`)}}
	csp := ContentSecurityPolicy(fsys)
	src := ScriptSrc(csp)
	if src == "" {
		t.Fatal("missing script-src")
	}
	if strings.Contains(src, "unsafe-inline") {
		t.Fatalf("script-src must not allow unsafe-inline: %s", src)
	}
	if !strings.Contains(csp, "style-src-attr 'unsafe-inline'") {
		t.Fatalf("Headless UI needs style-src-attr: %s", csp)
	}
	for _, need := range []string{"frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, need) {
			t.Fatalf("policy missing %s: %s", need, csp)
		}
	}
	if !strings.Contains(csp, "'sha256-") {
		t.Fatal("expected a script hash")
	}
}

func TestSecurityHeadersSetAndLeaveCORS(t *testing.T) {
	h := SecurityHeaders(ContentSecurityPolicy(nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Access-Control-Expose-Headers") != "Mcp-Session-Id" {
		t.Fatal("security headers must not clobber CORS")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal(rr.Header())
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(rr.Header())
	}
	if rr.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal(rr.Header())
	}
	if rr.Header().Get("Permissions-Policy") == "" {
		t.Fatal("missing Permissions-Policy")
	}
}

func TestInlineScriptHashesFromExport(t *testing.T) {
	dist, err := web.Dist()
	if err != nil {
		t.Skip("dashboard export not embedded")
	}
	hashes := InlineScriptHashes(dist)
	if len(hashes) == 0 {
		t.Fatal("web/out has inline scripts; hashes should not be empty")
	}
	csp := ContentSecurityPolicy(dist)
	if strings.Contains(ScriptSrc(csp), "unsafe-inline") {
		t.Fatal(csp)
	}
	t.Logf("export CSP: %d hashes, header %d bytes", len(hashes), len(csp))
}
