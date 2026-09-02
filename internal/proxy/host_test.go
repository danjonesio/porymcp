package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/store"
	"github.com/netcasklabs/porymcp/internal/webutil"
)

func TestHostAllowedForwarded(t *testing.T) {
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	trusted, err := webutil.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		EncryptionKey:  key,
		PublicURL:      "https://porymcp.example.com",
		TrustedProxies: trusted,
	}
	h := New(cfg, st, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "http://porymcp:8080/mcp", strings.NewReader(`{}`))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Host", "porymcp.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "invalid host") {
		t.Fatalf("trusted forwarded host should be allowed, got %d %s", rr.Code, rr.Body.String())
	}

	// Inverse: the same rewritten Host is rejected when nobody is trusted,
	// and the body names both sides so the operator can see the mismatch.
	cfg.TrustedProxies = nil
	h = New(cfg, st, nil, nil)
	req = httptest.NewRequest(http.MethodPost, "http://porymcp:8080/mcp", strings.NewReader(`{}`))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Host", "porymcp.example.com")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("untrusted forwarded host: code=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type=%q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %s", rr.Body.String())
	}
	if body["error"] != "invalid host" || body["seen"] != "porymcp:8080" || body["expected"] != "porymcp.example.com" {
		t.Fatalf("body=%v", body)
	}
	if strings.Contains(rr.Body.String(), "10.0.0.0/8") || strings.Contains(rr.Body.String(), "/8") {
		t.Fatalf("403 must not include CIDRs: %s", rr.Body.String())
	}
}
