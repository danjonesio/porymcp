package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

func TestSchemeEnforcement(t *testing.T) {
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := &config.Config{
		EncryptionKey: key,
		PublicURL:     "https://porymcp.example.com",
	}
	h := New(cfg, st, nil, nil)
	wrapped := webutil.EnforceHTTPS(cfg.SchemeEnforced(), cfg.TrustedProxies, nil)(h)

	req := httptest.NewRequest(http.MethodPost, "http://porymcp.example.com/mcp", strings.NewReader(`{}`))
	req.RemoteAddr = "203.0.113.9:1"
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("clear-text to https PUBLIC_URL: code=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %s", rr.Body.String())
	}
	if body["scheme"] != "http" {
		t.Fatalf("body=%v, want scheme http", body)
	}

	cfg.AllowInsecureHTTP = true
	wrapped = webutil.EnforceHTTPS(cfg.SchemeEnforced(), cfg.TrustedProxies, nil)(h)
	req = httptest.NewRequest(http.MethodPost, "http://porymcp.example.com/mcp", strings.NewReader(`{}`))
	req.RemoteAddr = "203.0.113.9:1"
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code == http.StatusUpgradeRequired {
		t.Fatalf("ALLOW_INSECURE_HTTP should let the request through, got 426 %s", rr.Body.String())
	}
}
