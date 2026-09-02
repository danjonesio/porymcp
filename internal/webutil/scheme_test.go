package webutil

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestEnforceHTTPSRejectsNonLoopbackHTTP(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	h := EnforceHTTPS(true, trusted, nil)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "http://porymcp.example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Host = "porymcp.example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type=%q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "insecure scheme" || body["scheme"] != "http" {
		t.Fatalf("body=%v", body)
	}
	if strings.Contains(rr.Body.String(), "10.0.0.0") || strings.Contains(rr.Body.String(), "https://") {
		t.Fatalf("must not leak CIDRs or PUBLIC_URL: %s", rr.Body.String())
	}
}

func TestEnforceHTTPSTrustedProtoHTTPSPasses(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	h := EnforceHTTPS(true, trusted, nil)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "http://porymcp:8080/mcp", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("trusted proto=https should pass, status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestEnforceHTTPSRejectsOPTIONS(t *testing.T) {
	h := EnforceHTTPS(true, nil, nil)(okHandler())
	req := httptest.NewRequest(http.MethodOptions, "http://porymcp.example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("OPTIONS should be rejected, status=%d", rr.Code)
	}
}

func TestEnforceHTTPSSkipsLoopback(t *testing.T) {
	h := EnforceHTTPS(true, nil, nil)(okHandler())
	for _, remote := range []string{"127.0.0.1:9", "[::1]:9", "127.0.0.9:80"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/health", nil)
		req.RemoteAddr = remote
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("loopback %s should skip enforcement, status=%d", remote, rr.Code)
		}
	}
}

func TestEnforceHTTPSAllowInsecure(t *testing.T) {
	h := EnforceHTTPS(false, nil, nil)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "http://porymcp.example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("ALLOW insecure should pass through, status=%d", rr.Code)
	}
}

func TestEnforceHTTPSInactiveWhenPublicURLIsHTTP(t *testing.T) {
	h := EnforceHTTPS(false, nil, nil)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "http://porymcp.example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("http PUBLIC_URL should not enforce, status=%d", rr.Code)
	}
}

func TestEnforceHTTPSCORSOn426(t *testing.T) {
	h := EnforceHTTPS(true, nil, nil)(okHandler())
	req := httptest.NewRequest(http.MethodOptions, "http://porymcp.example.com/mcp", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("Origin", "https://dashboard.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("status=%d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("ACA-Origin=%q", got)
	}
	if got := rr.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary=%q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "MCP-Session-Id") {
		t.Fatalf("ACA-Headers=%q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "PATCH") {
		t.Fatalf("ACA-Methods=%q", got)
	}
}

func TestEnforceHTTPSLogsOnceAMinute(t *testing.T) {
	insecureLogMu.Lock()
	lastInsecureLog = time.Time{}
	insecureLogMu.Unlock()

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	h := EnforceHTTPS(true, trusted, log)(okHandler())

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://porymcp.example.com/mcp", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		req.Host = "porymcp.example.com"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUpgradeRequired {
			t.Fatalf("status=%d", rr.Code)
		}
	}
	out := buf.String()
	if strings.Count(out, "rejected insecure scheme") != 1 {
		t.Fatalf("expected one log line, got %q", out)
	}
	if !strings.Contains(out, "scheme=http") || !strings.Contains(out, "host=porymcp.example.com") {
		t.Fatalf("log fields: %s", out)
	}
	if strings.Contains(out, "10.0.0.0") {
		t.Fatal("must not log trusted CIDRs")
	}
}

func TestEnforceHTTPSNilLogger(t *testing.T) {
	h := EnforceHTTPS(true, nil, nil)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("status=%d", rr.Code)
	}
}
