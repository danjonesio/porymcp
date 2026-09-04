package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

func TestListenAndServeTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir)

	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	trusted, err := webutil.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ListenAddr:     "127.0.0.1:0",
		AdminAPIKey:    "test-admin",
		EncryptionKey:  key,
		PublicURL:      "https://porymcp.example.com",
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		TrustedProxies: trusted,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	defer auditor.Close()
	handler := newRouter(cfg, st, auditor, log, nil, webutil.EncryptionOK)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(cfg, handler)
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSConfig.MinVersion=%v, want tls.VersionTLS12", srv.TLSConfig)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	url := "https://" + ln.Addr().String() + "/health"
	var resp *http.Response
	var getErr error
	for i := 0; i < 20; i++ {
		select {
		case err := <-errCh:
			t.Fatalf("ServeTLS: %v", err)
		default:
		}
		resp, getErr = client.Get(url)
		if getErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if getErr != nil {
		t.Fatalf("GET /health: %v", getErr)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	raw := string(body)
	if !strings.Contains(raw, `"ok"`) {
		t.Fatalf("body lacks ok: %s", raw)
	}
	if !strings.Contains(raw, "scheme_enforced") {
		t.Fatalf("body lacks scheme_enforced: %s", raw)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["trusted_proxies"].(float64); !ok {
		t.Fatalf("trusted_proxies is not a number: %v", parsed["trusted_proxies"])
	}
	if strings.Contains(raw, "10.0.0.0/8") || strings.Contains(raw, "10.0.0.0") {
		t.Fatalf("health must not include CIDRs: %s", raw)
	}
}

func TestHealthcheckURL(t *testing.T) {
	for _, tc := range []struct {
		addr, scheme, want string
	}{
		{":8080", "http", "http://127.0.0.1:8080/health"},
		{"0.0.0.0:8080", "http", "http://127.0.0.1:8080/health"},
		{"[::]:8080", "http", "http://127.0.0.1:8080/health"},
		{":8443", "https", "https://127.0.0.1:8443/health"},
	} {
		if got := healthcheckURL(tc.addr, tc.scheme); got != tc.want {
			t.Fatalf("healthcheckURL(%q, %q)=%q, want %q", tc.addr, tc.scheme, got, tc.want)
		}
	}
}

func TestEnforceHTTPSBeforeDashboardCORS(t *testing.T) {
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{
		AdminAPIKey:   "test-admin",
		EncryptionKey: key,
		PublicURL:     "https://porymcp.example.com",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	defer auditor.Close()
	r := newRouter(cfg, st, auditor, log, nil, webutil.EncryptionOK)

	req := httptest.NewRequest(http.MethodOptions, "http://porymcp.example.com/api/v1/health", nil)
	req.RemoteAddr = "203.0.113.9:1"
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("OPTIONS /api/v1/health must be 426 before dashboardCORS, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestHealthAliasReportsPolicy(t *testing.T) {
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	trusted, err := webutil.ParseTrustedProxies("10.99.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AdminAPIKey:    "test-admin",
		EncryptionKey:  key,
		PublicURL:      "http://localhost:8080",
		TrustedProxies: trusted,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	defer auditor.Close()
	r := newRouter(cfg, st, auditor, log, nil, webutil.EncryptionOK)

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["scheme_enforced"].(bool); !ok {
		t.Fatalf("scheme_enforced missing: %v", body)
	}
	n, ok := body["trusted_proxies"].(float64)
	if !ok {
		t.Fatalf("trusted_proxies is not a number: %v", body["trusted_proxies"])
	}
	if n != 1 {
		t.Fatalf("trusted_proxies=%v, want 1", n)
	}
	// PORM-52: the encryption verdict rides the same body, on both routes.
	if enc, _ := body["encryption"].(string); enc != "ok" {
		t.Fatalf("encryption=%v, want \"ok\"", body["encryption"])
	}
	if strings.Contains(rr.Body.String(), "10.99.0.0/16") {
		t.Fatalf("health must not include CIDRs: %s", rr.Body.String())
	}
}

func TestRequestLoggerUsesSocketIP(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	cfg := &config.Config{}
	h := requestLogger(log, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/v1/health", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	out := buf.String()
	if !strings.Contains(out, "203.0.113.9") {
		t.Fatalf("logged %s, want socket IP", out)
	}
	if strings.Contains(out, "9.9.9.9") {
		t.Fatalf("logged spoofed X-Forwarded-For: %s", out)
	}
}

func writeSelfSigned(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
