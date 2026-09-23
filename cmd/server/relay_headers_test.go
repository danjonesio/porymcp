package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// relayRouter is the router that ships, with one HTTP API upstream at the
// given httptest server and one key bound to it. It returns the router and
// the key's plaintext and id.
func relayRouter(t *testing.T, upstreamURL string) (http.Handler, string, string) {
	t.Helper()
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{AdminAPIKey: "test-admin", EncryptionKey: key, PublicURL: "http://localhost:8080"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := audit.New(st, log)
	t.Cleanup(auditor.Close)
	spa := webutil.FromFS(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("SPA-MARKER root")}})
	r, _ := newRouter(cfg, st, auditor, log, spa, webutil.EncryptionOK)

	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "77232bc0-dd4a-44d5-8ae7-ef2f679879ec", Name: "API", Slug: "vendor", Kind: models.KindHTTP,
		URL: upstreamURL, Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "a1", Name: "bot", KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "77232bc0-dd4a-44d5-8ae7-ef2f679879ec", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return r, plain, "a1"
}

// TestRelayHeadersSurviveMiddleware covers PORM-146 security requirement 4
// through the real middleware stack, which the proxy package's bare router
// cannot show: an upstream that sets every protected name does not replace
// one PoryMCP wrote.
func TestRelayHeadersSurviveMiddleware(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for _, name := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy",
			"X-Frame-Options", "Permissions-Policy", "Strict-Transport-Security", "Cache-Control", "Vary",
			"Access-Control-Allow-Origin", "Set-Cookie", "Clear-Site-Data", "Server"} {
			h.Set(name, "UPSTREAM-VALUE")
		}
		h.Set("Content-Type", "application/json")
		h.Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	r, plain, id := relayRouter(t, up.URL+"/v1")

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/"+id+"/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	req.Header.Set("Origin", "https://app.example")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	h := rr.Header()
	want := map[string]string{
		"X-Content-Type-Options":      "nosniff",
		"Referrer-Policy":             "no-referrer",
		"X-Frame-Options":             "DENY",
		"Permissions-Policy":          "camera=(), microphone=(), geolocation=(), payment=()",
		"Cache-Control":               "no-store",
		"Access-Control-Allow-Origin": "https://app.example",
		"ETag":                        `"v1"`,
	}
	for name, v := range want {
		if got := h.Get(name); got != v {
			t.Errorf("%s = %q, want %q", name, got, v)
		}
	}
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src") || csp == "UPSTREAM-VALUE" {
		t.Errorf("Content-Security-Policy = %q, want PoryMCP's own", csp)
	}
	if vary := h.Values("Vary"); len(vary) != 1 || vary[0] != "Origin" {
		t.Errorf("Vary = %v", vary)
	}
	for _, name := range []string{"Strict-Transport-Security", "Set-Cookie", "Clear-Site-Data", "Server"} {
		if v := h.Values(name); len(v) != 0 {
			t.Errorf("%s reached the client: %v", name, v)
		}
	}
	for name, vals := range h {
		for _, v := range vals {
			if v == "UPSTREAM-VALUE" {
				t.Errorf("%s carries the upstream's value", name)
			}
		}
	}
}

// TestRelayKeylessBindingIs404 covers PORM-146 security requirement 15 with
// a valid key: the //api/ binding chi produces for an empty first segment is
// refused with the uniform 404, so it is not a second door.
func TestRelayKeylessBindingIs404(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the keyless binding reached the upstream: %s", r.URL)
	}))
	defer up.Close()
	r, plain, _ := relayRouter(t, up.URL)
	for _, p := range []string{"//api/x", "//vendor/api/x", "//api"} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080"+p, nil)
		req.Header.Set("Authorization", "Bearer "+plain)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), `"unknown endpoint"`) || strings.Contains(rr.Body.String(), "SPA-MARKER") {
			t.Errorf("%s: status %d body %s", p, rr.Code, rr.Body.String())
		}
	}
}
