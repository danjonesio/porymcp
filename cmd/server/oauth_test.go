package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// The assembled router and the two commands, for PORM-139 (step 11): the two
// public OAuth routes are reachable through newRouter without a key, the
// request log never carries the callback's query, the well-known paths still
// fall through to the dashboard, rekey re-wraps an oauth row, and the boot
// sweep names an unconnected one as one to connect.

// oauthRouter builds the shipping router over a marker SPA, logging JSON to
// buf.
func oauthRouter(t *testing.T, buf *bytes.Buffer) http.Handler {
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
	var log *slog.Logger
	if buf != nil {
		log = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	auditor := audit.New(st, log)
	t.Cleanup(auditor.Close)
	spa := webutil.FromFS(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("SPA-MARKER root")}})
	r, _ := newRouter(cfg, st, auditor, log, spa, webutil.EncryptionOK)
	return r
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080"+path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestCallbackRouteIsPublic(t *testing.T) {
	r := oauthRouter(t, nil)
	rr := get(r, "/api/v1/oauth/callback?state=nope&code=x")
	if rr.Code != http.StatusBadRequest || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") || strings.Contains(rr.Body.String(), "SPA-MARKER") {
		t.Fatalf("%d %q %s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("headers %v", rr.Header())
	}
}

func TestClientMetadataIsPublic(t *testing.T) {
	r := oauthRouter(t, nil)
	rr := get(r, "/api/v1/oauth/client-metadata")
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", rr.Code, rr.Header())
	}
	var doc map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &doc)
	if doc["client_id"] != "http://localhost:8080/api/v1/oauth/client-metadata" {
		t.Fatalf("doc %v", doc)
	}
}

// Security requirement 9: the request log line carries the path and never
// the query, so a code or a state can never reach it.
func TestCallbackQueryNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	r := oauthRouter(t, &buf)
	rr := get(r, "/api/v1/oauth/callback?code=CODE_MARKER&state=STATE_MARKER&iss=ISS_MARKER")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("%d", rr.Code)
	}
	logged := buf.String()
	if !strings.Contains(logged, `"path":"/api/v1/oauth/callback"`) {
		t.Fatalf("no request line: %s", logged)
	}
	for _, needle := range []string{"CODE_MARKER", "STATE_MARKER", "ISS_MARKER"} {
		if strings.Contains(logged, needle) {
			t.Fatalf("%q reached the log: %s", needle, logged)
		}
	}
	if strings.Contains(logged, "callback failed") {
		t.Fatalf("an unknown state produced a warning: %s", logged)
	}
}

// The well-known OAuth paths stay what docs/09-clients.md says they are: the
// dashboard, because PoryMCP publishes no protected-resource or
// authorization-server metadata of its own.
func TestWellKnownProtectedResourceStillServesDashboard(t *testing.T) {
	r := oauthRouter(t, nil)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/.well-known/oauth-client-metadata"} {
		rr := get(r, path)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "SPA-MARKER") {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
}

// Criterion 9, first half: rekey re-wraps an oauth row like any other.
func TestRekeyRewrapsOAuthRow(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	path := filepath.Join(t.TempDir(), "rekey.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	set := models.OAuthTokenSet{AccessToken: "acc-REKEY-MARKER", RefreshToken: "ref-REKEY-MARKER", ExpiresAt: time.Now().Add(time.Hour).UTC(), Resource: "https://example.test/oauth"}
	raw, _ := json.Marshal(set)
	seeded := sealUnder(t, old, string(raw))
	now := time.Now().UTC()
	if err := st.CreateUpstream(context.Background(), &models.Upstream{
		ID: "oauth", Name: "OAuth", Slug: "oauth", URL: "https://example.test/oauth", Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthOAuth, AuthConfig: []byte(seeded), Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	rekeyEnv(t, path, cur, old)
	var out bytes.Buffer
	if code := rekey(&out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	rec := rekeyRecord(t, &out, "rekey complete")
	if rec["rewritten"] != float64(1) {
		t.Fatalf("counts: %v", rec)
	}
	got := rawColumn(t, path, "oauth")
	if got == seeded || !crypto.IsV1(got) {
		t.Fatalf("not rewritten: %q", got)
	}
	k := crypto.NewKeyring(cur, nil)
	plain, by, err := k.Open(got)
	if err != nil || by != k.Fingerprint() {
		t.Fatalf("does not open under the current key alone: %v", err)
	}
	var back models.OAuthTokenSet
	if err := json.Unmarshal(plain, &back); err != nil || back.RefreshToken != set.RefreshToken || back.AccessToken != set.AccessToken {
		t.Fatalf("plaintext changed: %+v %v", back, err)
	}
	if strings.Contains(out.String(), "REKEY-MARKER") {
		t.Fatal("a token reached the rekey output")
	}
}

// Criterion 9, second half (amendment A12): the boot sweep counts an
// unconnected oauth row as unreadable, names it as one to connect, leaves a
// connected or lapsed row alone, and never degrades /health for it.
func TestBootSweepClassifiesOAuth(t *testing.T) {
	cur := mustKey(t)
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	verdict, err, records, _ := boot(t, &config.Config{EncryptionKey: cur}, "", []bootRow{
		{"u1", "Unconnected", models.AuthOAuth, ""},
		{"u2", "ClientOnly", models.AuthOAuth, sealUnder(t, cur, `{"client_id":"cid","client_source":"supplied"}`)},
		{"u3", "Connected", models.AuthOAuth, sealUnder(t, cur, `{"access_token":"acc-BOOT-MARKER","refresh_token":"r","expires_at":"`+future+`"}`)},
		{"u4", "Lapsed", models.AuthOAuth, sealUnder(t, cur, `{"access_token":"acc-BOOT-MARKER-2","expires_at":"`+past+`"}`)},
	})
	if err != nil || verdict != webutil.EncryptionOK {
		t.Fatalf("verdict %q err %v", verdict, err)
	}
	warns := recordsAt(records, "WARN")
	if len(warns) != 1 {
		t.Fatalf("warns %d: %s", len(warns), msgs(records))
	}
	w := warns[0]
	if !strings.Contains(w["msg"].(string), "connect an OAuth upstream") || w["unreadable"] != float64(2) || w["unconnected_oauth"] != float64(2) {
		t.Fatalf("warn %v", w)
	}
	ids := fmtAny(w["upstream_ids"])
	if !strings.Contains(ids, "u1") || !strings.Contains(ids, "u2") || strings.Contains(ids, "u3") || strings.Contains(ids, "u4") {
		t.Fatalf("upstream_ids %v", w["upstream_ids"])
	}
	for _, r := range records {
		if strings.Contains(fmtAny(r), "BOOT-MARKER") {
			t.Fatalf("a token reached the boot log: %v", r)
		}
	}
}
