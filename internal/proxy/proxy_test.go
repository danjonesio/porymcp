package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/go-chi/chi/v5"
)

func TestInjectBearerAndHideVirtualKey(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping"}]}}`)
	}))
	defer up.Close()

	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	enc, err := crypto.NewKeyring(key, nil).Seal([]byte(`{"token":"sk-real-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "u1", Name: "mock", Slug: "mock", URL: up.URL, Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthBearer, AuthConfig: []byte(enc), Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "a1", Name: "bot", KeyHash: hash, KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080"}
	al := audit.New(st, nil)
	h := New(cfg, st, al, nil)

	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	))
	req.Header.Set("Authorization", "Bearer "+plain)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotAuth != "Bearer sk-real-secret" {
		t.Fatalf("upstream auth=%q", gotAuth)
	}
	if strings.Contains(rr.Body.String(), "sk-real-secret") {
		t.Fatal("real secret leaked to agent")
	}

	// Give the async auditor a moment.
	time.Sleep(50 * time.Millisecond)
	logs, _, err := st.ListAuditLogs(ctx, models.LogFilter{Limit: 10})
	if err != nil || len(logs) == 0 {
		t.Fatalf("expected audit log, err=%v logs=%v", err, logs)
	}
	if logs[0].Method != "tools/list" || logs[0].VirtualKeyID != "a1" {
		t.Fatalf("log=%+v", logs[0])
	}
}

func TestKeyPathMustMatchKey(t *testing.T) {
	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUpstream(context.Background(), &models.Upstream{
		ID: "u1", Name: "mock", Slug: "mock", URL: "http://127.0.0.1:9", Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthNone, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(context.Background(), &models.VirtualKey{
		ID: "a1", Name: "bot", KeyHash: hash, KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080"}, st, nil, nil)
	r := chi.NewRouter()
	r.HandleFunc("/mcp", h.ServeHTTP)
	r.HandleFunc(KeyRoute, h.ServeHTTP)
	r.HandleFunc(MemberRoute, h.ServeMember)

	post := func(url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+plain)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	const ping = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	rr := post("http://localhost:8080/other-id/mcp", ping)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("mismatched path code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "virtual key does not match this endpoint") {
		t.Fatalf("mismatched path body=%s", rr.Body.String())
	}

	// The binding check reads KeyParam, which MemberRoute binds too. If the
	// route and the lookup ever drifted, chi would hand the handler "" and
	// this would fail open, a valid key would reach another key's members.
	rr = post("http://localhost:8080/other-id/mock/mcp", ping)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member path, mismatched key: code=%d body=%s (endpoint binding has failed open)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "virtual key does not match this endpoint") {
		t.Fatalf("member path body=%s", rr.Body.String())
	}

	// The 403 precedes the body read. A batch array is refused by parseRequest
	// with 400, so a body that never parses coming back 403 is the proof that
	// nothing about the request was inspected before the key was bound to its
	// endpoint. Nothing else in the suite pins that ordering.
	const batch = `[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`
	for _, url := range []string{
		"http://localhost:8080/other-id/mcp",
		"http://localhost:8080/other-id/mock/mcp",
	} {
		if rr := post(url, batch); rr.Code != http.StatusForbidden {
			t.Errorf("%s with an unparseable body: code=%d want 403, not 400: the binding check must run before the body is read; body=%s", url, rr.Code, rr.Body.String())
		}
	}
}

// TestProxyURLUnchangedAcrossRename pins the one promise the rename makes to
// running clients: a proxy URL minted before it (/{id}/mcp with the key's id)
// keeps working unchanged. The URL is a hard-coded literal on purpose; it is
// the string a client already holds in its config. The second half asserts
// that the endpoint-binding check still fires under the renamed route
// parameter: the same valid key on the wrong id must get 403, not the
// upstream. If KeyRoute and the KeyParam lookup ever disagreed, chi would
// return "" for the parameter and that check would silently pass every key on
// every path, which nothing else in the suite would notice.
func TestProxyURLUnchangedAcrossRename(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping"}]}}`)
	}))
	defer up.Close()

	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "u1", Name: "mock", Slug: "mock", URL: up.URL, Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthNone, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// The worked example in docs/09-clients.md.
	const id = "77232bc0-dd4a-44d5-8ae7-ef2f679879ec"
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: id, Name: "claude-code", KeyHash: hash, KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080"}, st, nil, nil)
	r := chi.NewRouter()
	r.HandleFunc("/mcp", h.ServeHTTP)
	r.HandleFunc(KeyRoute, h.ServeHTTP)
	r.HandleFunc(MemberRoute, h.ServeMember)

	call := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		req.Header.Set("Authorization", "Bearer "+plain)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	// 1. The URL a client configured before the rename, verbatim.
	if rr := call("http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ping"`) {
		t.Fatalf("pre-rename proxy URL: code=%d body=%s", rr.Code, rr.Body.String())
	}
	// 2. The same key on another id is still bound to its own endpoint.
	if rr := call("http://localhost:8080/00000000-0000-0000-0000-000000000000/mcp"); rr.Code != http.StatusForbidden {
		t.Fatalf("valid key on the wrong endpoint: code=%d body=%s (endpoint binding has failed open)", rr.Code, rr.Body.String())
	}
	// 3. The registered pattern set is exactly the shared door and KeyRoute.
	seen := map[string]bool{}
	if err := chi.Walk(r, func(_, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		seen[route] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var patterns []string
	for p := range seen {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	if got, want := strings.Join(patterns, " "), "/mcp /{keyID}/mcp /{keyID}/{slug}/mcp"; got != want {
		t.Fatalf("registered patterns %q, want %q", got, want)
	}
	// 4. The member pattern is built from the same constants the handler reads.
	if want := "/{" + KeyParam + "}/{" + SlugParam + "}/mcp"; MemberRoute != want {
		t.Fatalf("MemberRoute=%q want %q", MemberRoute, want)
	}
}

func TestInvalidKeyRejected(t *testing.T) {
	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080"}, st, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer pory_notarealkey000000000000000000000000000000000000000000000000")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestGroupAlwaysPrefixesToolNames(t *testing.T) {
	mk := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			if req.Method == "tools/list" {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search"}]}}`)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
		}))
	}
	a := mk("alpha")
	b := mk("beta")
	defer a.Close()
	defer b.Close()

	key, _ := crypto.RandomKey()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	ctx := context.Background()
	for _, u := range []models.Upstream{
		// Name and Slug differ on purpose: the assertion below passes only if the
		// tool prefix comes from up.Slug. Do not "tidy" these names back to match
		// the slugs.
		{ID: "u1", Name: "Alpha Renamed", Slug: "alpha", URL: a.URL, Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "Beta Renamed", Slug: "beta", URL: b.URL, Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		cp := u
		if err := st.CreateUpstream(ctx, &cp); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateGroup(ctx, &models.Group{
		ID: "g1", Name: "both", UpstreamIDs: []string{"u1", "u2"}, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, hash, lookup, prefix, _ := auth.GenerateKey()
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "a1", Name: "multi", KeyHash: hash, KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetGroup, TargetID: "g1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	h := New(&config.Config{EncryptionKey: key, PublicURL: "http://localhost:8080"}, st, nil, nil)
	r := chi.NewRouter()
	r.HandleFunc("/mcp", h.ServeHTTP)
	r.HandleFunc(KeyRoute, h.ServeHTTP)
	r.HandleFunc(MemberRoute, h.ServeMember)

	list := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		))
		req.Header.Set("Authorization", "Bearer "+plain)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	rr := list("http://localhost:8080/mcp")
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alpha__search") || !strings.Contains(body, "beta__search") {
		t.Fatalf("expected every name to carry its member's slug, got %s", body)
	}

	// The contrast the prefixing exists for. A member endpoint speaks one
	// server, so there is nothing to disambiguate: the client sees the
	// upstream's own name and calls it by that name.
	rr = list("http://localhost:8080/a1/alpha/mcp")
	if rr.Code != 200 {
		t.Fatalf("member path: code=%d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if !strings.Contains(body, `"search"`) {
		t.Fatalf("member path: expected the upstream's own name, got %s", body)
	}
	if strings.Contains(body, "alpha__search") || strings.Contains(body, "beta__search") {
		t.Fatalf("member path: a name was prefixed on a 1:1 endpoint, got %s", body)
	}
}
