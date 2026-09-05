package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

func testAPI(t *testing.T) (*Server, http.Handler, *store.SQLStore) {
	t.Helper()
	return testAPIPublicURL(t, "http://localhost:8080")
}

// testAPIPublicURL is testAPI with a chosen PUBLIC_URL, for the tests that pin
// how endpoint URLs are joined. It builds a config.Config directly
// and so bypasses config.Load, which is the only place PUBLIC_URL is
// trailing-slash-trimmed: the value here is used verbatim, so callers pass one
// that is already trimmed.
func testAPIPublicURL(t *testing.T, publicURL string) (*Server, http.Handler, *store.SQLStore) {
	t.Helper()
	s, h, st, _ := testAPIStoreFile(t, publicURL)
	return s, h, st
}

// testAPIStoreFile is testAPIPublicURL plus the path to the database file, for
// the tests that have to reach past the store and write a value no exported
// call could produce.
func testAPIStoreFile(t *testing.T, publicURL string) (*Server, http.Handler, *store.SQLStore, string) {
	t.Helper()
	return testAPIWrappedStore(t, publicURL, nil)
}

// testAPIWrappedStore is testAPIStoreFile with the Store the Server is handed
// passed through wrap first, for the tests that have to watch a store call the
// handlers make from inside it, when it happens and on what context, which no
// assertion made after the response can see. wrap may be nil. The *SQLStore
// returned is always the real one underneath, so a test can still read and
// write rows directly.
func testAPIWrappedStore(t *testing.T, publicURL string, wrap func(store.Store) store.Store) (*Server, http.Handler, *store.SQLStore, string) {
	t.Helper()
	key, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{
		AdminAPIKey:   "test-admin",
		EncryptionKey: key,
		PublicURL:     publicURL,
	}
	var backing store.Store = st
	if wrap != nil {
		backing = wrap(st)
	}
	s := New(cfg, backing, nil, mcpclient.New(), webutil.EncryptionOK)
	return s, s.Routes(), st, path
}

func doJSON(t *testing.T, h http.Handler, method, path, admin string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONAddr(t, h, method, path, admin, "", body)
}

func doJSONAddr(t *testing.T, h http.Handler, method, path, admin, addr string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if admin != "" {
		req.Header.Set("Authorization", "Bearer "+admin)
	}
	if addr != "" {
		req.RemoteAddr = addr
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// doJSONCtx is doJSON with a caller-supplied request context, for the tests
// that cancel it from inside a store call to stand in for a client that went
// away after its mutation committed.
func doJSONCtx(t *testing.T, h http.Handler, ctx context.Context, method, path, admin string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	if admin != "" {
		req.Header.Set("Authorization", "Bearer "+admin)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// wantsBody asserts that every fragment appears in the response body. Rejection
// tests use it because an operator has to be able to fix the request from the
// response alone: the reason has to survive to the body, and so does the field
// and index of the entry that caused it.
func wantsBody(t *testing.T, rr *httptest.ResponseRecorder, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(rr.Body.String(), w) {
			t.Fatalf("body %s does not mention %q", rr.Body.String(), w)
		}
	}
}

func TestAdminAuthRequired(t *testing.T) {
	_, h, _ := testAPI(t)
	rr := doJSON(t, h, http.MethodGet, "/upstreams", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestAdminAuthRateLimited(t *testing.T) {
	s, h, _ := testAPI(t)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	s.adminFails.SetClock(func() time.Time { return now })

	const ipA = "203.0.113.10:1234"
	const ipB = "203.0.113.20:1234"

	// Successes from A must not consume the failure budget.
	for i := 0; i < 5; i++ {
		rr := doJSONAddr(t, h, http.MethodGet, "/upstreams", "test-admin", ipA, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("success %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}

	for i := 0; i < 10; i++ {
		rr := doJSONAddr(t, h, http.MethodGet, "/upstreams", "wrong", ipA, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d, want 401", i+1, rr.Code)
		}
	}
	rr := doJSONAddr(t, h, http.MethodGet, "/upstreams", "wrong", ipA, nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("11th failure: %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"error":"too many requests"}` {
		t.Fatalf("429 body %q", got)
	}

	// A different IP is unaffected, including with the correct key.
	rr = doJSONAddr(t, h, http.MethodGet, "/upstreams", "wrong", ipB, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("ip B wrong key: %d", rr.Code)
	}
	rr = doJSONAddr(t, h, http.MethodGet, "/upstreams", "test-admin", ipB, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("ip B correct key: %d %s", rr.Code, rr.Body.String())
	}

	// Spoofed X-Forwarded-For must not open a fresh bucket (no trusted proxies).
	req := httptest.NewRequest(http.MethodGet, "/upstreams", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.RemoteAddr = ipA
	spoofed := httptest.NewRecorder()
	h.ServeHTTP(spoofed, req)
	if spoofed.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF: %d, want 429 (still ip A)", spoofed.Code)
	}

	now = now.Add(time.Minute)
	rr = doJSONAddr(t, h, http.MethodGet, "/upstreams", "wrong", ipA, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("after window, failure should be 401, got %d", rr.Code)
	}
	rr = doJSONAddr(t, h, http.MethodGet, "/upstreams", "test-admin", ipA, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("after window, correct key: %d %s", rr.Code, rr.Body.String())
	}
}

func TestVirtualKeyKeyOnce(t *testing.T) {
	_, h, _ := testAPI(t)
	rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin", map[string]any{
		"name": "GitHub", "url": "https://example.com/mcp",
		"auth_type": "bearer", "auth_config": map[string]string{"token": "sk-real"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create upstream %d %s", rr.Code, rr.Body.String())
	}
	var up map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &up); err != nil {
		t.Fatal(err)
	}
	if up["auth_configured"] != true {
		t.Fatalf("expected auth_configured: %+v", up)
	}
	if _, ok := up["auth_config"]; ok {
		t.Fatal("auth_config must not be returned")
	}
	if up["slug"] != "github" {
		t.Fatalf("expected a derived slug, got %v", up["slug"])
	}
	uid := up["id"].(string)

	rr = doJSON(t, h, http.MethodPost, "/virtual-keys", "test-admin", map[string]any{
		"name": "cursor-dev", "target_type": "upstream", "target_id": uid,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create virtual key %d %s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	key, _ := created["api_key"].(string)
	id, _ := created["id"].(string)
	if key == "" || created["proxy_url"] != "http://localhost:8080/"+id+"/mcp" {
		t.Fatalf("missing one-time key fields: %+v", created)
	}
	if err := auth.VerifyKey(key, ""); err == nil {
		t.Fatal("blank hash should not verify")
	}
	if _, _, _, _, err := auth.GenerateKey(); err != nil {
		t.Fatal(err)
	}

	rr = doJSON(t, h, http.MethodGet, "/virtual-keys", "test-admin", nil)
	var list struct {
		VirtualKeys []map[string]any `json:"virtual_keys"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.VirtualKeys) != 1 {
		t.Fatalf("virtual_keys=%v", list.VirtualKeys)
	}
	if _, ok := list.VirtualKeys[0]["api_key"]; ok && list.VirtualKeys[0]["api_key"] != nil && list.VirtualKeys[0]["api_key"] != "" {
		t.Fatal("plaintext key leaked on list")
	}

	rr = doJSON(t, h, http.MethodPost, "/virtual-keys/"+id+"/rotate", "test-admin", map[string]any{})
	var rotated map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &rotated)
	if rotated["api_key"] == "" || rotated["api_key"] == key {
		t.Fatalf("rotate should return a new key: %+v", rotated)
	}

	rr = doJSON(t, h, http.MethodPost, "/virtual-keys/"+id+"/revoke", "test-admin", map[string]any{})
	if rr.Code != 200 {
		t.Fatalf("revoke %d", rr.Code)
	}
	var revoked map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &revoked)
	if revoked["status"] != "revoked" {
		t.Fatalf("status=%v", revoked["status"])
	}

	rr = doJSON(t, h, http.MethodDelete, "/virtual-keys/"+id, "test-admin", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/virtual-keys/"+id, "test-admin", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete %d", rr.Code)
	}
}

// TestUnknownAPIPathIs404 pins that the API sub-router owns its NotFound
// handler. Status alone would not prove it: chi's default 404 is also 404, but
// it is text/plain, and a sub-router without its own handler inherits the
// dashboard SPA from cmd/server/main.go and answers 200 text/html instead.
func TestUnknownAPIPathIs404(t *testing.T) {
	_, h, _ := testAPI(t)
	for _, tc := range []struct{ method, path, admin string }{
		{http.MethodGet, "/nope", "test-admin"},
		{http.MethodGet, "/nope", ""},
		{http.MethodPost, "/nope/x/y", "test-admin"},
		// The pre-rename paths are gone, with no alias.
		{http.MethodGet, "/agents", "test-admin"},
		{http.MethodPost, "/agents", "test-admin"},
		{http.MethodPost, "/agents/x/rotate-key", "test-admin"},
		// rotate-key became rotate; the old segment must not linger.
		{http.MethodPost, "/virtual-keys/x/rotate-key", "test-admin"},
	} {
		rr := doJSON(t, h, tc.method, tc.path, tc.admin, nil)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s (admin=%q): status %d, want 404", tc.method, tc.path, tc.admin, rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s %s: content-type %q, want application/json", tc.method, tc.path, ct)
		}
		if got := strings.TrimSpace(rr.Body.String()); got != `{"error":"not found"}` {
			t.Errorf("%s %s: body %q", tc.method, tc.path, got)
		}
	}
	// The handler must not shadow real routes: known paths still route and
	// still enforce admin auth.
	if rr := doJSON(t, h, http.MethodGet, "/virtual-keys", "test-admin", nil); rr.Code != http.StatusOK {
		t.Errorf("GET /virtual-keys: status %d, want 200", rr.Code)
	}
	if rr := doJSON(t, h, http.MethodGet, "/virtual-keys", "", nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /virtual-keys without a key: status %d, want 401", rr.Code)
	}
}

func TestHealthUnauthenticated(t *testing.T) {
	_, h, _ := testAPI(t)
	rr := doJSON(t, h, http.MethodGet, "/health", "", nil)
	if rr.Code != 200 {
		t.Fatalf("health %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status=%v", body["status"])
	}
	if _, ok := body["scheme_enforced"].(bool); !ok {
		t.Fatalf("scheme_enforced missing: %v", body)
	}
	if _, ok := body["trusted_proxies"].(float64); !ok {
		t.Fatalf("trusted_proxies is not a number: %v", body)
	}
}

func TestGroupRequiresKnownUpstreams(t *testing.T) {
	_, h, _ := testAPI(t)
	rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", map[string]any{
		"name": "bundle", "upstream_ids": []string{"missing"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestGroupToolFilterValidation covers the write half of PORM-19's fail-closed
// filter, together with the {slug}__{tool} identity rules the write side adds
// on top of it: because the proxy blocks every tool call on a group whose
// filter it cannot enforce, a filter that would be unenforceable must never
// reach the database in the first place. Every rejected case here decodes into
// a ToolFilter without error and then matches nothing, they would all be
// stored and silently ignored.
func TestGroupToolFilterValidation(t *testing.T) {
	_, h, _ := testAPI(t)
	rr, up := newUpstream(t, h, upstreamBody("GitHub", nil))
	if up == nil {
		t.Fatalf("create upstream: %d %s", rr.Code, rr.Body.String())
	}
	upstreamIDs := []string{up["id"].(string)}
	group := func(name, filter string) map[string]any {
		return map[string]any{
			"name":         name,
			"upstream_ids": upstreamIDs,
			"tool_filter":  json.RawMessage(filter),
		}
	}

	for _, tc := range []struct {
		name, filter string
		wants        []string
	}{
		{"mode is matched byte for byte", `{"mode":"Deny","tools":["x"]}`, []string{"mode"}},
		{"misspelt key would be dropped", `{"mode":"deny","tool":["x"]}`, []string{"unknown field"}},
		{"an empty entry matches nothing", `{"mode":"deny","tools":[""]}`, []string{"tools[0]", "empty"}},
		{"an allowlist of nothing permits everything", `{"mode":"allow"}`, []string{"at least one entry"}},

		// The identity rules. The unscoped allow entry is the one that matters
		// most: the proxy skips it rather than read it as "this name on every
		// member", which would widen the rule to the whole group, so an allow
		// rule holding only unscoped entries admits nothing and the group is
		// silently dead.
		{"an unscoped allow entry admits nothing", `{"mode":"allow","tools":["delete_repo"]}`, []string{"tools[0]", "must name a member"}},
		{"an allow entry leading with the separator is unscoped too", `{"mode":"allow","tools":["__x"]}`, []string{"tools[0]", "must name a member"}},
		{"a head that could never equal a slug", `{"mode":"deny","tools":["Bad Slug__x"]}`, []string{"tools[0]"}},
		// Second in the list, so the index in the message has to be the
		// entry's own and cannot be a hard-coded nought.
		{"a scoped entry naming no tool", `{"mode":"deny","tools":["delete_repo","alpha__"]}`, []string{"tools[1]", "names no tool"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", group(tc.name, tc.filter))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
			}
			wantsBody(t, rr, tc.wants...)
		})
	}

	// The other half of the same rules: what an operator is still allowed to
	// write. Membership is deliberately not checked, the group here has one
	// member, github, and a filter may name docs or a member added tomorrow.
	for _, tc := range []struct{ name, filter string }{
		{"a scoped entry over a name that itself holds the separator", `{"mode":"allow","tools":["github__mcp__fetch"]}`},
		{"a scoped prefixes entry may end at the separator", `{"mode":"allow","prefixes":["docs__"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", group(tc.name, tc.filter))
			if rr.Code != http.StatusCreated {
				t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	// Bare on purpose, and left bare here for good: an unscoped entry on the
	// DENY side names a tool by its own name on every member at once, which is
	// exactly what an operator writing "never delete_repo" means, and it holds
	// on the aggregate endpoint and on each member endpoint alike. Only the
	// allow side needs a member, because only there does an unscoped entry mean
	// nothing at all. This case pins that the identity rules did not creep
	// across and break filters that were already correct.
	const good = `{"mode":"deny","tools":["delete_repo"]}`
	rr = doJSON(t, h, http.MethodPost, "/groups", "test-admin", group("enforceable", good))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create with an enforceable filter: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID         string          `json:"id"`
		ToolFilter json.RawMessage `json:"tool_filter"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if string(created.ToolFilter) != good {
		t.Fatalf("stored filter %s, want %s", created.ToolFilter, good)
	}

	// A rejected PATCH must not half-apply: the group keeps the filter it had.
	rr = doJSON(t, h, http.MethodPatch, "/groups/"+created.ID, "test-admin", map[string]any{
		"tool_filter": json.RawMessage(`{"mode":"Deny"}`),
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("patch code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "mode") {
		t.Fatalf("patch body %s does not mention mode", rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/groups/"+created.ID, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get code=%d body=%s", rr.Code, rr.Body.String())
	}
	var fetched struct {
		ToolFilter json.RawMessage `json:"tool_filter"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &fetched); err != nil {
		t.Fatal(err)
	}
	if string(fetched.ToolFilter) != good {
		t.Fatalf("filter after a rejected patch is %s, want %s", fetched.ToolFilter, good)
	}
}

// newUpstream posts an upstream body and returns the recorder plus the decoded
// object (nil when the response was not a 201).
func newUpstream(t *testing.T, h http.Handler, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin", body)
	if rr.Code != http.StatusCreated {
		return rr, nil
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return rr, out
}

func upstreamBody(name string, extra map[string]any) map[string]any {
	b := map[string]any{"name": name, "url": "https://example.com/mcp"}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestCreateUpstreamDerivesSlug(t *testing.T) {
	_, h, _ := testAPI(t)
	for i, want := range []string{"github_enterprise", "github_enterprise-2", "github_enterprise-3"} {
		rr, up := newUpstream(t, h, upstreamBody("GitHub Enterprise", nil))
		if up == nil {
			t.Fatalf("create %d: %d %s", i, rr.Code, rr.Body.String())
		}
		if up["slug"] != want {
			t.Fatalf("create %d slug = %v, want %q", i, up["slug"], want)
		}
	}

	// A suffix already claimed by hand is skipped, not overwritten.
	_, h2, _ := testAPI(t)
	if _, up := newUpstream(t, h2, upstreamBody("Taken", map[string]any{"slug": "github_enterprise-2"})); up == nil {
		t.Fatal("could not claim github_enterprise-2")
	}
	_, first := newUpstream(t, h2, upstreamBody("GitHub Enterprise", nil))
	if first == nil || first["slug"] != "github_enterprise" {
		t.Fatalf("first derived slug = %v", first)
	}
	_, second := newUpstream(t, h2, upstreamBody("GitHub Enterprise", nil))
	if second == nil || second["slug"] != "github_enterprise-3" {
		t.Fatalf("second derived slug = %v, want github_enterprise-3", second)
	}
}

func TestCreateUpstreamSlugConflict(t *testing.T) {
	_, h, _ := testAPI(t)
	// A distinctive name, so the leak assertion below cannot pass by accident the
	// way a single common letter would.
	_, first := newUpstream(t, h, upstreamBody("Payroll Vendor", map[string]any{"slug": "github_enterprise"}))
	if first == nil {
		t.Fatal("first create failed")
	}
	rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin",
		upstreamBody("B", map[string]any{"slug": "github_enterprise"}))
	if rr.Code != http.StatusConflict {
		t.Fatalf("code = %d, body %s", rr.Code, rr.Body.String())
	}
	body := strings.TrimSpace(rr.Body.String())
	if body != `{"error":"slug is already taken"}` {
		t.Fatalf("body = %s", body)
	}
	// The 409 must not disclose anything about the upstream that holds the slug.
	for _, leak := range []string{first["id"].(string), "Payroll Vendor", "example.com"} {
		if strings.Contains(body, leak) {
			t.Fatalf("409 body leaked %q: %s", leak, body)
		}
	}
}

func TestCreateUpstreamSlugInvalid(t *testing.T) {
	// Assert WHICH 400: status alone would still pass if the reserved check were
	// deleted and the value happened to fail the syntax rule instead, or if the
	// two messages were swapped.
	syntax := `{"error":"` + errSlugRule + `"}`
	reserved := `{"error":"slug is reserved"}`
	cases := map[string]struct{ slug, want string }{
		"space":    {"Bad Slug!", syntax},
		"leading":  {"_x", syntax},
		"trailing": {"x_", syntax},
		"sep run":  {"a__b", syntax},
		"slash":    {"a/b", syntax},
		"too long": {strings.Repeat("a", 41), syntax},
		"reserved": {"mcp", reserved},
		"uuid":     {"550e8400-e29b-41d4-a716-446655440000", syntax},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, h, _ := testAPI(t)
			rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin",
				upstreamBody("Thing", map[string]any{"slug": c.slug}))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("slug %q: code = %d, body %s", c.slug, rr.Code, rr.Body.String())
			}
			if got := strings.TrimSpace(rr.Body.String()); got != c.want {
				t.Fatalf("slug %q: body = %s, want %s", c.slug, got, c.want)
			}
		})
	}
}

func TestCreateUpstreamSlugNormalisesCase(t *testing.T) {
	_, h, _ := testAPI(t)
	_, up := newUpstream(t, h, upstreamBody("Whatever", map[string]any{"slug": "GitHub_Enterprise"}))
	if up == nil || up["slug"] != "github_enterprise" {
		t.Fatalf("slug = %v, want github_enterprise", up)
	}
}

// TestCreateUpstreamBlankSlugDerives pins the deliberate create/PATCH asymmetry:
// on create there is nothing to clear, so a blank slug means "derive one".
func TestCreateUpstreamBlankSlugDerives(t *testing.T) {
	for _, blank := range []string{"", "   "} {
		_, h, _ := testAPI(t)
		_, up := newUpstream(t, h, upstreamBody("GitHub", map[string]any{"slug": blank}))
		if up == nil || up["slug"] != "github" {
			t.Fatalf("slug %q gave %v, want github", blank, up)
		}
	}
}

func TestCreateUpstreamUnslugifiableName(t *testing.T) {
	_, h, _ := testAPI(t)
	_, first := newUpstream(t, h, upstreamBody("日本語", nil))
	if first == nil || first["slug"] != "up" {
		t.Fatalf("first slug = %v, want up", first)
	}
	_, second := newUpstream(t, h, upstreamBody("日本語", nil))
	if second == nil || second["slug"] != "up-2" {
		t.Fatalf("second slug = %v, want up-2", second)
	}
}

// TestCreateUpstreamSlugRace covers the branch createUpstreamDerivedSlug exists
// for. SetMaxOpenConns(1) (sqlstore.go) largely serialises SQLite writes, so this
// is a regression guard on the retry path rather than a tight-window race prover,
// it would still catch a version that surfaced a lost race as a 500.
func TestCreateUpstreamSlugRace(t *testing.T) {
	const n = 8

	t.Run("derived", func(t *testing.T) {
		_, h, _ := testAPI(t)
		codes := make([]int, n)
		slugs := make([]string, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin", upstreamBody("GitHub", nil))
				codes[i] = rr.Code
				var up map[string]any
				if json.Unmarshal(rr.Body.Bytes(), &up) == nil {
					slugs[i], _ = up["slug"].(string)
				}
			}(i)
		}
		wg.Wait()
		seen := map[string]bool{}
		for i, c := range codes {
			if c != http.StatusCreated {
				t.Fatalf("goroutine %d: code = %d slug=%q", i, c, slugs[i])
			}
			if slugs[i] == "" {
				t.Fatalf("goroutine %d returned no slug", i)
			}
			if seen[slugs[i]] {
				t.Fatalf("duplicate slug %q", slugs[i])
			}
			seen[slugs[i]] = true
		}
	})

	t.Run("explicit", func(t *testing.T) {
		_, h, _ := testAPI(t)
		codes := make([]int, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin",
					upstreamBody("GitHub", map[string]any{"slug": "github"}))
				codes[i] = rr.Code
			}(i)
		}
		wg.Wait()
		created := 0
		for i, c := range codes {
			switch c {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
			default:
				t.Fatalf("goroutine %d: code = %d, want 201 or 409", i, c)
			}
		}
		if created != 1 {
			t.Fatalf("got %d 201s for the same explicit slug, want exactly 1", created)
		}
	})
}

// nonHTTPURLs are the shapes an upstream URL must not take. Every one of them
// was stored happily before this check landed, and not one is a URL PoryMCP
// could ever connect to, an operator found that out when a call failed with a
// message about the upstream rather than about what they typed.
var nonHTTPURLs = []string{
	"file:///etc/passwd",
	"//evil/mcp",         // scheme-relative: no scheme at all
	"localhost:8080/mcp", // parses as scheme "localhost", opaque "8080/mcp"
	"ftp://h/",
	"https://",           // a scheme and no host
	"https://h/mcp#frag", // a fragment is not part of a request
	"not a url at all",
}

// httpURLs must keep working: this check is about the scheme and the host, and
// nothing else about a URL is any of its business.
var httpURLs = []string{
	"HTTPS://h/mcp?ok=1", // url.Parse lower-cases the scheme
	"http://h/mcp?ok=1",
	"https://h:8443/path",
}

func TestCreateUpstreamRejectsNonHTTPURL(t *testing.T) {
	_, h, _ := testAPI(t)
	for _, raw := range nonHTTPURLs {
		rr, up := newUpstream(t, h, upstreamBody("Bad", map[string]any{"url": raw}))
		if rr.Code != http.StatusBadRequest || up != nil {
			t.Fatalf("create with url %q: %d %s", raw, rr.Code, rr.Body.String())
		}
		wantsBody(t, rr, "url must be an absolute http or https URL")
	}
	for i, raw := range httpURLs {
		rr, up := newUpstream(t, h, upstreamBody("Good", map[string]any{
			"url": raw, "slug": []string{"ok-a", "ok-b", "ok-c"}[i],
		}))
		if up == nil {
			t.Fatalf("create with url %q: %d %s", raw, rr.Code, rr.Body.String())
		}
	}
}

func TestPatchUpstreamRejectsNonHTTPURL(t *testing.T) {
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", nil)
	for _, raw := range nonHTTPURLs {
		rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"url": raw})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("patch with url %q: %d %s", raw, rr.Code, rr.Body.String())
		}
		wantsBody(t, rr, "url must be an absolute http or https URL")
	}
	// A body without a url leaves the stored url alone. A blank url is a 400
	// (TestPatchRejectsBlankRequiredFields), so this request sends none.
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"name": "Renamed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch without a url: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["url"] != "https://example.com/mcp" {
		t.Fatalf("the stored url changed: %v", out["url"])
	}
}

// TestPatchUpstreamNameKeepsSlug is AC 3 of PORM-48. It asserts only on the
// slug; TestPatchUpstreamKeepsDescription (PORM-21) covers the description.
func TestPatchUpstreamNameKeepsSlug(t *testing.T) {
	_, h, _ := testAPI(t)
	_, up := newUpstream(t, h, upstreamBody("GitHub", nil))
	if up == nil || up["slug"] != "github" {
		t.Fatalf("create: %v", up)
	}
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+up["id"].(string), "test-admin",
		map[string]any{"name": "Renamed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["name"] != "Renamed" {
		t.Fatalf("name = %v", got["name"])
	}
	if got["slug"] != "github" {
		t.Fatalf("renaming moved the slug to %v", got["slug"])
	}
}

func TestPatchUpstreamSlugIsImmutable(t *testing.T) {
	_, h, _ := testAPI(t)
	_, up := newUpstream(t, h, upstreamBody("GitHub", nil))
	if up == nil || up["slug"] != "github" {
		t.Fatalf("create: %v", up)
	}
	id := up["id"].(string)

	// Any differing value is refused with one message, valid, blank or invalid
	// alike, because no slug change is legal.
	for _, bad := range []string{"other", "", "Bad!"} {
		rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"slug": bad})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("patch slug %q: code = %d, body %s", bad, rr.Code, rr.Body.String())
		}
		body := strings.TrimSpace(rr.Body.String())
		if body != `{"error":"`+errSlugImmutable+`"}` {
			t.Fatalf("patch slug %q: body = %s", bad, body)
		}
	}

	// The current value, in any case, round-trips as a no-op.
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"slug": "GitHub"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch with the current slug: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["slug"] != "github" {
		t.Fatalf("slug = %v after a no-op patch", got["slug"])
	}

	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"name": "Renamed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch name: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["slug"] != "github" {
		t.Fatalf("slug = %v after renaming", got["slug"])
	}
}

// --- The recorded test result across create and PATCH (PORM-58) ---

// recordTestOn presses Tools once against a working stub, so that a PATCH has a
// real result to keep or to reset. It returns the recorded last_test_at.
func recordTestOn(t *testing.T, h http.Handler, id string) any {
	t.Helper()
	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}
	at, ok, _ := upstreamTest(t, h, id)
	if at == nil || ok != true {
		t.Fatalf("the press was not recorded: at=%v ok=%v", at, ok)
	}
	return at
}

// patchUpstreamJSON PATCHes and returns the decoded 200 body, so an assertion
// can be made about what the caller was told before anything is re-read.
func patchUpstreamJSON(t *testing.T, h http.Handler, id string, body map[string]any) map[string]any {
	t.Helper()
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH %v: %d %s", body, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPatchUpstreamCannotSetTestResult: the two columns are written by
// POST /upstreams/{id}/discover and by nothing else. upsertUpstream has no such
// fields, so a client that sends them is claiming a test that never ran.
func TestPatchUpstreamCannotSetTestResult(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})
	at := recordTestOn(t, h, id)

	got := patchUpstreamJSON(t, h, id, map[string]any{
		"name":         "Renamed",
		"last_test_at": "1999-01-01T00:00:00Z",
		"last_test_ok": false,
	})
	if got["name"] != "Renamed" {
		t.Fatalf("name = %v, want the rest of the patch to have landed", got["name"])
	}
	if got["last_test_at"] != at || got["last_test_ok"] != true {
		t.Fatalf("the response carried at=%v ok=%v, want the recorded %v/true", got["last_test_at"], got["last_test_ok"], at)
	}
	if gotAt, gotOK, _ := upstreamTest(t, h, id); gotAt != at || gotOK != true {
		t.Fatalf("the row carries at=%v ok=%v, want the recorded %v/true", gotAt, gotOK, at)
	}
}

// TestPatchUpstreamNameKeepsTestResult: an edit that changes no part of the
// connection leaves the result alone. Greying a valid result on every rename is
// exactly the failure a client-side "last_test_at < updated_at" rule would have.
func TestPatchUpstreamNameKeepsTestResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"name", map[string]any{"name": "Renamed"}},
		{"description", map[string]any{"name": "GitHub", "description": "the prod one"}},
		{"enabled", map[string]any{"enabled": false}},
		// A null auth_config is "leave the credential alone", the same reading
		// the assignment makes; only a present, non-null one is a change.
		{"null auth_config", map[string]any{"auth_config": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newMCPStub(t)
			_, h, _ := testAPI(t)
			id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})
			at := recordTestOn(t, h, id)

			got := patchUpstreamJSON(t, h, id, tc.body)
			if got["last_test_at"] != at || got["last_test_ok"] != true {
				t.Fatalf("the response reset the result: at=%v ok=%v", got["last_test_at"], got["last_test_ok"])
			}
			if gotAt, gotOK, _ := upstreamTest(t, h, id); gotAt != at || gotOK != true {
				t.Fatalf("the row reset the result: at=%v ok=%v", gotAt, gotOK)
			}
		})
	}
}

// TestPatchUpstreamSameURLKeepsTestResult: a client that round-trips the whole
// object back (sending the stored url, transport and auth_type verbatim)
// changes nothing, so it resets nothing.
func TestPatchUpstreamSameURLKeepsTestResult(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})
	at := recordTestOn(t, h, id)

	got := patchUpstreamJSON(t, h, id, map[string]any{
		"name":      "GitHub",
		"url":       stub.srv.URL,
		"transport": "streamable-http",
		"auth_type": "none",
	})
	if got["last_test_at"] != at || got["last_test_ok"] != true {
		t.Fatalf("a verbatim round-trip reset the result: at=%v ok=%v", got["last_test_at"], got["last_test_ok"])
	}
	if gotAt, gotOK, _ := upstreamTest(t, h, id); gotAt != at || gotOK != true {
		t.Fatalf("the row reset the result: at=%v ok=%v", gotAt, gotOK)
	}
}

// TestPatchUpstreamURLResetsTestResult is the security requirement: a dot must
// never vouch for a configuration nobody tested. Every field that changes what
// PoryMCP dials or presents resets both columns, in the same statement as the
// edit, and the PATCH response says so, which is what the dashboard renders
// before any re-read.
func TestPatchUpstreamURLResetsTestResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"url", map[string]any{"url": "https://new.example.com/mcp/"}},
		{"transport", map[string]any{"transport": "sse"}},
		{"auth_type", map[string]any{"auth_type": "bearer"}},
		// Ciphertext cannot be compared (Keyring.Seal draws a fresh nonce per
		// call) so a present, non-null auth_config always counts.
		{"auth_config", map[string]any{"auth_config": map[string]string{"token": "sk-new"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newMCPStub(t)
			_, h, _ := testAPI(t)
			id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})
			recordTestOn(t, h, id)

			got := patchUpstreamJSON(t, h, id, tc.body)
			if got["last_test_at"] != nil || got["last_test_ok"] != nil {
				t.Fatalf("the PATCH response still vouches for the old settings: at=%v ok=%v",
					got["last_test_at"], got["last_test_ok"])
			}
			if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
				t.Fatalf("the row still vouches for the old settings: at=%v ok=%v", at, ok)
			}
		})
	}
}

// TestCreateUpstreamIgnoresTestFields: a brand new upstream has never been
// tested, whatever the create body claims.
func TestCreateUpstreamIgnoresTestFields(t *testing.T) {
	_, h, _ := testAPI(t)
	rr, up := newUpstream(t, h, upstreamBody("GitHub", map[string]any{
		"last_test_at": "1999-01-01T00:00:00Z",
		"last_test_ok": true,
	}))
	if up == nil {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	for _, k := range []string{"last_test_at", "last_test_ok"} {
		v, present := up[k]
		if !present {
			t.Fatalf("%s is missing from the 201; a three-state cell needs an explicit null: %s", k, rr.Body.String())
		}
		if v != nil {
			t.Fatalf("%s = %v on a brand new upstream, want null", k, v)
		}
	}
	if at, ok, _ := upstreamTest(t, h, up["id"].(string)); at != nil || ok != nil {
		t.Fatalf("the stored row reads back tested: at=%v ok=%v", at, ok)
	}
}

func TestListUpstreamsIncludesSlug(t *testing.T) {
	_, h, _ := testAPI(t)
	for _, n := range []string{"GitHub", "Linear"} {
		if _, up := newUpstream(t, h, upstreamBody(n, nil)); up == nil {
			t.Fatalf("create %s failed", n)
		}
	}
	rr := doJSON(t, h, http.MethodGet, "/upstreams", "test-admin", nil)
	var list struct {
		Upstreams []map[string]any `json:"upstreams"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Upstreams) != 2 {
		t.Fatalf("upstreams = %v", list.Upstreams)
	}
	seen := map[string]bool{}
	for _, u := range list.Upstreams {
		slug, _ := u["slug"].(string)
		if slug == "" {
			t.Fatalf("upstream without a slug: %v", u)
		}
		if seen[slug] {
			t.Fatalf("duplicate slug %q", slug)
		}
		seen[slug] = true
	}
}

// --- endpoints[] (PORM-14) ---
//
// Every virtual-key response carries an endpoints array: one 1:1 URL per
// enabled member of the target, always an array, never null.

// mustUpstream creates an upstream through the API and returns its id and the
// slug the server derived.
func mustUpstream(t *testing.T, h http.Handler, name string, extra map[string]any) (id, slug string) {
	t.Helper()
	rr, up := newUpstream(t, h, upstreamBody(name, extra))
	if up == nil {
		t.Fatalf("create upstream %q: %d %s", name, rr.Code, rr.Body.String())
	}
	id, _ = up["id"].(string)
	slug, _ = up["slug"].(string)
	if id == "" || slug == "" {
		t.Fatalf("upstream %q has no id/slug: %v", name, up)
	}
	return id, slug
}

func mustGroup(t *testing.T, h http.Handler, name string, upstreamIDs []string) string {
	t.Helper()
	rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", map[string]any{
		"name": name, "upstream_ids": upstreamIDs,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create group %q: %d %s", name, rr.Code, rr.Body.String())
	}
	var g map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	id, _ := g["id"].(string)
	if id == "" {
		t.Fatalf("group %q has no id: %v", name, g)
	}
	return id
}

// mustVirtualKey creates a virtual key and returns the whole 201 body, so the
// caller can assert on what the one-time-key response carried.
func mustVirtualKey(t *testing.T, h http.Handler, name, targetType, targetID string) map[string]any {
	t.Helper()
	rr := doJSON(t, h, http.MethodPost, "/virtual-keys", "test-admin", map[string]any{
		"name": name, "target_type": targetType, "target_id": targetID,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create virtual key %q: %d %s", name, rr.Code, rr.Body.String())
	}
	var vk map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &vk); err != nil {
		t.Fatal(err)
	}
	return vk
}

// endpointsOf pulls the endpoints array out of a virtual-key body. It fails if
// the field is absent or null: the contract is that it is always an array.
func endpointsOf(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["endpoints"]
	if !ok {
		t.Fatalf("no endpoints field: %v", body)
	}
	list, ok := raw.([]any)
	if !ok {
		t.Fatalf("endpoints is not an array (%T): %v", raw, raw)
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("endpoint is not an object: %v", e)
		}
		out = append(out, m)
	}
	return out
}

// endpointsJSON re-marshals the endpoints array so two responses can be
// compared as one string, ordering included.
func endpointsJSON(t *testing.T, body map[string]any) string {
	t.Helper()
	b, err := json.Marshal(endpointsOf(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// getVirtualKeyBody fetches one key and returns both the decoded body and the
// raw JSON, because some assertions here are about the bytes on the wire.
func getVirtualKeyBody(t *testing.T, h http.Handler, id string) (map[string]any, string) {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+id, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get virtual key: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out, rr.Body.String()
}

func wantEndpoint(t *testing.T, got map[string]any, upstreamID, slug, name, url string) {
	t.Helper()
	if got["upstream_id"] != upstreamID || got["slug"] != slug || got["name"] != name || got["url"] != url {
		t.Fatalf("endpoint = %v, want {upstream_id:%s slug:%s name:%s url:%s}", got, upstreamID, slug, name, url)
	}
}

// TestVirtualKeyEndpointsForGroup pins the group shape: one entry per ENABLED
// member, in the stored membership order, and the aggregate proxy_url is not
// one of them.
func TestVirtualKeyEndpointsForGroup(t *testing.T) {
	_, h, _ := testAPI(t)
	ghID, ghSlug := mustUpstream(t, h, "GitHub", nil)
	linID, linSlug := mustUpstream(t, h, "Linear", nil)
	arcID, arcSlug := mustUpstream(t, h, "Archive", map[string]any{"enabled": false})
	if ghSlug != "github" || linSlug != "linear" || arcSlug != "archive" {
		t.Fatalf("derived slugs = %q %q %q", ghSlug, linSlug, arcSlug)
	}
	gid := mustGroup(t, h, "bundle", []string{ghID, linID, arcID})
	id, _ := mustVirtualKey(t, h, "agent", "group", gid)["id"].(string)

	body, raw := getVirtualKeyBody(t, h, id)
	eps := endpointsOf(t, body)
	if len(eps) != 2 {
		t.Fatalf("endpoints = %v, want 2 (the disabled member has none)", eps)
	}
	wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+id+"/github/mcp")
	wantEndpoint(t, eps[1], linID, "linear", "Linear", "http://localhost:8080/"+id+"/linear/mcp")
	// The disabled member must not appear at all: its URL answers 404, and a
	// consumer that had to filter would be one forgotten filter from writing a
	// broken client config.
	if strings.Contains(raw, "archive") || strings.Contains(raw, "Archive") {
		t.Fatalf("disabled member present in the body: %s", raw)
	}
	// proxy_url is the aggregate endpoint: unchanged, and never an entry,
	// listing it beside the members would advertise the merged view as if it
	// were one more server.
	wantProxy := "http://localhost:8080/" + id + "/mcp"
	if body["proxy_url"] != wantProxy {
		t.Fatalf("proxy_url = %v, want %s", body["proxy_url"], wantProxy)
	}
	for _, e := range eps {
		if e["url"] == wantProxy {
			t.Fatalf("the aggregate proxy_url is an endpoint entry: %v", eps)
		}
	}

	t.Run("disabling a member drops its endpoint", func(t *testing.T) {
		rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+linID, "test-admin", map[string]any{"enabled": false})
		if rr.Code != http.StatusOK {
			t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
		}
		body, _ := getVirtualKeyBody(t, h, id)
		eps := endpointsOf(t, body)
		if len(eps) != 1 {
			t.Fatalf("endpoints = %v, want github only", eps)
		}
		wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+id+"/github/mcp")
	})

	t.Run("a patch that changes the target re-resolves endpoints", func(t *testing.T) {
		// A patch is presented after the write, from the mutated key, so the
		// response must follow the target in both directions.
		rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin",
			map[string]any{"target_type": "upstream", "target_id": ghID})
		if rr.Code != http.StatusOK {
			t.Fatalf("patch to upstream: %d %s", rr.Code, rr.Body.String())
		}
		var patched map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &patched); err != nil {
			t.Fatal(err)
		}
		eps := endpointsOf(t, patched)
		if len(eps) != 1 {
			t.Fatalf("upstream-target endpoints = %v, want one mirror entry", eps)
		}
		// On a single-upstream target the one entry mirrors proxy_url.
		wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+id+"/mcp")

		rr = doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin",
			map[string]any{"target_type": "group", "target_id": gid})
		if rr.Code != http.StatusOK {
			t.Fatalf("patch back to group: %d %s", rr.Code, rr.Body.String())
		}
		body, _ := getVirtualKeyBody(t, h, id)
		eps = endpointsOf(t, body)
		if len(eps) != 1 {
			t.Fatalf("group-target endpoints = %v, want github only (linear is disabled)", eps)
		}
		wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+id+"/github/mcp")
	})

	t.Run("a revoked key keeps its endpoints", func(t *testing.T) {
		rr := doJSON(t, h, http.MethodPost, "/virtual-keys/"+id+"/revoke", "test-admin", map[string]any{})
		if rr.Code != http.StatusOK {
			t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
		}
		var revoked map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &revoked); err != nil {
			t.Fatal(err)
		}
		if revoked["status"] != "revoked" {
			t.Fatalf("status = %v", revoked["status"])
		}
		// Endpoints are a property of the target, not of the key's status, so
		// they stay exactly as proxy_url does; the URLs stop
		// authenticating.
		eps := endpointsOf(t, revoked)
		if len(eps) != 1 {
			t.Fatalf("revoked endpoints = %v, want the enabled member", eps)
		}
		wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+id+"/github/mcp")
	})
}

// TestVirtualKeyEndpointsMirrorSingleUpstream pins the mirror invariant: on a
// single-upstream key the aggregate endpoint is already 1:1, so the one entry
// carries proxy_url and not the group-only /{slug}/mcp route.
func TestVirtualKeyEndpointsMirrorSingleUpstream(t *testing.T) {
	_, h, _ := testAPI(t)
	upstreamID, slug := mustUpstream(t, h, "GitHub", nil)
	id, _ := mustVirtualKey(t, h, "cursor", "upstream", upstreamID)["id"].(string)

	body, _ := getVirtualKeyBody(t, h, id)
	eps := endpointsOf(t, body)
	if len(eps) != 1 {
		t.Fatalf("endpoints = %v, want exactly one", eps)
	}
	e := eps[0]
	if e["upstream_id"] != upstreamID || e["slug"] != slug || e["name"] != "GitHub" {
		t.Fatalf("endpoint = %v", e)
	}
	// The equality is the point, not the literal string.
	if e["url"] != body["proxy_url"] {
		t.Fatalf("url = %v, want proxy_url %v", e["url"], body["proxy_url"])
	}
	if e["url"] == "http://localhost:8080/"+id+"/"+slug+"/mcp" {
		t.Fatalf("single-upstream key advertises the group-only member route: %v", e)
	}
}

// TestVirtualKeyEndpointsHonourPublicURLPathPrefix pins the joining: a
// PUBLIC_URL with a path prefix produces exactly one slash between the prefix
// and the key id.
func TestVirtualKeyEndpointsHonourPublicURLPathPrefix(t *testing.T) {
	// No trailing slash: testAPIPublicURL bypasses config.Load, which is the
	// only place PUBLIC_URL is trimmed.
	const public = "https://porymcp.example.com/pory"
	_, h, _ := testAPIPublicURL(t, public)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	docsID, _ := mustUpstream(t, h, "Docs", nil)
	gid := mustGroup(t, h, "bundle", []string{ghID, docsID})
	id, _ := mustVirtualKey(t, h, "agent", "group", gid)["id"].(string)

	body, _ := getVirtualKeyBody(t, h, id)
	if body["proxy_url"] != public+"/"+id+"/mcp" {
		t.Fatalf("proxy_url = %v", body["proxy_url"])
	}
	eps := endpointsOf(t, body)
	if len(eps) != 2 {
		t.Fatalf("endpoints = %v, want 2", eps)
	}
	for _, e := range eps {
		slug, _ := e["slug"].(string)
		url, _ := e["url"].(string)
		if want := public + "/" + id + "/" + slug + "/mcp"; url != want {
			t.Fatalf("url = %q, want %q", url, want)
		}
		if strings.Contains(strings.TrimPrefix(url, "https://"), "//") {
			t.Fatalf("doubled slash in %q", url)
		}
	}
}

// TestVirtualKeyEndpointsOnCreateAndRotate: the one-time-key dialog must be
// able to write a client config from the response it already has.
func TestVirtualKeyEndpointsOnCreateAndRotate(t *testing.T) {
	_, h, _ := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	linID, _ := mustUpstream(t, h, "Linear", nil)
	gid := mustGroup(t, h, "bundle", []string{ghID, linID})

	created := mustVirtualKey(t, h, "agent", "group", gid)
	id, _ := created["id"].(string)
	if key, _ := created["api_key"].(string); key == "" {
		t.Fatalf("create returned no plaintext key: %v", created)
	}
	if eps := endpointsOf(t, created); len(eps) != 2 {
		t.Fatalf("create endpoints = %v, want 2", eps)
	}

	rr := doJSON(t, h, http.MethodPost, "/virtual-keys/"+id+"/rotate", "test-admin", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	var rotated map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}

	fetched, _ := getVirtualKeyBody(t, h, id)
	want := endpointsJSON(t, fetched)
	if got := endpointsJSON(t, created); got != want {
		t.Fatalf("create endpoints = %s, want %s", got, want)
	}
	// Rotation changes the key, never the target, so the endpoints are the same.
	if got := endpointsJSON(t, rotated); got != want {
		t.Fatalf("rotate endpoints = %s, want %s", got, want)
	}
}

// TestVirtualKeyEndpointsAlwaysAnArray is the nil-slice guard: a group whose
// only member is disabled has nothing reachable, and that is [] and a 200,
// not null, and not an error.
func TestVirtualKeyEndpointsAlwaysAnArray(t *testing.T) {
	_, h, _ := testAPI(t)
	arcID, _ := mustUpstream(t, h, "Archive", map[string]any{"enabled": false})
	gid := mustGroup(t, h, "bundle", []string{arcID})
	id, _ := mustVirtualKey(t, h, "agent", "group", gid)["id"].(string)

	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+id, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	// Assert on the bytes: a nil slice marshals to null, which a decoded
	// len() == 0 check would happily accept.
	raw := rr.Body.String()
	if !strings.Contains(raw, `"endpoints":[]`) {
		t.Fatalf(`want "endpoints":[] in %s`, raw)
	}
	if strings.Contains(raw, `"endpoints":null`) {
		t.Fatalf("endpoints marshalled as null: %s", raw)
	}
}

// TestListVirtualKeysIncludesEndpoints guards the list path: every key gets its
// own endpoints, and one key with a broken target does not spoil the page.
func TestListVirtualKeysIncludesEndpoints(t *testing.T) {
	_, h, st := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	linID, _ := mustUpstream(t, h, "Linear", nil)
	gid := mustGroup(t, h, "bundle", []string{ghID, linID})
	groupKeyID, _ := mustVirtualKey(t, h, "agent", "group", gid)["id"].(string)
	upstreamKeyID, _ := mustVirtualKey(t, h, "cursor", "upstream", ghID)["id"].(string)

	// A key whose group no longer exists. DeleteGroup returns ErrInUse while a
	// key references the group, so this dangling reference is seeded the only
	// way it can arise in the wild: at the database level.
	const danglingID = "dangling-virtual-key"
	if err := st.CreateVirtualKey(context.Background(), &models.VirtualKey{
		ID:         danglingID,
		Name:       "orphan",
		KeyHash:    "not-a-real-hash",
		KeyLookup:  "dangling-lookup",
		KeyPrefix:  "pory_dang",
		TargetType: models.TargetGroup,
		TargetID:   "no-such-group",
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	rr := doJSON(t, h, http.MethodGet, "/virtual-keys", "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	var list struct {
		VirtualKeys []map[string]any `json:"virtual_keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, k := range list.VirtualKeys {
		id, _ := k["id"].(string)
		byID[id] = k
	}
	if len(byID) != 3 {
		t.Fatalf("virtual_keys = %v", list.VirtualKeys)
	}

	eps := endpointsOf(t, byID[groupKeyID])
	if len(eps) != 2 {
		t.Fatalf("group key endpoints = %v", eps)
	}
	wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+groupKeyID+"/github/mcp")
	wantEndpoint(t, eps[1], linID, "linear", "Linear", "http://localhost:8080/"+groupKeyID+"/linear/mcp")

	eps = endpointsOf(t, byID[upstreamKeyID])
	if len(eps) != 1 {
		t.Fatalf("upstream key endpoints = %v", eps)
	}
	wantEndpoint(t, eps[0], ghID, "github", "GitHub", "http://localhost:8080/"+upstreamKeyID+"/mcp")

	// The orphan lists as 200 with an empty array. A missing target is a data
	// condition, and must never 404 or 500 the whole page.
	if eps := endpointsOf(t, byID[danglingID]); len(eps) != 0 {
		t.Fatalf("dangling key endpoints = %v", eps)
	}
}

// idOf pulls the id out of a create response, for the tests that need to keep
// working with the object they just made.
func idOf(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID == "" {
		t.Fatalf("no id in %s", rr.Body.String())
	}
	return out.ID
}

// countVirtualKeys is how a test asks whether a write happened at all, without
// having to know what the key would have been called.
func countVirtualKeys(t *testing.T, h http.Handler) int {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys", "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list virtual keys: %d %s", rr.Code, rr.Body.String())
	}
	var list struct {
		VirtualKeys []map[string]any `json:"virtual_keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	return len(list.VirtualKeys)
}

// storedLists reads one key's two entry lists back, so a test can assert that a
// rejected write changed nothing.
func storedLists(t *testing.T, h http.Handler, id string) (allow, deny []string) {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+id, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get virtual key: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ToolAllowlist []string `json:"tool_allowlist"`
		ToolDenylist  []string `json:"tool_denylist"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.ToolAllowlist, out.ToolDenylist
}

// TestVirtualKeyToolListValidation covers a virtual key's own two entry lists,
// which were validated nowhere at all: the proxy matches them byte for byte and
// the denylist outranks every other rule, so a trailing space was a deny that
// denied nothing and looked perfectly right everywhere it was displayed. That
// is the one rule in the system that failed OPEN on a typo.
//
// The allow-side rule is refused here even though the proxy also skips an
// unscoped allow entry when it reads one. The two are not redundant: the skip
// is what stops a key ALREADY in the database from widening to every member of
// its group, and it can only ever fail closed and in silence; this 400 is what
// stops a new one being written that way, while the operator is still here to
// be told which entry it was and how to spell it.
func TestVirtualKeyToolListValidation(t *testing.T) {
	_, h, st := testAPI(t)
	ghID, ghSlug := mustUpstream(t, h, "GitHub", nil)
	docsID, docsSlug := mustUpstream(t, h, "Docs", nil)
	gid := mustGroup(t, h, "bundle", []string{ghID, docsID})

	create := func(name, targetType, targetID string, lists map[string]any) *httptest.ResponseRecorder {
		body := map[string]any{"name": name, "target_type": targetType, "target_id": targetID}
		for k, v := range lists {
			body[k] = v
		}
		return doJSON(t, h, http.MethodPost, "/virtual-keys", "test-admin", body)
	}
	patch := func(id string, body map[string]any) *httptest.ResponseRecorder {
		return doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", body)
	}

	t.Run("entry text is judged on create and on patch alike", func(t *testing.T) {
		// A single-upstream target throughout, so the allow-side scoping rule
		// cannot be what does the rejecting: the text is the whole objection.
		victim, _ := mustVirtualKey(t, h, "text patch target", "upstream", ghID)["id"].(string)
		for _, tc := range []struct {
			name, field, entry string
			wants              []string
		}{
			{"an empty entry", "tool_denylist", "", []string{"tool_denylist[0]", "empty"}},
			{"a trailing space", "tool_denylist", "delete_repo ", []string{"tool_denylist[0]", "whitespace"}},
			{"a control character", "tool_allowlist", "delete\x01repo", []string{"tool_allowlist[0]", "control character"}},
			{"a byte the decoder replaced", "tool_allowlist", "delete�repo", []string{"tool_allowlist[0]", "valid UTF-8"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rr := create(tc.name, "upstream", ghID, map[string]any{tc.field: []string{tc.entry}})
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("create code=%d body=%s", rr.Code, rr.Body.String())
				}
				wantsBody(t, rr, tc.wants...)

				rr = patch(victim, map[string]any{tc.field: []string{tc.entry}})
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("patch code=%d body=%s", rr.Code, rr.Body.String())
				}
				wantsBody(t, rr, tc.wants...)
			})
		}
		if allow, deny := storedLists(t, h, victim); len(allow) != 0 || len(deny) != 0 {
			t.Fatalf("rejected patches still wrote: allow=%v deny=%v", allow, deny)
		}
	})

	t.Run("a rejected create mints no key", func(t *testing.T) {
		// auth.GenerateKey draws from the CSPRNG and the plaintext lives only
		// in the 201 body, so a key minted for a request that then 400s is a
		// row nobody could ever authenticate with, which is why the lists are
		// checked before it is called rather than after.
		before := countVirtualKeys(t, h)
		rr := create("stillborn", "group", gid, map[string]any{"tool_allowlist": []string{"delete_repo"}})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("create code=%d body=%s", rr.Code, rr.Body.String())
		}
		if after := countVirtualKeys(t, h); after != before {
			t.Fatalf("%d virtual keys before the rejected create, %d after", before, after)
		}
	})

	t.Run("an unscoped allow entry needs a member only on a group", func(t *testing.T) {
		rr := create("group allow", "group", gid, map[string]any{"tool_allowlist": []string{"delete_repo"}})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("create on a group: %d %s", rr.Code, rr.Body.String())
		}
		wantsBody(t, rr, "tool_allowlist[0]", "must name a member")

		// The same list on a single upstream is exactly right: there is only
		// one member for the bare name to mean.
		rr = create("upstream allow", "upstream", ghID, map[string]any{"tool_allowlist": []string{"delete_repo"}})
		if rr.Code != http.StatusCreated {
			t.Fatalf("create on an upstream: %d %s", rr.Code, rr.Body.String())
		}
		if rr := patch(idOf(t, rr), map[string]any{"tool_allowlist": []string{"read_issue"}}); rr.Code != http.StatusOK {
			t.Fatalf("patch on an upstream key: %d %s", rr.Code, rr.Body.String())
		}

		// A list-only PATCH of a group key is judged the same way as a create:
		// the target the key already has decides.
		id, _ := mustVirtualKey(t, h, "group key", "group", gid)["id"].(string)
		rr = patch(id, map[string]any{"tool_allowlist": []string{"delete_repo"}})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("list-only patch on a group key: %d %s", rr.Code, rr.Body.String())
		}
		wantsBody(t, rr, "tool_allowlist[0]", "must name a member")
		if rr := patch(id, map[string]any{"tool_allowlist": []string{ghSlug + "__delete_repo"}}); rr.Code != http.StatusOK {
			t.Fatalf("scoped patch on a group key: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("an unscoped deny entry is legal on either target", func(t *testing.T) {
		// One unscoped entry covering every member is what an operator writing
		// "never delete_repo" means, and it is honoured on the group's
		// aggregate endpoint and on each member endpoint alike. Only the allow
		// side needs a member.
		for _, tc := range []struct{ name, targetType, targetID string }{
			{"on a group", "group", gid},
			{"on an upstream", "upstream", ghID},
		} {
			rr := create("deny "+tc.name, tc.targetType, tc.targetID, map[string]any{"tool_denylist": []string{"delete_repo"}})
			if rr.Code != http.StatusCreated {
				t.Fatalf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("a rejected patch leaves the stored lists untouched", func(t *testing.T) {
		id, _ := mustVirtualKey(t, h, "settled", "group", gid)["id"].(string)
		wantAllow := []string{ghSlug + "__read_issue"}
		wantDeny := []string{"delete_repo"}
		if rr := patch(id, map[string]any{"tool_allowlist": wantAllow, "tool_denylist": wantDeny}); rr.Code != http.StatusOK {
			t.Fatalf("seed patch: %d %s", rr.Code, rr.Body.String())
		}
		// The allowlist in this request is good and the denylist is not.
		// Nothing is written until UpdateVirtualKey, so neither half lands.
		rr := patch(id, map[string]any{
			"tool_allowlist": []string{docsSlug + "__search"},
			"tool_denylist":  []string{"delete_repo "},
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
		}
		allow, deny := storedLists(t, h, id)
		if !slices.Equal(allow, wantAllow) || !slices.Equal(deny, wantDeny) {
			t.Fatalf("after a rejected patch allow=%v deny=%v, want %v and %v", allow, deny, wantAllow, wantDeny)
		}
	})

	t.Run("a rename does not re-judge a list it did not send", func(t *testing.T) {
		// A group key whose allowlist is bare. The API refuses to write one
		// now, so it is seeded the only way it can exist in the wild: straight
		// through the store, as a key written before the rule existed. Renaming
		// it must still work, a validation rule that locks an operator out of
		// their own key is worse than the entry it objects to.
		const id = "legacy-bare-allowlist"
		if err := st.CreateVirtualKey(context.Background(), &models.VirtualKey{
			ID:            id,
			Name:          "legacy",
			KeyHash:       "not-a-real-hash",
			KeyLookup:     "legacy-lookup",
			KeyPrefix:     "pory_lega",
			TargetType:    models.TargetGroup,
			TargetID:      gid,
			ToolAllowlist: []string{"delete_repo"},
			CreatedAt:     time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		if rr := patch(id, map[string]any{"name": "renamed"}); rr.Code != http.StatusOK {
			t.Fatalf("rename: %d %s", rr.Code, rr.Body.String())
		}
		if allow, _ := storedLists(t, h, id); !slices.Equal(allow, []string{"delete_repo"}) {
			t.Fatalf("allowlist after a rename = %v", allow)
		}
	})

	t.Run("a move onto a group refuses an unscoped allowlist", func(t *testing.T) {
		// Legal where it was written (one upstream, one thing the bare name
		// can mean) and after the move it would admit nothing at all, with
		// nothing in the request that said so.
		rr := create("moving up", "upstream", ghID, map[string]any{"tool_allowlist": []string{"read_issue"}})
		if rr.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
		}
		id := idOf(t, rr)
		rr = patch(id, map[string]any{"target_type": "group", "target_id": gid})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("move: %d %s", rr.Code, rr.Body.String())
		}
		wantsBody(t, rr, "tool_allowlist", "read_issue", "must name a member")
		// Refused before UpdateVirtualKey, so the key did not move either.
		body, _ := getVirtualKeyBody(t, h, id)
		if body["target_type"] != models.TargetUpstream || body["target_id"] != ghID {
			t.Fatalf("key moved anyway: %v", body)
		}
		// The same move carrying a rewritten allowlist is judged on the list
		// the key will hold, not on the one it holds now.
		rr = patch(id, map[string]any{
			"target_type": "group", "target_id": gid,
			"tool_allowlist": []string{ghSlug + "__read_issue"},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("move with a rewritten allowlist: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("a move onto an upstream refuses a foreign-headed allowlist", func(t *testing.T) {
		// Perfectly good on the group, where docs is a member. On github it can
		// never match, because a single-upstream key only ever sees github's
		// own tools, and membership is not something the models validators can
		// check, since they read no store.
		rr := create("moving down", "group", gid, map[string]any{"tool_allowlist": []string{docsSlug + "__search"}})
		if rr.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
		}
		id := idOf(t, rr)
		rr = patch(id, map[string]any{"target_type": "upstream", "target_id": ghID})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("move to github: %d %s", rr.Code, rr.Body.String())
		}
		wantsBody(t, rr, "tool_allowlist", docsSlug+"__search", ghSlug)
		body, _ := getVirtualKeyBody(t, h, id)
		if body["target_type"] != models.TargetGroup {
			t.Fatalf("key moved anyway: %v", body)
		}
		// The same move onto the upstream the entry actually names goes
		// through, and the list survives it untouched.
		if rr := patch(id, map[string]any{"target_type": "upstream", "target_id": docsID}); rr.Code != http.StatusOK {
			t.Fatalf("move to docs: %d %s", rr.Code, rr.Body.String())
		}
		if allow, _ := storedLists(t, h, id); !slices.Equal(allow, []string{docsSlug + "__search"}) {
			t.Fatalf("allowlist after the move = %v", allow)
		}
	})
}

// TestVirtualKeyWithUndecodableLists is the management half of the store's
// refusal to overwrite an unreadable entry list.
//
// A key whose tool_allowlist or tool_denylist did not decode is blocked on
// every call, and the operator meets that fact as a WARN at startup telling
// them to fix the key. The two obvious moves (rotate it, revoke it) read the
// key and write it straight back, so before the store started preserving the
// columns they replaced the unreadable rule with "null": no allowlist, no
// denylist, no warning any more, and a key the proxy blocked on every call now
// admitting everything. Following the advice destroyed the rule.
//
// So both must succeed and leave the key blocked, a patch of one list must be
// refused rather than silently dropped, and a patch of both must be the way
// out.
func TestVirtualKeyWithUndecodableLists(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, ghSlug := mustUpstream(t, h, "GitHub", nil)
	id, _ := mustVirtualKey(t, h, "blocked", "upstream", ghID)["id"].(string)

	const corrupt = `["unterminated`
	// Written through a second connection to the same file: the flag under test
	// is set by the scan that fails to decode the column, so the corruption has
	// to be real. Nothing exported could store this.
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE virtual_keys SET tool_denylist = ? WHERE id = ?`, corrupt, id); err != nil {
		t.Fatal(err)
	}
	denylistColumn := func(t *testing.T) string {
		t.Helper()
		var v string
		if err := db.QueryRow(`SELECT tool_denylist FROM virtual_keys WHERE id = ?`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	blocked := func(t *testing.T) bool {
		t.Helper()
		k, err := st.GetVirtualKey(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		return k.ListsMalformed
	}
	if !blocked(t) {
		t.Fatalf("the seeded key is not blocked; the rest of this test proves nothing")
	}

	for _, tc := range []struct{ name, method, path string }{
		{"rotate", http.MethodPost, "/virtual-keys/" + id + "/rotate"},
		{"revoke", http.MethodPost, "/virtual-keys/" + id + "/revoke"},
	} {
		t.Run(tc.name+" leaves the key blocked", func(t *testing.T) {
			rr := doJSON(t, h, tc.method, tc.path, "test-admin", nil)
			if rr.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
			}
			if v := denylistColumn(t); v != corrupt {
				t.Errorf("after %s the stored denylist is %q, want %q untouched", tc.name, v, corrupt)
			}
			if !blocked(t) {
				t.Errorf("after %s the key is no longer blocked; %s widened a rule it was never asked about", tc.name, tc.name)
			}
		})
	}

	t.Run("a rename leaves the key blocked", func(t *testing.T) {
		rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", map[string]any{"name": "still blocked"})
		if rr.Code != http.StatusOK {
			t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
		}
		if v := denylistColumn(t); v != corrupt {
			t.Errorf("after a rename the stored denylist is %q, want %q untouched", v, corrupt)
		}
		if !blocked(t) {
			t.Error("after a rename the key is no longer blocked")
		}
	})

	t.Run("one list alone is refused", func(t *testing.T) {
		// The store will not touch either column while the flag is set, so this
		// request could only ever be a no-op answered 200 with the new list
		// echoed back. The operator is told which fields to send instead.
		for _, field := range []string{"tool_allowlist", "tool_denylist"} {
			rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin",
				map[string]any{field: []string{"delete_repo"}})
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("patch %s alone: %d %s", field, rr.Code, rr.Body.String())
			}
			wantsBody(t, rr, "tool_allowlist", "tool_denylist", "could not be decoded")
		}
		if v := denylistColumn(t); v != corrupt {
			t.Errorf("a refused patch changed the stored denylist to %q", v)
		}
		if !blocked(t) {
			t.Error("a refused patch unblocked the key")
		}
	})

	t.Run("both lists together are the way out", func(t *testing.T) {
		rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", map[string]any{
			"tool_allowlist": []string{ghSlug + "__read_issue"},
			"tool_denylist":  []string{"delete_repo"},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("patch both: %d %s", rr.Code, rr.Body.String())
		}
		if want, v := `["delete_repo"]`, denylistColumn(t); v != want {
			t.Errorf("stored denylist is %q, want %q", v, want)
		}
		if blocked(t) {
			t.Fatal("the key is still blocked after both lists were replaced")
		}
		allow, deny := storedLists(t, h, id)
		if !slices.Equal(allow, []string{ghSlug + "__read_issue"}) || !slices.Equal(deny, []string{"delete_repo"}) {
			t.Fatalf("allow=%v deny=%v, want the replacements", allow, deny)
		}
		// And an ordinary single-list patch works again, because there is
		// nothing unreadable left for it to write over.
		if rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin",
			map[string]any{"tool_denylist": []string{"delete_branch"}}); rr.Code != http.StatusOK {
			t.Fatalf("patch one list on a fixed key: %d %s", rr.Code, rr.Body.String())
		}
	})
}

// ---- PORM-21: presence-aware PATCH -------------------------------------------
//
// Every write field is an Optional (optional.go): absent keeps, a value sets,
// null clears where a cleared state exists and is refused where none does. The
// tests below pin that contract; docs/03-api.md "Partial updates" states it.

// getJSON GETs a management object and returns the decoded body.
func getJSON(t *testing.T, h http.Handler, path string) map[string]any {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, path, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPatchUpstreamKeepsDescription is PORM-21 AC 1, the headline bug: a PATCH
// that carried name or url and omitted description used to store "".
func TestPatchUpstreamKeepsDescription(t *testing.T) {
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"description": "keep me"})
	for _, body := range []map[string]any{
		{"name": "Renamed"},
		{"name": "Renamed again", "url": "https://example.com/mcp"}, // an edit form's shape
	} {
		got := patchUpstreamJSON(t, h, id, body)
		if got["description"] != "keep me" {
			t.Fatalf("PATCH %v: description = %v, want it untouched", body, got["description"])
		}
	}
	if got := getJSON(t, h, "/upstreams/"+id); got["name"] != "Renamed again" || got["description"] != "keep me" {
		t.Fatalf("stored: name=%v description=%v", got["name"], got["description"])
	}
}

// TestPatchUpstreamClearsDescription is PORM-21 AC 2: "" and null both clear,
// and a cleared field is absent from the response (omitempty), not "".
func TestPatchUpstreamClearsDescription(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"empty string", map[string]any{"description": ""}},
		{"null", map[string]any{"description": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, h, st := testAPI(t)
			id, _ := mustUpstream(t, h, "GitHub", map[string]any{"description": "gone soon"})
			got := patchUpstreamJSON(t, h, id, tc.body)
			if _, has := got["description"]; has {
				t.Fatalf("response still carries description=%v", got["description"])
			}
			if got["name"] != "GitHub" {
				t.Fatalf("name changed to %v", got["name"])
			}
			if _, has := getJSON(t, h, "/upstreams/"+id)["description"]; has {
				t.Fatal("GET still carries a description")
			}
			u, err := st.GetUpstream(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			if u.Description != "" {
				t.Fatalf("stored description %q, want ''", u.Description)
			}
		})
	}
}

// TestPatchUpstreamNullAuthConfigKeepsCredential is PORM-21 security
// requirement 2: on PATCH a null auth_config means "unchanged" (the credential
// stays and the test result stays) while on create it means "no credential".
func TestPatchUpstreamNullAuthConfigKeepsCredential(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{
		"url": stub.srv.URL, "auth_type": "bearer", "auth_config": map[string]string{"token": "sk-1"},
	})
	at := recordTestOn(t, h, id)

	got := patchUpstreamJSON(t, h, id, map[string]any{"name": "Renamed", "auth_config": nil})
	if got["auth_configured"] != true {
		t.Fatalf("auth_configured = %v after a null auth_config", got["auth_configured"])
	}
	if got["last_test_at"] != at || got["last_test_ok"] != true {
		t.Fatalf("null auth_config reset the test result: at=%v ok=%v", got["last_test_at"], got["last_test_ok"])
	}
	if gotAt, gotOK, _ := upstreamTest(t, h, id); gotAt != at || gotOK != true {
		t.Fatalf("the row reset the result: at=%v ok=%v", gotAt, gotOK)
	}
	if _, has := got["auth_config"]; has {
		t.Fatal("the response echoed auth_config")
	}

	// Create: null is no credential, and says so, not ciphertext of the four
	// bytes "null" reported as configured.
	rr, created := newUpstream(t, h, upstreamBody("Bare", map[string]any{"auth_config": nil}))
	if created == nil {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if created["auth_configured"] != false {
		t.Fatalf("create with a null auth_config reports auth_configured=%v", created["auth_configured"])
	}
}

// TestPatchUpstreamCaseVariantKey is PORM-21 security requirement 5: presence
// follows encoding/json's own field matching, which is case-insensitive, so a
// key spelled "Description" clears exactly as "description" does, there is no
// second, case-sensitive notion of presence to disagree with.
func TestPatchUpstreamCaseVariantKey(t *testing.T) {
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"description": "gone soon"})
	got := patchUpstreamJSON(t, h, id, map[string]any{"Description": nil})
	if _, has := got["description"]; has {
		t.Fatalf("a case-variant key did not clear: description=%v", got["description"])
	}
}

// patchGroupJSON PATCHes a group and returns the decoded 200 body.
func patchGroupJSON(t *testing.T, h http.Handler, id string, body map[string]any) map[string]any {
	t.Helper()
	rr := doJSON(t, h, http.MethodPatch, "/groups/"+id, "test-admin", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH group %v: %d %s", body, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// columnText reads one column of one row through a second connection to the
// store file testAPIStoreFile returns, so an assertion sees the bytes on disk
// rather than what the scan made of them: ” and the text "null" both read
// back as "no filter", and only the column can tell them apart. Same pattern
// as TestVirtualKeyWithUndecodableLists.
func columnText(t *testing.T, path, query, id string) sql.NullString {
	t.Helper()
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v sql.NullString
	if err := db.QueryRow(query, id).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

// TestPatchGroupClearsDescription is PORM-21 AC 3: a group description could be
// set but never cleared; "" and null both clear it now, and the cleared field
// is absent from the response.
func TestPatchGroupClearsDescription(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"empty string", map[string]any{"description": ""}},
		{"null", map[string]any{"description": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, h, st := testAPI(t)
			rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", map[string]any{"name": "Tools", "description": "gone soon"})
			if rr.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
			}
			var created map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			id := created["id"].(string)
			if created["description"] != "gone soon" {
				t.Fatalf("create dropped the description: %v", created)
			}
			got := patchGroupJSON(t, h, id, tc.body)
			if _, has := got["description"]; has {
				t.Fatalf("response still carries description=%v", got["description"])
			}
			if got["name"] != "Tools" {
				t.Fatalf("name changed to %v", got["name"])
			}
			if _, has := getJSON(t, h, "/groups/"+id)["description"]; has {
				t.Fatal("GET still carries a description")
			}
			g, err := st.GetGroup(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			if g.Description != "" {
				t.Fatalf("stored description %q, want ''", g.Description)
			}
		})
	}
}

// TestPatchGroupClearsToolFilter: null clears the filter (the column is ” and
// the key is absent, not the text "null" echoed as "tool_filter": null) while
// {} is a valid filter that filters nothing and is stored as sent, and a
// rejected filter leaves the stored one intact (PORM-21 behaviour change 2).
func TestPatchGroupClearsToolFilter(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, ghSlug := mustUpstream(t, h, "GitHub", nil)
	id := mustGroup(t, h, "Tools", []string{ghID})
	const column = `SELECT tool_filter FROM groups WHERE id = ?`

	good := `{"mode":"deny","tools":["` + ghSlug + `__delete_repo"]}`
	patchGroupJSON(t, h, id, map[string]any{"tool_filter": json.RawMessage(good)})
	if col := columnText(t, path, column, id); col.String != good {
		t.Fatalf("column after set: %q, want %s", col.String, good)
	}

	got := patchGroupJSON(t, h, id, map[string]any{"tool_filter": nil})
	if _, has := got["tool_filter"]; has {
		t.Fatalf("response still carries tool_filter=%v after null", got["tool_filter"])
	}
	if col := columnText(t, path, column, id); col.String != "" {
		t.Fatalf("column after null: %q, want ''", col.String)
	}
	if g, err := st.GetGroup(t.Context(), id); err != nil || g.ToolFilter != nil {
		t.Fatalf("stored filter after null: %s (err %v), want nil", g.ToolFilter, err)
	}

	got = patchGroupJSON(t, h, id, map[string]any{"tool_filter": map[string]any{}})
	if tf, ok := got["tool_filter"].(map[string]any); !ok || len(tf) != 0 {
		t.Fatalf("response after {}: tool_filter=%v, want {}", got["tool_filter"])
	}
	if col := columnText(t, path, column, id); col.String != "{}" {
		t.Fatalf("column after {}: %q, want {}", col.String)
	}

	rr := doJSON(t, h, http.MethodPatch, "/groups/"+id, "test-admin", map[string]any{
		"tool_filter": json.RawMessage(`{"mode":"allow","tools":[]}`),
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an allow filter naming nothing: %d %s", rr.Code, rr.Body.String())
	}
	if col := columnText(t, path, column, id); col.String != "{}" {
		t.Fatalf("a rejected filter changed the column to %q", col.String)
	}
}

// TestPatchGroupClearsUpstreamIDs: null empties the member list exactly as []
// does (the response and the column both say [], never null) and a key
// targeting the group then reaches no endpoints (PORM-21 security requirement
// 7).
func TestPatchGroupClearsUpstreamIDs(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	id := mustGroup(t, h, "Tools", []string{ghID})
	keyID := mustVirtualKey(t, h, "k", "group", id)["id"].(string)
	if eps, _ := getJSON(t, h, "/virtual-keys/"+keyID)["endpoints"].([]any); len(eps) != 1 {
		t.Fatalf("endpoints before: %v, want one", eps)
	}

	got := patchGroupJSON(t, h, id, map[string]any{"upstream_ids": nil})
	if ids, ok := got["upstream_ids"].([]any); !ok || len(ids) != 0 {
		t.Fatalf("response upstream_ids=%v (%T), want []", got["upstream_ids"], got["upstream_ids"])
	}
	if col := columnText(t, path, `SELECT upstream_ids FROM groups WHERE id = ?`, id); col.String != "[]" {
		t.Fatalf("column %q, want []", col.String)
	}
	if eps, _ := getJSON(t, h, "/virtual-keys/"+keyID)["endpoints"].([]any); len(eps) != 0 {
		t.Fatalf("endpoints after: %v, want none", eps)
	}
}

// patchVirtualKeyJSON PATCHes a virtual key and returns the decoded 200 body.
func patchVirtualKeyJSON(t *testing.T, h http.Handler, id string, body map[string]any) map[string]any {
	t.Helper()
	rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH virtual key %v: %d %s", body, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// newVirtualKey posts a virtual key with extra fields and returns the decoded
// 201 body. mustVirtualKey takes none; the PORM-21 tests need rate_limit,
// expires_at, lists and metadata set at create.
func newVirtualKey(t *testing.T, h http.Handler, targetType, targetID string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"name": "k", "target_type": targetType, "target_id": targetID}
	for k, v := range extra {
		body[k] = v
	}
	rr := doJSON(t, h, http.MethodPost, "/virtual-keys", "test-admin", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create virtual key %v: %d %s", extra, rr.Code, rr.Body.String())
	}
	var vk map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &vk); err != nil {
		t.Fatal(err)
	}
	return vk
}

// TestPatchVirtualKeyClearsRateLimit is PORM-21 AC 4: null removes the limit
// (the key is absent from the response, the model holds nil, the column is
// NULL) and a value still sets it.
func TestPatchVirtualKeyClearsRateLimit(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	vk := newVirtualKey(t, h, "upstream", ghID, map[string]any{"rate_limit": 60})
	id := vk["id"].(string)
	if vk["rate_limit"] != float64(60) {
		t.Fatalf("create: rate_limit=%v", vk["rate_limit"])
	}

	got := patchVirtualKeyJSON(t, h, id, map[string]any{"rate_limit": nil})
	if _, has := got["rate_limit"]; has {
		t.Fatalf("response still carries rate_limit=%v", got["rate_limit"])
	}
	if _, has := getJSON(t, h, "/virtual-keys/"+id)["rate_limit"]; has {
		t.Fatal("GET still carries rate_limit")
	}
	if k, err := st.GetVirtualKey(t.Context(), id); err != nil || k.RateLimit != nil {
		t.Fatalf("stored RateLimit=%v (err %v), want nil", k.RateLimit, err)
	}
	if col := columnText(t, path, `SELECT rate_limit FROM virtual_keys WHERE id = ?`, id); col.Valid {
		t.Fatalf("column rate_limit=%q, want NULL", col.String)
	}

	if got := patchVirtualKeyJSON(t, h, id, map[string]any{"rate_limit": 30}); got["rate_limit"] != float64(30) {
		t.Fatalf("a value no longer sets rate_limit: %v", got["rate_limit"])
	}
}

// TestPatchVirtualKeyClearsExpiresAt is PORM-21 AC 4 and security requirement
// 7: null removes the expiry, and a key that had expired is active again.
func TestPatchVirtualKeyClearsExpiresAt(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	vk := newVirtualKey(t, h, "upstream", ghID, map[string]any{"expires_at": "2020-01-01T00:00:00Z"})
	id := vk["id"].(string)
	if vk["status"] != "expired" {
		t.Fatalf("create: status=%v, want expired", vk["status"])
	}

	got := patchVirtualKeyJSON(t, h, id, map[string]any{"expires_at": nil})
	if _, has := got["expires_at"]; has {
		t.Fatalf("response still carries expires_at=%v", got["expires_at"])
	}
	if got["status"] != "active" {
		t.Fatalf("status=%v after clearing the expiry, want active", got["status"])
	}
	if k, err := st.GetVirtualKey(t.Context(), id); err != nil || k.ExpiresAt != nil {
		t.Fatalf("stored ExpiresAt=%v (err %v), want nil", k.ExpiresAt, err)
	}
	if col := columnText(t, path, `SELECT expires_at FROM virtual_keys WHERE id = ?`, id); col.Valid {
		t.Fatalf("column expires_at=%q, want NULL", col.String)
	}
}

// TestPatchVirtualKeyClearsLists is PORM-21 security requirement 3. On a
// healthy key null clears a list exactly as [] does. On a key whose stored
// lists cannot be decoded, one side alone (null included) is refused, {}
// leaves both columns and the block alone, and both sides together (as null)
// replace both columns and lift the block.
func TestPatchVirtualKeyClearsLists(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	vk := newVirtualKey(t, h, "upstream", ghID, map[string]any{"tool_allowlist": []string{"search"}})
	id := vk["id"].(string)
	const allowColumn = `SELECT tool_allowlist FROM virtual_keys WHERE id = ?`
	const denyColumn = `SELECT tool_denylist FROM virtual_keys WHERE id = ?`

	got := patchVirtualKeyJSON(t, h, id, map[string]any{"tool_allowlist": nil})
	if _, has := got["tool_allowlist"]; has {
		t.Fatalf("response still carries tool_allowlist=%v", got["tool_allowlist"])
	}
	if col := columnText(t, path, allowColumn, id); col.String != "[]" {
		t.Fatalf("column after null: %q, want []", col.String)
	}

	// Corrupt the denylist through a second connection, as
	// TestVirtualKeyWithUndecodableLists does: the flag is set by the scan.
	const corrupt = `["unterminated`
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE virtual_keys SET tool_denylist = ? WHERE id = ?`, corrupt, id); err != nil {
		t.Fatal(err)
	}
	blocked := func(t *testing.T) bool {
		t.Helper()
		k, err := st.GetVirtualKey(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		return k.ListsMalformed
	}
	if !blocked(t) {
		t.Fatal("the seeded key is not blocked; the rest of this test proves nothing")
	}

	rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", map[string]any{"tool_denylist": nil})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("one null list on a blocked key: %d %s", rr.Code, rr.Body.String())
	}
	wantsBody(t, rr, "send both fields")
	if col := columnText(t, path, denyColumn, id); col.String != corrupt {
		t.Fatalf("a refused patch changed the denylist column to %q", col.String)
	}

	patchVirtualKeyJSON(t, h, id, map[string]any{})
	if col := columnText(t, path, denyColumn, id); col.String != corrupt || !blocked(t) {
		t.Fatalf("{} touched a blocked key: column %q blocked=%v", col.String, blocked(t))
	}

	patchVirtualKeyJSON(t, h, id, map[string]any{"tool_allowlist": nil, "tool_denylist": nil})
	if a, d := columnText(t, path, allowColumn, id), columnText(t, path, denyColumn, id); a.String != "[]" || d.String != "[]" {
		t.Fatalf("both-null left columns %q / %q, want [] / []", a.String, d.String)
	}
	if blocked(t) {
		t.Fatal("both-null replaced both columns but the key is still blocked")
	}
}

// TestPatchVirtualKeyClearsMetadata: null clears metadata (column ” and key
// absent), and {} is stored as sent, PoryMCP does not interpret metadata.
func TestPatchVirtualKeyClearsMetadata(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	vk := newVirtualKey(t, h, "upstream", ghID, map[string]any{"metadata": map[string]any{"team": "a"}})
	id := vk["id"].(string)
	const column = `SELECT metadata FROM virtual_keys WHERE id = ?`

	got := patchVirtualKeyJSON(t, h, id, map[string]any{"metadata": nil})
	if _, has := got["metadata"]; has {
		t.Fatalf("response still carries metadata=%v", got["metadata"])
	}
	if col := columnText(t, path, column, id); col.String != "" {
		t.Fatalf("column after null: %q, want ''", col.String)
	}

	got = patchVirtualKeyJSON(t, h, id, map[string]any{"metadata": map[string]any{}})
	if m, ok := got["metadata"].(map[string]any); !ok || len(m) != 0 {
		t.Fatalf("response after {}: metadata=%v, want {}", got["metadata"])
	}
	if col := columnText(t, path, column, id); col.String != "{}" {
		t.Fatalf("column after {}: %q, want {}", col.String)
	}
}

// TestPatchVirtualKeyIgnoresServerFields is PORM-21 security requirement 4:
// revoked_at, last_used_at, key_prefix and created_at are on no write struct,
// so a body carrying them (null included) changes nothing.
func TestPatchVirtualKeyIgnoresServerFields(t *testing.T) {
	_, h, _ := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	vk := newVirtualKey(t, h, "upstream", ghID, nil)
	id := vk["id"].(string)
	if rr := doJSON(t, h, http.MethodPost, "/virtual-keys/"+id+"/revoke", "test-admin", nil); rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	got := patchVirtualKeyJSON(t, h, id, map[string]any{
		"revoked_at": nil, "last_used_at": nil, "key_prefix": "x", "created_at": "1999-01-01T00:00:00Z",
	})
	if got["status"] != "revoked" {
		t.Fatalf("status=%v after a body carrying revoked_at null, want revoked", got["status"])
	}
	if got["key_prefix"] != vk["key_prefix"] || got["created_at"] != vk["created_at"] {
		t.Fatalf("server fields moved: prefix %v to %v created_at %v to %v", vk["key_prefix"], got["key_prefix"], vk["created_at"], got["created_at"])
	}
}

// TestPatchRejectsBlankRequiredFields is PORM-21 security requirement 1 and
// behaviour change 4: a required field sent with a value it cannot hold is a
// 400 with the field's usual message, and the row is untouched. One invalid
// field per row, so each row pins one message rather than which check ran
// first.
func TestPatchRejectsBlankRequiredFields(t *testing.T) {
	for _, tc := range []struct {
		name, resource string
		body           map[string]any
		want           string
	}{
		{"upstream name empty", "upstream", map[string]any{"name": ""}, errNameEmpty},
		{"upstream name blank", "upstream", map[string]any{"name": "   "}, errNameEmpty},
		{"upstream name null", "upstream", map[string]any{"name": nil}, errNameEmpty},
		{"upstream url empty", "upstream", map[string]any{"url": ""}, errURLRule},
		{"upstream url null", "upstream", map[string]any{"url": nil}, errURLRule},
		{"upstream transport null", "upstream", map[string]any{"transport": nil}, "invalid transport"},
		{"upstream auth_type empty", "upstream", map[string]any{"auth_type": ""}, "invalid auth_type"},
		{"upstream enabled null", "upstream", map[string]any{"enabled": nil}, errEnabledRule},
		{"upstream slug null", "upstream", map[string]any{"slug": nil}, errSlugImmutable},
		{"group name blank", "group", map[string]any{"name": "   "}, errNameEmpty},
		{"key name null", "key", map[string]any{"name": nil}, errNameEmpty},
		{"key target_type null", "key", map[string]any{"target_type": nil}, "target_type must be upstream or group"},
		{"key target_id empty", "key", map[string]any{"target_id": ""}, "unknown upstream target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, h, _ := testAPI(t)
			ghID, _ := mustUpstream(t, h, "GitHub", map[string]any{"description": "d"})
			var path string
			switch tc.resource {
			case "upstream":
				path = "/upstreams/" + ghID
			case "group":
				path = "/groups/" + mustGroup(t, h, "Tools", []string{ghID})
			case "key":
				path = "/virtual-keys/" + mustVirtualKey(t, h, "k", "upstream", ghID)["id"].(string)
			}
			before := getJSON(t, h, path)
			rr := doJSON(t, h, http.MethodPatch, path, "test-admin", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
			}
			if got, want := strings.TrimSpace(rr.Body.String()), `{"error":"`+tc.want+`"}`; got != want {
				t.Fatalf("body %s, want %s", got, want)
			}
			if after := getJSON(t, h, path); !reflect.DeepEqual(before, after) {
				t.Fatalf("a refused PATCH changed the row:\n before %v\n after  %v", before, after)
			}
		})
	}
}

// TestPatchEmptyObjectIsANoOp: {} changes no field on any of the three
// resources, and on the two that carry updated_at it still moves it, the
// compare-and-set in RecordUpstreamTest keys on that. Timestamps are parsed,
// not compared as strings: RFC3339Nano strips trailing zeros.
func TestPatchEmptyObjectIsANoOp(t *testing.T) {
	_, h, _ := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", map[string]any{"description": "d"})
	groupID := mustGroup(t, h, "Tools", []string{ghID})
	keyID := newVirtualKey(t, h, "group", groupID, map[string]any{"rate_limit": 60, "metadata": map[string]any{"team": "a"}})["id"].(string)
	for _, tc := range []struct {
		name, path string
		bumps      bool
	}{
		{"upstream", "/upstreams/" + ghID, true},
		{"group", "/groups/" + groupID, true},
		{"virtual key", "/virtual-keys/" + keyID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := getJSON(t, h, tc.path)
			if rr := doJSON(t, h, http.MethodPatch, tc.path, "test-admin", map[string]any{}); rr.Code != http.StatusOK {
				t.Fatalf("PATCH {}: %d %s", rr.Code, rr.Body.String())
			}
			after := getJSON(t, h, tc.path)
			if tc.bumps {
				was, err := time.Parse(time.RFC3339Nano, before["updated_at"].(string))
				if err != nil {
					t.Fatal(err)
				}
				now, err := time.Parse(time.RFC3339Nano, after["updated_at"].(string))
				if err != nil {
					t.Fatal(err)
				}
				if !now.After(was) {
					t.Fatalf("updated_at did not move: %v then %v", was, now)
				}
				delete(before, "updated_at")
				delete(after, "updated_at")
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("{} changed the row:\n before %v\n after  %v", before, after)
			}
		})
	}
}

// TestCreateNullMeansDefault is PORM-21 security requirement 6 and behaviour
// changes 5-6: on create the same keys PATCH refuses take their defaults
// (enabled null is enabled, transport "" and auth_type null are the defaults,
// a key made without rate_limit or expires_at is born active with neither) and
// a null tool_filter stores ” rather than the text "null".
func TestCreateNullMeansDefault(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	rr, up := newUpstream(t, h, upstreamBody("GitHub", map[string]any{"enabled": nil, "transport": "", "auth_type": nil}))
	if up == nil {
		t.Fatalf("create upstream: %d %s", rr.Code, rr.Body.String())
	}
	if up["enabled"] != true || up["transport"] != models.TransportStreamableHTTP || up["auth_type"] != models.AuthNone {
		t.Fatalf("defaults: enabled=%v transport=%v auth_type=%v", up["enabled"], up["transport"], up["auth_type"])
	}
	ghID := up["id"].(string)

	vk := newVirtualKey(t, h, "upstream", ghID, nil)
	_, hasLimit := vk["rate_limit"]
	_, hasExpiry := vk["expires_at"]
	if hasLimit || hasExpiry || vk["status"] != "active" {
		t.Fatalf("a key made without limit or expiry: rate_limit present=%v expires_at present=%v status=%v", hasLimit, hasExpiry, vk["status"])
	}
	if got := getJSON(t, h, "/virtual-keys/"+vk["id"].(string)); got["status"] != "active" {
		t.Fatalf("stored status=%v, want active", got["status"])
	}

	rr = doJSON(t, h, http.MethodPost, "/groups", "test-admin", map[string]any{"name": "Tools", "upstream_ids": []string{ghID}, "tool_filter": nil})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", rr.Code, rr.Body.String())
	}
	var g map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if col := columnText(t, path, `SELECT tool_filter FROM groups WHERE id = ?`, g["id"].(string)); col.String != "" {
		t.Fatalf("a null tool_filter on create stored %q, want ''", col.String)
	}
}

// TestPatchVirtualKeyClearLogsFields is PORM-21 security requirement 8: a
// PATCH that clears a policy-bearing field leaves one structured log line
// naming the resource, its id and the fields (never a value, never the key)
// and a PATCH that clears nothing logs nothing. Same log-capture idiom as
// TestDiscoverLogsNothing.
func TestPatchVirtualKeyClearLogsFields(t *testing.T) {
	s, h, _ := testAPI(t)
	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	vk := newVirtualKey(t, h, "upstream", ghID, map[string]any{"rate_limit": 60, "expires_at": "2030-01-01T00:00:00Z"})
	id := vk["id"].(string)
	plaintext, _ := vk["api_key"].(string)

	oneLine := func(t *testing.T) map[string]any {
		t.Helper()
		lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
		if len(lines) != 1 || lines[0] == "" {
			t.Fatalf("want exactly one log line, got:\n%s", logs.String())
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
			t.Fatalf("log line is not JSON: %v: %s", err, lines[0])
		}
		return line
	}

	logs.Reset()
	patchVirtualKeyJSON(t, h, id, map[string]any{"rate_limit": nil, "expires_at": nil})
	line := oneLine(t)
	if line["msg"] != "virtual key policy fields cleared" || line["virtual_key_id"] != id {
		t.Fatalf("line: %v", line)
	}
	if fields, _ := line["fields"].([]any); len(fields) != 2 || fields[0] != "rate_limit" || fields[1] != "expires_at" {
		t.Fatalf("fields=%v, want [rate_limit expires_at]", line["fields"])
	}
	if plaintext != "" && strings.Contains(logs.String(), plaintext) {
		t.Fatal("the log line carries the plaintext key")
	}

	// 0 means unlimited to the limiter, the same widening as null.
	logs.Reset()
	patchVirtualKeyJSON(t, h, id, map[string]any{"rate_limit": 0})
	if fields, _ := oneLine(t)["fields"].([]any); len(fields) != 1 || fields[0] != "rate_limit" {
		t.Fatalf("rate_limit 0: fields=%v, want [rate_limit]", fields)
	}

	logs.Reset()
	patchVirtualKeyJSON(t, h, id, map[string]any{"name": "Renamed", "rate_limit": 30})
	if logs.Len() != 0 {
		t.Fatalf("a PATCH that cleared nothing logged: %s", logs.String())
	}

	groupID := mustGroup(t, h, "Tools", []string{ghID})
	logs.Reset()
	patchGroupJSON(t, h, groupID, map[string]any{"upstream_ids": nil, "tool_filter": map[string]any{}})
	line = oneLine(t)
	if line["msg"] != "group policy fields cleared" || line["group_id"] != groupID {
		t.Fatalf("line: %v", line)
	}
	if fields, _ := line["fields"].([]any); len(fields) != 2 || fields[0] != "tool_filter" || fields[1] != "upstream_ids" {
		t.Fatalf("fields=%v, want [tool_filter upstream_ids]", line["fields"])
	}
}
