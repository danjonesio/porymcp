package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// overwriteAuth writes a raw auth_config through a second connection to the
// same file, nothing exported can store ciphertext the server's key will
// not open, or a legacy value.
func overwriteAuth(t *testing.T, path, id, value string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE upstreams SET auth_config = ? WHERE id = ?`, value, id); err != nil {
		t.Fatal(err)
	}
}

func rawAuth(t *testing.T, path, id string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT COALESCE(auth_config,'') FROM upstreams WHERE id = ?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func upstreamsByID(t *testing.T, h http.Handler) map[string]map[string]any {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/upstreams", "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Upstreams []map[string]any `json:"upstreams"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	m := map[string]map[string]any{}
	for _, u := range out.Upstreams {
		m[u["id"].(string)] = u
	}
	return m
}

func foreignSeal(t *testing.T, plain string) string {
	t.Helper()
	other, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewKeyring(other, nil).Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// TestListUpstreamsIncludesAuthStatus covers acceptance criterion 5 with the
// bodies the dashboard actually sends: a none upstream carries auth_config {},
// stores nothing and reads "none"; a bearer with a token is "ok"; a bearer
// with {} is "unreadable" (from the empty column since PORM-120); a row no
// configured key opens is "undecryptable", and its auth_hint is gone.
func TestListUpstreamsIncludesAuthStatus(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	none, _ := mustUpstream(t, h, "Docs", map[string]any{"auth_type": "none", "auth_config": map[string]string{}})
	ok, _ := mustUpstream(t, h, "GitHub", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	blank, _ := mustUpstream(t, h, "Draft", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{}})
	hinted, _ := mustUpstream(t, h, "Hinted", map[string]any{"auth_type": "header", "auth_config": map[string]string{"header": "X-Token", "value": "v"}})
	bad, _ := mustUpstream(t, h, "Linear", map[string]any{"auth_type": "header", "auth_config": map[string]string{"header": "X-Token", "value": "v"}})
	overwriteAuth(t, path, bad, foreignSeal(t, `{"header":"X-Token","value":"v"}`))

	got := upstreamsByID(t, h)
	for id, want := range map[string]string{none: "none", ok: "ok", blank: "unreadable", hinted: "ok", bad: "undecryptable"} {
		if s := got[id]["auth_status"]; s != want {
			t.Errorf("%s: auth_status = %v, want %q (row %v)", got[id]["name"], s, want, got[id])
		}
	}
	if got[none]["auth_configured"] != false {
		t.Errorf("a none row created by the dashboard sends {}, stores nothing and reads auth_configured false (PORM-120): %v", got[none])
	}
	if _, has := got[hinted]["auth_hint"]; !has {
		t.Errorf("ok header row lost its auth_hint: %v", got[hinted])
	}
	if _, has := got[bad]["auth_hint"]; has {
		t.Errorf("undecryptable row still carries an auth_hint: %v", got[bad])
	}
	for _, u := range got {
		if _, has := u["auth_config"]; has {
			t.Fatalf("auth_config leaked: %v", u)
		}
	}
}

// TestCreateUpstreamEmptyAuthConfigStoresNothing pins PORM-120 security
// requirement 4: an object with no members is no credential, so a create that
// sends auth_config {} (what the Add dialog sends for an untouched box) leaves
// the column empty for every auth type. A bearer row created that way still
// fails closed as unreadable, now from the empty column rather than a sealed {}.
func TestCreateUpstreamEmptyAuthConfigStoresNothing(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	none, _ := mustUpstream(t, h, "Docs", map[string]any{"auth_type": "none", "auth_config": map[string]string{}})
	bearer, _ := mustUpstream(t, h, "Draft", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{}})
	for name, id := range map[string]string{"none": none, "bearer": bearer} {
		if got := rawAuth(t, path, id); got != "" {
			t.Errorf("%s: auth_config column = %q, want empty", name, got)
		}
	}
	got := upstreamsByID(t, h)
	if got[none]["auth_status"] != "none" || got[none]["auth_configured"] != false {
		t.Errorf("none row created with {}: %v, want auth_status none and auth_configured false", got[none])
	}
	if got[bearer]["auth_status"] != "unreadable" || got[bearer]["auth_configured"] != false {
		t.Errorf("bearer row created with {}: %v, want auth_status unreadable and auth_configured false", got[bearer])
	}
}

// TestLegacyRowStillPresentsOK: a value written by a pre-PORM-52 build reads
// "ok" for ever.
func TestLegacyRowStillPresentsOK(t *testing.T) {
	s, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "Old", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	legacy, err := crypto.EncryptLegacy(s.cfg.EncryptionKey, []byte(`{"token":"sk-legacy"}`))
	if err != nil {
		t.Fatal(err)
	}
	overwriteAuth(t, path, id, legacy)
	if got := upstreamsByID(t, h)[id]["auth_status"]; got != "ok" {
		t.Fatalf("legacy row auth_status = %v, want ok", got)
	}
}

// TestStatsCountsCredentialStates: /stats carries the three counts from the
// same sweep the boot report uses; none rows are never counted.
func TestStatsCountsCredentialStates(t *testing.T) {
	s, h, backing, path := testAPIStoreFile(t, "http://localhost:8080")
	old, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	// A second server over the same store, built from a Config carrying the
	// previous key, so New -> cfg.Keyring() -> EncryptionKeyPrevious is what
	// this test exercises (the plan's recipe); h keeps seeding rows.
	cfg2 := *s.cfg
	cfg2.EncryptionKeyPrevious = [][]byte{old}
	h2 := New(&cfg2, backing, nil, mcpclient.New(), webutil.EncryptionOK).Routes()

	mustUpstream(t, h, "Docs", map[string]any{"auth_type": "none", "auth_config": map[string]string{}})
	mustUpstream(t, h, "GitHub", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	mustUpstream(t, h, "Draft", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{}})
	bad, _ := mustUpstream(t, h, "Linear", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	overwriteAuth(t, path, bad, foreignSeal(t, `{"token":"sk"}`))
	prev, _ := mustUpstream(t, h, "Notion", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	underOld, err := crypto.NewKeyring(old, nil).Seal([]byte(`{"token":"sk"}`))
	if err != nil {
		t.Fatal(err)
	}
	overwriteAuth(t, path, prev, underOld)

	rr := doJSON(t, h2, http.MethodGet, "/stats", "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", rr.Code, rr.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]float64{"upstreams": 5, "undecryptable_upstreams": 1, "unreadable_upstreams": 1, "upstreams_under_previous_key": 1} {
		if st[k] != want {
			t.Errorf("%s = %v, want %v (stats %v)", k, st[k], want, st)
		}
	}
}

// TestPatchWithoutAuthConfigDoesNotRewriteCiphertext pins security
// requirement 8: the ciphertext a PATCH read is not written back unless the
// request carried a credential.
func TestPatchWithoutAuthConfigDoesNotRewriteCiphertext(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	before := rawAuth(t, path, id)
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"name": "GitHub (prod)"}); rr.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
	if rawAuth(t, path, id) != before {
		t.Fatal("a PATCH without auth_config rewrote the ciphertext")
	}
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_config": map[string]string{"token": "sk-2"}}); rr.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
	if rawAuth(t, path, id) == before {
		t.Fatal("a PATCH with auth_config did not write the new ciphertext")
	}
}

// TestPatchUpstreamClearsCredential is PORM-120 acceptance criterion 1 and
// pins security requirements 1, 4 and 5: PATCH auth_type none on a bearer row
// with a recorded test answers auth_configured false and auth_status none with
// both test fields null, empties the column, and echoes no credential.
func TestPatchUpstreamClearsCredential(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL, "auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	recordTestOn(t, h, id)
	if rawAuth(t, path, id) == "" {
		t.Fatal("the bearer row holds no ciphertext before the clear")
	}

	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_type": "none"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	// The key form, because auth_configured contains the same letters.
	if strings.Contains(rr.Body.String(), `"auth_config":`) {
		t.Fatalf("the 200 carries an auth_config key: %s", rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["auth_configured"] != false || got["auth_status"] != "none" {
		t.Fatalf("response = %v, want auth_configured false and auth_status none", got)
	}
	if _, has := got["auth_hint"]; has {
		t.Fatalf("response still carries an auth_hint: %v", got)
	}
	if got["last_test_at"] != nil || got["last_test_ok"] != nil {
		t.Fatalf("the response still vouches for the old credential: at=%v ok=%v", got["last_test_at"], got["last_test_ok"])
	}
	if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
		t.Fatalf("the row still vouches for the old credential: at=%v ok=%v", at, ok)
	}
	if v := rawAuth(t, path, id); v != "" {
		t.Fatalf("auth_config column = %q after the clear, want empty", v)
	}
}

// TestPatchUpstreamClearsLegacyNoneRow: the rows PORM-120 exists for are
// already none and still hold a blob. Naming none again empties the column and
// resets the recorded test, because the request removed bytes.
func TestPatchUpstreamClearsLegacyNoneRow(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "Docs", map[string]any{"url": stub.srv.URL, "auth_type": "none"})
	recordTestOn(t, h, id)
	overwriteAuth(t, path, id, foreignSeal(t, `{"token":"old"}`))

	got := patchUpstreamJSON(t, h, id, map[string]any{"auth_type": "none"})
	if got["auth_configured"] != false || got["last_test_at"] != nil || got["last_test_ok"] != nil {
		t.Fatalf("response = %v, want auth_configured false and both test fields null", got)
	}
	if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
		t.Fatalf("the row still vouches for the old settings: at=%v ok=%v", at, ok)
	}
	if v := rawAuth(t, path, id); v != "" {
		t.Fatalf("auth_config column = %q after the clear, want empty", v)
	}
}

// TestPatchUpstreamClearsUndecryptableCredential pins PORM-120 security
// requirement 2: the clear decrypts nothing, so a row sealed under a key this
// server does not hold is cleared without it.
func TestPatchUpstreamClearsUndecryptableCredential(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "Linear", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	overwriteAuth(t, path, id, foreignSeal(t, `{"token":"sk"}`))
	if got := upstreamsByID(t, h)[id]["auth_status"]; got != "undecryptable" {
		t.Fatalf("auth_status before the clear = %v, want undecryptable", got)
	}

	got := patchUpstreamJSON(t, h, id, map[string]any{"auth_type": "none"})
	if got["auth_configured"] != false || got["auth_status"] != "none" {
		t.Fatalf("response = %v, want auth_configured false and auth_status none", got)
	}
	if v := rawAuth(t, path, id); v != "" {
		t.Fatalf("auth_config column = %q after the clear, want empty", v)
	}
}

// TestPatchUpstreamResentNoneOnEmptyRowIsNoOp: a round-trip that names none on
// a row with nothing stored removes nothing, so it keeps its recorded test
// (the same rule TestPatchUpstreamSameURLKeepsTestResult pins for url).
func TestPatchUpstreamResentNoneOnEmptyRowIsNoOp(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "Docs", map[string]any{"url": stub.srv.URL, "auth_type": "none"})
	at := recordTestOn(t, h, id)

	got := patchUpstreamJSON(t, h, id, map[string]any{"auth_type": "none"})
	if got["last_test_at"] != at || got["last_test_ok"] != true {
		t.Fatalf("a no-op none reset the test in the response: at=%v ok=%v", got["last_test_at"], got["last_test_ok"])
	}
	if rowAt, ok, _ := upstreamTest(t, h, id); rowAt != at || ok != true {
		t.Fatalf("a no-op none reset the test on the row: at=%v ok=%v", rowAt, ok)
	}
	if v := rawAuth(t, path, id); v != "" {
		t.Fatalf("auth_config column = %q, want empty", v)
	}
}

// TestPatchUpstreamEmptyAuthConfigClears: an object with no members stores
// nothing on PATCH as well as on create (PORM-120). The row keeps its type,
// so it reads unreadable and fails closed, as the sealed {} did before, but
// now with auth_configured false and no secret-shaped bytes at rest.
func TestPatchUpstreamEmptyAuthConfigClears(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL, "auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	recordTestOn(t, h, id)

	got := patchUpstreamJSON(t, h, id, map[string]any{"auth_config": map[string]string{}})
	if got["auth_configured"] != false || got["auth_status"] != "unreadable" {
		t.Fatalf("response = %v, want auth_configured false and auth_status unreadable", got)
	}
	if got["last_test_at"] != nil || got["last_test_ok"] != nil {
		t.Fatalf("the response still vouches for the old credential: at=%v ok=%v", got["last_test_at"], got["last_test_ok"])
	}
	if v := rawAuth(t, path, id); v != "" {
		t.Fatalf("auth_config column = %q after {}, want empty", v)
	}
}

type listCounter struct {
	store.Store
	n int32
}

func (c *listCounter) ListUpstreams(ctx context.Context) ([]models.Upstream, error) {
	atomic.AddInt32(&c.n, 1)
	return c.Store.ListUpstreams(ctx)
}

// TestHealthDoesNotListUpstreams pins security requirement 6: the
// unauthenticated /health issues no store read beyond Ping (the verdict is a
// boot fact) while the admin-authenticated /stats does the sweep.
func TestHealthDoesNotListUpstreams(t *testing.T) {
	var c *listCounter
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store {
		c = &listCounter{Store: st}
		return c
	})
	for i := 0; i < 5; i++ {
		if rr := doJSON(t, h, http.MethodGet, "/health", "", nil); rr.Code != http.StatusOK {
			t.Fatalf("health: %d %s", rr.Code, rr.Body.String())
		}
	}
	if n := atomic.LoadInt32(&c.n); n != 0 {
		t.Fatalf("/health listed upstreams %d times", n)
	}
	if rr := doJSON(t, h, http.MethodGet, "/stats", "test-admin", nil); rr.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", rr.Code, rr.Body.String())
	}
	if n := atomic.LoadInt32(&c.n); n != 1 {
		t.Fatalf("/stats listed upstreams %d times, want 1", n)
	}
}
