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
	h2 := New(&cfg2, backing, nil, mcpclient.New(cfg2.UpstreamGuard), webutil.EncryptionOK).Routes()

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

// queryBody is the create body for a query upstream (PORM-27).
func queryBody(param, value string) map[string]any {
	return map[string]any{"auth_type": "query", "auth_config": map[string]string{"param": param, "value": value}}
}

// TestCreateUpstreamQueryAuth covers PORM-27 security requirements 1 and 2:
// a query credential is sealed as the canonical {param, value} object, the
// list never returns the value or an auth_config key, auth_hint names the
// parameter under its own key, and the row reads ok.
func TestCreateUpstreamQueryAuth(t *testing.T) {
	s, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	const value = "QUERY_VALUE_MARKER_abcdefgh"
	rr, up := newUpstream(t, h, upstreamBody("Docs", queryBody("api_key", value)))
	if up == nil {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), value) {
		t.Fatalf("the create answer carries the value: %s", rr.Body.String())
	}
	id := up["id"].(string)
	got := upstreamsByID(t, h)
	row := got[id]
	if row["auth_status"] != "ok" || row["auth_configured"] != true || row["url"] != "https://example.com/mcp" {
		t.Fatalf("row = %v", row)
	}
	if _, has := row["auth_config"]; has {
		t.Fatalf("auth_config leaked: %v", row)
	}
	hint, _ := row["auth_hint"].(map[string]any)
	if hint["param"] != "api_key" || len(hint) != 1 {
		t.Fatalf("auth_hint = %v, want {param: api_key}", row["auth_hint"])
	}
	plain, _, err := s.keys.Open(rawAuth(t, path, id))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"value":"`+value+`","param":"api_key"}` && string(plain) != `{"param":"api_key","value":"`+value+`"}` {
		t.Fatalf("stored blob = %s, want the canonical two-member object", plain)
	}
}

// TestQueryAuthConfigRules covers PORM-27 security requirements 9 and 10 on
// the write path: the shape and bound sentences on create and PATCH, and the
// type-change refusal with its none and oauth exemptions.
func TestQueryAuthConfigRules(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	long := strings.Repeat("v", mcpclient.MaxQueryValueBytes+1)
	for name, tc := range map[string]struct {
		config any
		want   string
	}{
		"missing param":  {map[string]string{"value": "abcdefghijkl"}, errQueryConfigShape},
		"missing value":  {map[string]string{"param": "api_key"}, errQueryConfigShape},
		"empty object":   {map[string]string{}, errQueryConfigShape},
		"absent":         {nil, errQueryConfigShape},
		"extra header":   {map[string]string{"header": "X", "param": "p", "value": "v"}, errQueryConfigShape},
		"upper-case key": {map[string]string{"PARAM": "p", "value": "v"}, errQueryConfigShape},
		"non-object":     {"abc", errQueryConfigShape},
		"array":          {[]string{"a"}, errQueryConfigShape},
		"bad name":       {map[string]string{"param": "a b", "value": "v"}, errQueryParamName},
		"long value":     {map[string]string{"param": "api_key", "value": long}, errQueryValueLength},
	} {
		t.Run("create "+name, func(t *testing.T) {
			body := upstreamBody("Q", map[string]any{"auth_type": "query"})
			if tc.config != nil {
				body["auth_config"] = tc.config
			}
			rr, up := newUpstream(t, h, body)
			if rr.Code != http.StatusBadRequest || up != nil {
				t.Fatalf("%d %s", rr.Code, rr.Body.String())
			}
			if m := jsonObject(t, rr); m["error"] != tc.want {
				t.Fatalf("error %q, want %q", m["error"], tc.want)
			}
		})
	}
	// The sentences state mcpclient's bounds, so the two cannot drift.
	if !strings.Contains(errQueryParamName, "64") || !strings.Contains(errQueryValueLength, "4096") {
		t.Fatalf("bounds not stated: %q %q", errQueryParamName, errQueryValueLength)
	}

	// PATCH: the type-change refusal and its exemptions.
	bearer, _ := mustUpstream(t, h, "Bearer", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "abcdefghijkl"}})
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+bearer, "test-admin", map[string]any{"auth_type": "query"})
	if rr.Code != http.StatusBadRequest || jsonObject(t, rr)["error"] != errQueryTypeChange {
		t.Fatalf("bearer to query with no config: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+bearer, "test-admin", map[string]any{"auth_type": "query", "auth_config": map[string]string{}})
	if rr.Code != http.StatusBadRequest || jsonObject(t, rr)["error"] != errQueryTypeChange {
		t.Fatalf("bearer to query with {}: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+bearer, "test-admin", queryBody("api_key", "abcdefghijkl"))
	if rr.Code != http.StatusOK {
		t.Fatalf("bearer to query with a config: %d %s", rr.Code, rr.Body.String())
	}
	query := bearer // the row is a query row now
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_type": "header"})
	if rr.Code != http.StatusBadRequest || jsonObject(t, rr)["error"] != errQueryTypeChange {
		t.Fatalf("query to header with no config: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_config": map[string]string{"param": "", "value": "v"}})
	if rr.Code != http.StatusBadRequest || jsonObject(t, rr)["error"] != errQueryConfigShape {
		t.Fatalf("blank param on a query row: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_config": nil})
	if rr.Code != http.StatusOK || jsonObject(t, rr)["auth_status"] != "ok" {
		t.Fatalf("null keeps the credential: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_type": "header", "auth_config": map[string]string{"header": "X-Token", "value": "abcdefghijkl"}})
	if rr.Code != http.StatusOK || jsonObject(t, rr)["auth_status"] != "ok" {
		t.Fatalf("query to header with a config: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", queryBody("api_key", "abcdefghijkl"))
	if rr.Code != http.StatusOK {
		t.Fatalf("back to query: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_config": map[string]string{}})
	if rr.Code != http.StatusOK || jsonObject(t, rr)["auth_status"] != "unreadable" || rawAuth(t, path, query) != "" {
		t.Fatalf("{} clears on a query row (PORM-120): %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", queryBody("api_key", "abcdefghijkl"))
	if rr.Code != http.StatusOK {
		t.Fatalf("query again: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_type": "oauth"})
	if rr.Code != http.StatusOK || jsonObject(t, rr)["auth_configured"] != false {
		t.Fatalf("query to oauth with no config clears: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", queryBody("api_key", "abcdefghijkl"))
	if rr.Code != http.StatusOK {
		t.Fatalf("oauth to query with a config: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+query, "test-admin", map[string]any{"auth_type": "none"})
	if rr.Code != http.StatusOK || jsonObject(t, rr)["auth_status"] != "none" || rawAuth(t, path, query) != "" {
		t.Fatalf("query to none with no config clears: %d %s", rr.Code, rr.Body.String())
	}
}

// TestQueryRowRefusesURLWithParam covers PORM-27 security requirement 8: a
// query row's url may not carry the parameter the credential sets, whichever
// of url, auth_type or auth_config the request changes.
func TestQueryRowRefusesURLWithParam(t *testing.T) {
	_, h, _ := testAPI(t)
	rr, up := newUpstream(t, h, upstreamBody("Q", merge(queryBody("api_key", "abcdefghijkl"), map[string]any{"url": "https://h/mcp?api_key=1"})))
	if rr.Code != http.StatusBadRequest || up != nil || jsonObject(t, rr)["error"] != errURLQueryParam {
		t.Fatalf("create with the param in the url: %d %s", rr.Code, rr.Body.String())
	}
	_, up = newUpstream(t, h, upstreamBody("Q", merge(queryBody("api_key", "abcdefghijkl"), map[string]any{"url": "https://h/mcp?page=1"})))
	if up == nil {
		t.Fatal("create with another parameter refused")
	}
	id := up["id"].(string)
	for name, body := range map[string]map[string]any{
		"url gains the param, case folded": {"url": "https://h/mcp?page=1&API_KEY=1"},
		"url gains it after a semicolon":   {"url": "https://h/mcp?page=1;api_key=1"},
		// The spellings the send drops are the spellings the gate refuses.
		"url gains it NUL padded":                {"url": "https://h/mcp?page=1&api_key%00=1"},
		"url gains it space padded":              {"url": "https://h/mcp?page=1&api_key+=1"},
		"url gains an undecodable key":           {"url": "https://h/mcp?page=1&q%zz=1"},
		"config renames onto a stored parameter": {"auth_config": map[string]string{"param": "page", "value": "abcdefghijkl"}},
	} {
		rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", body)
		if rr.Code != http.StatusBadRequest || jsonObject(t, rr)["error"] != errURLQueryParam {
			t.Fatalf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"url": "https://h/mcp?page=2"})
	if rr.Code != http.StatusOK {
		t.Fatalf("url with another parameter: %d %s", rr.Code, rr.Body.String())
	}
	// A legacy row that carries the key in its url and is switched to the
	// query kind without editing the url is refused, so the key cannot stay
	// in the url column while the row reads as fixed.
	legacy, _ := mustUpstream(t, h, "Legacy", map[string]any{"url": "https://h/mcp?api_key=OLD_VALUE"})
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+legacy, "test-admin", queryBody("api_key", "abcdefghijkl"))
	if rr.Code != http.StatusBadRequest || jsonObject(t, rr)["error"] != errURLQueryParam {
		t.Fatalf("legacy row to query without a url edit: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+legacy, "test-admin", merge(queryBody("api_key", "abcdefghijkl"), map[string]any{"url": "https://h/mcp"}))
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy row fixed in one PATCH: %d %s", rr.Code, rr.Body.String())
	}
}

func merge(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
