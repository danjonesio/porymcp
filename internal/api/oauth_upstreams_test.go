package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// The upstream routes' half of PORM-139 (step 9): the oauth auth type on
// create and PATCH, the client-only shape rule, the widened clearing rules,
// the oauth object on the row, and discovery through the Presenter.

// storeOAuthSet seals set onto the row directly, the way the callback will,
// so a test can start from a connected upstream without a browser flow.
func storeOAuthSet(t *testing.T, s *Server, st *store.SQLStore, id string, set models.OAuthTokenSet) {
	t.Helper()
	ctx := context.Background()
	u, err := st.GetUpstream(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	enc, err := s.keys.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConnectUpstreamAuth(ctx, id, []byte(enc), u.UpdatedAt, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func storedOAuthSet(t *testing.T, s *Server, st *store.SQLStore, id string) (models.OAuthTokenSet, bool) {
	t.Helper()
	u, err := st.GetUpstream(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.AuthConfig) == 0 {
		return models.OAuthTokenSet{}, false
	}
	plain, _, err := s.keys.Open(string(u.AuthConfig))
	if err != nil {
		t.Fatal(err)
	}
	var set models.OAuthTokenSet
	if err := json.Unmarshal(plain, &set); err != nil {
		t.Fatal(err)
	}
	return set, true
}

func connectedSet(stub *oauthstub.Server, resource string) models.OAuthTokenSet {
	access, refresh := stub.Seed()
	return models.OAuthTokenSet{
		AccessToken: access, RefreshToken: refresh, ExpiresAt: time.Now().Add(time.Hour).UTC(),
		TokenEndpoint: stub.TokenEndpoint(), RevocationEndpoint: stub.RevocationEndpoint(), Issuer: stub.Issuer(),
		ClientID: "cid", ClientSource: "supplied", Resource: resource,
	}
}

// Criterion 1: an oauth create with no auth_config is 201, unreadable,
// unconfigured, with an oauth object that says not connected.
func TestCreateOAuthNotConnected(t *testing.T) {
	_, h, _ := testAPI(t)
	rr, up := newUpstream(t, h, upstreamBody("Linear", map[string]any{"auth_type": "oauth"}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if up["auth_type"] != "oauth" || up["auth_status"] != "unreadable" || up["auth_configured"] != false {
		t.Fatalf("row %v", up)
	}
	o, _ := up["oauth"].(map[string]any)
	if o == nil || o["expires_at"] != nil || o["has_refresh_token"] != false || o["client_source"] != nil {
		t.Fatalf("oauth %v", up["oauth"])
	}
	if _, has := up["auth_hint"]; has {
		t.Fatalf("auth_hint present: %v", up)
	}
	if strings.Contains(rr.Body.String(), `"auth_config":`) {
		t.Fatal("the 201 carries an auth_config key")
	}
}

func TestCreateOAuthWithClientIDOnly(t *testing.T) {
	s, h, st := testAPI(t)
	rr, up := newUpstream(t, h, upstreamBody("Vendor", map[string]any{"auth_type": "oauth", "auth_config": map[string]string{"client_id": "pub-client"}}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if up["auth_configured"] != true || up["auth_status"] != "unreadable" {
		t.Fatalf("row %v", up)
	}
	if o := up["oauth"].(map[string]any); o["client_source"] != "supplied" || o["expires_at"] != nil {
		t.Fatalf("oauth %v", o)
	}
	set, ok := storedOAuthSet(t, s, st, up["id"].(string))
	if !ok || set.ClientID != "pub-client" || set.ClientSecret != "" || set.ClientSource != "supplied" || set.AccessToken != "" {
		t.Fatalf("stored %+v", set)
	}
}

func TestCreateOAuthWithClientPair(t *testing.T) {
	s, h, st := testAPI(t)
	rr, up := newUpstream(t, h, upstreamBody("Vendor", map[string]any{"auth_type": "oauth", "auth_config": map[string]string{"client_id": "cid", "client_secret": "sec"}}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if up["auth_configured"] != true || up["auth_status"] != "unreadable" || up["oauth"].(map[string]any)["client_source"] != "supplied" {
		t.Fatalf("row %v", up)
	}
	set, _ := storedOAuthSet(t, s, st, up["id"].(string))
	if set.ClientID != "cid" || set.ClientSecret != "sec" {
		t.Fatalf("stored %+v", set)
	}
	if strings.Contains(rr.Body.String(), "sec") && strings.Contains(rr.Body.String(), `"client_secret"`) {
		t.Fatal("the secret came back")
	}
}

// Security requirement 5: no API caller can plant a token field, and the
// client fields are bounded.
func TestOAuthAuthConfigRefusesTokenFields(t *testing.T) {
	_, h, _ := testAPI(t)
	for name, cfg := range map[string]any{
		"refresh_token":  map[string]string{"client_id": "c", "refresh_token": "r"},
		"token_endpoint": map[string]string{"client_id": "c", "token_endpoint": "https://evil.invalid/token"},
		"access_token":   map[string]string{"access_token": "a"},
		"secret alone":   map[string]string{"client_secret": "s"},
		"not an object":  "cid",
	} {
		rr, _ := newUpstream(t, h, upstreamBody("Vendor", map[string]any{"auth_type": "oauth", "auth_config": cfg}))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errOAuthConfigShape) {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	// The same rule on PATCH.
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"auth_type": "oauth"})
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_config": map[string]string{"client_id": "c", "refresh_token": "r"}})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errOAuthConfigShape) {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthAuthConfigBounds(t *testing.T) {
	_, h, _ := testAPI(t)
	for name, cfg := range map[string]map[string]string{
		"long id":      {"client_id": strings.Repeat("a", maxClientFieldBytes+1)},
		"control byte": {"client_id": "c\x01d"},
		"space":        {"client_id": "c d"},
		"long secret":  {"client_id": "c", "client_secret": strings.Repeat("s", maxClientFieldBytes+1)},
		"non-ascii":    {"client_id": "clé"},
	} {
		rr, _ := newUpstream(t, h, upstreamBody("Vendor", map[string]any{"auth_type": "oauth", "auth_config": cfg}))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
	}
}

// Criterion 8: auth_type none on an oauth row clears exactly as PORM-120
// specifies.
func TestPatchOAuthToNoneClears(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_type": "none"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["auth_configured"] != false || got["auth_status"] != "none" {
		t.Fatalf("response %v", got)
	}
	if _, has := got["oauth"]; has {
		t.Fatalf("a none row carries an oauth object: %v", got)
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("the blob survived")
	}
	if d := detailsOf(t, st, models.ActionUpstreamUpdate); !strings.Contains(d, `"cleared":["credential"]`) {
		t.Fatalf("details %s", d)
	}
}

func TestPatchIntoOAuthClearsOldSecret(t *testing.T) {
	s, h, st := testAPI(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_type": "oauth"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["auth_configured"] != false || got["auth_status"] != "unreadable" {
		t.Fatalf("response %v", got)
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("the bearer token survived under an oauth row")
	}
	if d := detailsOf(t, st, models.ActionUpstreamUpdate); !strings.Contains(d, `"cleared":["credential"]`) || !strings.Contains(d, `"auth_type":"oauth"`) {
		t.Fatalf("details %s", d)
	}
}

func TestPatchOutOfOAuthClearsTokenSet(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_type": "bearer"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	u, _ := st.GetUpstream(context.Background(), id)
	if len(u.AuthConfig) != 0 {
		t.Fatal("a live refresh token survived under a bearer row")
	}
	if d := detailsOf(t, st, models.ActionUpstreamUpdate); !strings.Contains(d, `"cleared":["credential"]`) {
		t.Fatalf("details %s", d)
	}
	// Out of oauth WITH a credential: the new blob replaces the set and the
	// drop is still recorded.
	id2, _ := mustUpstream(t, h, "Vendor2", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id2, connectedSet(stub, stub.MCPURL()))
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id2, "test-admin", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH 2: %d %s", rr.Code, rr.Body.String())
	}
	u2, _ := st.GetUpstream(context.Background(), id2)
	plain, err := credential.Read(s.keys, models.AuthBearer, u2.AuthConfig)
	if err != nil || string(plain) != `{"token":"sk"}` {
		t.Fatalf("stored %s %v", plain, err)
	}
	events := eventsFor(adminEvents(t, st), models.ActionUpstreamUpdate)
	if len(events) != 2 || !strings.Contains(string(events[0].Details), `"cleared":["credential"]`) {
		t.Fatalf("events %d, newest details %s", len(events), events[0].Details)
	}
}

func TestPatchOAuthURLDropsTokens(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"url": stub.URL() + "/other"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["auth_configured"] != false || got["auth_status"] != "unreadable" || got["last_test_at"] != nil {
		t.Fatalf("response %v", got)
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("the token set survived a URL change")
	}
	if d := detailsOf(t, st, models.ActionUpstreamUpdate); !strings.Contains(d, `"cleared":["credential"]`) || !strings.Contains(d, `"url"`) {
		t.Fatalf("details %s", d)
	}
	// The same URL resent is not a change and keeps a set.
	id2, _ := mustUpstream(t, h, "Vendor2", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id2, connectedSet(stub, stub.MCPURL()))
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id2, "test-admin", map[string]any{"url": stub.MCPURL()}); rr.Code != http.StatusOK {
		t.Fatalf("PATCH same url: %d", rr.Code)
	}
	if _, ok := storedOAuthSet(t, s, st, id2); !ok {
		t.Fatal("the same URL dropped the set")
	}
}

// A client or a credential sent in the same body as a URL change is kept:
// the URL clause of clearAuth yields to a carried auth_config, as the type
// clause does.
func TestPatchOAuthURLChangeKeepsCarriedClient(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"url": stub.URL() + "/other", "auth_config": map[string]string{"client_id": "mine"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	set, ok := storedOAuthSet(t, s, st, id)
	if !ok || set.ClientID != "mine" || set.AccessToken != "" {
		t.Fatalf("stored %+v ok=%v, want the carried client alone", set, ok)
	}
	if d := detailsOf(t, st, models.ActionUpstreamUpdate); !strings.Contains(d, `"cleared":["credential"]`) || !strings.Contains(d, `"auth_changed":true`) {
		t.Fatalf("details %s", d)
	}
	// And out of oauth with a bearer token in the same body as the URL.
	id2, _ := mustUpstream(t, h, "Vendor2", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id2, connectedSet(stub, stub.MCPURL()))
	rr = doJSON(t, h, http.MethodPatch, "/upstreams/"+id2, "test-admin", map[string]any{"url": stub.URL() + "/other", "auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH 2: %d %s", rr.Code, rr.Body.String())
	}
	u2, _ := st.GetUpstream(context.Background(), id2)
	if plain, err := credential.Read(s.keys, models.AuthBearer, u2.AuthConfig); err != nil || string(plain) != `{"token":"sk"}` {
		t.Fatalf("stored %s %v", plain, err)
	}
}

func TestPatchOAuthNameKeepsTokens(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	set := connectedSet(stub, stub.MCPURL())
	storeOAuthSet(t, s, st, id, set)
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"name": "Renamed", "enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["auth_status"] != "ok" || got["auth_configured"] != true {
		t.Fatalf("response %v", got)
	}
	o := got["oauth"].(map[string]any)
	if o["expires_at"] == nil || o["has_refresh_token"] != true || o["client_source"] != "supplied" {
		t.Fatalf("oauth %v", o)
	}
	stored, _ := storedOAuthSet(t, s, st, id)
	if stored.RefreshToken != set.RefreshToken {
		t.Fatal("a rename touched the token set")
	}
	if d := detailsOf(t, st, models.ActionUpstreamUpdate); strings.Contains(d, "cleared") {
		t.Fatalf("details %s", d)
	}
}

func TestPatchOAuthNewClientDropsTokensRecordsCleared(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_config": map[string]string{"client_id": "new", "client_secret": "s2"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["auth_configured"] != true || got["auth_status"] != "unreadable" || got["oauth"].(map[string]any)["expires_at"] != nil {
		t.Fatalf("response %v", got)
	}
	stored, _ := storedOAuthSet(t, s, st, id)
	if stored.ClientID != "new" || stored.ClientSecret != "s2" || stored.AccessToken != "" || stored.RefreshToken != "" {
		t.Fatalf("stored %+v", stored)
	}
	d := detailsOf(t, st, models.ActionUpstreamUpdate)
	if !strings.Contains(d, `"cleared":["credential"]`) || !strings.Contains(d, `"auth_changed":true`) {
		t.Fatalf("details %s", d)
	}
}

// Security requirement 6 and 9: the row's oauth object and the list carry
// nothing secret.
func TestPresentUpstreamOAuthObjectCarriesNoSecret(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth", "auth_config": map[string]string{"client_id": "cid", "client_secret": "SECRET_MARKER"}})
	set := connectedSet(stub, stub.MCPURL())
	set.ClientSecret = "SECRET_MARKER"
	set.Scope = "SCOPE_MARKER"
	storeOAuthSet(t, s, st, id, set)
	for _, path := range []string{"/upstreams/" + id, "/upstreams"} {
		rr := doJSON(t, h, http.MethodGet, path, "test-admin", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rr.Code)
		}
		// The stub's issuer shares the upstream URL's origin, so the keys are
		// checked rather than the values: no issuer, endpoint or scope member.
		for _, needle := range []string{set.AccessToken, set.RefreshToken, "SECRET_MARKER", "SCOPE_MARKER", `"issuer"`, `"token_endpoint"`, `"scope"`, `"auth_config":`} {
			if strings.Contains(rr.Body.String(), needle) {
				t.Fatalf("%s carries %q: %s", path, needle, rr.Body.String())
			}
		}
	}
	got := getJSON(t, h, "/upstreams/"+id)
	o := got["oauth"].(map[string]any)
	if got["auth_status"] != "ok" || o["expires_at"] == nil || o["has_refresh_token"] != true || o["client_source"] != "supplied" {
		t.Fatalf("row %v", got)
	}
	// A lapsed set with no refresh token reads expired.
	lapsed := connectedSet(stub, stub.MCPURL())
	lapsed.RefreshToken = ""
	lapsed.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	storeOAuthSet(t, s, st, id, lapsed)
	got = getJSON(t, h, "/upstreams/"+id)
	if got["auth_status"] != "expired" || got["oauth"].(map[string]any)["has_refresh_token"] != false {
		t.Fatalf("lapsed row %v", got)
	}
}

func TestDiscoverUnsavedOAuthRefused(t *testing.T) {
	_, h, _ := testAPI(t)
	rr := doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", map[string]any{"url": "https://example.test/mcp", "auth_type": "oauth", "auth_config": map[string]string{"access_token": "a"}})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errDiscoverUnsavedOAuth) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// Tools on a saved oauth row goes through the Presenter: a lapsed token is
// renewed first, the refresh event names the admin and the caller's address,
// and a dead grant reads as expired.
func TestDiscoverOAuthRowRefreshesWithAdminActor(t *testing.T) {
	s, h, st := testAPI(t)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	set := connectedSet(stub, stub.MCPURL())
	set.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	storeOAuthSet(t, s, st, id, set)

	d := discovery(t, doJSONAddr(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", "203.0.113.9:4444", nil))
	if d["ok"] != true {
		t.Fatalf("discovery %v", d)
	}
	if stub.Grants("refresh_token") != 1 {
		t.Fatalf("refresh grants %d", stub.Grants("refresh_token"))
	}
	events := eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthRefresh)
	// No request id: chi's RequestID middleware is newRouter's (cmd/server),
	// not Routes()', as for every admin event in this package's tests.
	if len(events) != 1 || events[0].Actor != models.ActorAdmin || events[0].RemoteAddr != "203.0.113.9" {
		t.Fatalf("events %+v", events)
	}
	if reqs := stub.Requests(); len(reqs) == 0 || !strings.HasPrefix(reqs[0].Header.Get("Authorization"), "Bearer acc-") {
		t.Fatalf("stub requests %+v", reqs)
	}

	// A dead grant: the row reads expired and Tools says so without dialling.
	stub.RejectRefresh = true
	dead := connectedSet(stub, stub.MCPURL())
	dead.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	storeOAuthSet(t, s, st, id, dead)
	before := len(stub.Requests())
	d = discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil))
	if d["ok"] != false || d["error"] != "stored credential has expired; connect again" {
		t.Fatalf("discovery %v", d)
	}
	if len(stub.Requests()) != before {
		t.Fatal("the upstream was dialled with a dead grant")
	}
	if got := getJSON(t, h, "/upstreams/"+id); got["auth_status"] != "expired" || got["last_test_ok"] != false {
		t.Fatalf("row %v", got)
	}
}
