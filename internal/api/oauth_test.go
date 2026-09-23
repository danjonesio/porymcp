package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/go-chi/chi/v5"
)

// The OAuth routes (PORM-139 steps 10a to 10c). Start tests run under an
// https PUBLIC_URL: the default testAPI value is a loopback http address and
// the requests httptest builds carry Host example.com, which the start route
// refuses on purpose (TestOAuthStartLoopbackMismatchMessage).

const testPublicURL = "https://pory.test"

// oauthServer is testAPIPublicURL plus a stub and an oauth row for it.
func oauthServer(t *testing.T, publicURL string) (*Server, http.Handler, *store.SQLStore, *oauthstub.Server, string) {
	t.Helper()
	s, h, st := testAPIPublicURL(t, publicURL)
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	return s, h, st, stub, id
}

// start posts the start route and returns the response and the decoded body.
func start(t *testing.T, h http.Handler, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/oauth/start", "test-admin", body)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func mustStart(t *testing.T, h http.Handler, id string, body any) map[string]any {
	t.Helper()
	rr, out := start(t, h, id, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	return out
}

func authQuery(t *testing.T, out map[string]any) url.Values {
	t.Helper()
	u, err := url.Parse(out["authorization_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestClientMetadataDocument(t *testing.T) {
	_, h, _ := testAPIPublicURL(t, testPublicURL)
	rr := doJSON(t, h, http.MethodGet, "/oauth/client-metadata", "", nil)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" || rr.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("%d %v", rr.Code, rr.Header())
	}
	var doc map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &doc)
	if doc["client_id"] != testPublicURL+"/api/v1/oauth/client-metadata" || doc["token_endpoint_auth_method"] != "none" || doc["application_type"] != "web" {
		t.Fatalf("doc %v", doc)
	}
	if uris, _ := doc["redirect_uris"].([]any); len(uris) != 1 || uris[0] != testPublicURL+"/api/v1/oauth/callback" {
		t.Fatalf("redirect_uris %v", doc["redirect_uris"])
	}
	for _, key := range []string{"logo_uri", "client_uri", "contacts"} {
		if _, has := doc[key]; has {
			t.Fatalf("document carries %s", key)
		}
	}
}

// Security requirement 11: the document and the redirect URI come from
// PUBLIC_URL alone; a spoofed Host or X-Forwarded-Host changes nothing.
func TestClientMetadataIgnoresHost(t *testing.T) {
	_, h, _ := testAPIPublicURL(t, testPublicURL)
	req := httptest.NewRequest(http.MethodGet, "http://evil.invalid/oauth/client-metadata", nil)
	req.Host = "evil.invalid"
	req.Header.Set("X-Forwarded-Host", "evil.invalid")
	req.Header.Set("X-Forwarded-Proto", "http")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "evil") || !strings.Contains(rr.Body.String(), testPublicURL+"/api/v1/oauth/callback") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// Criterion 2.
func TestOAuthStartAuthorizationURL(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	rr, out := start(t, h, id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	q := authQuery(t, out)
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("response_type") != "code" {
		t.Fatalf("query %v", q)
	}
	if q.Get("resource") != stub.MCPURL() || q.Get("redirect_uri") != testPublicURL+"/api/v1/oauth/callback" {
		t.Fatalf("resource %q redirect_uri %q", q.Get("resource"), q.Get("redirect_uri"))
	}
	if out["expires_in"] != float64(600) || out["issuer"] != strings.TrimPrefix(stub.Issuer(), "http://") || out["client"] != "document" {
		t.Fatalf("body %v", out)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", rr.Header().Get("Cache-Control"))
	}
	if _, err := stub.Approve(out["authorization_url"].(string)); err != nil {
		t.Fatalf("the stub refused the URL: %v", err)
	}
	if strings.Contains(rr.Body.String(), "verifier") {
		t.Fatal("the verifier came back")
	}
}

func TestOAuthStartRefusesNonOAuthRow(t *testing.T) {
	_, h, _ := testAPIPublicURL(t, testPublicURL)
	id, _ := mustUpstream(t, h, "Bearer", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	rr, _ := start(t, h, id, nil)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errNotOAuthRow) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr, _ := start(t, h, "00000000-0000-4000-8000-000000000000", nil); rr.Code != http.StatusNotFound || rr.Body.String() != "{\"error\":\"not found\"}\n" {
		t.Fatalf("unknown id: %d %s", rr.Code, rr.Body.String())
	}
	oid, _ := mustUpstream(t, h, "Vendor", map[string]any{"auth_type": "oauth"})
	if rr, _ := start(t, h, oid, map[string]any{"client": "magic"}); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errClientChoice) {
		t.Fatalf("bad client: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthStartRefusesHTTPPublicURLOffLoopback(t *testing.T) {
	s, h, _, _, id := oauthServer(t, "http://pory.internal:8080")
	rr, _ := start(t, h, id, nil)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errPublicURLScheme) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	s.cfg.AllowInsecureHTTP = true
	if rr, out := start(t, h, id, nil); rr.Code != http.StatusOK || out["client"] != "registered" {
		t.Fatalf("with ALLOW_INSECURE_HTTP: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthStartAllowsLoopbackHTTP(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, "http://localhost:8080")
	rr := doJSON(t, h, http.MethodPost, "http://localhost:8080/upstreams/"+id+"/oauth/start", "test-admin", nil)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out["client"] != "registered" {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if q := authQuery(t, out); q.Get("redirect_uri") != "http://localhost:8080/api/v1/oauth/callback" {
		t.Fatalf("redirect_uri %q", q.Get("redirect_uri"))
	}
	if stub.Registrations() != 1 {
		t.Fatalf("registrations %d", stub.Registrations())
	}
}

func TestOAuthStartLoopbackMismatchMessage(t *testing.T) {
	_, h, _, _, id := oauthServer(t, "http://localhost:8080")
	rr, _ := start(t, h, id, nil) // Host example.com
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "PUBLIC_URL is http://localhost:8080 but this request was sent to example.com") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthStartPrefersSuppliedClient(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_config": map[string]string{"client_id": "mine", "client_secret": "s"}}); rr.Code != http.StatusOK {
		t.Fatalf("patch: %d", rr.Code)
	}
	out := mustStart(t, h, id, nil)
	if out["client"] != "supplied" || authQuery(t, out).Get("client_id") != "mine" || stub.Registrations() != 0 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
}

func TestOAuthStartPrefersStoredRegistrationOverDocument(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	storeOAuthSet(t, s, st, id, models.OAuthTokenSet{
		ClientID: "reg-old", ClientSecret: "x", ClientSource: "registered", ClientIssuer: stub.Issuer(), ClientRedirectURI: testPublicURL + "/api/v1/oauth/callback",
	})
	out := mustStart(t, h, id, nil)
	if out["client"] != "registered" || authQuery(t, out).Get("client_id") != "reg-old" || stub.Registrations() != 0 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
}

func TestOAuthStartUsesDocumentWhenAdvertised(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	out := mustStart(t, h, id, nil)
	if out["client"] != "document" || authQuery(t, out).Get("client_id") != testPublicURL+"/api/v1/oauth/client-metadata" || stub.Registrations() != 0 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
}

func TestOAuthStartNeverUsesDocumentOnLoopback(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, "https://localhost:8080")
	rr := doJSON(t, h, http.MethodPost, "https://localhost:8080/upstreams/"+id+"/oauth/start", "test-admin", nil)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out["client"] != "registered" || stub.Registrations() != 1 {
		t.Fatalf("%d %s registrations %d", rr.Code, rr.Body.String(), stub.Registrations())
	}
}

func TestOAuthStartForcesRegistered(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	out := mustStart(t, h, id, map[string]any{"client": "registered"})
	if out["client"] != "registered" || !strings.HasPrefix(authQuery(t, out).Get("client_id"), "reg-") || stub.Registrations() != 1 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
	// Forcing the document against a server that does not accept one is a
	// fixed refusal.
	stub2 := oauthstub.New(t)
	stub2.NoCIMD = true
	id2, _ := mustUpstream(t, h, "Vendor2", map[string]any{"url": stub2.MCPURL(), "auth_type": "oauth"})
	if rr, _ := start(t, h, id2, map[string]any{"client": "document"}); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errDocumentNotSupported) {
		t.Fatalf("forced document: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthStartFallsBackToRegistration(t *testing.T) {
	_, h, _ := testAPIPublicURL(t, testPublicURL)
	stub := oauthstub.New(t)
	stub.NoCIMD = true
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	out := mustStart(t, h, id, nil)
	if out["client"] != "registered" || stub.Registrations() != 1 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
	// Neither the document nor registration: a fixed refusal naming the fix.
	stub2 := oauthstub.New(t)
	stub2.NoCIMD = true
	stub2.NoRegistration = true
	id2, _ := mustUpstream(t, h, "Vendor2", map[string]any{"url": stub2.MCPURL(), "auth_type": "oauth"})
	if rr, _ := start(t, h, id2, nil); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errNoClientIdentity) {
		t.Fatalf("no identity: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthStartReregistersOnNewIssuer(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	stub.NoCIMD = true
	storeOAuthSet(t, s, st, id, models.OAuthTokenSet{
		ClientID: "reg-old", ClientSecret: "x", ClientSource: "registered", ClientIssuer: "https://other.invalid", ClientRedirectURI: testPublicURL + "/api/v1/oauth/callback",
	})
	out := mustStart(t, h, id, nil)
	if out["client"] != "registered" || authQuery(t, out).Get("client_id") == "reg-old" || stub.Registrations() != 1 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
	// A registration made for another redirect URI is re-made too.
	storeOAuthSet(t, s, st, id, models.OAuthTokenSet{
		ClientID: "reg-old", ClientSecret: "x", ClientSource: "registered", ClientIssuer: stub.Issuer(), ClientRedirectURI: "https://old.invalid/cb",
	})
	out = mustStart(t, h, id, nil)
	if authQuery(t, out).Get("client_id") == "reg-old" || stub.Registrations() != 2 {
		t.Fatalf("body %v registrations %d", out, stub.Registrations())
	}
}

// Security requirement 6: a supplied client is bound to the issuer that
// first accepted it.
func TestOAuthStartRefusesSuppliedClientForOtherIssuer(t *testing.T) {
	s, h, st, _, id := oauthServer(t, testPublicURL)
	storeOAuthSet(t, s, st, id, models.OAuthTokenSet{ClientID: "mine", ClientSource: "supplied", ClientIssuer: "https://other.invalid"})
	rr, _ := start(t, h, id, nil)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errClientOtherIssuer) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthStartReplacesPendingFlow(t *testing.T) {
	s, h, _, _, id := oauthServer(t, testPublicURL)
	first := authQuery(t, mustStart(t, h, id, nil)).Get("state")
	second := authQuery(t, mustStart(t, h, id, nil)).Get("state")
	if _, ok := s.flows.take(first); ok {
		t.Fatal("the first flow survived a second start")
	}
	if _, ok := s.flows.take(second); !ok {
		t.Fatal("the second flow is missing")
	}
	if _, ok := s.flows.take(second); ok {
		t.Fatal("a taken flow was taken twice")
	}
}

func TestOAuthFlowsCap(t *testing.T) {
	f := newOAuthFlows()
	now := time.Now()
	f.SetClock(func() time.Time { return now })
	for i := 0; i < oauthFlowCap; i++ {
		if !f.put(fmt.Sprint("state", i), oauthFlow{upstreamID: fmt.Sprint("u", i), expires: now.Add(oauthFlowTTL)}) {
			t.Fatalf("put %d refused", i)
		}
	}
	if f.put("one-more", oauthFlow{upstreamID: "u-more", expires: now.Add(oauthFlowTTL)}) {
		t.Fatal("the cap did not hold")
	}
	// A replacement for an upstream already pending is not a new entry.
	if !f.put("again", oauthFlow{upstreamID: "u1", expires: now.Add(oauthFlowTTL)}) {
		t.Fatal("a replacement was refused at the cap")
	}
	// Expired flows are pruned on the next insert, and an expired state is
	// not redeemable.
	now = now.Add(oauthFlowTTL + time.Second)
	if _, ok := f.take("state0"); ok {
		t.Fatal("an expired flow was redeemed")
	}
	if !f.put("fresh", oauthFlow{upstreamID: "u-fresh", expires: now.Add(oauthFlowTTL)}) {
		t.Fatal("the prune did not make room")
	}
}

func TestOAuthStartLogsStageOnFailure(t *testing.T) {
	s, h, _ := testAPIPublicURL(t, testPublicURL)
	stub := oauthstub.New(t)
	stub.NoS256 = true
	stub.ErrorDescriptionMarker = "VENDOR_WORDS_MARKER"
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, nil))
	rr, _ := start(t, h, id, nil)
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), mcpclient.ErrOAuthNoPKCE.Error()) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(logs.String(), "upstream oauth start failed") || !strings.Contains(logs.String(), `"stage":"authorization_server"`) {
		t.Fatalf("log %s", logs.String())
	}
	if strings.Contains(logs.String(), "VENDOR_WORDS_MARKER") {
		t.Fatalf("vendor words reached the log: %s", logs.String())
	}
}

// The callback (10b).

// approve plays the vendor's consent page for a started flow and returns
// the callback path plus query the browser would be sent to.
func approve(t *testing.T, stub *oauthstub.Server, out map[string]any) string {
	t.Helper()
	rd, err := stub.Approve(out["authorization_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(rd.Location)
	return "/oauth/callback?" + loc.RawQuery
}

// callback GETs the callback with no admin key.
func callback(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodGet, path, "", nil)
}

// connect runs start, approve and callback and returns the callback answer.
func connect(t *testing.T, h http.Handler, stub *oauthstub.Server, id string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	path := approve(t, stub, mustStart(t, h, id, nil))
	return callback(t, h, path), path
}

func withQuery(t *testing.T, path string, edit func(q url.Values)) string {
	t.Helper()
	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	edit(q)
	u.RawQuery = q.Encode()
	return u.String()
}

// Criterion 3.
func TestOAuthCallbackConnects(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	rr, cbPath := connect(t, h, stub, id)
	if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rr.Code, rr.Header(), rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Upstream connected") || !strings.Contains(body, `content="0; url=/upstreams/"`) || !strings.Contains(body, "Vendor is connected.") || strings.Contains(body, "<script") || strings.Contains(body, "<style") {
		t.Fatalf("page %s", body)
	}
	u, _ := st.GetUpstream(context.Background(), id)
	if !strings.HasPrefix(string(u.AuthConfig), "v1:") {
		t.Fatalf("stored %q, want a v1 blob", u.AuthConfig)
	}
	set, _ := storedOAuthSet(t, s, st, id)
	if !stub.AccessValid(set.AccessToken) || !stub.RefreshValid(set.RefreshToken) || set.Resource != stub.MCPURL() || set.TokenEndpoint != stub.TokenEndpoint() || set.ClientSource != "document" || set.Issuer != stub.Issuer() {
		t.Fatalf("stored %+v", set)
	}
	row := getJSON(t, h, "/upstreams/"+id)
	if row["auth_status"] != "ok" || row["auth_configured"] != true || row["last_test_at"] != nil {
		t.Fatalf("row %v", row)
	}
	events := eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthConnect)
	if len(events) != 1 || events[0].Actor != models.ActorAdmin || events[0].ResourceName != "Vendor" {
		t.Fatalf("events %+v", events)
	}
	if d := string(events[0].Details); !strings.Contains(d, `"auth_type":"oauth"`) || !strings.Contains(d, `"client":"document"`) || !strings.Contains(d, `"refresh_token":true`) || !strings.Contains(d, `"issuer":"`) {
		t.Fatalf("details %s", d)
	}
	// The same state a second time answers 400 and records nothing.
	rr = callback(t, h, cbPath)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "expired or was already used") {
		t.Fatalf("second use: %d %s", rr.Code, rr.Body.String())
	}
	if n := len(eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthConnect)); n != 1 {
		t.Fatalf("events after reuse %d", n)
	}
	if stub.Grants("authorization_code") != 1 {
		t.Fatalf("code grants %d", stub.Grants("authorization_code"))
	}
}

func TestOAuthCallbackStateSingleUse(t *testing.T) {
	s, h, _, stub, id := oauthServer(t, testPublicURL)
	out := mustStart(t, h, id, nil)
	path := approve(t, stub, out)
	// A failed callback consumes the state too: a vendor error on a live
	// state leaves nothing to redeem.
	rr := callback(t, h, withQuery(t, path, func(q url.Values) { q.Set("error", "access_denied"); q.Del("code") }))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if rr := callback(t, h, path); rr.Code != http.StatusBadRequest {
		t.Fatalf("after a consumed state: %d", rr.Code)
	}
	if _, ok := s.flows.take(authQuery(t, out).Get("state")); ok {
		t.Fatal("the state survived")
	}
}

func TestOAuthCallbackUnknownState(t *testing.T) {
	_, h, st, _, _ := oauthServer(t, testPublicURL)
	for _, path := range []string{"/oauth/callback", "/oauth/callback?code=x", "/oauth/callback?code=x&state=nope"} {
		rr := callback(t, h, path)
		if rr.Code != http.StatusBadRequest || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d %v", path, rr.Code, rr.Header())
		}
	}
	if n := len(adminEvents(t, st)); n != 1 { // the create
		t.Fatalf("events %d", n)
	}
}

func TestOAuthCallbackExpiredState(t *testing.T) {
	s, h, _, stub, id := oauthServer(t, testPublicURL)
	now := time.Now()
	s.flows.SetClock(func() time.Time { return now })
	path := approve(t, stub, mustStart(t, h, id, nil))
	now = now.Add(oauthFlowTTL + time.Second)
	if rr := callback(t, h, path); rr.Code != http.StatusBadRequest || stub.Grants("authorization_code") != 0 {
		t.Fatalf("%d grants %d", rr.Code, stub.Grants("authorization_code"))
	}
}

func TestOAuthCallbackVendorError(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	rr := callback(t, h, withQuery(t, path, func(q url.Values) {
		q.Set("error", "access_denied")
		q.Set("error_description", "DESCRIPTION_MARKER")
		q.Del("code")
	}))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "answered access_denied") || strings.Contains(rr.Body.String(), "DESCRIPTION_MARKER") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	path = approve(t, stub, mustStart(t, h, id, nil))
	rr = callback(t, h, withQuery(t, path, func(q url.Values) { q.Set("error", "<img src=x onerror=alert(1)>"); q.Del("code") }))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "refused the request") || strings.Contains(rr.Body.String(), "onerror") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// Security requirement 1: a wrong or missing iss is refused before the code
// goes anywhere.
func TestOAuthCallbackIssMismatchBeforeExchange(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	rr := callback(t, h, withQuery(t, path, func(q url.Values) { q.Set("iss", "https://other.invalid") }))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "could not be connected") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if stub.Grants("authorization_code") != 0 {
		t.Fatal("the code was exchanged despite the iss mismatch")
	}
}

func TestOAuthCallbackMissingIssWhenAdvertised(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	rr := callback(t, h, withQuery(t, path, func(q url.Values) { q.Del("iss") }))
	if rr.Code != http.StatusBadGateway || stub.Grants("authorization_code") != 0 {
		t.Fatalf("%d grants %d", rr.Code, stub.Grants("authorization_code"))
	}
	// A server that never promised iss may omit it.
	_, h2, _ := testAPIPublicURL(t, testPublicURL)
	stub2 := oauthstub.New(t)
	stub2.NoIss = true
	id2, _ := mustUpstream(t, h2, "Vendor", map[string]any{"url": stub2.MCPURL(), "auth_type": "oauth"})
	if rr, _ := connect(t, h2, stub2, id2); rr.Code != http.StatusOK {
		t.Fatalf("no-iss server: %d %s", rr.Code, rr.Body.String())
	}
}

// Security requirement 2: a row edited during the sign-in stores nothing.
func TestOAuthCallbackRowEditedDuringFlow(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"name": "Renamed"}); rr.Code != http.StatusOK {
		t.Fatalf("rename: %d", rr.Code)
	}
	rr := callback(t, h, path)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "changed during sign-in") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("a token was stored on an edited row")
	}
	if n := len(eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthConnect)); n != 0 {
		t.Fatalf("connect events %d", n)
	}
	// A URL change drops the flow itself.
	path = approve(t, stub, mustStart(t, h, id, nil))
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"url": stub.URL() + "/other"}); rr.Code != http.StatusOK {
		t.Fatalf("url change: %d", rr.Code)
	}
	if rr := callback(t, h, path); rr.Code != http.StatusBadRequest {
		t.Fatalf("after a URL change: %d, want the dropped flow's 400", rr.Code)
	}
}

func TestOAuthCallbackRowDeletedDuringFlow(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	if rr := doJSON(t, h, http.MethodDelete, "/upstreams/"+id, "test-admin", nil); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := callback(t, h, path); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "changed during sign-in") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthCallbackNeedsNoAdminKey(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	req := httptest.NewRequest(http.MethodGet, path, nil) // no Authorization at all
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// Security requirement 3: the budget is checked before the state, so an
// over-budget reload keeps its state and redeems once the budget refills.
func TestOAuthCallbackFailureLimiterKeepsState(t *testing.T) {
	s, h, _, stub, id := oauthServer(t, testPublicURL)
	now := time.Now()
	s.callbackFails.SetClock(func() time.Time { return now })
	for i := 0; i < callbackFailRPM; i++ {
		if rr := callback(t, h, "/oauth/callback?state=junk"); rr.Code != http.StatusBadRequest {
			t.Fatalf("junk %d: %d", i, rr.Code)
		}
	}
	path := approve(t, stub, mustStart(t, h, id, nil))
	rr := callback(t, h, path)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") || !strings.Contains(rr.Body.String(), "Too many failed sign-in attempts") {
		t.Fatalf("%d %v %s", rr.Code, rr.Header(), rr.Body.String())
	}
	now = now.Add(2 * time.Minute)
	if rr := callback(t, h, path); rr.Code != http.StatusOK {
		t.Fatalf("after the budget refilled: %d %s", rr.Code, rr.Body.String())
	}
}

// Security requirement 10: nothing from the query reaches any page, and no
// page says "tab".
func TestOAuthCallbackPageEchoesNothing(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, testPublicURL)
	stub.TokenType = "DPoP" // the exchange is refused
	stub.ErrorDescriptionMarker = "VENDOR_WORDS_MARKER"
	pages := map[string]*httptest.ResponseRecorder{}
	path := approve(t, stub, mustStart(t, h, id, nil))
	q, _ := url.ParseQuery(strings.TrimPrefix(path, "/oauth/callback?"))
	code, state := q.Get("code"), q.Get("state")
	pages["exchange"] = callback(t, h, path)
	pages["reused"] = callback(t, h, path)
	pages["unknown"] = callback(t, h, "/oauth/callback?code=CODE_MARKER&state=STATE_MARKER&iss=ISS_MARKER")
	path = approve(t, stub, mustStart(t, h, id, nil))
	pages["vendor"] = callback(t, h, withQuery(t, path, func(q url.Values) { q.Set("error", "access_denied"); q.Set("error_description", "DESC_MARKER") }))
	for name, rr := range pages {
		body := rr.Body.String()
		for _, needle := range []string{code, state, "CODE_MARKER", "STATE_MARKER", "ISS_MARKER", "DESC_MARKER", "VENDOR_WORDS_MARKER", "tab", "<script"} {
			if needle != "" && strings.Contains(body, needle) {
				t.Fatalf("%s page carries %q: %s", name, needle, body)
			}
		}
	}
	if pages["exchange"].Code != http.StatusBadGateway {
		t.Fatalf("exchange page %d", pages["exchange"].Code)
	}
}

func TestOAuthCallbackHeadIs405(t *testing.T) {
	s, h, _, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	req := httptest.NewRequest(http.MethodHead, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: %d", rr.Code)
	}
	_ = s
	if rr := callback(t, h, path); rr.Code != http.StatusOK {
		t.Fatalf("HEAD consumed the state: %d", rr.Code)
	}
}

// A browser that goes away after the vendor issued the grant cannot lose it.
func TestOAuthCallbackRunsOffRequestContext(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	path := approve(t, stub, mustStart(t, h, id, nil))
	release := stub.HoldToken()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- doJSONCtx(t, h, ctx, http.MethodGet, path, "", nil).Code }()
	deadline := time.Now().Add(5 * time.Second)
	for stub.Grants("authorization_code") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	release()
	<-done
	set, ok := storedOAuthSet(t, s, st, id)
	if !ok || !stub.AccessValid(set.AccessToken) {
		t.Fatalf("stored %+v ok=%v", set, ok)
	}
}

// Security requirement 3: the routes reachable without the admin key are
// exactly the three public ones.
func TestPublicRoutesArePinned(t *testing.T) {
	s, h, _ := testAPIPublicURL(t, testPublicURL)
	public := map[string]bool{"GET /health": true, "GET /oauth/callback": true, "GET /oauth/client-metadata": true}
	seen := map[string]bool{}
	// The admin-fail budget answers 429 after ten refusals from one address;
	// the clock moves a minute per route so every refusal is the 401 itself.
	now := time.Now()
	s.adminFails.SetClock(func() time.Time { return now })
	err := chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		seen[key] = true
		now = now.Add(time.Minute)
		path := strings.ReplaceAll(route, "{id}", "00000000-0000-4000-8000-000000000000")
		rr := doJSON(t, h, method, path, "", nil)
		if public[key] {
			if rr.Code == http.StatusUnauthorized {
				t.Errorf("%s answered 401, want it public", key)
			}
		} else if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d without a key, want 401", key, rr.Code)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key := range public {
		if !seen[key] {
			t.Errorf("public route %s is not served", key)
		}
	}
}

// Disconnect (10c).

func revoke(t *testing.T, h http.Handler, id string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/oauth/revoke", "test-admin", nil)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// Criterion 7.
func TestOAuthRevoke(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	if rr, _ := connect(t, h, stub, id); rr.Code != http.StatusOK {
		t.Fatalf("connect: %d", rr.Code)
	}
	rr, out := revoke(t, h, id)
	if rr.Code != http.StatusOK || out["vendor_revocation"] != revokedAtVendor {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	row := out["upstream"].(map[string]any)
	if row["auth_status"] != "unreadable" || row["auth_configured"] != false || row["oauth"].(map[string]any)["expires_at"] != nil {
		t.Fatalf("row %v", row)
	}
	if stub.Revocations() != 1 {
		t.Fatalf("revocations %d", stub.Revocations())
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("the blob survived")
	}
	events := eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthRevoke)
	if len(events) != 1 || !strings.Contains(string(events[0].Details), `"cleared":["credential"]`) || !strings.Contains(string(events[0].Details), `"vendor_revocation":"revoked"`) {
		t.Fatalf("events %+v", events)
	}
	if got := getJSON(t, h, "/upstreams/"+id); got["auth_status"] != "unreadable" || got["auth_configured"] != false {
		t.Fatalf("GET %v", got)
	}
	if rr, _ := revoke(t, h, "00000000-0000-4000-8000-000000000000"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rr.Code)
	}
	bid, _ := mustUpstream(t, h, "Bearer", map[string]any{"auth_type": "bearer", "auth_config": map[string]string{"token": "sk"}})
	if rr, _ := revoke(t, h, bid); rr.Code != http.StatusBadRequest {
		t.Fatalf("bearer row: %d", rr.Code)
	}
}

func TestOAuthRevokeVendorFailureStillClears(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer failing.Close()
	set := connectedSet(stub, stub.MCPURL())
	set.RevocationEndpoint = failing.URL + "/revoke"
	storeOAuthSet(t, s, st, id, set)
	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, nil))
	rr, out := revoke(t, h, id)
	if rr.Code != http.StatusOK || out["vendor_revocation"] != revokeFailed {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("the blob survived a vendor failure")
	}
	if !strings.Contains(logs.String(), "upstream oauth vendor revocation failed") || !strings.Contains(logs.String(), "upstream oauth disconnected") {
		t.Fatalf("log %s", logs.String())
	}
	if d := detailsOf(t, st, models.ActionUpstreamOAuthRevoke); !strings.Contains(d, `"vendor_revocation":"failed"`) {
		t.Fatalf("details %s", d)
	}
	// No revocation endpoint at all.
	id2, _ := mustUpstream(t, h, "Vendor2", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	set2 := connectedSet(stub, stub.MCPURL())
	set2.RevocationEndpoint = ""
	storeOAuthSet(t, s, st, id2, set2)
	if rr, out := revoke(t, h, id2); rr.Code != http.StatusOK || out["vendor_revocation"] != revokeNotOffered {
		t.Fatalf("not offered: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthRevokeNoTokenClientOnlyRow(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_config": map[string]string{"client_id": "mine"}}); rr.Code != http.StatusOK {
		t.Fatalf("patch: %d", rr.Code)
	}
	rr, out := revoke(t, h, id)
	if rr.Code != http.StatusOK || out["vendor_revocation"] != revokeNoToken || stub.Revocations() != 0 {
		t.Fatalf("%d %s revocations %d", rr.Code, rr.Body.String(), stub.Revocations())
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("the client survived")
	}
	if out["upstream"].(map[string]any)["auth_configured"] != false {
		t.Fatalf("row %v", out["upstream"])
	}
	if n := len(eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthRevoke)); n != 1 {
		t.Fatalf("events %d", n)
	}
}

func TestOAuthRevokeNothingStored(t *testing.T) {
	_, h, st, _, id := oauthServer(t, testPublicURL)
	rr, out := revoke(t, h, id)
	if rr.Code != http.StatusOK || out["vendor_revocation"] != revokeNoToken {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if n := len(eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthRevoke)); n != 0 {
		t.Fatalf("an empty row recorded %d events", n)
	}
}

// racingStore makes the first ConnectUpstreamAuth of a disconnect land after
// another writer moved the row, the way a writer that does not take the lock
// would.
type racingStore struct {
	store.Store
	first  sync.Once
	before func(st store.Store)
}

func (r *racingStore) ConnectUpstreamAuth(ctx context.Context, id string, next []byte, seen, at time.Time) error {
	r.first.Do(func() { r.before(r.Store) })
	return r.Store.ConnectUpstreamAuth(ctx, id, next, seen, at)
}

func TestOAuthRevokeRacingNameEditStillClears(t *testing.T) {
	var rs *racingStore
	s, h, st, _ := testAPIWrappedStore(t, testPublicURL, func(inner store.Store) store.Store {
		rs = &racingStore{Store: inner}
		return rs
	})
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	rs.before = func(inner store.Store) {
		u, _ := inner.GetUpstream(context.Background(), id)
		u.Name = "Renamed"
		u.UpdatedAt = time.Now().UTC().Add(time.Second)
		_ = inner.UpdateUpstream(context.Background(), u, store.KeepTest, store.KeepAuth)
	}
	rr, out := revoke(t, h, id)
	if rr.Code != http.StatusOK || out["vendor_revocation"] != revokedAtVendor || out["upstream"].(map[string]any)["auth_configured"] != false {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if n := len(eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthRevoke)); n != 1 {
		t.Fatalf("events %d", n)
	}
}

// Security requirement 12: a grant that landed after the vendor revoke is
// not cleared, because it was never revoked.
func TestOAuthRevokeRacingReconnectIs409(t *testing.T) {
	var rs *racingStore
	s, h, st, _ := testAPIWrappedStore(t, testPublicURL, func(inner store.Store) store.Store {
		rs = &racingStore{Store: inner}
		return rs
	})
	stub := oauthstub.New(t)
	id, _ := mustUpstream(t, h, "Vendor", map[string]any{"url": stub.MCPURL(), "auth_type": "oauth"})
	storeOAuthSet(t, s, st, id, connectedSet(stub, stub.MCPURL()))
	theirs := connectedSet(stub, stub.MCPURL())
	rs.before = func(inner store.Store) {
		u, _ := inner.GetUpstream(context.Background(), id)
		raw, _ := json.Marshal(theirs)
		enc, _ := s.keys.Seal(raw)
		_ = inner.ConnectUpstreamAuth(context.Background(), id, []byte(enc), u.UpdatedAt, time.Now().UTC().Add(time.Second))
	}
	rr, _ := revoke(t, h, id)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), errUpstreamChangedRevoke) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	stored, ok := storedOAuthSet(t, s, st, id)
	if !ok || stored.AccessToken != theirs.AccessToken {
		t.Fatalf("stored %+v ok=%v, want the newer grant untouched", stored, ok)
	}
	if n := len(eventsFor(adminEvents(t, st), models.ActionUpstreamOAuthRevoke)); n != 0 {
		t.Fatalf("events %d", n)
	}
}

// Security requirement 9: the three flows write their lines and nothing
// secret reaches the log or an admin_events row.
// An invalid PUBLIC_URL is refused with a fixed sentence before anything is
// dialled, and a forced client document on an http or loopback PUBLIC_URL
// likewise.
func TestOAuthStartRefusesInvalidPublicURLAndForcedDocumentOnHTTP(t *testing.T) {
	_, h, _, stub, id := oauthServer(t, "not-a-url")
	rr, _ := start(t, h, id, nil)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errPublicURLInvalid) {
		t.Fatalf("invalid PUBLIC_URL: %d %s", rr.Code, rr.Body.String())
	}
	if len(stub.Requests()) != 0 {
		t.Fatal("the stub was dialled")
	}
	_, h, _, stub, id = oauthServer(t, "http://localhost:8080")
	rr = doJSON(t, h, http.MethodPost, "http://localhost:8080/upstreams/"+id+"/oauth/start", "test-admin", map[string]string{"client": "document"})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), errDocumentNeedsHTTPS) {
		t.Fatalf("forced document on loopback: %d %s", rr.Code, rr.Body.String())
	}
	if len(stub.Requests()) != 0 {
		t.Fatal("the stub was dialled")
	}
}

// A callback that cannot take the per-upstream lock answers the busy page:
// the state is spent, nothing is stored, and the operator is told to press
// Connect again.
func TestOAuthCallbackBusyPage(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	saved := oauthLockWait
	oauthLockWait = 50 * time.Millisecond
	t.Cleanup(func() { oauthLockWait = saved })
	path := approve(t, stub, mustStart(t, h, id, nil))
	unlock, err := credential.LockUpstream(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	rr := callback(t, h, path)
	unlock()
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), pageBusy.Title) || !strings.Contains(rr.Body.String(), pageBusy.Body) {
		t.Fatalf("busy callback: %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := storedOAuthSet(t, s, st, id); ok {
		t.Fatal("a token set was stored")
	}
	if rr := callback(t, h, path); rr.Code != http.StatusBadRequest {
		t.Fatalf("the state survived the busy answer: %d", rr.Code)
	}
}

func TestOAuthLogsNothingSecret(t *testing.T) {
	s, h, st, stub, id := oauthServer(t, testPublicURL)
	stub.ErrorDescriptionMarker = "VENDOR_WORDS_MARKER"
	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, nil))
	// The Presenter holds the logger it was built with, as it does in the
	// binary; rebuild it on the buffer so the refresh line is captured too.
	s.present = credential.NewPresenter(s.keys, s.store, s.mcp, s.log)
	// A supplied client with a secret, so the secret is in play on every
	// path the test drives.
	stub.AllowClient("supplied-client", "CLIENT_SECRET_MARKER")
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{"auth_config": map[string]string{"client_id": "supplied-client", "client_secret": "CLIENT_SECRET_MARKER"}}); rr.Code != http.StatusOK {
		t.Fatalf("PATCH client: %d %s", rr.Code, rr.Body.String())
	}

	out := mustStart(t, h, id, nil)
	state := authQuery(t, out).Get("state")
	path := approve(t, stub, out)
	q, _ := url.ParseQuery(strings.TrimPrefix(path, "/oauth/callback?"))
	code := q.Get("code")
	if rr := callback(t, h, path); rr.Code != http.StatusOK {
		t.Fatalf("connect: %d %s", rr.Code, rr.Body.String())
	}
	set, _ := storedOAuthSet(t, s, st, id)
	// A refresh through Tools, and a failed callback, and a disconnect.
	lapsed := set
	lapsed.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	storeOAuthSet(t, s, st, id, lapsed)
	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("discovery %v", d)
	}
	renewed, _ := storedOAuthSet(t, s, st, id)
	// A transient refresh failure inside the window: the Warn fires, the
	// call still succeeds on the stored token.
	stub.RejectRefreshTransient = true
	soon := renewed
	soon.ExpiresAt = time.Now().Add(30 * time.Second).UTC()
	storeOAuthSet(t, s, st, id, soon)
	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("discovery inside the window %v", d)
	}
	stub.RejectRefreshTransient = false
	// A failed callback on a known state: the Warn fires and names the
	// allowlisted code only.
	second := mustStart(t, h, id, nil)
	state2 := authQuery(t, second).Get("state")
	if rr := callback(t, h, "/oauth/callback?state="+url.QueryEscape(state2)+"&error=access_denied&error_description=VENDOR_WORDS_MARKER"); rr.Code != http.StatusBadRequest {
		t.Fatalf("refused callback: %d", rr.Code)
	}
	knownWarns := strings.Count(logs.String(), "upstream oauth callback failed")
	if rr := callback(t, h, "/oauth/callback?state=junk&code=JUNK_CODE_MARKER"); rr.Code != http.StatusBadRequest {
		t.Fatalf("junk callback: %d", rr.Code)
	}
	if rr, _ := revoke(t, h, id); rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rr.Code)
	}

	all := logs.String() + serialiseEvents(t, adminEvents(t, st))
	for name, secret := range map[string]string{
		"access token": set.AccessToken, "refresh token": set.RefreshToken, "renewed access": renewed.AccessToken,
		"renewed refresh": renewed.RefreshToken, "code": code, "state": state, "second state": state2,
		"junk code": "JUNK_CODE_MARKER", "vendor words": "VENDOR_WORDS_MARKER", "auth_config key": "auth_config",
		"client secret": "CLIENT_SECRET_MARKER", "pkce verifier": stub.LastVerifier(),
	} {
		if secret == "" {
			t.Fatalf("%s fixture is empty", name)
		}
		if strings.Contains(all, secret) {
			t.Fatalf("%s reached the log or an event: %s", name, all)
		}
	}
	for _, line := range []string{"upstream oauth connected", "upstream oauth token refreshed", "upstream oauth refresh failed", `"reason":"vendor_error:access_denied"`, "upstream oauth disconnected", "upstream credential cleared"} {
		if !strings.Contains(logs.String(), line) {
			t.Errorf("log line %q missing:\n%s", line, logs.String())
		}
	}
	if knownWarns != 1 || strings.Count(logs.String(), "upstream oauth callback failed") != knownWarns {
		t.Fatalf("callback Warn lines: %d before the junk callback, %d after; want exactly one from the known state", knownWarns, strings.Count(logs.String(), "upstream oauth callback failed"))
	}
	events := adminEvents(t, st)
	for _, action := range []string{models.ActionUpstreamOAuthConnect, models.ActionUpstreamOAuthRefresh, models.ActionUpstreamOAuthRevoke} {
		if n := len(eventsFor(events, action)); n != 1 {
			t.Errorf("%s: %d events, want 1", action, n)
		}
	}
	// The connect and revoke carry the admin's address; the refresh through
	// Tools does too, with the admin actor.
	for _, e := range eventsFor(events, models.ActionUpstreamOAuthRefresh) {
		if e.Actor != models.ActorAdmin {
			t.Errorf("refresh actor %q", e.Actor)
		}
	}
}
