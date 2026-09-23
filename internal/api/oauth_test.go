package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
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
