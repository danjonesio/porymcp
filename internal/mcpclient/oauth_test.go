package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"
	"github.com/danjonesio/porymcp/internal/models"
)

// The OAuth client tests (PORM-139 step 4). Every metadata, registration,
// token and revocation request goes through the no-redirect client; every
// URL an authorization server names passes the gate; every error is a fixed
// sentence.

func find(t *testing.T, s *oauthstub.Server) (ProtectedResource, AuthServer) {
	t.Helper()
	pr, as, err := New().FindAuthServer(context.Background(), s.MCPURL())
	if err != nil {
		t.Fatalf("FindAuthServer: %v", err)
	}
	return pr, as
}

func oauthErr(t *testing.T, err error, want error) *OAuthError {
	t.Helper()
	var oe *OAuthError
	if !errors.As(err, &oe) {
		t.Fatalf("err=%v (%T), want *OAuthError", err, err)
	}
	if !errors.Is(oe, want) {
		t.Fatalf("err=%v, want %v", oe, want)
	}
	return oe
}

func TestFindAuthServerFromChallenge(t *testing.T) {
	s := oauthstub.New(t)
	pr, as := find(t, s)
	if pr.Resource != s.MCPURL() || as.Issuer != s.Issuer() || as.TokenEndpoint != s.TokenEndpoint() || as.RevocationEndpoint != s.RevocationEndpoint() {
		t.Fatalf("pr=%+v as=%+v", pr, as)
	}
	if !as.ClientIDMetadataDocumentSupported || !as.IssParameterSupported || as.RegistrationEndpoint == "" {
		t.Fatalf("as=%+v", as)
	}
}

func TestFindAuthServerFallsBackToWellKnown(t *testing.T) {
	s := oauthstub.New(t)
	s.NoChallengeMetadata = true
	pr, _ := find(t, s)
	if pr.Resource != s.MCPURL() {
		t.Fatalf("resource %q", pr.Resource)
	}
}

func TestFindAuthServerRootMetadataOnly(t *testing.T) {
	s := oauthstub.New(t)
	s.RootMetadataOnly = true
	pr, _ := find(t, s)
	if pr.Resource != s.URL() {
		t.Fatalf("resource %q, want the origin", pr.Resource)
	}
}

// A custom server whose documents can be shaped per test: for the issuer and
// resource mismatch cases the stub is too well behaved.
func metadataServer(t *testing.T, resource func(origin string) string, issuer func(origin string) string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srv.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/mcp":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource(srv.URL), "authorization_servers": []string{srv.URL}})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer(srv.URL), "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
				"code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFindAuthServerRejectsIssuerMismatch(t *testing.T) {
	srv := metadataServer(t, func(o string) string { return o + "/mcp" }, func(o string) string { return "https://other.invalid" })
	_, _, err := New().FindAuthServer(context.Background(), srv.URL+"/mcp")
	oauthErr(t, err, ErrOAuthIssuerMismatch)
}

func TestFindAuthServerRejectsResourceMismatch(t *testing.T) {
	srv := metadataServer(t, func(o string) string { return o + "/other" }, func(o string) string { return o })
	_, _, err := New().FindAuthServer(context.Background(), srv.URL+"/mcp")
	oauthErr(t, err, ErrOAuthResourceMismatch)
}

func TestFindAuthServerRefusesEndpointsOffIssuerWithoutIss(t *testing.T) {
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	s := oauthstub.New(t)
	s.EndpointsOnOtherHost = other.URL
	s.NoIss = true
	_, _, err := New().FindAuthServer(context.Background(), s.MCPURL())
	oauthErr(t, err, ErrOAuthEndpointsOffIssuer)

	// With iss promised the same layout is allowed; the callback checks iss.
	s2 := oauthstub.New(t)
	s2.EndpointsOnOtherHost = other.URL
	_, as := find(t, s2)
	if !strings.HasPrefix(as.TokenEndpoint, other.URL) {
		t.Fatalf("token endpoint %q", as.TokenEndpoint)
	}
}

func TestFindAuthServerRefusesWithoutS256(t *testing.T) {
	s := oauthstub.New(t)
	s.NoS256 = true
	_, _, err := New().FindAuthServer(context.Background(), s.MCPURL())
	oauthErr(t, err, ErrOAuthNoPKCE)
}

// A resource_metadata URL the challenge names is gated before it is dialled:
// an ftp scheme or a fragment is refused and the recorder sees nothing.
func TestFindAuthServerGatesResourceMetadataURL(t *testing.T) {
	for _, meta := range []string{"ftp://meta.invalid/doc", "http://meta.invalid/doc#frag"} {
		var hits atomic.Int64
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/mcp" {
				hits.Add(1)
			}
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+meta+`"`)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		_, _, err := New().FindAuthServer(context.Background(), srv.URL+"/mcp")
		oauthErr(t, err, ErrOAuthHostRule)
		if hits.Load() != 0 {
			t.Errorf("%s: the server was dialled %d times beyond the challenge", meta, hits.Load())
		}
		srv.Close()
	}
}

// A metadata URL answering 302 is never followed: the second host is never
// dialled and the sentence names the refusal, not the Location.
func TestFindAuthServerRefusesRedirect(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srv.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.Redirect(w, r, target.URL+"/doc?code=REDIRECT_QUERY_MARKER", http.StatusFound)
		}
	}))
	defer srv.Close()
	_, _, err := New().FindAuthServer(context.Background(), srv.URL+"/mcp")
	oe := oauthErr(t, err, ErrOAuthRedirected)
	if strings.Contains(oe.Error(), "REDIRECT_QUERY_MARKER") || strings.Contains(oe.Host, "REDIRECT") {
		t.Fatalf("redirect leaked: %v %q", oe, oe.Host)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("redirect target was dialled %d times", targetHits.Load())
	}
}

func TestOAuthTargetHTTPSRule(t *testing.T) {
	https, _ := url.Parse("https://mcp.example/mcp")
	http_, _ := url.Parse("http://127.0.0.1:1/mcp")
	for _, tc := range []struct {
		raw      string
		upstream *url.URL
		ok       bool
	}{
		{"https://as.example/token", https, true},
		{"http://as.example/token", https, false},
		{"http://127.0.0.1:1/token", http_, true},
		{"https://as.example/token#x", https, false},
		{"ftp://as.example/token", https, false},
		{"https://as.exämple/token", https, false},
	} {
		_, err := oauthTarget(tc.raw, tc.upstream)
		if (err == nil) != tc.ok {
			t.Errorf("%s under %s: err=%v, want ok=%v", tc.raw, tc.upstream, err, tc.ok)
		}
	}
	// The gate runs in FindAuthServer, where endpoints are learned and
	// pinned; Exchange, Refresh and Revoke dial only what it returned. An
	// https upstream whose metadata names an http token endpoint is refused
	// there and the transport never sees the endpoint.
	ct := &countingTransport{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL + "/mcp", "authorization_servers": []string{srv.URL}})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/a", "token_endpoint": "https://as.example/token", "code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	// srv is plain http, so an https token endpoint passes the scheme rule and
	// the mixed layout is what FindAuthServer must still pin; the point here
	// is only that nothing outside FindAuthServer re-derives an endpoint.
	_, as, err := New().FindAuthServer(context.Background(), srv.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if as.TokenEndpoint != "https://as.example/token" {
		t.Fatalf("token endpoint %q", as.TokenEndpoint)
	}
	if _, err := clientWith(ct).Refresh(context.Background(), models.OAuthTokenSet{TokenEndpoint: as.TokenEndpoint, RefreshToken: "r"}, time.Now()); err == nil || ct.count() != 1 {
		t.Fatalf("refresh dialled %d times, err=%v", ct.count(), err)
	}
}

func TestAuthorizationURLCarriesPKCEStateResource(t *testing.T) {
	as := AuthServer{AuthorizationEndpoint: "https://as.example/authorize"}
	set := models.OAuthTokenSet{ClientID: "cid", Resource: "https://mcp.example/mcp", Scope: "mcp"}
	u, err := url.Parse(AuthorizationURL(as, set, "https://pory.test/api/v1/oauth/callback", "STATE", "CHAL"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "cid", "redirect_uri": "https://pory.test/api/v1/oauth/callback",
		"state": "STATE", "code_challenge": "CHAL", "code_challenge_method": "S256", "resource": "https://mcp.example/mcp", "scope": "mcp",
	} {
		if q.Get(k) != want {
			t.Errorf("%s=%q, want %q", k, q.Get(k), want)
		}
	}
}

func TestAuthorizationURLOverwritesPrefilledQuery(t *testing.T) {
	as := AuthServer{AuthorizationEndpoint: "https://as.example/authorize?redirect_uri=https://evil.invalid&state=x&tenant=t1"}
	u, _ := url.Parse(AuthorizationURL(as, models.OAuthTokenSet{ClientID: "cid", Resource: "r"}, "https://pory.test/cb", "S", "C"))
	q := u.Query()
	if len(q["redirect_uri"]) != 1 || q.Get("redirect_uri") != "https://pory.test/cb" || len(q["state"]) != 1 || q.Get("state") != "S" || q.Get("tenant") != "t1" {
		t.Fatalf("query %v", q)
	}
}

func TestRegisterSendsApplicationTypeWeb(t *testing.T) {
	var got map[string]any
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "reg-1", "client_secret": "s", "redirect_uris": got["redirect_uris"]})
	}))
	defer srv.Close()
	id, secret, err := New().Register(context.Background(), AuthServer{RegistrationEndpoint: srv.URL + "/register", TokenEndpointAuthMethods: []string{"client_secret_basic"}}, "http://pory.test/cb")
	if err != nil || id != "reg-1" || secret != "s" {
		t.Fatalf("id=%q secret=%q err=%v", id, secret, err)
	}
	if got["application_type"] != "web" || got["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("sent %v", got)
	}
}

func TestRegisterRefusesChangedRedirectURIs(t *testing.T) {
	s := oauthstub.New(t)
	s.RegisterChangesRedirect = true
	_, as := find(t, s)
	_, _, err := New().Register(context.Background(), as, "http://pory.test/cb")
	oauthErr(t, err, ErrOAuthRegistrationRefused)
}

// approve runs a full code flow against the stub for the client in set and
// returns the code the stub minted plus the verifier.
func approve(t *testing.T, s *oauthstub.Server, as AuthServer, set models.OAuthTokenSet) (code, verifier string) {
	t.Helper()
	verifier = "verifier-verifier-verifier-verifier-verifier-1"
	rd, err := s.Approve(AuthorizationURL(as, set, "http://pory.test/cb", "st", PKCEChallenge(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	return rd.Code, verifier
}

func TestExchangeSendsVerifierAndResource(t *testing.T) {
	s := oauthstub.New(t)
	s.AllowClient("cid", "sec")
	_, as := find(t, s)
	set := models.OAuthTokenSet{ClientID: "cid", ClientSecret: "sec", Resource: s.MCPURL()}
	code, verifier := approve(t, s, as, set)
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	got, err := New().Exchange(context.Background(), as, set, code, verifier, "http://pory.test/cb", now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AccessValid(got.AccessToken) || !s.RefreshValid(got.RefreshToken) || got.ExpiresAt != now.Add(time.Hour) {
		t.Fatalf("set %+v", got)
	}
	if got.TokenEndpoint != s.TokenEndpoint() || got.RevocationEndpoint != s.RevocationEndpoint() || got.Issuer != s.Issuer() || got.ClientSecret != "sec" {
		t.Fatalf("set %+v", got)
	}
	// The stub checked the verifier, the redirect_uri and the resource; a
	// wrong verifier is refused as a rejected grant.
	code2, _ := approve(t, s, as, set)
	_, err = New().Exchange(context.Background(), as, set, code2, "wrong", "http://pory.test/cb", now)
	oauthErr(t, err, ErrGrantRejected)
}

func TestExchangeDefaultsExpiryToOneHour(t *testing.T) {
	s := oauthstub.New(t)
	s.OmitExpiresIn = true
	s.AllowClient("cid", "")
	_, as := find(t, s)
	set := models.OAuthTokenSet{ClientID: "cid", Resource: s.MCPURL()}
	code, verifier := approve(t, s, as, set)
	now := time.Now()
	got, err := New().Exchange(context.Background(), as, set, code, verifier, "http://pory.test/cb", now)
	if err != nil || got.ExpiresAt != now.UTC().Add(time.Hour) {
		t.Fatalf("expires_at %v err %v", got.ExpiresAt, err)
	}
}

func TestExchangeRefusesNonBearer(t *testing.T) {
	s := oauthstub.New(t)
	s.TokenType = "DPoP"
	s.AllowClient("cid", "")
	_, as := find(t, s)
	set := models.OAuthTokenSet{ClientID: "cid", Resource: s.MCPURL()}
	code, verifier := approve(t, s, as, set)
	_, err := New().Exchange(context.Background(), as, set, code, verifier, "http://pory.test/cb", time.Now())
	oauthErr(t, err, ErrOAuthTokenAnswer)
}

func TestExchangeBoundsTokenLength(t *testing.T) {
	s := oauthstub.New(t)
	s.AccessTokenBytes = maxTokenBytes + 1
	s.AllowClient("cid", "")
	_, as := find(t, s)
	set := models.OAuthTokenSet{ClientID: "cid", Resource: s.MCPURL()}
	code, verifier := approve(t, s, as, set)
	_, err := New().Exchange(context.Background(), as, set, code, verifier, "http://pory.test/cb", time.Now())
	oauthErr(t, err, ErrOAuthTokenAnswer)
}

func TestExchangePublicClientSendsNoAuth(t *testing.T) {
	var sawBasic bool
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, sawBasic = r.BasicAuth()
		_ = r.ParseForm()
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "bearer", "expires_in": 60})
	}))
	defer srv.Close()
	as := AuthServer{TokenEndpoint: srv.URL + "/token"}
	got, err := New().Exchange(context.Background(), as, models.OAuthTokenSet{ClientID: "pub", Resource: "http://r"}, "c", "v", "http://pory.test/cb", time.Now())
	if err != nil || sawBasic || form.Get("client_id") != "pub" || form.Get("code_verifier") != "v" || form.Get("resource") != "http://r" || got.AccessToken != "a" {
		t.Fatalf("basic=%v form=%v got=%+v err=%v", sawBasic, form, got, err)
	}
}

func seeded(t *testing.T, s *oauthstub.Server) models.OAuthTokenSet {
	t.Helper()
	access, refresh := s.Seed()
	return models.OAuthTokenSet{
		AccessToken: access, RefreshToken: refresh, ExpiresAt: time.Now().Add(-time.Minute),
		TokenEndpoint: s.TokenEndpoint(), RevocationEndpoint: s.RevocationEndpoint(), Issuer: s.Issuer(),
		ClientID: "cid", ClientSource: "supplied", Resource: s.MCPURL(),
	}
}

func TestRefreshRejectedIsErrGrantRejected(t *testing.T) {
	s := oauthstub.New(t)
	s.RejectRefresh = true
	_, err := New().Refresh(context.Background(), seeded(t, s), time.Now())
	oe := oauthErr(t, err, ErrGrantRejected)
	if oe.Code != "invalid_grant" || oe.Status != http.StatusBadRequest {
		t.Fatalf("code=%q status=%d", oe.Code, oe.Status)
	}
	// A transient answer is not a rejection.
	s2 := oauthstub.New(t)
	s2.RejectRefreshTransient = true
	_, err = New().Refresh(context.Background(), seeded(t, s2), time.Now())
	oe = oauthErr(t, err, ErrOAuthTokenAnswer)
	if oe.Code != "http_503" {
		t.Fatalf("code=%q", oe.Code)
	}
}

func TestRefreshKeepsOldRefreshTokenWhenAbsent(t *testing.T) {
	s := oauthstub.New(t)
	set := seeded(t, s)
	s.NoRefreshToken = true
	got, err := New().Refresh(context.Background(), set, time.Now())
	if err != nil || got.RefreshToken != set.RefreshToken || got.AccessToken == set.AccessToken {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	// And a normal refresh rotates it.
	s2 := oauthstub.New(t)
	set2 := seeded(t, s2)
	got2, err := New().Refresh(context.Background(), set2, time.Now())
	if err != nil || got2.RefreshToken == set2.RefreshToken || !s2.RefreshValid(got2.RefreshToken) || s2.RefreshValid(set2.RefreshToken) {
		t.Fatalf("got=%+v err=%v", got2, err)
	}
}

func TestRefreshErrorsQuoteNoBody(t *testing.T) {
	s := oauthstub.New(t)
	s.RejectRefresh = true
	s.ErrorDescriptionMarker = "VENDOR_WORDS_MARKER"
	set := seeded(t, s)
	_, err := New().Refresh(context.Background(), set, time.Now())
	oe := oauthErr(t, err, ErrGrantRejected)
	for _, needle := range []string{"VENDOR_WORDS_MARKER", set.RefreshToken, set.AccessToken} {
		if strings.Contains(oe.Error(), needle) || strings.Contains(oe.Host, needle) || strings.Contains(oe.Code, needle) {
			t.Fatalf("%q reached the error: %v %q %q", needle, oe, oe.Host, oe.Code)
		}
	}
}

func TestRevokeCallsEndpoint(t *testing.T) {
	s := oauthstub.New(t)
	set := seeded(t, s)
	if err := New().Revoke(context.Background(), set); err != nil || s.Revocations() != 1 {
		t.Fatalf("err=%v revocations=%d", err, s.Revocations())
	}
	set.RevocationEndpoint = ""
	if err := New().Revoke(context.Background(), set); err == nil {
		t.Fatal("revoke with no endpoint succeeded")
	}
}

func TestClientSecretNeverInURL(t *testing.T) {
	var seen *http.Request
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		user, pass, _ = r.BasicAuth()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer"})
	}))
	defer srv.Close()
	set := models.OAuthTokenSet{ClientID: "id with space", ClientSecret: "s&cret", TokenEndpoint: srv.URL + "/token", RefreshToken: "r"}
	if _, err := New().Refresh(context.Background(), set, time.Now()); err != nil {
		t.Fatal(err)
	}
	if seen.URL.RawQuery != "" {
		t.Fatalf("query %q", seen.URL.RawQuery)
	}
	if user != url.QueryEscape("id with space") || pass != url.QueryEscape("s&cret") {
		t.Fatalf("basic %q %q", user, pass)
	}
}
