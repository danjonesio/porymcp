package mcpclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// The OAuth client (PORM-139). Everything here carries a code, a verifier, a
// refresh token or a client secret, which is why it lives in this package and
// goes out on the same no-redirect client as every other credential-carrying
// request. Every URL it dials is one the upstream or its authorization server
// chose, so every one passes oauthTarget first, every answer is read under
// oauthBodyBytes, and every error it returns is a fixed sentence: nothing an
// authorization server wrote reaches a log, an audit row or an operator's
// screen except an RFC 6749 error code from the closed set below.

// oauthBodyBytes caps a metadata, registration, token or revocation answer.
// The documents are a few hundred bytes; a token is at most 8 KiB.
const oauthBodyBytes = 64 << 10

// maxTokenBytes bounds an access or refresh token before it is sealed or put
// on a header. net/http would otherwise quote a bad value back in an error.
const maxTokenBytes = 8 << 10

// maxExpiresIn clamps a vendor's expires_in; a year-long token is a mistake
// PoryMCP should not remember.
const maxExpiresIn = 30 * 24 * time.Hour

// defaultExpiresIn is what a token answer without expires_in gets.
const defaultExpiresIn = time.Hour

// ProtectedResource is the RFC 9728 document an MCP server publishes.
type ProtectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	Scopes               []string `json:"scopes_supported"`
}

// AuthServer is what PoryMCP keeps of an RFC 8414 document: the issuer and
// the four endpoints, pinned at start and never re-fetched.
type AuthServer struct {
	Issuer                            string
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	RegistrationEndpoint              string
	RevocationEndpoint                string
	ClientIDMetadataDocumentSupported bool
	IssParameterSupported             bool
	TokenEndpointAuthMethods          []string
}

// The closed set of sentences this file can say. They are error values so a
// caller can map them to a status and a log stage without reading text.
var (
	ErrGrantRejected            = errors.New("authorization server refused the grant")
	ErrOAuthNoMetadata          = errors.New("authorization server metadata not found")
	ErrOAuthHostRule            = errors.New("authorization server host is not allowed")
	ErrOAuthRedirected          = errors.New("authorization server redirected")
	ErrOAuthUnreachable         = errors.New("authorization server could not be reached")
	ErrOAuthIssuerMismatch      = errors.New("authorization server metadata names another issuer")
	ErrOAuthResourceMismatch    = errors.New("resource metadata names another resource")
	ErrOAuthNoPKCE              = errors.New("authorization server does not support PKCE S256")
	ErrOAuthEndpointsOffIssuer  = errors.New("authorization server endpoints are not on the issuer's origin and it does not return iss")
	ErrOAuthRegistrationRefused = errors.New("authorization server refused the client registration")
	ErrOAuthTokenAnswer         = errors.New("authorization server answered the token request with something PoryMCP cannot use")
	ErrOAuthRevocationRefused   = errors.New("authorization server refused the revocation")
)

// OAuthError is one of the sentences above with what a log line may carry
// beside it: the stage, the HTTP status, the host (only when HostSafe) and an
// RFC 6749 error code from the closed set. Error() is the sentence alone.
type OAuthError struct {
	Stage  string // protected_resource | authorization_server | registration | host_rule | token | revocation
	Err    error
	Status int
	Host   string
	Code   string
}

func (e *OAuthError) Error() string { return e.Err.Error() }
func (e *OAuthError) Unwrap() error { return e.Err }

// oauthErrorCodes is the RFC 6749 §5.2 and RFC 8707 set a token answer may
// name. Anything else is reported as http_<status>.
var oauthErrorCodes = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true,
	"unauthorized_client": true, "unsupported_grant_type": true, "invalid_scope": true,
	"invalid_target": true, "server_error": true, "temporarily_unavailable": true,
}

// PKCEChallenge is the S256 transform of a verifier (RFC 7636). The verifier
// itself comes from auth.RandomToken(32); this package imports nothing but
// models, so it computes the challenge and does not mint the verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// oauthTarget gates every URL learned from an upstream or its authorization
// server: CheckTarget, a host this package will write down, and https unless
// the upstream itself is plain http (which keeps a local test server and a
// LAN upstream working). It returns the parsed URL the caller then dials.
func oauthTarget(raw string, upstream *url.URL) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || CheckTarget(u) != nil || !HostSafe(u.Host) {
		return nil, &OAuthError{Stage: "host_rule", Err: ErrOAuthHostRule}
	}
	if upstream.Scheme == "https" && u.Scheme != "https" {
		return nil, &OAuthError{Stage: "host_rule", Err: ErrOAuthHostRule, Host: bound(u.Host, MaxErrorBytes)}
	}
	return u, nil
}

var resourceMetadataParam = regexp.MustCompile(`resource_metadata="([^"]*)"`)

// FindAuthServer learns which authorization server protects upstreamURL and
// what it offers. It sends one unauthenticated initialize and reads the
// resource_metadata URL from the WWW-Authenticate challenge, falls back to
// the RFC 9728 well-known path inserted before the upstream's path and then
// to the origin root, and requires the document's resource to equal the URL
// it was fetched for (with the well-known suffix removed) and the upstream
// URL to be that URL or under it. It then reads the first listed issuer's
// RFC 8414 document (the well-known path inserted before the issuer's path,
// then openid-configuration), requires issuer to equal the URL it was fetched
// for, S256 to be advertised, and, when the server does not promise an iss
// parameter, both endpoints to sit on the issuer's origin: that is what stops
// a hostile upstream naming the real vendor's sign-in page beside its own
// token endpoint (RFC 9700 §4.4, mix-up).
func (c *Client) FindAuthServer(ctx context.Context, upstreamURL string) (ProtectedResource, AuthServer, error) {
	up, err := url.Parse(upstreamURL)
	if err != nil || CheckTarget(up) != nil {
		return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "host_rule", Err: ErrOAuthHostRule}
	}
	origin := up.Scheme + "://" + up.Host

	// Candidate resource metadata URLs, each with the resource it must name.
	type candidate struct{ url, resource string }
	var cands []candidate
	if challenge := c.challenge(ctx, up); challenge != "" {
		cands = append(cands, candidate{challenge, resourceFor(challenge, upstreamURL)})
	}
	if p := strings.TrimSuffix(up.Path, "/"); p != "" {
		cands = append(cands, candidate{origin + "/.well-known/oauth-protected-resource" + p, origin + p})
	}
	cands = append(cands, candidate{origin + "/.well-known/oauth-protected-resource", origin})

	var pr ProtectedResource
	found := false
	for _, cand := range cands {
		target, err := oauthTarget(cand.url, up)
		if err != nil {
			return ProtectedResource{}, AuthServer{}, err
		}
		var doc ProtectedResource
		status, err := c.getJSON(ctx, target, &doc)
		if err != nil {
			if isRedirect(err) {
				return ProtectedResource{}, AuthServer{}, err
			}
			continue
		}
		if status != http.StatusOK || len(doc.AuthorizationServers) == 0 {
			continue
		}
		if trimSlash(doc.Resource) != trimSlash(cand.resource) || !underResource(upstreamURL, cand.resource) {
			return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "protected_resource", Err: ErrOAuthResourceMismatch}
		}
		pr, found = doc, true
		break
	}
	if !found {
		return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "protected_resource", Err: ErrOAuthNoMetadata}
	}

	issuer := trimSlash(pr.AuthorizationServers[0])
	iu, err := oauthTarget(issuer, up)
	if err != nil {
		return ProtectedResource{}, AuthServer{}, err
	}
	if iu.RawQuery != "" || iu.Fragment != "" {
		return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "authorization_server", Err: ErrOAuthHostRule, Host: bound(iu.Host, MaxErrorBytes)}
	}
	issuerOrigin := iu.Scheme + "://" + iu.Host
	ipath := strings.TrimSuffix(iu.Path, "/")
	asCands := []string{issuerOrigin + "/.well-known/oauth-authorization-server" + ipath}
	if ipath != "" {
		asCands = append(asCands, issuer+"/.well-known/oauth-authorization-server")
	}
	asCands = append(asCands, issuerOrigin+"/.well-known/openid-configuration"+ipath)
	if ipath != "" {
		asCands = append(asCands, issuer+"/.well-known/openid-configuration")
	}

	var raw struct {
		Issuer                   string   `json:"issuer"`
		AuthorizationEndpoint    string   `json:"authorization_endpoint"`
		TokenEndpoint            string   `json:"token_endpoint"`
		RegistrationEndpoint     string   `json:"registration_endpoint"`
		RevocationEndpoint       string   `json:"revocation_endpoint"`
		CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
		CIMD                     bool     `json:"client_id_metadata_document_supported"`
		Iss                      bool     `json:"authorization_response_iss_parameter_supported"`
	}
	found = false
	for _, cand := range asCands {
		target, err := oauthTarget(cand, up)
		if err != nil {
			return ProtectedResource{}, AuthServer{}, err
		}
		status, err := c.getJSON(ctx, target, &raw)
		if err != nil {
			if isRedirect(err) {
				return ProtectedResource{}, AuthServer{}, err
			}
			continue
		}
		if status != http.StatusOK || raw.TokenEndpoint == "" || raw.AuthorizationEndpoint == "" {
			continue
		}
		found = true
		break
	}
	if !found {
		return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "authorization_server", Err: ErrOAuthNoMetadata, Host: bound(iu.Host, MaxErrorBytes)}
	}
	if trimSlash(raw.Issuer) != issuer {
		return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "authorization_server", Err: ErrOAuthIssuerMismatch, Host: bound(iu.Host, MaxErrorBytes)}
	}
	s256 := false
	for _, m := range raw.CodeChallengeMethods {
		if m == "S256" {
			s256 = true
		}
	}
	if !s256 {
		return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "authorization_server", Err: ErrOAuthNoPKCE, Host: bound(iu.Host, MaxErrorBytes)}
	}
	as := AuthServer{
		Issuer:                            issuer,
		ClientIDMetadataDocumentSupported: raw.CIMD,
		IssParameterSupported:             raw.Iss,
		TokenEndpointAuthMethods:          raw.TokenEndpointAuthMethods,
	}
	gate := func(field string, into *string) error {
		if field == "" {
			return nil
		}
		u, err := oauthTarget(field, up)
		if err != nil {
			return err
		}
		*into = u.String()
		return nil
	}
	for _, g := range []struct {
		raw  string
		into *string
	}{
		{raw.AuthorizationEndpoint, &as.AuthorizationEndpoint},
		{raw.TokenEndpoint, &as.TokenEndpoint},
		{raw.RegistrationEndpoint, &as.RegistrationEndpoint},
		{raw.RevocationEndpoint, &as.RevocationEndpoint},
	} {
		if err := gate(g.raw, g.into); err != nil {
			return ProtectedResource{}, AuthServer{}, err
		}
	}
	if !as.IssParameterSupported {
		for _, ep := range []string{as.AuthorizationEndpoint, as.TokenEndpoint} {
			eu, _ := url.Parse(ep)
			if eu.Scheme+"://"+eu.Host != issuerOrigin {
				return ProtectedResource{}, AuthServer{}, &OAuthError{Stage: "authorization_server", Err: ErrOAuthEndpointsOffIssuer, Host: bound(iu.Host, MaxErrorBytes)}
			}
		}
	}
	return pr, as, nil
}

// challenge sends one unauthenticated initialize and returns the
// resource_metadata URL from the WWW-Authenticate header, or "".
func (c *Client) challenge(ctx context.Context, up *url.URL) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.String(), strings.NewReader(initializeRequest))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", AcceptMCP)
	resp, err := Open(c.http, req)
	if err != nil {
		return ""
	}
	_, _, hdr, err := ReadBody(resp, oauthBodyBytes)
	if err != nil {
		return ""
	}
	for _, v := range hdr.Values("WWW-Authenticate") {
		if m := resourceMetadataParam.FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// resourceFor derives the resource a metadata document fetched from metaURL
// must name: the well-known suffix removed from its path, or the upstream URL
// when the path has no such suffix.
func resourceFor(metaURL, upstreamURL string) string {
	u, err := url.Parse(metaURL)
	if err != nil {
		return upstreamURL
	}
	const suffix = "/.well-known/oauth-protected-resource"
	if !strings.HasPrefix(u.Path, suffix) {
		return upstreamURL
	}
	return u.Scheme + "://" + u.Host + strings.TrimPrefix(u.Path, suffix)
}

func trimSlash(s string) string { return strings.TrimSuffix(s, "/") }

// underResource reports whether upstreamURL is resource or a path under it.
func underResource(upstreamURL, resource string) bool {
	r := trimSlash(resource)
	u := trimSlash(upstreamURL)
	return u == r || strings.HasPrefix(u, r+"/")
}

func isRedirect(err error) bool {
	var oe *OAuthError
	return errors.As(err, &oe) && errors.Is(oe.Err, ErrOAuthRedirected)
}

// getJSON fetches one metadata document. A 3xx is refused by Open and comes
// back as ErrOAuthRedirected; any other transport failure is unreachable.
func (c *Client) getJSON(ctx context.Context, target *url.URL, into any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, &OAuthError{Stage: "host_rule", Err: ErrOAuthHostRule}
	}
	req.Header.Set("Accept", "application/json")
	raw, status, _, err := Send(c.http, req, oauthBodyBytes)
	if err != nil {
		return 0, c.transport(err, target.Host)
	}
	if status != http.StatusOK {
		return status, nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return status, &OAuthError{Err: ErrOAuthNoMetadata, Host: bound(target.Host, MaxErrorBytes)}
	}
	return status, nil
}

// transport classifies a failure from Send into a sentence and a host and
// throws the error's own text away: a *url.Error quotes the whole URL.
func (c *Client) transport(err error, host string) error {
	h := ""
	if HostSafe(host) {
		h = bound(host, MaxErrorBytes)
	}
	var rd Redirect
	if errors.As(err, &rd) {
		return &OAuthError{Err: ErrOAuthRedirected, Host: h}
	}
	return &OAuthError{Err: ErrOAuthUnreachable, Host: h}
}

// AuthorizationURL builds the URL the operator's browser is sent to. It
// parses the endpoint and Sets every protocol parameter, so a query the
// vendor pre-filled on its endpoint (or a hostile one carrying its own
// redirect_uri) cannot win over PoryMCP's values.
func AuthorizationURL(as AuthServer, set models.OAuthTokenSet, redirectURI, state, challenge string) string {
	u, err := url.Parse(as.AuthorizationEndpoint)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", set.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", set.Resource)
	if set.Scope != "" {
		q.Set("scope", set.Scope)
	} else {
		q.Del("scope")
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String()
}

// Register performs RFC 7591 dynamic client registration with the fields the
// client metadata document carries and application_type web. It refuses an
// answer whose redirect_uris differ from what was sent, and returns whatever
// client_secret the server issued ("" for a public client).
func (c *Client) Register(ctx context.Context, as AuthServer, redirectURI string) (clientID, clientSecret string, err error) {
	if as.RegistrationEndpoint == "" {
		return "", "", &OAuthError{Stage: "registration", Err: ErrOAuthRegistrationRefused}
	}
	method := "none"
	for _, m := range as.TokenEndpointAuthMethods {
		if m == "client_secret_basic" {
			method = m
			break
		}
	}
	body, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{redirectURI},
		"client_name":                "PoryMCP",
		"application_type":           "web",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": method,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, as.RegistrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", "", &OAuthError{Stage: "registration", Err: ErrOAuthRegistrationRefused}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	host := req.URL.Host
	raw, status, _, err := Send(c.http, req, oauthBodyBytes)
	if err != nil {
		oe := c.transport(err, host).(*OAuthError)
		oe.Stage = "registration"
		return "", "", oe
	}
	var answer struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if status < 200 || status >= 300 || json.Unmarshal(raw, &answer) != nil || !visibleASCII(answer.ClientID, 1<<10) {
		return "", "", &OAuthError{Stage: "registration", Err: ErrOAuthRegistrationRefused, Status: status, Host: bound(host, MaxErrorBytes)}
	}
	if answer.ClientSecret != "" && !visibleASCII(answer.ClientSecret, 1<<10) {
		return "", "", &OAuthError{Stage: "registration", Err: ErrOAuthRegistrationRefused, Status: status, Host: bound(host, MaxErrorBytes)}
	}
	if len(answer.RedirectURIs) > 0 && (len(answer.RedirectURIs) != 1 || answer.RedirectURIs[0] != redirectURI) {
		return "", "", &OAuthError{Stage: "registration", Err: ErrOAuthRegistrationRefused, Status: status, Host: bound(host, MaxErrorBytes)}
	}
	return answer.ClientID, answer.ClientSecret, nil
}

// Exchange redeems an authorization code at the pinned token endpoint with
// the PKCE verifier and the resource indicator, and returns the set with the
// tokens, the expiry computed from now, and the endpoints and issuer copied
// from as so refresh and revoke never read metadata again.
func (c *Client) Exchange(ctx context.Context, as AuthServer, set models.OAuthTokenSet, code, verifier, redirectURI string, now time.Time) (models.OAuthTokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("resource", set.Resource)
	set.TokenEndpoint = as.TokenEndpoint
	set.RevocationEndpoint = as.RevocationEndpoint
	set.Issuer = as.Issuer
	answer, err := c.token(ctx, set, form)
	if err != nil {
		return models.OAuthTokenSet{}, err
	}
	return apply(set, answer, now), nil
}

// Refresh renews the set at its stored token endpoint. ErrGrantRejected
// (inside an OAuthError carrying the code) means the server refused the
// refresh token itself; any other failure is a transient the caller may
// retry. A refresh answer without a refresh_token keeps the old one (RFC
// 6749 §6).
func (c *Client) Refresh(ctx context.Context, set models.OAuthTokenSet, now time.Time) (models.OAuthTokenSet, error) {
	if set.RefreshToken == "" || set.TokenEndpoint == "" {
		return models.OAuthTokenSet{}, &OAuthError{Stage: "token", Err: ErrGrantRejected, Code: "invalid_grant"}
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", set.RefreshToken)
	if set.Resource != "" {
		form.Set("resource", set.Resource)
	}
	answer, err := c.token(ctx, set, form)
	if err != nil {
		return models.OAuthTokenSet{}, err
	}
	return apply(set, answer, now), nil
}

// Revoke tells the stored revocation endpoint to drop the refresh token, or
// the access token when there is no refresh token (RFC 7009). A 2xx is
// success; the answer body is never read.
func (c *Client) Revoke(ctx context.Context, set models.OAuthTokenSet) error {
	if set.RevocationEndpoint == "" {
		return &OAuthError{Stage: "revocation", Err: ErrOAuthRevocationRefused}
	}
	form := url.Values{}
	hint := "refresh_token"
	token := set.RefreshToken
	if token == "" {
		hint, token = "access_token", set.AccessToken
	}
	form.Set("token", token)
	form.Set("token_type_hint", hint)
	req, err := c.formRequest(ctx, set.RevocationEndpoint, set, form)
	if err != nil {
		return &OAuthError{Stage: "revocation", Err: ErrOAuthRevocationRefused}
	}
	host := req.URL.Host
	_, status, _, err := Send(c.http, req, oauthBodyBytes)
	if err != nil {
		oe := c.transport(err, host).(*OAuthError)
		oe.Stage = "revocation"
		return oe
	}
	if status < 200 || status >= 300 {
		return &OAuthError{Stage: "revocation", Err: ErrOAuthRevocationRefused, Status: status, Host: bound(host, MaxErrorBytes)}
	}
	return nil
}

// tokenAnswer is a token endpoint's answer, validated before anything is
// sealed: Bearer only, tokens visible ASCII and bounded, expires_in clamped.
type tokenAnswer struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
	Scope        string
}

// formRequest builds a form POST to endpoint with the client's
// authentication: client_secret_basic when the set holds a secret (both
// values form-encoded first, RFC 6749 §2.3.1), client_id in the form for a
// public client. The secret never goes in the URL.
func (c *Client) formRequest(ctx context.Context, endpoint string, set models.OAuthTokenSet, form url.Values) (*http.Request, error) {
	if set.ClientSecret == "" {
		form.Set("client_id", set.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if set.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(set.ClientID), url.QueryEscape(set.ClientSecret))
	}
	return req, nil
}

// token posts one grant and validates the answer. The error is always an
// *OAuthError: ErrGrantRejected with the code for invalid_grant and
// invalid_client, ErrOAuthTokenAnswer for anything else the server said,
// ErrOAuthUnreachable or ErrOAuthRedirected for transport.
func (c *Client) token(ctx context.Context, set models.OAuthTokenSet, form url.Values) (tokenAnswer, error) {
	req, err := c.formRequest(ctx, set.TokenEndpoint, set, form)
	if err != nil {
		return tokenAnswer{}, &OAuthError{Stage: "token", Err: ErrOAuthTokenAnswer}
	}
	host := req.URL.Host
	raw, status, _, err := Send(c.http, req, oauthBodyBytes)
	if err != nil {
		oe := c.transport(err, host).(*OAuthError)
		oe.Stage = "token"
		return tokenAnswer{}, oe
	}
	h := ""
	if HostSafe(host) {
		h = bound(host, MaxErrorBytes)
	}
	if status < 200 || status >= 300 {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &body)
		code := "http_" + fmt.Sprint(status)
		if oauthErrorCodes[body.Error] {
			code = body.Error
		}
		oe := &OAuthError{Stage: "token", Err: ErrOAuthTokenAnswer, Status: status, Host: h, Code: code}
		if (status == http.StatusBadRequest || status == http.StatusUnauthorized) && (code == "invalid_grant" || code == "invalid_client") {
			oe.Err = ErrGrantRejected
		}
		return tokenAnswer{}, oe
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    *int64 `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	bad := &OAuthError{Stage: "token", Err: ErrOAuthTokenAnswer, Status: status, Host: h}
	if err := json.Unmarshal(raw, &body); err != nil {
		return tokenAnswer{}, bad
	}
	if !strings.EqualFold(body.TokenType, "bearer") || !visibleASCII(body.AccessToken, maxTokenBytes) {
		return tokenAnswer{}, bad
	}
	if body.RefreshToken != "" && !visibleASCII(body.RefreshToken, maxTokenBytes) {
		return tokenAnswer{}, bad
	}
	out := tokenAnswer{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken, ExpiresIn: defaultExpiresIn}
	if body.ExpiresIn != nil {
		switch {
		case *body.ExpiresIn <= 0:
			out.ExpiresIn = 0
		case time.Duration(*body.ExpiresIn)*time.Second > maxExpiresIn:
			out.ExpiresIn = maxExpiresIn
		default:
			out.ExpiresIn = time.Duration(*body.ExpiresIn) * time.Second
		}
	}
	if scope, _ := Clamp(Scrub(body.Scope), 1<<10); scope != "" {
		out.Scope = scope
	}
	return out, nil
}

// apply writes a validated answer into the set.
func apply(set models.OAuthTokenSet, a tokenAnswer, now time.Time) models.OAuthTokenSet {
	set.AccessToken = a.AccessToken
	if a.RefreshToken != "" {
		set.RefreshToken = a.RefreshToken
	}
	set.ExpiresAt = now.UTC().Add(a.ExpiresIn)
	if a.Scope != "" {
		set.Scope = a.Scope
	}
	return set
}
