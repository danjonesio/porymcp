package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
	"github.com/go-chi/chi/v5"
)

// The OAuth routes (PORM-139). An operator connects an oauth upstream in
// three steps: POST /upstreams/{id}/oauth/start learns the authorization
// server, chooses a client identity and answers the URL the browser is sent
// to; the vendor sends the browser back to GET /oauth/callback, the one
// unauthenticated write route, which redeems the code and seals the token
// set; POST /upstreams/{id}/oauth/revoke disconnects. GET
// /oauth/client-metadata is the Client ID Metadata Document a vendor fetches
// when PoryMCP identifies itself by URL. Every URL PoryMCP dials in the flow
// was gated and pinned by mcpclient.FindAuthServer at start; the callback
// never reads metadata.

const (
	// oauthFlowTTL is how long a started sign-in stays redeemable.
	oauthFlowTTL = 10 * time.Minute
	// oauthFlowCap bounds the pending map: one process, one operator.
	oauthFlowCap = 64
	// oauthExchangeBudget bounds the code exchange and the vendor revoke,
	// the same bound the refresh path uses.
	oauthExchangeBudget = 8 * time.Second
	// oauthWriteBudget bounds the store write after the vendor answered.
	oauthWriteBudget = 2 * time.Second
	// oauthStartBudget bounds the whole of start's vendor work: the metadata
	// walk and a registration together, so one slow document cannot hold a
	// discovery slot for the sum of the client's per-call backstops.
	oauthStartBudget = 10 * time.Second
	// callbackFailRPM is the per-address budget for callbacks. Every hit
	// counts, redeemed or not, and it is separate from adminFails so a scan
	// of the public route cannot lock the admin out. Ten a minute is far
	// above what one operator's sign-ins need.
	callbackFailRPM = 10
	// oauthHostBytes bounds the request host quoted in one message.
	oauthHostBytes = 256
)

// The fixed sentences the start route answers with.
const (
	errNotOAuthRow          = "upstream auth_type is not oauth"
	errPublicURLScheme      = "PUBLIC_URL must be an https address to connect an OAuth upstream"
	errPublicURLInvalid     = "PUBLIC_URL is not a valid URL; set it to the address the browser uses"
	errNoClientIdentity     = "the authorization server offers no way to register PoryMCP; enter a client ID"
	errClientOtherIssuer    = "the stored client ID belongs to another authorization server; enter it again"
	errClientChoice         = "client must be document or registered"
	errDocumentNotSupported = "the authorization server does not accept a client metadata document; use registered or enter a client ID"
	errDocumentNeedsHTTPS   = "a client metadata document needs an https PUBLIC_URL the vendor can fetch; use registered or enter a client ID"
	errTooManyFlows         = "too many pending sign-ins; wait for one to expire"
)

// oauthFlow is one started sign-in, held in memory until its callback or
// its expiry. The verifier lives here and nowhere else. The endpoints are
// pinned at start so the callback exchanges the code with the server the
// operator was shown, whatever metadata says by then.
type oauthFlow struct {
	upstreamID string
	// seen is the row's updated_at at start; the callback write is a
	// compare-and-swap on it, so an edit during the sign-in stores nothing.
	seen     time.Time
	verifier string
	as       mcpclient.AuthServer
	// set holds the client identity and the resource; the callback adds the
	// tokens.
	set     models.OAuthTokenSet
	expires time.Time
}

// oauthFlows is the pending map: keyed by the SHA-256 of the state so the
// process never holds a comparable raw value, one flow per upstream, pruned
// on every insert, bounded, on an injectable clock.
type oauthFlows struct {
	mu         sync.Mutex
	byState    map[[32]byte]oauthFlow
	byUpstream map[string][32]byte
	now        func() time.Time
}

func newOAuthFlows() *oauthFlows {
	return &oauthFlows{byState: map[[32]byte]oauthFlow{}, byUpstream: map[string][32]byte{}, now: time.Now}
}

// SetClock replaces the time source. Pass nil to restore time.Now.
func (f *oauthFlows) SetClock(now func() time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now == nil {
		f.now = time.Now
		return
	}
	f.now = now
}

func stateKey(state string) [32]byte { return sha256.Sum256([]byte(state)) }

// put stores a flow under state. An earlier flow for the same upstream is
// replaced; expired flows are pruned first; false means the cap is reached.
func (f *oauthFlows) put(state string, fl oauthFlow) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for k, v := range f.byState {
		if !v.expires.After(now) {
			delete(f.byState, k)
			if f.byUpstream[v.upstreamID] == k {
				delete(f.byUpstream, v.upstreamID)
			}
		}
	}
	if old, ok := f.byUpstream[fl.upstreamID]; ok {
		delete(f.byState, old)
		delete(f.byUpstream, fl.upstreamID)
	}
	if len(f.byState) >= oauthFlowCap {
		return false
	}
	k := stateKey(state)
	f.byState[k] = fl
	f.byUpstream[fl.upstreamID] = k
	return true
}

// take removes and returns the flow for state. It is single use by
// construction: a second take of the same state finds nothing, and so does a
// take after the expiry.
func (f *oauthFlows) take(state string) (oauthFlow, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := stateKey(state)
	fl, ok := f.byState[k]
	if !ok {
		return oauthFlow{}, false
	}
	delete(f.byState, k)
	if f.byUpstream[fl.upstreamID] == k {
		delete(f.byUpstream, fl.upstreamID)
	}
	if !fl.expires.After(f.now()) {
		return oauthFlow{}, false
	}
	return fl, true
}

// drop forgets the pending flow of one upstream: a PATCH that changed its
// URL, type or client made the flow's resource or client stale.
func (f *oauthFlows) drop(upstreamID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k, ok := f.byUpstream[upstreamID]; ok {
		delete(f.byState, k)
		delete(f.byUpstream, upstreamID)
	}
}

// redirectURI and clientMetadataURL are built from PUBLIC_URL alone, by
// concatenation as proxyURL does, and never from the request's Host: the
// Host check covers the proxy endpoints only, and a vendor compares redirect
// URIs byte for byte.
func (s *Server) redirectURI() string       { return s.cfg.PublicURL + "/api/v1/oauth/callback" }
func (s *Server) clientMetadataURL() string { return s.cfg.PublicURL + "/api/v1/oauth/client-metadata" }

// clientMetadata serves the Client ID Metadata Document: PoryMCP's client id
// is this document's own URL. It carries nothing about the deployment beyond
// PUBLIC_URL, and a short public cache life so a PUBLIC_URL change is not
// kept alive by a vendor's cache.
func (s *Server) clientMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"client_id":                  s.clientMetadataURL(),
		"client_name":                "PoryMCP",
		"redirect_uris":              []string{s.redirectURI()},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"application_type":           "web",
	})
}

// publicURLUsable decides whether PUBLIC_URL can be a redirect URI. https
// always; http only on a loopback host (the default laptop install, which
// OAuth 2.1 allows) or with ALLOW_INSECURE_HTTP. A loopback PUBLIC_URL
// reached from a non-loopback address is refused with both values, a
// usability guard for the operator who never set PUBLIC_URL on a remote
// host: the vendor would send their browser back to their own machine. The
// request host is caller text and is cleaned before it enters the sentence.
func (s *Server) publicURLUsable(r *http.Request) (loopback bool, msg string) {
	pu, err := url.Parse(s.cfg.PublicURL)
	if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
		return false, errPublicURLInvalid
	}
	loopback = loopbackHost(pu.Hostname())
	if pu.Scheme == "http" && !loopback && !s.cfg.AllowInsecureHTTP {
		return false, errPublicURLScheme
	}
	if loopback {
		host := webutil.RequestHost(r, s.cfg.TrustedProxies)
		h := host
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		h = strings.Trim(h, "[]")
		if host != "" && !loopbackHost(h) {
			shown := "another address"
			if mcpclient.HostSafe(host) {
				shown, _ = mcpclient.Clamp(host, oauthHostBytes)
			}
			return true, "PUBLIC_URL is " + s.cfg.PublicURL + " but this request was sent to " + shown + "; set PUBLIC_URL to the address the browser uses"
		}
	}
	return loopback, ""
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// oauthStartBody is the optional body of the start route: a forced client
// source for a deployment the vendor cannot fetch the document from.
type oauthStartBody struct {
	Client string `json:"client"`
}

// oauthStart learns the authorization server, chooses the client identity,
// records the flow and answers the authorization URL. It spends the
// discovery budgets, because it reaches a third party the same way. It
// records nothing: the connect event is written by the callback.
func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	if !s.allowDiscovery(w) {
		return
	}
	var in oauthStartBody
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<10))
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &in); err != nil || (in.Client != "" && in.Client != "document" && in.Client != "registered") {
			writeError(w, http.StatusBadRequest, errClientChoice)
			return
		}
	}
	u, err := s.store.GetUpstream(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	if u.AuthType != models.AuthOAuth {
		writeError(w, http.StatusBadRequest, errNotOAuthRow)
		return
	}
	if u.Kind == models.KindHTTP {
		// Unreachable through the API, which refuses oauth on an HTTP API row
		// at create and PATCH; kept so a hand-edited row cannot start a flow
		// that POSTs an MCP initialize to a REST API (PORM-146).
		writeError(w, http.StatusBadRequest, errOAuthOnHTTP)
		return
	}
	loopback, msg := s.publicURLUsable(r)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	https := strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "https://")
	if in.Client == "document" && (!https || loopback) {
		// The vendor would fetch the document from an address it cannot
		// reach; refused before anything is dialled.
		writeError(w, http.StatusBadRequest, errDocumentNeedsHTTPS)
		return
	}
	select {
	case s.discovering <- struct{}{}:
		defer func() { <-s.discovering }()
	default:
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too many concurrent discoveries")
		return
	}

	sctx, scancel := context.WithTimeout(r.Context(), oauthStartBudget)
	defer scancel()
	pr, as, err := s.mcp.FindAuthServer(sctx, u.URL)
	if err != nil {
		s.oauthStartFailed(w, u, err)
		return
	}
	issuerHost := ""
	if iu, perr := url.Parse(as.Issuer); perr == nil {
		issuerHost = iu.Host
	}

	// The stored blob, if any: a supplied client, a registration from an
	// earlier connect, or a live set being reconnected.
	var stored models.OAuthTokenSet
	if len(u.AuthConfig) > 0 {
		if plain, _, oerr := s.keys.Open(string(u.AuthConfig)); oerr == nil {
			_ = json.Unmarshal(plain, &stored)
		}
	}
	redirect := s.redirectURI()
	set := models.OAuthTokenSet{Resource: u.URL, Scope: strings.Join(pr.Scopes, " ")}
	switch {
	case stored.ClientSource == "supplied" && stored.ClientID != "":
		if stored.ClientIssuer != "" && stored.ClientIssuer != as.Issuer {
			writeError(w, http.StatusBadRequest, errClientOtherIssuer)
			return
		}
		set.ClientID, set.ClientSecret, set.ClientSource, set.ClientIssuer = stored.ClientID, stored.ClientSecret, "supplied", as.Issuer
	case stored.ClientSource == "registered" && stored.ClientIssuer == as.Issuer && stored.ClientRedirectURI == redirect && in.Client != "document":
		set.ClientID, set.ClientSecret, set.ClientSource, set.ClientIssuer, set.ClientRedirectURI = stored.ClientID, stored.ClientSecret, "registered", as.Issuer, redirect
	case in.Client == "document" && !as.ClientIDMetadataDocumentSupported:
		writeError(w, http.StatusBadRequest, errDocumentNotSupported)
		return
	case in.Client != "registered" && as.ClientIDMetadataDocumentSupported && https && !loopback:
		set.ClientID, set.ClientSource, set.ClientIssuer = s.clientMetadataURL(), "document", as.Issuer
	case as.RegistrationEndpoint != "":
		id, secret, rerr := s.mcp.Register(sctx, as, redirect)
		if rerr != nil {
			s.oauthStartFailed(w, u, rerr)
			return
		}
		set.ClientID, set.ClientSecret, set.ClientSource, set.ClientIssuer, set.ClientRedirectURI = id, secret, "registered", as.Issuer, redirect
	default:
		writeError(w, http.StatusBadRequest, errNoClientIdentity)
		return
	}

	state := auth.RandomToken(32)
	verifier := auth.RandomToken(32)
	now := s.flows.now()
	if !s.flows.put(state, oauthFlow{
		upstreamID: u.ID, seen: u.UpdatedAt, verifier: verifier, as: as, set: set, expires: now.Add(oauthFlowTTL),
	}) {
		tooManyRequests(w, time.Minute, errTooManyFlows)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"authorization_url": mcpclient.AuthorizationURL(as, set, redirect, state, mcpclient.PKCEChallenge(verifier)),
		"expires_in":        int(oauthFlowTTL / time.Second),
		"issuer":            issuerHost,
		"client":            set.ClientSource,
	})
}

// oauthStartFailed answers a metadata, host-rule, redirect or registration
// failure: the fixed sentence to the caller, and one Warn line with the
// stage, the status and the host, so the operator has something to
// diagnose from. Never a byte of what the server sent.
func (s *Server) oauthStartFailed(w http.ResponseWriter, u *models.Upstream, err error) {
	var oe *mcpclient.OAuthError
	stage, status, host := "", 0, ""
	if errors.As(err, &oe) {
		stage, status, host = oe.Stage, oe.Status, oe.Host
	}
	s.log.Warn("upstream oauth start failed", "upstream_id", u.ID, "stage", stage, "status", status, "host", host, "reason", err.Error())
	writeError(w, http.StatusBadGateway, err.Error())
}

// The callback (10b). The one unauthenticated write route: everything binds
// to the state, which is single use, ten minutes old at most, and keyed by
// its hash. The answer is always a fixed HTML page, because a browser lands
// here: no script (the CSP hashes only the dashboard's own), no <style>
// (style attributes only, which the CSP allows), no form, and nothing from
// the query ever enters the page: not the code, not the state, not the iss,
// and never error_description. The upstream's name is the one variable and
// html/template escapes it.

// callbackPage is what the template renders.
type callbackPage struct {
	Title   string
	Body    string
	Refresh bool
}

var callbackTemplate = template.Must(template.New("callback").Parse(`<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
{{if .Refresh}}<meta http-equiv="refresh" content="0; url=/upstreams/">
{{end}}<title>PoryMCP</title>
</head>
<body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5">
<h1 style="font-size: 1.5rem">{{.Title}}</h1>
<p>{{.Body}}</p>
<p><a href="/upstreams/">Open the Upstreams page</a></p>
</body>
</html>
`))

// The fixed pages. A page never says "tab": the flow runs in the browser's
// current tab and comes back to the dashboard.
var (
	pageConnected = callbackPage{Title: "Upstream connected", Refresh: true}
	pageState     = callbackPage{Title: "This sign-in link has expired or was already used", Body: "Open the Upstreams page to see whether the upstream is connected."}
	pageRefused   = callbackPage{Title: "The vendor did not connect this upstream", Body: "The authorization server refused the request. Nothing was stored. Press Connect to try again."}
	pageExchange  = callbackPage{Title: "The upstream could not be connected", Body: "The authorization server did not accept the sign-in. Nothing was stored. The server log has the reason. Press Connect to try again."}
	pageChanged   = callbackPage{Title: "This upstream changed during sign-in", Body: "It was deleted, or its URL or auth type changed. Nothing was stored."}
	pageBudget    = callbackPage{Title: "Too many failed sign-in attempts", Body: "Wait a minute, then reload this page."}
	pageBusy      = callbackPage{Title: "This upstream was busy", Body: "PoryMCP was renewing the token for this upstream. Nothing was stored. Press Connect to try again."}
)

// oauthLockWait is how long the callback waits for the per-upstream lock.
// A variable so a test can shorten it.
var oauthLockWait = 12 * time.Second

// vendorErrorCodes is RFC 6749 §4.1.2.1: the only error values a page may
// name. Anything else prints the fixed refusal.
var vendorErrorCodes = map[string]bool{
	"access_denied": true, "invalid_request": true, "unauthorized_client": true, "unsupported_response_type": true,
	"invalid_scope": true, "server_error": true, "temporarily_unavailable": true,
}

func writeCallbackPage(w http.ResponseWriter, status int, p callbackPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = callbackTemplate.Execute(w, p)
}

// oauthCallback redeems a sign-in. In order: the per-address budget (before
// the state is touched, so an over-budget reload keeps its state); the state,
// taken and deleted under the mutex; a vendor error; the iss check, before
// any exchange, so a mix-up never sends the code anywhere; the row, which
// must be the row the flow started against; the exchange, on its own
// context so a browser that goes away cannot abandon a redeemed code; the
// write, under the per-upstream lock and conditioned on updated_at; the
// event; the page.
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	ip := webutil.ClientIP(r, s.cfg.TrustedProxies)
	if ok, retry := s.callbackFails.Consume(ip, callbackFailRPM); !ok {
		sec := int(retry.Seconds())
		if sec < 1 {
			sec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		writeCallbackPage(w, http.StatusTooManyRequests, pageBudget)
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		writeCallbackPage(w, http.StatusBadRequest, pageState)
		return
	}
	flow, ok := s.flows.take(state)
	if !ok {
		writeCallbackPage(w, http.StatusBadRequest, pageState)
		return
	}
	warn := func(reason string) {
		s.log.Warn("upstream oauth callback failed", "upstream_id", flow.upstreamID, "reason", reason)
	}
	if code := q.Get("error"); code != "" {
		page := pageRefused
		if vendorErrorCodes[code] {
			page.Body = "The authorization server answered " + code + ". Nothing was stored. Press Connect to try again."
			warn("vendor_error:" + code)
		} else {
			warn("vendor_error")
		}
		writeCallbackPage(w, http.StatusBadRequest, page)
		return
	}
	if iss := q.Get("iss"); (flow.as.IssParameterSupported && iss == "") || (iss != "" && strings.TrimSuffix(iss, "/") != flow.as.Issuer) {
		warn("iss_mismatch")
		writeCallbackPage(w, http.StatusBadGateway, pageExchange)
		return
	}
	code := q.Get("code")
	if code == "" {
		warn("exchange")
		writeCallbackPage(w, http.StatusBadGateway, pageExchange)
		return
	}
	u, err := s.store.GetUpstream(r.Context(), flow.upstreamID)
	if err != nil {
		warn("changed")
		writeCallbackPage(w, http.StatusNotFound, pageChanged)
		return
	}
	if u.AuthType != models.AuthOAuth || !u.UpdatedAt.Equal(flow.seen) {
		warn("changed")
		writeCallbackPage(w, http.StatusConflict, pageChanged)
		return
	}

	now := time.Now().UTC()
	xctx, cancel := context.WithTimeout(context.Background(), oauthExchangeBudget)
	set, err := s.mcp.Exchange(xctx, flow.as, flow.set, code, flow.verifier, s.redirectURI(), now)
	cancel()
	if err != nil {
		var oe *mcpclient.OAuthError
		reason := "exchange"
		if errors.As(err, &oe) && oe.Code != "" {
			reason = "exchange:" + oe.Code
		}
		warn(reason)
		writeCallbackPage(w, http.StatusBadGateway, pageExchange)
		return
	}
	raw, _ := json.Marshal(set)
	enc, err := s.keys.Seal(raw)
	if err != nil {
		warn("seal")
		writeCallbackPage(w, http.StatusBadGateway, pageExchange)
		return
	}
	// The lock may be held by a refresh in flight (vendor call plus store
	// write, 10 s at most), so the wait outlasts that rather than sending
	// an operator who has just signed in back to Connect.
	lctx, lcancel := context.WithTimeout(context.Background(), oauthLockWait)
	unlock, err := credential.LockUpstream(lctx, u.ID)
	lcancel()
	if err != nil {
		warn("busy")
		writeCallbackPage(w, http.StatusServiceUnavailable, pageBusy)
		return
	}
	wctx, wcancel := context.WithTimeout(context.Background(), oauthWriteBudget)
	err = s.store.ConnectUpstreamAuth(wctx, u.ID, []byte(enc), flow.seen, now)
	wcancel()
	unlock()
	if err != nil {
		warn("changed")
		status := http.StatusConflict
		if _, gerr := s.store.GetUpstream(context.Background(), u.ID); errors.Is(gerr, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeCallbackPage(w, status, pageChanged)
		return
	}
	hasRefresh := set.RefreshToken != ""
	issuerHost := ""
	if iu, perr := url.Parse(set.Issuer); perr == nil {
		issuerHost = iu.Host
	}
	s.recordAdmin(r, models.ActionUpstreamOAuthConnect, u.ID, u.Name, adminDetails{
		AuthType: models.AuthOAuth, Client: set.ClientSource, RefreshToken: &hasRefresh, Issuer: issuerHost,
	})
	s.log.Info("upstream oauth connected", "upstream_id", u.ID, "client", set.ClientSource, "refresh_token", hasRefresh,
		"expires_in_s", int(set.ExpiresAt.Sub(now)/time.Second), "issuer", issuerHost)
	page := pageConnected
	page.Body = u.Name + " is connected."
	writeCallbackPage(w, http.StatusOK, page)
}

// Disconnect (10c).

// errUpstreamChangedRevoke is the 409 for a disconnect that found another
// grant on the row after it asked the vendor to revoke the one it read: the
// new grant was never revoked, so it is not cleared.
const errUpstreamChangedRevoke = "upstream changed; try Disconnect again"

// The vendor_revocation values a disconnect answers with.
const (
	revokedAtVendor     = "revoked"
	revokeFailed        = "failed"
	revokeNotOffered    = "not_offered"
	revokeNoToken       = "no_token"
	errUpstreamBusyText = "upstream is busy; try again"
)

// oauthRevoke disconnects: under the per-upstream lock it asks the vendor to
// revoke the stored grant when there is one and an endpoint to ask, then
// clears the blob (the client identity included: criterion 7 says
// auth_configured false) with the compare-and-swap on updated_at. The local
// clear always happens once the vendor was asked; it never clears a grant
// it did not revoke.
func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.allowDiscovery(w) {
		return
	}
	u, err := s.store.GetUpstream(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	if u.AuthType != models.AuthOAuth {
		writeError(w, http.StatusBadRequest, errNotOAuthRow)
		return
	}
	unlock, err := credential.LockUpstream(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errUpstreamBusyText)
		return
	}
	defer unlock()
	// The row again, under the lock: a refresh that was in flight has landed
	// or not, and what is stored now is what gets revoked.
	if u, err = s.store.GetUpstream(r.Context(), u.ID); err != nil {
		storeError(w, err)
		return
	}
	if u.AuthType != models.AuthOAuth {
		writeError(w, http.StatusBadRequest, errNotOAuthRow)
		return
	}
	if len(u.AuthConfig) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"upstream": s.presentUpstream(u), "vendor_revocation": revokeNoToken})
		return
	}
	var set models.OAuthTokenSet
	if plain, _, oerr := s.keys.Open(string(u.AuthConfig)); oerr == nil {
		_ = json.Unmarshal(plain, &set)
	}
	vendor := revokeNoToken
	if set.Connected() {
		vendor = revokeNotOffered
		if set.RevocationEndpoint != "" {
			vctx, cancel := context.WithTimeout(context.Background(), oauthExchangeBudget)
			rerr := s.mcp.Revoke(vctx, set)
			cancel()
			vendor = revokedAtVendor
			if rerr != nil {
				vendor = revokeFailed
				var oe *mcpclient.OAuthError
				status, host := 0, ""
				if errors.As(rerr, &oe) {
					status, host = oe.Status, oe.Host
				}
				s.log.Warn("upstream oauth vendor revocation failed", "upstream_id", u.ID, "status", status, "host", host)
			}
		}
	}
	now := time.Now().UTC()
	wctx, wcancel := context.WithTimeout(context.Background(), oauthWriteBudget)
	err = s.store.ConnectUpstreamAuth(wctx, u.ID, nil, u.UpdatedAt, now)
	wcancel()
	if errors.Is(err, store.ErrNotFound) {
		// The row moved under the lock: only a writer that does not take it
		// can do that. Re-read; the same grant means only updated_at moved
		// and the clear is retried once; another grant is left alone.
		again, gerr := s.store.GetUpstream(context.Background(), u.ID)
		if gerr != nil {
			storeError(w, gerr)
			return
		}
		var theirs models.OAuthTokenSet
		if plain, _, oerr := s.keys.Open(string(again.AuthConfig)); oerr == nil {
			_ = json.Unmarshal(plain, &theirs)
		}
		if again.AuthType != models.AuthOAuth || theirs.AccessToken != set.AccessToken || theirs.RefreshToken != set.RefreshToken {
			writeError(w, http.StatusConflict, errUpstreamChangedRevoke)
			return
		}
		wctx, wcancel := context.WithTimeout(context.Background(), oauthWriteBudget)
		err = s.store.ConnectUpstreamAuth(wctx, u.ID, nil, again.UpdatedAt, now)
		wcancel()
	}
	if err != nil {
		storeError(w, err)
		return
	}
	s.log.Info("upstream credential cleared", "upstream_id", u.ID, "cleared", []string{"credential"})
	s.log.Info("upstream oauth disconnected", "upstream_id", u.ID, "vendor_revocation", vendor)
	s.recordAdmin(r, models.ActionUpstreamOAuthRevoke, u.ID, u.Name, adminDetails{Cleared: []string{"credential"}, VendorRevocation: vendor})
	fresh, err := s.store.GetUpstream(r.Context(), u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"upstream": s.presentUpstream(fresh), "vendor_revocation": vendor})
}
