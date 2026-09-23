// Package oauthstub is a test-only authorization server plus a protected MCP
// resource, the fixture PORM-139's OAuth tests drive. It is a non-test package
// so that mcpclient, credential, proxy, api and cmd/server tests can all
// import it; it imports the standard library only, so it can never pull
// mcpclient into a cycle, and TestOAuthStubNeverImported in mcpclient keeps
// it out of every non-test file.
//
// It serves, on one httptest origin:
//
//   - /mcp: a stateless legacy MCP server that answers initialize,
//     notifications/initialized and tools/list, and refuses anything without a
//     valid bearer with 401 plus a WWW-Authenticate challenge naming its
//     resource metadata (RFC 9728).
//   - /.well-known/oauth-protected-resource[/mcp]: the resource metadata.
//   - /.well-known/oauth-authorization-server: RFC 8414 metadata.
//   - /register: RFC 7591 dynamic client registration.
//   - /token: authorization_code with PKCE S256 and refresh_token, rotating
//     the refresh token on every refresh.
//   - /revoke: RFC 7009, which counts and answers 200.
//
// The browser's consent step is Approve, which checks the authorization URL
// PoryMCP built and returns the redirect the vendor would send.
package oauthstub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Server is one stub instance. Knobs are plain fields set before the request
// they steer; counters are read through the methods below.
type Server struct {
	srv *httptest.Server

	// Knobs.

	// RejectRefresh answers every refresh_token grant with 400 invalid_grant.
	RejectRefresh bool
	// RejectRefreshTransient answers every refresh_token grant with 503.
	RejectRefreshTransient bool
	// NoRefreshToken omits refresh_token from every token answer.
	NoRefreshToken bool
	// OmitExpiresIn omits expires_in from every token answer.
	OmitExpiresIn bool
	// ExpiresIn is the expires_in every token answer carries; 0 means 3600.
	ExpiresIn int
	// NoCIMD advertises client_id_metadata_document_supported: false and
	// refuses a URL-shaped client_id at Approve.
	NoCIMD bool
	// NoRegistration omits registration_endpoint and answers /register 404.
	NoRegistration bool
	// NoIss advertises no authorization_response_iss_parameter_supported and
	// omits iss from the redirect.
	NoIss bool
	// NoS256 omits code_challenge_methods_supported from the metadata.
	NoS256 bool
	// EndpointsOnOtherHost, when set, names authorization_endpoint and
	// token_endpoint on that origin instead of the issuer's.
	EndpointsOnOtherHost string
	// NoChallengeMetadata leaves resource_metadata out of the 401 challenge.
	NoChallengeMetadata bool
	// RootMetadataOnly serves the resource metadata only at the origin root
	// (resource = origin) and drops it from the challenge.
	RootMetadataOnly bool
	// TokenType is the token_type every token answer carries; "" means Bearer.
	TokenType string
	// ErrorDescriptionMarker is a marker put into error_description of every
	// token error, beside the presented refresh token, so a test can prove
	// neither reaches a log or an audit row.
	ErrorDescriptionMarker string
	// RegisterChangesRedirect makes /register answer with a redirect_uris list
	// that differs from the one sent.
	RegisterChangesRedirect bool
	// AccessTokenBytes, when set, makes every issued access token this long.
	AccessTokenBytes int

	mu       sync.Mutex
	seq      int
	codes    map[string]codeRecord
	access   map[string]bool
	refresh  map[string]bool
	clients  map[string]string // client_id -> secret ("" for a public client)
	requests []Request
	grants   map[string]int
	revokes  int
	regs     int
	hold     chan struct{}
}

type codeRecord struct {
	challenge   string
	redirectURI string
	resource    string
	clientID    string
}

// Request is what the MCP resource recorded about one call.
type Request struct {
	Method string
	Path   string
	RPC    string
	Header http.Header
}

// Redirect is what Approve hands back: the code, the state, and the full
// redirect the vendor would send the browser to.
type Redirect struct {
	Code     string
	State    string
	Location string
}

// New starts a stub and closes it with the test.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		codes:   map[string]codeRecord{},
		access:  map[string]bool{},
		refresh: map[string]bool{},
		clients: map[string]string{},
		grants:  map[string]int{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the stub's origin.
func (s *Server) URL() string { return s.srv.URL }

// MCPURL is the protected resource, what an operator types as the upstream URL.
func (s *Server) MCPURL() string { return s.srv.URL + "/mcp" }

// Issuer is the authorization server's issuer, the same origin.
func (s *Server) Issuer() string { return s.srv.URL }

// TokenEndpoint and RevocationEndpoint are what a stored token set names.
func (s *Server) TokenEndpoint() string      { return s.srv.URL + "/token" }
func (s *Server) RevocationEndpoint() string { return s.srv.URL + "/revoke" }

// AllowClient registers a client the operator "supplied" in the vendor's
// settings. secret "" makes it a public client.
func (s *Server) AllowClient(id, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[id] = secret
}

// Seed mints a valid access and refresh token pair without a browser flow,
// for tests that start from a connected row.
func (s *Server) Seed() (access, refresh string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	access, refresh = s.mintLocked()
	return access, refresh
}

// Grants reports how many times /token saw grantType.
func (s *Server) Grants(grantType string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grants[grantType]
}

// Revocations reports how many times /revoke was called.
func (s *Server) Revocations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokes
}

// Registrations reports how many times /register was called.
func (s *Server) Registrations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.regs
}

// Requests returns every call the MCP resource recorded.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// AccessValid reports whether the resource would accept this access token.
func (s *Server) AccessValid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.access[token]
}

// RefreshValid reports whether /token would accept this refresh token.
func (s *Server) RefreshValid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh[token]
}

// HoldToken makes the next token answers wait until release is called, so a
// test can overlap callers or cancel a context mid-refresh.
func (s *Server) HoldToken() (release func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan struct{})
	s.hold = ch
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			if s.hold == ch {
				s.hold = nil
			}
			s.mu.Unlock()
			close(ch)
		})
	}
}

// Approve plays the browser and the vendor's consent page: it checks the
// authorization URL PoryMCP built and returns the redirect the vendor would
// send, with the code bound to the request's PKCE challenge.
func (s *Server) Approve(authURL string) (Redirect, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return Redirect{}, err
	}
	want := s.srv.URL + "/authorize"
	if s.EndpointsOnOtherHost != "" {
		want = s.EndpointsOnOtherHost + "/authorize"
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != want {
		return Redirect{}, fmt.Errorf("authorization endpoint %s, want %s", got, want)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		return Redirect{}, fmt.Errorf("response_type %q", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		return Redirect{}, fmt.Errorf("pkce: method %q challenge %q", q.Get("code_challenge_method"), q.Get("code_challenge"))
	}
	if q.Get("state") == "" {
		return Redirect{}, fmt.Errorf("no state")
	}
	if q.Get("redirect_uri") == "" {
		return Redirect{}, fmt.Errorf("no redirect_uri")
	}
	if q.Get("resource") != s.MCPURL() && !s.RootMetadataOnly {
		return Redirect{}, fmt.Errorf("resource %q, want %q", q.Get("resource"), s.MCPURL())
	}
	clientID := q.Get("client_id")
	if clientID == "" {
		return Redirect{}, fmt.Errorf("no client_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.clients[clientID]; !known {
		if !strings.HasPrefix(clientID, "https://") && !strings.HasPrefix(clientID, "http://") {
			return Redirect{}, fmt.Errorf("unknown client_id %q", clientID)
		}
		if s.NoCIMD {
			return Redirect{}, fmt.Errorf("client id metadata documents are not supported")
		}
	}
	s.seq++
	code := fmt.Sprintf("code-%d", s.seq)
	s.codes[code] = codeRecord{
		challenge:   q.Get("code_challenge"),
		redirectURI: q.Get("redirect_uri"),
		resource:    q.Get("resource"),
		clientID:    clientID,
	}
	loc, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		return Redirect{}, err
	}
	rq := loc.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	if !s.NoIss {
		rq.Set("iss", s.srv.URL)
	}
	loc.RawQuery = rq.Encode()
	return Redirect{Code: code, State: q.Get("state"), Location: loc.String()}, nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/mcp":
		s.serveMCP(w, r)
	case r.URL.Path == "/.well-known/oauth-protected-resource/mcp":
		if s.RootMetadataOnly {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{
			"resource":              s.MCPURL(),
			"authorization_servers": []string{s.srv.URL},
			"scopes_supported":      []string{"mcp"},
		})
	case r.URL.Path == "/.well-known/oauth-protected-resource":
		if !s.RootMetadataOnly {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{
			"resource":              s.srv.URL,
			"authorization_servers": []string{s.srv.URL},
		})
	case r.URL.Path == "/.well-known/oauth-authorization-server":
		s.serveASMetadata(w)
	case r.URL.Path == "/register":
		s.serveRegister(w, r)
	case r.URL.Path == "/token":
		s.serveToken(w, r)
	case r.URL.Path == "/revoke":
		s.mu.Lock()
		s.revokes++
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveASMetadata(w http.ResponseWriter) {
	origin := s.srv.URL
	if s.EndpointsOnOtherHost != "" {
		origin = s.EndpointsOnOtherHost
	}
	doc := map[string]any{
		"issuer":                                s.srv.URL,
		"authorization_endpoint":                origin + "/authorize",
		"token_endpoint":                        origin + "/token",
		"revocation_endpoint":                   s.srv.URL + "/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"client_id_metadata_document_supported": !s.NoCIMD,
	}
	if !s.NoRegistration {
		doc["registration_endpoint"] = s.srv.URL + "/register"
	}
	if !s.NoS256 {
		doc["code_challenge_methods_supported"] = []string{"S256"}
	}
	if !s.NoIss {
		doc["authorization_response_iss_parameter_supported"] = true
	}
	writeJSON(w, doc)
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request) {
	if s.NoRegistration || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		RedirectURIs    []string `json:"redirect_uris"`
		ApplicationType string   `json:"application_type"`
		ClientName      string   `json:"client_name"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &req); err != nil || len(req.RedirectURIs) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client_metadata"}`))
		return
	}
	s.mu.Lock()
	s.regs++
	s.seq++
	id := fmt.Sprintf("reg-%d", s.seq)
	secret := fmt.Sprintf("regsecret-%d", s.seq)
	s.clients[id] = secret
	s.mu.Unlock()
	uris := req.RedirectURIs
	if s.RegisterChangesRedirect {
		uris = []string{"https://elsewhere.invalid/callback"}
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"redirect_uris":              uris,
		"application_type":           req.ApplicationType,
		"token_endpoint_auth_method": "client_secret_basic",
	})
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.tokenError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	// A held answer waits here, outside the lock, so counters and Seed keep
	// working while a test overlaps callers.
	s.mu.Lock()
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	grant := r.PostForm.Get("grant_type")
	s.mu.Lock()
	s.grants[grant]++
	s.mu.Unlock()

	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}
	if strings.Contains(r.URL.RawQuery, "client_secret") {
		s.tokenError(w, http.StatusBadRequest, "invalid_request", "secret in query")
		return
	}

	switch grant {
	case "authorization_code":
		s.mu.Lock()
		rec, ok := s.codes[r.PostForm.Get("code")]
		delete(s.codes, r.PostForm.Get("code"))
		known, registered := s.clients[rec.clientID]
		s.mu.Unlock()
		if !ok {
			s.tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown code")
			return
		}
		if clientID != rec.clientID {
			s.tokenError(w, http.StatusUnauthorized, "invalid_client", "client mismatch")
			return
		}
		if registered && known != "" && known != secret {
			s.tokenError(w, http.StatusUnauthorized, "invalid_client", "bad secret")
			return
		}
		if s256(r.PostForm.Get("code_verifier")) != rec.challenge {
			s.tokenError(w, http.StatusBadRequest, "invalid_grant", "pkce mismatch")
			return
		}
		if r.PostForm.Get("redirect_uri") != rec.redirectURI {
			s.tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}
		if r.PostForm.Get("resource") != rec.resource {
			s.tokenError(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
			return
		}
		s.writeTokens(w)
	case "refresh_token":
		presented := r.PostForm.Get("refresh_token")
		if s.RejectRefreshTransient {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("try later " + s.ErrorDescriptionMarker))
			return
		}
		if s.RejectRefresh {
			s.tokenError(w, http.StatusBadRequest, "invalid_grant", presented)
			return
		}
		s.mu.Lock()
		valid := s.refresh[presented]
		if valid {
			delete(s.refresh, presented) // rotation: the old one is spent
		}
		s.mu.Unlock()
		if !valid {
			s.tokenError(w, http.StatusBadRequest, "invalid_grant", presented)
			return
		}
		s.writeTokens(w)
	default:
		s.tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *Server) writeTokens(w http.ResponseWriter) {
	s.mu.Lock()
	access, refresh := s.mintLocked()
	s.mu.Unlock()
	tokenType := s.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	doc := map[string]any{
		"access_token": access,
		"token_type":   tokenType,
		"scope":        "mcp",
	}
	if !s.NoRefreshToken {
		doc["refresh_token"] = refresh
	}
	if !s.OmitExpiresIn {
		exp := s.ExpiresIn
		if exp == 0 {
			exp = 3600
		}
		doc["expires_in"] = exp
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, doc)
}

func (s *Server) mintLocked() (access, refresh string) {
	s.seq++
	access = fmt.Sprintf("acc-%d", s.seq)
	if s.AccessTokenBytes > 0 {
		access = strings.Repeat("a", s.AccessTokenBytes)
	}
	refresh = fmt.Sprintf("ref-%d", s.seq)
	s.access[access] = true
	if !s.NoRefreshToken {
		s.refresh[refresh] = true
	}
	return access, refresh
}

func (s *Server) tokenError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	desc := strings.TrimSpace(s.ErrorDescriptionMarker + " " + detail)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var probe struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &probe)
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, RPC: probe.Method, Header: r.Header.Clone()})
	s.mu.Unlock()

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || !s.AccessValid(token) {
		challenge := `Bearer realm="oauthstub"`
		if !s.NoChallengeMetadata && !s.RootMetadataOnly {
			challenge += `, resource_metadata="` + s.srv.URL + `/.well-known/oauth-protected-resource/mcp"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := probe.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	switch probe.Method {
	case "initialize":
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "oauthstub", "version": "1.0.0"},
		}})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
			"tools": []map[string]any{{"name": "echo", "description": "Echoes back the input string", "inputSchema": map[string]any{"type": "object"}}},
		}})
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "Method not found"}})
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// S256 is the PKCE transform, exported so a test can build a verifier and
// challenge pair without importing mcpclient.
func S256(verifier string) string { return s256(verifier) }

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
