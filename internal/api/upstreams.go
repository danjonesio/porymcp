package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// errSlugRule is the single source of the slug 400 message. Only createUpstream
// reaches it: a slug is immutable after create, so patchUpstream rejects any
// change outright rather than validating a replacement value.
const errSlugRule = "slug must be 1-40 characters of a-z (case is folded), 0-9, _ or -, " +
	"starting and ending with a letter or digit, with no repeated separator, " +
	"and must not be UUID-shaped"

// errSlugImmutable is the single source of the PATCH message. A slug is fixed at
// create: group tool filters and virtual-key allow/deny lists are written
// against the tool identity "{slug}__{tool}", the same on every path, and a
// stale deny entry would fail open.
const errSlugImmutable = "slug cannot be changed after create"

// errURLRule is the single source of the URL 400 message, shared by create and
// patch. It names what a caller has to supply rather than what was wrong with
// what they sent: the value they sent is not this server's to repeat.
const errURLRule = "url must be an absolute http or https URL"

// errEnabledRule is the PATCH message for enabled sent as null. A bool has no
// cleared state, and on PATCH there is no default to fall back to: create reads
// null as "enabled", PATCH refuses it rather than guessing.
const errEnabledRule = "enabled must be true or false"

// errAuthNoneCredential is the single source of the 400 for a credential sent
// beside auth_type none, shared by create and patch (PORM-120). It names what
// the caller must change and never repeats what was sent.
const errAuthNoneCredential = "auth_config cannot be set when auth_type is none"

// errOAuthConfigShape is the single source of the 400 for an oauth
// auth_config that carries anything but the client identity (PORM-139). The
// token set is written by the callback and the refresh path only; an API
// caller that could plant a token_endpoint or a refresh_token would have the
// proxy post a refresh token to a host no metadata discovery vetted.
const errOAuthConfigShape = "auth_config for oauth accepts client_id and client_secret only"

// The kind rules (PORM-146). errKindImmutable mirrors errSlugImmutable: a
// key's endpoints are derived from kind, so a flipped kind would turn every
// key on the upstream from an MCP door into an HTTP door in silence.
// errOAuthOnHTTP is a scope reduction, not a safety rule: the connect flow
// POSTs an MCP initialize to the URL to read its challenge, which is not a
// request to make of a REST API, and REST APIs rarely publish the RFC 9728
// metadata the fallback reads, so the flow would fail after sending it.
const (
	errKindInvalid   = "invalid kind"
	errKindImmutable = "kind cannot be changed"
	errTestPathKind  = "test_path applies to an HTTP API upstream"
	errOAuthOnHTTP   = "oauth is not available on an HTTP API upstream"
)

// maxClientFieldBytes bounds an operator-supplied client_id or client_secret:
// both go on the token request, one of them into the authorization URL.
const maxClientFieldBytes = 1 << 10

// errSlugsExhausted means every derived candidate was taken. Kept distinct from
// store.ErrConflict so the caller gets an actionable message about a slug it
// never supplied, rather than "slug is already taken".
var errSlugsExhausted = errors.New("slug candidates exhausted")

type upstreamPublic struct {
	models.Upstream
	// AuthConfigured says a blob is stored, whatever it holds.
	AuthConfigured bool `json:"auth_configured"`
	// AuthStatus is credential.Status (PORM-52), always present: "none" iff
	// auth_type is none (whatever the dashboard stored beside it); "ok";
	// "undecryptable" (no configured key opens the blob, the key changed);
	// "unreadable" (nothing stored, or nothing the auth type can send, never
	// a key problem). auth_hint appears only when ok. auth_configured false
	// and auth_status "unreadable" together mean a non-none type with no
	// credential yet.
	AuthStatus string            `json:"auth_status"`
	AuthHint   map[string]string `json:"auth_hint,omitempty"`
	// OAuth is present on an oauth row whose blob is absent or opens
	// (PORM-139): when the connection ends, whether the vendor issued a
	// refresh token, and which client identity the row uses. Never a token,
	// a secret, an issuer URL, a scope or an endpoint. auth_status "expired"
	// is an oauth row whose access token lapsed with no refresh token; "not
	// connected" in the dashboard is an oauth row whose expires_at is null.
	OAuth *upstreamOAuth `json:"oauth,omitempty"`
}

type upstreamOAuth struct {
	ExpiresAt       *time.Time `json:"expires_at"`
	HasRefreshToken bool       `json:"has_refresh_token"`
	ClientSource    *string    `json:"client_source"`
}

func (s *Server) presentUpstream(u *models.Upstream) upstreamPublic {
	out := upstreamPublic{Upstream: *u, AuthConfigured: len(u.AuthConfig) > 0, AuthStatus: credential.StatusNone}
	out.AuthConfig = nil
	if u.AuthType == models.AuthNone || u.AuthType == "" {
		return out
	}
	// One decrypt feeds both the status and the hint; the mapping itself is
	// credential.StatusOf, shared with credential.Status.
	plain, err := credential.Read(s.keys, u.AuthType, u.AuthConfig)
	out.AuthStatus = credential.StatusOf(u.AuthType, plain, err, time.Now())
	if err == nil && u.AuthType != models.AuthOAuth {
		var cfg models.AuthConfig
		if json.Unmarshal(plain, &cfg) == nil && cfg.Header != "" {
			out.AuthHint = map[string]string{"header": cfg.Header}
		}
	}
	if u.AuthType == models.AuthOAuth {
		out.OAuth = s.oauthOf(u, plain, err)
	}
	return out
}

// oauthOf builds the oauth object: from Read's plaintext when the set is
// usable, from the opened blob when it holds only a client (Read drops that
// plaintext as unreadable), and empty when nothing is stored. An
// undecryptable blob gives nothing.
func (s *Server) oauthOf(u *models.Upstream, plain json.RawMessage, readErr error) *upstreamOAuth {
	var set models.OAuthTokenSet
	switch {
	case readErr == nil:
		_ = json.Unmarshal(plain, &set)
	case len(u.AuthConfig) == 0:
	case errors.Is(readErr, credential.ErrUnreadable):
		opened, _, err := s.keys.Open(string(u.AuthConfig))
		if err != nil || json.Unmarshal(opened, &set) != nil {
			return nil
		}
	default:
		return nil
	}
	o := &upstreamOAuth{HasRefreshToken: set.RefreshToken != ""}
	if set.Connected() && !set.ExpiresAt.IsZero() {
		t := set.ExpiresAt
		o.ExpiresAt = &t
	}
	if set.ClientSource != "" {
		src := set.ClientSource
		o.ClientSource = &src
	}
	return o
}

// oauthClient applies the shape rule for an oauth auth_config a caller
// writes: an object whose members are client_id (required when present) and
// optionally client_secret, both visible ASCII within maxClientFieldBytes.
// It returns the sealed-to-be set, with ClientSource "supplied".
func oauthClient(raw json.RawMessage) (models.OAuthTokenSet, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return models.OAuthTokenSet{}, false
	}
	for k := range fields {
		if k != "client_id" && k != "client_secret" {
			return models.OAuthTokenSet{}, false
		}
	}
	var in struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &in); err != nil || in.ClientID == "" {
		return models.OAuthTokenSet{}, false
	}
	if !clientField(in.ClientID) || (in.ClientSecret != "" && !clientField(in.ClientSecret)) {
		return models.OAuthTokenSet{}, false
	}
	return models.OAuthTokenSet{ClientID: in.ClientID, ClientSecret: in.ClientSecret, ClientSource: "supplied"}, true
}

func clientField(s string) bool {
	if s == "" || len(s) > maxClientFieldBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// upsertUpstream is the write shape for create, patch and unsaved discovery.
// Every field is an Optional (see optional.go) so patchUpstream can tell a key
// the body did not carry from one sent as null or empty. last_test_at and
// last_test_ok are deliberately absent: they are written only by
// POST /upstreams/{id}/discover, and a client that round-trips an upstream
// object back through this struct must not be able to claim a test that never
// ran. decodeBody does not DisallowUnknownFields, so the two keys are
// ignored when they arrive.
type upsertUpstream struct {
	Name        Optional[string]          `json:"name"`
	Slug        Optional[string]          `json:"slug"`
	Description Optional[string]          `json:"description"`
	Kind        Optional[string]          `json:"kind"`
	URL         Optional[string]          `json:"url"`
	Transport   Optional[string]          `json:"transport"`
	TestPath    Optional[string]          `json:"test_path"`
	AuthType    Optional[string]          `json:"auth_type"`
	AuthConfig  Optional[json.RawMessage] `json:"auth_config"`
	Enabled     Optional[bool]            `json:"enabled"`
}

func (s *Server) listUpstreams(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListUpstreams(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	pub := make([]upstreamPublic, 0, len(items))
	for i := range items {
		pub = append(pub, s.presentUpstream(&items[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"upstreams": pub})
}

func (s *Server) getUpstream(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUpstream(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.presentUpstream(u))
}

func (s *Server) createUpstream(w http.ResponseWriter, r *http.Request) {
	var in upsertUpstream
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(in.Name.Value) == "" || strings.TrimSpace(in.URL.Value) == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if !usableUpstreamURL(in.URL.Value) {
		writeError(w, http.StatusBadRequest, errURLRule)
		return
	}
	// Defaults live in locals rather than being written back into in: a field
	// whose Value and Has() disagree is the confusion Optional exists to end.
	// "" and null both take the default here; PATCH has no default and refuses
	// them instead.
	transport := in.Transport.Value
	if transport == "" {
		transport = models.TransportStreamableHTTP
	}
	authType := in.AuthType.Value
	if authType == "" {
		authType = models.AuthNone
	}
	if !validTransport(transport) {
		writeError(w, http.StatusBadRequest, "invalid transport")
		return
	}
	if !validAuthType(authType) {
		writeError(w, http.StatusBadRequest, "invalid auth_type")
		return
	}
	// kind defaults like transport and auth_type; the rules that tie kind,
	// url, auth_type and test_path together are one function shared with
	// PATCH and the unsaved discovery route (PORM-146).
	kind := in.Kind.Value
	if kind == "" {
		kind = models.KindMCP
	}
	if msg := checkUpstreamKindRules(kind, in.URL.Value, authType, in.TestPath.Value); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// A credential cannot ride along with auth_type none: the row would hold a
	// secret the proxy never sends and report auth_configured true for it
	// (PORM-120). An omitted auth_type took the default above, so the same
	// refusal covers a create that sends only a credential. The unsaved
	// POST /upstreams/discover route is not guarded: it persists nothing and
	// headersFor ignores the credential for none.
	if authType == models.AuthNone && in.AuthConfig.Has() && !emptyAuthConfig(in.AuthConfig.Value) {
		writeError(w, http.StatusBadRequest, errAuthNoneCredential)
		return
	}
	var slug string
	if in.Slug.Has() {
		slug = models.NormalizeSlug(in.Slug.Value)
		// Blank means "derive one" on create, the dashboard posts "" for an
		// untouched field. PATCH never accepts a changed slug at all: there, a
		// slug already exists and it is immutable.
		if slug != "" {
			if !models.ValidSlug(slug) {
				writeError(w, http.StatusBadRequest, errSlugRule)
				return
			}
			if models.ReservedSlug(slug) {
				writeError(w, http.StatusBadRequest, "slug is reserved")
				return
			}
		}
	}
	// A null auth_config is no credential: Value is nil, encryptAuth stores
	// nothing, and the row reports auth_configured false, not ciphertext of
	// the four bytes "null". For oauth the value is the client identity and
	// nothing else (errOAuthConfigShape), sealed as an OAuthTokenSet.
	rawAuth := in.AuthConfig.Value
	if authType == models.AuthOAuth && !emptyAuthConfig(rawAuth) {
		set, ok := oauthClient(rawAuth)
		if !ok {
			writeError(w, http.StatusBadRequest, errOAuthConfigShape)
			return
		}
		rawAuth, _ = json.Marshal(set)
	}
	enc, err := s.encryptAuth(rawAuth)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid auth_config")
		return
	}
	now := time.Now().UTC()
	enabled := true
	if in.Enabled.Has() {
		enabled = in.Enabled.Value
	}
	u := &models.Upstream{
		ID:          uuid.NewString(),
		Name:        strings.TrimSpace(in.Name.Value),
		Description: in.Description.Value,
		Kind:        kind,
		URL:         strings.TrimSpace(in.URL.Value),
		Transport:   transport,
		TestPath:    in.TestPath.Value,
		AuthType:    authType,
		AuthConfig:  enc,
		Enabled:     enabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if slug != "" {
		u.Slug = slug
		err = s.store.CreateUpstream(r.Context(), u)
	} else {
		err = s.createUpstreamDerivedSlug(r.Context(), u)
	}
	if err != nil {
		switch {
		case errors.Is(err, errSlugsExhausted):
			writeError(w, http.StatusConflict, "could not derive a unique slug; supply one explicitly")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "slug is already taken")
		default:
			storeError(w, err)
		}
		return
	}
	// AuthChanged reports a credential that was stored, so an Add that sent
	// {} for an untouched box does not read "credential set" (PORM-120).
	s.recordAdmin(r, models.ActionUpstreamCreate, u.ID, u.Name, adminDetails{
		Slug:        u.Slug,
		Kind:        u.Kind,
		AuthType:    u.AuthType,
		AuthChanged: len(u.AuthConfig) > 0,
	})
	writeJSON(w, http.StatusCreated, s.presentUpstream(u))
}

// createUpstreamDerivedSlug inserts u under the first free derived slug. The
// probe keeps the common case to one extra query; retrying on ErrConflict keeps
// it correct when two creates race for the same name.
//
// A conflict here can only be the slug: upstreams_slug is the only UNIQUE index
// on upstreams, and uniqueViolation excludes SQLite's PRIMARYKEY code. Adding a
// second unique index to upstreams means revisiting this loop.
func (s *Server) createUpstreamDerivedSlug(ctx context.Context, u *models.Upstream) error {
	// Lost races are budgeted separately from the candidate walk, so a wrong
	// assumption above cannot turn one create into 50 failed inserts on the
	// connection SetMaxOpenConns(1) shares with the proxy data plane.
	lost := 0
	for _, candidate := range models.SlugCandidates(u.Name) {
		if _, err := s.store.GetUpstreamBySlug(ctx, candidate); err == nil {
			continue // taken
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		u.Slug = candidate
		err := s.store.CreateUpstream(ctx, u)
		if errors.Is(err, store.ErrConflict) {
			if lost++; lost > 5 {
				return err
			}
			continue // lost the race; try the next suffix
		}
		return err
	}
	return errSlugsExhausted
}

func (s *Server) patchUpstream(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUpstream(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	// Snapshot for the admin event's field diff, before any assignment. A
	// shallow copy is enough because every assignment below replaces a whole
	// value and never appends to or mutates one in place.
	before := *u
	var in upsertUpstream
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Computed before a single field is assigned: once u carries the new values
	// there is nothing left to compare against. A change to what PoryMCP dials
	// or presents resets the recorded test result, because a green dot beside a
	// connection nobody has tried is worse than no dot at all. name,
	// description and enabled never reset it, they change no part of the
	// connection.
	//
	// auth_config cannot be compared: Keyring.Seal draws a fresh nonce per call,
	// so two ciphertexts of one credential never match. A present, non-null
	// auth_config therefore always counts as a change, the same condition the
	// assignment below uses. An edit dialog has to omit the field when the
	// operator did not touch it (PORM-2), or every save resets the dot.
	//
	// Choosing None removes the stored credential as well as stopping PoryMCP
	// sending it. It keys off the value the request named rather than a change
	// of type, so one request also empties a row that was already none and
	// still holds a blob sealed by an earlier build (PORM-120). It counts as a
	// change only when it removes bytes, so a resent none on an empty row
	// stays a no-op and keeps its recorded test.
	//
	// Two more removals join it for oauth (PORM-139), through the same
	// expression so the log line and the event stay single-sourced: a URL
	// change on an oauth row (the token was minted for the old resource, RFC
	// 8707, and must never be presented to the new one), and a type change
	// into or out of oauth with no auth_config in the body (a bearer token
	// under an oauth row is never sent; a live refresh token under a bearer
	// row is never revoked). A body that carries an auth_config replaces the
	// blob anyway.
	urlChanged := in.URL.Has() && strings.TrimSpace(in.URL.Value) != u.URL
	typeChanged := in.AuthType.Has() && in.AuthType.Value != u.AuthType
	acrossOAuth := typeChanged && (u.AuthType == models.AuthOAuth || in.AuthType.Value == models.AuthOAuth)
	clearAuth := (in.AuthType.Has() && in.AuthType.Value == models.AuthNone) ||
		(u.AuthType == models.AuthOAuth && urlChanged && !in.AuthConfig.Has()) ||
		(acrossOAuth && !in.AuthConfig.Has())
	cleared := clearAuth && len(u.AuthConfig) > 0
	// droppedTokens is the one removal the length test cannot see: a stored
	// oauth token set replaced by a client-only blob or by a credential of
	// another type. Known here because the old blob is opened to decide it.
	droppedTokens := u.AuthType == models.AuthOAuth && in.AuthConfig.Has() && !emptyAuthConfig(in.AuthConfig.Value) &&
		credential.Status(s.keys, u.AuthType, u.AuthConfig) != credential.StatusUnreadable && len(u.AuthConfig) > 0
	// test_path joins the reset (PORM-146): the probe requests a different
	// path, so a dot recorded against the old one vouches for nothing. "" and
	// null both clear it, the column is TEXT NOT NULL DEFAULT ''.
	testPathChanged := in.TestPath.Set && in.TestPath.Value != u.TestPath
	resetTest := (in.URL.Has() && strings.TrimSpace(in.URL.Value) != u.URL) ||
		(in.Transport.Has() && in.Transport.Value != u.Transport) ||
		(in.AuthType.Has() && in.AuthType.Value != u.AuthType) ||
		in.AuthConfig.Has() ||
		testPathChanged ||
		cleared
	// Every field is an Optional (see optional.go): a key the body did not carry
	// leaves the stored value alone, a value sets it under the same checks as
	// create, and null clears the fields that have a cleared state. A required
	// field sent as null or blank has nothing to fall back to (on create the
	// same key would take its default) so it is refused rather than ignored.
	if in.Name.Set {
		name := strings.TrimSpace(in.Name.Value)
		if name == "" {
			writeError(w, http.StatusBadRequest, errNameEmpty)
			return
		}
		u.Name = name
	}
	if in.Slug.Set {
		// A slug is fixed at create. Sending the current value is a no-op so a
		// client can round-trip the object; any other value is rejected, blank,
		// null and invalid ones included, there is nothing to validate against
		// because there is no legal change. To move a slug, delete and recreate.
		if models.NormalizeSlug(in.Slug.Value) != u.Slug {
			writeError(w, http.StatusBadRequest, errSlugImmutable)
			return
		}
	}
	if in.Kind.Set && in.Kind.Value != u.Kind {
		// The same rule as slug (PORM-146): the current value round-trips, any
		// other value is refused, and the store never writes the column.
		writeError(w, http.StatusBadRequest, errKindImmutable)
		return
	}
	if in.TestPath.Set {
		u.TestPath = in.TestPath.Value
	}
	if in.Description.Set {
		// "" and null both clear: the column is TEXT NOT NULL DEFAULT ''.
		u.Description = in.Description.Value
	}
	if in.URL.Set {
		if !usableUpstreamURL(in.URL.Value) {
			writeError(w, http.StatusBadRequest, errURLRule)
			return
		}
		u.URL = strings.TrimSpace(in.URL.Value)
	}
	if in.Transport.Set {
		if !validTransport(in.Transport.Value) {
			writeError(w, http.StatusBadRequest, "invalid transport")
			return
		}
		u.Transport = in.Transport.Value
	}
	if in.AuthType.Set {
		if !validAuthType(in.AuthType.Value) {
			writeError(w, http.StatusBadRequest, "invalid auth_type")
			return
		}
		u.AuthType = in.AuthType.Value
	}
	// The kind rules on the merged row (PORM-146), after every field they
	// read has been applied: a test_path on an MCP row, oauth or a base URL
	// with a query or userinfo on an HTTP API row.
	if msg := checkUpstreamKindRules(u.Kind, u.URL, u.AuthType, u.TestPath); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// The same refusal as create, keyed on what this request named: auth_type
	// none and a credential in one body. It sits after the auth_type block, so
	// a null auth_type still answers "invalid auth_type", and before the
	// auth_config branch, so nothing is sealed first. A credential sent alone
	// to a row stored as none is still stored, as before; the next request
	// that names none removes it.
	if in.AuthType.Has() && in.AuthType.Value == models.AuthNone && in.AuthConfig.Has() && !emptyAuthConfig(in.AuthConfig.Value) {
		writeError(w, http.StatusBadRequest, errAuthNoneCredential)
		return
	}
	if in.AuthConfig.Has() {
		// null keeps the stored credential. The value is write-only, so an
		// object read back and sent again cannot carry it, and null has to mean
		// "unchanged" rather than "remove". For oauth the value is the client
		// identity only (errOAuthConfigShape), and writing one drops any
		// token set: the tokens belong to the old client.
		rawAuth := in.AuthConfig.Value
		if u.AuthType == models.AuthOAuth && !emptyAuthConfig(rawAuth) {
			set, ok := oauthClient(rawAuth)
			if !ok {
				writeError(w, http.StatusBadRequest, errOAuthConfigShape)
				return
			}
			rawAuth, _ = json.Marshal(set)
		}
		enc, err := s.encryptAuth(rawAuth)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid auth_config")
			return
		}
		u.AuthConfig = enc
	}
	if clearAuth {
		u.AuthConfig = nil
	}
	if in.Enabled.Set {
		if in.Enabled.Null {
			writeError(w, http.StatusBadRequest, errEnabledRule)
			return
		}
		u.Enabled = in.Enabled.Value
	}
	u.UpdatedAt = time.Now().UTC()
	if resetTest {
		// The row loses both columns in the same statement as the edit; nil
		// them here too, so the 200 built from this struct says what the row
		// says rather than echoing the result of a test of the old settings.
		u.LastTestAt, u.LastTestOK = nil, nil
	}
	// auth_config is written back only when this request carried one (a
	// literal {} counts) or named auth_type none over a stored value. Writing
	// the empty column is not writing back a value the request did not carry.
	// Otherwise the ciphertext read at the top of this handler stays out of
	// the statement, so an edit that raced a `porymcp rekey` cannot put an
	// old-key value back (PORM-52).
	writeAuth := in.AuthConfig.Has() || cleared
	// authChanged means a credential was stored: a request that carried {}
	// stored nothing and is not reported as one.
	authChanged := in.AuthConfig.Has() && len(u.AuthConfig) > 0
	// An oauth row's write runs under the per-upstream lock (PORM-139), so a
	// refresh in flight cannot land a rotated token on top of a clear, and a
	// clear cannot drop a grant a refresh has just rotated at the vendor.
	if before.AuthType == models.AuthOAuth || u.AuthType == models.AuthOAuth {
		unlock, err := credential.LockUpstream(r.Context(), u.ID)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "upstream is busy; try again")
			return
		}
		defer unlock()
	}
	if err := s.store.UpdateUpstream(r.Context(), u, resetTest, writeAuth); err != nil {
		storeError(w, err)
		return
	}
	// A pending sign-in was started for the old URL, type or client: forget
	// it, so its callback cannot store a token for a row that moved.
	if (before.AuthType == models.AuthOAuth || u.AuthType == models.AuthOAuth) && (urlChanged || typeChanged || in.AuthConfig.Has()) {
		s.flows.drop(u.ID)
	}
	// The log line fires on the same test the admin event uses (a column that
	// held bytes and holds none now, or a token set dropped for a new
	// client), so the two records of a removal never disagree, whichever
	// request emptied it: auth_type none, {}, a URL or type change on an
	// oauth row, or a new client. After the write returned nil, like
	// patchGroup's line: the id and what was cleared, never the name or a
	// value.
	if (len(before.AuthConfig) > 0 && len(u.AuthConfig) == 0) || droppedTokens {
		s.log.Info("upstream credential cleared", "upstream_id", u.ID, "cleared", []string{"credential"})
	}
	// A PATCH that changed nothing still records: the row was written (and
	// updated_at moved), and an event with empty details says so honestly.
	s.recordAdmin(r, models.ActionUpstreamUpdate, u.ID, u.Name, upstreamPatchDetails(before, *u, authChanged, droppedTokens))
	writeJSON(w, http.StatusOK, s.presentUpstream(u))
}

func (s *Server) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Read before the delete: the event names what was removed, and after
	// DeleteUpstream there is nothing left to read the name from. A missing id
	// now 404s from this Get rather than from the delete. An upstream a group
	// or a key still references 409s from the delete below, so nothing is
	// recorded.
	u, err := s.store.GetUpstream(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.DeleteUpstream(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.recordAdmin(r, models.ActionUpstreamDelete, u.ID, u.Name, adminDetails{})
	w.WriteHeader(http.StatusNoContent)
}

// usableUpstreamURL reports whether PoryMCP could connect to what is being
// stored. The check is mcpclient's own, so the write path and the outbound
// path give one answer instead of accepting a "url" here that discovery and
// the proxy can only refuse later, a scheme-less "localhost:8080/mcp" parses
// as scheme "localhost" and was stored happily before this.
//
// Syntax only, and deliberately so: whether a host is one PoryMCP should dial
// at all is PORM-79's question, and mcpclient.CheckTarget is the one place it
// will be answered for every caller at once.
func usableUpstreamURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && mcpclient.CheckTarget(u) == nil
}

// checkUpstreamKindRules is the one place the rules that tie an upstream's
// kind to its other fields live (PORM-146), for create, PATCH (on the merged
// row) and the unsaved discovery route. It returns the 400 message, or "".
// kind must be mcp or http; test_path is validated by models.ValidateTestPath
// and belongs to an HTTP API row only; an HTTP API row takes no oauth
// credential and no base URL with a query string or userinfo
// (mcpclient.CheckHTTPBase). rawURL has already passed usableUpstreamURL, so
// a parse failure here is unreachable and reads as the URL rule.
func checkUpstreamKindRules(kind, rawURL, authType, testPath string) string {
	switch kind {
	case models.KindMCP, models.KindHTTP:
	default:
		return errKindInvalid
	}
	if err := models.ValidateTestPath(testPath); err != nil {
		return err.Error()
	}
	if kind == models.KindMCP {
		if testPath != "" {
			return errTestPathKind
		}
		return ""
	}
	if authType == models.AuthOAuth {
		return errOAuthOnHTTP
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return errURLRule
	}
	if err := mcpclient.CheckHTTPBase(u); err != nil {
		return err.Error()
	}
	return ""
}

// validTransport is the write gate for the transport field: only
// streamable-http is accepted on create, on PATCH and on the unsaved discover
// route. models.TransportSSE stays a stored value that rows saved before
// PORM-28 may still carry; the proxy refuses to dial it, because the legacy
// HTTP+SSE client is not implemented.
func validTransport(v string) bool {
	return v == models.TransportStreamableHTTP
}

func validAuthType(v string) bool {
	switch v {
	case models.AuthNone, models.AuthBearer, models.AuthHeader, models.AuthAPIKey, models.AuthCustom, models.AuthOAuth:
		return true
	}
	return false
}

func decodeBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(dst)
}
