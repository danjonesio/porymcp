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
}

func (s *Server) presentUpstream(u *models.Upstream) upstreamPublic {
	out := upstreamPublic{Upstream: *u, AuthConfigured: len(u.AuthConfig) > 0, AuthStatus: credential.StatusNone}
	out.AuthConfig = nil
	if u.AuthType == models.AuthNone || u.AuthType == "" {
		return out
	}
	// One decrypt feeds both the status and the hint; the mapping itself is
	// credential.StatusFor, shared with credential.Status.
	plain, err := credential.Read(s.keys, u.AuthType, u.AuthConfig)
	out.AuthStatus = credential.StatusFor(err)
	if err == nil {
		var cfg models.AuthConfig
		if json.Unmarshal(plain, &cfg) == nil && cfg.Header != "" {
			out.AuthHint = map[string]string{"header": cfg.Header}
		}
	}
	return out
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
	URL         Optional[string]          `json:"url"`
	Transport   Optional[string]          `json:"transport"`
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
	if !validTransport(transport) || !validAuthType(authType) {
		writeError(w, http.StatusBadRequest, "invalid transport or auth_type")
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
	// the four bytes "null".
	enc, err := s.encryptAuth(in.AuthConfig.Value)
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
		URL:         strings.TrimSpace(in.URL.Value),
		Transport:   transport,
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
	s.recordAdmin(r, models.ActionUpstreamCreate, u.ID, u.Name, adminDetails{
		Slug:        u.Slug,
		AuthType:    u.AuthType,
		AuthChanged: in.AuthConfig.Has(),
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
	clearAuth := in.AuthType.Has() && in.AuthType.Value == models.AuthNone
	cleared := clearAuth && len(u.AuthConfig) > 0
	resetTest := (in.URL.Has() && strings.TrimSpace(in.URL.Value) != u.URL) ||
		(in.Transport.Has() && in.Transport.Value != u.Transport) ||
		(in.AuthType.Has() && in.AuthType.Value != u.AuthType) ||
		in.AuthConfig.Has() ||
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
		// "unchanged" rather than "remove".
		enc, err := s.encryptAuth(in.AuthConfig.Value)
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
	if err := s.store.UpdateUpstream(r.Context(), u, resetTest, writeAuth); err != nil {
		storeError(w, err)
		return
	}
	// A PATCH that changed nothing still records: the row was written (and
	// updated_at moved), and an event with empty details says so honestly.
	s.recordAdmin(r, models.ActionUpstreamUpdate, u.ID, u.Name, upstreamPatchDetails(before, *u, in.AuthConfig.Has()))
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

func validTransport(v string) bool {
	return v == models.TransportStreamableHTTP || v == models.TransportSSE
}

func validAuthType(v string) bool {
	switch v {
	case models.AuthNone, models.AuthBearer, models.AuthHeader, models.AuthAPIKey, models.AuthCustom:
		return true
	}
	return false
}

func decodeBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(dst)
}
