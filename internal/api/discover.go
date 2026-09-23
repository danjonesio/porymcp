package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Discovery is the one management call that leaves the process. Everything
// else here reads and writes PoryMCP's own database; these two routes open a
// connection to a host an operator chose and present a real credential to it,
// which is why they carry budgets of their own and why the handlers below say
// nothing to the log, except when a result could not be recorded: one DEBUG
// (row changed or gone) or one WARN (store error), each naming the upstream id
// and nothing else.
//
// The HTTP status describes the request and `ok` inside the body describes the
// upstream: an unreachable host, a refused credential and an empty catalogue
// are all 200s, because the request was answered exactly as asked. Only the
// request being wrong (no admin key, an unknown id, a malformed payload, a
// spent budget) changes the status.

// discoverUpstream discovers what a stored upstream advertises.
func (s *Server) discoverUpstream(w http.ResponseWriter, r *http.Request) {
	if !s.allowDiscovery(w) {
		return
	}
	// The body is ignored, as it is on rotate and revoke: the id in the path
	// is the whole request, and everything else comes from the stored row.
	u, err := s.store.GetUpstream(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	// Deliberately no Enabled check. An operator disables an upstream to stop
	// serving it and then wants to know why it broke; the flag gates a
	// caller's access, not the operator's own inspection.
	// credential.Read is the one rule (PORM-52): a none upstream sends
	// nothing and skips this; otherwise the stored blob either opens into
	// something the auth type can send, or the reason it does not is one of
	// two. No request goes out on either: sending one would present no
	// credential, collect the upstream's 401, and tell the operator their
	// token is wrong when the truth is that ENCRYPTION_KEY is (undecryptable)
	// or that the stored value is empty or the wrong shape (unreadable).
	//
	// Recorded all the same, and recorded as a failure: no outbound call was
	// made, but PoryMCP cannot use this upstream, which is what the dot
	// answers. A key change is the one failure that hits every row at once,
	// so a table that stayed green through it would be lying at exactly the
	// moment it matters. The cause lives in auth_status on the row.
	//
	// Through the Presenter rather than Read (PORM-139): an oauth row whose
	// token is about to lapse is renewed here exactly as the proxy renews it,
	// so Tools does not report as failed an upstream the proxy would have
	// reached. A refresh this route triggers is recorded with the admin's
	// own actor and address.
	plain, err := s.present.Present(r.Context(), u, credential.Caller{
		Actor: models.ActorAdmin, RemoteAddr: webutil.ClientIP(r, s.cfg.TrustedProxies), RequestID: middleware.GetReqID(r.Context()),
	})
	if err != nil {
		msg := "stored credential cannot be decrypted"
		switch {
		case errors.Is(err, credential.ErrUnreadable):
			msg = "stored credential is not usable for this auth type"
		case errors.Is(err, credential.ErrExpired):
			msg = "stored credential has expired; connect again"
		case errors.Is(err, credential.ErrRefreshFailed):
			msg = "the token could not be refreshed; try again"
		}
		d := mcpclient.Failed(u.Kind, msg)
		s.recordTest(r, u, d)
		writeJSON(w, http.StatusOK, d)
		return
	}
	s.runDiscovery(w, r, u, plain, savedUpstream)
}

// errDiscoverUnsavedOAuth is the 400 for an unsaved discovery of an oauth
// upstream: there is no token before Connect, and Connect needs a saved row.
const errDiscoverUnsavedOAuth = "oauth upstreams are discovered after they are connected: create the upstream, connect it, then call POST /upstreams/{id}/discover"

// discoverUnsaved discovers what the upstream in the request body advertises,
// so the Add-upstream dialog can show its tools before anything is created.
func (s *Server) discoverUnsaved(w http.ResponseWriter, r *http.Request) {
	if !s.allowDiscovery(w) {
		return
	}
	var in upsertUpstream
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// url alone is required, unlike create: the Discover button is enabled as
	// soon as there is a URL to look at, and a name is a decision the operator
	// makes after seeing what is there.
	target := strings.TrimSpace(in.URL.Value)
	if target == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
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
	if authType == models.AuthOAuth {
		writeError(w, http.StatusBadRequest, errDiscoverUnsavedOAuth)
		return
	}
	// The kind rules run here as on create (PORM-146): the Test button in the
	// Add dialog must not probe a base URL create would refuse, and a base
	// carrying userinfo would otherwise go out as Basic auth.
	kind := in.Kind.Value
	if kind == "" {
		kind = models.KindMCP
	}
	if !usableUpstreamURL(target) {
		writeError(w, http.StatusBadRequest, errURLRule)
		return
	}
	if msg := checkUpstreamKindRules(kind, target, authType, in.TestPath.Value); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// No slug is derived. createUpstream walks candidates and de-duplicates,
	// so an upstream previewed as "github" may well be stored as "github-2",
	// and an operator who copied "github__search" out of this panel into a
	// deny rule would have written one that matches nothing and fails open.
	// With no slug the response carries no scoped_name at all, which is the
	// honest answer before the row exists.
	u := &models.Upstream{
		Kind:      kind,
		URL:       target,
		Transport: transport,
		TestPath:  in.TestPath.Value,
		AuthType:  authType,
	}
	// in.AuthConfig arrives as plaintext, exactly as it does on create. It is
	// handed straight to the client: never encrypted, never stored, and never
	// echoed back, Discovery has no field that could hold it. A null is
	// forwarded as no credential, not as the four bytes "null".
	s.runDiscovery(w, r, u, in.AuthConfig.Value, unsavedPayload)
}

// savedUpstream and unsavedPayload say whether runDiscovery has a stored row to
// stamp. The unsaved route has none and persists nothing, that is the whole
// difference between the two routes, and it reads better at the call site than
// a bare bool.
const (
	savedUpstream  = true
	unsavedPayload = false
)

// runDiscovery is the one place either route reaches an upstream.
//
// r.Context() is passed through unmodified: mcpclient owns the ten-second
// budget for the whole handshake, and a second deadline here would be a second
// answer to one question. It also means an operator who closes the dialog
// unwinds the outbound request rather than leaving it running. The server sets
// no WriteTimeout (cmd/server/main.go), so a slow discovery is not cut off
// mid-response, do not add one.
func (s *Server) runDiscovery(w http.ResponseWriter, r *http.Request, u *models.Upstream, plain json.RawMessage, stored bool) {
	// Acquired here rather than at the top of each handler, so a 404 or an
	// undecryptable credential (neither of which makes an outbound call)
	// never holds a slot a real discovery could use.
	select {
	case s.discovering <- struct{}{}:
		defer func() { <-s.discovering }()
	default:
		// Not queued: a caller waiting behind four ten-second handshakes
		// learns nothing a "try again shortly" does not tell them sooner.
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too many concurrent discoveries")
		return
	}
	// An HTTP API upstream is probed, not handshaken (PORM-146): one GET to
	// the base URL joined with its test path, under the same slot and the
	// same recording.
	var d mcpclient.Discovery
	if u.Kind == models.KindHTTP {
		d = s.mcp.Probe(r.Context(), u, plain)
	} else {
		d = s.mcp.Discover(r.Context(), u, plain)
	}
	// Before the response, not after: the dashboard re-reads the table the
	// moment the response lands, so a record made afterwards would race the
	// read it exists to feed.
	if stored {
		s.recordTest(r, u, d)
	}
	// The only write. Discovery is structured fields the client composed, so
	// no upstream header and no byte of an upstream body outside the tool list
	// can reach the operator's browser through it.
	writeJSON(w, http.StatusOK, d)
}

// recordTimeout bounds the detached write. The handshake is over; one UPDATE
// behind SQLite's 5 s busy timeout either lands quickly or is not landing.
// Same figure as mcpclient's teardownTimeout, for the same reason.
const recordTimeout = 2 * time.Second

// recordTest stamps u's row with the outcome of d. A caller that has gone away
// tested nothing: a reload or a closed tab cancels r.Context() mid-handshake,
// and transportFailure has no branch for that, it comes back as "cannot reach
// <host>", which would put a red dot on an upstream nobody tested. Same reading
// endSession makes of the same signal. The write itself is detached with a
// short timeout: the handshake already happened, so its result is true, and a
// cancel arriving between the check and the write must not lose it.
//
// A failed write is not a failed request (the operator asked what the upstream
// offers and that answer is composed) so the Discovery goes out either way.
// ErrNotFound means the row was deleted or edited during the handshake (or, for
// a hand-edited updated_at, can never match, see RecordUpstreamTest): one DEBUG
// line with the id, nothing to say to the operator. Anything else is one WARN
// naming the upstream id and the store's error, never the name, the url or a
// credential.
func (s *Server) recordTest(r *http.Request, u *models.Upstream, d mcpclient.Discovery) {
	if r.Context().Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
	defer cancel()
	switch err := s.store.RecordUpstreamTest(ctx, u.ID, time.Now().UTC(), d.OK, u.UpdatedAt); {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		s.log.Debug("upstream test result not recorded: row changed or gone", "upstream_id", u.ID)
	default:
		s.log.Warn("could not record upstream test result", "upstream_id", u.ID, "error", err)
	}
}

// allowDiscovery spends one token from the outbound budget, and answers the
// caller when there is none.
//
// It is spent before the store is read, so a flood of unknown ids costs the
// same as a flood of real ones and neither reaches the single SQLite
// connection the proxy data plane shares. Nothing is refunded when the request
// turns out to make no outbound call: what this bounds is the route.
func (s *Server) allowDiscovery(w http.ResponseWriter) bool {
	ok, retry := s.discoverLimit.Consume(discoverBucket, discoverRPM)
	if !ok {
		tooManyRequests(w, retry, "too many discovery requests")
	}
	return ok
}
