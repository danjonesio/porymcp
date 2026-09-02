package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/netcasklabs/porymcp/internal/audit"
	"github.com/netcasklabs/porymcp/internal/auth"
	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/credential"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/mcpclient"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
	"github.com/netcasklabs/porymcp/internal/webutil"
)

type Handler struct {
	cfg *config.Config
	// keys is the process keyring, ENCRYPTION_KEY plus any previous keys.
	// Every stored credential is opened through internal/credential before a
	// request is built, and one that will not open is never dialled (PORM-52).
	keys   crypto.Keyring
	store  store.Store
	audit  *audit.Logger
	limit  *auth.Limiter
	log    *slog.Logger
	client *http.Client
}

func New(cfg *config.Config, st store.Store, al *audit.Logger, log *slog.Logger) *Handler {
	return &Handler{
		cfg:   cfg,
		keys:  cfg.Keyring(),
		store: st,
		audit: al,
		limit: auth.NewLimiter(),
		log:   log,
		// The no-redirect policy and the wrapped default transport are
		// mcpclient's, not this handler's: every client that carries an
		// upstream credential has them, and NewHTTPClient is the only place
		// they are set. See its comment for why.
		client: mcpclient.NewHTTPClient(mcpclient.Options{Timeout: 60 * time.Second}),
	}
}

func (h *Handler) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Session-Id, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Session-Id")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// KeyParam is the chi route parameter that carries a virtual key's id on the
// per-key proxy endpoint, and KeyRoute is that endpoint's pattern. cmd/server
// registers KeyRoute and ServeHTTP reads KeyParam; sharing the constants is
// what keeps the two from drifting. If they did, chi.URLParam would return ""
// and the endpoint-binding check in ServeHTTP would silently accept every key
// on every path.
const (
	KeyParam = "keyID"
	KeyRoute = "/{" + KeyParam + "}/mcp"
)

// SlugParam is the chi route parameter that carries an upstream's slug on a
// member endpoint, and MemberRoute is that endpoint's pattern. They share the
// constants above for the same reason KeyRoute and KeyParam do: a route and
// the lookup that reads it cannot be allowed to drift apart.
//
// A member endpoint gets its own handler rather than a "was a slug bound?"
// branch inside one. chi binds /{keyID}//mcp to this three-segment pattern
// with slug == "", so a test on the parameter's value would serve that URL as
// a second, undocumented aggregate endpoint. Which door was knocked on is a
// property of the registered route, so that is where it is read from.
const (
	SlugParam   = "slug"
	MemberRoute = "/{" + KeyParam + "}/{" + SlugParam + "}/mcp"
)

// ServeHTTP serves the shared door and the per-key aggregate endpoint: a group
// key gets the merged catalogue, a single-upstream key gets its one upstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.serve(w, r, false) }

// ServeMember serves MemberRoute: one enabled member of the key's group,
// 1:1, with nothing merged, synthesised or renamed.
func (h *Handler) ServeMember(w http.ResponseWriter, r *http.Request) { h.serve(w, r, true) }

// serve is both endpoints. memberPath says which route this request arrived
// on; everything else about the two is deliberately the same code.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, memberPath bool) {
	if h.applyCORS(w, r) {
		return
	}
	if !h.hostAllowed(r) {
		h.writeInvalidHost(w, r)
		return
	}

	start := time.Now()
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.NewString()
	}

	vk, err := h.authenticate(r)
	if err != nil {
		h.record(models.AuditLog{
			RequestID: requestID, Method: r.Method, Status: models.StatusBlocked,
			ErrorMessage: err.Error(), LatencyMS: int(time.Since(start).Milliseconds()),
		})
		status := http.StatusUnauthorized
		if errors.Is(err, errRateLimited) {
			status = http.StatusTooManyRequests
		}
		writeRPCError(w, status, nil, -32000, err.Error())
		return
	}
	if pathID := chi.URLParam(r, KeyParam); pathID != "" && pathID != vk.ID {
		h.finish(vk, requestID, r.Method, "", "", models.StatusBlocked, "virtual key does not match this endpoint", start, 0, nil)
		writeRPCError(w, http.StatusForbidden, nil, -32000, "virtual key does not match this endpoint")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, nil, -32000, "invalid body")
		return
	}

	// Parse before anything is dispatched or forwarded: a body that reaches an
	// upstream unparsed is a body no tool policy has seen. This runs on every
	// verb because forward replays the inbound method, so a DELETE carrying a
	// batch array would otherwise be relayed as one.
	req, rpcErr := parseRequest(body)
	if rpcErr != nil {
		// A rejection that got as far as decoding knows the method the client
		// claimed; one that did not records the HTTP verb, as the pre-auth
		// paths above do.
		methodForAudit := r.Method
		if req.Method != "" {
			methodForAudit = truncate(req.Method, auditFieldBytes)
		}
		h.finish(vk, requestID, methodForAudit, "", "", models.StatusError, rpcErr.Message, start, 0, nil)
		writeRPCError(w, http.StatusBadRequest, nil, rpcErr.Code, rpcErr.Message)
		return
	}
	method := req.Method
	tool, hasName := toolNameFromParams(req.Params)

	var (
		upstreams []*models.Upstream
		group     *models.Group
		member    *models.Upstream // nil on every path but MemberRoute
	)
	if memberPath {
		slug := chi.URLParam(r, SlugParam)
		member, group, err = h.resolveMember(r.Context(), vk, slug)
		if member == nil {
			// One answer for every miss: unknown, foreign, disabled, removed,
			// a single-upstream key, an empty group and a store failure are
			// all the same 404 with the same body, so a valid key cannot use
			// this route to find out which slugs the deployment has. The
			// operator's row and log line say which it was.
			//
			// A notification gets the envelope too, with "id":null. There is
			// nothing to correlate it against, but the endpoint does not exist,
			// so the status is the message, a 202 would tell a client its call
			// had been accepted by a server that is not there.
			size := writeRPCError(w, http.StatusNotFound, req.ID, -32000, "unknown endpoint")
			h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes), "",
				models.StatusBlocked, unknownEndpointReason(slug, err), start, size, boundedParams(req.Params))
			if h.log != nil {
				attrs := []any{
					"virtual_key_id", vk.ID,
					"virtual_key_name", vk.Name,
					"slug", truncate(slug, auditFieldBytes),
					"request_id", requestID,
				}
				if err != nil {
					// Only a genuine store failure carries an error; an
					// ordinary miss must not read like one.
					attrs = append(attrs, "err", err)
				}
				h.log.Warn("unknown member endpoint", attrs...)
			}
			return
		}
		// The member named in the URL is the only upstream this request can
		// reach, so the forward branch below needs no case of its own.
		upstreams = []*models.Upstream{member}
	} else {
		upstreams, group, err = h.resolveTargets(r.Context(), vk)
		if err != nil {
			// No upstream is contacted on this path (a valid key against a
			// disabled upstream or an empty group provokes it) so the row is
			// bounded like every other one the proxy writes for free.
			h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes), "", models.StatusError,
				truncate(err.Error(), auditFieldBytes), start, 0, nil)
			writeRPCError(w, http.StatusBadRequest, req.ID, -32000, err.Error())
			return
		}
	}

	// One gate for every tool rule, run here and nowhere else. It sits before
	// the dispatch below on purpose: a refused call must cost zero upstream
	// requests, both because the whole point is that the real credential is
	// never presented, and because a proxy that had to list a group's members
	// to decide would answer a denied name and a name that does not exist at
	// measurably different speeds.
	//
	// The two arms are not the same policy. tools/call gets everything. Any
	// other method that happens to carry a params.name (prompts/get,
	// resources/read) is judged by the key's own lists alone, which is
	// exactly the reach that check has had all along; a group's tool_filter
	// says nothing about prompts, and PORM-6 owns making that a real policy.
	// Methods carrying no name at all (initialize, tools/list, ping) fall
	// through both arms untouched: permits("") is false under any allowlist,
	// so gating them would take every key with an allowlist offline.
	//
	// A rule is written against a tool's identity (the member's slug and the
	// tool's own name) and the three endpoints spell that identity
	// differently. A group's aggregate endpoint advertises it whole, so the
	// name is split back into its halves; a member endpoint and a
	// single-upstream key show the tool's own name and name their upstream in
	// the route or the key, so the identity is composed from that. One entry
	// therefore means the same thing wherever it is enforced, which is the
	// whole point: an operator writes a rule about a tool, not about a URL.
	mode, slug := modeParse, ""
	switch {
	case member != nil:
		mode, slug = modeCompose, member.Slug
	case group == nil:
		mode, slug = modeCompose, upstreams[0].Slug
	}
	pol := newToolPolicy(group, vk, mode, slug)
	// onAggregate is the group's own endpoint: the one place a client names a
	// tool by its identity rather than by the name its upstream advertises.
	onAggregate := member == nil && group != nil
	blockedUpstream := "" // nothing is contacted on a group block, so nothing to name
	if group == nil || member != nil {
		// A member endpoint names its upstream in the URL, so the row can say
		// which credential the refused call was aimed at without contacting
		// anything, the single-upstream arm's argument, one route further on.
		blockedUpstream = upstreams[0].ID
	}
	switch {
	case method == "tools/call":
		if !hasName {
			// The MCP schema requires params.name, so this is a malformed
			// request rather than a policy decision, audited as an error, not as
			// a block, and still refused before anything is forwarded.
			h.finish(vk, requestID, truncate(method, auditFieldBytes), "", "", models.StatusError, "tools/call without a tool name", start, 0, boundedParams(req.Params))
			writeRPCError(w, http.StatusOK, req.ID, codeInvalidParams, "invalid params: tools/call requires a tool name")
			return
		}
		if onAggregate && !models.ValidToolIdentity(tool) {
			// Every tool a group endpoint advertises is spelled
			// {slug}__{tool}, so a name that is not one names nothing here and
			// is answered before the policy and before any member is asked.
			//
			// The check is purely syntactic: one strings.Index and one pass of
			// ValidSlug over the client's own string. It reads no group, no
			// member and no store, so a member's slug and a stranger's cost the
			// same and get the same answer, this route cannot be walked to find
			// out which upstreams sit behind a group.
			//
			// It sits before the policy because a name of the wrong shape is a
			// malformed request rather than a policy decision, which is the
			// same argument the missing-name branch above makes, and it is
			// audited as an error rather than a block for the same reason: no
			// rule fired, so an operator filtering for blocked calls is not
			// shown a probe for a name that never existed. The row still
			// carries the name, so the probing is visible to anyone looking.
			//
			// The echo is bounded because this path is free to provoke (nothing
			// is contacted, so the reply and the row are the only cost) and
			// truncate leaves no split rune behind. A notification gets the
			// envelope with "id":null, as writeRPCError does everywhere.
			size := writeRPCError(w, http.StatusOK, req.ID, codeInvalidParams, "unknown tool: "+truncate(tool, auditFieldBytes))
			h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes), "",
				models.StatusError, "unknown tool", start, size, boundedParams(req.Params))
			return
		}
		if by := pol.blockedBy(tool); by != "" {
			h.block(w, vk, requestID, req, tool, blockedUpstream, by, start)
			return
		}
	case tool != "":
		if by := pol.keyListsOnly().blockedBy(tool); by != "" {
			h.block(w, vk, requestID, req, tool, blockedUpstream, by, start)
			return
		}
	}

	var (
		respBody   []byte
		statusCode int
		headers    http.Header
		usedID     string
	)

	// The one line that decides dispatch. A member endpoint never aggregates:
	// it forwards, so initialize is the member's own, tools/list is the
	// member's own names, and its Mcp-Session-Id reaches the client.
	aggregated := onAggregate && shouldAggregate(method)
	if aggregated {
		respBody, statusCode, usedID, err = h.aggregate(r.Context(), r, pol, upstreams, req, body)
	} else {
		up := upstreams[0]
		usedID = up.ID
		respBody, statusCode, headers, err = h.forward(r.Context(), r, up, body)
		// Trim the catalogue to what the gate above would let this key call,
		// before the classification below, so the row records the size of the
		// body the client is actually sent.
		if method == "tools/list" && err == nil {
			respBody, headers = h.filterListResponse(respBody, statusCode, headers, pol, vk, up)
		}
	}

	if errors.Is(err, errUnknownTool) {
		// A name of the right shape that names no tool the group has. The
		// client is told the same thing the gate above tells it, and the row
		// keeps the message this path has always recorded, now bounded, since
		// the name is the client's and only the catalogue requests were spent
		// getting here.
		msg := "unknown tool: " + truncate(tool, auditFieldBytes)
		size := writeRPCError(w, http.StatusOK, req.ID, codeInvalidParams, msg)
		h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes), "",
			models.StatusError, msg, start, size, boundedParams(req.Params))
		return
	}
	if err != nil {
		// Bounded because the message is not always the proxy's own words: a
		// transport error quotes what the upstream sent (a malformed header
		// line, say) and http.Client.Do would quote an unparseable Location
		// the same way, a megabyte of it if the upstream sent a megabyte, were
		// upstreamTransport not dropping that header first.
		h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes),
			usedID, models.StatusError, truncate(err.Error(), auditFieldBytes), start, 0,
			boundedParams(req.Params))
		writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed")
		return
	}

	st := models.StatusSuccess
	errMsg := ""
	if statusCode >= 400 || rpcFailed(respBody) {
		st = models.StatusError
		errMsg = rpcErrorMessage(respBody)
	}
	// The relay path writes the widest row in the file and was the only one
	// left unbounded. errMsg is the upstream's own error.message, returned
	// verbatim out of a body allowed to be 16 MiB, so a hostile
	// 200 {"error":{"message":"<8 MiB>"}} wrote a multi-megabyte row on every
	// request; method and tool are the client's strings and params can be the
	// whole 8 MiB the reader admits.
	h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes),
		usedID, st, truncate(errMsg, auditFieldBytes), start, len(respBody),
		boundedParams(req.Params))
	_ = h.store.TouchVirtualKey(r.Context(), vk.ID)

	for k, vs := range headers {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(respBody)
}

func (h *Handler) hostAllowed(r *http.Request) bool {
	seen := webutil.RequestHost(r, h.cfg.TrustedProxies)
	return webutil.HostAllowed(seen, h.cfg.PublicURL, h.cfg.ExtraAllowedHosts, h.cfg.AllowLocalhost)
}

func (h *Handler) writeInvalidHost(w http.ResponseWriter, r *http.Request) {
	// http.Error would be text/plain; the operator needs JSON they can parse
	// and the seen/expected pair so a rewritten container Host is diagnosable.
	// CIDRs stay out of the body, only the resolved host values.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":    "invalid host",
		"seen":     webutil.RequestHost(r, h.cfg.TrustedProxies),
		"expected": webutil.ExpectedHost(h.cfg.PublicURL),
	})
}

func (h *Handler) authenticate(r *http.Request) (*models.VirtualKey, error) {
	token := auth.BearerToken(r)
	if token == "" {
		return nil, errUnauthorized
	}
	vk, err := h.store.GetVirtualKeyByLookup(r.Context(), auth.LookupDigest(token))
	if err != nil {
		return nil, errUnauthorized
	}
	if err := auth.VerifyKey(token, vk.KeyHash); err != nil {
		return nil, errUnauthorized
	}
	if vk.RevokedAt != nil {
		return nil, errRevoked
	}
	if vk.ExpiresAt != nil && time.Now().After(*vk.ExpiresAt) {
		return nil, errExpired
	}
	rpm := 0
	if vk.RateLimit != nil {
		rpm = *vk.RateLimit
	}
	if !h.limit.Allow(vk.ID, rpm) {
		return nil, errRateLimited
	}
	return vk, nil
}

func (h *Handler) resolveTargets(ctx context.Context, vk *models.VirtualKey) ([]*models.Upstream, *models.Group, error) {
	switch vk.TargetType {
	case models.TargetUpstream:
		u, err := h.store.GetUpstream(ctx, vk.TargetID)
		if err != nil {
			return nil, nil, err
		}
		if !u.Enabled {
			return nil, nil, errUpstreamDisabled
		}
		return []*models.Upstream{u}, nil, nil
	case models.TargetGroup:
		g, err := h.store.GetGroup(ctx, vk.TargetID)
		if err != nil {
			return nil, nil, err
		}
		var ups []*models.Upstream
		for _, id := range g.UpstreamIDs {
			u, err := h.store.GetUpstream(ctx, id)
			if err != nil || !u.Enabled {
				continue
			}
			ups = append(ups, u)
		}
		if len(ups) == 0 {
			return nil, nil, errNoUpstreams
		}
		return ups, g, nil
	default:
		return nil, nil, errInvalidTarget
	}
}

// resolveMember resolves the enabled group member a member endpoint names,
// and the group whose tool_filter applies to it. Every ordinary miss is the
// same miss, produced by the same walk: a key bound to a single upstream, a
// group that has gone or has no enabled members, a slug no upstream carries, a
// slug carried by an upstream outside this group, a disabled member, and a
// member removed from the group all return nil.
//
// It deliberately does not use store.GetUpstreamBySlug. A lookup across the
// deployment would make a slug that exists elsewhere cost one row read more
// than one that exists nowhere, and would need separate membership and enabled
// branches, three chances to answer differently, from a route a valid key can
// call once per candidate slug.
//
// err is non-nil only for a failure that is not a configuration state (not
// ErrNotFound, errUpstreamDisabled or errNoUpstreams). The client is told the
// same thing either way; the operator's row and log line say "resolve failed".
func (h *Handler) resolveMember(ctx context.Context, vk *models.VirtualKey, slug string) (*models.Upstream, *models.Group, error) {
	// The path segment is judged by the rule stored slugs are judged by,
	// before any lookup: "", "..", "%2f", a decoded NUL, "GitHub" and anything
	// over MaxSlugLen are not slugs, and asking the store about them would
	// only reveal what the caller already knows.
	if !models.ValidSlug(slug) {
		return nil, nil, nil
	}
	ups, group, err := h.resolveTargets(ctx, vk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, errUpstreamDisabled) || errors.Is(err, errNoUpstreams) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if group == nil {
		// A key bound to one upstream is served at its own /{keyID}/mcp; the
		// member form of that URL does not exist, even for its own slug.
		return nil, nil, nil
	}
	for _, up := range ups {
		if up.Slug == slug {
			return up, group, nil
		}
	}
	return nil, nil, nil
}

// unknownEndpointReason is the operator-facing half of the uniform 404: which
// of the misses this was. The slug is only repeated once it has passed
// ValidSlug, error_message is an unbounded column, and an unvalidated segment
// carrying a NUL would fail a Postgres insert and drop the row entirely.
func unknownEndpointReason(slug string, err error) string {
	switch {
	case err != nil:
		return "unknown endpoint: resolve failed"
	case models.ValidSlug(slug):
		return "unknown endpoint: " + slug
	default:
		return "unknown endpoint"
	}
}

// credential is the plaintext the proxy presents to an upstream, or the reason
// it must not dial: credential.ErrUndecryptable (no configured key opens the
// stored blob, ENCRYPTION_KEY changed) or errCredentialUnreadable (nothing
// stored, or nothing the auth type can send). auth_type none is (nil, nil) and
// never consults the blob. Both errors are bare sentinels, because they reach
// the audit row's error_message, which is not redacted; the client sees the
// generic 502 either way (see serve).
func (h *Handler) credential(u *models.Upstream) (json.RawMessage, error) {
	return credential.Read(h.keys, u.AuthType, u.AuthConfig)
}

// listToolsRequest is the body the proxy sends to discover what an upstream
// can do. The id is the proxy's own, because this is the proxy's request.
const listToolsRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

// forward relays the client's own request to an upstream: its verb, its hop
// headers and its body, with the virtual key swapped for the real credential.
// Everything the client sent that an upstream might act on reaches that
// upstream, which is exactly what makes it the wrong thing to use for a
// request the proxy makes on its own behalf. See listTools.
func (h *Handler) forward(ctx context.Context, inbound *http.Request, up *models.Upstream, body []byte) ([]byte, int, http.Header, error) {
	// Before the request exists: a credential that cannot be presented means
	// nothing is dialled, not a request with the virtual key stripped and
	// nothing put back, which is what a wrong ENCRYPTION_KEY used to send.
	plain, err := h.credential(up)
	if err != nil {
		return nil, 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, inbound.Method, up.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	copyHopHeaders(req.Header, inbound.Header)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", mcpclient.AcceptMCP)
	}
	if req.Header.Get("Content-Type") == "" && len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := mcpclient.ApplyAuth(req, up.AuthType, plain); err != nil {
		// Unreachable after credential(); kept so the seam cannot regress.
		return nil, 0, nil, errCredentialUnreadable
	}
	return mcpclient.Send(h.client, req, mcpclient.MaxBodyBytes)
}

// listTools asks one upstream what tools it advertises, using a request the
// proxy composes itself instead of a copy of the client's.
//
// Routing a group call means re-listing every member, and those catalogues
// decide which upstream a name resolves to. Discovering them with forward gave
// the client a vote in that: its Mcp-Session-Id, Accept, Last-Event-ID and
// Mcp-Protocol-Version were copied to every member, and a member that refused
// any of them was silently dropped from the merge. A bogus session id was
// enough to make a member's tools vanish from the catalogue, and, while an
// advertised name still depended on how many members answered, to move a tool
// out from under the rule written against it.
//
// Nothing legitimate is lost by composing the request here. A group endpoint
// never hands the client a member's session id (aggregate returns no upstream
// headers and answers initialize itself) so no working client holds a session
// for a member to recognise, and there is no client header a member could
// need. The Accept below is the one the reference servers require.
//
// An advertised name no longer moves at all: buildRoutes composes every one of
// them from the member's own slug. What a client can still reach depends on
// this call, because a member whose catalogue does not parse contributes no
// routes and its tools cannot be called until it does. PORM-32 owns routing a
// call by the slug the name carries, which removes the catalogue from the call
// path entirely.
func (h *Handler) listTools(ctx context.Context, up *models.Upstream) ([]byte, int, error) {
	plain, err := h.credential(up)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.URL, strings.NewReader(listToolsRequest))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", mcpclient.AcceptMCP)
	req.Header.Set("Content-Type", "application/json")
	if err := mcpclient.ApplyAuth(req, up.AuthType, plain); err != nil {
		return nil, 0, errCredentialUnreadable
	}
	body, status, _, err := mcpclient.Send(h.client, req, mcpclient.MaxBodyBytes)
	return body, status, err
}

// upstreamTransport is a type alias, not a defined type: the identifier is
// what TestProxyClientRefusesRedirectsByConstruction asserts h.client's
// transport to be, and that assertion is the proxy's own tripwire on a policy
// that now lives one package away. See mcpclient.UpstreamTransport.
type upstreamTransport = mcpclient.UpstreamTransport

// memberCatalogues lists every member of a group and returns those that
// answered with a readable catalogue, paired index for index with their tools.
//
// A member that fails is skipped rather than failing the whole request. That
// is the behaviour this endpoint has always had and it is deliberately kept:
// refusing every call while one member is unreachable would let a single
// outage take a whole group offline, and a member answering over SSE (the
// reference SDKs' default) is unreadable here today, so the outage would be
// permanent rather than transient.
//
// What a dropout costs is now confined to the member that dropped out: its own
// tools disappear from the catalogue and cannot be routed, and every other
// member's names are exactly what they were, because each is composed from its
// own slug. Routability is the part still tied to this walk, PORM-32 routes a
// call by the slug the name carries and takes the catalogue off the call path.
func (h *Handler) memberCatalogues(ctx context.Context, ups []*models.Upstream) ([]*models.Upstream, [][]mcpTool) {
	active := make([]*models.Upstream, 0, len(ups))
	lists := make([][]mcpTool, 0, len(ups))
	// A dropout is otherwise invisible: the row belongs to the client's
	// request, which succeeded on the survivors, so nothing anywhere says why
	// a member's tools are missing. Warn rather than Debug because a member
	// that cannot be listed stays unlistable (the commonest cause, a member
	// answering tools/list over SSE, is permanent) and a group quietly
	// serving fewer tools than it was built with is worth being loud about.
	// The error is bounded because a redirect's is the upstream's own string.
	skip := func(up *models.Upstream, err error) {
		if h.log == nil {
			return
		}
		h.log.Warn("group member skipped", "slug", up.Slug, "upstream_id", up.ID,
			"err", truncate(err.Error(), auditFieldBytes))
	}
	for _, up := range ups {
		// A 3xx is refused in mcpclient.Send, before there is a body to read,
		// so a member that answers its catalogue request with a redirect
		// arrives here as an error. Any other status is not consulted: a
		// catalogue is still judged by whether it parses, as it was before.
		listBody, _, err := h.listTools(ctx, up)
		if err != nil {
			skip(up, err)
			continue
		}
		tools, err := parseToolsList(listBody)
		if err != nil {
			skip(up, err)
			continue
		}
		active = append(active, up)
		lists = append(lists, tools)
	}
	return active, lists
}

func shouldAggregate(method string) bool {
	switch method {
	case "initialize", "tools/list", "tools/call", "notifications/initialized":
		return true
	default:
		return false
	}
}

// aggregate answers the four methods a group endpoint handles itself. It takes
// the already-parsed request rather than re-decoding the body: two decoders
// over the same bytes are two chances to disagree about which call this is,
// and the gate in ServeHTTP has already made its decision from the first one.
func (h *Handler) aggregate(ctx context.Context, inbound *http.Request, pol toolPolicy, ups []*models.Upstream, req rpcRequest, body []byte) ([]byte, int, string, error) {
	switch req.Method {
	case "notifications/initialized":
		return []byte(`{}`), http.StatusAccepted, ups[0].ID, nil
	case "initialize":
		result := map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "porymcp", "version": "0.1.0"},
		}
		return encodeRPC(req.ID, result, nil), http.StatusOK, ups[0].ID, nil
	case "tools/list":
		active, lists := h.memberCatalogues(ctx, ups)
		merged, _ := h.buildRoutes(active, lists)
		// The same policy the gate would apply to a call on each of these
		// names, so the catalogue and the call agree by construction.
		merged = filterTools(merged, pol)
		return encodeRPC(req.ID, map[string]any{"tools": merged}, nil), http.StatusOK, "", nil
	case "tools/call":
		// ok is not checked: ServeHTTP refuses a tools/call without a usable
		// name before it gets here.
		name, _ := toolNameFromParams(req.Params)
		// The catalogues that decide where this call goes are the proxy's own
		// requests, not replays of the client's: see listTools.
		active, lists := h.memberCatalogues(ctx, ups)
		_, routes := h.buildRoutes(active, lists)
		route, ok := routes[name]
		if !ok {
			// The name is a well-formed identity (serve refuses anything else
			// before this) but no member's catalogue holds it: a tool that has
			// gone, a member that could not be listed, or a slug belonging to no
			// member of this group. serve answers it, so that the reply and the
			// row are bounded there exactly as the gate's are.
			return nil, 0, "", errUnknownTool
		}
		// No policy check here. ServeHTTP gated this call on the same
		// advertised name before any upstream was contacted, so a check on
		// these bytes could only ever agree with it, which is why the one
		// that used to live here was unreachable, and why a group's filter
		// went unenforced with no audit row to show for it.
		rewritten := rewriteMethod(body, "tools/call", rewriteToolCallParams(req.Params, route.Original))
		out, status, _, err := h.forward(ctx, inbound, route.Upstream, rewritten)
		return out, status, route.Upstream.ID, err
	default:
		out, status, _, err := h.forward(ctx, inbound, ups[0], body)
		return out, status, ups[0].ID, err
	}
}

func rewriteMethod(original []byte, method string, params json.RawMessage) []byte {
	var req map[string]any
	if err := json.Unmarshal(original, &req); err != nil {
		req = map[string]any{"jsonrpc": "2.0", "id": 1}
	}
	req["method"] = method
	if params != nil {
		var p any
		_ = json.Unmarshal(params, &p)
		req["params"] = p
	}
	b, _ := json.Marshal(req)
	return b
}

func encodeRPC(id json.RawMessage, result any, rpcErr any) []byte {
	m := map[string]any{"jsonrpc": "2.0"}
	if len(id) > 0 {
		var v any
		_ = json.Unmarshal(id, &v)
		m["id"] = v
	} else {
		m["id"] = 1
	}
	if rpcErr != nil {
		m["error"] = rpcErr
	} else {
		m["result"] = result
	}
	b, _ := json.Marshal(m)
	return b
}

func rpcFailed(body []byte) bool {
	var env struct {
		Error *json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil {
		return false
	}
	return env.Error != nil
}

func rpcErrorMessage(body []byte) string {
	var env struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil || env.Error == nil {
		return ""
	}
	return env.Error.Message
}

// block refuses one call at the gate: it answers the client, records the row
// and returns. The caller must return too, falling through to the status
// classification below would let rpcFailed see the error member and relabel
// the row error, which is precisely the row an operator filtering for blocked
// calls would never find.
//
// A refused call reaches no upstream, so this audit write is the only cost of
// sending one, and everything client-controlled on the row is bounded before
// it is stored. The client is told "tool blocked" and nothing more; which rule
// fired goes to the operator's audit row and log, not to the caller.
func (h *Handler) block(w http.ResponseWriter, vk *models.VirtualKey, requestID string, req rpcRequest, tool, upstreamID, reason string, start time.Time) {
	tool = truncate(tool, auditFieldBytes)
	size := 0
	if len(bytes.TrimSpace(req.ID)) == 0 {
		// A notification has no id, so an error envelope would have nothing to
		// correlate against and an honest client would match it to whatever it
		// numbered 1. Acknowledge the delivery instead and say nothing.
		w.WriteHeader(http.StatusAccepted)
	} else {
		size = writeRPCError(w, http.StatusOK, req.ID, codeInvalidParams, "tool blocked")
	}
	h.finish(vk, requestID, truncate(req.Method, auditFieldBytes), tool, upstreamID, models.StatusBlocked, reason, start, size, boundedParams(req.Params))
	if h.log != nil {
		// No params: they are the one part of a request that routinely carries
		// the caller's secrets, and only the audit path redacts them.
		h.log.Warn("tool blocked",
			"virtual_key_id", vk.ID,
			"virtual_key_name", vk.Name,
			"method", truncate(req.Method, auditFieldBytes),
			"tool", tool,
			"reason", reason,
			"request_id", requestID,
		)
	}
}

func (h *Handler) finish(vk *models.VirtualKey, requestID, method, tool, upstreamID, status, errMsg string, start time.Time, size int, params json.RawMessage) {
	if h.audit == nil {
		return
	}
	h.audit.Record(models.AuditLog{
		VirtualKeyID:      vk.ID,
		VirtualKeyName:    vk.Name,
		Method:            method,
		ToolName:          tool,
		Params:            params,
		Status:            status,
		LatencyMS:         int(time.Since(start).Milliseconds()),
		ResponseSizeBytes: size,
		UpstreamID:        upstreamID,
		ErrorMessage:      errMsg,
		RequestID:         requestID,
	})
}

func (h *Handler) record(e models.AuditLog) {
	if h.audit != nil {
		h.audit.Record(e)
	}
}

// writeRPCError sends a JSON-RPC error envelope. The id is echoed as raw bytes
// rather than round-tripped through any: decoding an id into an interface
// turns a large integer into a float and invents an id for a request that
// never carried one, and a client that cannot match the error to its request
// waits for a reply that will never arrive. An absent or non-scalar id becomes
// null, which is what JSON-RPC prescribes when the id is unknowable.
//
// It returns the number of bytes written, which is what the blocked path
// records as response_size_bytes. Callers with nothing to record ignore it.
func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) int {
	if len(bytes.TrimSpace(id)) == 0 || !scalarRPCID(id) {
		id = json.RawMessage("null")
	}
	// Encoded into a buffer rather than straight onto the wire only so the
	// length is knowable; the bytes are identical either way, and a body that
	// fails to encode is still no body at all.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcError        `json:"error"`
	}{JSONRPC: "2.0", ID: id, Error: rpcError{Code: code, Message: msg}}); err != nil {
		buf.Reset()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, _ := w.Write(buf.Bytes())
	return n
}

// errUnknownTool is aggregate's answer for a call that resolved to no member.
// It is an error value rather than a ready-made body so that the one place
// that can bound a client-controlled string against the audit row (serve)
// writes both the reply and the row, and so that this refusal and the gate's
// cannot drift into telling a client two different things.
var errUnknownTool = errors.New("unknown tool")

// A stored credential stops a request before it is built for two reasons
// (PORM-52), both the credential package's own bare sentinels, which reach the
// audit row's error_message as exactly their text: credential.ErrUndecryptable
// ("credential undecryptable" (no configured key opens the blob), which
// propagates out of credential.Read untouched, and credential.ErrUnreadable
// ("credential unreadable") it opens to nothing the auth type can send),
// aliased below for the ApplyAuth defence-in-depth returns. The client is told
// "upstream request failed" like any other 502: a key holder must not learn
// that the operator's encryption key is wrong (docs/07-security.md).
var errCredentialUnreadable = credential.ErrUnreadable

var (
	errUnauthorized     = errors.New("invalid virtual key")
	errRevoked          = errors.New("virtual key revoked")
	errExpired          = errors.New("virtual key expired")
	errRateLimited      = errors.New("rate limit exceeded")
	errUpstreamDisabled = errors.New("upstream is disabled")
	errNoUpstreams      = errors.New("group has no enabled upstreams")
	errInvalidTarget    = errors.New("invalid virtual key target")
)
