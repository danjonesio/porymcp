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
	"sync/atomic"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
	// present is Read plus the OAuth refresh (PORM-139). It is built on a
	// client of its own with the discovery backstop, because a token call is
	// bounded by a timeout and not by a relayed stream's context; the lock
	// it refreshes under is package state shared with the API's Presenter.
	present *credential.Presenter
	// eras remembers which MCP era each upstream speaks, so a group call asks
	// server/discover once and not on every walk. In memory only: nothing an
	// upstream said is persisted (PORM-58).
	eras *eraCache
	// streams is done once StopStreams has run; every relayed stream watches
	// it (relayStream). openStreams counts the streams open right now, for the
	// two log lines that are the only place they can be seen.
	streams     context.Context
	stopStreams context.CancelFunc
	openStreams atomic.Int64
}

func New(cfg *config.Config, st store.Store, al *audit.Logger, log *slog.Logger) *Handler {
	streams, stop := context.WithCancel(context.Background())
	keys := cfg.Keyring()
	return &Handler{
		cfg:         cfg,
		keys:        keys,
		present:     credential.NewPresenter(keys, st, mcpclient.New(cfg.UpstreamGuard), log),
		store:       st,
		audit:       al,
		limit:       auth.NewLimiter(),
		log:         log,
		streams:     streams,
		stopStreams: stop,
		// The no-redirect policy and the wrapped default transport are
		// mcpclient's, not this handler's: every client that carries an
		// upstream credential has them, and NewHTTPClient is the only place
		// they are set. See its comment for why. No timeout: a relayed event
		// stream stays open for as long as the upstream and the client keep
		// it, and every request is bounded by its context instead (budget.go).
		// The address guard's two switches are config's (PORM-79); the
		// presenter's client above carries the same value.
		client: mcpclient.NewHTTPClient(mcpclient.Options{Guard: cfg.UpstreamGuard}),
		eras:   newEraCache(),
	}
}

// allowedMethods is both sides of one rule: the Allow header on the 405 in
// serve and on the OPTIONS 204 below, and the Access-Control-Allow-Methods
// that applyCORS advertises. POST carries every JSON-RPC call and DELETE is
// a session teardown. A Streamable HTTP client opens GET after initialize to
// listen for server-initiated messages; PoryMCP proxies none, so the honest
// answer is a 405 rather than a forward that ends at the upstream timeout.
// For a browser the entry that matters is DELETE: GET, HEAD and POST are
// CORS-safelisted methods, which a preflight never refuses on this header,
// so naming GET or not changes nothing on the wire and the two headers are
// kept equal so they cannot disagree. GET stays out: in the 2026-07-28
// revision a server's messages arrive on the response to a POST, which the
// relay streams (stream.go). A verb added later changes the header and the
// handler together, which is why they share this.
const allowedMethods = "POST, DELETE, OPTIONS"

// allowedHeaders is the fixed half of the endpoint's Access-Control-Allow-
// Headers: the names a browser client may send on every request, the
// 2026-07-28 routing headers included. The mirrored Mcp-Param- names are
// known only from a preflight's own request, so applyCORS appends those per
// answer. The clear-text refusal (webutil.writeInsecureScheme) writes a list
// of its own on purpose, docs/07-security.md records why, and it is widened
// by the same two names, never merged with this one.
const allowedHeaders = "Authorization, Content-Type, Accept, MCP-Session-Id, Mcp-Session-Id, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Last-Event-ID"

// door is what differs between the MCP doors (/mcp) and the HTTP relay doors
// (/api/, PORM-146) inside the shared prelude, admit. Everything a door does
// not name is the same code on both: the two cannot drift on host checking,
// authentication or the key-versus-path rule, because there is one copy.
type door struct {
	allow   string // Allow on the 405 and on a preflight, and Access-Control-Allow-Methods
	headers string // Access-Control-Allow-Headers
	expose  string // Access-Control-Expose-Headers
	// mirrorParams is the MCP doors' reflection of Mcp-Param- names on a
	// preflight (paramHeaderNames); the relay door reflects nothing.
	mirrorParams bool
	// retryAfter writes Retry-After on the 429 from the wait the limiter
	// computed. The relay door does; the MCP doors keep their bytes.
	retryAfter bool
	// boundRequestID truncates a client's X-Request-Id to auditFieldBytes
	// before it reaches a row or an error body. The relay door does; the MCP
	// doors keep their bytes.
	boundRequestID bool
	// keyRequired refuses a request whose route bound an empty key id (chi
	// binds //api/x with keyID "") with the uniform 404. The MCP doors keep
	// today's behaviour, where an empty path key skips the check.
	keyRequired bool
	// refusalSize records the wrong-key 403's body length on its row. The
	// relay door does; the MCP doors keep the 0 serve recorded before admit
	// existed, so their rows do not change.
	refusalSize bool
	// tool, when set, is what the rows admit itself writes (the 401, the 429
	// and the wrong-key 403) record as tool_name: on the relay door the
	// bounded escaped path, so every relay row starts with "/". Computed from
	// the request alone, before authentication. nil on the MCP doors.
	tool   func(r *http.Request) string
	verbOK func(method string) bool
	// refuse writes the door's refusal body: a JSON-RPC envelope on the MCP
	// doors, plain JSON with request_id on the relay door. It returns the
	// bytes written.
	refuse func(w http.ResponseWriter, status int, requestID, msg string) int
}

// mcpDoor is the /mcp doors as they always were. The values are the ones
// serve wrote inline before the prelude was shared, and every existing proxy
// test passes unmodified against them.
var mcpDoor = door{
	allow:        allowedMethods,
	headers:      allowedHeaders,
	expose:       "Mcp-Session-Id, MCP-Session-Id, Retry-After",
	mirrorParams: true,
	verbOK:       func(m string) bool { return m == http.MethodPost || m == http.MethodDelete },
	refuse: func(w http.ResponseWriter, status int, _ string, msg string) int {
		return writeRPCError(w, status, nil, -32000, msg)
	},
}

// admitted is what the prelude hands the door that called it: the request
// with the audit id on its context, the authenticated key, the plaintext the
// client presented (the relay door sweeps it out of outbound headers and
// redacts it from the row), the id, the door's tool_name and the clock.
type admitted struct {
	r         *http.Request
	vk        *models.VirtualKey
	token     string
	requestID string
	tool      string
	start     time.Time
}

// admit is every step both doors take before anything door-specific, in the
// order serve always took them: Cache-Control: no-store; the CORS block and
// the preflight; the host check; the verb check (before the key is read, so a
// probe with no credential buys no audit row and cannot tell a live key from
// a dead one; the request id does not exist yet, so a 405 body carries none
// on either door); the request id; authentication with its blocked row; the
// key-versus-path rule. ok is false when the request was answered here.
func (h *Handler) admit(w http.ResponseWriter, r *http.Request, d door) (admitted, bool) {
	// Every proxy response is uncacheable. The upstream's own Cache-Control is
	// not relayed (copyResponseHeaders): a per-key answer an upstream marked
	// cacheable would be stored against a URL that does not name the key on
	// the shared /mcp door. Written here rather than beside the relay so the
	// refusal paths and the preflight carry it too (uniformity, not a leak
	// today: a preflight cache reads Access-Control-Max-Age, not this) and so
	// the streaming relay inherits it before its first write.
	w.Header().Set("Cache-Control", "no-store")
	if h.applyCORS(w, r, d) {
		return admitted{}, false
	}
	if !h.hostAllowed(r) {
		h.writeInvalidHost(w, r)
		return admitted{}, false
	}

	// Refused on the verb alone, before the key is read. On the MCP doors
	// anything other than a POST or a DELETE, the GET a Streamable HTTP
	// client opens after initialize included, is answered here rather than
	// replayed to the upstream with the real credential attached, which is
	// what forward does with any verb it is handed. The answer is the same
	// with a valid key, a wrong one and none, so a GET can no longer tell a
	// caller whether a key is live, and no upstream round trip and no audit
	// row is spent on a probe that presents no credential; requestLogger in
	// cmd/server records it. After applyCORS so a preflight keeps its 204,
	// and after the host check so a rewritten Host is diagnosed the same way
	// on every verb. Allow goes on before the refusal, which commits the
	// header block. GET stays refused on the MCP doors: in the 2026-07-28
	// revision a server's messages arrive on the response to a POST, which
	// the relay streams (stream.go), and a server may answer GET with 405 in
	// every revision.
	if !d.verbOK(r.Method) {
		w.Header().Set("Allow", d.allow)
		d.refuse(w, http.StatusMethodNotAllowed, "", "method not allowed")
		return admitted{}, false
	}

	start := time.Now()
	requestID := r.Header.Get("X-Request-Id")
	if d.boundRequestID {
		requestID = truncate(requestID, auditFieldBytes)
	}
	if requestID == "" {
		requestID = uuid.NewString()
	}
	// The id the audit row will carry rides the context, so a token refresh
	// made on this request's behalf (credential) records the same id and
	// the Logs page can join the two.
	r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, requestID))
	tool := ""
	if d.tool != nil {
		tool = d.tool(r)
		// A caller that put its key in the path would otherwise write it
		// into tool_name on the rows admit itself records, before the door
		// gets to refuse the request for exactly that.
		if tok := auth.BearerToken(r); tok != "" && strings.Contains(tool, tok) {
			tool = "/[redacted]"
		}
	}

	vk, wait, err := h.authenticate(r)
	if err != nil {
		h.record(models.AuditLog{
			RequestID: requestID, Method: r.Method, ToolName: tool, Status: models.StatusBlocked,
			ErrorMessage: err.Error(), LatencyMS: int(time.Since(start).Milliseconds()),
		})
		status := http.StatusUnauthorized
		if errors.Is(err, errRateLimited) {
			status = http.StatusTooManyRequests
			if d.retryAfter {
				w.Header().Set("Retry-After", webutil.RetryAfterSeconds(wait))
			}
		}
		d.refuse(w, status, requestID, err.Error())
		return admitted{}, false
	}
	pathID := chi.URLParam(r, KeyParam)
	if pathID == "" && d.keyRequired {
		// The keyless binding is not a door: same body as every other miss, so
		// a valid key cannot use it to learn anything.
		size := d.refuse(w, http.StatusNotFound, requestID, "unknown endpoint")
		h.finish(vk, requestID, r.Method, tool, "", models.StatusBlocked, "unknown endpoint: no key in path", start, size, nil)
		return admitted{}, false
	}
	if pathID != "" && pathID != vk.ID {
		size := d.refuse(w, http.StatusForbidden, requestID, "virtual key does not match this endpoint")
		if !d.refusalSize {
			size = 0
		}
		h.finish(vk, requestID, r.Method, tool, "", models.StatusBlocked, "virtual key does not match this endpoint", start, size, nil)
		return admitted{}, false
	}
	return admitted{r: r, vk: vk, token: auth.BearerToken(r), requestID: requestID, tool: tool, start: start}, true
}

// applyCORS writes the door's CORS block when the request carries an Origin,
// and answers a preflight. Every name in a door's Access-Control-Expose-
// Headers is one that door vetted on its response copier; Content-Type needs
// no entry because it is CORS-safelisted.
func (h *Handler) applyCORS(w http.ResponseWriter, r *http.Request, d door) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", d.headers)
		w.Header().Set("Access-Control-Allow-Methods", d.allow)
		w.Header().Set("Access-Control-Expose-Headers", d.expose)
		// A preflight asking to send mirrored parameters is answered with
		// their names, in the spelling the proxy produced and only when the
		// whole set is within the bound (paramHeaderNames). This is the one
		// place client input is reflected into a response header, and it
		// runs before authentication, so it is confined to OPTIONS on the MCP
		// doors: the block above is written on every request carrying an
		// Origin and nothing else in it comes from the client. Vary is
		// untouched. The answer depends on Access-Control-Request-Headers,
		// but admit has already written Cache-Control: no-store, so no shared
		// cache keys on it, and Set would drop Origin.
		if d.mirrorParams && r.Method == http.MethodOptions {
			if names := paramHeaderNames(r.Header.Values("Access-Control-Request-Headers")); len(names) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", d.headers+", "+strings.Join(names, ", "))
			}
		}
	}
	if r.Method == http.MethodOptions {
		// A successful OPTIONS names the methods the resource supports (RFC
		// 9110), Origin or not; the CORS block above is the browser's copy.
		w.Header().Set("Allow", d.allow)
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

// auditMethodFor is what an audit row records as the method: the JSON-RPC
// method when the body carried one, bounded like every other row field, and
// the HTTP verb when it did not. parseRequest accepts a body with no method
// member: a session teardown is a DELETE with an empty body, an operator's
// curl is a POST with none, and a tools/call shaped body can name a tool
// without naming a method. All of those recorded "", which the Logs filter
// matches exactly and so could never find. Only the audit value: the
// dispatch value stays req.Method and is compared byte-exactly downstream.
func auditMethodFor(r *http.Request, method string) string {
	if method == "" {
		return r.Method
	}
	return truncate(method, auditFieldBytes)
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
	a, ok := h.admit(w, r, mcpDoor)
	if !ok {
		return
	}
	r, vk, requestID, start := a.r, a.vk, a.requestID, a.start
	var err error

	// The bound on what the proxy forwards blind, before the body is read so
	// a header flood does not also buy an 8 MiB read, and after authenticate
	// so an unauthenticated caller buys no audit row outside the key's rate
	// limit. It is a size limit and not a mismatch, so the status is 431 and
	// the code is the proxy's own: a 400 whose body is not a recognised
	// modern error is the signal on which a dual-era client abandons the
	// 2026-07-28 protocol for the whole connection. Nothing has been read, so
	// the row records the verb and the reply carries no id.
	if rpcErr := checkParamHeaders(r.Header); rpcErr != nil {
		n := writeRPCError(w, http.StatusRequestHeaderFieldsTooLarge, nil, rpcErr.Code, rpcErr.Message)
		h.finish(vk, requestID, auditMethodFor(r, ""), "", "", models.StatusError, rpcErr.Message, start, n, nil)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
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
		// paths above do (auditMethodFor).
		auditMethod := auditMethodFor(r, req.Method)
		h.finish(vk, requestID, auditMethod, "", "", models.StatusError, rpcErr.Message, start, 0, nil)
		writeRPCError(w, http.StatusBadRequest, nil, rpcErr.Code, rpcErr.Message)
		return
	}
	method := req.Method
	// auditMethod is what every row below records; method itself decides
	// dispatch and stays exactly what the body said.
	auditMethod := auditMethodFor(r, method)
	fields := decodeRoutingFields(req.Params)
	tool, hasName := fields.toolName()

	// The 2026-07-28 revision's routing headers, held to the body just read.
	// The tool policy below still reads the body and only the body; this
	// runs first, before any member or upstream is resolved, so a refused
	// request costs one audit write and presents no credential, and so a
	// strict tools/call that omits params.name but sends Mcp-Name answers
	// -32020 here while one that sends neither reaches the -32602 below. A
	// DELETE, or an empty body, has method == "" and is not compared. The
	// message names the header and never its value; the row carries the
	// bounded tool name and the method, as the unknown-shape refusal's does,
	// so a probe that swaps a block for this row is still visible.
	if rpcErr := checkRoutingHeaders(r.Header, method, fields); rpcErr != nil {
		n := writeRPCError(w, http.StatusBadRequest, req.ID, rpcErr.Code, rpcErr.Message)
		h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "", models.StatusError, rpcErr.Message, start, n, boundedParams(req.Params))
		return
	}
	// Which era the client speaks, by the version it declared. Asked of the
	// same function the check above used, so for a request with a method the
	// two cannot disagree and the error, already refused above, is nil. A
	// request with no method (a DELETE, a body that names none) is one the
	// check above returns on before it asks, as it always has, so here an
	// unreadable declaration can still come back: it is read as no declaration,
	// which is the handshake era, and the request goes on as it did before this
	// function existed. The group endpoint is a server in both eras and answers
	// each in its own shape; a request with no method is relayed, under the
	// same two rules below as any other relayed request.
	declared, _ := declaredVersion(r.Header, fields)
	clientModern := strictRevision(declared)

	var (
		upstreams []*models.Upstream
		group     *models.Group
		member    *models.Upstream // nil on every path but MemberRoute
	)
	if memberPath {
		slug := chi.URLParam(r, SlugParam)
		member, group, err = h.resolveMember(r.Context(), vk, slug, models.KindMCP)
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
			h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "",
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
		upstreams, group, err = h.resolveTargets(r.Context(), vk, models.KindMCP)
		if errors.Is(err, errKindMismatch) {
			// A key bound to one HTTP API upstream is served at its /api/
			// door; its /mcp door does not exist. The same uniform 404 as a
			// member miss, and no credential work has happened.
			size := writeRPCError(w, http.StatusNotFound, req.ID, -32000, "unknown endpoint")
			h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "",
				models.StatusBlocked, err.Error(), start, size, boundedParams(req.Params))
			return
		}
		if err != nil {
			// No upstream is contacted on this path (a valid key against a
			// disabled upstream, an empty group or a group with no MCP member
			// provokes it) so the row is bounded like every other one the
			// proxy writes for free.
			h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "", models.StatusError,
				truncate(err.Error(), auditFieldBytes), start, 0, nil)
			writeRPCError(w, http.StatusBadRequest, req.ID, -32000, err.Error())
			return
		}
	}

	// A stored transport the proxy cannot dial (sse, or a hand-edited value)
	// is refused here, before any dispatch, and nothing below is reached.
	// upstreams holds the single member, the single target, or the group's
	// enabled members, so one loop covers member URLs, single keys and every
	// aggregate method, initialize included.
	//
	// Why here and not in resolveTargets: that path answers 400 with the
	// error text on the JSON-RPC body and turns a member lookup into
	// 404 unknown endpoint, which would take the group's healthy members
	// offline and hand the key holder the sentence. Why before dispatch and
	// not only in forward and listTools: the aggregate initialize never
	// dials, and memberCatalogues skips a member whose listing fails, so a
	// group with an sse member would answer a 200 partial catalogue and no
	// audit row would ever name the cause, the silent failure PORM-28
	// forbids. A group therefore fails on its aggregate endpoint while an
	// enabled member is sse; the other members' own endpoints keep working.
	//
	// The client body stays the generic 502: operator configuration is not
	// the key holder's to learn, and docs/07-security.md promises one shape
	// for every upstream failure. The audit row carries the fixed sentence
	// and the row's id, which is what the operator needs and no more than
	// the undecryptable-credential arm records. A row that worked because its
	// URL already spoke Streamable HTTP now fails until transport is set to
	// streamable-http; that is the one-field repair the changelog and the
	// startup WARN name.
	for _, up := range upstreams {
		if err := mcpclient.TransportError(up.Transport); err != nil {
			h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes),
				up.ID, models.StatusError, truncate(err.Error(), auditFieldBytes), start, 0,
				boundedParams(req.Params))
			writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed")
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
	// On the group endpoint PoryMCP is the server, and its server/discover says
	// which stateless revision it speaks: one. strictRevision accepts any date
	// from that one onward, so a request declaring a later revision would
	// otherwise be served as if PoryMCP spoke it. The revision makes this
	// refusal a MUST and names its data. requested is written back only because
	// strictRevision has just proved it a ten-byte date. Header validation has
	// already run and the method is not looked at yet, which is the order a
	// client can observe. No member is contacted and the row names none. A
	// single-upstream key and a member endpoint relay, and the upstream
	// answers for itself.
	if onAggregate && clientModern && declared != mcpclient.RevisionModern {
		out := answerRPC(req.ID, nil, &rpcError{
			Code: codeUnsupportedVersion, Message: msgUnsupportedVersion,
			Data: map[string]any{"supported": []string{mcpclient.RevisionModern}, "requested": declared},
		})
		n := writeRPCBody(w, http.StatusBadRequest, out)
		h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "", models.StatusError, msgUnsupportedVersion, start, n, boundedParams(req.Params))
		return
	}
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
			h.finish(vk, requestID, auditMethod, "", "", models.StatusError, "tools/call without a tool name", start, 0, boundedParams(req.Params))
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
			h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "",
				models.StatusError, "unknown tool", start, size, boundedParams(req.Params))
			return
		}
		if by := pol.blockedBy(tool); by != "" {
			h.block(w, vk, requestID, req, auditMethod, tool, blockedUpstream, by, start)
			return
		}
	case tool != "":
		if by := pol.keyListsOnly().blockedBy(tool); by != "" {
			h.block(w, vk, requestID, req, auditMethod, tool, blockedUpstream, by, start)
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
		respBody, statusCode, headers, usedID, err = h.aggregate(r.Context(), r, pol, upstreams, req, fields, clientModern, body)
	} else {
		up := upstreams[0]
		usedID = up.ID
		// A method the group endpoint neither answers nor refuses goes to the
		// group's first member, as it always has. One header of a handshake-era
		// client's does not go with it. The version such a client declares on
		// every request is the one this endpoint's initialize agreed to, and it
		// agreed for itself: no member was asked. It used to answer 2024-11-05
		// whatever was requested; it now answers up to 2025-11-25, and the
		// handshake transport says a member MUST refuse a version it does not
		// support, so a first member on an older revision would start refusing
		// logging/setLevel the day this shipped. Without the header the member
		// reads the request as it reads the proxy's own catalogue request. A
		// modern client's request crosses as it came, and so does everything on
		// a member endpoint and a single-upstream key, where the client and the
		// upstream negotiated with each other.
		var relay *memberHeaders
		if onAggregate && !clientModern {
			relay = &memberHeaders{drop: []string{hdrProtocol}}
		}
		sent := body
		var memberModern bool
		// The credential first, before the era probe and before the budget is
		// armed (upstreamContext): for an oauth row this may renew the token
		// at the vendor, and that call must run neither on the budget's
		// context (its trace hook would stop the upstream's connect timer)
		// nor after the connect timer has started counting.
		var plain json.RawMessage
		if err == nil {
			plain, err = h.credential(r.Context(), up)
		}
		if err == nil && onAggregate && clientModern {
			// Only a modern client's request changes with the member's era,
			// so only that client can cost a member a probe, through
			// memberEra, which caches whatever it learns: one server/discover
			// per member per eraTTL for callers in sequence, per eraRetry
			// while the member does not answer, and one per caller when
			// several miss at once, as on the catalogue walk. Nothing walks
			// the catalogue on a relay, and the merged list lets a client
			// cache it for an hour, so the cache is cold here in an ordinary
			// flow. A member the cache then holds as handshake-era is sent
			// what a routed call sends it: no version header, whatever the
			// method, and no reserved _meta member. Every other value the
			// client sent crosses as sent, and a body with nothing to strip,
			// or with no method, crosses untouched.
			verdict, known := h.eras.get(up.ID, up.UpdatedAt)
			if !known {
				// The same plaintext forward presents, so the two agree.
				verdict, known = h.memberEra(r.Context(), up, plain), true
			}
			memberModern = verdict.era == mcpclient.EraModern
			if legacyStrip(verdict, known, clientModern) {
				relay = &memberHeaders{drop: []string{hdrProtocol}}
				if params, changed := stripReservedMeta(req.Params); changed && method != "" {
					sent = replaceParams(body, params)
				}
			}
		}
		if err == nil {
			// One request, one budget: five minutes for a buffered answer or
			// for a stream's headers, and the connect budget in front of it
			// (upstreamContext). A buffered answer releases the budget as soon
			// as the body is read; a stream disarms the answer timer once the
			// headers are in and holds the context for as long as it lives. A
			// budget that fired is the sentence the row records (causeError).
			ctx, disarm, cancel := upstreamContext(r.Context(), answerBudget)
			var resp *http.Response
			resp, err = h.forward(ctx, r, up, plain, sent, relay)
			switch {
			case err != nil:
				err = causeError(ctx, err)
				cancel(nil)
			case streamable(onAggregate, method, resp):
				disarm()
				h.relayStream(w, r, ctx, cancel, resp, streamRow{
					vk: vk, requestID: requestID, method: method, auditMethod: auditMethod,
					tool: truncate(tool, auditFieldBytes), upstreamID: up.ID, upstream: up,
					params: boundedParams(req.Params), start: start,
					wantID:     strings.TrimSpace(string(req.ID)),
					memberPath: memberPath, slug: chi.URLParam(r, SlugParam),
				})
				return
			default:
				respBody, statusCode, headers, err = mcpclient.ReadBody(resp, mcpclient.MaxBodyBytes)
				if err != nil {
					err = readFailed(ctx, err)
				}
				cancel(nil)
			}
		}
		if onAggregate && err == nil {
			// On this endpoint PoryMCP is the server: the member's answer is
			// read as a routed call's is. Nothing is completed for a request
			// with no id member: a DELETE or a notification asked for no
			// result. An unreduced event stream is read once more by
			// answerStatus below, for the row only; labelling it JSON to
			// spare that read would tell the client a lie about its shape.
			respBody, headers, err = h.groupAnswer(up, auditMethod, statusCode, sent, respBody, headers,
				clientModern && !memberModern && len(bytes.TrimSpace(req.ID)) > 0)
		}
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
		h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes), "",
			models.StatusError, msg, start, size, boundedParams(req.Params))
		return
	}
	if err != nil {
		// A refusal by the address guard arrives as the bare class sentence
		// (mcpclient's open unwraps it) and is the one transport error that
		// also gets a log line.
		var denied netguard.Denied
		if errors.As(err, &denied) {
			h.warnDenied(usedID, requestID, denied.Class)
		}
		// The message is one of the proxy's own sentences: a transport
		// failure was read into the closed set where the client returned it
		// (forward, forwardRead, the ReadBody above), and every other error
		// on this path is a fixed sentence of this package's. Still bounded,
		// because a member's own error.message can arrive on the aggregate
		// path (PORM-72) and is the upstream's string.
		h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes),
			usedID, models.StatusError, truncate(err.Error(), auditFieldBytes), start, 0,
			boundedParams(req.Params))
		writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed")
		return
	}

	st, errMsg := answerStatus(statusCode, headers.Get("Content-Type"), respBody, strings.TrimSpace(string(req.ID)))
	// The relay path writes the widest row in the file and was the only one
	// left unbounded. errMsg is the upstream's own error.message, returned
	// verbatim out of a body allowed to be 16 MiB, so a hostile
	// 200 {"error":{"message":"<8 MiB>"}} wrote a multi-megabyte row on every
	// request; method and tool are the client's strings and params can be the
	// whole 8 MiB the reader admits.
	h.finish(vk, requestID, auditMethod, truncate(tool, auditFieldBytes),
		usedID, st, truncate(errMsg, auditFieldBytes), start, len(respBody),
		boundedParams(req.Params))
	_ = h.store.TouchVirtualKey(r.Context(), vk.ID)

	copyResponseHeaders(w.Header(), headers)
	// A label on no bytes is a claim about nothing: the group endpoint's 202 to
	// a notification has no body in either era, and gets no media type.
	if w.Header().Get("Content-Type") == "" && len(respBody) > 0 {
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

// authenticate resolves the presented virtual key, or the reason it is refused.
// wait is the limiter's own answer to a rate-limited caller, which the relay
// door writes as Retry-After; the MCP doors ignore it.
func (h *Handler) authenticate(r *http.Request) (vk *models.VirtualKey, wait time.Duration, err error) {
	token := auth.BearerToken(r)
	if token == "" {
		return nil, 0, errUnauthorized
	}
	vk, err = h.store.GetVirtualKeyByLookup(r.Context(), auth.LookupDigest(token))
	if err != nil {
		return nil, 0, errUnauthorized
	}
	if err := auth.VerifyLookup(token, vk.KeyLookup); err != nil {
		return nil, 0, errUnauthorized
	}
	if vk.RevokedAt != nil {
		return nil, 0, errRevoked
	}
	if vk.ExpiresAt != nil && time.Now().After(*vk.ExpiresAt) {
		return nil, 0, errExpired
	}
	rpm := 0
	if vk.RateLimit != nil {
		rpm = *vk.RateLimit
	}
	if ok, retry := h.limit.Consume(vk.ID, rpm); !ok {
		return nil, retry, errRateLimited
	}
	return vk, 0, nil
}

// resolveTargets is the upstreams a key can reach through a door of kind
// want, and the group when the key is bound to one. The kind filter lives
// here and nowhere else (PORM-146): each door serves only rows whose kind is
// exactly its own constant, so a stored value that is neither (a hand-edited
// row) is served on no door, which is also what internal/api's endpointsFor
// mirrors. A single upstream of another kind is errKindMismatch, the uniform
// 404; a group whose enabled members are all of another kind is
// errNoMCPMembers on the MCP door and, like any group, a 404 on the relay
// door, which serves members by slug only.
func (h *Handler) resolveTargets(ctx context.Context, vk *models.VirtualKey, want string) ([]*models.Upstream, *models.Group, error) {
	switch vk.TargetType {
	case models.TargetUpstream:
		u, err := h.store.GetUpstream(ctx, vk.TargetID)
		if err != nil {
			return nil, nil, err
		}
		if !u.Enabled {
			return nil, nil, errUpstreamDisabled
		}
		if u.Kind != want {
			return nil, nil, errKindMismatch
		}
		return []*models.Upstream{u}, nil, nil
	case models.TargetGroup:
		g, err := h.store.GetGroup(ctx, vk.TargetID)
		if err != nil {
			return nil, nil, err
		}
		var ups []*models.Upstream
		otherKind := 0
		for _, id := range g.UpstreamIDs {
			u, err := h.store.GetUpstream(ctx, id)
			if err != nil || !u.Enabled {
				continue
			}
			if u.Kind != want {
				otherKind++
				continue
			}
			ups = append(ups, u)
		}
		if len(ups) == 0 {
			if otherKind > 0 && want == models.KindMCP {
				return nil, nil, errNoMCPMembers
			}
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
func (h *Handler) resolveMember(ctx context.Context, vk *models.VirtualKey, slug, want string) (*models.Upstream, *models.Group, error) {
	// The path segment is judged by the rule stored slugs are judged by,
	// before any lookup: "", "..", "%2f", a decoded NUL, "GitHub" and anything
	// over MaxSlugLen are not slugs, and asking the store about them would
	// only reveal what the caller already knows.
	if !models.ValidSlug(slug) {
		return nil, nil, nil
	}
	// want is passed straight through, so a member of the other kind is the
	// same miss as a slug no member carries: the same walk, the same nil.
	ups, group, err := h.resolveTargets(ctx, vk, want)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, errUpstreamDisabled) ||
			errors.Is(err, errNoUpstreams) || errors.Is(err, errNoMCPMembers) || errors.Is(err, errKindMismatch) {
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

// requestIDKey carries the audit row's request id on the request context, so
// credential can hand it to the refresh event.
type requestIDKey struct{}

// credential is the plaintext the proxy presents to an upstream, or the reason
// it must not dial: credential.ErrUndecryptable (no configured key opens the
// stored blob, ENCRYPTION_KEY changed), errCredentialUnreadable (nothing
// stored, or nothing the auth type can send), errCredentialExpired (an oauth
// token lapsed and the vendor refused to renew it) or
// errCredentialRefreshFailed (lapsed and the vendor could not be reached).
// auth_type none is (nil, nil) and never consults the blob. Every error is a
// bare sentinel, because it reaches the audit row's error_message, which is
// not redacted; the client sees the generic 502 either way (see serve).
//
// For an oauth row this is where the token is renewed (PORM-139), so every
// caller resolves it BEFORE upstreamContext arms a budget: the vendor call
// runs on its own context, and a caller waiting on the per-upstream lock is
// bounded by its request context, not by a connect timer that is not yet
// counting.
func (h *Handler) credential(ctx context.Context, u *models.Upstream) (json.RawMessage, error) {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	return h.present.Present(ctx, u, credential.Caller{Actor: models.ActorProxy, RequestID: requestID})
}

// listToolsRequest is the body the proxy sends to discover what a handshake-era
// upstream can do. The id is the proxy's own, because this is the proxy's
// request. A 2026-07-28 upstream gets mcpclient.ModernListRequest under the
// same id; these bytes are what every other upstream has always received.
const (
	listToolsID      = "1"
	listToolsRequest = `{"jsonrpc":"2.0","id":` + listToolsID + `,"method":"tools/list","params":{}}`
)

// forward relays the client's own request to an upstream: its verb, its hop
// headers and its body, with the virtual key swapped for the real credential.
// Everything the client sent that an upstream might act on reaches that
// upstream, which is exactly what makes it the wrong thing to use for a
// request the proxy makes on its own behalf. See listTools.
//
// hdr is what the aggregate decided about this request's headers (see
// memberHeaders) and nil on every path that relays the client's request as it
// was sent. Both halves go through copyHopHeaders, so the allowlist stays the
// one writer of outbound client headers and the aggregate cannot introduce a
// name that is not on it. drop is honoured on the way in. set is written after
// ApplyAuth, the one thing here that is: a routing header the aggregate
// composed is what the member must read, and a stored auth_config that names
// one (the API has refused to save such a config since PORM-150, but a row
// saved before that still holds it) would otherwise replace it, so a member
// that routes on Mcp-Name would run the name the stored config chose and not
// the one the policy gate judged.
//
// It hands back the live response, refused already when it was a 3xx
// (mcpclient.Open), and the caller decides whether to read it whole
// (forwardRead) or relay it as it arrives (relayStream). ctx is one
// upstreamContext derives: its budgets are what bound the request.
func (h *Handler) forward(ctx context.Context, inbound *http.Request, up *models.Upstream, plain json.RawMessage, body []byte, hdr *memberHeaders) (*http.Response, error) {
	// Before the request exists: a transport this client cannot speak means
	// nothing is dialled. serve refuses the transport before dispatch; this
	// is the same check for any future caller that reaches a dial without
	// passing through serve, not a second policy. plain is what credential
	// handed the caller, resolved before ctx's budget was armed; ApplyAuth
	// below is the check that it can be presented, so a request with the
	// virtual key stripped and nothing put back is never sent.
	if err := mcpclient.TransportError(up.Transport); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, inbound.Method, up.URL, bytes.NewReader(body))
	if err != nil {
		// The parse error quotes the stored URL, query string and all.
		return nil, errUpstreamURL
	}
	var (
		set  http.Header
		drop []string
	)
	if hdr != nil {
		set, drop = hdr.set, hdr.drop
	}
	copyHopHeaders(req.Header, inbound.Header, drop...)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", mcpclient.AcceptMCP)
	}
	if req.Header.Get("Content-Type") == "" && len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := mcpclient.ApplyAuth(req, up.AuthType, plain); err != nil {
		// Unreachable after credential(); kept so the seam cannot regress.
		return nil, errCredentialUnreadable
	}
	copyHopHeaders(req.Header, set)
	resp, err := mcpclient.Open(h.client, req)
	if err != nil {
		// Read into the closed set here, where the upstream and the budget
		// context are both in hand: the *url.Error quotes the outbound URL,
		// query string and all, and leaves the error chain at this line.
		return nil, upstreamFailed(ctx, err, up)
	}
	return resp, nil
}

// forwardRead is forward then ReadBody at the relay cap: the shape every
// caller that wants the whole answer uses, so none of them can be handed a
// live body and forget to read or close it. The error a cancelled request
// comes back with is the budget's own sentence (causeError), not the
// transport's "context canceled".
func (h *Handler) forwardRead(ctx context.Context, inbound *http.Request, up *models.Upstream, plain json.RawMessage, body []byte, hdr *memberHeaders) ([]byte, int, http.Header, error) {
	resp, err := h.forward(ctx, inbound, up, plain, body, hdr)
	if err != nil {
		return nil, 0, nil, causeError(ctx, err)
	}
	out, status, header, err := mcpclient.ReadBody(resp, mcpclient.MaxBodyBytes)
	if err != nil {
		return nil, 0, nil, readFailed(ctx, err)
	}
	return out, status, header, nil
}

// memberHeaders is what the aggregate decides about the headers of a request
// it sends one member on a client's behalf. nil relays the client's request as
// it was sent.
type memberHeaders struct {
	// set holds the routing headers the aggregate composes for the member. It
	// crosses copyHopHeaders after ApplyAuth, so a stored auth_config cannot
	// replace it.
	set http.Header
	// drop names allowlisted client headers that must not cross, because they
	// declare an era the member does not speak.
	drop []string
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
// never hands the client a member's session id (aggregate answers initialize
// itself, and the only header it ever returns is a Content-Type it chose) so
// no working client holds a session for a member to recognise, and there is no
// client header a member could need. The Accept below is the one the reference
// servers require.
//
// An advertised name no longer moves at all: buildRoutes composes every one of
// them from the member's own slug. What a client can still reach depends on
// this call, because a member whose catalogue does not parse contributes no
// routes and its tools cannot be called until it does. PORM-32 owns routing a
// call by the slug the name carries, which removes the catalogue from the call
// path entirely.
//
// The request is still the proxy's own when the member speaks the 2026-07-28
// era, and for the same reason. Such a member has to be told the version, the
// method and who is asking on every request, and all three come from the
// cached verdict and PoryMCP's constants (see memberEra), never from the
// inbound request: a client that could choose them would be choosing which
// members answer. The two guards run before the era is looked up, so a member
// the proxy must not dial is not probed either.
func (h *Handler) listTools(ctx context.Context, up *models.Upstream) ([]byte, int, error) {
	// The whole of one member's turn, the era probe included, has the minute
	// the client's flat timeout used to give it: a silent member costs the
	// walk that and no more. The two guards and the credential come first:
	// a member the proxy must not dial is not probed, and an oauth refresh
	// (credential) must not run under the budget's context. Wrapped before
	// the probe so the probe's connection is the one the connect timer
	// watches.
	if err := mcpclient.TransportError(up.Transport); err != nil {
		return nil, 0, err
	}
	plain, err := h.credential(ctx, up)
	if err != nil {
		return nil, 0, err
	}
	ctx, _, cancel := upstreamContext(ctx, listBudget)
	defer cancel(nil)
	verdict := h.memberEra(ctx, up, plain)
	if verdict.fail != "" {
		// A modern server that cannot be spoken to: one of mcpclient's fixed
		// sentences, and no request. The entry expires at the retry floor.
		return nil, 0, errors.New(verdict.fail)
	}
	modern := verdict.era == mcpclient.EraModern
	request := listToolsRequest
	if modern {
		request = mcpclient.ModernListRequest(listToolsID, "")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.URL, strings.NewReader(request))
	if err != nil {
		// The parse error quotes the stored URL, query string and all.
		return nil, 0, errUpstreamURL
	}
	req.Header.Set("Accept", mcpclient.AcceptMCP)
	req.Header.Set("Content-Type", "application/json")
	if err := mcpclient.ApplyAuth(req, up.AuthType, plain); err != nil {
		return nil, 0, errCredentialUnreadable
	}
	if modern {
		// After ApplyAuth, so a stored auth_config cannot choose either header.
		mcpclient.SetModernHeaders(req.Header, verdict.version, "tools/list")
	}
	// Open then ReadBody rather than Send, so the two failures are told
	// apart: a request that got no answer is read into the closed set with
	// the member's host, a body that failed while it was read with the read
	// sentences, because a read error is never a refused connection. Both
	// are chosen here, where the budget context and the upstream are in
	// hand, and before the reduction: a refused redirect arrives with no
	// body, and reducing that would replace the sentence that names the
	// redirect with one about an empty body.
	resp, err := mcpclient.Open(h.client, req)
	if err != nil {
		return nil, 0, upstreamFailed(ctx, err, up)
	}
	body, status, hdr, err := mcpclient.ReadBody(resp, mcpclient.MaxBodyBytes)
	if err != nil {
		return nil, status, readFailed(ctx, err)
	}
	// A member answers in whichever framing its SDK defaults to, and the
	// reference SDKs default to an event stream. The answer is reduced here
	// to the one document that answers this request, by the reader mcpclient
	// already has, so memberCatalogues and parseToolsList see plain JSON and
	// this package parses no frames of its own. A failure is one of
	// mcpclient's fixed sentences and carries no byte of the body.
	doc, err := mcpclient.PickResponse(hdr.Get("Content-Type"), body, listToolsID)
	if err != nil {
		return nil, status, err
	}
	return doc, status, nil
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
// outage take a whole group offline. A member answering over SSE (the
// reference SDKs' default) is read like any other since PORM-171; the member
// that still cannot be listed is one that refuses a tools/list sent without a
// session (PORM-23), and for that member the outage is permanent.
//
// What a dropout costs is now confined to the member that dropped out: its own
// tools disappear from the catalogue and cannot be routed, and every other
// member's names are exactly what they were, because each is composed from its
// own slug. Routability is the part still tied to this walk, PORM-32 routes a
// call by the slug the name carries and takes the catalogue off the call path.
func (h *Handler) memberCatalogues(ctx context.Context, ups []*models.Upstream) ([]*models.Upstream, [][]mcpTool, []int64) {
	active := make([]*models.Upstream, 0, len(ups))
	lists := make([][]mcpTool, 0, len(ups))
	// ttls is each listed member's cache hint, paired index for index with the
	// other two: what it reported, or the default when it reported nothing.
	ttls := make([]int64, 0, len(ups))
	// A dropout is otherwise invisible: the row belongs to the client's
	// request, which succeeded on the survivors, so nothing anywhere says why
	// a member's tools are missing. Warn rather than Debug because a member
	// that cannot be listed tends to stay unlistable (one that wants a session
	// before it will list, say) and a group quietly serving fewer tools than
	// it was built with is worth being loud about. A transport failure
	// arrives as one of the closed sentences (listTools reads it into the set
	// where the client returned it), so the line carries the same sentence
	// the member's own row would. Still bounded, because a member's own
	// error.message (parseToolsList) is the upstream's string; the handler
	// is slog's JSON one, so a control byte in it is escaped and cannot
	// start a line of its own.
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
		//
		// retrySoon sits beside skip and not inside it: skip returns at once
		// when there is no logger, and the retry floor is not a log line. Any
		// failure to list brings the member's era entry forward to the floor,
		// which is what lets a wrong verdict heal without a probe per call.
		listBody, _, err := h.listTools(ctx, up)
		if err != nil {
			h.eras.retrySoon(up.ID)
			skip(up, err)
			continue
		}
		tools, err := parseToolsList(listBody)
		if err != nil {
			h.eras.retrySoon(up.ID)
			skip(up, err)
			continue
		}
		ttl, reported := listTTLMs(listBody)
		if !reported {
			ttl = defaultListTTLMs
		}
		active = append(active, up)
		lists = append(lists, tools)
		ttls = append(ttls, ttl)
	}
	return active, lists, ttls
}

// shouldAggregate names the methods the group endpoint answers or refuses
// itself. Everything else is relayed to the group's first member.
func shouldAggregate(method string) bool {
	switch method {
	case "initialize", "tools/list", "tools/call", "notifications/initialized", "ping", "server/discover":
		return true
	case "subscriptions/listen", "tasks/get", "tasks/update":
		// Refused here, not relayed: see aggregate.
		return true
	default:
		return false
	}
}

// The messages the group endpoint writes as a server. Fixed strings, in the
// reply and on the row.
const (
	msgMethodNotFound     = "method not found"
	msgUnsupportedVersion = "unsupported protocol version"
)

// aggregate answers the methods a group endpoint handles itself. It takes the
// already-parsed request, and the routing fields and the client's era that
// serve read from it, rather than re-decoding the body: two decoders over the
// same bytes are two chances to disagree about which call this is, and the
// gate in ServeHTTP has already made its decision from the first one.
//
// The http.Header it returns is not a member's header set. It is nil on every
// arm but tools/call, and there it holds at most the Content-Type the
// aggregate chose itself and the member's Retry-After (see groupAnswer), so
// serve's one writer of response headers stays the one writer and no member's
// Mcp-Session-Id can reach a group client through it. A method this endpoint
// neither answers nor refuses never gets here: serve relays it to the first
// member and reads the answer through the same groupAnswer.
func (h *Handler) aggregate(ctx context.Context, inbound *http.Request, pol toolPolicy, ups []*models.Upstream, req rpcRequest, fields routingFields, clientModern bool, body []byte) ([]byte, int, http.Header, string, error) {
	switch req.Method {
	case "subscriptions/listen", "tasks/get", "tasks/update":
		// Methods the group endpoint cannot serve, refused the way the
		// revision's transport prescribes for a method a server does not
		// implement: 404 and -32601. subscriptions/listen needs a stream held
		// open to one member, which this endpoint, which reads every member's
		// answer whole to merge or reduce it, cannot give; relayed to the first
		// member it once held that member's stream until the client timed out
		// and tried again. A member endpoint and a single-upstream key relay
		// the stream as it arrives (stream.go). A task handle belongs to the
		// one member that issued it and the group has no way to know which;
		// tasks are an extension this endpoint does not advertise. No member
		// is contacted, so the row names none. A member endpoint relays all
		// three to its member.
		return answerRPC(req.ID, nil, &rpcError{Code: codeMethodNotFound, Message: msgMethodNotFound}), http.StatusNotFound, nil, "", nil
	case "notifications/initialized":
		// Both eras of the transport say an accepted notification is a 202 with
		// no body. Nothing is dialled for this or for initialize below, so
		// neither row names an upstream: upstream_id is how an operator reads
		// which credential a request presented, and none was.
		return nil, http.StatusAccepted, nil, "", nil
	case "initialize":
		// The handshake's own rule: the version asked for when PoryMCP speaks
		// it, the newest handshake revision otherwise. The answer comes out of
		// mcpclient's closed set and never out of the client's string. The
		// capabilities say the same thing server/discover says, so one sentence
		// describes a group in either era: tools, and no list-changed
		// notifications, because nothing here can send one.
		result := map[string]any{
			"protocolVersion": mcpclient.NegotiateHandshake(fields.protocolVersion()),
			"capabilities":    groupCapabilities(),
			"serverInfo":      mcpclient.SelfInfo(),
		}
		return answerRPC(req.ID, result, nil), http.StatusOK, nil, "", nil
	case "server/discover":
		// The stateless era's description of this server, and it is of THIS
		// server: a group, under PoryMCP's name, speaking the one stateless
		// revision PoryMCP speaks. Relayed to the first member, as it used to
		// be, it described one upstream, under that upstream's name and
		// version, to a client about to be shown composed names no member has.
		// Every value is a constant of PoryMCP's. No member and no policy is
		// read, so one call by any key holder cannot inventory a group's
		// upstream software, and a key whose rules leave it no tools is still
		// told the endpoint serves tools, which it does. private, because what
		// the endpoint serves is composed per key; an hour, because nothing in
		// it changes without a new build. No instructions: a member's are its
		// own and PoryMCP has none.
		result := map[string]any{
			"resultType":        "complete",
			"supportedVersions": []string{mcpclient.RevisionModern},
			"capabilities":      groupCapabilities(),
			"ttlMs":             discoverTTLMs,
			"cacheScope":        "private",
			"_meta":             selfMeta(),
		}
		return answerRPC(req.ID, result, nil), http.StatusOK, nil, "", nil
	case "ping":
		// Answered here in both eras, and no member is asked. The stateless
		// revision removed ping, so a member on it would refuse a relayed one,
		// and every result in that revision carries resultType, so its empty
		// result is not an empty object.
		result := map[string]any{}
		if clientModern {
			result["resultType"] = "complete"
		}
		return answerRPC(req.ID, result, nil), http.StatusOK, nil, "", nil
	case "tools/list":
		active, lists, ttls := h.memberCatalogues(ctx, ups)
		merged, _ := h.buildRoutes(active, lists)
		// The same policy the gate would apply to a call on each of these
		// names, so the catalogue and the call agree by construction.
		merged = filterTools(merged, pol)
		// This list is PoryMCP's own document, composed per key from composed
		// names, so it is private by construction and says so in the
		// revision's cacheScope member. resultType is the revision's retry
		// protocol field: complete means no client input is needed to finish
		// the result, and says nothing about a member skipped at catalogue
		// time, which memberCatalogues logs. ttlMs is required of a list by the
		// revision, and a client that validates what it is sent rejects a list
		// without it; it is the one value here a member has a say in, and
		// mergedTTLMs bounds that say. _meta is PoryMCP's own serverInfo and
		// nothing of a member's. There is never a nextCursor: whole catalogues
		// are merged (PORM-73 owns paging).
		result := map[string]any{
			"tools":      merged,
			"cacheScope": "private",
			"resultType": "complete",
			"ttlMs":      mergedTTLMs(ttls),
			"_meta":      selfMeta(),
		}
		return answerRPC(req.ID, result, nil), http.StatusOK, nil, "", nil
	case "tools/call":
		// ok is not checked: ServeHTTP refuses a tools/call without a usable
		// name before it gets here.
		name, _ := toolNameFromParams(req.Params)
		// The catalogues that decide where this call goes are the proxy's own
		// requests, not replays of the client's: see listTools.
		active, lists, _ := h.memberCatalogues(ctx, ups)
		_, routes := h.buildRoutes(active, lists)
		route, ok := routes[name]
		if !ok {
			// The name is a well-formed identity (serve refuses anything else
			// before this) but no member's catalogue holds it: a tool that has
			// gone, a member that could not be listed, or a slug belonging to no
			// member of this group. serve answers it, so that the reply and the
			// row are bounded there exactly as the gate's are.
			return nil, 0, nil, "", errUnknownTool
		}
		// No policy check here. ServeHTTP gated this call on the same
		// advertised name before any upstream was contacted, so a check on
		// these bytes could only ever agree with it, which is why the one
		// that used to live here was unreachable, and why a group's filter
		// went unenforced with no audit row to show for it.
		// The body's params.name and the Mcp-Name header are two spellings of
		// one identity and are rewritten together, so the member compares a
		// header and a body that agree; the client's Mcp-Method is already
		// tools/call and crosses as it is.
		//
		// The member is also told its own era, whichever era the client spoke
		// to this endpoint: see memberCallHeaders. The verdict is read from the
		// cache and never asked for. The catalogue walk above has just stored
		// it, and a call must not cost a probe, nor put a second caller behind
		// memberEra, whose entries correct themselves only because every probe
		// is followed by that caller's own listing.
		verdict, known := h.eras.get(route.Upstream.ID, route.Upstream.UpdatedAt)
		composed, meta := memberCallHeaders(inbound.Header, route.Original, verdict, known, clientModern)
		rewritten := rewriteMethod(body, "tools/call", rewriteToolCallParams(req.Params, route.Original, meta))
		// The routed call has the same answer budget a call on a member
		// endpoint has; the catalogue walk above ran under listBudget per
		// member. The context is released as soon as the body is read.
		plain, err := h.credential(ctx, route.Upstream)
		if err != nil {
			return nil, 0, nil, route.Upstream.ID, err
		}
		callCtx, _, cancel := upstreamContext(ctx, answerBudget)
		out, status, hdr, err := h.forwardRead(callCtx, inbound, route.Upstream, plain, rewritten, composed)
		cancel(nil)
		if err != nil {
			return out, status, nil, route.Upstream.ID, err
		}
		// Not completed for a member known to speak the stateless revision: it
		// sends its own resultType, and a second decode of up to 16 MiB to
		// change nothing is a cost on every call.
		memberModern := known && verdict.era == mcpclient.EraModern
		doc, media, err := h.groupAnswer(route.Upstream, "tools/call", status, rewritten, out, hdr, clientModern && !memberModern)
		return doc, status, media, route.Upstream.ID, err
	default:
		// Unreachable: serve calls aggregate only for a method shouldAggregate
		// names, and every one of those has an arm above. A method that is
		// relayed is relayed by serve, which also decides its headers. Kept as
		// a relay, not a panic, so a method added to one list and not the other
		// fails towards the old behaviour.
		plain, err := h.credential(ctx, ups[0])
		if err != nil {
			return nil, 0, nil, ups[0].ID, err
		}
		relayCtx, _, cancel := upstreamContext(ctx, answerBudget)
		out, status, _, err := h.forwardRead(relayCtx, inbound, ups[0], plain, body, nil)
		cancel(nil)
		return out, status, nil, ups[0].ID, err
	}
}

// errUnrelayableAnswer is a member's answer, to a routed tools/call or a
// relayed method, that the group endpoint can neither read nor pass on. On a
// success status serve turns it into the 502 every failed upstream request
// gets, and this sentence, which carries no byte of the answer, is the row's;
// on a failure status the status crosses with no body (groupAnswer).
var errUnrelayableAnswer = errors.New("upstream answered with a media type the proxy cannot relay")

// errAnswersNothing is why an answer that did decode is still passed on
// unreduced: the one document in it carries neither a result nor an error.
var errAnswersNothing = errors.New("answer carried neither a result nor an error")

// groupAnswer reads a member's answer on the group endpoint, whether the
// request was a routed tools/call or a method relayed to the first member.
// The answer is reduced to the one document that answers sent, labelled by
// its shape alone, and completed with a resultType when complete is true.
// Of the member's headers only Retry-After crosses: it names no member, and
// a group client is under the same limit. An answer that cannot be read at
// all keeps its status with no body when the status already says failure,
// so a 429's Retry-After is not lost behind a 502; a success status on
// unreadable bytes is the 502 it has been since PORM-171. method is the
// bounded name the row carries, never the client's raw string.
func (h *Handler) groupAnswer(up *models.Upstream, method string, status int, sent, answer []byte, hdr http.Header, complete bool) (doc []byte, media http.Header, err error) {
	doc, media, unreduced, err := reduceCallAnswer(sent, answer, hdr.Get("Content-Type"))
	if errors.Is(err, errUnrelayableAnswer) && status >= 400 {
		// The one Warn line below is the trace an operator has for a member
		// 404 that sent HTML; the row is error with no message.
		doc, media, unreduced, err = nil, nil, errUnrelayableAnswer, nil
	}
	if unreduced != nil && h.log != nil {
		// The row for this request is judged from what could be read of the
		// answer, else by its status and its raw bytes. This line is the only
		// place that says so. unreduced is a fixed sentence.
		h.log.Warn("group answer relayed unreduced", "method", method, "slug", up.Slug,
			"upstream_id", up.ID, "err", unreduced.Error())
	}
	if err == nil && unreduced == nil && complete {
		doc = completeResult(doc)
	}
	if v := hdr.Get("Retry-After"); v != "" && err == nil {
		if media == nil {
			media = http.Header{}
		}
		media.Set("Retry-After", v)
	}
	return doc, media, err
}

// reduceCallAnswer turns a member's answer, to a routed tools/call or to a
// method relayed to the first member, into what the group's client is sent.
// On the aggregate endpoint PoryMCP is the server, so the answer is its own to
// frame, and the transport lets a server answer a POST with application/json
// every time. groupAnswer is its one caller.
//
// A member answers in whichever framing its SDK defaults to, and the reference
// SDKs default to an event stream. Relayed as it came, that stream reached the
// client labelled application/json, because aggregate returned no member
// headers, and serve read it as a success whatever it held, because rpcFailed
// reads JSON. So the answer is reduced, by the one reader mcpclient has, to the
// document that answers the request the member was sent. The client gets that
// document as JSON and the audit row is judged from the same bytes.
//
// The wanted id is read back off sent and not taken from the client's request:
// rewriteMethod re-marshals the envelope, so an integer id too large for a
// float64 reaches the member in another spelling, and the member echoes what it
// received. Where even that does not match (a member that reformats the id
// again, or a notification, which has none) PickResponse falls back to the
// first document that answers anything, and one member answering one request
// has only the one. Notifications the member interleaved are dropped; under a
// buffered relay they could only ever have arrived along with the result.
//
// A lone document that answers nothing is read differently here than on the
// catalogue path. There it is a member with no tools. Here it would hand the
// client a notification as the answer to its call, so it counts as unreduced.
//
// What cannot be reduced is passed on as it came, and only under one of the two
// media types the transport allows a server: the member's own label when it is
// one of them, and what the body is when the member sent no label (an event
// stream by the reader's own test, or JSON only if it parses as JSON, so an
// unlabelled HTML error page is never sent out under a type it does not have).
// The type is written here, as a bare constant, and is the one header serve may
// copy back. unreduced says why, in a fixed sentence, so groupAnswer can log a
// relay the row cannot fully describe: serve judges those bytes by their HTTP
// status and by what answerStatus can still read of them. A body in any other
// media type is an error: a third media type on a response of PoryMCP's own is
// something no client can classify, and a member's Content-Type is otherwise a
// string this endpoint never repeats. groupAnswer decides whether that error
// is a 502 or the member's own failure status with no body.
//
// An answer with no body (a notification's 202) is passed on as no body at
// all, which is what both eras of the transport require of a 202, and whatever
// Content-Type came with it: a gateway in front of a member may add one, and a
// label on zero bytes is a claim about nothing.
func reduceCallAnswer(sent, answer []byte, contentType string) (out []byte, media http.Header, unreduced, err error) {
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(sent, &envelope)
	doc, perr := mcpclient.PickResponse(contentType, answer, strings.TrimSpace(string(envelope.ID)))
	if perr == nil && !answersSomething(doc) {
		perr = errAnswersNothing
	}
	if perr == nil {
		return doc, nil, nil, nil
	}
	if len(bytes.TrimSpace(answer)) == 0 {
		return nil, nil, nil, nil
	}
	shape := mcpclient.MediaType(contentType)
	if shape == "" {
		switch {
		case mcpclient.LooksLikeSSE(answer):
			shape = "text/event-stream"
		case json.Valid(answer):
			shape = "application/json"
		}
	}
	switch shape {
	case "application/json", "text/event-stream":
		return answer, http.Header{"Content-Type": []string{shape}}, perr, nil
	default:
		return nil, nil, nil, errUnrelayableAnswer
	}
}

// completeResult gives a member's result the resultType the stateless
// revision requires of every result, when the member sent none. It is called
// only for a client that declared that revision, a member not known to speak
// it, and a request that carried an id, on a routed tools/call and on a
// method the group endpoint relays to its first member alike (groupAnswer).
//
// A handshake-era member's result has no resultType, and the revision does say
// a client reads an absent one as "complete", but only of a server on an
// EARLIER revision. To a modern client this endpoint IS a 2026-07-28 server:
// its server/discover says so. The reference SDK holds it to that and refuses
// the result ("missing required resultType: servers implementing protocol
// revision 2026-07-28 MUST include it"), which is what the MCP Inspector did to
// a DeepWiki call through a group before this existed. "complete" is the true
// value: a handshake server has no way to ask for more input inside a result.
//
// Only that one member is added, and only to a result that is an object and
// lacks it, a null counting as lacking it. The id, the error of an error
// answer, and every VALUE the member put in its result are carried as raw JSON
// and cross unchanged; the members of the envelope and of the result come back
// in sorted order, which JSON gives no meaning to. A member's own resultType,
// "input_required" included, is left alone. A document that does not decode is
// returned as it came.
func completeResult(doc []byte) []byte {
	var env map[string]json.RawMessage
	if json.Unmarshal(doc, &env) != nil {
		return doc
	}
	raw := bytes.TrimSpace(env["result"])
	if len(raw) == 0 || raw[0] != '{' {
		return doc
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil {
		return doc
	}
	if v, has := result["resultType"]; has && string(bytes.TrimSpace(v)) != "null" {
		return doc
	}
	result["resultType"] = json.RawMessage(`"complete"`)
	patched, err := marshalRaw(result)
	if err != nil {
		return doc
	}
	env["result"] = patched
	out, err := marshalRaw(env)
	if err != nil {
		return doc
	}
	return out
}

// answersSomething reports whether a JSON-RPC document carries a result or an
// error, a null one counting as absent.
func answersSomething(doc []byte) bool {
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(doc, &env) != nil {
		return false
	}
	present := func(v json.RawMessage) bool { return len(v) > 0 && string(v) != "null" }
	return present(env.Result) || present(env.Error)
}

// discoverTTLMs is how long a client may keep the group endpoint's
// server/discover answer: an hour.
const discoverTTLMs = 3600000

// selfMeta is the _meta of a result the group endpoint composes as a server:
// PoryMCP's own serverInfo and nothing of any member's.
func selfMeta() map[string]any {
	return map[string]any{mcpclient.MetaServerInfo: mcpclient.SelfInfo()}
}

// groupCapabilities is what a group endpoint says it can do, in initialize and
// in server/discover alike: exactly what it serves. Prompts and resources join
// it when the group serves them (PORM-6).
func groupCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{"listChanged": false}}
}

// answerRPC is a JSON-RPC answer the group endpoint composes itself, a result
// or an error. The id follows writeRPCError's rule and for its reason: echoed
// as the raw bytes the client sent, and null when there were none or they are
// not a scalar, so a notification is not handed an id it never had and an
// integer past 2^53 comes back as it was written.
func answerRPC(id json.RawMessage, result any, rpcErr *rpcError) []byte {
	if len(bytes.TrimSpace(id)) == 0 || !scalarRPCID(id) {
		id = json.RawMessage("null")
	}
	var (
		out json.RawMessage
		err error
	)
	if rpcErr != nil {
		out, err = marshalRaw(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   *rpcError       `json:"error"`
		}{"2.0", id, rpcErr})
	} else {
		out, err = marshalRaw(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  any             `json:"result"`
		}{"2.0", id, result})
	}
	if err != nil {
		// Unreachable with the results composed here, which are maps of strings,
		// numbers and mcpclient.Info. Said out loud and not sent as a success
		// with no body: a client waiting on an id gets an answer it can read.
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
	return out
}

// writeRPCBody sends a JSON-RPC document serve has already composed, and
// returns the bytes written for the row.
func writeRPCBody(w http.ResponseWriter, status int, body []byte) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, _ := w.Write(body)
	return n
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

// answerStatus judges the row for an answer the client is sent. An answer in
// SSE framing is reduced to the one document that answers the request before
// it is read, because a JSON-RPC error inside an event stream is still an
// error. When the framing cannot be read, or the label is anything else, the
// raw bytes are judged as they always were: a JSON error under a wrong label
// stays an error row, and a JSON body is never reduced, since it would reduce
// to itself at the cost of a copy. A status of 400 or more is an error
// whatever the body. On the group paths the answer arrives already reduced
// and labelled JSON, so nothing is read twice there but an unreduced event
// stream, which is rare and bounded.
func answerStatus(statusCode int, contentType string, body []byte, wantID string) (status, errMsg string) {
	judged := body
	if mcpclient.SSEFramed(contentType, body) {
		if doc, err := mcpclient.PickResponse(contentType, body, wantID); err == nil {
			judged = doc
		}
	}
	if statusCode >= 400 || rpcFailed(judged) {
		return models.StatusError, rpcErrorMessage(judged)
	}
	return models.StatusSuccess, ""
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
func (h *Handler) block(w http.ResponseWriter, vk *models.VirtualKey, requestID string, req rpcRequest, auditMethod, tool, upstreamID, reason string, start time.Time) {
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
	h.finish(vk, requestID, auditMethod, tool, upstreamID, models.StatusBlocked, reason, start, size, boundedParams(req.Params))
	if h.log != nil {
		// No params: they are the one part of a request that routinely carries
		// the caller's secrets, and only the audit path redacts them.
		h.log.Warn("tool blocked",
			"virtual_key_id", vk.ID,
			"virtual_key_name", vk.Name,
			"method", auditMethod,
			"tool", tool,
			"reason", reason,
			"request_id", requestID,
		)
	}
}

// warnDenied is the one line a refused dial writes to the server log, from
// both doors (PORM-79): the class and the ids, never the URL or an address.
// The audit row holds the same sentence; the line is for an operator who
// alerts on logs without reading the database.
func (h *Handler) warnDenied(upstreamID, requestID, class string) {
	if h.log == nil {
		return
	}
	h.log.Warn("upstream address denied",
		"upstream_id", upstreamID,
		"class", class,
		"request_id", requestID,
	)
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

// The two OAuth sentinels (PORM-139), bare like the two above and reaching
// error_message as exactly their text: "credential expired" (the token lapsed
// and the vendor refused to renew it, or issued no refresh token; the fix is
// Connect again) and "credential refresh failed" (lapsed and the vendor could
// not be reached; the next call retries after a hold-off). Distinct from
// errExpired's "virtual key expired" on purpose.
var (
	errCredentialExpired       = credential.ErrExpired
	errCredentialRefreshFailed = credential.ErrRefreshFailed
)

var (
	errUnauthorized     = errors.New("invalid virtual key")
	errRevoked          = errors.New("virtual key revoked")
	errExpired          = errors.New("virtual key expired")
	errRateLimited      = errors.New("rate limit exceeded")
	errUpstreamDisabled = errors.New("upstream is disabled")
	errNoUpstreams      = errors.New("group has no enabled upstreams")
	errInvalidTarget    = errors.New("invalid virtual key target")
	// errNoMCPMembers is the MCP door's answer for a group whose enabled
	// members are all HTTP APIs (PORM-146): reachable at their own /api/
	// doors, but nothing for /mcp to merge.
	errNoMCPMembers = errors.New("group has no MCP members")
	// errKindMismatch is a key bound to one upstream knocked on the door of
	// the other kind. The client sees the uniform 404; this is the row's
	// reason.
	errKindMismatch = errors.New("unknown endpoint: upstream is not served on this door")
)

// maxRequestBytes bounds the body either door reads from a client. The MCP
// doors read up to it and parse what arrived; the relay door reads one byte
// past it and answers 413 (httprelay.go), because a truncated body relayed
// with a real credential is a corrupt write, not a refusal.
const maxRequestBytes = 8 << 20
