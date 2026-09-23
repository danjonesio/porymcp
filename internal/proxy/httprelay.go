package proxy

// The HTTP relay door (PORM-146): a virtual key bound to an HTTP API upstream
// is served at /{keyID}/api/*, and an HTTP API member of a group at
// /{keyID}/{slug}/api/*. A request there is relayed to the upstream's base
// URL request for request, the same verb, the path joined under the base,
// the same query, headers by denylist and the same body, with the virtual key
// swapped for the stored credential and the upstream's status, headers and
// body relayed back. It shares admit with the MCP doors, so authentication,
// the host rule, the rate limit and the key-versus-path rule are one code
// path, and it goes out through the same client and the same two calls
// (ApplyAuth, then OpenRelay) as forward does.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

// The four relay routes. chi's /x/* does not match /x, so the base URL is a
// route of its own: /{keyID}/api and /{keyID}/api/ both mean the base. The
// static "api" child beats {slug} at the second segment, and "api" is a
// reserved slug (models.reservedSlugs), so no member can shadow the door.
const (
	HTTPRoute           = "/{" + KeyParam + "}/api/*"
	HTTPBaseRoute       = "/{" + KeyParam + "}/api"
	HTTPMemberRoute     = "/{" + KeyParam + "}/{" + SlugParam + "}/api/*"
	HTTPMemberBaseRoute = "/{" + KeyParam + "}/{" + SlugParam + "}/api"
)

// relayAllowedMethods is the Allow header on the relay door's 405 and its
// Access-Control-Allow-Methods: the six verbs models.HTTPMethodsAllowed
// names, plus the preflight. Anything else is refused before authentication,
// whatever a key's http_methods says.
const relayAllowedMethods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"

// relayAllowedHeaders is the relay door's Access-Control-Allow-Headers: a
// fixed list, with nothing reflected from the preflight. The door is for SDKs
// and scripts; a browser caller gets the conditional and idempotency names a
// REST client sends.
const relayAllowedHeaders = "Authorization, X-Api-Key, X-Request-Id, Content-Type, Accept, Accept-Language, If-None-Match, If-Match, If-Modified-Since, Idempotency-Key, Prefer"

// relayDoor is the relay's half of admit: the six verbs, its own CORS block,
// Retry-After on the 429, a bounded X-Request-Id, the keyless binding refused,
// every row's tool_name starting with "/", and plain JSON refusals.
var relayDoor = door{
	allow:          relayAllowedMethods,
	headers:        relayAllowedHeaders,
	expose:         "ETag, Link, Last-Modified, Retry-After, X-Request-Id",
	retryAfter:     true,
	boundRequestID: true,
	keyRequired:    true,
	tool:           relayTool,
	verbOK:         func(m string) bool { return slices.Contains(models.HTTPMethodsAllowed, m) },
	refuse:         writePlainError,
}

// ServeRelay serves HTTPRoute and HTTPBaseRoute: a key bound to one HTTP API
// upstream.
func (h *Handler) ServeRelay(w http.ResponseWriter, r *http.Request) { h.relay(w, r, false) }

// ServeRelayMember serves HTTPMemberRoute and HTTPMemberBaseRoute: one HTTP
// API member of the key's group.
func (h *Handler) ServeRelayMember(w http.ResponseWriter, r *http.Request) { h.relay(w, r, true) }

// relayRemainder is the escaped path after the door's fixed prefix ("/" +
// key + "/api", or with the slug), read from r.URL.EscapedPath() and never
// from chi's "*", which is escaped or decoded depending on whether the
// request line needed a RawPath. "" is the base URL for both /api and /api/.
// ok is false when the path does not carry the prefix, which the router
// makes unreachable but the function does not assume.
func relayRemainder(r *http.Request, key, slug string) (string, bool) {
	prefix := "/" + key + "/api"
	if slug != "" {
		prefix = "/" + key + "/" + slug + "/api"
	}
	p := r.URL.EscapedPath()
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	rest := p[len(prefix):]
	if rest == "" {
		return "", true
	}
	if rest[0] != '/' {
		return "", false
	}
	return rest[1:], true
}

// relayTool is the relay door's tool_name for every row, the prelude's
// included: "/" plus the bounded escaped remainder, so a relay row is
// recognisable by its leading "/" and never holds a decoded byte a TEXT
// column would refuse. The query is not part of it. A remainder that holds
// the presented key, escaped or decoded, whole or cut by the bound, is
// recorded as "/[redacted]": the door refuses such a request, but the rows
// admit writes before that (401, wrong key) carry the tool too, and the
// check runs on the whole remainder so a key straddling the bound leaves
// no prefix behind.
func relayTool(r *http.Request) string {
	rest, ok := relayRemainder(r, chi.URLParam(r, KeyParam), chi.URLParam(r, SlugParam))
	if !ok {
		return "/"
	}
	if tok := auth.BearerToken(r); tok != "" && holdsToken(rest, tok) {
		return "/[redacted]"
	}
	return "/" + truncate(rest, auditFieldBytes-1)
}

// holdsToken reports whether s carries token as sent or once
// percent-decoded, so an encoded spelling of the key is caught as the plain
// one is.
func holdsToken(s, token string) bool {
	if strings.Contains(s, token) {
		return true
	}
	decoded, err := url.PathUnescape(s)
	return err == nil && strings.Contains(decoded, token)
}

// relayRequestDenylist is every inbound header name (lower-cased) that must
// not reach an HTTP API, beyond the hop-by-hop set mcpclient.HopByHop names
// and whatever Connection lists. The groups, and why each crosses or not:
// Host and Content-Length are the outbound request's own; Expect would make
// the upstream wait for a 100-continue nobody sends; the five credential
// names are the ones auth.BearerToken reads and ApplyAuth strips, listed here
// so the rule reads in one place; the forwarding and client-address names
// would tell the upstream the agent's address, and an upstream IP allowlist
// might trust them; the method-override and URL-override names are honoured
// by common frameworks and would defeat http_methods and the path rule;
// Accept-Encoding is dropped so the transport negotiates its own gzip and
// hands back decoded bytes, which is what the read cap and
// response_size_bytes count. Everything else (X-GitHub-Api-Version,
// Notion-Version, If-None-Match, Idempotency-Key, Prefer, Accept and the
// rest) crosses, which is what lets an unmodified SDK work.
var relayRequestDenylist = map[string]bool{
	"host": true, "content-length": true, "expect": true,
	"authorization": true, "proxy-authorization": true, "cookie": true, "x-api-key": true,
	"forwarded": true, "x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true,
	"x-forwarded-port": true, "x-forwarded-prefix": true, "x-forwarded-scheme": true, "x-forwarded-ssl": true,
	"x-real-ip": true, "x-client-ip": true, "true-client-ip": true, "cf-connecting-ip": true,
	"x-cluster-client-ip": true, "client-ip": true,
	"x-http-method-override": true, "x-http-method": true, "x-method-override": true,
	"x-original-url": true, "x-rewrite-url": true,
	"accept-encoding": true,
}

// connectionListed is the lower-cased names a Connection header declares
// hop-by-hop, which a proxy must not forward either.
func connectionListed(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				out[name] = true
			}
		}
	}
	return out
}

// copyRelayRequestHeaders copies every inbound header except the denylist,
// the hop-by-hop set, whatever Connection lists, any name containing "_"
// (WSGI, PHP and CGI fold "-" and "_" together, so X_Api_Key would read as
// X-Api-Key there), and any header whose value carries the virtual key the
// client presented (an SDK that puts its key in a second header too). It
// runs before ApplyAuth, so the sweep touches only client-copied headers and
// can never remove the stored credential.
func copyRelayRequestHeaders(dst, src http.Header, token string) {
	listed := connectionListed(src)
	for name, vals := range src {
		lower := strings.ToLower(name)
		if mcpclient.HopByHop(name) || listed[lower] || relayRequestDenylist[lower] || strings.Contains(name, "_") {
			continue
		}
		if token != "" && slices.ContainsFunc(vals, func(v string) bool { return strings.Contains(v, token) }) {
			continue
		}
		dst[name] = append([]string(nil), vals...)
	}
}

// relayResponseDenylist is every upstream response header name (lower-cased)
// that must not reach the client, beyond the hop-by-hop set and whatever
// Connection lists. Content-Length is set from the relayed body (and copied
// on HEAD only) and Content-Encoding is gone because the bytes are decoded;
// cookies and the two auth challenges would be stored against PoryMCP's
// origin or name an authorization server to a key holder (PORM-98's rules);
// Location and Refresh are redirects (the first is unreachable after
// OpenRelay, the second is a browser's); the security-policy, cross-origin,
// reporting and client-hint names act on PoryMCP's origin, which holds the
// admin session, and the ones PoryMCP's middleware writes must never be
// replaced; Server, Via and Alt-Svc describe the upstream; Cache-Control is
// already no-store and Vary is applyCORS's. Everything else (Content-Type,
// ETag, Last-Modified, Link, Retry-After, X-RateLimit-* and the rest) reaches
// the client, every value copied.
var relayResponseDenylist = map[string]bool{
	"content-encoding": true,
	"set-cookie":       true, "set-cookie2": true, "www-authenticate": true, "proxy-authenticate": true,
	"location": true, "refresh": true,
	"content-security-policy": true, "content-security-policy-report-only": true,
	"strict-transport-security": true, "x-frame-options": true, "x-content-type-options": true,
	"x-xss-protection": true, "x-dns-prefetch-control": true, "x-permitted-cross-domain-policies": true,
	"referrer-policy": true, "permissions-policy": true, "document-policy": true, "document-isolation-policy": true,
	"cross-origin-opener-policy": true, "cross-origin-embedder-policy": true, "cross-origin-resource-policy": true,
	"origin-agent-cluster": true, "timing-allow-origin": true, "clear-site-data": true,
	"nel": true, "report-to": true, "reporting-endpoints": true, "service-worker-allowed": true,
	"accept-ch": true, "critical-ch": true, "set-login": true, "origin-trial": true,
	"attribution-reporting-register-source": true, "attribution-reporting-register-trigger": true,
	"observe-browsing-topics": true, "speculation-rules": true, "sourcemap": true, "x-sourcemap": true,
	"expect-ct": true, "public-key-pins": true, "alt-svc": true, "server": true, "via": true,
	"cache-control": true, "vary": true,
}

// copyRelayResponseHeaders copies an upstream's response headers onto dst
// under the denylist. The names already on dst are snapshotted BEFORE the
// loop: those are what the security middleware, applyCORS and admit wrote,
// and none of them may be replaced or added to by an upstream, by
// construction rather than by list. The snapshot is taken first so that a
// repeated upstream header (Link twice) is not mistaken for a protected name
// after its own first value lands. Every value of a permitted name is copied
// (Add), so nothing repeated is lost. Content-Length crosses on a HEAD answer
// only, where the length is the point of the request; on every other answer
// the caller sets it from the body it relays.
func copyRelayResponseHeaders(dst, src http.Header, head bool) {
	protected := make(map[string]bool, len(dst))
	for name := range dst {
		protected[strings.ToLower(name)] = true
	}
	listed := connectionListed(src)
	for name, vals := range src {
		lower := strings.ToLower(name)
		if lower == "content-length" {
			if !head {
				continue
			}
		} else if mcpclient.HopByHop(name) || listed[lower] || relayResponseDenylist[lower] ||
			protected[lower] || strings.HasPrefix(lower, "access-control-") {
			continue
		}
		for _, v := range vals {
			dst.Add(name, v)
		}
	}
}

// writePlainError is the relay door's refusal body: {"error":..,"request_id":..}
// with the statuses the MCP door uses and never a JSON-RPC envelope, because
// the caller is an HTTP client. request_id is left out when it does not exist
// yet (the 405 and the host refusal run before it is minted). Encoded into a
// buffer first so the byte count is knowable for the row, as writeRPCError
// does; a body that fails to encode is no body at all.
func writePlainError(w http.ResponseWriter, status int, requestID, msg string) int {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id,omitempty"`
	}{Error: msg, RequestID: requestID}); err != nil {
		buf.Reset()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, _ := w.Write(buf.Bytes())
	return n
}

// relayParams is a relay row's params: the query redacted by name
// (audit.RedactQuery, both name sets) and then by value (any value carrying
// the presented virtual key), the client's Content-Type bounded, and the
// request body's size. The body itself is never recorded. When the query
// alone exceeds the params bound it is replaced by the size marker
// boundedParams uses, so the other two members survive.
func relayParams(q url.Values, token, contentType string, requestBytes int) json.RawMessage {
	query := audit.RedactQuery(q)
	if token != "" {
		// A key can arrive as a parameter's value, as its name, or inside
		// the Content-Type; each is replaced, never stored. A name holding
		// the key is folded into one "[redacted]" member.
		for k, v := range query {
			switch {
			case strings.Contains(k, token):
				delete(query, k)
				query["[redacted]"] = "[redacted]"
			case strings.Contains(v, token):
				query[k] = "[redacted]"
			}
		}
		if strings.Contains(contentType, token) {
			contentType = "[redacted]"
		}
	}
	qb, err := json.Marshal(query)
	if err != nil || len(qb) > auditParamsBytes {
		qb = []byte(`{"truncated":true,"bytes":` + strconv.Itoa(len(qb)) + `}`)
	}
	out, err := json.Marshal(struct {
		Query        json.RawMessage `json:"query"`
		ContentType  string          `json:"content_type"`
		RequestBytes int             `json:"request_bytes"`
	}{Query: qb, ContentType: truncate(contentType, auditFieldBytes), RequestBytes: requestBytes})
	if err != nil {
		return nil
	}
	return out
}

// relayCarriesToken reports whether the presented virtual key appears in the
// request's path (escaped or decoded) or query (raw or decoded): an SDK that
// puts its key in a query parameter or a path segment as well as a header
// would otherwise hand PoryMCP's credential to the vendor and the audit row.
func relayCarriesToken(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	if strings.Contains(r.URL.EscapedPath(), token) || strings.Contains(r.URL.Path, token) || strings.Contains(r.URL.RawQuery, token) {
		return true
	}
	decoded, err := url.QueryUnescape(r.URL.RawQuery)
	return err == nil && strings.Contains(decoded, token)
}

// relayFailureText is the row's sentence for a request that got no usable
// answer, in this order: the proxy's own budget cause (causeError, which
// names the relay's budget and not discovery's), a refused redirect or an
// oversized body by their own typed text (the MCP door's sentences for the
// same failures), and otherwise mcpclient.TransportFailure, which names the
// base host only when it is HostSafe. err's own text never reaches a row: a
// *url.Error quotes the outbound URL, query and all.
func relayFailureText(ctx context.Context, err error, host string) string {
	if cause := causeError(ctx, err); cause != err {
		return cause.Error()
	}
	var redirect mcpclient.Redirect
	if errors.As(err, &redirect) {
		return redirect.Error()
	}
	var big mcpclient.BodyTooLarge
	if errors.As(err, &big) {
		return big.Error()
	}
	if !mcpclient.HostSafe(host) {
		host = ""
	}
	return mcpclient.TransportFailure(err, host)
}

// relay is the door. The order after admit mirrors serve where the steps
// exist there: resolve the target before any credential work; the method
// gate; the path join and the key-in-request check; the body under the cap;
// the credential (before the budget, as forward's callers do); the outbound
// request with headers by denylist and the credential written last; the
// send through the one client; the answer written with headers by denylist;
// the row; the key's last-used stamp.
func (h *Handler) relay(w http.ResponseWriter, r *http.Request, memberPath bool) {
	a, ok := h.admit(w, r, relayDoor)
	if !ok {
		return
	}
	r, vk, requestID, start, tool := a.r, a.vk, a.requestID, a.start, a.tool
	verb := r.Method
	key, slug := chi.URLParam(r, KeyParam), ""

	// 1. The target, and no credential work until it is known.
	var up *models.Upstream
	if memberPath {
		slug = chi.URLParam(r, SlugParam)
		member, _, err := h.resolveMember(r.Context(), vk, slug, models.KindHTTP)
		if member == nil {
			// One answer for every miss, as on the MCP member door.
			size := writePlainError(w, http.StatusNotFound, requestID, "unknown endpoint")
			h.finish(vk, requestID, verb, tool, "", models.StatusBlocked, unknownEndpointReason(slug, err), start, size, nil)
			if h.log != nil {
				attrs := []any{"virtual_key_id", vk.ID, "virtual_key_name", vk.Name,
					"slug", truncate(slug, auditFieldBytes), "request_id", requestID}
				if err != nil {
					attrs = append(attrs, "err", err)
				}
				h.log.Warn("unknown member endpoint", attrs...)
			}
			return
		}
		up = member
	} else {
		if vk.TargetType == models.TargetGroup {
			// A group key reaches its HTTP API members by slug only, so the
			// single door is the same uniform 404 as a member miss, decided
			// before the group is read: what its members are, or whether any
			// is enabled, must not show through as a different status.
			size := writePlainError(w, http.StatusNotFound, requestID, "unknown endpoint")
			h.finish(vk, requestID, verb, tool, "", models.StatusBlocked, "unknown endpoint: group key on the single-upstream door", start, size, nil)
			return
		}
		ups, _, err := h.resolveTargets(r.Context(), vk, models.KindHTTP)
		switch {
		case errors.Is(err, errKindMismatch):
			// A key bound to one MCP upstream has no /api/ door.
			size := writePlainError(w, http.StatusNotFound, requestID, "unknown endpoint")
			h.finish(vk, requestID, verb, tool, "", models.StatusBlocked, errKindMismatch.Error(), start, size, nil)
			return
		case err != nil:
			// No upstream is contacted on this path (a disabled target
			// provokes it), so the row is bounded like every other free one.
			size := writePlainError(w, http.StatusBadRequest, requestID, err.Error())
			h.finish(vk, requestID, verb, tool, "", models.StatusError, truncate(err.Error(), auditFieldBytes), start, size, nil)
			return
		}
		up = ups[0]
	}

	// 2. The method gate. Tool lists and ListsMalformed are not consulted on
	// this door: they judge tool names, and a relayed request has none.
	if vk.MethodsMalformed {
		size := writePlainError(w, http.StatusForbidden, requestID, "method not allowed by virtual key")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusBlocked, "blocked: virtual key http_methods could not be decoded", start, size, nil)
		return
	}
	if len(vk.HTTPMethods) > 0 && !slices.Contains(vk.HTTPMethods, verb) {
		size := writePlainError(w, http.StatusForbidden, requestID, "method not allowed by virtual key")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusBlocked, "blocked by virtual key http_methods", start, size, nil)
		return
	}

	// 3. The path, joined under the base and never resolved against it, and
	// the check that the virtual key is nowhere in the request itself.
	rest, ok := relayRemainder(r, key, slug)
	if !ok {
		size := writePlainError(w, http.StatusNotFound, requestID, "unknown endpoint")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusBlocked, "unknown endpoint", start, size, nil)
		return
	}
	base, err := url.Parse(up.URL)
	if err != nil || mcpclient.CheckTarget(base) != nil {
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, "upstream url is not usable", start, size, nil)
		return
	}
	target, err := mcpclient.JoinBase(base, rest)
	if err != nil {
		size := writePlainError(w, http.StatusBadRequest, requestID, mcpclient.ErrPathEscapes.Error())
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, mcpclient.ErrPathEscapes.Error(), start, size, nil)
		return
	}
	if relayCarriesToken(r, a.token) {
		size := writePlainError(w, http.StatusBadRequest, requestID, "request carries the virtual key")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, "request carries the virtual key", start, size,
			relayParams(r.URL.Query(), a.token, r.Header.Get("Content-Type"), 0))
		return
	}

	// 4. The body, read one byte past the cap so "over" is told apart from
	// "exactly": a truncated body relayed with a real credential would be a
	// corrupt write, not a refusal.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		writePlainError(w, http.StatusBadRequest, requestID, "invalid body")
		return
	}
	params := relayParams(r.URL.Query(), a.token, r.Header.Get("Content-Type"), len(body))
	if len(body) > maxRequestBytes {
		size := writePlainError(w, http.StatusRequestEntityTooLarge, requestID, "request body too large")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, "request body too large", start, size, params)
		return
	}

	// 5. The credential, before the budget is armed (see credential).
	plain, err := h.credential(r.Context(), up)
	if err != nil {
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, err.Error(), start, size, params)
		return
	}

	// 6, 7. The outbound request under the relay's budgets, with the joined
	// URL assigned rather than re-parsed (so an escaped segment goes out as
	// JoinBase built it), the client's query verbatim, the headers by
	// denylist with the key swept out, and the credential written last.
	ctx, _, cancel := upstreamContext(r.Context(), answerBudget)
	target.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(ctx, verb, "http://placeholder/", bytes.NewReader(body))
	if err != nil {
		cancel(nil)
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, "cannot build the upstream request", start, size, params)
		return
	}
	req.URL = target
	req.Host = target.Host
	req.ContentLength = int64(len(body))
	copyRelayRequestHeaders(req.Header, r.Header, a.token)
	if err := mcpclient.TransportError(up.Transport); err != nil {
		cancel(nil)
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, err.Error(), start, size, params)
		return
	}
	if err := mcpclient.ApplyAuth(req, up.AuthType, plain); err != nil {
		// Unreachable after credential(); kept so the seam cannot regress.
		cancel(nil)
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, errCredentialUnreadable.Error(), start, size, params)
		return
	}

	// 8. The send, through the one client, and the whole answer under the cap.
	resp, err := mcpclient.OpenRelay(h.client, req)
	var (
		respBody []byte
		status   int
		headers  http.Header
	)
	if err == nil {
		respBody, status, headers, err = mcpclient.ReadBody(resp, mcpclient.MaxBodyBytes)
	}
	reason := ""
	if err != nil {
		reason = relayFailureText(ctx, err, base.Host)
	}
	cancel(nil)
	if err != nil {
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, truncate(reason, auditFieldBytes), start, size, params)
		return
	}
	if status < 200 || status > 599 {
		// A 1xx that reached here (Upgrade is stripped, so none should):
		// Go's server would turn WriteHeader(101) into a 200 on the first
		// write, so it is not relayed.
		msg := "upstream answered " + strconv.Itoa(status)
		size := writePlainError(w, http.StatusBadGateway, requestID, "upstream request failed")
		h.finish(vk, requestID, verb, tool, up.ID, models.StatusError, msg, start, size, params)
		return
	}

	// 9. The answer. Content-Length is the relayed body's own; a body with no
	// upstream Content-Type is labelled octet-stream so Go's sniffer never
	// calls it text/html on PoryMCP's origin (the MCP door's default is
	// application/json for the same reason).
	head := verb == http.MethodHead
	copyRelayResponseHeaders(w.Header(), headers, head)
	writeBody := status != http.StatusNotModified && !head
	if writeBody {
		w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
		if w.Header().Get("Content-Type") == "" && len(respBody) > 0 {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
	}
	w.WriteHeader(status)
	if writeBody {
		_, _ = w.Write(respBody)
	}

	// 10. The row and the key's last-used stamp, as on the MCP door.
	st, errMsg := models.StatusSuccess, ""
	if status >= 400 {
		st, errMsg = models.StatusError, "upstream answered "+strconv.Itoa(status)
	}
	h.finish(vk, requestID, verb, tool, up.ID, st, errMsg, start, len(respBody), params)
	_ = h.store.TouchVirtualKey(r.Context(), vk.ID)
}
