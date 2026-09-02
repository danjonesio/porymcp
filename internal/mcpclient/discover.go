package mcpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netcasklabs/porymcp/internal/models"
)

// What one discovery is allowed to cost.
const (
	// discoverBodyBytes caps each response read. Smaller than the proxy's
	// MaxBodyBytes because discovery reads handshake envelopes and a
	// catalogue, never a tools/call result: 500 tools of 2 KiB of description
	// is about 1 MiB, so 2 MiB is generous for the largest legitimate answer.
	discoverBodyBytes = 2 << 20
	// maxTools is how many tools are reported. Past it the catalogue is
	// truncated rather than refused — an operator with 600 tools on one server
	// still wants to see the first 500 and be told there are more.
	maxTools = 500
	// maxPages bounds the paging loop, which maxTools does not: a server
	// answering {"tools":[],"nextCursor":"x"} forever never reaches 500 tools
	// and would spin until the deadline, spending an authenticated request per
	// turn. 500 tools across 50 pages needs 10 tools a page, which every
	// reference server exceeds.
	maxPages        = 50
	teardownTimeout = 2 * time.Second

	// Per-field caps. The dashboard clamps for display; these are the
	// transport bound, because 500 tools times a 1 MiB description is a
	// half-gigabyte response an operator's browser has to parse.
	maxToolNameBytes        = 256
	maxTitleBytes           = 256
	maxDescriptionBytes     = 4 << 10
	maxServerNameBytes      = 128
	maxServerVersionBytes   = 64
	maxProtocolVersionBytes = 32
	maxUpstreamMessageBytes = 200
	maxSessionIDBytes       = 512
	maxCursorBytes          = 1 << 10
)

// discoverBudget is the whole sequence's deadline — initialize, the
// notification, every tools/list page — not a per-request one, which would let
// fifty pages cost fifty times as much. It is a var only so a timing test can
// shorten it; TestDiscoverTimesOut pins the shipped value at 10s first.
var discoverBudget = 10 * time.Second

// The MCP revision PoryMCP asks for, and who it says it is. tools/list is
// unchanged across every revision to date, so no fallback negotiation is
// needed: what a server answers with is what later requests declare.
const (
	clientProtocolVersion = "2025-06-18"
	clientName            = "porymcp"
	// clientVersion: the binary carries no build-stamped version today. When
	// one lands it belongs here, so an upstream's own logs can tell which
	// PoryMCP release called it.
	clientVersion = "dev"
)

// The JSON-RPC ids PoryMCP puts on its own two requests. They are named
// because they are read back as well as written: a Streamable HTTP server may
// put its own notifications and requests on the POST's stream, and the id is
// what tells its answer to THIS request apart from the rest of the traffic.
const (
	idInitialize = "1"
	idList       = "2"
)

var initializeRequest = fmt.Sprintf(
	`{"jsonrpc":"2.0","id":%s,"method":"initialize","params":{"protocolVersion":%q,"capabilities":{},"clientInfo":{"name":%q,"version":%q}}}`,
	idInitialize, clientProtocolVersion, clientName, clientVersion)

// notifyRequest is a NOTIFICATION: it carries no id, which is what makes it
// one. A server that got an id here would owe a response and the reference
// implementations answer 202 with an empty body.
const notifyRequest = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

// The three steps a failure can be attributed to. They are named in
// Discovery.Error, so they are fixed strings and never anything an upstream
// chose.
const (
	stepInitialize = "initialize"
	stepNotify     = "notifications/initialized"
	stepList       = "tools/list"
)

// Annotations is the MCP tool-annotation block, decoded into a fixed shape
// rather than carried as raw JSON: annotations are upstream-controlled and
// PORM-95 will act on these hints, so what arrives here has to be five known
// fields and not an arbitrary document. Absent hints stay absent — a nil
// *bool is "the server said nothing", which is not the same as false.
type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Tool is one entry of a discovered catalogue.
//
// No inputSchema. It is unbounded upstream JSON with no display use, and
// carrying it would put a megabyte of nesting in a response an operator reads;
// an opt-in ?include=schema can add it later without breaking anything.
type Tool struct {
	// Name is the tool's name exactly as its upstream advertises it.
	Name string `json:"name"`
	// ScopedName is the identity a rule is written against — "{slug}__{name}"
	// — and is present only when the upstream has a stored, valid slug. An
	// unsaved payload has none, and inventing one would hand an operator a
	// deny rule naming a tool that will be called something else once saved.
	ScopedName           string       `json:"scoped_name,omitempty"`
	Title                string       `json:"title,omitempty"`
	Description          string       `json:"description,omitempty"`
	DescriptionTruncated bool         `json:"description_truncated,omitempty"`
	Annotations          *Annotations `json:"annotations,omitempty"`
}

// Info is the upstream's own name for itself.
type Info struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Discovery is what one look at an upstream produced. It is returned to an
// operator whether or not the upstream answered: OK describes the upstream,
// and the HTTP status of the call that produced it describes the request.
//
// Every string in it is either PoryMCP's own or a bounded upstream string that
// exists to be read: a tool's name, title and description, the server's name
// and version, the protocol version, and UpstreamMessage. No header value and
// no raw body byte reaches any field — Mcp-Session-Id is used and never
// returned — and Error is built from the closed set of templates in this file.
type Discovery struct {
	OK              bool   `json:"ok"`
	LatencyMS       int    `json:"latency_ms"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	ServerInfo      *Info  `json:"server_info,omitempty"`
	Slug            string `json:"slug,omitempty"`
	// ToolCount is len(Tools) — how many tools are SHOWN, after unnameable
	// ones are dropped and after truncation. It is at most 500, and on a
	// catalogue cut short by the page cap or by a repeated cursor it is
	// however many arrived first; it is never the upstream's true total,
	// which discovery never learns.
	ToolCount int    `json:"tool_count"`
	Tools     []Tool `json:"tools"`
	// Unnameable counts tools dropped because the proxy could not hold a
	// caller to their names. A count and never a name: the reason they were
	// dropped is that the name carries something a log or a page has no
	// business reproducing.
	Unnameable int    `json:"unnameable_tools"`
	Truncated  bool   `json:"truncated"`
	Error      string `json:"error,omitempty"`
	// UpstreamMessage is a sanitised JSON-RPC error.message and the one place
	// an upstream's own words are repeated. It is a separate field from Error
	// on purpose: Error stays a closed set an operator and the dashboard can
	// both rely on, and "the server said: token lacks the repo scope" is the
	// failure this whole feature exists to diagnose.
	UpstreamMessage string `json:"upstream_message,omitempty"`
}

// fail stamps a refusal on a Discovery and returns it. Failures after
// initialize keep what was already learned — protocol version, server info,
// latency — because "initialize worked, tools/list did not" is the most useful
// thing an operator can be told.
func (d Discovery) fail(msg string) Discovery {
	d.OK = false
	// Whatever pages already landed are still what is shown, so the count
	// still describes the list beside it: a catalogue cut short at page two
	// reported tool_count 0 next to forty tools, and tool_count is the field
	// an API client trusts.
	d.ToolCount = len(d.Tools)
	d.Error = bound(msg, MaxErrorBytes)
	return d
}

// errNeedsCredential is the closed-set sentence for a draft or stored
// auth_config that its auth type cannot send anything from. It is the only
// sentence CheckCredential's refusal ever produces.
const errNeedsCredential = "this auth type needs a credential; add one or choose None"

// Failed is a Discovery for a refusal decided before this package is reached —
// the management API's "the stored credential will not decrypt", which must
// stop before any request goes out. Same shape, same empty tool array.
func Failed(msg string) Discovery {
	return Discovery{Tools: []Tool{}, Error: bound(msg, MaxErrorBytes)}
}

// Client discovers what an upstream offers. The only state it holds is the
// connection pool of the one client every credential-carrying request goes out
// on, so it is safe for concurrent use and the four to six requests of a
// single handshake reuse one connection.
//
// The *http.Client is unexported and taken from nobody: see NewHTTPClient for
// why the redirect policy is not something a caller gets to pass in.
type Client struct{ http *http.Client }

func New() *Client {
	// Timeout as well as the context deadline: the context bounds the whole
	// sequence, and Client.Timeout is the backstop for a body that trickles
	// in a byte at a time, which no read cap stops. Both surface as
	// context.DeadlineExceeded, so one branch classifies them.
	return &Client{http: NewHTTPClient(Options{Timeout: discoverBudget})}
}

// Discover performs a real MCP handshake against one upstream and reports what
// it advertises: initialize, notifications/initialized, tools/list following
// every cursor, then DELETE to end the session it opened.
//
// It is a pure function of its arguments. plainAuth is the DECRYPTED
// credential — this package holds no key and reads no config, which is what
// lets both internal/proxy and internal/api use it.
func (c *Client) Discover(ctx context.Context, up *models.Upstream, plainAuth json.RawMessage) Discovery {
	out := Discovery{Tools: []Tool{}}
	if models.ValidSlug(up.Slug) {
		out.Slug = up.Slug
	}

	// Everything down to the deadline happens before a single byte leaves the
	// process. A refusal here costs the upstream nothing and tells the
	// operator something they can act on without waiting ten seconds.
	switch up.Transport {
	case models.TransportStreamableHTTP, "":
	case models.TransportSSE:
		// PORM-28 accepts this transport without implementing it. Saying so is
		// the correct outcome; hanging or reporting a network failure is not.
		return out.fail("the sse transport is not implemented yet; use streamable-http")
	default:
		// Never the value itself: the unsaved-payload route accepts whatever
		// an operator types, so it is not PoryMCP's string to repeat.
		return out.fail("unsupported transport")
	}

	u, err := url.Parse(up.URL)
	if err != nil || CheckTarget(u) != nil {
		return out.fail("url must be an absolute http or https URL")
	}
	// The one variable ever interpolated into an error. A host that is not
	// plain ASCII is not written down at all — see HostSafe.
	host := "the upstream"
	if HostSafe(u.Host) {
		host = bound(u.Host, MaxErrorBytes)
	}

	if !authHeadersSendable(up.AuthType, plainAuth) {
		// Otherwise net/http fails the request late and quotes the name back.
		return out.fail("auth_config names a header that cannot be sent")
	}
	// After the header-name check on purpose: a partially decodable config
	// fails json.Unmarshal AND leaves a bad name behind, and the name is the
	// more specific sentence. Refusing here keeps an empty or unusable
	// credential from dialling the upstream unauthenticated and reporting its
	// 401 as a bad token (PORM-52).
	if err := CheckCredential(up.AuthType, plainAuth); err != nil {
		return out.fail(errNeedsCredential)
	}

	ctx, cancel := context.WithTimeout(ctx, discoverBudget)
	defer cancel()
	start := time.Now()

	p := &probe{client: c.http, up: up, auth: plainAuth, host: host}

	// Step 1: initialize.
	res := p.exchange(ctx, stepInitialize, initializeRequest, true)
	out.LatencyMS = latencyMS(time.Since(start))
	if res.fail != "" {
		out.UpstreamMessage = res.message
		return out.fail(res.fail)
	}
	// The session id is a response header PoryMCP will put back on its own
	// outbound requests, so it is checked before it is trusted with that:
	// net/http accepted a 100 KB value in a probe, and a CRLF in it makes Do
	// fail with the header NAME quoted, which would be misread as a transport
	// failure. Absent is not a failure — a stateless server sends none, and
	// then PoryMCP sends none and skips the DELETE.
	if sid := res.header.Get("Mcp-Session-Id"); sid != "" {
		if !visibleASCII(sid, maxSessionIDBytes) {
			// Nothing to tear down: a session id this will not put on its own
			// requests is a session id it cannot end either, and the return
			// above is the only path out of here with none registered.
			return out.fail("upstream sent an unusable session id")
		}
		p.session = sid
		// Deferred the moment there IS a session, so every later failure ends
		// it — including the notification's, which sits between opening a
		// session and the paging loop and used to leak one per press of
		// Refresh. It no-ops on an empty session, it runs after LatencyMS is
		// taken so a slow teardown never inflates the number an operator
		// reads, and it is synchronous: a goroutine that outlives this call is
		// a leak, not a speed-up. Registered after defer cancel(), so LIFO
		// runs it while the context is still alive.
		defer p.endSession(ctx)
	}

	var initResult struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      *Info  `json:"serverInfo"`
	}
	if json.Unmarshal(res.result, &initResult) != nil || initResult.ProtocolVersion == "" {
		return out.fail("upstream did not complete the MCP handshake")
	}
	// scrub before clamp on every one of these: the cap bounds the size, and
	// the scrub is what keeps an upstream's control characters out of an
	// operator's terminal.
	out.ProtocolVersion, _ = clamp(scrub(initResult.ProtocolVersion), maxProtocolVersionBytes)
	if initResult.ServerInfo != nil {
		name, _ := clamp(scrub(initResult.ServerInfo.Name), maxServerNameBytes)
		version, _ := clamp(scrub(initResult.ServerInfo.Version), maxServerVersionBytes)
		if name != "" || version != "" {
			out.ServerInfo = &Info{Name: name, Version: version}
		}
	}
	// The NEGOTIATED version, not the one asked for: a strict 2025-06-18
	// server answers 400 when the header disagrees with what it chose. It is
	// only sent when it is a value a header can hold, so a server that
	// answers with something else fails on its catalogue rather than on a
	// request net/http refuses to make.
	if visibleASCII(out.ProtocolVersion, maxProtocolVersionBytes) {
		p.protocol = out.ProtocolVersion
	}

	// Step 2: the notification. A server that requires initialization will
	// refuse tools/list until it has seen this.
	if msg := p.exchange(ctx, stepNotify, notifyRequest, false); msg.fail != "" {
		out.LatencyMS = latencyMS(time.Since(start))
		out.UpstreamMessage = msg.message
		return out.fail(msg.fail)
	}

	// Step 3: the catalogue.
	cursor := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			out.Truncated = true
			break
		}
		res := p.exchange(ctx, stepList, listRequest(cursor), true)
		if res.fail != "" {
			out.LatencyMS = latencyMS(time.Since(start))
			out.UpstreamMessage = res.message
			return out.fail(res.fail)
		}
		var body struct {
			Tools      []upstreamTool  `json:"tools"`
			NextCursor json.RawMessage `json:"nextCursor"`
		}
		if json.Unmarshal(res.result, &body) != nil {
			out.LatencyMS = latencyMS(time.Since(start))
			return out.fail("upstream did not answer " + stepList + " with JSON-RPC")
		}

		full := false
		for _, t := range body.Tools {
			if len(out.Tools) >= maxTools {
				full = true
				break
			}
			// The same predicate the call gate and the aggregate catalogue
			// use, so what an operator is shown is exactly what the proxy
			// will let a caller name. A 256-byte name is unusable in a rule
			// even though it is nameable, so it goes the same way: counted,
			// never reproduced.
			if !models.UsableToolName(t.Name) || len(t.Name) > maxToolNameBytes {
				out.Unnameable++
				continue
			}
			out.Tools = append(out.Tools, t.discovered(out.Slug))
		}
		if full {
			out.Truncated = true
			break
		}

		next, ok := readCursor(body.NextCursor)
		if !ok {
			// A cursor that is not a bounded JSON string is not one this will
			// send back. There may be more; say so rather than claim the
			// catalogue is complete.
			out.Truncated = true
			break
		}
		if next == "" {
			break
		}
		if next == cursor {
			// The same cursor twice is a server that will never end. One
			// string compare, and it catches the shape maxPages only bounds.
			out.Truncated = true
			break
		}
		cursor = next
	}

	out.LatencyMS = latencyMS(time.Since(start))
	out.ToolCount = len(out.Tools)
	out.OK = true
	return out
}

// upstreamTool is the catalogue entry as the upstream writes it, before any of
// it is clamped.
type upstreamTool struct {
	Name        string       `json:"name"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Annotations *Annotations `json:"annotations"`
}

// discovered clamps one upstream entry into the shape that is returned.
func (t upstreamTool) discovered(slug string) Tool {
	out := Tool{Name: t.Name}
	out.Title, _ = clamp(scrub(t.Title), maxTitleBytes)
	out.Description, out.DescriptionTruncated = clamp(scrub(t.Description), maxDescriptionBytes)
	if t.Annotations != nil {
		a := *t.Annotations
		a.Title, _ = clamp(scrub(a.Title), maxTitleBytes)
		out.Annotations = &a
	}
	if slug != "" {
		out.ScopedName = models.ToolIdentity{Slug: slug, Name: t.Name}.Canonical()
	}
	return out
}

// probe is the immutable half of one discovery plus the two values the
// handshake learns: the session the upstream minted and the protocol version
// it negotiated.
type probe struct {
	client   *http.Client
	up       *models.Upstream
	auth     json.RawMessage
	host     string
	session  string
	protocol string
}

// stepResult is one request's outcome: either a JSON-RPC result to read, or a
// sentence saying why there is none. message is the upstream's own words,
// sanitised, and it can accompany either.
type stepResult struct {
	header  http.Header
	result  json.RawMessage
	fail    string
	message string
}

// rpcEnvelope is a JSON-RPC document as far as this package reads one: which
// request it answers, and either the result or the error it answers with.
type rpcEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// pickResponse finds, among the documents one answer carried, the one that
// answers the request wantID was put on.
//
// A Streamable HTTP server may write JSON-RPC notifications and requests of
// its own onto the stream it answers a POST with — notifications/message and
// progress notifications are the common case — and they are allowed to come
// first. Reading only the first event reported such a server as one that
// answered with no result, which is how a client comes to work against a
// fixture and fail against the reference implementation.
//
// A document that carries neither result nor error answers nothing, so it is
// skipped; among those that do, the one whose id matches wins, and the first
// otherwise. When a single document answers nothing it is still decoded, so
// that "answered with no result" stays distinguishable from "did not answer
// with JSON-RPC"; when several did, the caller reports a stream that carried
// no response.
func pickResponse(payloads [][]byte, wantID string) (rpcEnvelope, bool) {
	var best rpcEnvelope
	found := false
	for _, payload := range payloads {
		var env rpcEnvelope
		if json.Unmarshal(payload, &env) != nil {
			continue
		}
		if len(env.Result) == 0 && env.Error == nil {
			continue
		}
		if wantID != "" && strings.TrimSpace(string(env.ID)) == wantID {
			return env, true
		}
		if !found {
			best, found = env, true
		}
	}
	if found {
		return best, true
	}
	if len(payloads) == 1 {
		var env rpcEnvelope
		return env, json.Unmarshal(payloads[0], &env) == nil
	}
	return rpcEnvelope{}, false
}

// exchange makes one request and classifies its answer. wantResult is false
// for the notification, where any 2xx is success and an empty body is the
// expected answer.
func (p *probe) exchange(ctx context.Context, step, body string, wantResult bool) stepResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.up.URL, strings.NewReader(body))
	if err != nil {
		// Unreachable: CheckTarget already parsed this URL. Classified rather
		// than quoted, because err here would carry the whole URL.
		return stepResult{fail: "url must be an absolute http or https URL"}
	}
	req.Header.Set("Content-Type", "application/json")
	if err := p.setHeaders(req); err != nil {
		return stepResult{fail: errNeedsCredential}
	}

	raw, status, hdr, err := Send(p.client, req, discoverBodyBytes)
	if err != nil {
		return stepResult{fail: p.transportFailure(step, err)}
	}

	// A JSON-RPC error object is read wherever one is present, whatever the
	// HTTP status: the reference server answers an uninitialised tools/list
	// with 400 and -32000, and the message is the one thing an operator needs
	// when a token is scoped wrong.
	payloads, perr := rpcPayload(hdr.Get("Content-Type"), raw)
	env, decoded := pickResponse(payloads, rpcID(step))
	if perr == nil && !decoded && len(payloads) > 1 {
		// Events arrived and not one of them answered what was sent — the same
		// news, for an operator, as a stream with no data event at all.
		perr = errNoEvent
	}
	message := ""
	if decoded && env.Error != nil {
		message = sanitiseMessage(env.Error.Message)
	}

	if status < 200 || status >= 300 {
		// The status-specific sentences first: "the credential was rejected"
		// and "this url is not the mcp endpoint" are what an operator acts on,
		// and a server is free to attach a JSON-RPC body to either. The
		// upstream's own message rides along in its own field.
		if msg, ok := statusFailure(status, step); ok {
			return stepResult{fail: msg, message: message}
		}
		if decoded && env.Error != nil {
			return stepResult{fail: fmt.Sprintf("upstream refused %s (JSON-RPC error %d)", step, env.Error.Code), message: message}
		}
		return stepResult{fail: fmt.Sprintf("upstream answered %d at %s", status, step)}
	}

	if !wantResult {
		return stepResult{header: hdr}
	}
	if perr != nil {
		switch {
		case errors.Is(perr, errEmptyBody):
			return stepResult{fail: "upstream answered " + step + " with an empty body"}
		case errors.Is(perr, errNoEvent):
			return stepResult{fail: "upstream answered " + step + " with an event stream carrying no response"}
		default:
			return stepResult{fail: "upstream did not answer " + step + " with JSON-RPC"}
		}
	}
	if !decoded {
		return stepResult{fail: "upstream did not answer " + step + " with JSON-RPC"}
	}
	if env.Error != nil {
		return stepResult{fail: fmt.Sprintf("upstream refused %s (JSON-RPC error %d)", step, env.Error.Code), message: message}
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return stepResult{fail: "upstream answered " + step + " with no result"}
	}
	return stepResult{header: hdr, result: env.Result}
}

// setHeaders writes what every discovery request carries.
//
// The credential goes on FIRST and the three protocol headers after it, so
// that PoryMCP's own half of the conversation wins whatever an auth_config
// asks for. sendableHeaderName already refuses those three names, so this is
// belt and braces — but the order is the half that cannot be got round, and
// with it the other way an auth_config of {"headers":{"Mcp-Session-Id":"…"}}
// handed the upstream a session id PoryMCP never minted, on every request.
// ApplyAuth clears the three header names a credential can arrive in before it
// writes the real one, and it touches none of the three set here.
func (p *probe) setHeaders(req *http.Request) error {
	if err := ApplyAuth(req, p.up.AuthType, p.auth); err != nil {
		// Unreachable: Discover refused the credential before building the
		// probe. Kept so the seam cannot regress silently.
		return err
	}
	req.Header.Set("Accept", AcceptMCP)
	if p.session != "" {
		req.Header.Set("Mcp-Session-Id", p.session)
	}
	if p.protocol != "" {
		// Not on initialize: there is nothing negotiated to declare yet.
		req.Header.Set("MCP-Protocol-Version", p.protocol)
	}
	return nil
}

// endSession sends the DELETE that ends the session initialize opened, so
// discovery does not leave one behind on every look at an upstream.
//
// It goes to the upstream's own configured URL, never to anything derived from
// a response, and carries the credential and the session id like every other
// request. 404 and 405 are normal answers — plenty of servers do not implement
// it — so every outcome is ignored. It is skipped when the CALLER's context
// was cancelled, because then the operator's browser has already gone and
// there is nobody left to be slow for.
func (p *probe) endSession(ctx context.Context) {
	if p.session == "" {
		return
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	// WithoutCancel because the sequence's own deadline has usually expired by
	// the time a failure gets here, and a session left open is the thing this
	// exists to prevent. Bounded, synchronous, and never a detached goroutine.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), teardownTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.up.URL, nil)
	if err != nil {
		return
	}
	// Every outcome of the teardown is ignored, this one included.
	_ = p.setHeaders(req)
	_, _, _, _ = Send(p.client, req, discoverBodyBytes)
}

// transportFailure maps a failed request to one of the sentences in this
// file's closed set.
//
// Nothing here reads err's own text except the TLS check, and nothing writes
// it: *url.Error masks the password in a URL and keeps the username, the path
// and the whole query string, and a query parameter is where a large share of
// hosted MCP servers put their token.
func (p *probe) transportFailure(step string, err error) string {
	// Both the sequence deadline and Client.Timeout arrive as this.
	if errors.Is(err, context.DeadlineExceeded) {
		return "upstream did not answer within " + discoverBudget.String()
	}
	// A body past the read cap is news of its own. Before Send refused it, the
	// half-read document failed to parse and a working server with a very
	// large catalogue was reported as one that does not speak JSON-RPC.
	if errors.Is(err, ErrBodyTooLarge) {
		return "upstream's answer to " + step + " is larger than discovery will read"
	}
	var redirect Redirect
	if errors.As(err, &redirect) {
		// The proxy's own sentence for the same refusal, composed from a
		// host-safe host and nothing else.
		if redirect.Host == "" {
			return "upstream redirected"
		}
		return "upstream redirected to " + redirect.Host
	}
	// Before *net.OpError, which a DNS failure arrives wrapped in.
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "cannot resolve " + p.host
	}
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) {
		return "tls handshake with " + p.host + " failed"
	}
	// The rest of the TLS failures keep no type through *url.Error — a
	// protocol version mismatch, a bad record header, an https request to a
	// plaintext port. The text is read to classify and never to report.
	if msg := err.Error(); strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:") {
		return "tls handshake with " + p.host + " failed"
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return "cannot connect to " + p.host
	}
	return "cannot reach " + p.host
}

// statusFailure is the sentence for the HTTP statuses worth naming. ok is
// false for everything else, which the caller reports generically.
func statusFailure(status int, step string) (string, bool) {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("upstream rejected the credential (%d) at %s", status, step), true
	case http.StatusNotFound:
		return "upstream answered 404 at " + step + "; check the url points at the mcp endpoint", true
	case http.StatusMethodNotAllowed:
		return "upstream does not accept POST at this url (405)", true
	case http.StatusNotAcceptable:
		return "upstream refused the Accept header (406)", true
	}
	return "", false
}

// CheckTarget is the whole gate on where a request carrying an upstream
// credential may go: an absolute http or https URL, with a host, and no
// fragment. Deliberately syntax and nothing else.
//
// Exported so the management API can refuse such a URL on create and patch
// rather than storing one only discovery can complain about. There is one
// answer to "is this a URL PoryMCP will connect to", and it lives here.
//
// TODO(PORM-79): refusing loopback, link-local and cloud-metadata addresses
// does NOT belong in this function. A check that resolves the host here and
// inspects the answer is defeated by the second resolution at dial time — Go
// re-resolves, which is classic DNS rebinding — so the real block has to sit
// on the transport's DialContext/Control hook inside NewHTTPClient, where it
// can read the peer address the connection actually got. This is the seam that
// says the decision has one owner, not the decision.
func CheckTarget(u *url.URL) error {
	switch {
	case u == nil:
		return errors.New("no url")
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("scheme is not http or https")
	case u.Host == "":
		return errors.New("no host")
	case u.Fragment != "":
		return errors.New("url carries a fragment")
	}
	return nil
}

// authHeadersSendable reports whether every header name the stored auth_config
// asks for is one net/http will actually send. A name that is not a token, or
// one of the four the transport owns, makes Do fail with the name quoted back
// — late, and in a string this package must not repeat.
func authHeadersSendable(authType string, raw json.RawMessage) bool {
	switch authType {
	case models.AuthHeader, models.AuthAPIKey, models.AuthCustom:
	default:
		return true
	}
	// The error is DISCARDED here on purpose: encoding/json populates every
	// field it decoded before it hits the failure, so
	// {"header":"X-Bad\r\nInject","headers":123} leaves a header name behind.
	// This check answers a different question from ApplyAuth — are the NAMES
	// sendable — and runs first, so a bad name gets its own sentence instead
	// of CheckCredential's generic "needs a credential"; ApplyAuth itself now
	// refuses a value that does not decode (ErrNoCredential), which is why
	// that one never reaches the network either way.
	var cfg models.AuthConfig
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg)
	}
	if cfg.Header != "" && !sendableHeaderName(cfg.Header) {
		return false
	}
	if authType == models.AuthCustom {
		for name := range cfg.Headers {
			if !sendableHeaderName(name) {
				return false
			}
		}
	}
	return true
}

// sendableHeaderName reports whether name is an RFC 7230 token that is neither
// a hop-by-hop header the transport owns nor one of the three protocol headers
// PoryMCP writes for itself.
//
// The hop-by-hop set is the whole RFC list, not the four Go computes: the
// point of the list is that it is closed, and Proxy-Authorization is a
// credential-shaped header an operator could otherwise aim at any upstream.
// Accept, Mcp-Session-Id and MCP-Protocol-Version are PoryMCP's own half of
// the conversation — a stored auth_config must not get to choose what Accept
// PoryMCP offers, or hand an upstream a session id PoryMCP never minted.
func sendableHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "upgrade",
		"proxy-authorization", "proxy-authenticate", "proxy-connection",
		"keep-alive", "te", "trailer":
		return false
	case "accept", "mcp-session-id", "mcp-protocol-version":
		return false
	}
	return name != ""
}

// listRequest is the catalogue request, with the cursor the last page named.
func listRequest(cursor string) string {
	first := `{"jsonrpc":"2.0","id":` + idList + `,"method":"tools/list","params":{}}`
	if cursor == "" {
		return first
	}
	quoted, err := json.Marshal(cursor)
	if err != nil {
		return first
	}
	return `{"jsonrpc":"2.0","id":` + idList + `,"method":"tools/list","params":{"cursor":` + string(quoted) + `}}`
}

// rpcID is the id the request for one step carries, and so the id its answer
// carries back. Empty for the notification, which has none and expects none.
func rpcID(step string) string {
	switch step {
	case stepInitialize:
		return idInitialize
	case stepList:
		return idList
	}
	return ""
}

// readCursor accepts a nextCursor only when it is a bounded JSON string. ok is
// false for anything else — a number, an object, a megabyte of text — which
// the caller treats as "there may be more, but not by a cursor this will send".
func readCursor(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", true
	}
	if len(raw) > maxCursorBytes {
		return "", false
	}
	var cursor string
	if json.Unmarshal(raw, &cursor) != nil {
		return "", false
	}
	return cursor, true
}

// scrub cleans an upstream string that PoryMCP will show to an operator: a
// newline, carriage return or tab becomes one space, every other control
// character and DEL is dropped, U+FFFD is dropped (the string already lost
// information there, and invalid UTF-8 arrives as one), and the ends are
// trimmed. One line out, always.
//
// It is applied to every upstream string that reaches a response — a tool's
// description and title, the annotations' title, the server's name and
// version, the protocol version, and the upstream's own error message —
// because an operator reading the API with `curl | jq -r` gets those bytes
// raw, and \x1b[31m from a server nobody at PoryMCP controls is somebody
// else's escape sequence in an operator's terminal. A tool's NAME needs none
// of this: models.UsableToolName already refuses every one of these characters
// outright, because a name is an identity a rule is written against.
//
// It deliberately does NOT touch the invisible and bidi class — U+202E,
// U+200B, U+FEFF, U+2066 and the rest. Those cannot escape the element they
// are rendered in (every one carries dir="ltr") and flagging them is PORM-83's
// job, which needs the whole run to say anything useful about it.
func scrub(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// sanitiseMessage prepares an upstream's own error.message to be shown to an
// operator. It is the single deliberate exception to "no upstream bytes", so
// it is scrubbed like every other upstream string and then cut to 200 bytes at
// a rune boundary. It is rendered as text by the dashboard and labelled as the
// server's words, never PoryMCP's.
func sanitiseMessage(s string) string {
	out, _ := clamp(scrub(s), maxUpstreamMessageBytes)
	return out
}

// visibleASCII reports whether s is at most max bytes of printable ASCII
// (0x21-0x7E) — what the MCP spec says a session id is, and what a header
// value may hold without making net/http refuse the request.
func visibleASCII(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// clamp cuts s to max bytes, dropping the partial rune the cut may leave, and
// reports whether it cut anything.
func clamp(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	return strings.ToValidUTF8(s[:max], ""), true
}

// latencyMS rounds to 10 ms. An operator cannot use finer than that, and the
// difference between a refused connection and a filtered port is exactly the
// signal that turns this route into a port scanner's stopwatch.
func latencyMS(d time.Duration) int {
	return int(d.Round(10*time.Millisecond) / time.Millisecond)
}
