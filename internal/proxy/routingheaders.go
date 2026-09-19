package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/danjonesio/porymcp/internal/mcpclient"
)

// The 2026-07-28 revision mirrors three routing values out of the JSON-RPC
// body into request headers, so that a server or an intermediary can route a
// POST without reading it: Mcp-Method carries the method, Mcp-Name carries
// params.name or params.uri on the three calls that name a target, and an
// Mcp-Param-{Name} header mirrors a tool argument the tool's own schema marked
// x-mcp-header. A server that does read the body must refuse a request whose
// headers disagree with it, and an intermediary must forward the mirrored
// parameters whether or not it understands them.
//
// PoryMCP reads the body (the tool gate in serve is keyed on it and on nothing
// else) so the comparison here is compliance and defence in depth, never the
// gate: a header can refuse a request and can never permit one. The spec's
// own sentence for intermediaries that enforce policy on a mirrored header is
// that they should verify the declared version requires header validation and
// reject the request otherwise; PoryMCP enforces nothing on a header today, so
// a request declaring an older version or none is judged only on the headers
// it did send. The day something reads Mcp-Name to make a decision (PORM-93's
// per-tool limiter is the candidate) the lenient branch below has to close.
const (
	// hdrProtocol is the canonical spelling of MCP-Protocol-Version; the
	// header map arrives canonicalised, so lookups by either spelling agree.
	hdrProtocol = "Mcp-Protocol-Version"
	hdrMethod   = "Mcp-Method"
	hdrName     = "Mcp-Name"
	// mcpParamPrefix is canonical too: a client's "mcp-param-region" reaches
	// the handler as "Mcp-Param-Region", over HTTP/1.1 and HTTP/2 alike.
	mcpParamPrefix = "Mcp-Param-"
	// strictFrom is the revision that made the routing headers required. It
	// is mcpclient's constant because the era probe declares the same
	// revision and the import runs from this package to that one.
	strictFrom = mcpclient.RevisionModern
	// maxParamHeaders and maxRoutingValueBytes bound what an intermediary is
	// told to forward blind. The spec caps neither; a proxy must. Both are
	// PoryMCP's own numbers and docs/07-security.md records them. The count
	// is of header values, not names, so one name sent many times trips it.
	maxParamHeaders      = 32
	maxRoutingValueBytes = 4 << 10
	// The revision carries a value that is not header-safe as
	// =?base64?<base64>?=; the prefix and suffix are lowercase and exact.
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="

	// The refusal messages. Each names the header and never its value, so
	// neither the client body nor the audit row carries attacker-chosen
	// bytes. They sit beside the checker that raises them, as policy.go keeps
	// its reason strings beside the policy.
	msgMismatchProtocol = "header mismatch: MCP-Protocol-Version"
	msgMismatchMethod   = "header mismatch: Mcp-Method"
	msgMismatchName     = "header mismatch: Mcp-Name"
	msgMismatchParam    = "header mismatch: Mcp-Param"
	msgParamBound       = "too many or too large Mcp-Param headers"
)

// strictRevision reports whether a declared protocol version is one on which
// the routing headers are required. A revision is a date, YYYY-MM-DD, and the
// format sorts, so once the shape is confirmed the comparison is bytewise.
// The shape is checked first because a value the proxy cannot order cannot be
// used to raise strictness: "9999", "draft" and "abc" all compare above the
// date as strings, and a client sending any of them is on no revision this
// proxy knows. Refusing an unknown version is -32022, the upstream's answer,
// not this proxy's.
func strictRevision(v string) bool {
	if len(v) != len("YYYY-MM-DD") || v[4] != '-' || v[7] != '-' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if i == 4 || i == 7 {
			continue
		}
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return v >= strictFrom
}

// printableASCII reports whether every byte of v is in 0x20 to 0x7E, the
// range a header value may carry in the clear. It is one byte wider than
// mcpclient's visibleASCII, which starts at 0x21 because a session id may not
// hold a space; a mirrored tool argument may. The two are kept apart on
// purpose.
func printableASCII(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// sentinelShaped reports whether v carries both halves of the base64 sentinel.
func sentinelShaped(v string) bool {
	return len(v) >= len(sentinelPrefix)+len(sentinelSuffix) &&
		strings.HasPrefix(v, sentinelPrefix) && strings.HasSuffix(v, sentinelSuffix)
}

// headerSafe reports whether v can be written into a routing header as it is:
// non-empty printable ASCII with no leading or trailing space or tab, and not
// itself of the sentinel shape. The last rule is what makes encoding
// reversible: a tool literally named "=?base64?ZWNobw==?=" is encoded, so the
// receiver's decode gives back the name and not "echo".
func headerSafe(v string) bool {
	if v == "" || !printableASCII(v) {
		return false
	}
	if v[0] == ' ' || v[len(v)-1] == ' ' {
		return false
	}
	return !sentinelShaped(v)
}

// encodeHeaderValue is v when it is header-safe and the sentinel form of it
// otherwise. The aggregate uses it to write a member's own tool name into the
// Mcp-Name it forwards.
func encodeHeaderValue(v string) string {
	if headerSafe(v) {
		return v
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(v)) + sentinelSuffix
}

// decodeHeaderValue is v when it is not sentinel-shaped, and the decoded
// value when it is. ok is false for a sentinel that will not decode, decodes
// to bytes that are not UTF-8, or exceeds maxRoutingValueBytes: none of those
// can be compared with a name the gate would accept, so each is a mismatch.
// The inbound header is forwarded raw either way; only the comparison reads
// the decoded form, so the upstream applies the same rule to the same bytes.
func decodeHeaderValue(v string) (string, bool) {
	if !sentinelShaped(v) {
		return v, true
	}
	middle := v[len(sentinelPrefix) : len(v)-len(sentinelSuffix)]
	decoded, err := base64.StdEncoding.DecodeString(middle)
	if err != nil || len(decoded) > maxRoutingValueBytes || !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

// isParamHeader reports whether a canonical header name is an Mcp-Param-
// header with a non-empty remainder.
func isParamHeader(canonicalName string) bool {
	return len(canonicalName) > len(mcpParamPrefix) && strings.HasPrefix(canonicalName, mcpParamPrefix)
}

// validParamHeaderName reports whether a name a client wrote (in
// Access-Control-Request-Headers, where nothing has canonicalised it) is an
// RFC 9110 token of bounded length that canonicalises to an Mcp-Param- header.
// The token loop is the one in mcpclient's sendableHeaderName, copied rather
// than imported: that function is welded to a refused set that answers a
// different question (which names a stored auth_config may send) and grows
// with it, and a CORS answer must not change when that set does.
func validParamHeaderName(name string) bool {
	if name == "" || len(name) > maxRoutingValueBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return isParamHeader(textproto.CanonicalMIMEHeaderKey(name))
}

// paramHeaderNames reads the Access-Control-Request-Headers values of a
// preflight and returns the Mcp-Param- names it asked for, canonicalised and
// deduplicated, so only spellings the proxy produced reach the response.
//
// It returns nil when more than maxParamHeaders valid names were asked for:
// a truncated allowance would let a browser send a request that passes this
// proxy's bound and is then refused at the upstream for a mirrored header
// that is missing while its value sits in the body, and the spec's answer to
// that refusal is a retry with the same headers. Refusing the set fails the
// request at the preflight instead, before anything is sent, and the fixed
// names are still advertised, so only the mirrored parameters are lost.
//
// This runs before authentication (applyCORS answers every request carrying
// an Origin) so the parse is bounded by construction: fields are read one at
// a time with strings.Cut and at most 2*maxParamHeaders of them are examined,
// which leaves room for the fixed names a browser lists beside the mirrored
// ones; a longer line returns nil.
func paramHeaderNames(requested []string) []string {
	var names []string
	seen := map[string]bool{}
	fields := 0
	for _, value := range requested {
		rest := value
		for {
			field, tail, more := strings.Cut(rest, ",")
			fields++
			if fields > 2*maxParamHeaders {
				return nil
			}
			field = strings.TrimSpace(field)
			if validParamHeaderName(field) {
				canon := textproto.CanonicalMIMEHeaderKey(field)
				if !seen[canon] {
					seen[canon] = true
					names = append(names, canon)
					if len(names) > maxParamHeaders {
						return nil
					}
				}
			}
			if !more {
				break
			}
			rest = tail
		}
	}
	return names
}

// checkParamHeaders is the bound on what the proxy forwards blind, applied
// before the body is read and on every verb: more than maxParamHeaders
// Mcp-Param- values across all names, or any one name or value over
// maxRoutingValueBytes, is refused. The caller answers 431 with -32000, the
// literal every other proxy-originated refusal uses. It is a size limit, not
// a mismatch, so it stays off the revision's 400 rule: a 400 whose body is
// not a recognised modern error is the signal on which a dual-era client
// abandons the modern protocol for the whole connection.
func checkParamHeaders(h http.Header) *rpcError {
	count := 0
	for name, vals := range h {
		if !isParamHeader(name) {
			continue
		}
		count += len(vals)
		if count > maxParamHeaders || len(name) > maxRoutingValueBytes {
			return &rpcError{Code: -32000, Message: msgParamBound}
		}
		for _, v := range vals {
			if len(v) > maxRoutingValueBytes {
				return &rpcError{Code: -32000, Message: msgParamBound}
			}
		}
	}
	return nil
}

// metaProtocolVersion reads the protocol version a body declares in
// params._meta. present is false when _meta is absent, is not an object, or
// carries no version member. bad is true when _meta is an object the proxy
// cannot read: member names that collide under case folding (the same rule
// distinctKeys applies to the envelope and to params) or a version member
// that is not a JSON string, a null included. A declaration that cannot be
// read cannot be shown to agree with the header, and treating it as absent
// would let a body opt out of strictness by being malformed, so the caller
// refuses it.
func metaProtocolVersion(meta json.RawMessage) (version string, present bool, bad bool) {
	trimmed := bytes.TrimSpace(meta)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", false, false
	}
	if !distinctKeys(trimmed) {
		return "", false, true
	}
	var m struct {
		Version json.RawMessage `json:"io.modelcontextprotocol/protocolVersion"`
	}
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return "", false, true
	}
	if len(bytes.TrimSpace(m.Version)) == 0 {
		return "", false, false
	}
	s, ok := jsonString(m.Version)
	if !ok {
		return "", false, true
	}
	return s, true, false
}

// mismatchFor is the refusal for one routing header: the revision's own code
// and a message that names the header and nothing else.
func mismatchFor(name string) *rpcError {
	msg := msgMismatchName
	switch name {
	case hdrProtocol:
		msg = msgMismatchProtocol
	case hdrMethod:
		msg = msgMismatchMethod
	}
	return &rpcError{Code: codeHeaderMismatch, Message: msg}
}

// headerLine is the one value of a header the caller has already confirmed
// appears at most once, and whether it appears at all. Get alone cannot tell
// an absent header from one sent with an empty value.
func headerLine(h http.Header, name string) (string, bool) {
	vals := h.Values(name)
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// checkRoutingHeaders compares the routing headers with the body the gate
// read. It runs after parseRequest, before the tool policy and before any
// upstream is resolved, and returns only an error: it never writes to the
// request, the method or the tool name, so a header can refuse a request and
// can never permit one.
//
// The first two arms, the character check on Mcp-Param- values and the
// refusal of a duplicate routing header line, apply to every request. The
// comparisons apply only when method is non-empty: a DELETE, or a POST with
// an empty body, carries no JSON-RPC request for Mcp-Method or the declared
// version to disagree with, so neither is compared and both are forwarded as
// they always were. Mcp-Name mirrors a body value, and such a request has
// none, so an Mcp-Name sent on it is refused, the same rule a compared method
// applies to a header sent against an absent value.
//
// The declared version is the MCP-Protocol-Version header, or the body's
// _meta version when the header is absent; when both are present they must
// agree, and a body that declares a strict revision with no header is refused
// rather than read leniently. Strictness (the headers being required, not
// only compared) is strictRevision over that value. A duplicate header line
// is refused rather than reduced to its first value, as distinctKeys refuses
// two spellings of one member name: an intermediary in front of this proxy
// may fold duplicates differently, and the value compared here has to be the
// one the upstream reads.
//
// Mcp-Name is compared against the value the gate already holds: toolName on
// tools/call (the same string the policy judges), params.name on prompts/get
// and params.uri on resources/read. On a strict request it is required only
// when the body carries a value at that field, so a tools/call that names no
// usable tool and sends no header falls through to the existing -32602; a
// header sent against an absent body value is a mismatch whatever the
// version. On every other method Mcp-Name is forwarded and not compared. The
// inbound header is compared decoded and forwarded raw.
func checkRoutingHeaders(h http.Header, method string, f routingFields) *rpcError {
	for name, vals := range h {
		if !isParamHeader(name) {
			continue
		}
		for _, v := range vals {
			if !printableASCII(v) {
				return &rpcError{Code: codeHeaderMismatch, Message: msgMismatchParam}
			}
		}
	}
	for _, name := range []string{hdrProtocol, hdrMethod, hdrName} {
		if len(h.Values(name)) > 1 {
			return mismatchFor(name)
		}
	}
	if method == "" {
		if _, sent := headerLine(h, hdrName); sent {
			return mismatchFor(hdrName)
		}
		return nil
	}

	declared, rpcErr := declaredVersion(h, f)
	if rpcErr != nil {
		return rpcErr
	}
	strict := strictRevision(declared)

	if hm, ok := headerLine(h, hdrMethod); ok {
		if hm != method {
			return mismatchFor(hdrMethod)
		}
	} else if strict {
		return mismatchFor(hdrMethod)
	}

	var (
		bodyValue string
		hasBody   bool
	)
	switch method {
	case "tools/call":
		bodyValue, hasBody = f.toolName()
	case "prompts/get":
		bodyValue, hasBody = f.name()
	case "resources/read":
		bodyValue, hasBody = f.uri()
	default:
		return nil
	}
	hn, ok := headerLine(h, hdrName)
	if !ok {
		if strict && hasBody {
			return mismatchFor(hdrName)
		}
		return nil
	}
	if !hasBody || len(hn) > maxRoutingValueBytes {
		return mismatchFor(hdrName)
	}
	decoded, ok := decodeHeaderValue(hn)
	if !ok || decoded != bodyValue {
		return mismatchFor(hdrName)
	}
	return nil
}

// declaredVersion is the protocol version a request declares, by the rule in
// checkRoutingHeaders' comment: the header, or the body's _meta version when
// the header is absent, with a disagreement between the two refused. It is a
// function of its own because two callers need the one answer. serve asks it
// again, once checkRoutingHeaders has passed, to learn which era the client
// speaks; the refusals are already behind it by then, so the second call
// cannot disagree with the first and its error is nil.
func declaredVersion(h http.Header, f routingFields) (string, *rpcError) {
	headerVersion, headerPresent := headerLine(h, hdrProtocol)
	metaVersion, metaPresent, metaBad := metaProtocolVersion(f.Meta)
	if metaBad {
		return "", mismatchFor(hdrProtocol)
	}
	declared := headerVersion
	if metaPresent {
		if !headerPresent {
			if strictRevision(metaVersion) {
				return "", mismatchFor(hdrProtocol)
			}
			declared = metaVersion
		} else if headerVersion != metaVersion {
			return "", mismatchFor(hdrProtocol)
		}
	}
	return declared, nil
}

// memberRoutingHeaders is the aggregate's half of the rewrite that
// rewriteToolCallParams makes on the body. When the client sent an Mcp-Name,
// which checkRoutingHeaders has already held to the composed name, the member
// receives one carrying its own tool name instead, sentinel-encoded when that
// name is not header-safe; the member then compares it with the params.name
// it was sent and the two agree. nil when the client sent none, so a legacy
// client's member sees none. forward applies it through copyHopHeaders,
// after the inbound copy and before ApplyAuth, so the allowlist stays the
// one writer of outbound client headers. The value is not held to
// maxRoutingValueBytes: base64 grows a name by a third, so a member name near
// that bound leaves larger than it. The client's inbound header, which is
// bounded, is what the comparison read; the member bounds its own request
// headers, and Go's transport refuses a value it cannot send before dialling,
// which surfaces as the existing 502 path.
func memberRoutingHeaders(src http.Header, memberTool string) http.Header {
	if len(src.Values(hdrName)) == 0 {
		return nil
	}
	override := http.Header{}
	override.Set(hdrName, encodeHeaderValue(memberTool))
	return override
}
