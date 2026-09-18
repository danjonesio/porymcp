package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// Era is which generation of MCP an upstream speaks. The 2026-07-28 revision
// removed the initialize handshake and the session, so the two are different
// conversations and not two versions of one: a modern server is asked
// server/discover and then listed with _meta on every request, a legacy one is
// walked through initialize as it always was.
type Era string

const (
	EraModern Era = "modern"
	EraLegacy Era = "legacy"
)

// RevisionModern is the one stateless revision PoryMCP speaks. It lives here
// and not in internal/proxy because the import runs one way: the proxy's
// strictFrom references this, and the discovery probe declares it.
const RevisionModern = "2026-07-28"

// The three JSON-RPC errors only a 2026-07-28 server sends. On a 400 they are
// what tells "a modern server that refused this request" from "a legacy server
// that has never heard of the method", and a modern server is never walked
// through a handshake it does not have.
const (
	CodeHeaderMismatch          = -32020
	CodeMissingClientCapability = -32021
	CodeUnsupportedVersion      = -32022
)

// The reverse-DNS keys the revision puts in params._meta on a request and in
// result._meta on the answer to server/discover.
const (
	metaProtocol   = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo = "io.modelcontextprotocol/clientInfo"
	metaClientCaps = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo = "io.modelcontextprotocol/serverInfo"
)

// What a server/discover answer is allowed to cost a response.
const (
	maxSupportedVersions = 8
	maxCapabilities      = 16
	maxCapabilityBytes   = 128
	// maxVersionListBytes bounds the RAW supportedVersions (or data.supported)
	// array before it is decoded. Eight versions of 32 bytes is about 300
	// bytes, so 4 KiB is generous, and a list past it is never unmarshalled:
	// capping after the decode would let one probe allocate a body's worth of
	// strings first. The capabilities object has no such bound of its own, on
	// purpose: its extension keys are reported sorted, which means reading all
	// of them, so it is bounded by the body cap (discoverBodyBytes) alone.
	maxVersionListBytes = 4 << 10
)

// handshakeRevisions is every revision that is spoken through initialize. A
// server that answers server/discover and lists only these is still one PoryMCP
// can talk to, by the handshake, so such a list means "fall back" and never
// "unsupported". A closed set on purpose: the verdict tests membership and
// needs no opinion on what a date looks like.
var handshakeRevisions = map[string]bool{
	"2025-11-25": true,
	"2025-06-18": true,
	"2025-03-26": true,
	"2024-11-05": true,
}

// probeBudget bounds the server/discover probe on both planes. Discovery's own
// ten seconds is for a whole handshake and a paged catalogue; this is one
// round trip, and on the proxy it is spent per member of a group on a request
// an agent is waiting for, where the client's own timeout is a minute. A var
// for the same reason discoverBudget is one.
var probeBudget = 5 * time.Second

// The three sentences a probe can end a discovery with. Fixed strings, in the
// closed set TestDiscoverErrorAllowlist pins: what the upstream advertised goes
// in supported_versions and its own words in upstream_message, never in here.
const (
	errNoSharedVersion    = "upstream supports no protocol version PoryMCP speaks"
	errRoutingRefused     = "upstream refused the routing headers PoryMCP sent (-32020)"
	errCapabilityRequired = "upstream requires a client capability PoryMCP does not offer (-32021)"
)

// discoverRequestTemplate takes the probe's id and the shared _meta object.
const discoverRequestTemplate = `{"jsonrpc":"2.0","id":%s,"method":"server/discover","params":{"_meta":%s}}`

// knownFamilies is the fixed head of a capabilities list, in the order it is
// reported, so an upstream with many extensions cannot push "tools" out of it.
var knownFamilies = []string{"tools", "resources", "prompts", "completions"}

// Probe is the server/discover probe's verdict on one upstream.
//
// Fail is set only when the probe DECIDED the upstream cannot be spoken to: a
// modern server that refused the request, or one that speaks no version
// PoryMCP does. A legacy verdict never sets it, which is what keeps a probe's
// outcome off the Discovery a fallback then completes. ProbeEra never returns
// a transport sentence either: nothing coming back is a legacy verdict with
// Reached false, and the handshake that follows reports the failure in the
// words an operator already knows.
type Probe struct {
	// Era is EraLegacy when Reached is false: the caller falls back, and
	// whether to REPORT an era is a separate question Reached answers.
	Era Era
	// Version is RevisionModern on a modern verdict that can be listed.
	Version string
	// Reached says an HTTP response arrived, whatever it said.
	Reached bool
	// Supported, Capabilities and Info are what the answer advertised, bounded
	// for display. Supported is filled on a fallback too when the server named
	// its versions, because that list is the reason for the fallback.
	Supported    []string
	Capabilities []string
	Info         *Info
	Fail         string
	// Message is the server's own error.message, through sanitiseMessage.
	Message string
	// LatencyMS feeds the proxy's log line and nothing an operator's API reads.
	LatencyMS int
}

// ProbeEra asks one upstream which era it speaks. It is package-level, like
// Send, so the proxy passes the one credential-carrying client it already has
// and no second one exists. The caller has already run TransportError and the
// credential check: a refusal there must cost the upstream nothing.
//
// The probe's own headers and _meta are PoryMCP's constants. Nothing about an
// inbound request reaches it.
func ProbeEra(ctx context.Context, hc *http.Client, up *models.Upstream, plainAuth json.RawMessage) Probe {
	ctx, cancel := context.WithTimeout(ctx, probeBudget)
	defer cancel()
	start := time.Now()

	// host stays empty on purpose: it is only ever read by transportFailure,
	// and a transport failure here is a verdict, never a sentence.
	p := &probe{client: hc, up: up, auth: plainAuth, modern: true, protocol: RevisionModern}
	body := fmt.Sprintf(discoverRequestTemplate, idDiscover, modernMeta())
	out := classify(p.exchange(ctx, stepDiscover, body, true))
	out.LatencyMS = latencyMS(time.Since(start))
	return out
}

// classify is the one place an answer to server/discover becomes a verdict.
//
// Only three things make an upstream modern: a 200 whose result, in the
// document that answers THIS request, carries a supportedVersions array; or a
// 400 carrying one of the three modern error codes. Everything else is the
// legacy signal, -32601 included: the spec lists that as a modern server's
// answer to an unknown method, but a modern server must implement
// server/discover, and a legacy server answering -32601 is the common case.
func classify(res stepResult) Probe {
	if res.status == 0 {
		return Probe{Era: EraLegacy}
	}
	legacy := Probe{Era: EraLegacy, Reached: true}

	if res.status == http.StatusBadRequest {
		switch res.code {
		case CodeHeaderMismatch:
			return Probe{Era: EraModern, Reached: true, Fail: errRoutingRefused, Message: res.message}
		case CodeMissingClientCapability:
			return Probe{Era: EraModern, Reached: true, Fail: errCapabilityRequired, Message: res.message}
		case CodeUnsupportedVersion:
			var data struct {
				Supported json.RawMessage `json:"supported"`
			}
			_ = json.Unmarshal(res.data, &data)
			versions, _ := versionList(data.Supported)
			if speaksHandshake(versions) {
				legacy.Supported = boundVersions(versions)
				return legacy
			}
			return Probe{
				Era: EraModern, Reached: true, Fail: errNoSharedVersion,
				Supported: boundVersions(versions), Message: res.message,
			}
		}
		return legacy
	}

	if res.status != http.StatusOK || len(res.result) == 0 {
		return legacy
	}
	// pickResponse falls back to the first document that answers anything when
	// none carries the id that was asked for. For a catalogue that is
	// tolerance; for a verdict it would let an off-id document choose the era.
	if res.id != idDiscover {
		return legacy
	}
	var body struct {
		Supported    json.RawMessage            `json:"supportedVersions"`
		Capabilities json.RawMessage            `json:"capabilities"`
		Meta         map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(res.result, &body) != nil {
		return legacy
	}
	versions, state := versionList(body.Supported)
	if state == listAbsent {
		// A 200 that is not a DiscoverResult: a lenient legacy server answering
		// a method it does not know with some result of its own.
		return legacy
	}

	out := Probe{
		Era: EraModern, Reached: true,
		Supported:    boundVersions(versions),
		Capabilities: capabilityFamilies(body.Capabilities),
	}
	var info *Info
	if raw := body.Meta[metaServerInfo]; len(raw) > 0 && json.Unmarshal(raw, &info) == nil {
		out.Info = boundInfo(info)
	}
	for _, v := range versions {
		if v == RevisionModern {
			out.Version = RevisionModern
			return out
		}
	}
	if speaksHandshake(versions) {
		// A dual-era server configured for the handshake only. It answered
		// server/discover, and what it said is "talk to me the old way".
		legacy.Supported = out.Supported
		return legacy
	}
	out.Fail = errNoSharedVersion
	return out
}

// The three things a raw version list can be.
const (
	listAbsent  = iota // no such key, null, or not an array of strings
	listUnread         // an array past maxVersionListBytes, never decoded
	listDecoded        // an array of strings, possibly empty
)

// versionList decodes a supportedVersions (or data.supported) array. The raw
// value is length-checked first, as readCursor does, so an oversized list is
// never unmarshalled. The whole decoded list is returned, uncut: membership is
// tested over all of it, and boundVersions cuts it for display afterwards.
func versionList(raw json.RawMessage) ([]string, int) {
	// On the byte slice, so an oversized value is never copied either: raw is
	// a slice of a body that can be 2 MiB, and the bound below is 4 KiB.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, listAbsent
	}
	if len(raw) > maxVersionListBytes {
		return nil, listUnread
	}
	var versions []string
	if json.Unmarshal(raw, &versions) != nil {
		return nil, listAbsent
	}
	return versions, listDecoded
}

func speaksHandshake(versions []string) bool {
	for _, v := range versions {
		if handshakeRevisions[v] {
			return true
		}
	}
	return false
}

// boundVersions is the version list as it is shown: at most eight entries,
// each visible ASCII within 32 bytes. An entry is tested RAW and dropped when
// it fails. It is never scrubbed first, because a version is a token: Scrub
// deletes control bytes, so "2026\x0107-28" would come out as a different,
// valid-looking version the upstream never advertised. The negotiated version
// is gated the same way in Discover.
func boundVersions(versions []string) []string {
	var out []string
	for _, v := range versions {
		if len(out) >= maxSupportedVersions {
			break
		}
		if visibleASCII(v, maxProtocolVersionBytes) {
			out = append(out, v)
		}
	}
	return out
}

// capabilityFamilies is a capabilities object reduced to the names of what it
// advertises: the four families PoryMCP knows, in a fixed order, then the keys
// of its extensions object, sorted. At most sixteen, each visible ASCII within
// 128 bytes. The order is decided here and never by ranging the map, which Go
// randomises: a cut taken mid-range would keep a different sixteen per call.
func capabilityFamilies(raw json.RawMessage) []string {
	var caps map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &caps) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range knownFamilies {
		if _, ok := caps[name]; ok {
			out = append(out, name)
			seen[name] = true
		}
	}
	var extensions map[string]json.RawMessage
	if json.Unmarshal(caps["extensions"], &extensions) == nil {
		names := make([]string, 0, len(extensions))
		for name := range extensions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if len(out) >= maxCapabilities {
				break
			}
			if seen[name] || !visibleASCII(name, maxCapabilityBytes) {
				continue
			}
			out = append(out, name)
			seen[name] = true
		}
	}
	return out
}

// modernMeta is the _meta object every 2026-07-28 request carries, composed in
// one place so the probe and the listing that follows it cannot disagree about
// who PoryMCP says it is.
func modernMeta() string {
	return fmt.Sprintf(`{%q:%q,%q:{"name":%q,"version":%q},%q:{}}`,
		metaProtocol, RevisionModern, metaClientInfo, clientName, clientVersion, metaClientCaps)
}

// ModernListRequest is the catalogue request for a modern upstream, and the
// only composer of one. id is the raw JSON-RPC id token: discovery's idList, or
// the proxy's own. The two legacy composers are deliberately left alone, so the
// bytes a legacy upstream receives cannot move.
func ModernListRequest(id, cursor string) string {
	params := `{"_meta":` + modernMeta()
	if cursor != "" {
		if quoted, err := json.Marshal(cursor); err == nil {
			params += `,"cursor":` + string(quoted)
		}
	}
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list","params":` + params + `}}`
}

// SetModernHeaders writes the two headers a 2026-07-28 request declares itself
// with. Callers run it AFTER ApplyAuth, so a stored auth_config can never
// choose either; method is empty for a request that has none.
func SetModernHeaders(h http.Header, version, method string) {
	h.Set("MCP-Protocol-Version", version)
	if method != "" {
		h.Set("Mcp-Method", method)
	}
}
