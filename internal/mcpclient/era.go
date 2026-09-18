package mcpclient

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
	// strings first.
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
