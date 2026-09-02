package proxy

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// rpcError is a JSON-RPC error the proxy originates itself, before any
// upstream is contacted. It doubles as the "error" member of the envelope
// writeRPCError sends.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC 2.0 error codes the request parser can return.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInvalidParams  = -32602
)

// auditFieldBytes caps a client-controlled string before it is stored on an
// audit row. Requests rejected here never reach an upstream, so the audit
// write is the only cost an attacker pays for sending one.
const auditFieldBytes = 256

// auditParamsBytes caps the params stored on a row the proxy writes without
// contacting an upstream. Those rows are free to provoke, and audit.Record
// unmarshals and re-marshals params to redact them on the request goroutine,
// so an 8 MiB body would be paid for twice by the proxy and once by the disk.
const auditParamsBytes = 4 << 10

// bom is U+FEFF. It is not whitespace to unicode.IsSpace, so it has to be
// checked for by hand.
const bom = "\ufeff"

// parseRequest decodes an inbound MCP request and refuses anything the rest of
// the proxy could not gate reliably. It is what lets tool policy be a single
// check: every dispatch site downstream — the tool gate, shouldAggregate,
// aggregate's own switch — compares the method byte-exactly, and that is only
// sound if a body which reaches them carries exactly one call, spelled one way.
//
// Each rule closes a path that used to end in the body being forwarded
// verbatim to the first upstream, with the real credential, past every tool
// policy, because peekRPC reported ("", "") and every check treats an empty
// method and an empty tool name as harmless:
//
//   - A batch array carries N calls where the gate can only inspect one.
//     Batching left MCP in 2025-06-18, but a server still on 2025-03-26
//     executes every element, so the proxy refuses the shape rather than
//     gating the first element and forwarding the rest.
//   - A body that does not decode (trailing garbage, a BOM prefix, excessive
//     nesting) is refused rather than passed on: an upstream whose decoder is
//     more lenient than Go's would otherwise execute what the proxy never
//     inspected.
//   - A non-scalar id cannot be echoed back to the client safely, and no
//     honest client sends one.
//   - A method carrying control characters, a BOM, or surrounding whitespace
//     is not the method it looks like, so the gate and the router would
//     disagree about which request this is. The same goes for a case variant
//     of the two policy-relevant names: "Tools/Call" satisfied a gate keyed on
//     the raw string and then missed shouldAggregate, so a group request
//     skipped routing entirely. Only tools/call and tools/list are
//     case-checked — MCP has legitimate mixed-case methods such as
//     logging/setLevel and sampling/createMessage.
//   - An object whose member names collide under case folding is two requests
//     in one body: Go binds the last of them, an upstream looks the name up
//     exactly, and the body is forwarded verbatim. See distinctKeys.
//
// An empty body is not a JSON-RPC request at all (a DELETE session teardown
// sends none) and is left alone. The returned rpcRequest is populated whenever
// the body decoded, so a caller auditing a rejection can still record the
// method the client claimed.
func parseRequest(body []byte) (rpcRequest, *rpcError) {
	var req rpcRequest
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return req, nil
	}
	if trimmed[0] == '[' {
		return req, &rpcError{Code: codeInvalidRequest, Message: "batch requests are not supported"}
	}
	if err := json.Unmarshal(body, &req); err != nil {
		// Unmarshal rejects an array on its own; the check above only makes
		// the client-facing message say why. TestParseRequest pins both, so a
		// later refactor cannot drop one and reopen the bypass with the other.
		return req, &rpcError{Code: codeParseError, Message: "parse error"}
	}
	if !scalarRPCID(req.ID) {
		return req, &rpcError{Code: codeInvalidRequest, Message: "invalid request"}
	}
	if !canonicalMethod(req.Method) {
		return req, &rpcError{Code: codeInvalidRequest, Message: "invalid request"}
	}
	// The envelope and params are the only two objects the proxy binds fields
	// from, so they are the only two that can be made to say one thing here and
	// another upstream.
	if !distinctKeys(body) || !distinctKeys(req.Params) {
		return req, &rpcError{Code: codeInvalidRequest, Message: "invalid request"}
	}
	return req, nil
}

// distinctKeys reports whether every member name of one JSON object is unique
// when the names are compared case-insensitively.
//
// encoding/json binds a member name case-insensitively and lets the last match
// win, while a JavaScript or Python server looks the key up exactly. So
// {"method":"tools/call","Method":"ping","params":{"name":"delete_repo"}} is
// two requests in one body: the gate reads it as ping, judges it by the key's
// lists alone and never applies the group's tool_filter, and the upstream —
// which the body reaches verbatim — runs tools/call delete_repo. The same
// trick on params, or on params.name, hands the gate a permitted tool name and
// the upstream a denied one. One request was judged and a different one was
// executed, which is the whole property the gate exists to provide.
//
// No honest client sends two spellings of one key, so the shape is refused
// rather than normalised: normalising would only change what the gate reads,
// and the body forwarded upstream would still carry both.
//
// A same-case duplicate ({"name":"a","name":"b"}) is not that bug — Go and
// JavaScript both take the last one, so there is nothing to diverge — but
// folding the name catches it too, and refusing it costs an honest client
// nothing.
//
// Only the top level of raw is walked. tools/call arguments are forwarded
// verbatim and never bound to a field here, so a duplicate nested inside them
// means whatever the upstream decides it means.
func distinctKeys(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return true // not an object: no member names to bind
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := tok.(string)
		if !ok {
			return false
		}
		lower := strings.ToLower(key)
		if seen[lower] {
			return false
		}
		seen[lower] = true
		// Decode into a RawMessage to step over the value whole, however
		// deeply it nests, without inspecting it.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false
		}
	}
	return true
}

// scalarRPCID reports whether id is absent or one of the three types JSON-RPC
// allows: string, number or null. The bytes have already been through
// json.Unmarshal, so the first byte identifies the type.
func scalarRPCID(id json.RawMessage) bool {
	raw := bytes.TrimSpace(id)
	if len(raw) == 0 {
		return true // a notification carries no id
	}
	switch raw[0] {
	case '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return true
	case 'n':
		return bytes.Equal(raw, []byte("null"))
	}
	return false
}

// canonicalMethod reports whether method is a name the proxy can dispatch on
// byte-exactly. See parseRequest for why each variant is refused rather than
// normalised: normalising would mean the audit row records a method the client
// never sent, and the body forwarded upstream would still carry the original.
func canonicalMethod(method string) bool {
	for i := 0; i < len(method); i++ {
		// Byte-wise is safe: no byte of a multi-byte UTF-8 rune is below 0x80.
		if c := method[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	if strings.Contains(method, bom) {
		return false
	}
	if strings.TrimSpace(method) != method {
		return false
	}
	if lower := strings.ToLower(method); lower == "tools/call" || lower == "tools/list" {
		return method == lower
	}
	return true
}

// boundedParams is params, or a marker naming its size when it is too large to
// store. A marker is more useful than a prefix: half a JSON object tells an
// operator nothing that its length does not, and it would not survive
// redaction as JSON.
func boundedParams(params json.RawMessage) json.RawMessage {
	if len(params) <= auditParamsBytes {
		return params
	}
	return json.RawMessage(`{"truncated":true,"bytes":` + strconv.Itoa(len(params)) + `}`)
}

// truncate caps a client-controlled string at max bytes. Cutting on a byte
// boundary can split a rune, so the result is re-validated; a well-formed
// method or tool name never reaches the limit.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "")
}
