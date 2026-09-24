package proxy

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/mcpclient"
)

// clientMessageBytes bounds the error message a key holder receives
// (PORM-195). The message is cut at a value boundary before the rules run,
// so nothing past the bound is sent and a credential is never cut in half.
// 64 KiB is about 22 ms of RedactText on the request goroutine; the whole
// 16 MiB body cap would be about 5.6 s, and an upstream that echoes the
// request id lets the key holder choose that size. The stored row keeps its
// own, smaller window in audit.
const clientMessageBytes = 64 << 10

// redactErrorDoc returns doc with the message of every JSON-RPC error member
// passed through audit.RedactBounded, and whether the bytes changed. The
// check is rpcFailed first, the judge's own decode, which allocates nothing
// for a result and matches keys the way the judge does; only a document
// rpcFailed accepts is decoded into raw maps. Every member whose key folds to
// "error" is treated: a string is redacted as the message, an object has
// every member whose key folds to "message" and is a string redacted. A
// document that is not an object, has no error member, or whose messages
// RedactBounded leaves alone is returned as doc itself, so a body the proxy
// did not need to touch is passed on byte for byte. Values are carried raw
// and re-encoded with marshalRaw, so id, code, data and unknown members are
// the upstream's bytes; members come back in sorted order, as completeResult
// already accepts. Once a message has changed the original doc is never
// returned: a re-encoding failure, which cannot happen over values the
// decoder just accepted, comes back as err and the callers fail closed.
func redactErrorDoc(doc []byte) (out []byte, changed bool, err error) {
	if !rpcFailed(doc) {
		return doc, false, nil
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(doc, &env) != nil {
		return doc, false, nil
	}
	for k, v := range env {
		if !strings.EqualFold(k, "error") {
			continue
		}
		patched, ok, perr := redactErrorMember(v)
		if perr != nil {
			return nil, true, perr
		}
		if ok {
			env[k] = patched
			changed = true
		}
	}
	if !changed {
		return doc, false, nil
	}
	out, err = marshalRaw(env)
	if err != nil {
		return nil, true, err
	}
	return out, true, nil
}

// redactErrorMember rewrites one error member: a string is the message
// itself, an object carries it under every key that folds to "message".
// Anything else, and a message that is not a string, is left as it is.
func redactErrorMember(raw json.RawMessage) (json.RawMessage, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, false, nil
	}
	switch trimmed[0] {
	case '"':
		return redactString(trimmed)
	case '{':
		var obj map[string]json.RawMessage
		if json.Unmarshal(trimmed, &obj) != nil {
			return raw, false, nil
		}
		changed := false
		for k, v := range obj {
			if !strings.EqualFold(k, "message") {
				continue
			}
			t := bytes.TrimSpace(v)
			if len(t) == 0 || t[0] != '"' {
				continue
			}
			patched, ok, err := redactString(t)
			if err != nil {
				return nil, true, err
			}
			if ok {
				obj[k] = patched
				changed = true
			}
		}
		if !changed {
			return raw, false, nil
		}
		out, err := marshalRaw(obj)
		if err != nil {
			return nil, true, err
		}
		return out, true, nil
	}
	return raw, false, nil
}

// redactString runs the client bound and the rules on one JSON string and
// re-encodes it only when they changed it.
func redactString(raw json.RawMessage) (json.RawMessage, bool, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return raw, false, nil
	}
	r := audit.RedactBounded(s, clientMessageBytes)
	if r == s {
		return raw, false, nil
	}
	out, err := marshalRaw(r)
	if err != nil {
		return nil, true, err
	}
	return out, true, nil
}

// redactPayload is the walkSSE callback for the buffered and the stream
// paths: the joined payload of one event in, the rewritten document out.
func redactPayload(payload []byte, _ int) ([]byte, bool, error) {
	return redactErrorDoc(payload)
}

// redactErrorAnswer is the buffered path. When the body is SSE-framed it
// walks the events with walkSSE and redactPayload; when the walk saw no data
// event it tries the whole body as one document, the fallback answerStatus
// makes for an unframed body under a stream label. Otherwise it calls
// redactErrorDoc on the body. It returns body itself when nothing changed.
// err is the walker's callback error only, and the caller fails closed on it.
func redactErrorAnswer(contentType string, body []byte) ([]byte, error) {
	if mcpclient.SSEFramed(contentType, body) {
		out, changed, seen, err := walkSSE(body, redactPayload)
		if err != nil {
			return nil, err
		}
		if seen > 0 || changed {
			return out, nil
		}
	}
	out, _, err := redactErrorDoc(body)
	if err != nil {
		return nil, err
	}
	return out, nil
}
