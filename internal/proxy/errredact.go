package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

// holdBytes is how much of one stream event the holder keeps before it
// decides, once, whether the event can be relayed raw; it is the bound the
// row judge already has. maxHeldBytes is the most it holds an event that may
// be an error, the cap a buffered answer already has; a var so a test can
// lower it.
const holdBytes = judgeTailBytes

var maxHeldBytes = mcpclient.MaxBodyBytes

// errEventTooLarge ends a stream whose event could neither be checked nor
// relayed raw.
var errEventTooLarge = errors.New("stream event too large to check")

type holdState uint8

const (
	holding     holdState = iota // under holdBytes, or over it and being held to its end
	passthrough                  // proved not an error at holdBytes: relayed raw to its end
)

// eventHolder sits between the read loop and the client on the stream door
// (PORM-195). Outside an event it forwards, on the read that brings it,
// every complete line that is a comment, an event:, id: or retry: field, or
// blank, so a keep-alive is never delayed. Any other complete line, data: or
// not, starts a held event; a partial line is held. A unit that has a data:
// line ends at the next line that is empty after TrimSpace; it is rewritten
// through redactErrorAnswer, the ending line is appended and the whole is
// returned. A unit with no data: line yet does not end at a blank line,
// because JSON allows blank lines between tokens and the judge reads such a
// body whole (answerDoc); it is held until a data: line joins it or until
// EOF, where end rewrites it. Lines are cut from scanned, so a partial line
// is never rescanned. A CR ends a line at once; a LF that follows on the next
// read belongs to that terminator and goes where the line went (lfOwed).
//
// Everything held is bounded. At holdBytes the holder decides once for the
// unit: a token walk over the payload so far allows passthrough only when a
// depth-1 key folding to result or method has been seen and none folding to
// error; the held bytes then go out raw and the unit is relayed raw to its
// ending line. Anything else is held to maxHeldBytes and rewritten at its
// end; past that, feed returns errEventTooLarge and the stream ends. A key
// holder's padded id cannot produce a passthrough, and an escaped key is
// decoded by the walk. The leftover is a nonconforming document that carries
// result or method first and error after a member larger than holdBytes.
type eventHolder struct {
	held    []byte // bytes not yet returned, from start
	start   int    // held[:start] has left already; compact drops it once per read
	scanned int    // held[:scanned] has been walked; the next scan starts here
	inEvent bool   // a held unit is open
	hasData bool   // the open unit has a data: line
	lfOwed  bool   // the last byte processed was a CR that ended a line
	decided bool   // the open unit has passed holdBytes and been judged
	state   holdState
	// passthrough tracks the ending line byte by byte, since nothing is held.
	lineBlank bool // the current line holds only whitespace so far
	skipLF    bool // the last byte was a CR inside p; a LF next is its pair
	out       []byte
}

// feed appends p and returns the bytes to write now; an empty return means
// write nothing. err means the stream must end (endRedact).
func (h *eventHolder) feed(p []byte) ([]byte, error) {
	h.out = h.out[:0]
	if h.lfOwed {
		h.lfOwed = false
		if len(p) > 0 && p[0] == '\n' {
			switch {
			case h.state == passthrough || !h.inEvent:
				h.out = append(h.out, '\n')
			default:
				h.held = append(h.held, '\n')
				h.scanned++
			}
			p = p[1:]
		}
	}
	if h.state == passthrough {
		return h.relayRaw(p)
	}
	h.held = append(h.held, p...)
	if err := h.scan(); err != nil {
		return nil, err
	}
	return h.finishOut(), nil
}

// finishOut releases an output buffer that grew past holdBytes.
func (h *eventHolder) finishOut() []byte {
	out := h.out
	if cap(h.out) > holdBytes {
		h.out = nil
	}
	return out
}

// scan walks the complete lines held since scanned and applies the rules.
// Bytes that left are skipped by start and compacted once per read, as
// streamCapture compacts pending, so a read packed with keep-alives costs
// one copy and not one per line.
func (h *eventHolder) scan() error {
	for {
		i := bytes.IndexAny(h.held[h.scanned:], "\r\n")
		if i < 0 {
			break
		}
		lineStart, lineEnd := h.scanned, h.scanned+i
		termEnd := lineEnd + 1
		if h.held[lineEnd] == '\r' {
			if termEnd < len(h.held) {
				if h.held[termEnd] == '\n' {
					termEnd++
				}
			} else {
				h.lfOwed = true
			}
		}
		line := h.held[lineStart:lineEnd]
		blank := len(bytes.TrimSpace(line)) == 0
		switch {
		case !h.inEvent && (blank || fieldLine(line)):
			h.out = append(h.out, h.held[lineStart:termEnd]...)
			h.start = termEnd
		case !h.inEvent:
			h.inEvent = true
			_, h.hasData = dataPayload(line)
		case blank && h.hasData:
			res, err := redactErrorAnswer("text/event-stream", h.held[h.start:lineStart])
			if err != nil {
				return err
			}
			h.out = append(h.out, res...)
			h.out = append(h.out, h.held[lineStart:termEnd]...)
			h.start = termEnd
			h.inEvent, h.hasData, h.decided = false, false, false
		default:
			if !h.hasData {
				_, h.hasData = dataPayload(line)
			}
		}
		h.scanned = termEnd
	}
	h.compact()
	if len(h.held) > maxHeldBytes {
		return errEventTooLarge
	}
	if !h.decided && len(h.held) >= holdBytes {
		h.decided = true
		if ok, hasData := h.provedNotError(); ok {
			// The unit is open from here even when its first line has not
			// ended, so the raw relay still stops at its ending line.
			h.inEvent, h.hasData = true, hasData
			h.out = append(h.out, h.held...)
			h.lineBlank = len(bytes.TrimSpace(h.held[h.scanned:])) == 0
			h.state = passthrough
			h.start = len(h.held)
			h.compact()
		}
	}
	return nil
}

// compact drops held[:start], keeping the rest at the front, and releases an
// array that grew past holdBytes, as streamCapture does.
func (h *eventHolder) compact() {
	if h.start == 0 {
		return
	}
	rest := h.held[h.start:]
	if cap(h.held) > holdBytes {
		h.held = append([]byte(nil), rest...)
	} else {
		h.held = h.held[:copy(h.held, rest)]
	}
	h.scanned = max(h.scanned-h.start, 0)
	h.start = 0
}

// relayRaw is the passthrough path: p goes out as it is, and the ending line
// is watched byte by byte so the unit's end returns the holder to holding.
func (h *eventHolder) relayRaw(p []byte) ([]byte, error) {
	for i, c := range p {
		if h.skipLF {
			h.skipLF = false
			if c == '\n' {
				continue // the LF of a CRLF, seen already
			}
		}
		switch c {
		case '\n', '\r':
			if c == '\r' {
				if i+1 == len(p) {
					h.lfOwed = true
				} else {
					h.skipLF = true
				}
			}
			if h.lineBlank && h.hasData {
				h.out = append(h.out, p[:i+1]...)
				h.state, h.inEvent, h.hasData, h.decided = holding, false, false, false
				rest := p[i+1:]
				if h.skipLF {
					h.skipLF = false
					if len(rest) > 0 && rest[0] == '\n' {
						h.out = append(h.out, '\n')
						rest = rest[1:]
					}
				}
				if len(rest) == 0 {
					return h.finishOut(), nil
				}
				h.held = append(h.held, rest...)
				if err := h.scan(); err != nil {
					return nil, err
				}
				return h.finishOut(), nil
			}
			h.lineBlank = true
		case ' ', '\t', '\f', '\v':
		default:
			h.lineBlank = false
		}
	}
	h.out = append(h.out, p...)
	return h.finishOut(), nil
}

// provedNotError runs the token walk over what the unit holds so far: the
// data: payloads joined as eventData joins them, or the raw bytes of a unit
// with no data: line. hasData says which it was, so the caller can keep the
// unit's ending rule. The prefix always ends inside a value, so running out
// of input is the expected end of the walk and the decision is read from the
// depth-1 keys seen up to it; only a syntax error, or a top level that is not
// an object, refuses the passthrough.
func (h *eventHolder) provedNotError() (ok, hasData bool) {
	payload := h.held
	var join []byte
	// The partial last line counts: an event over holdBytes is usually one
	// data: line that has not ended yet.
	for rest := h.held; len(rest) > 0; {
		line, _, next := mcpclient.NextLine(rest)
		rest = next
		if p, isData := dataPayload(line); isData {
			hasData = true
			if len(join) > 0 {
				join = append(join, '\n')
			}
			join = append(join, p...)
		}
	}
	if hasData {
		payload = join
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return false, hasData
	}
	depth, wantKey, sawGood := 1, true, false
	for {
		tok, err := dec.Token()
		if err != nil {
			return sawGood && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)), hasData
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				depth++
			default:
				depth--
				if depth == 1 {
					wantKey = true
				}
				if depth == 0 {
					return sawGood, hasData
				}
			}
		default:
			if depth != 1 {
				continue
			}
			if wantKey {
				key, _ := t.(string)
				switch {
				case strings.EqualFold(key, "error"):
					return false, hasData
				case strings.EqualFold(key, "result"), strings.EqualFold(key, "method"):
					sawGood = true
				}
				wantKey = false
			} else {
				wantKey = true
			}
		}
	}
}

// end returns what is held at EOF: an open unit rewritten without its ending
// line, through redactErrorAnswer, which covers bare JSON; nothing when the
// unit was in passthrough. On any other end of the stream the caller drops
// the holder.
func (h *eventHolder) end() ([]byte, error) {
	if h.state == passthrough || len(h.held) == 0 {
		return nil, nil
	}
	out, err := redactErrorAnswer("text/event-stream", h.held)
	h.held = nil
	return out, err
}

// fieldLine reports a line the holder forwards at once: a comment, or an
// event, id or retry field, the SSE fields that are not data.
func fieldLine(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	if line[0] == ':' {
		return true
	}
	name := line
	if i := bytes.IndexByte(line, ':'); i >= 0 {
		name = line[:i]
	}
	for _, f := range [...]string{"event", "id", "retry"} {
		if strings.EqualFold(string(name), f) {
			return true
		}
	}
	return false
}
