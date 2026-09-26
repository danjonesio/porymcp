package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

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
// passed through audit.RedactBoundedLiterals, with literals the values the
// proxy injected (PORM-208), and whether the bytes changed. The
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
func redactErrorDoc(doc []byte, literals ...string) (out []byte, changed bool, err error) {
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
		patched, ok, perr := redactErrorMember(v, literals)
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
func redactErrorMember(raw json.RawMessage, lits []string) (json.RawMessage, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, false, nil
	}
	switch trimmed[0] {
	case '"':
		return redactString(trimmed, lits)
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
			patched, ok, err := redactString(t, lits)
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

// redactString runs the literal pass, the client bound and the rules on one
// JSON string and re-encodes it only when they changed it. The string is
// decoded first, so a literal written with \u escapes is matched.
func redactString(raw json.RawMessage, lits []string) (json.RawMessage, bool, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return raw, false, nil
	}
	r := audit.RedactBoundedLiterals(s, clientMessageBytes, lits)
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
// makes for an unframed body under a stream label; a body that mixes framed
// events with bare JSON lines goes through the holder, as on the stream door.
// Otherwise it calls redactErrorDoc on the body. It returns body itself when
// nothing changed.
// literals are the values the proxy injected, replaced before the rules
// (PORM-208). err is the walker's callback error only, and the caller fails
// closed on it.
func redactErrorAnswer(contentType string, body []byte, literals ...string) ([]byte, error) {
	if mcpclient.SSEFramed(contentType, body) {
		if hasStrayLine(body) {
			return redactThroughHolder(body, literals)
		}
		return redactUnit(body, nil, literals)
	}
	out, _, err := redactErrorDoc(body, literals...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// errRefusalNotRewritable is returned when the text pass over a JSON
// refusal would leave it unparseable; the caller answers with the fixed
// sentence instead of the upstream's bytes.
var errRefusalNotRewritable = errors.New("refusal body not rewritable")

// rpcErrorEnvelope reports whether body is a JSON-RPC error document: an
// object with a jsonrpc member that is "2.0" and a non-null error member,
// both spelled exactly, as JSON-RPC member names are. rpcFailed alone is true for any
// JSON with an error member, which is the shape an OAuth gateway's 401
// takes, and a struct decode would fold the case of the names, so neither
// is enough here. The map keeps the last of duplicate keys, so an error
// whose last value is null is not an envelope, as for the judge.
func rpcErrorEnvelope(body []byte) bool {
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) != nil {
		return false
	}
	if v, ok := env["jsonrpc"]; !ok || !bytes.Equal(bytes.TrimSpace(v), []byte(`"2.0"`)) {
		return false
	}
	errMember, ok := env["error"]
	return ok && !bytes.Equal(bytes.TrimSpace(errMember), []byte("null"))
}

// redactRefusal rewrites a refusal body (a status of 400 or more) on the MCP
// doors, so a gateway's plain-text, HTML or JSON 401 never carries the
// injected credential to the key holder (PORM-205). Two shapes are returned
// as sent because redactErrorAnswer has already rewritten them on those
// doors: a JSON-RPC error envelope (so error.data stays as the upstream
// wrote it) and a body under an event-stream label, or sniffed as one, that
// carries a data event. A body that only opens like a stream (a comment, an
// id: or a retry: line) and then holds plain text goes on to redactBody with
// every other body. literals are the values the proxy injected (PORM-208).
func redactRefusal(contentType string, body []byte, literals ...string) ([]byte, error) {
	if len(body) == 0 || rpcErrorEnvelope(body) {
		return body, nil
	}
	if mcpclient.SSEFramed(contentType, body) && carriesEvent(body) {
		return body, nil
	}
	return redactBody(body, literals)
}

// redactBody is the door-neutral part of the refusal pass. The MCP doors
// reach it through redactRefusal; the HTTP API relay calls it directly,
// because nothing runs before it on that door, so there a JSON-RPC envelope
// is walked whole and an event stream is scanned as text (PORM-204). Valid
// JSON within the client bound is walked with each string decoded, the way
// redactErrorDoc does, so an escaped credential is caught, and then scanned
// once more as text, so a labelled short value and a shadowed duplicate
// member are caught as well; the text pass runs on the walk's output, and if
// it leaves the document unparseable the caller fails closed. Any other body
// is scanned as text and cut at clientMessageBytes; the cut runs before the
// rules, so no unscanned byte crosses. A body the rules did not change comes
// back as body itself, so a clean refusal is relayed byte for byte. Invalid
// UTF-8 is scanned as well: under the bound the rules copy unmatched bytes
// as they are, so one stray byte cannot switch redaction off; over the bound
// Clamp strips invalid bytes from the kept prefix. literals are replaced
// over the whole text before any cut.
func redactBody(body []byte, literals []string) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	if len(body) <= clientMessageBytes && json.Valid(body) {
		walked, changed, err := redactJSONStrings(body, 0, literals)
		if err != nil {
			return nil, err
		}
		if !changed {
			walked = body
		}
		s := string(walked)
		r := audit.RedactBoundedLiterals(s, clientMessageBytes, literals)
		if r == s {
			return walked, nil
		}
		if !json.Valid([]byte(r)) {
			return nil, errRefusalNotRewritable
		}
		return []byte(r), nil
	}
	// The whole body is converted, not the window plus one byte: the literal
	// pass must see every byte before the cut, or a literal split at the
	// window's edge would leave a fragment. The copy is bounded by
	// mcpclient.MaxBodyBytes and made only for a refusal. Clamp still cuts at
	// the window.
	s := string(body)
	if escapedJSON(s[:min(len(s), clientMessageBytes+1)]) {
		// A body that opens as JSON but gets no walk, because it is over the
		// bound or does not parse, would be scanned as text, and the text
		// rules cannot see a credential written with \u or \/ escapes; one
		// that holds either inside the window is refused instead.
		return nil, errRefusalNotRewritable
	}
	r := audit.RedactBoundedLiterals(s, clientMessageBytes, literals)
	if r == s && len(body) <= clientMessageBytes {
		return body, nil
	}
	return []byte(r), nil
}

// maxWalkDepth bounds the nesting redactJSONStrings follows. Every level
// decodes its whole subtree once, so the walk costs the body's size times
// its depth; a gateway's refusal is a few levels deep, and a body nested
// past this many levels is refused rather than walked.
const maxWalkDepth = 32

// redactJSONStrings walks raw the way redactErrorMember does: a string leaf
// goes through redactString, an object is decoded into
// map[string]json.RawMessage and an array into []json.RawMessage, each value
// recursed, and the node is re-encoded with marshalRaw only when a value
// changed. Keys are never rewritten, so two members cannot collide. A clean
// document comes back as raw itself. Numbers, booleans and null are the
// upstream's bytes. depth is the caller's level, 0 at the top; past
// maxWalkDepth the walk returns errRefusalNotRewritable and the caller fails
// closed.
func redactJSONStrings(raw json.RawMessage, depth int, lits []string) (json.RawMessage, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, false, nil
	}
	if depth > maxWalkDepth && (trimmed[0] == '{' || trimmed[0] == '[') {
		return nil, true, errRefusalNotRewritable
	}
	switch trimmed[0] {
	case '"':
		return redactString(trimmed, lits)
	case '{':
		var obj map[string]json.RawMessage
		if json.Unmarshal(trimmed, &obj) != nil {
			return raw, false, nil
		}
		// The map keeps the last of duplicate keys, so a member shadowed by a
		// later one is not walked and its bytes would otherwise cross. An
		// object with fewer entries than members is re-encoded, which drops
		// the shadowed bytes the way any decoder that keeps the last would.
		changed := memberCount(trimmed) != len(obj)
		for k, v := range obj {
			patched, ok, err := redactJSONStrings(v, depth+1, lits)
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
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal(trimmed, &arr) != nil {
			return raw, false, nil
		}
		changed := false
		for i, v := range arr {
			patched, ok, err := redactJSONStrings(v, depth+1, lits)
			if err != nil {
				return nil, true, err
			}
			if ok {
				arr[i] = patched
				changed = true
			}
		}
		if !changed {
			return raw, false, nil
		}
		out, err := marshalRaw(arr)
		if err != nil {
			return nil, true, err
		}
		return out, true, nil
	}
	return raw, false, nil
}

// memberCount is the number of members written in a JSON object, duplicate
// keys counted each time, or -1 when obj is not one object.
func memberCount(obj []byte) int {
	dec := json.NewDecoder(bytes.NewReader(obj))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return -1
	}
	n := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return -1
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return -1
		}
		n++
	}
	return n
}

// escapedJSON reports whether s opens as a JSON object, array or string and
// holds a \u or \/ escape, the two escapes that can split a credential into
// pieces the text rules do not match.
func escapedJSON(s string) bool {
	t := strings.TrimLeft(s, " \t\r\n")
	if t == "" || (t[0] != '{' && t[0] != '[' && t[0] != '"') {
		return false
	}
	return strings.Contains(t, `\u`) || strings.Contains(t, `\/`)
}

// carriesEvent reports whether body holds at least one data event in SSE
// framing, the shape redactErrorAnswer's walk has already rewritten. A body
// whose first line merely looks like a stream field is not one.
func carriesEvent(body []byte) bool {
	_, _, seen, err := walkSSE(body, func(payload []byte, _ int) ([]byte, bool, error) {
		return payload, false, nil
	}, nil)
	return err == nil && seen > 0
}

// redactUnit rewrites one SSE-framed unit: the events through walkSSE and
// redactPayload, or, when the walk saw no data event, the whole unit as one
// document. join is the caller's scratch for a multi-line payload, or nil.
// lits are the injected values (PORM-208); with none, the walk takes
// redactPayload itself, so a result event costs what it always did. The
// holder calls this on each unit it closes and on what it holds at EOF.
func redactUnit(unit []byte, join *[]byte, lits []string) ([]byte, error) {
	fn := redactPayload
	if len(lits) > 0 {
		fn = func(payload []byte, _ int) ([]byte, bool, error) {
			return redactErrorDoc(payload, lits...)
		}
	}
	out, changed, seen, err := walkSSE(unit, fn, join)
	if err != nil {
		return nil, err
	}
	if seen > 0 || changed {
		return out, nil
	}
	out, _, err = redactErrorDoc(unit, lits...)
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
// through redactUnit, the ending line is appended and the whole is returned. A unit with no data: line yet does not end at a blank line,
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
	held     []byte // bytes not yet returned, from start
	start    int    // held[:start] has left already; compact drops it once per read
	scanned  int    // held[:scanned] has been walked; the current line starts here
	searched int    // held[:searched] holds no terminator; the next search starts here
	inEvent  bool   // a held unit is open
	hasData  bool   // the open unit has a data: line
	lfOwed   bool   // the last byte processed was a CR that ended a line
	decided  bool   // the open unit has passed holdBytes and been judged
	state    holdState
	// passthrough tracks the ending line byte by byte, since nothing is held:
	// blank means the line so far is only whitespace by unicode.IsSpace, the
	// rule bytes.TrimSpace applies, with a multi-byte rune carried across
	// reads in runeBuf.
	lineBlank bool    // the current line holds only whitespace so far
	runeBuf   [4]byte // the bytes of a rune not yet complete
	runeLen   int
	skipLF    bool   // the last byte was a CR inside p; a LF next is its pair
	join      []byte // scratch for a multi-line payload, kept across events
	out       []byte
	// literals are the injected values redactUnit replaces before the rules
	// (PORM-208), set where the holder is built; nil means the rules alone.
	literals []string
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
				h.searched = h.scanned
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
		i := bytes.IndexAny(h.held[h.searched:], "\r\n")
		if i < 0 {
			h.searched = len(h.held) // a partial line is never searched twice
			break
		}
		lineStart, lineEnd := h.scanned, h.searched+i
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
			h.decided = false // a long field line was judged once; the next unit is judged afresh
		case !h.inEvent:
			h.inEvent = true
			_, h.hasData = dataPayload(line)
		case blank && h.hasData:
			res, err := redactUnit(h.held[h.start:lineStart], &h.join, h.literals)
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
		h.scanned, h.searched = termEnd, termEnd
	}
	h.compact()
	if len(h.held) > maxHeldBytes {
		return errEventTooLarge
	}
	if !h.decided && len(h.held) >= holdBytes {
		h.decided = true
		// Only a unit with a data: line can pass through: it is the only
		// unit whose end the raw relay can find, at its blank line. Bare
		// JSON under the label has no end before EOF, so it is held.
		if ok, hasData := h.provedNotError(); ok && hasData {
			// The unit is open from here even when its first line has not
			// ended, so the raw relay still stops at its ending line.
			h.inEvent, h.hasData = true, true
			h.out = append(h.out, h.held...)
			h.startRawLine(h.held[h.scanned:])
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
	h.searched = max(h.searched-h.start, 0)
	h.start = 0
}

// startRawLine seeds the raw relay's blank-line state from the partial line
// that was held when passthrough was decided: whether it is whitespace so
// far, and the bytes of a rune it ends in the middle of.
func (h *eventHolder) startRawLine(partial []byte) {
	h.lineBlank, h.runeLen = true, 0
	for _, c := range partial {
		h.rawByte(c)
	}
}

// rawByte feeds one byte of the current line to the raw relay's blank-line
// state.
func (h *eventHolder) rawByte(c byte) {
	if !h.lineBlank {
		return
	}
	if h.runeLen == 0 && c < utf8.RuneSelf {
		if !unicode.IsSpace(rune(c)) {
			h.lineBlank = false
		}
		return
	}
	h.runeBuf[h.runeLen] = c
	h.runeLen++
	if utf8.FullRune(h.runeBuf[:h.runeLen]) || h.runeLen == len(h.runeBuf) {
		r, _ := utf8.DecodeRune(h.runeBuf[:h.runeLen])
		h.runeLen = 0
		if !unicode.IsSpace(r) {
			h.lineBlank = false
		}
	}
}

// relayRaw is the passthrough path: p goes out as it is, and the ending line
// is watched byte by byte, on the judge's rule (a line that bytes.TrimSpace
// empties), so the unit's end returns the holder to holding.
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
			if h.lineBlank && h.runeLen == 0 {
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
			h.lineBlank, h.runeLen = true, 0
		default:
			h.rawByte(c)
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
// line, through redactUnit, which covers bare JSON; nothing when the unit was
// in passthrough. On any other end of the stream the caller drops
// the holder.
func (h *eventHolder) end() ([]byte, error) {
	if h.state == passthrough || len(h.held) == 0 {
		return nil, nil
	}
	out, err := redactUnit(h.held, &h.join, h.literals)
	h.held = nil
	return out, err
}

// fieldLine reports a line the holder forwards at once: a comment, or a
// field line that is not data:, which is any line starting with an ASCII
// letter (event, id, retry, and any field a client ignores). No line of a
// JSON document starts with a letter: compact JSON starts with a brace and a
// pretty-printed line with whitespace, a quote or a bracket, so every line
// that could be part of an error is held.
func fieldLine(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	if line[0] == ':' {
		return true
	}
	if bytes.HasPrefix(line, dataField) {
		return false
	}
	c := line[0] | 0x20
	return 'a' <= c && c <= 'z'
}

// strayLine reports a line neither door treats as SSE framing: not blank, not
// a field line, not data:. Only a bare JSON document under the stream label
// has such lines. On the buffered path a body with one is run through the
// holder, so both doors give the same answer.
func strayLine(line []byte) bool {
	return len(bytes.TrimSpace(line)) != 0 && !fieldLine(line) && !bytes.HasPrefix(line, dataField)
}

// hasStrayLine walks body's lines for strayLine.
func hasStrayLine(body []byte) bool {
	for rest := body; len(rest) > 0; {
		line, _, next := mcpclient.NextLine(rest)
		rest = next
		if strayLine(line) {
			return true
		}
	}
	return false
}

// redactThroughHolder rewrites a buffered body the way the stream door would,
// for the bodies where the two rules differ, with lits the injected values
// (PORM-208). It returns body itself when nothing changed.
func redactThroughHolder(body []byte, lits []string) ([]byte, error) {
	h := eventHolder{literals: lits}
	out, err := h.feed(body)
	if err != nil {
		return nil, err
	}
	out = append([]byte(nil), out...)
	tail, err := h.end()
	if err != nil {
		return nil, err
	}
	out = append(out, tail...)
	if bytes.Equal(out, body) {
		return body, nil
	}
	return out, nil
}
