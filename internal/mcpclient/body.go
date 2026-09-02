package mcpclient

import (
	"bytes"
	"errors"
	"strings"
)

// dataField is the SSE field the JSON-RPC payload arrives in.
var dataField = []byte("data:")

// Why a response carried no JSON-RPC document. Each maps to one sentence in
// Discovery.Error, and none of them reproduces a byte of the body or of the
// Content-Type that produced it.
var (
	errEmptyBody    = errors.New("empty body")
	errNoEvent      = errors.New("event stream carried no data event")
	errUnknownMedia = errors.New("media type is not a JSON-RPC response")
)

// rpcPayload pulls the JSON-RPC documents out of an upstream response: the
// body itself when it is JSON, and EVERY event's data when it is an event
// stream. Which of them answers the request is the caller's decision (see
// pickResponse) because a Streamable HTTP server is allowed to put its own
// notifications and requests on the POST's stream ahead of the response, and
// logging and progress notifications are the common case.
//
// This is the opposite job to listfilter's filterToolsListSSE, which
// reproduces the framing byte for byte in order to rewrite one payload in
// place. Here the framing is thrown away, so the two cannot share more than
// the primitives above. Both do now walk the whole stream, which is the one
// thing the two halves of the codebase have to agree about.
//
// An upstream that sends no Content-Type still sent one shape or the other,
// and the reference servers do omit it, so the body is asked rather than
// assumed. Each event's data lines are joined with newlines exactly as the
// event-stream grammar says to, so a server that wraps a long catalogue across
// several data: lines is read rather than reported as broken.
func rpcPayload(contentType string, body []byte) ([][]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errEmptyBody
	}
	shape := MediaType(contentType)
	if shape == "" {
		shape = "application/json"
		if LooksLikeSSE(body) {
			shape = "text/event-stream"
		}
	}
	switch shape {
	case "application/json":
		return [][]byte{body}, nil
	case "text/event-stream":
		return eventData(body)
	default:
		return nil, errUnknownMedia
	}
}

// eventData returns the data of every event that carried any, in the order the
// stream sent them. Every other field (comments, event:, id:, retry:) is
// skipped, because the only thing wanted here is the JSON-RPC documents the
// server put in the stream.
//
// Every event and not just the first: a server that sends a
// notifications/message or a progress notification before it answers the POST
// is behaving correctly, and reading only the first event reports it as a
// server that answered with no result.
func eventData(body []byte) ([][]byte, error) {
	var out [][]byte
	var data [][]byte
	flush := func() {
		if len(data) == 0 {
			return
		}
		joined := bytes.Join(data, []byte("\n"))
		data = data[:0]
		if len(bytes.TrimSpace(joined)) == 0 {
			return
		}
		out = append(out, joined)
	}
	for rest := body; len(rest) > 0; {
		line, _, next := NextLine(rest)
		rest = next
		if len(bytes.TrimSpace(line)) == 0 { // a blank line ends an event
			flush()
			continue
		}
		if !bytes.HasPrefix(line, dataField) {
			continue
		}
		// The one optional space after the colon belongs to the framing.
		payload := line[len(dataField):]
		if len(payload) > 0 && payload[0] == ' ' {
			payload = payload[1:]
		}
		data = append(data, payload)
	}
	// A stream the upstream closed without a trailing blank line still ended
	// its last event.
	flush()
	if len(out) == 0 {
		return nil, errNoEvent
	}
	return out, nil
}

// MediaType is the bare type from a Content-Type header: lowercased, with any
// parameters dropped, so application/json; charset=utf-8 is application/json.
func MediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

// NextLine splits one line off body and returns it without its terminator, the
// terminator itself, and the rest. All three endings the event-stream grammar
// allows are accepted: LF, CRLF and a bare CR. A walker that knew only about
// LF would read a CR-terminated stream as one enormous line, filter nothing,
// and report nothing wrong.
func NextLine(body []byte) (line, term, rest []byte) {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\n':
			return body[:i], body[i : i+1], body[i+1:]
		case '\r':
			if i+1 < len(body) && body[i+1] == '\n' {
				return body[:i], body[i : i+2], body[i+2:]
			}
			return body[:i], body[i : i+1], body[i+1:]
		}
	}
	return body, nil, nil
}

// LooksLikeSSE reports whether body opens with an event-stream field. It is
// only consulted when the upstream sent no Content-Type at all; every line the
// grammar allows starts with one of these names, and none of them is anything
// a JSON document could begin with.
func LooksLikeSSE(body []byte) bool {
	for len(body) > 0 {
		line, _, rest := NextLine(body)
		body = rest
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		for _, field := range [][]byte{dataField, []byte("event:"), []byte("id:"), []byte("retry:"), []byte(":")} {
			if bytes.HasPrefix(line, field) {
				return true
			}
		}
		return false
	}
	return false
}
