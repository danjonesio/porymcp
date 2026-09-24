package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

// Why a tools/list response went out whole. Neither error reaches the client,
// which is exactly why they exist: a pass-through is invisible from outside,
// so the operator is the only one who can be told about it.
var (
	// errUnreadableList: the body did not decode as a JSON-RPC envelope
	// carrying a result.tools array.
	errUnreadableList = errors.New("body is not a readable tools/list result")
	// errUnfilterableMedia: the response was in a format this filter has no
	// rewriter for.
	errUnfilterableMedia = errors.New("response media type cannot be filtered")
)

// filterListResponse trims a forwarded tools/list answer to the tools the gate
// would let this key call, and returns the headers that still describe the
// body it produced.
//
// It runs on the forward path, a single-upstream key, and a member endpoint by
// inheritance, which is why it is guarded on being on that path rather than on
// the key having no group. Before it, a key with an allowlist was handed the
// upstream's entire catalogue and discovered its own policy one refused call
// at a time.
//
// Anything it cannot prove it understands is returned exactly as it arrived.
// That is the deliberate failure policy: the gate in ServeHTTP is the control
// and this is presentation, so a catalogue the proxy cannot parse leaks tool
// names that still cannot be called, whereas failing closed would take an
// upstream offline for answering in a shape the proxy has not seen before.
// Every pass-through under an active policy is logged once, so an operator
// can tell an enforced filter from an inert one.
//
// Every tools/list passes through here, a key with no policy included, since
// the 2026-07-28 revision's cacheScope member is corrected on any list that
// carries one (see filterToolsListJSON). A key with no policy pays the parse
// and nothing else: a list it did not need to touch comes back byte for
// byte, and a list it could not read passes through without a log line, as
// it always did for such a key. The pol.active() decision lives here and
// nowhere below it, so the two filters cannot each keep a guard of their own
// that a caller forgets.
func (h *Handler) filterListResponse(body []byte, status int, hdr http.Header, pol toolPolicy, vk *models.VirtualKey, up *models.Upstream) ([]byte, http.Header) {
	if status < 200 || status >= 300 || len(body) == 0 {
		return body, hdr
	}

	mt := mcpclient.MediaType(hdr.Get("Content-Type"))
	// An upstream that sends no Content-Type still sent one shape or the
	// other, and guessing JSON at a stream would mean filtering nothing while
	// looking like it worked, so the body is asked instead.
	shape := mt
	if shape == "" {
		shape = "application/json"
		if mcpclient.LooksLikeSSE(body) {
			shape = "text/event-stream"
		}
	}
	var (
		out     []byte
		changed bool
		err     error
	)
	switch shape {
	case "application/json":
		out, changed, err = filterToolsListJSON(body, pol)
	case "text/event-stream":
		out, changed, err = filterToolsListSSE(body, pol)
	default:
		err = errUnfilterableMedia
	}
	if err != nil {
		// The line's contract is "unfiltered while a policy was active". A
		// key with no policy had nothing to enforce, so a body the proxy
		// could not read is relayed for it in silence, as it was before the
		// scope correction brought such keys here.
		if pol.active() {
			h.warnListPassThrough(vk, up, mt, len(body))
		}
		return body, hdr
	}
	if !changed {
		return body, hdr
	}

	// The body is no longer the one these headers were computed over. hdr is
	// the private clone forward returned, so deleting from it affects nothing
	// else. These deletions are this function's own contract over the clone it
	// returns; a tools/list is never streamed, so this is the one place its
	// headers are shaped. The copy-back
	// allowlist (copyResponseHeaders) excludes these four names as well; the
	// deletion stays so a later addition to that list cannot ship a digest
	// describing bytes the client never received. Content-Length needs no
	// handling here: the allowlist never copies it and net/http recomputes it.
	for _, k := range []string{"Etag", "Content-Digest", "Repr-Digest", "Digest"} {
		hdr.Del(k)
	}
	return out, hdr
}

// warnListPassThrough tells the operator a catalogue went out unfiltered while
// a policy was active. It carries what identifies the pair to fix and nothing
// else: no body bytes and no tool names, because the reason this record exists
// is that the proxy could not read the body, and logging fragments of a
// document it did not understand is how upstream data ends up in a log file.
func (h *Handler) warnListPassThrough(vk *models.VirtualKey, up *models.Upstream, mt string, size int) {
	if h.log == nil {
		return
	}
	// media_type is the one upstream header string a log line carries, so it
	// is bounded the way the audit row's fields are.
	h.log.Warn("tools/list passed through unfiltered",
		"virtual_key_id", vk.ID,
		"upstream_id", up.ID,
		"media_type", truncate(mt, auditFieldBytes),
		"bytes", size,
	)
}

// filterToolsListJSON rewrites result.tools, and nothing else, in a JSON-RPC
// tools/list response. It reports whether it removed anything and, separately,
// whether it failed to understand the body at all.
//
// The envelope, the result and each tool are handled as raw JSON so that
// everything the proxy has no opinion about survives untouched: nextCursor (a
// filtered page may legitimately empty while paging continues, so the cursor
// is never invented or dropped), _meta, unknown members, an id too large for a
// float64 to hold exactly, and a tool's annotations, outputSchema and title.
// Decoding tools into a struct is exactly how the aggregate path came to strip
// those fields, and re-encoding an id through an interface is how it corrupts
// large ones.
//
// When nothing was removed and the result carries no cacheScope, or one that
// already reads private (the common case, and every case against an upstream
// on an earlier revision) the original bytes are returned. Not re-encoding is
// both free and the only way to guarantee a body the proxy did not need to
// touch is passed on byte for byte.
//
// cacheScope is the revision's cache directive for the client's own store.
// The proxy never adds one: a list that carried none is returned as it came.
// It corrects one it relays, whether or not a tool was removed: one /mcp URL
// answers for every key and the same upstream catalogue is a different
// document per key, so "public" is a claim this proxy cannot honour on any
// list it answers, which is the same reason serve writes Cache-Control:
// no-store on every response. Only tools/list comes through here;
// resources/list and prompts/list are relayed as they arrive (PORM-6).
func filterToolsListJSON(body []byte, pol toolPolicy) ([]byte, bool, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return body, false, errUnreadableList
	}
	if _, failed := env["error"]; failed {
		// An error envelope carries no catalogue to trim. It was understood,
		// so it is not a pass-through worth an operator's attention.
		return body, false, nil
	}
	rawResult, ok := env["result"]
	if !ok {
		return body, false, errUnreadableList
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return body, false, errUnreadableList
	}
	rawTools, ok := result["tools"]
	if !ok {
		return body, false, errUnreadableList
	}
	// A null tools member decodes to a nil slice with nothing to remove, so it
	// is returned as it came rather than being "corrected" to [].
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return body, false, errUnreadableList
	}

	kept := make([]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		// Only the name is decoded. An element that is not an object, or that
		// carries no name, has the identity "", which the policy then judges
		// exactly as the gate would judge a call naming nothing: dropped under
		// an allowlist, kept when only a denylist applies.
		var probe struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(tool, &probe)
		if pol.permits(probe.Name) {
			kept = append(kept, tool)
		}
	}
	scope, hasScope := result["cacheScope"]
	needScope := hasScope && !bytes.Equal(bytes.TrimSpace(scope), []byte(`"private"`))
	if len(kept) == len(tools) && !needScope {
		return body, false, nil
	}

	// kept was made with a length, so an emptied page marshals as "tools":[]
	// and never as null: a client can read the first and loop on nextCursor,
	// where the second is a decode error waiting to happen.
	newTools, err := marshalRaw(kept)
	if err != nil {
		return body, false, err
	}
	result["tools"] = newTools
	if hasScope {
		result["cacheScope"] = json.RawMessage(`"private"`)
	}
	newResult, err := marshalRaw(result)
	if err != nil {
		return body, false, err
	}
	env["result"] = newResult
	out, err := marshalRaw(env)
	if err != nil {
		return body, false, err
	}
	return out, true, nil
}

// dataField is the SSE field the JSON-RPC payload arrives in.
var dataField = []byte("data:")

// filterToolsListSSE runs the JSON filter over the payload of each event in a
// buffered event stream and copies every other byte through untouched.
//
// It exists because the reference MCP SDKs answer a POST with
// text/event-stream unless they are configured not to (enableJsonResponse in
// the TypeScript transport, json_response in the Python one, both false by
// default) so a JSON-only filter would be inert against most real upstreams
// and this proxy would only look like it worked against a hand-written test
// server.
//
// Only an event carrying exactly one data: line is rewritten. The payload of a
// multi-line event is its lines joined, and putting a filtered result back
// would mean choosing where to break it up again; those are left to the call
// gate and reported. The framing is walkSSE's, shared with the error
// redaction on the same path (PORM-195).
func filterToolsListSSE(body []byte, pol toolPolicy) ([]byte, bool, error) {
	var understood, unreadable int
	out, changed, _, err := walkSSE(body, func(payload []byte, count int) ([]byte, bool, error) {
		if count > 1 {
			unreadable++
			return nil, false, nil
		}
		switch filtered, ok, err := filterToolsListJSON(payload, pol); {
		case err != nil:
			unreadable++
			return nil, false, nil
		case ok:
			understood++
			return filtered, true, nil
		default:
			understood++
			return nil, false, nil
		}
	}, nil)
	if err != nil {
		return body, false, err
	}
	if !changed {
		// Nothing was removed. That is only good news if the stream was read:
		// a body whose events could not be understood, or that held no data
		// at all, went out whole and the operator should hear about it.
		if unreadable > 0 || understood == 0 {
			return body, false, errUnreadableList
		}
		return body, false, nil
	}
	return out, true, nil
}

// walkSSE calls fn on every event that has at least one data: line, with the
// payloads joined by "\n" as eventData joins them and count the number of
// data: lines, and returns the body with each changed event re-encoded as one
// data: line at the first data: line's position, keeping that line's optional
// space. Every other line (a comment, id:, event:, retry:, an unknown field,
// a whitespace-only line) and every terminator is copied as it is; a
// whitespace-only line is written as line plus terminator. An event ends on a
// line that bytes.TrimSpace empties, the rule eventData uses, so a rewrite
// never sees a coarser split than the judge; a client that joins across such
// a line joins already-rewritten documents. The output is allocated only when
// an event changes, and the join of a multi-line event reuses one scratch
// buffer across the walk, so a walk over an unchanged body of single-line
// events allocates nothing and returns body itself. seen is how many events
// had a data: line; err is fn's own error, and the walk stops on it.
//
// join is a caller's scratch for the multi-line payload, kept across walks by
// a caller that walks once per event, or nil for one of the walk's own.
func walkSSE(body []byte, fn func(payload []byte, count int) ([]byte, bool, error), join *[]byte) (out []byte, changed bool, seen int, err error) {
	var local []byte
	if join == nil {
		join = &local
	}
	var (
		buf                *bytes.Buffer
		copied             int // body[:copied] is already in buf
		eventStart         int // offset of the current event's first line
		count              int // data: lines seen in the current event
		firstPay, firstEnd int // payload range of the first data: line
	)
	// flush finishes the event that ends at eventEnd, the offset of its
	// ending line or of the end of the body.
	flush := func(eventEnd int) error {
		if count == 0 {
			return nil
		}
		seen++
		payload := body[firstPay:firstEnd]
		if count > 1 {
			*join = (*join)[:0]
			for rest := body[eventStart:eventEnd]; len(rest) > 0; {
				line, _, next := mcpclient.NextLine(rest)
				rest = next
				if p, ok := dataPayload(line); ok {
					if len(*join) > 0 {
						*join = append(*join, '\n')
					}
					*join = append(*join, p...)
				}
			}
			payload = *join
		}
		res, ok, err := fn(payload, count)
		if err != nil {
			return err
		}
		count = 0
		if !ok {
			return nil
		}
		if buf == nil {
			buf = new(bytes.Buffer)
			buf.Grow(len(body))
		}
		buf.Write(body[copied:eventStart])
		first := true
		for rest := body[eventStart:eventEnd]; len(rest) > 0; {
			line, term, next := mcpclient.NextLine(rest)
			rest = next
			if _, isData := dataPayload(line); isData {
				if !first {
					continue
				}
				first = false
				// The one optional space after the colon belongs to the
				// framing, so it is measured and put back as it was.
				prefix := line[:len(dataField)]
				if len(line) > len(dataField) && line[len(dataField)] == ' ' {
					prefix = line[:len(dataField)+1]
				}
				buf.Write(prefix)
				buf.Write(res)
				buf.Write(term)
				continue
			}
			buf.Write(line)
			buf.Write(term)
		}
		copied = eventEnd
		return nil
	}

	for pos := 0; pos < len(body); {
		line, term, _ := mcpclient.NextLine(body[pos:])
		lineStart, lineEnd := pos, pos+len(line)
		pos = lineEnd + len(term)
		if len(bytes.TrimSpace(line)) == 0 { // a blank line ends an event
			if err := flush(lineStart); err != nil {
				return nil, false, seen, err
			}
			eventStart = pos
			continue
		}
		if p, ok := dataPayload(line); ok {
			count++
			if count == 1 {
				firstPay, firstEnd = lineEnd-len(p), lineEnd
			}
		}
	}
	if err := flush(len(body)); err != nil {
		return nil, false, seen, err
	}
	if buf == nil {
		return body, false, seen, nil
	}
	buf.Write(body[copied:])
	return buf.Bytes(), true, seen, nil
}

// dataPayload is a data: line's payload, without the one optional space
// after the colon, and whether the line is one.
func dataPayload(line []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, dataField) {
		return nil, false
	}
	p := line[len(dataField):]
	if len(p) > 0 && p[0] == ' ' {
		p = p[1:]
	}
	return p, true
}

// marshalRaw encodes v with HTML escaping turned off. json.Marshal escapes
// <, > and & by default, so a description reading "use <b>&</b>" would come
// back with those three characters replaced by Unicode escapes: valid JSON,
// but not the bytes the upstream wrote, in a field an agent reads as prose.
// The Encoder appends a newline that has no place inside a JSON document, so
// it is trimmed back off.
func marshalRaw(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}
