package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/netcasklabs/porymcp/internal/mcpclient"
	"github.com/netcasklabs/porymcp/internal/models"
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
// It runs on the forward path — a single-upstream key, and a member endpoint
// by inheritance, which is why it is guarded on being on that path rather than
// on the key having no group. Before it, a key with an allowlist was handed
// the upstream's entire catalogue and discovered its own policy one refused
// call at a time.
//
// Anything it cannot prove it understands is returned exactly as it arrived.
// That is the deliberate failure policy: the gate in ServeHTTP is the control
// and this is presentation, so a catalogue the proxy cannot parse leaks tool
// names that still cannot be called, whereas failing closed would take an
// upstream offline for answering in a shape the proxy has not seen before.
// Every pass-through is logged once, so an operator can tell an enforced
// filter from an inert one.
func (h *Handler) filterListResponse(body []byte, status int, hdr http.Header, pol toolPolicy, vk *models.VirtualKey, up *models.Upstream) ([]byte, http.Header) {
	if status < 200 || status >= 300 || len(body) == 0 || !pol.active() {
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
		h.warnListPassThrough(vk, up, mt, len(body))
		return body, hdr
	}
	if !changed {
		return body, hdr
	}

	// The body is no longer the one these headers were computed over. hdr is
	// the private clone forward returned, so deleting from it affects nothing
	// else. Content-Length needs no handling here: the copy-back loop skips
	// it and net/http recomputes it.
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
	h.log.Warn("tools/list passed through unfiltered",
		"virtual_key_id", vk.ID,
		"upstream_id", up.ID,
		"media_type", mt,
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
// When nothing was removed — the common case, and every case for a key with no
// policy — the original bytes are returned. Not re-encoding is both free and
// the only way to guarantee a body the proxy did not need to touch is passed
// on byte for byte.
func filterToolsListJSON(body []byte, pol toolPolicy) ([]byte, bool, error) {
	if !pol.active() {
		return body, false, nil
	}

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
		// carries no name, has the identity "" — which the policy then judges
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
	if len(kept) == len(tools) {
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
// text/event-stream unless they are configured not to — enableJsonResponse in
// the TypeScript transport, json_response in the Python one, both false by
// default — so a JSON-only filter would be inert against most real upstreams
// and this proxy would only look like it worked against a hand-written test
// server.
//
// Only an event carrying exactly one data: line is rewritten. The payload of a
// multi-line event is its lines joined, and putting a filtered result back
// would mean choosing where to break it up again; those are left to the call
// gate and reported. Comments, id:, event: and retry: lines, blank lines, the
// original line endings and a missing trailing newline are all reproduced
// exactly, because the framing is the upstream's and only the catalogue inside
// it is ours to edit.
func filterToolsListSSE(body []byte, pol toolPolicy) ([]byte, bool, error) {
	if !pol.active() {
		return body, false, nil
	}

	var (
		out        bytes.Buffer
		lines      [][]byte // the current event's lines, terminators stripped
		terms      [][]byte // and the terminator each one had
		changed    bool
		understood int
		unreadable int
	)
	out.Grow(len(body))

	// flush emits one event, rewritten if it turned out to carry a catalogue.
	flush := func() {
		idx, count := -1, 0
		for i, line := range lines {
			if bytes.HasPrefix(line, dataField) {
				count++
				idx = i
			}
		}
		switch {
		case count > 1:
			unreadable++
		case count == 1:
			// The one optional space after the colon belongs to the framing,
			// so it is measured here and put back as it was rather than
			// normalised.
			prefix, payload := lines[idx][:len(dataField)], lines[idx][len(dataField):]
			if len(payload) > 0 && payload[0] == ' ' {
				prefix, payload = lines[idx][:len(dataField)+1], payload[1:]
			}
			switch filtered, ok, err := filterToolsListJSON(payload, pol); {
			case err != nil:
				unreadable++
			case ok:
				lines[idx] = append(append([]byte{}, prefix...), filtered...)
				changed = true
				understood++
			default:
				understood++
			}
		}
		for i, line := range lines {
			out.Write(line)
			out.Write(terms[i])
		}
		lines, terms = lines[:0], terms[:0]
	}

	for rest := body; len(rest) > 0; {
		line, term, next := mcpclient.NextLine(rest)
		rest = next
		if len(line) == 0 { // a blank line ends an event
			flush()
			out.Write(term)
			continue
		}
		lines = append(lines, line)
		terms = append(terms, term)
	}
	flush()

	if !changed {
		// Nothing was removed. That is only good news if the stream was read:
		// a body whose events could not be understood, or that held no data
		// at all, went out whole and the operator should hear about it.
		if unreadable > 0 || understood == 0 {
			return body, false, errUnreadableList
		}
		return body, false, nil
	}
	return out.Bytes(), true, nil
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
