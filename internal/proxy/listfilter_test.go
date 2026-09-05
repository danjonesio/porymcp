package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// The catalogue and the gate are one policy asked twice, so every test here
// pairs "what did the client see listed" with "what happens when it calls the
// name that is missing". A filter that only hid tools would be decoration; one
// that only refused calls is what PORM-19 exists to fix.

// allowSafe is the policy most rows below are judged by: a key whose allowlist
// names one tool.
var allowSafe = toolPolicy{allow: []string{"safe_tool"}}

func TestFilterToolsListJSON(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		pol     toolPolicy
		want    string
		changed bool
		wantErr bool
	}{
		{
			name:    "allowlist removes one tool",
			body:    `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"},{"name":"danger"}]}}`,
			pol:     allowSafe,
			want:    `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"safe_tool"}]}}`,
			changed: true,
		},
		{
			// A page that filters down to nothing still has to carry its
			// cursor: a conformant client keeps paging on it, and an empty
			// page is not the end of the catalogue.
			name:    "nextCursor, _meta and unknown envelope keys survive",
			body:    `{"jsonrpc":"2.0","id":"x","result":{"tools":[{"name":"danger"}],"nextCursor":"abc","_meta":{"k":1}},"_extra":true}`,
			pol:     allowSafe,
			want:    `{"_extra":true,"id":"x","jsonrpc":"2.0","result":{"_meta":{"k":1},"nextCursor":"abc","tools":[]}}`,
			changed: true,
		},
		{
			// The fields the aggregate path drops, because it re-encodes tools
			// through a struct with four members. A surviving tool here is the
			// upstream's own bytes.
			name:    "a surviving tool keeps every field it arrived with",
			body:    `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","title":"Safe","annotations":{"readOnlyHint":true},"outputSchema":{"type":"object"},"inputSchema":{"type":"object"},"_meta":{"x":1}},{"name":"danger"}]}}`,
			pol:     allowSafe,
			want:    `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"safe_tool","title":"Safe","annotations":{"readOnlyHint":true},"outputSchema":{"type":"object"},"inputSchema":{"type":"object"},"_meta":{"x":1}}]}}`,
			changed: true,
		},
		{
			name: "nothing removed is byte-identical",
			body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"}]}}`,
			pol:  allowSafe,
			want: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"}]}}`,
		},
		{
			// The id is the client's only way to match this reply to its
			// request. Round-tripping it through an interface would round it
			// to ...992, a reply the client never asked for.
			name:    "an id past float64 precision is echoed exactly",
			body:    `{"jsonrpc":"2.0","id":9007199254740993,"result":{"tools":[{"name":"danger"}]}}`,
			pol:     allowSafe,
			want:    `{"id":9007199254740993,"jsonrpc":"2.0","result":{"tools":[]}}`,
			changed: true,
		},
		{
			name:    "markup in a description is not escaped",
			body:    `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"use <b>&</b>"},{"name":"danger"}]}}`,
			pol:     allowSafe,
			want:    `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"safe_tool","description":"use <b>&</b>"}]}}`,
			changed: true,
		},
		{
			name: "error envelope is understood and left alone",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`,
			pol:  allowSafe,
			want: `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`,
		},
		{
			name:    "batch array is passed through and reported",
			body:    `[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"danger"}]}}]`,
			pol:     allowSafe,
			want:    `[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"danger"}]}}]`,
			wantErr: true,
		},
		{
			name: "null tools is not corrected to an empty array",
			body: `{"jsonrpc":"2.0","id":1,"result":{"tools":null}}`,
			pol:  allowSafe,
			want: `{"jsonrpc":"2.0","id":1,"result":{"tools":null}}`,
		},
		{
			name:    "a result carrying no tools is reported",
			body:    `{"jsonrpc":"2.0","id":1,"result":{"prompts":[]}}`,
			pol:     allowSafe,
			want:    `{"jsonrpc":"2.0","id":1,"result":{"prompts":[]}}`,
			wantErr: true,
		},
		{
			name:    "empty body",
			body:    ``,
			pol:     allowSafe,
			want:    ``,
			wantErr: true,
		},
		{
			name:    "an HTML error page is passed through and reported",
			body:    `<html>502</html>`,
			pol:     allowSafe,
			want:    `<html>502</html>`,
			wantErr: true,
		},
		{
			// The gate judges a call naming nothing the same way: "" is not on
			// any allowlist. Hiding it keeps the catalogue and the gate in
			// agreement even about a malformed entry.
			name:    "an element with no name is dropped under an allowlist",
			body:    `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"description":"nameless"},{"name":"safe_tool"}]}}`,
			pol:     allowSafe,
			want:    `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"safe_tool"}]}}`,
			changed: true,
		},
		{
			name: "a policy with no rules changes nothing",
			body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"},{"name":"b"}]}}`,
			pol:  toolPolicy{},
			want: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"},{"name":"b"}]}}`,
		},
		{
			// The 1:1 endpoints' shape: the client sees the tool's own name,
			// the rule names the identity, and the advertised name is never
			// rewritten to match it.
			name:    "a rule matches the composed identity, not the advertised name",
			body:    `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"create_issue"},{"name":"list_issues"}]}}`,
			pol:     toolPolicy{tf: toolFilter("deny", "github__create_issue"), mode: modeCompose, slug: "github"},
			want:    `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"list_issues"}]}}`,
			changed: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, changed, err := filterToolsListJSON([]byte(c.body), c.pol)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
			if changed != c.changed {
				t.Errorf("changed=%v want %v", changed, c.changed)
			}
			if string(got) != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

// The list a single-upstream key is shown and the calls it may make are the
// same policy, so AC2 asserts both halves in one test: the catalogue is
// trimmed, everything the proxy has no opinion about survives the rewrite, and
// the tool that was hidden is refused when called by name.
func TestSingleUpstreamListRespectsAllowlist(t *testing.T) {
	const richList = `{"jsonrpc":"2.0","id":3,"result":{"tools":[` +
		`{"name":"safe_tool","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}},` +
		`{"name":"danger_tool","description":"drops the database"}` +
		`],"nextCursor":"abc","_meta":{"k":1}}}`

	f := newSingleFixture(t, upstreamSpec{RawList: richList}, []string{"safe_tool"}, nil)

	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got, want := strings.Join(listedNames(t, rr.Body.Bytes()), ","), "safe_tool"; got != want {
		t.Fatalf("listed %q want %q; the catalogue must not advertise a tool the gate refuses", got, want)
	}
	body := rr.Body.String()
	if strings.Contains(body, "danger_tool") {
		t.Errorf("the hidden tool is still in the body: %s", body)
	}
	// A rewrite must edit result.tools and nothing else: the cursor a client
	// pages on, the metadata it may key on, the schema it calls the tool with,
	// and the id it matches the reply against.
	for _, want := range []string{`"nextCursor":"abc"`, `"_meta"`, `"annotations"`, `"inputSchema"`, `"id":3`} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered body lost %s: %s", want, body)
		}
	}

	rr = f.post(toolCall("7", "danger_tool"))
	if rr.Code != http.StatusOK {
		t.Errorf("blocked call HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	code, msg, id := rpcErrorOf(t, rr.Body.Bytes())
	if code != codeInvalidParams || msg != "tool blocked" {
		t.Errorf("got %d %q want %d %q", code, msg, codeInvalidParams, "tool blocked")
	}
	if id != float64(7) {
		t.Errorf("id=%v want 7; a client that cannot match the error waits for a reply that never comes", id)
	}
	if n := f.count("solo", "tools/call", "danger_tool"); n != 0 {
		t.Errorf("the upstream saw %d calls for a tool it never advertised to this key", n)
	}
}

// Pass-through is the failure policy, and it has to be exact: a body the proxy
// does not rewrite is the upstream's bytes, unchanged.
func TestSingleUpstreamListPassesThroughNonJSON(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
	}{
		{"html", "text/html", `<html>502 upstream is unhappy</html>`},
		{"plain text", "text/plain", `tools: safe_tool, danger_tool`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{RawList: c.body, ListCT: c.ct}, []string{"safe_tool"}, nil)
			rr := f.post(listRequest)
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d", rr.Code)
			}
			if got := rr.Body.String(); got != c.body {
				t.Errorf("body was rewritten\ngot  %q\nwant %q", got, c.body)
			}
		})
	}
}

// An error envelope has no catalogue in it. Rewriting one would mean inventing
// a result member the upstream never sent.
func TestSingleUpstreamListErrorEnvelopeUntouched(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`
	f := newSingleFixture(t, upstreamSpec{RawList: body}, []string{"safe_tool"}, nil)
	logs := captureLogs(f)

	rr := f.post(listRequest)
	if got := rr.Body.String(); got != body {
		t.Errorf("got  %s\nwant %s", got, body)
	}
	if recs := logRecords(t, logs); len(recs) != 0 {
		t.Errorf("an understood body was logged as a pass-through: %v", recs)
	}
}

// A key with no rules must pay nothing for this feature: no rewrite, no
// re-encoding, and nothing in the log.
func TestSingleUpstreamListUnchangedWithoutPolicy(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"},{"name":"danger_tool"}],"nextCursor":"abc"}}`
	f := newSingleFixture(t, upstreamSpec{RawList: body}, nil, nil)
	logs := captureLogs(f)

	rr := f.post(listRequest)
	if got := rr.Body.String(); got != body {
		t.Errorf("a key with no policy had its catalogue rewritten\ngot  %s\nwant %s", got, body)
	}
	if recs := logRecords(t, logs); len(recs) != 0 {
		t.Errorf("logged something for a key with no policy: %v", recs)
	}
}

// Failing open is a decision, not an accident, so it is recorded. Without this
// an operator cannot tell a filter that is enforced from one that is inert,
// and the record itself must not become a way to read the upstream's
// catalogue out of the log file.
func TestListPassThroughWarns(t *testing.T) {
	const body = `<html>secret_tool</html>`
	f := newSingleFixture(t, upstreamSpec{RawList: body, ListCT: "text/html; charset=utf-8"}, []string{"safe_tool"}, nil)
	logs := captureLogs(f)

	if rr := f.post(listRequest); rr.Body.String() != body {
		t.Fatalf("body=%s want it passed through", rr.Body.String())
	}

	recs := logRecords(t, logs)
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %s", len(recs), logs.String())
	}
	rec := recs[0]
	want := map[string]any{
		"level":          "WARN",
		"msg":            "tools/list passed through unfiltered",
		"virtual_key_id": "a1",
		"upstream_id":    "u1",
		"media_type":     "text/html", // parameters stripped, as the switch saw it
		"bytes":          float64(len(body)),
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q]=%v want %v", k, rec[k], v)
		}
	}
	if strings.Contains(logs.String(), "secret_tool") {
		t.Errorf("the log carries the body the proxy could not read: %s", logs.String())
	}
}

// The media type on that record is the upstream's own string, so it is cut at
// auditFieldBytes like every other upstream string a row or a log line
// carries (PORM-98, security requirement 6). mcpclient.MediaType only splits
// at a semicolon, so a long bare type reaches the line whole.
func TestListPassThroughWarnsBoundsMediaType(t *testing.T) {
	long := "text/" + strings.Repeat("x", 1024)
	f := newSingleFixture(t, upstreamSpec{RawList: `<html></html>`, ListCT: long}, []string{"safe_tool"}, nil)
	logs := captureLogs(f)

	f.post(listRequest)

	recs := logRecords(t, logs)
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %s", len(recs), logs.String())
	}
	mt, _ := recs[0]["media_type"].(string)
	if mt == "" || len(mt) > auditFieldBytes {
		t.Errorf("media_type is %d bytes, want non-empty and at most %d", len(mt), auditFieldBytes)
	}
}

// A rewritten body is not the body the upstream computed its digests over, so
// anything claiming to describe those bytes has to go. The response allowlist
// (copyResponseHeaders, PORM-98) drops the integrity headers whether or not
// the body was rewritten, so both subtests assert absence: the filtered one
// proves a rewritten body reaches the client without a digest, whichever
// layer removed it, and the unfiltered one proves an untouched body carries no
// validator either.
func TestListFilterDropsIntegrityHeaders(t *testing.T) {
	const list = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"},{"name":"danger_tool"}]}}`
	spec := upstreamSpec{
		RawList:     list,
		RespHeaders: map[string]string{"ETag": `"v1"`, "Content-Digest": "sha-256=:abc:"},
	}

	t.Run("filtered", func(t *testing.T) {
		f := newSingleFixture(t, spec, []string{"safe_tool"}, nil)
		rr := f.post(listRequest)
		if rr.Body.String() == list {
			t.Fatal("the body was not filtered, so this test proves nothing")
		}
		for _, k := range []string{"ETag", "Content-Digest"} {
			if v := rr.Header().Get(k); v != "" {
				t.Errorf("%s=%q survived a rewrite; it describes bytes the client never received", k, v)
			}
		}
	})

	t.Run("unfiltered", func(t *testing.T) {
		f := newSingleFixture(t, spec, nil, nil)
		rr := f.post(listRequest)
		if rr.Body.String() != list {
			t.Fatal("a key with no policy had its body rewritten")
		}
		// A client cannot send If-None-Match back through copyHopHeaders, and
		// a 304 would become a 502 at mcpclient.Send, so a validator it
		// received could never be spent.
		for _, k := range []string{"ETag", "Content-Digest"} {
			if v := rr.Header().Get(k); v != "" {
				t.Errorf("%s=%q reached the client on an untouched body; the response allowlist drops it", k, v)
			}
		}
	})
}

// The payloads the SSE cases below are built from: one catalogue the filter
// trims, and the same catalogue with everything removed.
const (
	sseFull    = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"},{"name":"danger"}]}}`
	sseTrimmed = `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"safe_tool"}]}}`
	sseDanger  = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"danger"}]}}`
	sseEmptied = `{"id":1,"jsonrpc":"2.0","result":{"tools":[]}}`
	sseAllSafe = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool"}]}}`
)

// The framing belongs to the upstream and only the catalogue inside it is ours
// to edit, so every case here checks the bytes around the payload as closely as
// the payload itself.
func TestFilterToolsListSSE(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    string
		changed bool
		wantErr bool
	}{
		{
			name:    "single event",
			body:    "event: message\ndata: " + sseFull + "\n\n",
			want:    "event: message\ndata: " + sseTrimmed + "\n\n",
			changed: true,
		},
		{
			name:    "crlf endings and an id line",
			body:    "id: 7\r\nevent: message\r\ndata: " + sseDanger + "\r\n\r\n",
			want:    "id: 7\r\nevent: message\r\ndata: " + sseEmptied + "\r\n\r\n",
			changed: true,
		},
		{
			// A stream ended with bare CRs is legal and, read by a walker that
			// only knows LF, is one line long and filters to nothing.
			name:    "bare cr endings",
			body:    "event: message\rdata: " + sseFull + "\r\r",
			want:    "event: message\rdata: " + sseTrimmed + "\r\r",
			changed: true,
		},
		{
			name:    "a comment survives and no trailing newline is invented",
			body:    ": keep-alive\n\ndata: " + sseDanger,
			want:    ": keep-alive\n\ndata: " + sseEmptied,
			changed: true,
		},
		{
			// The single space after the colon is optional framing, not part
			// of the payload, so it comes back exactly as it went in.
			name:    "data with no space keeps its framing",
			body:    "data:" + sseFull + "\n\n",
			want:    "data:" + sseTrimmed + "\n\n",
			changed: true,
		},
		{
			name: "nothing to remove is byte-identical",
			body: "event: message\ndata: " + sseAllSafe + "\n\n",
			want: "event: message\ndata: " + sseAllSafe + "\n\n",
		},
		{
			// Its payload is the two lines joined; putting a filtered result
			// back would mean choosing where to break it up again.
			name:    "a multi-line data event is left to the call gate",
			body:    "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1}\n\n",
			want:    "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1}\n\n",
			wantErr: true,
		},
		{
			name:    "an unreadable payload is reported",
			body:    "data: <html>502</html>\n\n",
			want:    "data: <html>502</html>\n\n",
			wantErr: true,
		},
		{
			name:    "a stream carrying no data at all is reported",
			body:    ": keep-alive\n\n",
			want:    ": keep-alive\n\n",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, changed, err := filterToolsListSSE([]byte(c.body), allowSafe)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
			if changed != c.changed {
				t.Errorf("changed=%v want %v", changed, c.changed)
			}
			if string(got) != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}

	// An upstream that sends no Content-Type still sent one shape or the
	// other. Read as JSON, a stream would fail to decode and pass through,
	// which looks exactly like a filter that had nothing to do.
	t.Run("an absent content type is sniffed", func(t *testing.T) {
		var h Handler // no logger; the pass-through warn is covered elsewhere
		in := "event: message\ndata: " + sseFull + "\n\n"
		got, _ := h.filterListResponse([]byte(in), http.StatusOK, http.Header{}, allowSafe, nil, nil)
		if want := "event: message\ndata: " + sseTrimmed + "\n\n"; string(got) != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})
}

// The same catalogue as AC2, delivered the way the reference SDKs deliver it.
// Without this the single-upstream filter would be inert against most real
// upstreams and AC2 would only hold against a hand-written JSON server.
func TestSingleUpstreamListFilteredOverSSE(t *testing.T) {
	const richList = `{"jsonrpc":"2.0","id":3,"result":{"tools":[` +
		`{"name":"safe_tool","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}},` +
		`{"name":"danger_tool","description":"drops the database"}` +
		`],"nextCursor":"abc","_meta":{"k":1}}}`
	raw := "event: message\ndata: " + richList + "\n\n"

	f := newSingleFixture(t, upstreamSpec{RawList: raw, ListCT: "text/event-stream"}, []string{"safe_tool"}, nil)

	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list HTTP code=%d body=%q", rr.Code, rr.Body.String())
	}
	// A client that cannot tell a stream from a document cannot read the
	// answer. filterListResponse reads the media type off forward's private
	// clone before the copy-back runs; this is the client-visible half of
	// that (PORM-98, acceptance criterion 3).
	if got := rr.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type=%q want text/event-stream", got)
	}
	body := rr.Body.String()
	if !strings.HasPrefix(body, "event: message\ndata: ") || !strings.HasSuffix(body, "\n\n") {
		t.Errorf("the event framing was not reproduced: %q", body)
	}
	payload := ssePayload(t, body)
	if got, want := strings.Join(listedNames(t, []byte(payload)), ","), "safe_tool"; got != want {
		t.Fatalf("listed %q want %q", got, want)
	}
	for _, want := range []string{`"nextCursor":"abc"`, `"_meta"`, `"annotations"`, `"id":3`} {
		if !strings.Contains(payload, want) {
			t.Errorf("filtered payload lost %s: %s", want, payload)
		}
	}

	rr = f.post(toolCall("7", "danger_tool"))
	code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || code != codeInvalidParams || msg != "tool blocked" {
		t.Errorf("call on the hidden tool: HTTP %d, %d %q", rr.Code, code, msg)
	}
	if n := f.count("solo", "tools/call", "danger_tool"); n != 0 {
		t.Errorf("the upstream saw %d calls for a tool it never advertised to this key", n)
	}
}

// ssePayload is the body of the single data: line in an event stream.
func ssePayload(t *testing.T, stream string) string {
	t.Helper()
	for _, line := range strings.Split(stream, "\n") {
		if after, ok := strings.CutPrefix(line, "data:"); ok {
			return strings.TrimPrefix(after, " ")
		}
	}
	t.Fatalf("no data line in %q", stream)
	return ""
}

// toolFilter builds a group filter for a policy literal.
func toolFilter(mode string, tools ...string) models.ToolFilter {
	return models.ToolFilter{Mode: mode, Tools: tools}
}

// captureLogs points the handler's logger at a buffer. h.log is nil everywhere
// else in these tests, and a pass-through logged nowhere is indistinguishable
// from one that never happened.
func captureLogs(f *fixture) *bytes.Buffer {
	var buf bytes.Buffer
	f.H.log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buf
}

// logRecords decodes what captureLogs collected, one map per record.
func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v (%s)", err, line)
		}
		out = append(out, rec)
	}
	return out
}
