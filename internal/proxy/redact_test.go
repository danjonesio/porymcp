package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

// echoedToken is the credential the stub upstream is given and echoes back
// inside its JSON-RPC error.
const echoedToken = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

// fragments is every 8-byte window of tok: a stored fragment of a
// credential is a leak as much as the whole is.
func fragments(tok string) []string {
	var out []string
	for i := 0; i+8 <= len(tok); i++ {
		out = append(out, tok[i:i+8])
	}
	return out
}

// errorAnswer is a JSON-RPC error document whose message is msg.
func errorAnswer(id int, msg string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"error":{"code":-32000,"message":%q}}`, id, msg)
}

// escapeEvery writes every nth byte of s as a JSON \u escape, so a reader
// that never decodes the message sees no run long enough for any rule.
func escapeEvery(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i%n == 0 {
			fmt.Fprintf(&b, `\u%04x`, s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// assertSentToken proves the proxy presented the credential the upstream
// then echoed: the last request the stub saw carried it.
func assertSentToken(t *testing.T, f *fixture) {
	t.Helper()
	reqs := f.requestsTo("solo")
	if len(reqs) == 0 {
		t.Fatal("the upstream saw no request")
	}
	if got := reqs[len(reqs)-1].Header.Get("Authorization"); got != "Bearer "+echoedToken {
		t.Fatalf("upstream saw Authorization=%q, want the stored bearer", got)
	}
}

// assertRedactedRow is what every row an echoing upstream produces must
// read: the upstream's sentence with the credential replaced, and no
// fragment of the credential anywhere in it.
func assertRedactedRow(t *testing.T, row models.AuditLog) {
	t.Helper()
	if row.Status != models.StatusError {
		t.Errorf("row status=%q, want error", row.Status)
	}
	if !strings.HasPrefix(row.ErrorMessage, "invalid token ") || !strings.Contains(row.ErrorMessage, "[redacted]") {
		t.Errorf("row error_message=%q, want \"invalid token [redacted]\"", row.ErrorMessage)
	}
	assertNoLeak(t, "row error_message", row.ErrorMessage, fragments(echoedToken)...)
}

// TestUpstreamErrorMessageIsRedacted is PORM-72 criterion 1 and security
// requirements 2 and 6: an upstream that echoes the bearer it was sent in
// its JSON-RPC error produces a row that names the failure and not the
// credential, on the buffered JSON answer, the buffered SSE answer, a
// JSON-escaped answer and the stream.
func TestUpstreamErrorMessageIsRedacted(t *testing.T) {
	msg := "invalid token " + echoedToken
	buffered := []struct{ name, ct, body string }{
		{"json", "", errorAnswer(7, msg)},
		{"sse", "text/event-stream", sseFrame(errorAnswer(7, msg))},
		// The upstream JSON-escapes every sixth byte of the token. Decoded,
		// the token is whole and a rule takes it; undecoded, no piece
		// reaches 20 characters, nothing matches and the row would carry
		// no [redacted], so this subtest fails against a reader that does
		// not unescape.
		{"escaped", "", `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"invalid token ` + escapeEvery(echoedToken, 6) + `"}}`},
	}
	for _, tc := range buffered {
		t.Run(tc.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallCT: tc.ct, CallBody: tc.body}, nil, nil)
			rr := f.post(toolCall("7", "ping_tool"))
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d want 200", rr.Code)
			}
			assertSentToken(t, f)
			assertRedactedRow(t, f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0])
		})
	}
	t.Run("stream", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, Handler: thenClose(sseFrame(progressDoc), sseFrame(errorAnswer(1, msg)))}, nil, nil)
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		assertSentToken(t, f)
		assertRedactedRow(t, oneRow(t, f, id))
	})
}

// TestErrorMessageIsBounded is PORM-72 criterion 3 and security requirement
// 2: a 100 KB error.message with the credential placed across the stored
// bound produces a row at or under audit.ErrorMessageBytes, valid UTF-8,
// with no fragment of the credential, on the JSON and the SSE answer.
func TestErrorMessageIsBounded(t *testing.T) {
	// 245 bytes of words ending in a space, so the token starts at byte
	// 245 as its own word and crosses the 256-byte bound.
	filler := strings.Repeat("word ", 49)
	msg := filler + echoedToken + strings.Repeat(" word", 20<<10)
	for _, tc := range []struct{ name, ct, body string }{
		{"json", "", errorAnswer(7, msg)},
		{"sse", "text/event-stream", sseFrame(errorAnswer(7, msg))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallCT: tc.ct, CallBody: tc.body}, nil, nil)
			rr := f.post(toolCall("7", "ping_tool"))
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d want 200", rr.Code)
			}
			row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
			if row.Status != models.StatusError {
				t.Errorf("row status=%q, want error", row.Status)
			}
			if n := len(row.ErrorMessage); n > audit.ErrorMessageBytes {
				t.Errorf("row error_message is %d bytes, want at most %d", n, audit.ErrorMessageBytes)
			}
			if !utf8.ValidString(row.ErrorMessage) {
				t.Errorf("row error_message is not valid UTF-8: %q", row.ErrorMessage)
			}
			if !strings.HasPrefix(row.ErrorMessage, "word word") {
				t.Errorf("row error_message=%q, want the upstream's text first", row.ErrorMessage)
			}
			assertNoLeak(t, "row error_message", row.ErrorMessage, fragments(echoedToken)...)
		})
	}
}

// assertRedactedAnswer is what every answer an echoing upstream produces
// must read at the client (PORM-195 criteria 1 and 2, security requirements
// 1, 2, 8 and 9): the upstream's sentence with the credential replaced, its
// code and id, no fragment of the credential anywhere, and a row that
// records the same message.
func assertRedactedAnswer(t *testing.T, f *fixture, body []byte, wantID string, row models.AuditLog) {
	t.Helper()
	assertSentToken(t, f)
	if !strings.Contains(string(body), "invalid token [redacted]") {
		t.Errorf("client body lacks \"invalid token [redacted]\": %.300s", body)
	}
	assertNoLeak(t, "client body", string(body), fragments(echoedToken)...)
	doc := body
	if docs, err := mcpclient.PickResponse("text/event-stream", body, wantID); err == nil && mcpclient.LooksLikeSSE(body) {
		doc = docs
	}
	code, _, id := rpcErrorOf(t, doc)
	if code != -32000 || fmt.Sprint(id) != wantID {
		t.Errorf("client error code=%d id=%v, want -32000 and %s", code, id, wantID)
	}
	assertRedactedRow(t, row)
}

// TestUpstreamErrorAnswerToClientIsRedacted is PORM-195 criteria 1 and 2:
// an upstream that echoes the bearer it was sent in its JSON-RPC error
// answers the key holder with the sentence and not the credential, on the
// JSON answer, the buffered SSE answer, a mislabelled answer, an escaped
// answer, a long answer, the stream in three shapes, the member endpoint on
// each door, the group's reduced and unreduced answers and a tools/list
// error. Criterion 3, the unchanged relay of a result and of an error with
// nothing to redact, is pinned by relay_status_test.go,
// TestJSONAnswerRelayedByteIdentical and TestStreamReachesClientEventByEvent.
func TestUpstreamErrorAnswerToClientIsRedacted(t *testing.T) {
	msg := "invalid token " + echoedToken
	long := strings.Repeat("word ", 20<<10) + echoedToken // 100 KiB, the token past the client bound
	const offIDResult = `{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"later"}]}}`

	buffered := []struct {
		name, ct, body string
		code           int
		member         bool
	}{
		{name: "json", body: errorAnswer(7, msg)},
		{name: "sse", ct: "text/event-stream", code: 500, body: sseFrame(progressDoc) + sseFrame(errorAnswer(7, msg))},
		{name: "text_plain", ct: "text/plain", body: errorAnswer(7, msg)},
		{name: "escaped", body: `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"invalid token ` + escapeEvery(echoedToken, 6) + `"}}`},
		{name: "member_json", body: errorAnswer(7, msg), member: true},
		{name: "member_sse", ct: "text/event-stream", code: 500, body: sseFrame(errorAnswer(7, msg)), member: true},
	}
	for _, tc := range buffered {
		t.Run(tc.name, func(t *testing.T) {
			spec := upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallCT: tc.ct, CallBody: tc.body, CallCode: tc.code}
			if tc.name == "json" {
				spec.RespHeaders = map[string]string{"Mcp-Session-Id": "sess-195"}
			}
			var f *fixture
			var rr *httptest.ResponseRecorder
			if tc.member {
				f = singleMember(t, spec)
				rr = f.postMember("solo", toolCall("7", "ping_tool"))
			} else {
				f = newSingleFixture(t, spec, nil, nil)
				rr = f.post(toolCall("7", "ping_tool"))
			}
			if want := max(tc.code, http.StatusOK); rr.Code != want {
				t.Fatalf("HTTP code=%d want %d", rr.Code, want)
			}
			row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
			assertRedactedAnswer(t, f, rr.Body.Bytes(), "7", row)
			if int64(rr.Body.Len()) != int64(row.ResponseSizeBytes) {
				t.Errorf("row size=%d, client got %d bytes", row.ResponseSizeBytes, rr.Body.Len())
			}
			if tc.name == "json" {
				// Caller's usage 1: the exact document, sorted members and
				// raw values, under the JSON label, with the upstream's
				// session id still crossing.
				const want = `{"error":{"code":-32000,"message":"invalid token [redacted]"},"id":7,"jsonrpc":"2.0"}`
				if got := rr.Body.String(); got != want {
					t.Errorf("body=%s\nwant %s", got, want)
				}
				if got := rr.Header().Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type=%q want application/json", got)
				}
				if got := rr.Header().Get("Mcp-Session-Id"); got != "sess-195" {
					t.Errorf("Mcp-Session-Id=%q, want the upstream's to cross a rewritten answer", got)
				}
			}
			if tc.name == "sse" && !strings.Contains(rr.Body.String(), sseFrame(progressDoc)) {
				t.Errorf("the progress event did not cross byte for byte: %.200s", rr.Body.String())
			}
		})
	}

	t.Run("long", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallBody: errorAnswer(7, long)}, nil, nil)
		rr := f.post(toolCall("7", "ping_tool"))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200", rr.Code)
		}
		assertSentToken(t, f)
		assertNoLeak(t, "client body", rr.Body.String(), fragments(echoedToken)...)
		_, got, _ := rpcErrorOf(t, rr.Body.Bytes())
		if len(got) > clientMessageBytes || !strings.HasPrefix(got, "word word") {
			t.Errorf("client message is %d bytes starting %.20q, want the upstream's words cut at %d", len(got), got, clientMessageBytes)
		}
		row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
		if len(row.ErrorMessage) > audit.ErrorMessageBytes {
			t.Errorf("row error_message is %d bytes", len(row.ErrorMessage))
		}
		assertNoLeak(t, "row", row.ErrorMessage, fragments(echoedToken)...)
	})

	t.Run("json_content_length", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallBody: errorAnswer(1, msg)}, nil, nil)
		srv := f.serve()
		req, _ := f.streamRequest(srv, "/a1/mcp", toolCall("1", "ping_tool"), nil)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.ContentLength != -1 && resp.ContentLength != int64(len(body)) {
			t.Errorf("Content-Length=%d, body is %d bytes", resp.ContentLength, len(body))
		}
		assertNoLeak(t, "client body", string(body), fragments(echoedToken)...)
	})

	// The stream door: a framed error after a progress event, bare JSON
	// under the label in three shapes, a token cut across two writes, and
	// the member endpoint.
	split := func(w http.ResponseWriter, r *http.Request) {
		sseHeader(w)
		doc := errorAnswer(1, msg)
		cut := strings.Index(doc, echoedToken) + len(echoedToken)/2
		writeEvents(w, "data: "+doc[:cut])
		time.Sleep(50 * time.Millisecond)
		writeEvents(w, doc[cut:]+"\n\n")
	}
	streams := []struct {
		name, path string
		handler    http.HandlerFunc
		member     bool
	}{
		// The result after the error carries another id, so the row is judged
		// from the error and the result only has to cross byte for byte.
		{name: "stream", path: "/a1/mcp", handler: thenClose(sseFrame(progressDoc), sseFrame(errorAnswer(1, msg)), sseFrame(offIDResult))},
		{name: "stream_unframed", path: "/a1/mcp", handler: thenClose(errorAnswer(1, msg))},
		{name: "stream_unframed_lf", path: "/a1/mcp", handler: thenClose(errorAnswer(1, msg) + "\n")},
		{name: "stream_unframed_pretty", path: "/a1/mcp", handler: thenClose("{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"error\": {\"code\": -32000, \"message\": \"" + msg + "\"}\n}\n")},
		{name: "stream_split", path: "/a1/mcp", handler: split},
		{name: "member_stream", path: "/a1/solo/mcp", handler: thenClose(sseFrame(progressDoc), sseFrame(errorAnswer(1, msg))), member: true},
	}
	for _, tc := range streams {
		t.Run(tc.name, func(t *testing.T) {
			spec := upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, Handler: tc.handler}
			var f *fixture
			if tc.member {
				f = singleMember(t, spec)
			} else {
				f = newSingleFixture(t, spec, nil, nil)
			}
			srv := f.serve()
			resp, id := open(t, f, srv, tc.path, toolCall("1", "ping_tool"))
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			row := oneRow(t, f, id)
			assertRedactedAnswer(t, f, body, "1", row)
			if int64(len(body)) != int64(row.ResponseSizeBytes) {
				t.Errorf("row size=%d, client read %d bytes", row.ResponseSizeBytes, len(body))
			}
			if tc.name == "stream" {
				for _, ev := range []string{sseFrame(progressDoc), sseFrame(offIDResult)} {
					if !strings.Contains(string(body), ev) {
						t.Errorf("event did not cross byte for byte: %q", ev)
					}
				}
			}
		})
	}

	t.Run("group", func(t *testing.T) {
		f := singleMember(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallBody: errorAnswer(7, msg)})
		rr := f.post(toolCall("7", "solo__ping_tool"))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
		}
		row := f.waitAudit(models.LogFilter{Tool: "solo__ping_tool"})[0]
		assertRedactedAnswer(t, f, rr.Body.Bytes(), "7", row)
	})

	t.Run("group_unreduced", func(t *testing.T) {
		// One event past MaxPickDocuments, so PickResponse gives up and the
		// member's raw SSE is relayed: every error event in it is rewritten.
		body := strings.Repeat(sseFrame(progressDoc), mcpclient.MaxPickDocuments) + sseFrame(errorAnswer(7, msg))
		f := singleMember(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallCT: "text/event-stream", CallBody: body})
		rr := f.post(toolCall("7", "solo__ping_tool"))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200", rr.Code)
		}
		assertSentToken(t, f)
		if !strings.Contains(rr.Body.String(), "invalid token [redacted]") {
			t.Errorf("client body lacks the redacted message; tail %.200q", rr.Body.String()[max(0, rr.Body.Len()-200):])
		}
		assertNoLeak(t, "client body", rr.Body.String(), fragments(echoedToken)...)
	})

	t.Run("tools_list_error", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Bearer: echoedToken, RawList: errorAnswer(7, msg)}, nil, nil)
		rr := f.post(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200", rr.Code)
		}
		assertSentToken(t, f)
		assertNoLeak(t, "client body", rr.Body.String(), fragments(echoedToken)...)
		if !strings.Contains(rr.Body.String(), "invalid token [redacted]") {
			t.Errorf("client body=%s", rr.Body.String())
		}
	})
}

// TestBufferedSSEResultIsRelayedUnchanged is PORM-195 criterion 3 on the
// buffered path: an SSE-framed body the gate walks (a non-2xx status, which
// keeps it off the stream door) carrying a result and a progress event
// crosses byte for byte, whichever framing the walk had to read.
func TestBufferedSSEResultIsRelayedUnchanged(t *testing.T) {
	body := sseFrame(progressDoc) + "id: 3\r\ndata: " + resultDoc + "\r\n\r\n"
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: echoedToken, CallCT: "text/event-stream", CallCode: 503, CallBody: body, RespHeaders: map[string]string{"Mcp-Session-Id": "sess-3"}}, nil, nil)
	rr := f.post(toolCall("1", "ping_tool"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP code=%d want 503", rr.Code)
	}
	assertRelayUnchanged(t, rr.Header(), rr.Body.String(), body, "text/event-stream", "sess-3")
}
