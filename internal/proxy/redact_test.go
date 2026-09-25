package proxy

import (
	"context"
	"encoding/json"
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

// assertRedactedRefusal is what a refusal that is not JSON-RPC must read at
// the client (PORM-205 criterion 1, security requirements 1, 7 and 8): the
// upstream's text with the credential replaced and nothing else changed, no
// fragment of the credential anywhere, and a row judged as today with the
// size the client was actually sent.
func assertRedactedRefusal(t *testing.T, f *fixture, rr *httptest.ResponseRecorder, wantBody string, row models.AuditLog) {
	t.Helper()
	assertSentToken(t, f)
	if got := rr.Body.String(); got != wantBody {
		t.Errorf("client body:\n got %.300q\nwant %.300q", got, wantBody)
	}
	assertNoLeak(t, "client body", rr.Body.String(), fragments(echoedToken)...)
	if row.Status != models.StatusError || row.ErrorMessage != "" {
		t.Errorf("row status=%q error_message=%q, want error / empty", row.Status, row.ErrorMessage)
	}
	if rr.Body.Len() != row.ResponseSizeBytes {
		t.Errorf("row size=%d, client got %d bytes", row.ResponseSizeBytes, rr.Body.Len())
	}
}

// TestUpstreamRefusalToClientIsRedacted is PORM-205 criterion 1 with
// amendment A1: an upstream that refuses a tools/call before its JSON-RPC
// layer and quotes the bearer it was sent answers the key holder with its
// text and not the credential, in plain text, HTML, problem JSON, OAuth-style
// JSON, under a wrong event-stream label, beside an invalid byte and past
// the client bound, on the single key and the member endpoint. On the group
// endpoint a text refusal keeps reaching the client as its status with no
// body, and a JSON one is redacted like the others.
func TestUpstreamRefusalToClientIsRedacted(t *testing.T) {
	tok := echoedToken
	page := "<html><body><p>invalid token " + tok + "</p></body></html>"
	redactedPage := "<html><body><p>invalid token [redacted]</p></body></html>"
	const html = "text/html; charset=utf-8"
	type door int
	const (
		single door = iota
		member
		group
	)
	cases := []struct {
		name, ct, body string
		door           door
		want, wantCT   string // the exact body and label the client gets
		check          func(t *testing.T, rr *httptest.ResponseRecorder)
	}{
		{name: "single_text_plain", ct: "text/plain", body: "invalid token " + tok, want: "invalid token [redacted]", wantCT: "text/plain"},
		{name: "single_text_html", ct: html, body: page, want: redactedPage, wantCT: html},
		{name: "member_text_plain", ct: "text/plain", body: "invalid token " + tok, door: member, want: "invalid token [redacted]", wantCT: "text/plain"},
		{name: "member_text_html", ct: html, body: page, door: member, want: redactedPage, wantCT: html},
		{name: "group_text_plain", ct: "text/plain", body: "invalid token " + tok, door: group, want: "", wantCT: ""},
		{name: "group_text_html", ct: html, body: page, door: group, want: "", wantCT: ""},
		{name: "group_json_label", ct: "application/json", body: "invalid token " + tok, door: group, want: "invalid token [redacted]", wantCT: "application/json"},
		{name: "group_unlabelled_json", ct: "-", body: `{"detail":"invalid token ` + tok + `"}`, door: group, want: `{"detail":"invalid token [redacted]"}`, wantCT: "application/json"},
		{name: "auth_header_quote", ct: "text/plain", body: "401 Unauthorized: Authorization: Bearer " + tok, want: "401 Unauthorized: Authorization: Bearer [redacted]", wantCT: "text/plain"},
		{name: "problem_json", ct: "application/problem+json", body: `{"title":"Unauthorized","detail":"invalid token ` + tok + `"}`, want: `{"detail":"invalid token [redacted]","title":"Unauthorized"}`, wantCT: "application/problem+json"},
		{name: "oauth_error_json", ct: "application/json", body: `{"error":"invalid_token","error_description":"Bearer ` + tok + ` is expired"}`, want: `{"error":"invalid_token","error_description":"Bearer [redacted] is expired"}`, wantCT: "application/json"},
		{name: "sse_label_plain_body", ct: "text/event-stream", body: "invalid token " + tok, want: "invalid token [redacted]", wantCT: "text/event-stream"},
		{name: "non_utf8", ct: "text/plain", body: "invalid token " + tok + " \xff", want: "invalid token [redacted] \xff", wantCT: "text/plain"},
		{name: "long", ct: "text/plain", body: strings.Repeat("word ", 20<<10) + tok, wantCT: "text/plain", check: func(t *testing.T, rr *httptest.ResponseRecorder) {
			if rr.Body.Len() > clientMessageBytes || !strings.HasPrefix(rr.Body.String(), "word word") {
				t.Errorf("client body is %d bytes starting %.20q, want the upstream's words cut at %d", rr.Body.Len(), rr.Body.String(), clientMessageBytes)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := upstreamSpec{Tools: []string{"ping_tool"}, Bearer: tok, CallCode: http.StatusUnauthorized, CallCT: tc.ct, CallBody: tc.body}
			var f *fixture
			var rr *httptest.ResponseRecorder
			tool := "ping_tool"
			switch tc.door {
			case single:
				f = newSingleFixture(t, spec, nil, nil)
				rr = f.post(toolCall("7", "ping_tool"))
			case member:
				f = singleMember(t, spec)
				rr = f.postMember("solo", toolCall("7", "ping_tool"))
			case group:
				f = singleMember(t, spec)
				tool = "solo__ping_tool"
				rr = f.post(toolCall("7", tool))
			}
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("HTTP code=%d want 401; body=%.200s", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("Content-Type"); got != tc.wantCT {
				t.Errorf("Content-Type=%q want %q", got, tc.wantCT)
			}
			row := f.waitAudit(models.LogFilter{Tool: tool})[0]
			if tc.check != nil {
				assertSentToken(t, f)
				assertNoLeak(t, "client body", rr.Body.String(), fragments(tok)...)
				if rr.Body.Len() != row.ResponseSizeBytes {
					t.Errorf("row size=%d, client got %d bytes", row.ResponseSizeBytes, rr.Body.Len())
				}
				tc.check(t, rr)
				return
			}
			assertRedactedRefusal(t, f, rr, tc.want, row)
		})
	}

	t.Run("empty", func(t *testing.T) {
		// A refusal with no body at all: the stub answers the call with a bare
		// 401 and everything else as its ordinary arms would.
		handler := func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			_ = json.Unmarshal(body, &req)
			switch req.Method {
			case "tools/call":
				w.WriteHeader(http.StatusUnauthorized)
			case "tools/list":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"ping_tool","inputSchema":{"type":"object"}}]}}`, req.ID)
			default:
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
			}
		}
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: tok, Handler: handler}, nil, nil)
		rr := f.post(toolCall("7", "ping_tool"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("HTTP code=%d want 401; body=%.200s", rr.Code, rr.Body.String())
		}
		if rr.Body.Len() != 0 || rr.Header().Get("Content-Type") != "" {
			t.Errorf("body=%q Content-Type=%q, want neither", rr.Body.String(), rr.Header().Get("Content-Type"))
		}
		row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
		if row.Status != models.StatusError || row.ResponseSizeBytes != 0 {
			t.Errorf("row status=%q size=%d, want error / 0", row.Status, row.ResponseSizeBytes)
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

// assertRedactedRowOf is assertRedactedRow for any stored credential tok
// and the exact message wantMsg the row must carry (PORM-208).
func assertRedactedRowOf(t *testing.T, row models.AuditLog, tok, wantMsg string) {
	t.Helper()
	if row.Status != models.StatusError {
		t.Errorf("row status=%q, want error", row.Status)
	}
	if row.ErrorMessage != wantMsg {
		t.Errorf("row error_message=%q, want %q", row.ErrorMessage, wantMsg)
	}
	assertNoLeak(t, "row error_message", row.ErrorMessage, fragments(tok)...)
}

// assertRedactedAnswerOf is assertRedactedAnswer for any stored credential
// tok and the exact message wantMsg the client's error must carry, on a JSON
// or an event-stream body (PORM-208). The row is the caller's to check.
func assertRedactedAnswerOf(t *testing.T, body []byte, wantID, tok, wantMsg string) {
	t.Helper()
	assertNoLeak(t, "client body", string(body), fragments(tok)...)
	doc := body
	if docs, err := mcpclient.PickResponse("text/event-stream", body, wantID); err == nil && mcpclient.LooksLikeSSE(body) {
		doc = docs
	}
	code, msg, id := rpcErrorOf(t, doc)
	if code != -32000 || fmt.Sprint(id) != wantID {
		t.Errorf("client error code=%d id=%v, want -32000 and %s", code, id, wantID)
	}
	if msg != wantMsg {
		t.Errorf("client error message=%q, want %q", msg, wantMsg)
	}
}

// TestShortCredentialNeverReachesReader is PORM-208 criteria 1 and 2 with
// amendments A1 and A8: an upstream stored with a 12-byte plain bearer, one
// the pattern rules cannot see, echoes it in a JSON-RPC error, in a 401
// text/plain refusal and in an event stream, in the plain spelling and
// after "Bearer%20" and "Bearer&#32;". The key holder and the row read the
// message with the literal replaced on the single key, the member endpoint
// and the group endpoint, and no 8-byte window of the bearer crosses. A
// text refusal keeps its PORM-205 shape: an empty row, and no body on the
// group endpoint.
func TestShortCredentialNeverReachesReader(t *testing.T) {
	const lit = "abcdefghijkl"
	spellings := []struct{ name, in, want string }{
		{"plain", lit, "[redacted]"},
		{"url_encoded_scheme", "Bearer%20" + lit, "Bearer%20[redacted]"},
		{"entity_scheme", "Bearer&#32;" + lit, "Bearer&#32;[redacted]"},
	}
	type door int
	const (
		single door = iota
		member
		group
	)
	doors := []struct {
		name string
		door door
		path string // the stream door's path
		tool string // the row's tool name
	}{
		{"single", single, "/a1/mcp", "ping_tool"},
		{"member", member, "/a1/solo/mcp", "ping_tool"},
		{"group", group, "", "solo__ping_tool"},
	}
	build := func(d door, spec upstreamSpec) *fixture {
		if d == single {
			return newSingleFixture(t, spec, nil, nil)
		}
		return singleMember(t, spec)
	}
	call := func(d door, f *fixture, tool string) *httptest.ResponseRecorder {
		if d == member {
			return f.postMember("solo", toolCall("7", "ping_tool"))
		}
		return f.post(toolCall("7", tool))
	}
	for _, sp := range spellings {
		msg := "invalid token " + sp.in
		want := "invalid token " + sp.want
		for _, d := range doors {
			t.Run(sp.name+"/"+d.name+"/json", func(t *testing.T) {
				f := build(d.door, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, CallBody: errorAnswer(7, msg)})
				rr := call(d.door, f, d.tool)
				if rr.Code != http.StatusOK {
					t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
				}
				row := f.waitAudit(models.LogFilter{Tool: d.tool})[0]
				assertRedactedAnswerOf(t, rr.Body.Bytes(), "7", lit, want)
				assertRedactedRowOf(t, row, lit, want)
			})
			t.Run(sp.name+"/"+d.name+"/text_plain_401", func(t *testing.T) {
				f := build(d.door, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, CallCode: http.StatusUnauthorized, CallCT: "text/plain", CallBody: msg})
				rr := call(d.door, f, d.tool)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("HTTP code=%d want 401; body=%.200s", rr.Code, rr.Body.String())
				}
				wantBody := want
				if d.door == group {
					wantBody = "" // PORM-205: a text refusal reaches the group's client as its status alone
				}
				if got := rr.Body.String(); got != wantBody {
					t.Errorf("client body=%q, want %q", got, wantBody)
				}
				assertNoLeak(t, "client body", rr.Body.String(), fragments(lit)...)
				row := f.waitAudit(models.LogFilter{Tool: d.tool})[0]
				if row.Status != models.StatusError || row.ErrorMessage != "" {
					t.Errorf("row status=%q error_message=%q, want error / empty (A1)", row.Status, row.ErrorMessage)
				}
				assertNoLeak(t, "row error_message", row.ErrorMessage, fragments(lit)...)
			})
			t.Run(sp.name+"/"+d.name+"/event_stream", func(t *testing.T) {
				if d.door == group {
					// The group's tools/call is read whole and reduced, so a
					// stream label takes the buffered door there.
					f := singleMember(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, CallCT: "text/event-stream", CallBody: sseFrame(errorAnswer(7, msg))})
					rr := f.post(toolCall("7", d.tool))
					if rr.Code != http.StatusOK {
						t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
					}
					row := f.waitAudit(models.LogFilter{Tool: d.tool})[0]
					assertRedactedAnswerOf(t, rr.Body.Bytes(), "7", lit, want)
					assertRedactedRowOf(t, row, lit, want)
					return
				}
				f := build(d.door, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, Handler: thenClose(sseFrame(progressDoc), sseFrame(errorAnswer(1, msg)))})
				srv := f.serve()
				resp, id := open(t, f, srv, d.path, toolCall("1", "ping_tool"))
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				row := oneRow(t, f, id)
				assertRedactedAnswerOf(t, body, "1", lit, want)
				assertRedactedRowOf(t, row, lit, want)
			})
		}
	}

	t.Run("stream_split_inside_the_literal", func(t *testing.T) {
		msg := "invalid token " + lit
		split := func(w http.ResponseWriter, r *http.Request) {
			sseHeader(w)
			doc := errorAnswer(1, msg)
			cut := strings.Index(doc, lit) + 6
			writeEvents(w, "data: "+doc[:cut])
			time.Sleep(50 * time.Millisecond)
			writeEvents(w, doc[cut:]+"\n\n")
		}
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, Handler: split}, nil, nil)
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		row := oneRow(t, f, id)
		assertRedactedAnswerOf(t, body, "1", lit, "invalid token [redacted]")
		assertRedactedRowOf(t, row, lit, "invalid token [redacted]")
	})
}

// TestLiteralRedactionPerKind is PORM-208's scope: every credential kind
// headersFor writes reaches the literal pass. Each kind stores a 12-byte
// plain value the upstream echoes in its JSON-RPC error on the single key,
// and the stub's last request shows the kind's own header carried it.
func TestLiteralRedactionPerKind(t *testing.T) {
	const lit = "abcdefghijkl"
	msg := "invalid token " + lit
	const want = "invalid token [redacted]"
	kinds := []struct {
		name, authType string
		cfg            models.AuthConfig
		header, value  string // what the stub must have seen
	}{
		{"header", models.AuthHeader, models.AuthConfig{Header: "X-Token", Value: lit}, "X-Token", lit},
		{"api_key", models.AuthAPIKey, models.AuthConfig{Value: lit}, "X-API-Key", lit},
		{"custom", models.AuthCustom, models.AuthConfig{Headers: map[string]string{"X-Tenant": "acme-corp-europe"}, Header: "X-Secret", Value: lit}, "X-Secret", lit},
	}
	check := func(t *testing.T, f *fixture, header, value string) {
		t.Helper()
		rr := f.post(toolCall("7", "ping_tool"))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
		}
		reqs := f.requestsTo("solo")
		if len(reqs) == 0 {
			t.Fatal("the upstream saw no request")
		}
		if got := reqs[len(reqs)-1].Header.Get(header); got != value {
			t.Fatalf("upstream saw %s=%q, want %q", header, got, value)
		}
		row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
		assertRedactedAnswerOf(t, rr.Body.Bytes(), "7", lit, want)
		assertRedactedRowOf(t, row, lit, want)
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, AuthType: k.authType, AuthConfig: k.cfg, CallBody: errorAnswer(7, msg)}, nil, nil)
			check(t, f, k.header, k.value)
		})
	}
	t.Run("oauth", func(t *testing.T) {
		// The stub stays the upstream; only the credential becomes an oauth
		// set, unexpired so no refresh runs and the access token is the one
		// literal the request carries.
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, CallBody: errorAnswer(7, msg)}, nil, nil)
		u, err := f.Store.GetUpstream(context.Background(), "u1")
		if err != nil {
			t.Fatal(err)
		}
		toOAuth(t, f, "u1", u.URL, models.OAuthTokenSet{
			AccessToken: lit, RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour),
			TokenEndpoint: "http://127.0.0.1:1/token", ClientID: "cid", ClientSource: "supplied",
			Resource: u.URL,
		})
		check(t, f, "Authorization", "Bearer "+lit)
	})
}

// TestThirdCredentialStillRedacted is PORM-208 security requirement 10:
// the pattern rules run after the literal pass, so a credential the proxy
// did not inject is still caught beside the one it did.
func TestThirdCredentialStillRedacted(t *testing.T) {
	const lit = "abcdefghijkl"
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, CallBody: errorAnswer(7, "stored "+lit+" other "+echoedToken)}, nil, nil)
	rr := f.post(toolCall("7", "ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
	}
	const want = "stored [redacted] other [redacted]"
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	assertRedactedAnswerOf(t, rr.Body.Bytes(), "7", lit, want)
	assertRedactedRowOf(t, row, lit, want)
	assertNoLeak(t, "client body", rr.Body.String(), fragments(echoedToken)...)
	assertNoLeak(t, "row error_message", row.ErrorMessage, fragments(echoedToken)...)
}

// TestCustomHeaderValuesAreLiterals is PORM-208 amendment A5: every value a
// custom credential writes counts as a literal, a non-secret one included,
// so it is redacted wherever it appears in an upstream's error text.
func TestCustomHeaderValuesAreLiterals(t *testing.T) {
	const lit = "abcdefghijkl"
	cfg := models.AuthConfig{Headers: map[string]string{"X-Tenant": "acme-corp-europe"}, Header: "X-Secret", Value: lit}
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, AuthType: models.AuthCustom, AuthConfig: cfg, CallBody: errorAnswer(7, "tenant acme-corp-europe rejected")}, nil, nil)
	rr := f.post(toolCall("7", "ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
	}
	const want = "tenant [redacted] rejected"
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	assertRedactedAnswerOf(t, rr.Body.Bytes(), "7", "acme-corp-europe", want)
	assertRedactedRowOf(t, row, "acme-corp-europe", want)
}

// TestSevenByteCredentialIsLeftToPatterns is PORM-208 security requirement
// 5: a stored value under MinLiteralBytes is not a literal, so its bare echo
// is the pattern rules' alone, which read a 7-byte plain word as prose.
func TestSevenByteCredentialIsLeftToPatterns(t *testing.T) {
	const short = "abcdefg"
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: short, CallBody: errorAnswer(7, "invalid token "+short)}, nil, nil)
	rr := f.post(toolCall("7", "ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
	}
	_, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if msg != "invalid token "+short || row.ErrorMessage != "invalid token "+short {
		t.Errorf("client message=%q row=%q, want the echo as sent", msg, row.ErrorMessage)
	}

	t.Run("echoed with its scheme word", func(t *testing.T) {
		// The wire value "Bearer abcdefg" has no piece over the floor, so
		// the whole value is the literal: an echo that quotes the header
		// loses the scheme word with the token.
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: short, CallBody: errorAnswer(7, "Authorization: Bearer "+short)}, nil, nil)
		rr := f.post(toolCall("7", "ping_tool"))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200; body=%.200s", rr.Code, rr.Body.String())
		}
		row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
		assertRedactedAnswerOf(t, rr.Body.Bytes(), "7", "Bearer "+short, "Authorization: [redacted]")
		assertRedactedRowOf(t, row, "Bearer "+short, "Authorization: [redacted]")
	})
}

// TestStreamRowKeepsProxySentences is PORM-208 security requirement 4 on
// the stream door: the literals apply only when the row's message is the
// upstream's own text. A stream that ends without an answer writes the
// proxy's sentence, unchanged even when the stored bearer is one of its
// words.
func TestStreamRowKeepsProxySentences(t *testing.T) {
	const word = "upstream" // 8 bytes: a literal, and the sentence's first word
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: word, Handler: thenClose(sseFrame(progressDoc))}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	row := oneRow(t, f, id)
	const want = "upstream closed the stream before the answer"
	if row.Status != models.StatusError || row.ErrorMessage != want {
		t.Errorf("row status=%q error_message=%q, want error / %q", row.Status, row.ErrorMessage, want)
	}
}

// TestFailClosedRowRedactsLiteral is PORM-208 security requirement 9 on
// the fail-closed branch: a JSON refusal the refusal pass cannot rewrite is
// refused with the fixed sentence, and the row, which took the upstream's
// error.message before the gate, still reads the literal replaced.
func TestFailClosedRowRedactsLiteral(t *testing.T) {
	const lit = "abcdefghijkl"
	// Not a JSON-RPC envelope, so the refusal pass runs; nested past
	// maxWalkDepth, so the walk fails closed.
	body := `{"error":{"code":1,"message":"invalid token ` + lit + `"},"deep":` + strings.Repeat("[", maxWalkDepth+8) + strings.Repeat("]", maxWalkDepth+8) + `}`
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Bearer: lit, CallCode: http.StatusUnauthorized, CallCT: "application/json", CallBody: body}, nil, nil)
	rr := f.post(toolCall("7", "ping_tool"))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "upstream request failed") {
		t.Fatalf("HTTP code=%d body=%.200s, want 502 with the fixed sentence", rr.Code, rr.Body.String())
	}
	assertNoLeak(t, "client body", rr.Body.String(), fragments(lit)...)
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	assertRedactedRowOf(t, row, lit, "invalid token [redacted]")
}
