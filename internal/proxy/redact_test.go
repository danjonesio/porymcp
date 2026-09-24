package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/danjonesio/porymcp/internal/audit"
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
		// The upstream JSON-escapes the first letters of the token; the
		// decoder sees them whole before any rule runs.
		{"escaped", "", `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"invalid token \u0067\u0068p\u005f` + strings.TrimPrefix(echoedToken, "ghp_") + `"}}`},
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
