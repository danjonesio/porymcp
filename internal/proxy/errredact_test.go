package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestRedactErrorDoc is PORM-195 security requirements 3, 6 and 8: a
// document the judge reads as an error has every message the judge could
// read redacted under the client bound, a result or a clean error is passed
// on as the same bytes, and id, code and data cross as the upstream wrote
// them.
func TestRedactErrorDoc(t *testing.T) {
	filler := strings.Repeat("word ", 1000) // 5000 bytes, past the audit window
	long := strings.Repeat("word ", 20<<10) // 100 KiB, past the client bound
	cases := []struct {
		name, in string
		same     bool     // the same backing array comes back
		want     []string // substrings the output must carry
		absent   []string // substrings it must not
		leak     bool     // the token may survive (documented nonconforming case)
	}{
		{name: "result", in: `{"jsonrpc":"2.0","id":7,"result":{"isError":false,"content":[]}}`, same: true},
		{name: "error null", in: `{"jsonrpc":"2.0","id":7,"error":null}`, same: true},
		{name: "error a number", in: `{"jsonrpc":"2.0","id":7,"error":5}`, same: true},
		{name: "message a number", in: `{"jsonrpc":"2.0","id":7,"error":{"code":1,"message":5}}`, same: true},
		{name: "message clean", in: errorAnswer(7, "rate limited"), same: true},
		{name: "message with a token", in: errorAnswer(7, "invalid token "+echoedToken), want: []string{`"message":"invalid token [redacted]"`, `"code":-32000`, `"id":7`}},
		{name: "message entirely a token", in: errorAnswer(7, echoedToken), want: []string{`"message":"[redacted]"`}},
		{name: "escaped token", in: `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"invalid token ` + escapeEvery(echoedToken, 3) + `"}}`, want: []string{`"message":"invalid token [redacted]"`}},
		{name: "token past the audit window", in: errorAnswer(7, filler+echoedToken), want: []string{filler + `[redacted]"`}},
		{name: "token past the client bound", in: errorAnswer(7, long+echoedToken), absent: []string{"[redacted]"}},
		{name: "folded keys", in: `{"jsonrpc":"2.0","id":7,"Error":{"code":1,"Message":"invalid token ` + echoedToken + `"}}`, want: []string{`"Message":"invalid token [redacted]"`}},
		{name: "escaped key", in: `{"jsonrpc":"2.0","id":7,"error":{"code":1,"message":"invalid token ` + echoedToken + `"}}`, want: []string{`"message":"invalid token [redacted]"`}},
		{name: "two spellings", in: `{"id":7,"error":{"message":"a ` + echoedToken + `"},"Error":{"message":"b ` + echoedToken + `"}}`, want: []string{`"message":"a [redacted]"`, `"message":"b [redacted]"`}},
		{name: "error a string", in: `{"jsonrpc":"2.0","id":7,"error":"invalid token ` + echoedToken + `"}`, want: []string{`"error":"invalid token [redacted]"`}},
		{name: "duplicate message key", in: `{"id":7,"error":{"message":"x","message":"invalid token ` + echoedToken + `"}}`, want: []string{`"message":"invalid token [redacted]"`}},
		{name: "duplicate error key null last", in: `{"id":7,"error":{"message":"invalid token ` + echoedToken + `"},"error":null}`, same: true, leak: true},
		{name: "big id and data cross raw", in: `{"jsonrpc":"2.0","id":98765432109876543210,"error":{"code":-32000,"message":"invalid token ` + echoedToken + `","data":"<b>&"}}`, want: []string{`"id":98765432109876543210`, `"data":"<b>&"`, `[redacted]`}},
		{name: "undecodable", in: `{"error":{"message":"invalid token ` + echoedToken, same: true, leak: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := []byte(c.in)
			out, changed, err := redactErrorDoc(doc)
			if err != nil {
				t.Fatalf("redactErrorDoc: %v", err)
			}
			if c.same {
				if changed || &out[0] != &doc[0] {
					t.Fatalf("changed=%v, want the same bytes back", changed)
				}
				return
			}
			if !changed {
				t.Fatalf("changed=false, got %q", out)
			}
			if !json.Valid(out) {
				t.Fatalf("output is not JSON: %q", out)
			}
			for _, w := range c.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("output lacks %q: %q", w, truncateForLog(out))
				}
			}
			for _, a := range c.absent {
				if strings.Contains(string(out), a) {
					t.Errorf("output carries %q", a)
				}
			}
			if !c.leak {
				assertNoLeak(t, "client document", string(out), fragments(echoedToken)...)
			}
			if len(out) > clientMessageBytes+1024 {
				t.Errorf("output is %d bytes, want the message cut at %d", len(out), clientMessageBytes)
			}
		})
	}
}

func truncateForLog(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

// TestRedactErrorDocAllocs pins the result path: a document the judge reads
// as a success costs no more allocations than the judge's own check.
func TestRedactErrorDocAllocs(t *testing.T) {
	doc := []byte(`{"jsonrpc":"2.0","id":7,"result":{"isError":false,"content":[{"type":"text","text":"an error occurred upstream"}]}}`)
	judge := testing.AllocsPerRun(200, func() { rpcFailed(doc) })
	got := testing.AllocsPerRun(200, func() { redactErrorDoc(doc) })
	if got > judge {
		t.Fatalf("redactErrorDoc allocates %.0f per result, rpcFailed %.0f", got, judge)
	}
}

// upper is a walkSSE callback that upper-cases a payload holding "x".
func upper(payload []byte, _ int) ([]byte, bool, error) {
	if !bytes.Contains(payload, []byte("x")) {
		return nil, false, nil
	}
	return bytes.ToUpper(payload), true, nil
}

// TestWalkSSE is PORM-195 security requirements 1, 4 and 5 at the framing
// level: every event with data is offered to the callback with its lines
// joined, a changed event goes back as one data: line in the first line's
// place, everything else is byte for byte, and an unchanged body is the same
// bytes.
func TestWalkSSE(t *testing.T) {
	cases := []struct {
		name, body, want string
		seen             int
	}{
		{"one data line with a space", "data: {x}\n\n", "data: {X}\n\n", 1},
		{"one data line without a space", "data:{x}\n\n", "data:{X}\n\n", 1},
		{"two data lines changed become one", "data: {x\ndata: y}\n\n", "data: {X\nY}\n\n", 1},
		{"two data lines unchanged stay two", "data: {a\ndata: b}\n\n", "data: {a\ndata: b}\n\n", 1},
		{"whitespace-only line ends the event", "data: {x}\n \ndata: {y}\n\n", "data: {X}\n \ndata: {y}\n\n", 2},
		{"field lines and a comment are kept", ": keep\nevent: message\nid: 9\nretry: 5\nfoo: bar\ndata: {x}\n\n: tail\n", ": keep\nevent: message\nid: 9\nretry: 5\nfoo: bar\ndata: {X}\n\n: tail\n", 1},
		{"crlf", "event: message\r\ndata: {x}\r\n\r\n", "event: message\r\ndata: {X}\r\n\r\n", 1},
		{"bare cr", "event: message\rdata: {x}\r\r", "event: message\rdata: {X}\r\r", 1},
		{"no trailing blank line", "data: {x}", "data: {X}", 1},
		{"no data at all", ": keep\n\nevent: message\n\n", ": keep\n\nevent: message\n\n", 0},
		{"second of three changes", "data: {a}\n\ndata: {x}\n\ndata: {b}\n\n", "data: {a}\n\ndata: {X}\n\ndata: {b}\n\n", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(c.body)
			out, changed, seen, err := walkSSE(body, upper)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != c.want {
				t.Errorf("got  %q\nwant %q", out, c.want)
			}
			if seen != c.seen {
				t.Errorf("seen=%d want %d", seen, c.seen)
			}
			if wantChanged := c.want != c.body; changed != wantChanged {
				t.Errorf("changed=%v want %v", changed, wantChanged)
			}
			if !changed && len(body) > 0 && &out[0] != &body[0] {
				t.Error("an unchanged body was copied")
			}
		})
	}

	t.Run("callback error stops the walk", func(t *testing.T) {
		boom := errors.New("boom")
		_, _, _, err := walkSSE([]byte("data: {x}\n\n"), func([]byte, int) ([]byte, bool, error) { return nil, false, boom })
		if !errors.Is(err, boom) {
			t.Fatalf("err=%v, want the callback's", err)
		}
	})

	t.Run("an unchanged catalogue allocates like the judge", func(t *testing.T) {
		body := []byte(strings.Repeat(sseFrame(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"no error here"}]}}`), 50))
		payload := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"no error here"}]}}`)
		judge := testing.AllocsPerRun(50, func() { rpcFailed(payload) }) * 50
		got := testing.AllocsPerRun(50, func() { walkSSE(body, redactPayload) })
		if got > judge {
			t.Fatalf("walkSSE allocates %.0f over 50 result events, rpcFailed %.0f", got, judge)
		}
	})
}

// TestRedactErrorAnswer is PORM-195 security requirements 1 and 3 on the
// buffered path: a JSON body, an SSE body and a mislabelled body are each
// found the way answerStatus finds them, every error event is rewritten, and
// a body with nothing to redact is the same bytes.
func TestRedactErrorAnswer(t *testing.T) {
	msg := "invalid token " + echoedToken
	cases := []struct {
		name, ct, body string
		same           bool
		want, absent   []string
	}{
		{name: "json", ct: "application/json", body: errorAnswer(7, msg), want: []string{`invalid token [redacted]`}},
		{name: "sse progress then error", ct: "text/event-stream", body: sseFrame(progressDoc) + sseFrame(errorAnswer(7, msg)), want: []string{sseFrame(progressDoc), `invalid token [redacted]`}},
		{name: "sse multi-line error", ct: "text/event-stream", body: "data: {\"jsonrpc\":\"2.0\",\"id\":7,\ndata: \"error\":{\"code\":1,\"message\":\"" + msg + "\"}}\n\n", want: []string{`data: {"error"`, `invalid token [redacted]`}},
		{name: "sse label over bare json", ct: "text/event-stream", body: errorAnswer(7, msg), want: []string{`invalid token [redacted]`}},
		{name: "text plain over json", ct: "text/plain", body: errorAnswer(7, msg), want: []string{`invalid token [redacted]`}},
		{name: "sse with nothing to redact", ct: "text/event-stream", body: sseFrame(progressDoc) + sseFrame(errorDoc), same: true},
		{name: "json result", ct: "application/json", body: resultDoc, same: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(c.body)
			out, err := redactErrorAnswer(c.ct, body)
			if err != nil {
				t.Fatal(err)
			}
			if c.same {
				if &out[0] != &body[0] {
					t.Fatalf("body was copied: %q", out)
				}
				return
			}
			for _, w := range c.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("output lacks %q: %q", w, truncateForLog(out))
				}
			}
			assertNoLeak(t, "client body", string(out), fragments(echoedToken)...)
		})
	}
}
