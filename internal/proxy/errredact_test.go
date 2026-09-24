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
		{name: "escaped key", in: `{"jsonrpc":"2.0","id":7,"\u0065rror":{"code":1,"message":"invalid token ` + echoedToken + `"}}`, want: []string{`"message":"invalid token [redacted]"`}},
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
			out, changed, seen, err := walkSSE(body, upper, nil)
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
		_, _, _, err := walkSSE([]byte("data: {x}\n\n"), func([]byte, int) ([]byte, bool, error) { return nil, false, boom }, nil)
		if !errors.Is(err, boom) {
			t.Fatalf("err=%v, want the callback's", err)
		}
	})

	t.Run("an unchanged catalogue allocates like the judge", func(t *testing.T) {
		body := []byte(strings.Repeat(sseFrame(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"no error here"}]}}`), 50))
		payload := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"no error here"}]}}`)
		judge := testing.AllocsPerRun(50, func() { rpcFailed(payload) }) * 50
		got := testing.AllocsPerRun(50, func() { walkSSE(body, redactPayload, nil) })
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
		{name: "sse then bare json error", ct: "text/event-stream", body: sseFrame(progressDoc) + errorAnswer(7, msg) + "\n", want: []string{sseFrame(progressDoc), `invalid token [redacted]`}},
		{name: "sse with an unknown field", ct: "text/event-stream", body: "foo: bar\n" + sseFrame(errorAnswer(7, msg)), want: []string{"foo: bar\n", `invalid token [redacted]`}},
		{name: "sse with nothing to redact", ct: "text/event-stream", body: sseFrame(progressDoc) + sseFrame(errorDoc), same: true},
		{name: "sse then bare json result", ct: "text/event-stream", body: sseFrame(progressDoc) + resultDoc + "\n", same: true},
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

// feedChunks runs body through a holder in chunks of at most n bytes and
// returns everything it released, the end flush included.
func feedChunks(t *testing.T, h *eventHolder, body []byte, n int) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(body); i += n {
		piece := append([]byte(nil), body[i:min(i+n, len(body))]...)
		got, err := h.feed(piece)
		if err != nil {
			t.Fatalf("feed at %d: %v", i, err)
		}
		out = append(out, got...)
	}
	got, err := h.end()
	if err != nil {
		t.Fatalf("end: %v", err)
	}
	return append(out, got...)
}

// TestEventHolderSplitAtEveryOffset is PORM-195 security requirement 2 at
// the holder level: however the upstream's bytes fall across reads, what the
// client receives is what the buffered rewrite of the whole body would be,
// in every line-ending spelling.
func TestEventHolderSplitAtEveryOffset(t *testing.T) {
	msg := "invalid token " + echoedToken
	for _, nl := range []string{"\n", "\r\n", "\r"} {
		frame := func(lines ...string) string { return strings.Join(lines, nl) + nl + nl }
		body := []byte(": keep" + nl +
			frame("id: 4", "event: message", "data: "+progressDoc) +
			frame("data: {\"jsonrpc\":\"2.0\",\"id\":7,", "data: \"error\":{\"code\":1,\"message\":\""+msg+"\"}}") +
			frame("retry: 5", "data:"+resultDoc) +
			frame("data: "+errorAnswer(8, msg)) +
			": tail" + nl +
			errorAnswer(9, msg) + nl) // bare JSON after the events, held to EOF on both doors
		want, err := redactErrorAnswer("text/event-stream", body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(want), echoedToken) || !strings.Contains(string(want), "[redacted]") {
			t.Fatalf("whole-body rewrite is wrong: %q", want)
		}
		for i := 1; i < len(body); i++ {
			var h eventHolder
			var got []byte
			for _, piece := range [][]byte{body[:i], body[i:]} {
				out, err := h.feed(append([]byte(nil), piece...))
				if err != nil {
					t.Fatalf("nl=%q split %d: %v", nl, i, err)
				}
				got = append(got, out...)
			}
			tail, err := h.end()
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, tail...)
			if !bytes.Equal(got, want) {
				t.Fatalf("nl=%q split at %d:\ngot  %q\nwant %q", nl, i, got, want)
			}
		}
	}

	t.Run("non-error events allocate like the judge", func(t *testing.T) {
		var h eventHolder
		event := []byte(sseFrame(progressDoc))
		payload := []byte(progressDoc)
		h.feed(append([]byte(nil), event...)) // warm the buffers
		judge := testing.AllocsPerRun(100, func() { rpcFailed(payload) })
		got := testing.AllocsPerRun(100, func() { h.feed(event) })
		if got > judge {
			t.Fatalf("feed allocates %.0f per progress event, rpcFailed %.0f", got, judge)
		}
		// A multi-line event joins its lines into the holder's own scratch,
		// so it costs the judge's allocations and no more once warm.
		multi := []byte("data: {\"jsonrpc\":\"2.0\",\ndata: \"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n")
		h.feed(append([]byte(nil), multi...))
		got = testing.AllocsPerRun(100, func() { h.feed(multi) })
		if got > judge {
			t.Fatalf("feed allocates %.0f per multi-line progress event, rpcFailed %.0f", got, judge)
		}
	})
}

// TestEventHolderForwardsFieldLinesAtOnce is the keep-alive rule: a comment,
// an event:, id: or retry: field and a blank line leave on the read that
// brings them; a data: line, a bare JSON line and an unknown field start a
// held unit.
func TestEventHolderForwardsFieldLinesAtOnce(t *testing.T) {
	forwarded := []string{": keep-alive\r\n", "event: message\n", "id: 9\n", "retry: 1000\n", "\n", "ID:7\n", "foo: bar\n", "Data: x\n"}
	for _, line := range forwarded {
		var h eventHolder
		out, err := h.feed([]byte(line))
		if err != nil || string(out) != line {
			t.Errorf("feed(%q) = %q, %v; want the line back", line, out, err)
		}
	}
	held := []string{"data: {}\n", errorAnswer(1, "x") + "\n", "  \"error\": {\n", "[1]\n", "data: partial"}
	for _, line := range held {
		var h eventHolder
		out, err := h.feed([]byte(line))
		if err != nil || len(out) != 0 {
			t.Errorf("feed(%q) = %q, %v; want nothing yet", line, out, err)
		}
	}
	// A comment line inside an open unit is part of the unit.
	var h eventHolder
	h.feed([]byte("data: {}\n"))
	if out, _ := h.feed([]byte(": inside\n")); len(out) != 0 {
		t.Errorf("a comment inside a unit was released: %q", out)
	}
}

// TestEventHolderBareCRReleasesPerRead: a CR ends a line at once, so a
// bare-CR stream releases each event on the read that brings its second CR,
// and a LF that follows on the next read is forwarded alone.
func TestEventHolderBareCRReleasesPerRead(t *testing.T) {
	var h eventHolder
	if out, _ := h.feed([]byte("data: " + progressDoc + "\r")); len(out) != 0 {
		t.Fatalf("released before the ending line: %q", out)
	}
	out, _ := h.feed([]byte("\r"))
	if string(out) != "data: "+progressDoc+"\r\r" {
		t.Fatalf("second CR released %q", out)
	}
	if out, _ := h.feed([]byte("\n")); string(out) != "\n" {
		t.Fatalf("the LF after the CR was not forwarded: %q", out)
	}
	if out, _ := h.feed([]byte(": ping\r")); string(out) != ": ping\r" {
		t.Fatalf("a CR-ended comment was held: %q", out)
	}
}

// TestEventHolderUnframedJSON is the stream door's unframed case: bare JSON
// under the stream label, in every shape a server writes it, is held and
// leaves redacted from end, never from feed.
func TestEventHolderUnframedJSON(t *testing.T) {
	msg := "invalid token " + echoedToken
	doc := errorAnswer(7, msg)
	pretty := "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 7,\n  \"error\": {\n    \"code\": -32000,\n    \"message\": \"" + msg + "\"\n  }\n}\n"
	blankInside := "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":1,\"message\":\"" + msg + "\"},\n\n\"id\":7}\n"
	for name, body := range map[string]string{"bare": doc, "trailing lf": doc + "\n", "crlf": doc + "\r\n", "pretty": pretty, "blank line inside": blankInside} {
		t.Run(name, func(t *testing.T) {
			var h eventHolder
			for _, n := range []int{len(body), 7} {
				h = eventHolder{}
				var early []byte
				for i := 0; i < len(body); i += n {
					out, err := h.feed([]byte(body[i:min(i+n, len(body))]))
					if err != nil {
						t.Fatal(err)
					}
					early = append(early, out...)
				}
				if len(early) != 0 {
					t.Fatalf("chunk %d: feed released %q before EOF", n, early)
				}
				out, err := h.end()
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(out), "invalid token [redacted]") {
					t.Fatalf("chunk %d: end returned %q", n, out)
				}
				assertNoLeak(t, "end", string(out), fragments(echoedToken)...)
			}
		})
	}
}

// bigEvent frames one document whose padding member holds n bytes.
func bigEvent(prefix, suffix string, n int) []byte {
	return []byte("data: " + prefix + strings.Repeat("x", n) + suffix + "\n\n")
}

// TestEventHolderOversizedResultPassesThrough is the passthrough proof: a
// result over holdBytes is relayed raw, byte for byte, and its first part
// leaves before its ending line arrives.
func TestEventHolderOversizedResultPassesThrough(t *testing.T) {
	body := bigEvent(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`, `"}]}}`, 2<<20)
	var h eventHolder
	var got []byte
	released := -1
	for i := 0; i < len(body); i += 32 << 10 {
		out, err := h.feed(append([]byte(nil), body[i:min(i+32<<10, len(body))]...))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) > 0 && released < 0 {
			released = i
		}
		got = append(got, out...)
	}
	tail, _ := h.end()
	got = append(got, tail...)
	if !bytes.Equal(got, body) {
		t.Fatalf("a large result was changed: %d bytes out, %d in", len(got), len(body))
	}
	if released < 0 || released > holdBytes+(32<<10) {
		t.Fatalf("first bytes released at offset %d, want at holdBytes", released)
	}
	// The raw relay stopped at the result's ending line: an error that
	// follows is held and rewritten as usual.
	after, err := h.feed([]byte(sseFrame(errorAnswer(2, "invalid token "+echoedToken))))
	if err != nil || !strings.Contains(string(after), "invalid token [redacted]") {
		t.Fatalf("the event after a passthrough came out as %q, %v", after, err)
	}
	assertNoLeak(t, "event after passthrough", string(after), fragments(echoedToken)...)
}

// TestEventHolderPaddedIDErrorIsHeld is security requirement 7: a key
// holder's padded id, an escaped key and a large member before the error
// cannot turn an error into a passthrough; the event is held to its end and
// leaves redacted.
func TestEventHolderPaddedIDErrorIsHeld(t *testing.T) {
	msg := "invalid token " + echoedToken
	cases := map[string][]byte{
		"padded id":      bigEvent(`{"jsonrpc":"2.0","id":"`, `","error":{"code":1,"message":"`+msg+`"}}`, 2<<20),
		"escaped key":    bigEvent(`{"jsonrpc":"2.0","id":"`, `","\u0065rror":{"code":1,"message":"`+msg+`"}}`, 2<<20),
		"params first":   bigEvent(`{"jsonrpc":"2.0","params":{"pad":"`, `"},"error":{"code":1,"message":"`+msg+`"}}`, 2<<20),
		"error a string": bigEvent(`{"jsonrpc":"2.0","id":"`, `","error":"`+msg+`"}`, 2<<20),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var h eventHolder
			var early, got []byte
			for i := 0; i < len(body); i += 32 << 10 {
				last := i+32<<10 >= len(body)
				out, err := h.feed(append([]byte(nil), body[i:min(i+32<<10, len(body))]...))
				if err != nil {
					t.Fatal(err)
				}
				if !last {
					early = append(early, out...)
				}
				got = append(got, out...)
			}
			if len(early) != 0 {
				t.Fatalf("released %d bytes before the ending line", len(early))
			}
			if !strings.Contains(string(got), "[redacted]") {
				t.Fatalf("the error was not rewritten: %d bytes, tail %q", len(got), got[max(0, len(got)-120):])
			}
			assertNoLeak(t, "client bytes", string(got), fragments(echoedToken)...)
		})
	}
}

// TestEventHolderOverMaxEnds: an event that may be an error and passes
// maxHeldBytes ends the stream rather than leaving unchecked; so does a
// partial line with no terminator, which is bounded the same way.
func TestEventHolderOverMaxEnds(t *testing.T) {
	old := maxHeldBytes
	maxHeldBytes = 4 << 20
	defer func() { maxHeldBytes = old }()
	for name, body := range map[string][]byte{
		"error-shaped event": bigEvent(`{"jsonrpc":"2.0","id":"`, `","error":{"message":"x"}}`, 5<<20),
	} {
		t.Run(name, func(t *testing.T) {
			var h eventHolder
			var err error
			for i := 0; i < len(body) && err == nil; i += 32 << 10 {
				_, err = h.feed(append([]byte(nil), body[i:min(i+32<<10, len(body))]...))
			}
			if !errors.Is(err, errEventTooLarge) {
				t.Fatalf("err=%v, want errEventTooLarge", err)
			}
		})
	}
}

// BenchmarkEventHolderFeed is the holder's cost per 32 KiB read, for the
// inputs BenchmarkStreamCaptureWrite uses and one large result. Figures for
// the pull request, not a gate.
func BenchmarkEventHolderFeed(b *testing.B) {
	chunk := 32 << 10
	progress := []byte(sseFrame(progressDoc))
	cases := map[string][]byte{
		"blank-lines":         bytes.Repeat([]byte("\n\n"), chunk/2),
		"progress-events":     bytes.Repeat(progress, chunk/len(progress)),
		"one-event":           []byte("data: " + strings.Repeat("x", chunk-8) + "\n\n"),
		"2mib-result":         bigEvent(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`, `"}]}}`, 2<<20),
		"4mib-one-line-error": bigEvent(`{"jsonrpc":"2.0","id":"`, `","error":{"code":1,"message":"x"}}`, 4<<20),
	}
	for name, body := range cases {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for range b.N {
				var h eventHolder
				for i := 0; i < len(body); i += chunk {
					if _, err := h.feed(body[i:min(i+chunk, len(body))]); err != nil {
						b.Fatal(err)
					}
				}
				h.end()
			}
		})
	}
}

// TestEventHolderPassthroughEndsOnJudgeRule: a unit relayed raw ends at the
// same line the judge ends it on, a line bytes.TrimSpace empties, so an error
// event after a large result is held and rewritten, whether the blank line is
// ASCII or a Unicode space and however the reads fall.
func TestEventHolderPassthroughEndsOnJudgeRule(t *testing.T) {
	msg := "invalid token " + echoedToken
	result := bigEvent(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`, `"}]}}`, 2<<20)
	result = result[:len(result)-1] // the ending line is appended per case
	for name, ending := range map[string]string{"lf": "\n", "nbsp": " \n", "nel": "\u0085\n", "spaces and nbsp": "   \n"} {
		t.Run(name, func(t *testing.T) {
			body := append(append([]byte(nil), result...), []byte(ending+sseFrame(errorAnswer(2, msg)))...)
			for _, n := range []int{32 << 10, 1} {
				if n == 1 {
					// Byte-sized reads around the ending line only, so a
					// multi-byte space split across reads is exercised.
					var h eventHolder
					var got []byte
					head := len(result)
					out, err := h.feed(append([]byte(nil), body[:head]...))
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, out...)
					for i := head; i < len(body); i++ {
						out, err := h.feed([]byte{body[i]})
						if err != nil {
							t.Fatal(err)
						}
						got = append(got, out...)
					}
					tail, _ := h.end()
					got = append(got, tail...)
					assertNoLeak(t, "byte reads", string(got), fragments(echoedToken)...)
					continue
				}
				var h eventHolder
				got := feedChunks(t, &h, body, n)
				if !strings.Contains(string(got), "invalid token [redacted]") {
					t.Fatalf("the error after the passthrough was not rewritten (tail %q)", got[max(0, len(got)-100):])
				}
				assertNoLeak(t, "chunk reads", string(got), fragments(echoedToken)...)
				if !bytes.HasPrefix(got, result) {
					t.Fatal("the result did not cross byte for byte")
				}
			}
		})
	}
}

// TestEventHolderBareJSONNeverPassesThrough: a unit with no data: line has no
// end the raw relay could find, so it is held whatever its shape, and an
// error event that follows it is rewritten with it.
func TestEventHolderBareJSONNeverPassesThrough(t *testing.T) {
	msg := "invalid token " + echoedToken
	bare := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + strings.Repeat("x", 2<<20) + `"}]}}` + "\n"
	body := []byte(bare + sseFrame(errorAnswer(2, msg)))
	var h eventHolder
	var early []byte
	for i := 0; i < len(bare); i += 32 << 10 {
		out, err := h.feed(append([]byte(nil), body[i:min(i+32<<10, len(bare))]...))
		if err != nil {
			t.Fatal(err)
		}
		early = append(early, out...)
	}
	if len(early) != 0 || h.state == passthrough {
		t.Fatalf("bare JSON was relayed raw: %d bytes, state=%v", len(early), h.state)
	}
	out, err := h.feed(append([]byte(nil), body[len(bare):]...))
	if err != nil {
		t.Fatal(err)
	}
	tail, _ := h.end()
	got := append(out, tail...)
	if !strings.Contains(string(got), "invalid token [redacted]") {
		t.Fatalf("the error after bare JSON was not rewritten (tail %q)", got[max(0, len(got)-120):])
	}
	assertNoLeak(t, "client bytes", string(got), fragments(echoedToken)...)
}

// TestEventHolderPartialLineIsBounded: a partial line outside an event is
// judged at holdBytes like anything else held, its judgement does not stick
// to the next unit once it has been forwarded, and one that never ends is
// bounded by maxHeldBytes. Not parallel: it lowers a package var.
func TestEventHolderPartialLineIsBounded(t *testing.T) {
	comment := []byte(": " + strings.Repeat("x", holdBytes+100) + "\n")
	result := bigEvent(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`, `"}]}}`, 2<<20)
	var h eventHolder
	var got []byte
	for i := 0; i < len(comment); i += 32 << 10 {
		out, err := h.feed(append([]byte(nil), comment[i:min(i+32<<10, len(comment))]...))
		if err != nil {
			t.Fatal(err)
		}
		if h.searched != len(h.held) {
			t.Fatalf("searched=%d held=%d: a partial line would be searched again", h.searched, len(h.held))
		}
		got = append(got, out...)
	}
	if !bytes.Equal(got, comment) {
		t.Fatalf("the long comment did not come out whole: %d of %d bytes", len(got), len(comment))
	}
	if h.decided {
		t.Fatal("the forwarded line left decided set")
	}
	released := -1
	for i := 0; i < len(result); i += 32 << 10 {
		out, err := h.feed(append([]byte(nil), result[i:min(i+32<<10, len(result))]...))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) > 0 && released < 0 {
			released = i
		}
	}
	if released < 0 || released > holdBytes+(32<<10) {
		t.Fatalf("the next result was released at offset %d, want at holdBytes", released)
	}

	old := maxHeldBytes
	maxHeldBytes = 4 << 20
	defer func() { maxHeldBytes = old }()
	endless := []byte(": " + strings.Repeat("x", 5<<20))
	var g eventHolder
	var err error
	for i := 0; i < len(endless) && err == nil; i += 32 << 10 {
		_, err = g.feed(append([]byte(nil), endless[i:min(i+32<<10, len(endless))]...))
	}
	if !errors.Is(err, errEventTooLarge) {
		t.Fatalf("err=%v, want errEventTooLarge", err)
	}
}

// TestEventHolderReleasesBuffer: an array that grew past holdBytes for one
// event is released once that event has left, on the held and the passthrough
// paths, as streamCapture releases its own.
func TestEventHolderReleasesBuffer(t *testing.T) {
	msg := "invalid token " + echoedToken
	for name, body := range map[string][]byte{
		"held error":         bigEvent(`{"jsonrpc":"2.0","id":"`, `","error":{"code":1,"message":"`+msg+`"}}`, 2<<20),
		"passthrough result": bigEvent(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`, `"}]}}`, 2<<20),
	} {
		t.Run(name, func(t *testing.T) {
			var h eventHolder
			feedChunks(t, &h, body, 32<<10)
			if cap(h.held) > holdBytes || cap(h.out) > holdBytes {
				t.Fatalf("after the event cap(held)=%d cap(out)=%d, want both released", cap(h.held), cap(h.out))
			}
		})
	}
}
