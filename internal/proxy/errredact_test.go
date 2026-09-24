package proxy

import (
	"encoding/json"
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
