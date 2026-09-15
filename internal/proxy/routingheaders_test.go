package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// The routing headers are compared with the body before anything is
// forwarded, and the comparison is only as sound as the pieces below: which
// declared versions raise strictness, how a value that is not header-safe
// crosses, and what the proxy will forward blind. Each table pins one piece
// on its own so a mismatch found end to end can be traced to the rule that
// produced it.

// Security requirement 7. A lexical "2026-07-28 or later" would put the
// existing fixture's "9999" into strict mode and refuse it; strictness is
// raised only by a value in the revision-date shape.
func TestStrictRevision(t *testing.T) {
	for _, c := range []struct {
		v    string
		want bool
	}{
		{"2026-07-28", true},
		{"2027-01-01", true},
		{"2025-06-18", false},
		{"2025-11-25", false},
		{"9999", false},
		{"draft", false},
		{"abc", false},
		{"2026-07-28 ", false},
		{"2026-7-28", false},
		{"", false},
	} {
		if got := strictRevision(c.v); got != c.want {
			t.Errorf("strictRevision(%q)=%v want %v", c.v, got, c.want)
		}
	}
}

// Security requirement 8. The sentinel round-trips every name the gate could
// accept, including one that already looks like a sentinel, and refuses what
// cannot be compared with a name.
func TestHeaderValueSentinel(t *testing.T) {
	t.Run("a safe name crosses as it is", func(t *testing.T) {
		if got := encodeHeaderValue("echo"); got != "echo" {
			t.Errorf("encode=%q want echo", got)
		}
		if got, ok := decodeHeaderValue("echo"); !ok || got != "echo" {
			t.Errorf("decode=%q ok=%v", got, ok)
		}
	})
	t.Run("a non-ASCII name is encoded and decodes back", func(t *testing.T) {
		enc := encodeHeaderValue("créer")
		if enc != "=?base64?Y3LDqWVy?=" {
			t.Errorf("encode=%q", enc)
		}
		if got, ok := decodeHeaderValue(enc); !ok || got != "créer" {
			t.Errorf("decode=%q ok=%v", got, ok)
		}
	})
	t.Run("a sentinel-shaped name is encoded, not passed raw", func(t *testing.T) {
		const name = "=?base64?ZWNobw==?="
		enc := encodeHeaderValue(name)
		if enc == name {
			t.Fatalf("a name that already looks like a sentinel crossed raw, so the receiver decodes it to echo")
		}
		if got, ok := decodeHeaderValue(enc); !ok || got != name {
			t.Errorf("decode=%q ok=%v want the original name back", got, ok)
		}
	})
	t.Run("a leading space is encoded", func(t *testing.T) {
		if got := encodeHeaderValue(" echo"); got == " echo" {
			t.Error("a value with a leading space is not header-safe")
		}
	})
	t.Run("a sentinel that will not decode is refused", func(t *testing.T) {
		if _, ok := decodeHeaderValue("=?base64?!!!?="); ok {
			t.Error("undecodable base64 was accepted")
		}
	})
	t.Run("a decoded value over the bound is refused", func(t *testing.T) {
		big := encodeHeaderValue(strings.Repeat("é", maxRoutingValueBytes))
		if _, ok := decodeHeaderValue(big); ok {
			t.Error("a decoded value over maxRoutingValueBytes was accepted")
		}
	})
	t.Run("invalid UTF-8 is refused", func(t *testing.T) {
		// 0xff is never a valid UTF-8 byte; encoded by hand so the encoder's
		// own rule (it only ever sees Go strings) is not what is tested.
		if _, ok := decodeHeaderValue("=?base64?/w==?="); ok {
			t.Error("a decoded value that is not UTF-8 was accepted")
		}
	})
}

// Security requirement 5. The bound counts values, not names, so a name
// repeated many times trips it, and the size bound is per value. The
// character check is checkRoutingHeaders's, so a value outside printable
// ASCII passes here.
func TestCheckParamHeaders(t *testing.T) {
	withParams := func(n int) http.Header {
		h := http.Header{}
		for i := 0; i < n; i++ {
			h.Set("Mcp-Param-P"+strings.Repeat("x", i), "v")
		}
		return h
	}
	t.Run("32 names pass", func(t *testing.T) {
		if err := checkParamHeaders(withParams(maxParamHeaders)); err != nil {
			t.Errorf("refused: %v", err.Message)
		}
	})
	t.Run("33 names are refused", func(t *testing.T) {
		err := checkParamHeaders(withParams(maxParamHeaders + 1))
		if err == nil || err.Code != -32000 || err.Message != msgParamBound {
			t.Errorf("err=%+v", err)
		}
	})
	t.Run("one name with 33 values is refused", func(t *testing.T) {
		h := http.Header{}
		for i := 0; i <= maxParamHeaders; i++ {
			h.Add("Mcp-Param-X", "v")
		}
		if err := checkParamHeaders(h); err == nil || err.Message != msgParamBound {
			t.Errorf("err=%+v; the bound must count values, not names", err)
		}
	})
	t.Run("a value over the bound is refused", func(t *testing.T) {
		h := http.Header{}
		h.Set("Mcp-Param-X", strings.Repeat("a", maxRoutingValueBytes+1))
		if err := checkParamHeaders(h); err == nil || err.Message != msgParamBound {
			t.Errorf("err=%+v", err)
		}
	})
	t.Run("a value at the bound passes", func(t *testing.T) {
		h := http.Header{}
		h.Set("Mcp-Param-X", strings.Repeat("a", maxRoutingValueBytes))
		if err := checkParamHeaders(h); err != nil {
			t.Errorf("refused: %v", err.Message)
		}
	})
	t.Run("an empty remainder is not a param header", func(t *testing.T) {
		h := http.Header{}
		for i := 0; i <= maxParamHeaders; i++ {
			h.Add("Mcp-Param-", "v")
		}
		if err := checkParamHeaders(h); err != nil {
			t.Errorf("refused: %v; Mcp-Param- with nothing after it names no parameter", err.Message)
		}
	})
	t.Run("a non-ASCII value passes here", func(t *testing.T) {
		h := http.Header{}
		h.Set("Mcp-Param-X", "\x80")
		if err := checkParamHeaders(h); err != nil {
			t.Errorf("refused: %v; the character check belongs to checkRoutingHeaders", err.Message)
		}
	})
}

// Security requirement 10. Only names the proxy produced reach the preflight
// answer, and a request for more than the bound gets none of them.
func TestParamHeaderNames(t *testing.T) {
	t.Run("a lowercase name is canonicalised", func(t *testing.T) {
		got := paramHeaderNames([]string{"mcp-param-region"})
		if len(got) != 1 || got[0] != "Mcp-Param-Region" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("other names are not returned", func(t *testing.T) {
		if got := paramHeaderNames([]string{"Authorization, Mcp-Method, X-Custom"}); len(got) != 0 {
			t.Errorf("got %q", got)
		}
	})
	t.Run("a name with a space is not returned", func(t *testing.T) {
		if got := paramHeaderNames([]string{"Mcp-Param-Re gion"}); len(got) != 0 {
			t.Errorf("got %q", got)
		}
	})
	t.Run("a name over the length bound is not returned", func(t *testing.T) {
		long := "Mcp-Param-" + strings.Repeat("a", maxRoutingValueBytes)
		if got := paramHeaderNames([]string{long}); len(got) != 0 {
			t.Errorf("got %d names", len(got))
		}
	})
	t.Run("32 valid names are returned", func(t *testing.T) {
		names := make([]string, 0, maxParamHeaders)
		for i := 0; i < maxParamHeaders; i++ {
			names = append(names, "Mcp-Param-N"+strings.Repeat("x", i))
		}
		if got := paramHeaderNames([]string{strings.Join(names, ", ")}); len(got) != maxParamHeaders {
			t.Errorf("got %d names want %d", len(got), maxParamHeaders)
		}
	})
	t.Run("33 valid names return nil", func(t *testing.T) {
		names := make([]string, 0, maxParamHeaders+1)
		for i := 0; i <= maxParamHeaders; i++ {
			names = append(names, "Mcp-Param-N"+strings.Repeat("x", i))
		}
		if got := paramHeaderNames([]string{strings.Join(names, ", ")}); got != nil {
			t.Errorf("got %d names want none: a truncated allowance sends a request the upstream refuses", len(got))
		}
	})
	t.Run("100 comma fields return nil", func(t *testing.T) {
		if got := paramHeaderNames([]string{strings.Repeat("Mcp-Param-A,", 100)}); got != nil {
			t.Errorf("got %d names", len(got))
		}
	})
	t.Run("duplicates collapse", func(t *testing.T) {
		got := paramHeaderNames([]string{"Mcp-Param-A, mcp-param-a, MCP-PARAM-A"})
		if len(got) != 1 || got[0] != "Mcp-Param-A" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("names split across two header values are read", func(t *testing.T) {
		got := paramHeaderNames([]string{"Mcp-Param-A", "Mcp-Param-B"})
		if len(got) != 2 {
			t.Errorf("got %q", got)
		}
	})
}
