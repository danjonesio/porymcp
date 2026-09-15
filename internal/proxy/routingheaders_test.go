package proxy

import (
	"encoding/json"
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

// toolNameFromParams is now a wrapper over the one-pass decode. These rows
// pin what the wrapper has to keep identical, the null case above all: a
// "name":null reaches the decode as the literal bytes null rather than as an
// absent member, and it is jsonString's quote test that keeps it refused.
func TestToolNameFromParams(t *testing.T) {
	for _, c := range []struct {
		name, params, want string
		ok                 bool
	}{
		{"absent name", `{}`, "", false},
		{"null name", `{"name":null}`, "", false},
		{"numeric name", `{"name":5}`, "", false},
		{"miscased key binds", `{"Name":"echo"}`, "echo", true},
		{"unusable name", `{"name":"a\u0001b"}`, "", false},
		{"params not an object", `"x"`, "", false},
		{"empty params", ``, "", false},
		{"usable name", `{"name":"echo","arguments":{}}`, "echo", true},
	} {
		got, ok := toolNameFromParams(json.RawMessage(c.params))
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

// Security requirements 2, 6, 7 and 8. Every arm of the comparison on its
// own, against a tools/call body naming echo unless the row says otherwise.
// A want of "" is a request the check lets through.
func TestCheckRoutingHeaders(t *testing.T) {
	const (
		strictMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
		echoStrict = `{"name":"echo",` + strictMeta + `}`
		echoPlain  = `{"name":"echo"}`
	)
	hdr := func(pairs ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(pairs); i += 2 {
			h.Add(pairs[i], pairs[i+1])
		}
		return h
	}
	cases := []struct {
		name   string
		method string
		params string
		h      http.Header
		want   string
	}{
		{"strict request in agreement", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), ""},
		{"Mcp-Method disagrees with the body", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/list", "Mcp-Name", "echo"), msgMismatchMethod},
		{"Mcp-Method missing on a strict request", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Name", "echo"), msgMismatchMethod},
		{"Mcp-Name missing on a strict tools/call", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call"), msgMismatchName},
		{"Mcp-Name disagrees with params.name", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "other"), msgMismatchName},
		{"_meta version disagrees with the header", "tools/call",
			`{"name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchProtocol},
		{"a body declaring the strict revision with no header", "tools/call", echoStrict,
			hdr("Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchProtocol},
		{"a legacy header against a strict _meta", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2025-06-18", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchProtocol},
		{"a strict header with no _meta version is judged on the header", "tools/call", echoPlain,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), ""},
		{"a null _meta version member declares nothing", "tools/call",
			`{"name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":null}}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), ""},
		{"a _meta that is not an object declares nothing", "tools/call", `{"name":"echo","_meta":"x"}`,
			hdr(), ""},
		{"_meta with two spellings of the version key", "tools/call",
			`{"name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","IO.MODELCONTEXTPROTOCOL/PROTOCOLVERSION":"2026-07-28"}}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchProtocol},
		{"a numeric _meta version member", "tools/call",
			`{"name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":2026}}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchProtocol},
		{"two Mcp-Method lines", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchMethod},
		{"two Mcp-Name lines", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo", "Mcp-Name", "echo"), msgMismatchName},
		{"the 9999 fixture is not strict", "tools/call", echoPlain,
			hdr("Mcp-Protocol-Version", "9999"), ""},
		{"a legacy request with no routing headers", "tools/call", echoPlain,
			hdr("MCP-Protocol-Version", "2025-06-18"), ""},
		{"a legacy request with a wrong Mcp-Name", "tools/call", echoPlain,
			hdr("MCP-Protocol-Version", "2025-06-18", "Mcp-Name", "other"), msgMismatchName},
		{"no version anywhere with an agreeing Mcp-Method", "tools/call", echoPlain,
			hdr("Mcp-Method", "tools/call"), ""},
		{"an empty method is not compared", "", ``,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call"), ""},
		{"an Mcp-Param value outside printable ASCII, even with an empty method", "", ``,
			hdr("Mcp-Param-X", "\x80"), msgMismatchParam},
		{"an Mcp-Param value outside printable ASCII on a strict request", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo", "Mcp-Param-X", "caf\xc3\xa9"), msgMismatchParam},
		{"a printable Mcp-Param value passes", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo", "Mcp-Param-Region", "us west 1"), ""},
		{"Mcp-Name on tools/list is not compared", "tools/list", `{` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/list", "Mcp-Name", "anything"), ""},
		{"resources/read compares params.uri", "resources/read", `{"uri":"file:///a",` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "resources/read", "Mcp-Name", "file:///a"), ""},
		{"resources/read with a different uri", "resources/read", `{"uri":"file:///a",` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "resources/read", "Mcp-Name", "file:///b"), msgMismatchName},
		{"prompts/get compares params.name without the tool-name rule", "prompts/get", `{"name":"a\u0001b",` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "prompts/get", "Mcp-Name", encodeHeaderValue("a\x01b")), ""},
		{"tools/call holds the same name to the tool-name rule", "tools/call", `{"name":"a\u0001b",` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", encodeHeaderValue("a\x01b")), msgMismatchName},
		{"a sentinel Mcp-Name decodes and passes", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "=?base64?ZWNobw==?="), ""},
		{"a sentinel that will not decode", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "=?base64?!!!?="), msgMismatchName},
		{"Mcp-Name over the length bound", "tools/call", echoStrict,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", strings.Repeat("a", maxRoutingValueBytes+1)), msgMismatchName},
		{"Mcp-Name sent against a body with no usable name, strict", "tools/call", `{` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "echo"), msgMismatchName},
		{"Mcp-Name sent against a body with no usable name, legacy", "tools/call", `{}`,
			hdr("Mcp-Name", "echo"), msgMismatchName},
		{"neither Mcp-Name nor params.name on a strict tools/call falls through", "tools/call", `{` + strictMeta + `}`,
			hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call"), ""},
		{"an empty Mcp-Method value is not the method", "tools/call", echoPlain,
			hdr("Mcp-Method", ""), msgMismatchMethod},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkRoutingHeaders(c.h, c.method, decodeRoutingFields(json.RawMessage(c.params)))
			got := ""
			if err != nil {
				if err.Code != codeHeaderMismatch {
					t.Errorf("code=%d want %d", err.Code, codeHeaderMismatch)
				}
				got = err.Message
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}
