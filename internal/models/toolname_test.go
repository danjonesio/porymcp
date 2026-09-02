package models

import (
	"strings"
	"testing"
)

// TestUsableToolName pins the predicate three packages now share: the call
// gate, the aggregate catalogue and discovery. The cases that matter are the
// ones where the string a gate reads and the string an upstream executes could
// differ — U+FFFD is what Go's JSON decoder leaves behind for a lone surrogate
// or an invalid byte, where a JavaScript or Python client keeps the original
// bytes and the proxy forwards the body verbatim.
func TestUsableToolName(t *testing.T) {
	usable := []string{
		"search",
		"create_issue",
		"a__b",
		"__x",
		"tool-with-dashes",
		"日本語",                    // non-ASCII is a name like any other
		"has space",              // MCP constrains nothing about a tool name
		"nbsp\u00a0name",         // callable but unmatchable by an exact rule: PORM-83
		strings.Repeat("n", 300), // long, but nameable; a byte cap is the caller's own
	}
	for _, name := range usable {
		if !UsableToolName(name) {
			t.Errorf("UsableToolName(%q) = false, want true", name)
		}
	}

	unusable := map[string]string{
		"":             "empty is not a name at all",
		"a\x00b":       "NUL is a control character",
		"a\tb":         "tab is below 0x20",
		"a\nb":         "newline is below 0x20",
		"a\x7fb":       "DEL",
		"a\uFFFDb":     "U+FFFD, which is what a lone surrogate decodes to",
		"\uFFFD":       "a name that is only U+FFFD",
		"a\x80b":       "an invalid UTF-8 byte, which ranges as U+FFFD",
		"\x1bescape":   "ESC",
		"trailing\x1f": "0x1f",
		"\x01leading":  "SOH",
	}
	for name, why := range unusable {
		if UsableToolName(name) {
			t.Errorf("UsableToolName(%q) = true, want false — %s", name, why)
		}
	}
}
