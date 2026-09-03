package models

import "unicode/utf8"

// UsableToolName reports whether a tool name is one the proxy can hold a
// caller to. Empty is not a name at all. Neither is one containing U+FFFD or a
// control character, which is the one place the proxy could authorise a
// different string from the one the upstream executes: Go's decoder turns a
// lone surrogate or an invalid byte into U+FFFD while JavaScript and Python
// clients keep the original, and the body is forwarded verbatim.
//
// One test, asked from three ends. A name the gate cannot pin down is refused
// on the way in, the same name is dropped from a group's catalogue on the way
// out, and discovery drops it from the list it shows an operator, so no two
// of them can disagree about which tools exist. It lives in the vocabulary
// package rather than in either caller because that argument now spans
// internal/proxy and internal/mcpclient, and neither may import the other.
func UsableToolName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
