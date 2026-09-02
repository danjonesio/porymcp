package web

import (
	"bytes"
	"testing"
)

// TestNoDangerouslySetInnerHTML keeps untrusted upstream text (error_message,
// params, tool descriptions) from being rendered as HTML. The dashboard is
// safe today only by convention; this fails the Go test suite if that changes.
func TestNoDangerouslySetInnerHTML(t *testing.T) {
	forEachSource(t, "src", []string{".ts", ".tsx", ".js", ".jsx"}, nil, func(path string, b []byte) {
		if bytes.Contains(b, []byte("dangerouslySetInnerHTML")) {
			t.Errorf("%s uses dangerouslySetInnerHTML", path)
		}
	})
}
