package audit

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/redact"
)

const (
	ghpToken = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	hexToken = "deadbeef0123456789abcdef0123456789abcdef"
)

// fragments is every 8-byte window of tok: a stored fragment of a
// credential is a leak as much as the whole is.
func fragments(tok string) []string {
	var out []string
	for i := 0; i+8 <= len(tok); i++ {
		out = append(out, tok[i:i+8])
	}
	return out
}

func assertNoFragment(t *testing.T, what, text, tok string) {
	t.Helper()
	for _, f := range fragments(tok) {
		if strings.Contains(text, f) {
			t.Errorf("%s carries %q of the credential: %q", what, f, text)
			return
		}
	}
}

// TestRedactTextCoversSecretKeys keeps the pattern rules and this package's
// secretKeys from drifting apart: the namedValue suffix list in
// internal/redact is not secretKeys, and this walk fails the day a name
// added here stops matching in prose. The rules' own cases are
// TestRedactTextPatterns in internal/redact.
func TestRedactTextCoversSecretKeys(t *testing.T) {
	for name := range secretKeys {
		if name == "value" {
			continue
		}
		in := name + "=abc123def456"
		if got, want := redact.RedactText(in), name+"=[redacted]"; got != want {
			t.Errorf("RedactText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestErrorTextRedactsBeforeItCuts is PORM-72 security requirements 2, 3
// and 4: a credential is seen whole before any cut, a cut at the scan
// window never leaves a fragment for the stored bytes, the stored value is
// bounded and valid UTF-8, and it shares no memory with the input.
func TestErrorTextRedactsBeforeItCuts(t *testing.T) {
	filler := func(n int) string { return strings.Repeat("word ", n/5+1)[:n] }
	// prefixTo builds text so that the credential begins keep bytes before
	// the window ends: the window keeps exactly keep bytes of it.
	prefixTo := func(body string, keep int) string {
		want := redact.WindowBytes - keep - len(body)
		return body + filler(want)
	}
	a1 := strings.Repeat("a1", 200)
	tenRuns := strings.Repeat(a1+" ", 10)
	jwt := "eyJ" + strings.Repeat("a", 500) + "." + strings.Repeat("b1", 250) + "." + strings.Repeat("c", 296)
	threeJWTs := jwt + " " + jwt + " " + jwt + " "

	cases := []struct {
		name, in, tok string
		prefix        string
	}{
		{"straddles the stored bound", filler(250) + hexToken + " rest", hexToken, "word word"},
		{"shrink case", prefixTo(tenRuns, 15+len("invalid token ")) + "invalid token " + ghpToken, ghpToken, "[redacted] [redacted]"},
		{"three jwts then a token at the window", prefixTo(threeJWTs, 15) + hexToken, hexToken, "[redacted] [redacted] [redacted] word"},
		{"benign 100 KiB", filler(100 << 10), "", "word word"},
		// A multi-byte rune is the last kept character before the run the
		// window cuts, and redaction shrinks what precedes it to under the
		// stored bound: the cut lands after the rune's last byte, never
		// inside it, so the stored value stays valid UTF-8.
		{"multi-byte rune before the cut", tenRuns + filler(redact.WindowBytes-30-len("é")-len(tenRuns)) + "é" + hexToken, hexToken, "[redacted] [redacted]"},
		{"multi-byte rune before a shrunk cut", "sk-" + strings.Repeat("a1", 2000) + "é" + strings.Repeat("B", 300), "", "[redacted]é"},
		// A multi-byte space is the boundary the cut-back lands on: the
		// cut keeps every byte of it. A four-byte rune has no space form,
		// so that case keeps it whole before an ASCII space.
		{"two-byte space then a run", strings.Repeat("x ", 10) + " " + strings.Repeat("Ab1", 1500), "", "x x x x x x x x x x  "},
		{"three-byte space then a run", strings.Repeat("x ", 10) + "　" + strings.Repeat("Ab1", 1500), "", "x x x x x x x x x x 　"},
		{"four-byte rune then a run", strings.Repeat("x ", 10) + "𝔸 " + strings.Repeat("Ab1", 1500), "", "x x x x x x x x x x 𝔸 "},
		// A symbol inside a labelled value at the cut: the cut-back stops
		// at the space before the label, not at the symbol, so no part of
		// the value reaches the rules.
		{"symbol inside a labelled value at the cut", prefixTo(tenRuns, len("api_key=hunterhunter!hu")) + "api_key=hunterhunter!hunter2026", "hunterhunter!hunter2026", "[redacted] [redacted]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := errorText(c.in)
			if len(got) > ErrorMessageBytes {
				t.Errorf("stored %d bytes, want at most %d", len(got), ErrorMessageBytes)
			}
			if !utf8.ValidString(got) {
				t.Errorf("stored value is not valid UTF-8: %q", got)
			}
			if !strings.HasPrefix(got, c.prefix) {
				t.Errorf("stored %q, want prefix %q", got, c.prefix)
			}
			if c.tok != "" {
				assertNoFragment(t, "stored value", got, c.tok)
			}
		})
	}

	t.Run("a window of one run is kept for longRun to judge", func(t *testing.T) {
		got := errorText(strings.Repeat("A", 64<<10))
		if want := strings.Repeat("A", ErrorMessageBytes); got != want {
			t.Errorf("stored %q, want %d A", got, ErrorMessageBytes)
		}
		if got := errorText(strings.Repeat("a1", 32<<10)); got != redact.Redacted {
			t.Errorf("stored %q, want %q", got, redact.Redacted)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if got := errorText(""); got != "" {
			t.Errorf("stored %q for an empty message", got)
		}
	})

	t.Run("stored value is never a view of the input", func(t *testing.T) {
		// Today every non-empty path allocates (ReplaceAllStringFunc builds
		// a new string even when nothing matched), so this cannot fail
		// against the current code; it is here for a future shortcut that
		// returns the input's own bytes when no rule matched, which would
		// keep the upstream's whole body alive in a queued row.
		in := filler(100 << 10)
		got := errorText(in)
		inStart := uintptr(unsafe.Pointer(unsafe.StringData(in)))
		outStart := uintptr(unsafe.Pointer(unsafe.StringData(got)))
		if outStart >= inStart && outStart < inStart+uintptr(len(in)) {
			t.Errorf("the stored value points into the upstream's message")
		}
	})
}

// TestRecordRedactsErrorMessage is PORM-72 security requirements 1, 5 and
// 10: every row goes through errorText inside Record, so the proxy's own
// sentences come back exact, an echoed credential comes back redacted and
// an oversized message comes back bounded, all read through the store.
func TestRecordRedactsErrorMessage(t *testing.T) {
	st := openStore(t)
	l := New(st, nil)
	rows := map[string]string{
		"policy":     "blocked by virtual key denylist",
		"credential": "credential undecryptable",
		"echo":       "invalid token " + ghpToken,
		"huge":       strings.Repeat("word ", 20<<10),
	}
	for id, msg := range rows {
		l.Record(models.AuditLog{VirtualKeyID: "k", Method: "tools/call", Status: models.StatusError, RequestID: id, ErrorMessage: msg})
	}
	l.Close()
	got, _, err := st.ListAuditLogs(context.Background(), models.LogFilter{Status: models.StatusError, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]string{}
	for _, row := range got {
		stored[row.RequestID] = row.ErrorMessage
	}
	if len(stored) != len(rows) {
		t.Fatalf("%d rows stored, want %d", len(stored), len(rows))
	}
	if stored["policy"] != rows["policy"] {
		t.Errorf("policy reason stored as %q", stored["policy"])
	}
	if stored["credential"] != rows["credential"] {
		t.Errorf("credential sentinel stored as %q", stored["credential"])
	}
	if stored["echo"] != "invalid token [redacted]" {
		t.Errorf("echoed credential stored as %q", stored["echo"])
	}
	assertNoFragment(t, "echo row", stored["echo"], ghpToken)
	if n := len(stored["huge"]); n > ErrorMessageBytes {
		t.Errorf("huge message stored as %d bytes, want at most %d", n, ErrorMessageBytes)
	}
}

// TestRecordRedactsLiteral is PORM-208 security requirement 3: the
// literals reach Record on the call and are gone from the stored row.
func TestRecordRedactsLiteral(t *testing.T) {
	st := openStore(t)
	l := New(st, nil)
	const lit = "abcdefghijkl"
	l.Record(models.AuditLog{VirtualKeyID: "k", Method: "tools/call", Status: models.StatusError, RequestID: "lit", ErrorMessage: "invalid token " + lit}, lit)
	l.Record(models.AuditLog{VirtualKeyID: "k", Method: "tools/call", Status: models.StatusError, RequestID: "none", ErrorMessage: "invalid token " + lit})
	l.Close()
	got, _, err := st.ListAuditLogs(context.Background(), models.LogFilter{Status: models.StatusError, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]string{}
	for _, row := range got {
		stored[row.RequestID] = row.ErrorMessage
	}
	if stored["lit"] != "invalid token [redacted]" {
		t.Errorf("row with literals stored as %q", stored["lit"])
	}
	assertNoFragment(t, "lit row", stored["lit"], lit)
	if stored["none"] != "invalid token "+lit {
		t.Errorf("row without literals stored as %q, want the pattern rules alone", stored["none"])
	}
}
