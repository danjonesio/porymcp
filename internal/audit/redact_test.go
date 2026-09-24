package audit

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/danjonesio/porymcp/internal/models"
)

const (
	ghpToken = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	hexToken = "deadbeef0123456789abcdef0123456789abcdef"
	jwtToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
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

// TestRedactTextPatterns is PORM-72 criterion 2 and security requirements
// 5, 6, 7 and 9: every credential shape the proxy injects is replaced when
// it is echoed in free text, and the proxy's own sentences, identifiers and
// ordinary prose read as sent.
func TestRedactTextPatterns(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// Redacted.
		{"bearer ghp", "Bearer " + ghpToken, "Bearer [redacted]"},
		{"sk-proj", "invalid token sk-proj-abcdefghij1234567890ABCD", "invalid token [redacted]"},
		{"sk_live", "sk_" + "live_abcdefghij1234567890ABCD is not valid", "[redacted] is not valid"},
		{"sk-ant", "sk-ant-abcdefghij1234567890ABCD", "[redacted]"},
		{"gho", "gho_abcdefghij1234567890", "[redacted]"},
		{"ghs", "ghs_abcdefghij1234567890", "[redacted]"},
		{"ghu", "ghu_abcdefghij1234567890", "[redacted]"},
		{"ghr", "ghr_abcdefghij1234567890", "[redacted]"},
		{"github_pat", "github_pat_abcdefghij1234567890AB", "[redacted]"},
		{"glpat", "glpat-abcdefghij1234567890", "[redacted]"},
		{"xoxb", "xoxb-123456789012-1234567890123-AbCdEfGh", "[redacted]"},
		{"xoxp", "token xoxp-123456789012-1234567890123-AbCdEfGh revoked", "token [redacted] revoked"},
		{"akia", "AKIAIOSFODNN7EXAMPLE", "[redacted]"},
		{"asia", "ASIAIOSFODNN7EXAMPLE", "[redacted]"},
		{"hex 40", "signature " + hexToken + " mismatch", "signature [redacted] mismatch"},
		{"jwt", "expired: " + jwtToken, "expired: [redacted]"},
		{"x-api-key digit", "X-API-Key: s3cr3t-2026", "X-API-Key: [redacted]"},
		{"x-api-key mixed case", "X-API-Key: AbCdEfGhIjKlMnOp", "X-API-Key: [redacted]"},
		{"json api_key", `"api_key":"abc123def456"`, `"api_key":"[redacted]"`},
		{"basic", "Basic dXNlcjpwYXNzd29yZDEyMw==", "Basic [redacted]"},
		{"standard base64", "key q8ZkT2mA9bXr4Lw+Pz7Nc1Vh/Ke3Jd6Ys0Fu5Gi== rejected", "key [redacted] rejected"},
		{"base64url with separator", "AbCdEfGhIjKlMnO-pQrStUvWxYz12345", "[redacted]"},
		{"lambda host label", "cannot connect to abcdef1234567890abcdef1234567890.lambda-url.eu-west-1.on.aws:443", "cannot connect to [redacted].lambda-url.eu-west-1.on.aws:443"},
		{"trace id", "trace 4bf92f3577b34da6a3ce929d0e0e4736 not found", "trace [redacted] not found"},
		{"labelled uuid", "X-API-Key: 550e8400-e29b-41d4-a716-446655440000", "X-API-Key: [redacted]"},
		// Partly caught: a token the upstream split or encoded keeps a
		// short fragment, the rest goes. docs/07-security.md says so.
		{"zero-width split token", "ghp_AbCd\u200bEfGhIjKlMnOpQrStUvWxYz0123456789", "ghp_AbCd\u200b[redacted]"},
		{"url-encoded token", "invalid token ghp%5FAbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "invalid token ghp%[redacted]"},
		{"whole token", ghpToken, "[redacted]"},
		// Unchanged.
		{"sentence", "the upstream is not available right now", "the upstream is not available right now"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"tool name", "filesystem__read_file", "filesystem__read_file"},
		{"tool identity", "github__create_pull_request_review", "github__create_pull_request_review"},
		{"hyphenated tool identity", "github-copilot__create_pull_request_review", "github-copilot__create_pull_request_review"},
		{"camel case with version", "getRepoContentsV2Beta", "getRepoContentsV2Beta"},
		{"unknown endpoint", "unknown endpoint: my-company-internal-tools-eu-west-1", "unknown endpoint: my-company-internal-tools-eu-west-1"},
		{"unknown tool", "unknown tool: github__create_pull_request_review", "unknown tool: github__create_pull_request_review"},
		{"policy reason", "blocked: not a {slug}__{tool} identity", "blocked: not a {slug}__{tool} identity"},
		{"host", "cannot connect to mcp-server-production-eu-west-1.example.com:443", "cannot connect to mcp-server-production-eu-west-1.example.com:443"},
		{"redirect host", "upstream redirected to elsewhere.example", "upstream redirected to elsewhere.example"},
		{"path", "/api/v1/tools/search/results", "/api/v1/tools/search/results"},
		{"timestamp", "2026-09-24T10:00:00.123456789Z", "2026-09-24T10:00:00.123456789Z"},
		{"long word", "internationalization", "internationalization"},
		{"missing bearer token", "missing bearer token", "missing bearer token"},
		{"bearer token full stop", "must be a Bearer token.", "must be a Bearer token."},
		{"bearer realm", "Bearer realm", "Bearer realm"},
		{"www-authenticate", `Bearer realm="mcp", error="invalid_token"`, `Bearer realm="mcp", error="invalid_token"`},
		{"token expired", "token=expired", "token=expired"},
		{"required key", "missing required key: api_version", "missing required key: api_version"},
		{"monkey", "Monkey: 12345", "Monkey: 12345"},
		{"hotkey", "Hotkey: F5", "Hotkey: F5"},
		{"oauth", "oauth: 2", "oauth: 2"},
		{"status", "status: 401", "status: 401"},
		{"max_tokens", "max_tokens: 4096 exceeded", "max_tokens: 4096 exceeded"},
		{"fixture api key", "invalid token REAL-APIKEY-SECRET", "invalid token REAL-APIKEY-SECRET"},
		{"hyphenated lowercase run", "invalid token abcd1234-efgh5678-ijkl9012-mnop", "invalid token abcd1234-efgh5678-ijkl9012-mnop"},
		{"hyphenated name with digits", "invalid token my-app-2026-eu-west-1-prod", "invalid token my-app-2026-eu-west-1-prod"},
		{"value with spaces", "invalid token ab12 cd34 ef56 gh78 ij90", "invalid token ab12 cd34 ef56 gh78 ij90"},
		{"fixture token", "invalid token stored-token-42", "invalid token stored-token-42"},
		{"rate limited", "rate limited", "rate limited"},
		{"subscription", "Subscription limit reached", "Subscription limit reached"},
		{"not initialized", "Bad Request: Server not initialized", "Bad Request: Server not initialized"},
		{"credential sentinel", "credential undecryptable", "credential undecryptable"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactText(c.in)
			if got != c.want {
				t.Errorf("RedactText(%q) = %q, want %q", c.in, got, c.want)
			}
			if again := RedactText(got); again != got {
				t.Errorf("RedactText is not idempotent: %q then %q", got, again)
			}
		})
	}
	// namedValue's suffix list is not secretKeys; this walk fails the day
	// a name added there stops matching in prose.
	for name := range secretKeys {
		if name == "value" {
			continue
		}
		in := name + "=abc123def456"
		if got, want := RedactText(in), name+"=[redacted]"; got != want {
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
		want := redactWindowBytes - keep - len(body)
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
		{"multi-byte rune before the cut", tenRuns + filler(redactWindowBytes-30-len("é")-len(tenRuns)) + "é" + hexToken, hexToken, "[redacted] [redacted]"},
		{"multi-byte rune before a shrunk cut", "sk-" + strings.Repeat("a1", 2000) + "é" + strings.Repeat("B", 300), "", "[redacted]é"},
		// A multi-byte space is the boundary the cut-back lands on: the
		// cut keeps every byte of it. A four-byte rune has no space form,
		// so that case keeps it whole before an ASCII space.
		{"two-byte space then a run", strings.Repeat("x ", 10) + "\u00a0" + strings.Repeat("Ab1", 1500), "", "x x x x x x x x x x \u00a0"},
		{"three-byte space then a run", strings.Repeat("x ", 10) + "\u3000" + strings.Repeat("Ab1", 1500), "", "x x x x x x x x x x \u3000"},
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
		if got := errorText(strings.Repeat("a1", 32<<10)); got != redacted {
			t.Errorf("stored %q, want %q", got, redacted)
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
