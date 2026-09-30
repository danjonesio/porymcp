// Package redact makes text an upstream wrote safe to repeat.
//
// Scrub removes control characters, Clamp bounds bytes at a rune boundary,
// RedactLiterals replaces the credential the proxy sent whatever its shape,
// RedactText replaces credential-shaped text, and RedactClamped is the order
// every repeated upstream text takes: the literals over the whole text, the
// pattern rules inside WindowBytes, then the cut. One body serves the audit
// row's error_message (internal/audit), the error answer a key holder
// receives and the relay's headers (internal/proxy), discovery's
// upstream_message and the group member skipped log line.
//
// It imports nothing from the rest of the module, so the upstream client and
// the audit trail can both import it. The coverage test that walks the audit
// trail's secretKeys through RedactText lives beside that map, in
// internal/audit/redact_test.go.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scrub cleans a string PoryMCP will show to an operator so that it is one
// line of printable text: a newline, carriage return or tab becomes one space,
// every other control character and DEL is dropped, U+FFFD is dropped (the
// string already lost information there, and invalid UTF-8 arrives as one),
// and the ends are trimmed.
//
// Discovery applies it to every upstream string that reaches a response (a
// tool's description and title, the annotations' title, the server's name and
// version, the protocol version, and the upstream's own error message),
// because an operator reading the API with `curl | jq -r` gets those bytes
// raw, and \x1b[31m from a server nobody at PoryMCP controls is somebody
// else's escape sequence in an operator's terminal. The admin audit trail
// (internal/api) applies it to the resource name and request id it stores on
// an admin_events row, which an operator reads back the same way. The group
// member skipped log line applies it before the literal pass, so a credential
// split by a control byte is seen whole. A tool's NAME needs none of this:
// models.UsableToolName already refuses every one of these characters
// outright, because a name is an identity a rule is written against. A
// resource's own name stays as the operator typed it; only the audit row's
// copy is cleaned.
//
// It deliberately does NOT touch the invisible and bidi class, U+202E, U+200B,
// U+FEFF, U+2066 and the rest. Those cannot escape the element they are
// rendered in (every one carries dir="ltr") and flagging them is PORM-83's
// job, which needs the whole run to say anything useful about it.
func Scrub(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// Clamp cuts s to max bytes, dropping the partial rune the cut may leave, and
// reports whether it cut anything.
func Clamp(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	return strings.ToValidUTF8(s[:max], ""), true
}

// MinLiteralBytes is the shortest injected value the proxy replaces by
// literal match (PORM-208). A shorter value is left to the pattern rules so
// that a credential of a few bytes cannot blank ordinary words in error
// text. mcpclient.Literals drops the pieces under it and RedactLiterals
// enforces the same floor, so the two cannot disagree.
const MinLiteralBytes = 8

// WindowBytes bounds how much of a text the pattern rules read. The audit
// row's Record runs on the request goroutine and an upstream may send a
// 16 MiB message; 4 KiB is what the proxy already admits there for params
// (auditParamsBytes). Redaction shrinks text, so a credential cut at the
// window could otherwise surface inside the stored bytes; RedactBounded
// drops the trailing run of credential characters whenever the window cut
// fired.
const WindowBytes = 4 << 10

// Redacted replaces a secret value under a secret key (the audit trail's
// Redact and RedactQuery), an injected literal (RedactLiterals) and a
// credential-shaped run in free text (RedactText).
const Redacted = "[redacted]"

// runChars is the alphabet of a base64, base64url or hex credential: what
// longRun matches. schemeChars is the alphabet of a token68 value after an
// Authorization scheme, what schemeValue matches. namedValue's value class
// is wider than both (anything but whitespace and a few delimiters), so
// the cut-back RedactBounded makes at a window cut stops only at those
// delimiters (valueBoundary), never inside any rule's value.
const (
	runChars    = `A-Za-z0-9_+/=-`
	schemeChars = `A-Za-z0-9._~+/=-`
)

var (
	// schemeValue is an Authorization scheme and the credential after it.
	// The value goes only when secretLike says so, so "missing bearer
	// token" and an echoed WWW-Authenticate challenge (the scheme, then
	// name="value" pairs) read as sent.
	schemeValue = regexp.MustCompile(`(?i)\b(bearer|basic)(\s+)([` + schemeChars + `]+)`)
	// namedValue is a name that says it holds a secret, then its value:
	// "X-API-Key: v", "api_key=v", "\"token\":\"v\"". The keyword must start
	// a word or follow "_" or "-", so "Monkey: 1", "Hotkey: F5" and
	// "oauth: 2" are prose. This is how a header or api_key credential,
	// which has no vendor prefix and may be short, is caught when the
	// upstream labels it. The suffix list is not the audit trail's
	// secretKeys or queryOnlySecretKeys: those match a JSON key whole, this
	// matches a suffix in prose, and "value", "code", "sig" and "session"
	// are ordinary words there. TestRedactTextCoversSecretKeys in
	// internal/audit walks secretKeys so the two cannot drift apart
	// unnoticed.
	namedValue = regexp.MustCompile(`(?i)\b(?:[A-Za-z0-9]+[_-])*((?:api)?(?:key|token|secret|password|passwd|credential|authorization|auth|signature))(["']?[ \t]*[:=][ \t]*["']?)([^\s"',;&]+)`)
	// vendorToken is a credential with a vendor prefix, replaced whole. The
	// leading \b keeps "task-management" from losing "sk-management".
	vendorToken = regexp.MustCompile(`\b(?:` +
		`sk[-_][A-Za-z0-9_-]{20,}` + // OpenAI, Anthropic (sk-ant-), Stripe (sk_live_)
		`|gh[pousr]_[A-Za-z0-9]{20,}` + // GitHub
		`|github_pat_[A-Za-z0-9_]{20,}` +
		`|glpat-[A-Za-z0-9_-]{20,}` + // GitLab
		`|xox[abposr]-[A-Za-z0-9-]{10,}` + // Slack
		`|(?:AKIA|ASIA)[A-Z0-9]{16}` + // AWS
		`|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?` + // JWT
		`)`)
	// longRun is a base64, base64url or hex run, replaced whole when
	// tokenLike. "." is outside runChars so a host splits at its dots.
	longRun = regexp.MustCompile(`[` + runChars + `]{20,}`)
)

// RedactText replaces credential-shaped text in s with "[redacted]". It is
// idempotent, returns "" for "", and turns a message that is entirely a
// token into "[redacted]". The rules run in order: a scheme and its value,
// a labelled value, a vendor-prefixed token, then any long run that looks
// like one. The two labelled rules keep the label and replace the value
// only when secretLike says it is one; the two run rules replace the whole
// match.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	s = schemeValue.ReplaceAllStringFunc(s, redactTrailingValue(schemeValue))
	s = namedValue.ReplaceAllStringFunc(s, redactTrailingValue(namedValue))
	s = vendorToken.ReplaceAllString(s, Redacted)
	return longRun.ReplaceAllStringFunc(s, func(run string) string {
		if tokenLike(run) {
			return Redacted
		}
		return run
	})
}

// redactTrailingValue replaces the last group of a labelled match, which is
// always the value, when secretLike says the value is a credential. The
// label and the separator before it are kept as they were.
func redactTrailingValue(re *regexp.Regexp) func(string) string {
	return func(m string) string {
		idx := re.FindStringSubmatchIndex(m)
		if idx == nil {
			return m
		}
		start := idx[len(idx)-2]
		if !secretLike(m[start:]) {
			return m
		}
		return m[:start] + Redacted
	}
}

// secretLike says whether a labelled value is a credential rather than a
// word. Sentence punctuation and base64 padding at the end are not
// evidence, so "must be a Bearer token." and a challenge's name= pair keep
// their value. A value is a credential when it is long, holds a digit, mixes
// upper and lower case over 12 or more characters, or holds a base64 sign.
func secretLike(v string) bool {
	v = strings.TrimRight(v, `.,;:!?)"'`)
	v = strings.TrimRight(v, "=")
	if v == "" {
		return false
	}
	if len(v) >= 20 {
		return true
	}
	var digit, upper, lower bool
	for _, r := range v {
		switch {
		case r == '+' || r == '/':
			return true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		}
	}
	return digit || (len(v) >= 12 && upper && lower)
}

// tokenLike says whether a long run of credential characters is a
// credential rather than an identifier an operator reads. Either one
// separator-free piece of 20 or more characters holds a letter and two
// digits, or the whole run does and also mixes upper and lower case and is
// not a path. Two digits, not one, so a camelCase tool name with a version
// ("getRepoContentsV2Beta") reads as sent; a 20-character key of hex, or of
// lowercase letters and digits, has two digits about 99 times in 100, and a
// mixed-case key of that length is missed about one time in seven (one in
// 40 at 32 characters), which docs/07-security.md states. A UUID, a slug, a
// snake_case tool identity, a hyphenated host label and a timestamp all
// fail both tests.
func tokenLike(run string) bool {
	for _, piece := range strings.FieldsFunc(run, isRunSeparator) {
		if len(piece) >= 20 && mixed(piece, false) {
			return true
		}
	}
	return len(run) >= 20 && !strings.HasPrefix(run, "/") && mixed(run, true)
}

func isRunSeparator(r rune) bool {
	return r == '-' || r == '_' || r == '=' || r == '+' || r == '/'
}

// mixed reports a letter and at least two digits in s, and both letter
// cases too when needCase is set.
func mixed(s string, needCase bool) bool {
	var letters, digits, upper, lower int
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsUpper(r):
			letters++
			upper++
		case unicode.IsLower(r):
			letters++
			lower++
		}
	}
	if digits < 2 || letters == 0 {
		return false
	}
	return !needCase || (upper > 0 && lower > 0)
}

// valueBoundary is the rune RedactBounded cuts back to after a window cut:
// whitespace or one of the delimiters that end namedValue's value, the
// widest value class of the rules. Every other byte can be inside some
// rule's value, so cutting after it could leave a fragment.
func valueBoundary(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(`"',;&`, r)
}

// RedactLiterals replaces every occurrence of each literal in s with
// "[redacted]" (PORM-208). The literals are the values the proxy injected,
// from mcpclient.Literals, so the match is exact and case-sensitive and a
// literal inside a longer word is replaced too. Overlapping or touching
// occurrences merge into one marker, so no fragment of a literal survives
// where two literals share bytes, which a left-to-right replacer would
// leave. A literal under MinLiteralBytes is ignored. A string with no
// occurrence comes back as s itself, with no allocation, so a body the
// proxy did not need to touch is passed on byte for byte.
func RedactLiterals(s string, literals []string) string {
	if s == "" || len(literals) == 0 {
		return s
	}
	var spans [][2]int
	for _, lit := range literals {
		if len(lit) < MinLiteralBytes {
			continue
		}
		first := len(spans) // spans before this index belong to other literals
		for from := 0; from < len(s); {
			i := strings.Index(s[from:], lit)
			if i < 0 {
				break
			}
			start, end := from+i, from+i+len(lit)
			// Hits of one literal arrive in start order, so a hit that
			// overlaps or touches the last span extends it: a periodic
			// literal over a long run costs one span, not one per offset,
			// and the text is at most the proxy's 16 MiB read cap.
			if n := len(spans); n > first && start <= spans[n-1][1] {
				spans[n-1][1] = end
			} else {
				spans = append(spans, [2]int{start, end})
			}
			from = start + 1
		}
	}
	if len(spans) == 0 {
		return s
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	start, end := spans[0][0], spans[0][1]
	for _, sp := range spans[1:] {
		if sp[0] <= end {
			end = max(end, sp[1])
			continue
		}
		b.WriteString(s[pos:start])
		b.WriteString(Redacted)
		pos = end
		start, end = sp[0], sp[1]
	}
	b.WriteString(s[pos:start])
	b.WriteString(Redacted)
	b.WriteString(s[end:])
	return b.String()
}

// RedactBoundedLiterals replaces the literals in the whole of s, then
// clamps, cuts back to a value boundary and runs the pattern rules as
// RedactBounded does. The literal pass runs over the whole text first so
// that no cut can split a literal and leave a fragment of it at the edge;
// the text is at most the proxy's 16 MiB read cap and the pass runs only on
// an error answer. The row pipeline and the client bound share it.
func RedactBoundedLiterals(s string, window int, literals []string) string {
	return RedactBounded(RedactLiterals(s, literals), window)
}

// RedactBounded clamps s to window bytes, cuts back to the last value
// boundary when it had to clamp so a credential is never cut in half, and
// replaces credential-shaped text. It is the client-facing half of
// RedactClamped, which adds the final clamp; the proxy calls it on the error
// message a key holder receives (PORM-195) with its own window. A window
// with no boundary in it has nothing to cut back to: it is kept whole and
// the rules decide, so a token pressed against padding with no separator can
// keep a fragment there, the property PORM-72 accepted.
func RedactBounded(s string, window int) string {
	s, cut := Clamp(s, window)
	if cut {
		// The cut lands after the whole of the last kept rune, never inside
		// a multi-byte one.
		if i := strings.LastIndexFunc(s, valueBoundary); i >= 0 {
			_, w := utf8.DecodeRuneInString(s[i:])
			s = s[:i+w]
		}
	}
	return RedactText(s)
}

// RedactClamped is the pass every repeated upstream text takes: the literals
// over the whole text, the pattern rules inside WindowBytes, then a cut to
// max bytes. The cut comes last because Redacted is longer than the shortest
// value it replaces. The audit row's error_message, discovery's
// upstream_message and the group member skipped log line each call it with
// their own bound.
func RedactClamped(s string, max int, literals []string) string {
	out, _ := Clamp(RedactBoundedLiterals(s, WindowBytes, literals), max)
	return out
}
