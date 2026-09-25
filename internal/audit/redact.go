package audit

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/danjonesio/porymcp/internal/mcpclient"
)

// ErrorMessageBytes is the most an audit row's error_message holds. Record
// applies it to every row after redaction, so a credential cut at the
// boundary is already gone before the cut. It is 256, the twin of
// AdminTextBytes and of internal/proxy's auditFieldBytes, kept separate for
// the reason recorded at internal/mcpclient/client.go beside MaxErrorBytes.
const ErrorMessageBytes = 256

// redactWindowBytes bounds how much of an error message RedactText reads.
// Record runs on the request goroutine and an upstream may send a 16 MiB
// message; 4 KiB is what the proxy already admits there for params
// (auditParamsBytes). Redaction shrinks text, so a credential cut at the
// window could otherwise surface inside the stored bytes; errorText drops
// the trailing run of credential characters whenever the window cut fired.
const redactWindowBytes = 4 << 10

// redacted replaces a secret value under a secret key (Redact, RedactQuery)
// and a credential-shaped run in free text (RedactText).
const redacted = "[redacted]"

// runChars is the alphabet of a base64, base64url or hex credential: what
// longRun matches. schemeChars is the alphabet of a token68 value after an
// Authorization scheme, what schemeValue matches. namedValue's value class
// is wider than both (anything but whitespace and a few delimiters), so
// the cut-back errorText makes at a window cut stops only at those
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
	// upstream labels it. The suffix list is not secretKeys or
	// queryOnlySecretKeys: those match a JSON key whole, this matches a
	// suffix in prose, and "value", "code", "sig" and "session" are
	// ordinary words there. TestRedactTextPatterns walks secretKeys so the
	// two cannot drift apart unnoticed.
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
	s = vendorToken.ReplaceAllString(s, redacted)
	return longRun.ReplaceAllStringFunc(s, func(run string) string {
		if tokenLike(run) {
			return redacted
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
		return m[:start] + redacted
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

// valueBoundary is the rune errorText cuts back to after a window cut:
// whitespace or one of the delimiters that end namedValue's value, the
// widest value class of the rules. Every other byte can be inside some
// rule's value, so cutting after it could leave a fragment.
func valueBoundary(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(`"',;&`, r)
}

// errorText is what Record stores: the injected literals replaced
// (PORM-208), the message cut to the scan window (with a trailing run of
// credential characters dropped when the cut fired), redacted, cut to
// ErrorMessageBytes, then cloned so a queued row never keeps the upstream's
// body alive. It does not call Text: Scrub would move exactly-pinned rows,
// and the invisible-character class is PORM-83's.
func errorText(s string, literals ...string) string {
	s, _ = mcpclient.Clamp(RedactBoundedLiterals(s, redactWindowBytes, literals), ErrorMessageBytes)
	return strings.Clone(s)
}

// RedactLiterals replaces every occurrence of each literal in s with
// "[redacted]" (PORM-208). The literals are the values the proxy injected,
// from mcpclient.Literals, so the match is exact and case-sensitive and a
// literal inside a longer word is replaced too. Overlapping or touching
// occurrences merge into one marker, so no fragment of a literal survives
// where two literals share bytes, which a left-to-right replacer would
// leave. A literal under mcpclient.MinLiteralBytes is ignored. A string with
// no occurrence comes back as s itself, with no allocation, so a body the
// proxy did not need to touch is passed on byte for byte.
func RedactLiterals(s string, literals []string) string {
	if s == "" || len(literals) == 0 {
		return s
	}
	var spans [][2]int
	for _, lit := range literals {
		if len(lit) < mcpclient.MinLiteralBytes {
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
			// and the text is at most mcpclient.MaxBodyBytes.
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
		b.WriteString(redacted)
		pos = end
		start, end = sp[0], sp[1]
	}
	b.WriteString(s[pos:start])
	b.WriteString(redacted)
	b.WriteString(s[end:])
	return b.String()
}

// RedactBoundedLiterals replaces the literals in the whole of s, then
// clamps, cuts back to a value boundary and runs the pattern rules as
// RedactBounded does. The literal pass runs over the whole text first so
// that no cut can split a literal and leave a fragment of it at the edge;
// the text is at most mcpclient.MaxBodyBytes and the pass runs only on an
// error answer. The row pipeline (errorText) and the client bound share it.
func RedactBoundedLiterals(s string, window int, literals []string) string {
	return RedactBounded(RedactLiterals(s, literals), window)
}

// RedactBounded clamps s to window bytes, cuts back to the last value
// boundary when it had to clamp so a credential is never cut in half, and
// replaces credential-shaped text. It is the client-facing half of errorText,
// which adds the stored row's 256-byte clamp and clone; the proxy calls it
// on the error message a key holder receives (PORM-195) with its own window.
// A window with no boundary in it has nothing to cut back to: it is kept
// whole and the rules decide, so a token pressed against padding with no
// separator can keep a fragment there, the property PORM-72 accepted.
func RedactBounded(s string, window int) string {
	s, cut := mcpclient.Clamp(s, window)
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
