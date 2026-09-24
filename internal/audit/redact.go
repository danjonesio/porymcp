package audit

import (
	"regexp"
	"strings"
	"unicode"

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
// longRun matches. trimChars is the union of every rule's value class, what
// errorText drops at a window cut so no rule can see a fragment.
const (
	runChars  = `A-Za-z0-9_+/=-`
	trimChars = `A-Za-z0-9._~+/=-`
)

var (
	// schemeValue is an Authorization scheme and the credential after it.
	// The value goes only when secretLike says so, so "missing bearer
	// token" and an echoed WWW-Authenticate challenge (the scheme, then
	// name="value" pairs) read as sent.
	schemeValue = regexp.MustCompile(`(?i)\b(bearer|basic)(\s+)([` + trimChars + `]+)`)
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
// ("getRepoContentsV2Beta") reads as sent; a random 20-character key has two
// digits about 99 times in 100. A UUID, a slug, a snake_case tool identity,
// a hyphenated host label and a timestamp all fail both tests.
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

// notTrimChar is the byte errorText cuts back to after a window cut: the
// first byte from the end that no rule counts as part of a credential.
func notTrimChar(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return false
	case r == '.', r == '_', r == '~', r == '+', r == '/', r == '=', r == '-':
		return false
	}
	return true
}

// errorText is what Record stores: the message cut to the scan window (with
// a trailing run of credential characters dropped when the cut fired),
// redacted, cut to ErrorMessageBytes, then cloned so a queued row never
// keeps the upstream's body alive. It does not call Text: Scrub would move
// exactly-pinned rows, and the invisible-character class is PORM-83's.
func errorText(s string) string {
	s, cut := mcpclient.Clamp(s, redactWindowBytes)
	if cut {
		// A whole window of credential characters has no byte to cut back
		// to; it is kept whole and longRun decides.
		if i := strings.LastIndexFunc(s, notTrimChar); i >= 0 {
			s = s[:i+1]
		}
	}
	s, _ = mcpclient.Clamp(RedactText(s), ErrorMessageBytes)
	return strings.Clone(s)
}
