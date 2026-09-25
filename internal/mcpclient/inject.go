package mcpclient

import (
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/danjonesio/porymcp/internal/models"
)

// ErrNoCredential reports that an auth type other than none has nothing to
// send: the value is empty, is not an auth_config, or carries no field its
// auth type writes. ApplyAuth writes no credential in that case, and a caller
// that dialled anyway would hand the upstream an unauthenticated request and
// read its 401 as a bad token, the silent failure PORM-52 removes. The proxy
// and the discover gate refuse before the request is built; this error is how
// they know to.
var ErrNoCredential = errors.New("credential is empty or not valid for its auth type")

// ApplyAuth writes real credentials onto the outbound request and strips the
// inbound virtual-key Authorization so it never leaks upstream. It returns
// ErrNoCredential (and writes nothing) when authType needs a credential and
// raw does not supply one; auth_type none always succeeds and writes nothing.
func ApplyAuth(req *http.Request, authType string, raw json.RawMessage) error {
	req.Header.Del("Authorization")
	req.Header.Del("X-Api-Key")
	req.Header.Del("X-API-Key")

	h, err := headersFor(authType, raw)
	if err != nil {
		return err
	}
	for name, vals := range h {
		req.Header[name] = vals
	}
	return nil
}

// CheckCredential is ApplyAuth's verdict without a request: nil when ApplyAuth
// would write a credential (or authType is none), ErrNoCredential otherwise.
// It is the one predicate the proxy, the discover gate and auth_status share.
func CheckCredential(authType string, raw json.RawMessage) error {
	_, err := headersFor(authType, raw)
	return err
}

// headersFor is the one place that decides what a credential writes. It builds
// an http.Header (whose Set canonicalises names) in the same order ApplyAuth
// always wrote them, so a custom auth_config whose "header" repeats a key in
// "headers" still resolves to the later Set, deterministically, rather than to
// whichever of two map keys iterated last.
//
// ErrNoCredential iff authType is not none and: raw is empty, raw does not
// unmarshal (a partially decodable value counts as not decoded), or the
// branch for authType would write no header: bearer with no token; header or
// api_key with no value; custom with no headers and no header/value pair. An
// empty value inside custom "headers" still counts as written, as it always
// has. An unknown auth type writes nothing and is ErrNoCredential.
//
// oauth decodes an OAuthTokenSet instead of an AuthConfig and writes exactly
// one header, Authorization: Bearer <access_token>; a set with no access token
// (not yet connected, or a client-only blob) is ErrNoCredential. Refresh is
// not this function's business: the Presenter in internal/credential renews
// the set before it reaches here, so headersFor stays a pure function.
func headersFor(authType string, raw json.RawMessage) (http.Header, error) {
	h := http.Header{}
	switch authType {
	case models.AuthNone, "":
		return h, nil
	}
	if len(raw) == 0 {
		return nil, ErrNoCredential
	}
	if authType == models.AuthOAuth {
		var set models.OAuthTokenSet
		if err := json.Unmarshal(raw, &set); err != nil || set.AccessToken == "" {
			return nil, ErrNoCredential
		}
		h.Set("Authorization", "Bearer "+set.AccessToken)
		return h, nil
	}
	var cfg models.AuthConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, ErrNoCredential
	}

	switch authType {
	case models.AuthBearer:
		token := cfg.Token
		if token == "" {
			token = strings.TrimPrefix(cfg.Value, "Bearer ")
			token = strings.TrimSpace(token)
		}
		if token != "" {
			h.Set("Authorization", "Bearer "+token)
		}
	case models.AuthHeader:
		if cfg.Header != "" && cfg.Value != "" {
			h.Set(cfg.Header, cfg.Value)
		}
	case models.AuthAPIKey:
		header := cfg.Header
		if header == "" {
			header = "X-API-Key"
		}
		val := cfg.Value
		if val == "" {
			val = cfg.Token
		}
		if val != "" {
			h.Set(header, val)
		}
	case models.AuthCustom:
		for k, v := range cfg.Headers {
			h.Set(k, v)
		}
		if cfg.Header != "" && cfg.Value != "" {
			h.Set(cfg.Header, cfg.Value)
		}
	}
	if len(h) == 0 {
		return nil, ErrNoCredential
	}
	return h, nil
}

// MinLiteralBytes is the shortest injected value the proxy replaces by
// literal match (PORM-208). A shorter value is left to the pattern rules so
// that a trivially short credential cannot blank ordinary words in error
// text. audit.RedactLiterals applies the same floor.
const MinLiteralBytes = 8

// literalDelimiters splits a whitespace piece of a header value into the
// sub-pieces an upstream may echo on their own: a labelled value ("key=v")
// loses its label and a cookie-style value ("sid=v;") its terminator.
const literalDelimiters = `=,;:"'&`

// Literals returns the values a credential writes on the wire, in every
// spelling an upstream is likely to echo, for the literal redaction pass
// (PORM-208). It derives from headersFor, so the switch over kinds is not
// restated. Each header value is trimmed as net/http writes it, then split
// into the pieces an echo can carry (literalCandidates), and each piece is
// added with its URL-encoded and HTML-escaped spellings where those differ
// (encodedForms). Pieces under MinLiteralBytes are dropped, so a scheme
// word such as "Bearer" is never a literal on its own and an echoed
// "Authorization: Bearer <token>" keeps its scheme word. The result is
// deduplicated and sorted longest first; it is nil when the kind writes
// nothing or the credential is not valid for its kind.
func Literals(authType string, raw json.RawMessage) []string {
	h, err := headersFor(authType, raw)
	if err != nil || len(h) == 0 {
		return nil
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if len(s) < MinLiteralBytes || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, name := range names {
		for _, v := range h[name] {
			for _, c := range literalCandidates(textproto.TrimString(v)) {
				add(c)
				for _, e := range encodedForms(c) {
					add(e)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// literalCandidates is the pieces of one trimmed header value an upstream
// may echo: every whitespace piece, the sub-pieces of each piece split at
// literalDelimiters, the remainder after the first whitespace run (so a
// value "Token a b" yields "a b"), and the whole value when no whitespace
// piece reaches MinLiteralBytes (so "abcd efgh ijkl" is a literal, and
// "Bearer <long token>" is not, which keeps the scheme word in an echo).
// Candidates under MinLiteralBytes are the caller's to drop.
func literalCandidates(v string) []string {
	var out []string
	long := false
	for _, p := range strings.Fields(v) {
		if len(p) >= MinLiteralBytes {
			long = true
		}
		out = append(out, p)
		out = append(out, strings.FieldsFunc(p, isLiteralDelimiter)...)
	}
	if i := strings.IndexFunc(v, unicode.IsSpace); i >= 0 {
		out = append(out, strings.TrimLeftFunc(v[i:], unicode.IsSpace))
	}
	if !long {
		out = append(out, v)
	}
	return out
}

func isLiteralDelimiter(r rune) bool {
	return strings.ContainsRune(literalDelimiters, r)
}

// encodedForms is the URL-encoded and HTML-escaped spellings of c that
// differ from c. An upstream may percent-encode an echo, with either hex
// case, or escape it as HTML. The bare token already covers "Bearer%20<tok>"
// and "Bearer&#32;<tok>"; these cover a token whose own bytes change under
// encoding, such as base64's "+", "/" and "=".
func encodedForms(c string) []string {
	var out []string
	for _, e := range []string{url.QueryEscape(c), url.PathEscape(c)} {
		if e != c {
			out = append(out, e, lowerHex(e))
		}
	}
	if e := html.EscapeString(c); e != c {
		out = append(out, e)
	}
	return out
}

// lowerHex lowercases the two hex digits after every "%" in a
// percent-encoded string and nothing else, so the token's own letters keep
// their case. Every "%" in url.QueryEscape's and url.PathEscape's output
// starts a triplet, because a literal "%" is written as "%25".
func lowerHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		for j := i + 1; j <= i+2; j++ {
			if b[j] >= 'A' && b[j] <= 'F' {
				b[j] += 'a' - 'A'
			}
		}
		i += 2
	}
	return string(b)
}
