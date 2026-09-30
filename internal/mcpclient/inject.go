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
	"github.com/danjonesio/porymcp/internal/redact"
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
// inbound virtual-key Authorization so it never leaks upstream. A header
// credential is written as headers; a query credential (PORM-27) is written
// into req.URL.RawQuery by withQueryParam, which drops every piece that
// already names the parameter and appends the pair last, so the query type
// writes no header and a second call gives the same request. It returns
// ErrNoCredential (and writes nothing) when authType needs a credential and
// raw does not supply one; auth_type none always succeeds and writes nothing.
func ApplyAuth(req *http.Request, authType string, raw json.RawMessage) error {
	req.Header.Del("Authorization")
	req.Header.Del("X-Api-Key")
	req.Header.Del("X-API-Key")

	w, err := wireFor(authType, raw)
	if err != nil {
		return err
	}
	for name, vals := range w.header {
		req.Header[name] = vals
	}
	if w.queryName != "" {
		req.URL.RawQuery = withQueryParam(req.URL.RawQuery, w.queryName, w.queryValue)
		req.URL.ForceQuery = false
	}
	return nil
}

// CheckCredential is ApplyAuth's verdict without a request: nil when ApplyAuth
// would write a credential (or authType is none), ErrNoCredential otherwise.
// It is the one predicate the proxy, the discover gate and auth_status share.
func CheckCredential(authType string, raw json.RawMessage) error {
	_, err := wireFor(authType, raw)
	return err
}

// QueryParam is the parameter name a query credential writes, and "" for
// every other kind or a config the query kind cannot send. It is wireFor's
// queryName, exported for the relay's audit params (PORM-27) so the name is
// read from the one decision point and never decoded a second time.
func QueryParam(authType string, raw json.RawMessage) string {
	w, err := wireFor(authType, raw)
	if err != nil {
		return ""
	}
	return w.queryName
}

// MaxQueryParamBytes bounds a query credential's parameter name.
// MaxQueryValueBytes bounds its value, which travels in the request line on
// every call; common servers cap that line near 8 KiB.
const (
	MaxQueryParamBytes = 64
	MaxQueryValueBytes = 4096
)

// ValidQueryParam reports whether name is 1 to MaxQueryParamBytes bytes of
// [A-Za-z0-9._~-], the characters that need no escaping in a query and
// cannot split one. The header rule (sendableHeaderName) is wider and allows
// "&", "=" and "#", so it is not reused here.
func ValidQueryParam(name string) bool {
	if name == "" || len(name) > MaxQueryParamBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '~', c == '-':
		default:
			return false
		}
	}
	return true
}

// wire is what a credential puts on the request: headers, and for the query
// kind one parameter appended to the URL. A kind writes one or the other.
type wire struct {
	header     http.Header
	queryName  string // "" unless the kind is query
	queryValue string
}

func (w wire) empty() bool {
	return len(w.header) == 0 && w.queryName == ""
}

// wireFor is the one place that decides what a credential writes. It builds
// an http.Header (whose Set canonicalises names) in the same order ApplyAuth
// always wrote them, so a custom auth_config whose "header" repeats a key in
// "headers" still resolves to the later Set, deterministically, rather than to
// whichever of two map keys iterated last.
//
// ErrNoCredential iff authType is not none and: raw is empty, raw does not
// unmarshal (a partially decodable value counts as not decoded), or the
// branch for authType would write nothing: bearer with no token; header or
// api_key with no value; custom with no headers and no header/value pair;
// query with no param, a param ValidQueryParam refuses, no value or a value
// over MaxQueryValueBytes. An empty value inside custom "headers" still
// counts as written, as it always has. An unknown auth type writes nothing
// and is ErrNoCredential.
//
// oauth decodes an OAuthTokenSet instead of an AuthConfig and writes exactly
// one header, Authorization: Bearer <access_token>; a set with no access token
// (not yet connected, or a client-only blob) is ErrNoCredential. Refresh is
// not this function's business: the Presenter in internal/credential renews
// the set before it reaches here, so wireFor stays a pure function.
//
// query reads Param, never Header: a header-shaped blob left under the query
// kind by a type change has no Param and reads as no credential.
func wireFor(authType string, raw json.RawMessage) (wire, error) {
	w := wire{header: http.Header{}}
	h := w.header
	switch authType {
	case models.AuthNone, "":
		return w, nil
	}
	if len(raw) == 0 {
		return wire{}, ErrNoCredential
	}
	if authType == models.AuthOAuth {
		var set models.OAuthTokenSet
		if err := json.Unmarshal(raw, &set); err != nil || set.AccessToken == "" {
			return wire{}, ErrNoCredential
		}
		h.Set("Authorization", "Bearer "+set.AccessToken)
		return w, nil
	}
	var cfg models.AuthConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return wire{}, ErrNoCredential
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
	case models.AuthQuery:
		if ValidQueryParam(cfg.Param) && cfg.Value != "" && len(cfg.Value) <= MaxQueryValueBytes {
			w.queryName, w.queryValue = cfg.Param, cfg.Value
		}
	}
	if w.empty() {
		return wire{}, ErrNoCredential
	}
	return w, nil
}

// withQueryParam rebuilds rawQuery so that exactly one piece carries name.
// It splits rawQuery on "&" and drops every piece pieceNames says names the
// parameter; every other piece, empty ones included, keeps its bytes and its
// order, and url.QueryEscape(name)+"="+url.QueryEscape(value) is appended
// last. It never calls url.Values.Encode, which would re-sort and re-encode
// the stored URL's own parameters and the relay client's. Dropping before
// appending is what makes the credential the only value an upstream reads
// for that name, whichever occurrence its parser takes, and what makes a
// second call on the same request give the same query.
func withQueryParam(rawQuery, name, value string) string {
	var kept []string
	if rawQuery != "" {
		for _, piece := range strings.Split(rawQuery, "&") {
			if !pieceNames(piece, name) {
				kept = append(kept, piece)
			}
		}
	}
	kept = append(kept, url.QueryEscape(name)+"="+url.QueryEscape(value))
	return strings.Join(kept, "&")
}

// pieceNames reports whether one "&" piece of a query names the parameter,
// read the way a lenient upstream parser might: each ";"-separated sub-piece
// is a candidate (some stacks still split on ";"), its key is the text before
// the first "=" or the whole sub-piece, a key url.QueryUnescape cannot decode
// counts as a match (a lenient decoder may read it as the name), and a decoded
// key is cut at the first NUL and trimmed of ASCII space before a
// case-insensitive comparison, because stacks that truncate at NUL, trim, or
// fold case would otherwise read a padded spelling as the name.
func pieceNames(piece, name string) bool {
	for _, sub := range strings.Split(piece, ";") {
		key := sub
		if i := strings.IndexByte(sub, '='); i >= 0 {
			key = sub[:i]
		}
		if key == "" {
			continue
		}
		dec, err := url.QueryUnescape(key)
		if err != nil {
			return true
		}
		if i := strings.IndexByte(dec, 0); i >= 0 {
			dec = dec[:i]
		}
		if strings.EqualFold(strings.Trim(dec, " "), name) {
			return true
		}
	}
	return false
}

// literalDelimiters splits a whitespace piece of a header value into the
// sub-pieces an upstream may echo on their own: a labelled value ("key=v")
// loses its label and a cookie-style value ("sid=v;") its terminator.
const literalDelimiters = `=,;:"'&`

// Literals returns the values a credential writes on the wire, in every
// spelling an upstream is likely to echo, for the literal redaction pass
// (PORM-208). It derives from wireFor, so the switch over kinds is not
// restated. Each header value is trimmed as net/http writes it, then split
// into the pieces an echo can carry (literalCandidates), and each piece is
// added with its URL-encoded and HTML-escaped spellings where those differ
// (encodedForms). Pieces under redact.MinLiteralBytes are dropped, so a scheme
// word such as "Bearer" is never a literal on its own and an echoed
// "Authorization: Bearer <token>" keeps its scheme word. The result is
// deduplicated and sorted longest first; it is nil when the kind writes
// nothing or the credential is not valid for its kind.
//
// A query credential (PORM-27) contributes its value the same way, plus the
// two wire pairs name=value and QueryEscape(name)=QueryEscape(value), which
// is how an upstream echoes its own request URL, decoded or as sent. The
// pairs are added whole and not split, so the parameter name alone is never
// a literal. A pair under redact.MinLiteralBytes (len(name)+1+len(value) < 8)
// is dropped like any other short text. req.URL carries the credential on a
// query row after ApplyAuth; any code that wrote req.URL.String() to a sink
// would leak it, and only this literal set stands between that and a row.
func Literals(authType string, raw json.RawMessage) []string {
	w, err := wireFor(authType, raw)
	if err != nil || w.empty() {
		return nil
	}
	h := w.header
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if len(s) < redact.MinLiteralBytes || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	addPiece := func(c string) {
		if len(c) < redact.MinLiteralBytes {
			return // and no encoded spelling of it either
		}
		add(c)
		for _, e := range encodedForms(c) {
			add(e)
		}
	}
	for _, name := range names {
		for _, v := range h[name] {
			for _, c := range literalCandidates(textproto.TrimString(v)) {
				addPiece(c)
			}
		}
	}
	if w.queryName != "" {
		for _, c := range literalCandidates(w.queryValue) {
			addPiece(c)
		}
		addPiece(w.queryName + "=" + w.queryValue)
		addPiece(url.QueryEscape(w.queryName) + "=" + url.QueryEscape(w.queryValue))
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
// piece reaches redact.MinLiteralBytes (so "abcd efgh ijkl" is a literal, and
// "Bearer <long token>" is not, which keeps the scheme word in an echo).
// Candidates under redact.MinLiteralBytes are the caller's to drop.
func literalCandidates(v string) []string {
	var out []string
	long := false
	for _, p := range strings.Fields(v) {
		if len(p) >= redact.MinLiteralBytes {
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
