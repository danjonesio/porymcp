package models

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// HTTPMethodsAllowed is every verb the relay door will forward, in the order
// a normalised http_methods list is stored. Anything else answers 405 before
// authentication, whatever a key's list says.
var HTTPMethodsAllowed = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

// TestPathMaxBytes bounds Upstream.TestPath.
const TestPathMaxBytes = 256

// NormalizeHTTPMethods is the one rule for a virtual key's http_methods, on
// the way in (the API) and on the way out (the store's read, which marks a
// value that does not re-encode to itself as malformed). Entries are
// upper-cased, must be one of HTTPMethodsAllowed, may not repeat once
// upper-cased, and come back in HTTPMethodsAllowed's order. nil normalises to
// an empty, non-nil list so it encodes as [] and never as null.
func NormalizeHTTPMethods(entries []string) ([]string, error) {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		u := strings.ToUpper(e)
		if !isAllowedMethod(u) {
			return nil, fmt.Errorf("invalid http_methods: %s", boundedEntry(e))
		}
		if seen[u] {
			return nil, fmt.Errorf("duplicate http_methods entry: %s", u)
		}
		seen[u] = true
	}
	out := make([]string, 0, len(seen))
	for _, m := range HTTPMethodsAllowed {
		if seen[m] {
			out = append(out, m)
		}
	}
	return out, nil
}

func isAllowedMethod(m string) bool {
	for _, a := range HTTPMethodsAllowed {
		if a == m {
			return true
		}
	}
	return false
}

// boundedEntry keeps a refusal from echoing a long client value.
func boundedEntry(e string) string {
	const max = 16
	if len(e) <= max {
		return e
	}
	return e[:max] + "..."
}

// ErrPathSegment is what PathSegmentsError returns for any refused segment.
// Callers reword it for their own field; the text never names the segment.
var ErrPathSegment = errors.New("path contains a segment that is not allowed")

// PathSegmentsError is the one dot-segment rule, shared by ValidateTestPath
// and by the relay's path join in internal/mcpclient, so the two cannot
// disagree on an edge case. escaped is a path or path remainder in its escaped
// form. Every segment is percent-decoded once and refused when the decoded
// form, split on "/" and "\" and cut at the first ";", has a component that is
// "." or ".."; when it fails to decode; when it holds NUL; or when it still
// carries %2e, %2f or %5c after that one decode, because an upstream or a
// middlebox that decodes twice would then see a dot segment PoryMCP did not.
// The join itself runs on the escaped form afterwards, so a %2F inside an
// ordinary segment still crosses encoded.
func PathSegmentsError(escaped string) error {
	for _, seg := range strings.Split(escaped, "/") {
		dec, err := url.PathUnescape(seg)
		if err != nil {
			return ErrPathSegment
		}
		if strings.ContainsRune(dec, 0) {
			return ErrPathSegment
		}
		low := strings.ToLower(dec)
		if strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") {
			return ErrPathSegment
		}
		if i := strings.IndexByte(dec, ';'); i >= 0 {
			dec = dec[:i]
		}
		parts := strings.FieldsFunc(dec, func(r rune) bool { return r == '/' || r == '\\' })
		for _, p := range parts {
			if p == "." || p == ".." {
				return ErrPathSegment
			}
		}
	}
	return nil
}

// ValidateTestPath checks Upstream.TestPath on the way in. Empty is valid and
// means the base URL. Otherwise the value is a path: it begins with "/", is at
// most TestPathMaxBytes, carries no query, fragment or control character, and
// passes PathSegmentsError. A test path is joined to the base URL by the same
// rule the relay uses, never resolved against it, so "//host/x" stays a path
// on the base host.
func ValidateTestPath(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return errors.New("test_path must begin with /")
	}
	if len(p) > TestPathMaxBytes {
		return fmt.Errorf("test_path is longer than %d bytes", TestPathMaxBytes)
	}
	if strings.ContainsAny(p, "?#") {
		return errors.New("test_path must not contain a query or fragment")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return errors.New("test_path must not contain a control character")
		}
	}
	if err := PathSegmentsError(p); err != nil {
		return errors.New("test_path must not contain a .. segment")
	}
	return nil
}
