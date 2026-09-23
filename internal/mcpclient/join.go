package mcpclient

import (
	"errors"
	"net/url"
	"strings"

	"github.com/danjonesio/porymcp/internal/models"
)

// ErrPathEscapes is JoinBase's refusal: the remainder would leave the base
// URL's path, or a segment is one PathSegmentsError refuses. Its text is the
// sentence the relay door answers with; it names nothing from the request.
var ErrPathEscapes = errors.New("path escapes the upstream base")

// JoinBase joins a relayed path remainder, or a test path, onto an HTTP API's
// base URL (PORM-146). Scheme, host and port are the base's and never the
// caller's. The rule, in order:
//
//   - escapedRest is checked segment by segment in its decoded form by
//     models.PathSegmentsError, the one dot-segment rule in the tree, before
//     any join, because url.JoinPath runs path.Join over escaped strings and
//     %2e%2e is an ordinary name to it.
//   - An empty remainder is the base URL's path exactly as stored, trailing
//     slash included or not.
//   - A base with no path is treated as "/": JoinPath on an empty path takes
//     its relative branch and yields a request line with no leading slash.
//   - The join runs on the escaped form, so a %2F inside an ordinary segment
//     crosses still encoded; "a//b" collapses to "a/b" as path.Join does.
//   - The result's escaped path must equal the base's with its trailing slash
//     trimmed, or begin with that plus "/", so a base of /v1 is never left for
//     /v1beta. Nothing is resolved against the base: "//host/x" is a path.
func JoinBase(base *url.URL, escapedRest string) (*url.URL, error) {
	if base == nil {
		return nil, ErrPathEscapes
	}
	if err := models.PathSegmentsError(escapedRest); err != nil {
		return nil, ErrPathEscapes
	}
	b := *base
	if b.Path == "" {
		b.Path, b.RawPath = "/", ""
	}
	if escapedRest == "" {
		return &b, nil
	}
	joined := b.JoinPath(escapedRest)
	trimmed := strings.TrimSuffix(b.EscapedPath(), "/")
	got := joined.EscapedPath()
	if got != trimmed && !strings.HasPrefix(got, trimmed+"/") {
		return nil, ErrPathEscapes
	}
	return joined, nil
}
