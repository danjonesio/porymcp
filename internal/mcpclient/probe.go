package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// probeDrainBytes is how much of a test answer's body Probe reads before
// closing it. The body is never kept or reported; the drain only lets the
// connection be reused, and a longer body is not an error.
const probeDrainBytes = 2 << 20

// Probe is the connection test for an HTTP API upstream (PORM-146), the
// counterpart of Discover for kind http: one GET to the base URL joined with
// the upstream's test path, with the stored credential, under the discovery
// budget. It runs Discover's pre-flight first (preflight, with the base-URL
// rules), so a refused transport, URL or credential is reported without a
// request, and it builds the target with JoinBase, never by resolving the
// test path against the base. A 2xx is ok. The failure sentences are one
// closed set in Discover's voice; the body never reaches the result.
func (c *Client) Probe(ctx context.Context, up *models.Upstream, plainAuth json.RawMessage) Discovery {
	out := Discovery{Kind: models.KindHTTP, Tools: []Tool{}}
	if models.ValidSlug(up.Slug) {
		out.Slug = up.Slug
	}
	host, fail := preflight(up, plainAuth, true)
	if fail != "" {
		return out.fail(fail)
	}
	if err := models.ValidateTestPath(up.TestPath); err != nil {
		return out.fail(err.Error())
	}
	base, err := url.Parse(up.URL) // preflight has already accepted it
	if err != nil {
		return out.fail("url must be an absolute http or https URL")
	}
	target, err := JoinBase(base, strings.TrimPrefix(up.TestPath, "/"))
	if err != nil {
		return out.fail("test_path escapes the base url")
	}

	ctx, cancel := context.WithTimeout(ctx, discoverBudget)
	defer cancel()
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://placeholder/", nil)
	if err != nil {
		return out.fail("cannot build the test request")
	}
	// Assigned rather than re-parsed from a string, so the escaped path
	// JoinBase produced (a %2F inside a segment, say) is sent as it is.
	req.URL = target
	req.Host = target.Host
	if err := ApplyAuth(req, up.AuthType, plainAuth); err != nil {
		// Unreachable: preflight refused the credential first. Kept so the
		// seam cannot regress silently.
		return out.fail(errNeedsCredential)
	}
	req.Header.Set("Accept", "*/*")

	resp, err := Open(c.http, req)
	out.LatencyMS = latencyMS(time.Since(start))
	if err != nil {
		// Both the sequence deadline and Client.Timeout arrive as this.
		if errors.Is(err, context.DeadlineExceeded) {
			return out.fail("upstream did not answer within " + discoverBudget.String())
		}
		return out.fail(TransportFailure(err, host))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeDrainBytes))
	out.HTTPStatus = resp.StatusCode

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		out.OK = true
		return out
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return out.fail(fmt.Sprintf("upstream rejected the credential (%d)", code))
	case code == http.StatusNotFound:
		return out.fail("upstream answered 404; check the test path")
	default:
		return out.fail(fmt.Sprintf("upstream answered %d", code))
	}
}
