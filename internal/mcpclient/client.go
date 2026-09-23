// Package mcpclient is the one place PoryMCP talks to an upstream MCP server.
//
// Everything here carries a real upstream credential, so the transport policy
// is a property of the package rather than of any caller: NewHTTPClient is the
// only construction, and the redirect refusal and the wrapped default
// transport are set inside it rather than offered as options. The proxy relays
// a client's request through it; the management API discovers a catalogue
// through it. Nothing else in the tree may build an http.Client that carries a
// credential, TestNoSecondCredentialCarryingHTTPClient is what says so.
//
// It imports internal/models and the standard library and nothing else, which
// is what lets both internal/proxy and internal/api use it without a cycle.
package mcpclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AcceptMCP is what an MCP client has to accept: the reference servers answer
// a POST with an SSE stream unless configured otherwise, and refuse with 406
// unless both media types are offered.
const AcceptMCP = "application/json, text/event-stream"

// MaxBodyBytes caps how much of an upstream response the proxy buffers. An
// upstream is trusted with a credential, not with the proxy's memory.
const MaxBodyBytes = 16 << 20

// MaxErrorBytes caps a string this package writes into an error an operator
// will read. It is the twin of internal/proxy's auditFieldBytes, which bounds
// the same host on its way to an audit row; the two are separate because
// truncate there is an audit-row concern that several proxy tests pin by name,
// and five lines of bound below is cheaper than a third package or an
// inverted dependency between these two.
const MaxErrorBytes = 256

// Options is what a caller gets to choose. The timeout is the only knob, and
// it is an http.Client.Timeout: it covers the whole exchange, body included.
// Discovery allows 10s for a whole handshake. The proxy passes none, because a
// relayed event stream stays open for as long as the upstream and the client
// keep it, and bounds each request through the context instead (the budgets
// in internal/proxy/budget.go). Everything else NewHTTPClient sets is policy,
// see there.
type Options struct {
	Timeout time.Duration
}

// NewHTTPClient builds the client every credential-carrying request goes out
// on.
//
// The real credential is presented to the host in upstreams.url and to no host
// an upstream names in a redirect. Go follows a 3xx by rebuilding the request
// and copying every header across except Authorization, Www-Authenticate,
// Cookie, Cookie2 and their two Proxy- equivalents, and only when the hostname
// changes, not on a subdomain or a scheme downgrade. Three of the four auth
// types write the credential into some other header (api_key to X-API-Key,
// header, custom), and on 307/308 the client's whole body is replayed too. A
// Location would also let an upstream steer PoryMCP at an internal address.
//
// ErrUseLastResponse and not an error of our own: net/http wraps a
// CheckRedirect error in a *url.Error whose URL is the raw Location (query
// string and all) and that string is what would reach error_message.
// ErrUseLastResponse hands back the 3xx itself and Send decides what to say
// about it.
//
// Neither of those is an Options field, and the *http.Client is returned
// rather than held, because a policy a caller can switch off is not a policy.
// TestClientRefusesRedirectsByConstruction pins this construction and
// TestProxyClientRefusesRedirectsByConstruction pins the proxy's use of it.
func NewHTTPClient(o Options) *http.Client {
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: UpstreamTransport{Next: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// UpstreamTransport is the default transport with one rule in front of it: a
// 3xx whose Location will not parse comes back with no Location at all. Go
// parses a Location before it consults CheckRedirect, and when the parse fails
// Do returns a *url.Error that quotes the raw header (the upstream's own
// bytes, query string and all, headed for error_message) so neither
// ErrUseLastResponse nor Send's status check ever sees the response. With the
// header gone Go has nothing to parse, hands the 3xx back, and Send records
// the bare refusal. Only 301/302/303/307/308 would reach that parse, but the
// rule covers the whole class so it reads as one policy.
//
// The default transport is wrapped, not replaced, so HTTPS_PROXY and the rest
// of its environment behave as before, and so certificate verification stays
// on. TestClientDoesNotWeakenTLS pins that Next is http.DefaultTransport, so a
// "let me point this at my self-signed dev server" patch has to argue with a
// test.
type UpstreamTransport struct{ Next http.RoundTripper }

func (t UpstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.Next.RoundTrip(req)
	if err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			if _, perr := url.Parse(loc); perr != nil {
				resp.Header.Del("Location")
			}
		}
	}
	return resp, err
}

// Open performs an already-built upstream request and hands back the live
// response, unless the answer is a 3xx, which it refuses before reading
// anything. It is the one place in the tree that calls Do on a client carrying
// a credential: a request PoryMCP composes, a request it relays and reads
// whole, and a request whose answer it relays as it arrives all go out through
// here, with the same refusal to be sent somewhere else. The caller owns the
// body it is handed and closes it; ReadBody does that for the buffered callers.
func Open(hc *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	// Before the body is read: a 3xx body is not an answer. CheckRedirect is
	// not a complete gate, Go consults it only for 301/302/303/307/308 that
	// carry a Location; 300, 304, 305 and a Location-less 3xx come back as
	// ordinary responses and, before this, were relayed to the client with
	// Location attached and audited as a success. So the test is the status
	// class, not a case list. The body is closed unread, so the connection is
	// not reused; an upstream that just asked us to go elsewhere does not get
	// a warm connection back.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, RedirectRefused(resp.Header.Get("Location"))
	}
	return resp, nil
}

// ReadBody reads a response Open handed back, whole, up to limit bytes, and
// closes it. It is the buffered half of what Send always did.
func ReadBody(resp *http.Response, limit int64) ([]byte, int, http.Header, error) {
	defer resp.Body.Close()
	// limit+1 so that "exactly the cap" is told apart from "more than the cap".
	// A LimitReader that stops AT the cap hands back a document cut in half,
	// which json.Unmarshal then rejects, so a legitimately large catalogue was
	// reported as a server that does not speak JSON-RPC, and on the proxy path
	// half a document was relayed to the client and audited as a success.
	// Neither caller can do anything useful with a truncated body, so it is an
	// error with no body rather than a body with no warning.
	out, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, nil, err
	}
	if int64(len(out)) > limit {
		return nil, 0, nil, BodyTooLarge{Limit: limit}
	}
	return out, resp.StatusCode, resp.Header.Clone(), nil
}

// Send is Open then ReadBody: the request goes out, a 3xx is refused, and the
// body is read whole under the cap. Every caller that wants the whole answer
// uses it; the proxy's streaming relay uses Open alone and reads the body as it
// arrives.
func Send(hc *http.Client, req *http.Request, limit int64) ([]byte, int, http.Header, error) {
	resp, err := Open(hc, req)
	if err != nil {
		return nil, 0, nil, err
	}
	return ReadBody(resp, limit)
}

// ErrBodyTooLarge is what an upstream answer past the caller's read cap
// becomes. Its own text names the cap and nothing about the body; the proxy
// writes it into an audit row.
var ErrBodyTooLarge = errors.New("upstream body exceeds the read limit")

// BodyTooLarge carries the cap that was exceeded, so the sentence an operator
// or an audit row gets is bounded and fixed whichever caller produced it: the
// proxy relays at MaxBodyBytes, discovery reads at a tenth of that.
type BodyTooLarge struct{ Limit int64 }

func (e BodyTooLarge) Error() string {
	return fmt.Sprintf("upstream body exceeds %d bytes", e.Limit)
}

func (e BodyTooLarge) Unwrap() error { return ErrBodyTooLarge }

// ErrRedirected is a refusal with no host to name: a 3xx the upstream sent
// without a Location (a 304 usually, a 301/302 sometimes, nothing stops an
// upstream putting one on a 304), a relative one, one that does not parse, or
// one whose host is not plain host-safe ASCII.
var ErrRedirected = errors.New("upstream redirected")

// HostSafe reports whether every byte of a host is a letter, a digit, a dot,
// an underscore (illegal per RFC 1123, ubiquitous in internal DNS and Compose
// service names), a hyphen, a colon or an IPv6 bracket. It is the discipline
// the proxy's unknownEndpointReason applies to a slug: write a name down only
// when it is known-safe to write down. Anything else (an IDN in Unicode form,
// U+FEFF, U+2028, invalid UTF-8 (url.Parse accepts 0x80-0xFF)) is
// upstream-controlled bytes headed for a TEXT column that SQLite stores and
// Postgres rejects, which would drop the whole row, and for a dashboard panel
// an operator reads.
func HostSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == ':', c == '[', c == ']':
		default:
			return false
		}
	}
	return true
}

// Redirect is what a 3xx upstream answer becomes. Host is the host the
// upstream pointed at, and it is empty when the Location named none this is
// willing to write down.
//
// It carries the host as a field rather than only in its message because two
// callers report it in two places: the proxy writes Error() into an audit row,
// and Discover has to classify it like every other failure: a Discovery's
// error is built from templates and never from an error's own text, because a
// transport error quotes the whole request URL, query string and all. A typed
// host is what lets a redirect obey that rule while both callers still say the
// same sentence.
type Redirect struct{ Host string }

func (e Redirect) Error() string {
	if e.Host == "" {
		return ErrRedirected.Error()
	}
	return fmt.Sprintf("%s to %s", ErrRedirected, e.Host)
}

func (e Redirect) Unwrap() error { return ErrRedirected }

// RedirectRefused names the host the upstream pointed at and nothing else: a
// Location can carry userinfo, a path and a query string, and an OAuth code in
// a query parameter is exactly the shape of string that must not be recorded.
// url.URL keeps userinfo in User and the query in RawQuery, so Host is already
// host[:port]. A scheme-relative "//evil.example/x" has a Host and Go would
// follow it, so it is named.
//
// The bound here is defence in depth for a caller that does not apply one of
// its own; the proxy's audit row is bounded again at auditFieldBytes for the
// whole message.
func RedirectRefused(location string) error {
	u, err := url.Parse(location)
	if err != nil || u.Host == "" || !HostSafe(u.Host) {
		return Redirect{}
	}
	return Redirect{Host: bound(u.Host, MaxErrorBytes)}
}

// bound cuts s to max bytes and scrubs whatever invalid UTF-8 the cut leaves,
// the partial rune at the end, and any that was already there. It is the twin
// of internal/proxy's truncate, see MaxErrorBytes.
func bound(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "")
}
