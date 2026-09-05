package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/models"
)

// A redirect is the one upstream answer that asks the proxy to do something
// with the credential rather than something with the response, so every test
// here asserts the same thing first: the recorder below (a second server the
// upstream points at) saw nothing at all. What the client is told and what
// the operator's row says come after that, because they only matter once the
// secret has stayed where it was put.

// redirectQueryMarker rides in the Location's query string. The audit row may
// name the host a redirect pointed at and nothing else: a Location can carry
// an OAuth code, a signed URL or a session id, and the row is read by anyone
// with the Logs page open.
const redirectQueryMarker = "SECRET-QUERY-STRING"

// recorder is the redirect target, the host the credential must never reach.
// It is addressed as localhost while httptest binds 127.0.0.1, so it is a
// DIFFERENT host to Go: net/http drops Authorization across a host change and
// copies every other header, which is why bearer looks safe and the other
// three auth types are not. Once CheckRedirect returns ErrUseLastResponse none
// of that is consulted (no second request is made at all) so the naming
// matters only to make the failure on an unfixed proxy the one PORM-94
// documents. The swap is best-effort: should httptest ever bind [::1] the two
// names would be one host again, and only the red run's shape would change.
type recorder struct {
	mu   sync.Mutex
	reqs []recordedRequest
	URL  string // http://localhost:<port>
	Host string // localhost:<port>: the only part an audit row may name
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, recordedRequest{
			HTTPMethod: req.Method,
			Header:     req.Header.Clone(),
			Body:       append([]byte(nil), body...),
		})
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	t.Cleanup(srv.Close)
	r.URL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	r.Host = strings.TrimPrefix(r.URL, "http://")
	return r
}

func (r *recorder) requests() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest(nil), r.reqs...)
}

// location is the Location the upstream answers with: a path and a query
// string as well as a host, so a test can assert the row names the host and
// stops there.
func (r *recorder) location() string {
	return r.URL + "/oauth/callback?code=" + redirectQueryMarker
}

// authCase is one of the four kinds of credential an upstream can hold. Bearer
// looks protected across a redirect, and only by an accident of Go's rules
// that a subdomain or a same-host scheme downgrade defeats; the other three
// ride a header Go copies to the target verbatim. That is the whole of
// PORM-94, so the table is over the auth types and not over anything else.
type authCase struct {
	slug   string
	typ    string
	cfg    models.AuthConfig
	header string // where mcpclient.ApplyAuth writes it
	secret string
}

var redirectAuthCases = []authCase{
	{"bear", models.AuthBearer, models.AuthConfig{Token: "sk-real-bearer"},
		"Authorization", "sk-real-bearer"},
	{"apik", models.AuthAPIKey, models.AuthConfig{Value: "REAL-APIKEY-SECRET"},
		"X-API-Key", "REAL-APIKEY-SECRET"}, // the default header, mcpclient.ApplyAuth
	{"hdr", models.AuthHeader, models.AuthConfig{Header: "X-Auth-Token", Value: "REAL-HEADER-SECRET"},
		"X-Auth-Token", "REAL-HEADER-SECRET"},
	{"cust", models.AuthCustom, models.AuthConfig{Headers: map[string]string{"X-Custom-Secret": "REAL-CUSTOM-SECRET"}},
		"X-Custom-Secret", "REAL-CUSTOM-SECRET"},
}

// An upstream that answers a call with a 3xx causes no second outbound request
// whatever kind of credential it holds, on the endpoint that names one member.
// The client is told the transport failed and nothing about where the upstream
// pointed; the row says the upstream redirected and names the host it aimed
// at, with none of the Location's path or query string.
func TestUpstreamRedirectIsNotFollowed(t *testing.T) {
	b := newRecorder(t)

	// One fixture, four members: one argon2id hash instead of four. Each
	// member redirects everything it is sent.
	specs := map[string]upstreamSpec{}
	for _, tc := range redirectAuthCases {
		specs[tc.slug] = upstreamSpec{
			Tools:          []string{"ping_" + tc.slug},
			AuthType:       tc.typ,
			AuthConfig:     tc.cfg,
			RedirectStatus: http.StatusFound,
			RedirectTo:     b.location(),
		}
	}
	f := newFixture(t, specs, true, nil, nil, nil)

	for _, tc := range redirectAuthCases {
		t.Run(tc.typ, func(t *testing.T) {
			// A tool name unique to this subtest. The four share one store and
			// waitAudit returns on the first matching row, so a filter that
			// matched a neighbour's row would let three of the four cases
			// assert nothing.
			tool := "ping_" + tc.slug
			before := map[string]int{}
			for _, other := range redirectAuthCases {
				before[other.slug] = f.totalReqs(other.slug)
			}
			rr := f.postMember(tc.slug, toolCall("1", tool))

			// 1. The credential never left the configured host.
			if got := b.requests(); len(got) != 0 {
				t.Fatalf("the redirect target saw %d requests; %s would have carried %s off the configured host: %+v",
					len(got), tc.header, tc.secret, got)
			}
			// 2. Exactly one request reached the upstream itself: refused, not
			//    retried.
			if n := f.totalReqs(tc.slug); n != 1 {
				t.Errorf("%s saw %d requests, want exactly 1: a redirect must not be replayed", tc.slug, n)
			}
			// 3. No other member of the group was drawn into it: counted as a
			//    total, so a fan-out under a rewritten name would show too.
			for _, other := range redirectAuthCases {
				if other.slug == tc.slug {
					continue
				}
				if n := f.totalReqs(other.slug) - before[other.slug]; n != 0 {
					t.Errorf("%s saw %d new requests; a member endpoint reaches one member", other.slug, n)
				}
			}
			// 4. The client is told the transport failed, and nothing about
			//    where the upstream pointed.
			if rr.Code != http.StatusBadGateway {
				t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
			}
			code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
			if code != -32000 || msg != "upstream request failed" {
				t.Errorf("rpc code=%d message=%q want -32000 %q", code, msg, "upstream request failed")
			}
			if got := rr.Header().Get("Location"); got != "" {
				t.Errorf("the 502 carries Location=%q; relaying it hands the client the host the upstream chose", got)
			}
			for _, leak := range []string{b.Host, redirectQueryMarker, tc.secret} {
				if strings.Contains(rr.Body.String(), leak) {
					t.Errorf("the reply contains %q: %s", leak, rr.Body.String())
				}
			}
			// 5. The row says what happened, names the host, and stops there.
			row := f.waitAudit(models.LogFilter{Status: models.StatusError, Tool: tool})[0]
			if !strings.Contains(row.ErrorMessage, "redirected") {
				t.Errorf("error_message=%q want it to name the redirect", row.ErrorMessage)
			}
			if !strings.Contains(row.ErrorMessage, b.Host) {
				t.Errorf("error_message=%q want it to name %q: an operator has to know which host was aimed at", row.ErrorMessage, b.Host)
			}
			for _, leak := range []string{redirectQueryMarker, "/oauth/callback"} {
				if strings.Contains(row.ErrorMessage, leak) {
					t.Errorf("error_message=%q carries %q; a Location can hold an OAuth code or a signed URL", row.ErrorMessage, leak)
				}
			}
			if len(row.ErrorMessage) > auditFieldBytes {
				t.Errorf("error_message is %d bytes, want at most %d: the host is the upstream's own string", len(row.ErrorMessage), auditFieldBytes)
			}
		})
	}
}

// Every 3xx is one refusal, not only the five Go would have followed. The verb
// and body Go would have sent differ by code (301/303 arrive at the target as
// a GET with no body, 307/308 as the original POST carrying the client's own
// JSON-RPC request) while 300 and a Location-less 3xx were not followed at all
// and were relayed to the client as a success, Location attached. 304 appears
// twice: once carrying a Location, which nothing stops an upstream doing, and
// once without, as the no-Location case.
func TestUpstreamRedirectStatusCodes(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		location bool
		wantHost bool // the row names a host only when there was one to name
	}{
		{"301", http.StatusMovedPermanently, true, true},
		{"303", http.StatusSeeOther, true, true},
		{"307", http.StatusTemporaryRedirect, true, true}, // preserves POST and body
		{"308", http.StatusPermanentRedirect, true, true},
		{"300", http.StatusMultipleChoices, true, true}, // Go never follows it
		{"304 with a Location", http.StatusNotModified, true, true},
		{"304 without", http.StatusNotModified, false, false},
		{"302 without a Location", http.StatusFound, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newRecorder(t)
			spec := upstreamSpec{
				Tools:          []string{"ping_tool"},
				AuthType:       models.AuthAPIKey,
				AuthConfig:     models.AuthConfig{Value: "REAL-APIKEY-SECRET"},
				RedirectStatus: tc.status,
			}
			if tc.location {
				spec.RedirectTo = b.location()
			}
			f := newSingleFixture(t, spec, nil, nil)

			rr := f.postTo("http://localhost:8080/a1/mcp", toolCall("1", "ping_tool"))
			if got := b.requests(); len(got) != 0 {
				t.Fatalf("the redirect target saw %d requests: %+v", len(got), got)
			}
			if rr.Code != http.StatusBadGateway {
				t.Fatalf("HTTP code=%d want 502 (a 3xx is a failure whether or not Go would have followed it); body=%s", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("Location"); got != "" {
				t.Errorf("Location=%q relayed to the client", got)
			}
			row := f.waitAudit(models.LogFilter{Status: models.StatusError, Tool: "ping_tool"})[0]
			if tc.wantHost {
				if want := "upstream redirected to " + b.Host; row.ErrorMessage != want {
					t.Errorf("error_message=%q want %q", row.ErrorMessage, want)
				}
			} else if row.ErrorMessage != "upstream redirected" {
				t.Errorf("error_message=%q want exactly %q: there was no host to name", row.ErrorMessage, "upstream redirected")
			}
		})
	}
}

// The refusal is a property of the one place a request is performed, not of
// the POST path, so the verbs the proxy replays for an SSE open and a session
// teardown are refused the same way. This is the assertion PORM-5's streaming
// path rests on.
func TestUpstreamRedirectRefusedOnEveryVerb(t *testing.T) {
	for _, verb := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(verb, func(t *testing.T) {
			b := newRecorder(t)
			f := newSingleFixture(t, upstreamSpec{
				Tools:          []string{"ping_tool"},
				AuthType:       models.AuthAPIKey,
				AuthConfig:     models.AuthConfig{Value: "REAL-APIKEY-SECRET"},
				RedirectStatus: http.StatusFound,
				RedirectTo:     b.location(),
			}, nil, nil)

			// An empty body is not a JSON-RPC request, so nothing aggregates
			// and both verbs reach forward, which replays them upstream.
			rr := f.do(verb, "")
			if got := b.requests(); len(got) != 0 {
				t.Fatalf("%s: the redirect target saw %d requests: %+v", verb, len(got), got)
			}
			if rr.Code != http.StatusBadGateway {
				t.Fatalf("%s: HTTP code=%d want 502; body=%s", verb, rr.Code, rr.Body.String())
			}
			if n := f.totalReqs("solo"); n != 1 {
				t.Errorf("%s: the upstream saw %d requests, want exactly 1", verb, n)
			}
		})
	}
}

// A relative Location names no host, and following it is what Go does ten
// times over (each hop carrying the real credential) before giving up with a
// *url.Error whose message holds the path and query string the upstream chose.
// One request, one row, no host, and nothing of the Location's text.
func TestUpstreamRelativeRedirectNamesNoHost(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{
		Tools:          []string{"ping_tool"},
		AuthType:       models.AuthAPIKey,
		AuthConfig:     models.AuthConfig{Value: "REAL-APIKEY-SECRET"},
		RedirectStatus: http.StatusFound,
		RedirectTo:     "/elsewhere?code=" + redirectQueryMarker,
	}, nil, nil)

	rr := f.post(toolCall("1", "ping_tool"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
	}
	if n := f.totalReqs("solo"); n != 1 {
		t.Errorf("the upstream saw %d requests, want exactly 1: a relative Location is followed ten times, each hop with the real credential", n)
	}
	row := f.waitAudit(models.LogFilter{Status: models.StatusError, Tool: "ping_tool"})[0]
	if row.ErrorMessage != "upstream redirected" {
		t.Errorf("error_message=%q want %q: there was no host to name", row.ErrorMessage, "upstream redirected")
	}
	for _, leak := range []string{redirectQueryMarker, "elsewhere"} {
		if strings.Contains(row.ErrorMessage, leak) {
			t.Errorf("error_message=%q carries %q from the Location", row.ErrorMessage, leak)
		}
	}
}

// The Location is the upstream's own string, and so is the host inside it, so
// both are bounded before they reach a TEXT column no schema limits. The
// unparseable case is the one neither CheckRedirect nor the status check would
// see on its own: Go parses a Location before it consults CheckRedirect and
// would hand back a *url.Error quoting the raw header, query string included.
// upstreamTransport drops such a Location first, so the row is the bare
// refusal and nothing of the header survives, the bound on the audit sink is
// only the backstop.
func TestUpstreamRedirectAuditRowIsBounded(t *testing.T) {
	cases := []struct {
		name         string
		location     string
		wantExact    string
		wantContains string
	}{
		{"8 KiB host", "http://" + strings.Repeat("a", 8<<10) + ".example.invalid/",
			"", "upstream redirected to "},
		// The marker sits at the front, where the first 256 bytes of Go's own
		// parse error would otherwise have carried it onto the row.
		{"unparseable Location", "http://[::1?code=" + redirectQueryMarker + strings.Repeat("a", 4<<10),
			"upstream redirected", ""},
		{"U+FEFF in the host", "http://ex\ufeffample.invalid/",
			"upstream redirected", ""},
		// An underscore is illegal per RFC 1123 and is what a Compose service
		// name looks like, so it is host-safe and the operator gets a name.
		{"underscore host", "http://my_host.internal:9000/",
			"", "my_host.internal:9000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{
				Tools:          []string{"ping_tool"},
				RedirectStatus: http.StatusFound,
				RedirectTo:     tc.location,
			}, nil, nil)

			if rr := f.post(toolCall("1", "ping_tool")); rr.Code != http.StatusBadGateway {
				t.Fatalf("HTTP code=%d want 502; body=%.200s", rr.Code, rr.Body.String())
			}
			row := f.waitAudit(models.LogFilter{Status: models.StatusError, Tool: "ping_tool"})[0]
			if len(row.ErrorMessage) > auditFieldBytes {
				t.Errorf("error_message is %d bytes, want at most %d", len(row.ErrorMessage), auditFieldBytes)
			}
			if tc.wantExact != "" && row.ErrorMessage != tc.wantExact {
				t.Errorf("error_message=%q want exactly %q", row.ErrorMessage, tc.wantExact)
			}
			if tc.wantContains != "" && !strings.Contains(row.ErrorMessage, tc.wantContains) {
				t.Errorf("error_message=%q want it to contain %q", row.ErrorMessage, tc.wantContains)
			}
			if strings.Contains(row.ErrorMessage, redirectQueryMarker) {
				t.Errorf("error_message=%q carries the Location's query string", row.ErrorMessage)
			}
		})
	}
}

// Everything a Location can carry beyond the host (userinfo, a path, a query
// string) stops at the proxy, and the Location itself never reaches the
// client, because the 502 mapping returns before the copy site
// (copyResponseHeaders). An allowed name on the stub is what proves that, and
// the 502 carries the proxy's own Cache-Control like every other response.
func TestUpstreamRedirectLocationNeverReachesTheClient(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{
		Tools:          []string{"ping_tool"},
		AuthType:       models.AuthAPIKey,
		AuthConfig:     models.AuthConfig{Value: "REAL-APIKEY-SECRET"},
		RedirectStatus: http.StatusFound,
		RedirectTo:     "https://u:p@evil.example/x?token=secret",
		RespHeaders:    map[string]string{"Mcp-Session-Id": "sess-redirect"},
	}, nil, nil)

	rr := f.post(toolCall("1", "ping_tool"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
	}
	// Location and Set-Cookie are off the response allowlist and would be
	// absent whatever this arm did. Mcp-Session-Id is on it, and Send returns
	// a nil header on every error path today, so it is the name that would
	// notice a future error path that both carries headers and reaches the
	// copy site.
	for _, h := range []string{"Location", "Set-Cookie", "Mcp-Session-Id"} {
		if got := rr.Header().Get(h); got != "" {
			t.Errorf("the 502 carries %s=%q; no upstream header is copied back on this path", h, got)
		}
	}
	if vs := rr.Header().Values("Cache-Control"); len(vs) != 1 || vs[0] != "no-store" {
		t.Errorf("Cache-Control=%q on the 502 want exactly [no-store]", vs)
	}
	for _, leak := range []string{"evil.example", "token", "secret", "u:p"} {
		if strings.Contains(rr.Body.String(), leak) {
			t.Errorf("the reply contains %q: %s", leak, rr.Body.String())
		}
	}
	row := f.waitAudit(models.LogFilter{Status: models.StatusError, Tool: "ping_tool"})[0]
	if !strings.Contains(row.ErrorMessage, "evil.example") {
		t.Errorf("error_message=%q want it to name evil.example", row.ErrorMessage)
	}
	for _, leak := range []string{"token", "secret", "u:p", "/x"} {
		if strings.Contains(row.ErrorMessage, leak) {
			t.Errorf("error_message=%q carries %q; the row names the host and nothing else", row.ErrorMessage, leak)
		}
	}
}

// A member whose catalogue request is answered with a redirect drops out of
// the merge exactly as a member that is down does, and the redirect target is
// never contacted, a catalogue request the proxy composes for itself carries
// the real credential too. The rest of the group is unaffected: every
// surviving name is composed from its own slug, so nothing moves when a member
// disappears. The client's request still succeeds, so the log line is the only
// place the dropout is recorded.
func TestGroupCatalogueSkipsRedirectingMember(t *testing.T) {
	b := newRecorder(t)
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"search_docs"}},
		"beta": {
			Tools:          []string{"only_beta"},
			AuthType:       models.AuthAPIKey,
			AuthConfig:     models.AuthConfig{Value: "REAL-APIKEY-SECRET"},
			RedirectStatus: http.StatusFound,
			RedirectTo:     b.location(),
			RedirectOn:     "tools/list",
		},
	}, true, nil, nil, nil)
	logs := captureLogs(f)

	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := b.requests(); len(got) != 0 {
		t.Fatalf("the redirect target saw %d catalogue requests; a proxy-composed tools/list carries the real credential too: %+v", len(got), got)
	}
	if got, want := strings.Join(listedNames(t, rr.Body.Bytes()), ","), "alpha__search_docs"; got != want {
		t.Errorf("listed %q want %q: one member's redirect must cost only that member's tools", got, want)
	}
	if n := f.totalReqs("beta"); n != 1 {
		t.Errorf("beta saw %d requests, want 1", n)
	}
	row := f.waitAudit(models.LogFilter{})[0]
	if row.Status != models.StatusSuccess {
		t.Errorf("row status=%q want %q: the request succeeded on the surviving member", row.Status, models.StatusSuccess)
	}
	recs := logRecords(t, logs)
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %s", len(recs), logs.String())
	}
	rec := recs[0]
	want := map[string]any{
		"level":       "WARN",
		"msg":         "group member skipped",
		"slug":        "beta",
		"upstream_id": "u2",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q]=%v want %v", k, rec[k], v)
		}
	}
	errText, _ := rec["err"].(string)
	if !strings.Contains(errText, "redirected") || !strings.Contains(errText, b.Host) {
		t.Errorf("record[\"err\"]=%q want it to name the redirect and %q", errText, b.Host)
	}
	if len(errText) > auditFieldBytes {
		t.Errorf("record[\"err\"] is %d bytes, want at most %d", len(errText), auditFieldBytes)
	}
}

// The aggregate path's other arm: the catalogue is readable, so the call
// routes, and the redirect is met on the forward, where forward's error is
// serve's error and the whole request fails. 307 is the shape that would have
// replayed the client's own body at the target, and the row names the member
// so an operator knows which credential was aimed where.
func TestGroupCallOnRedirectingMemberIs502(t *testing.T) {
	b := newRecorder(t)
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"search_docs"}},
		"beta": {
			Tools:          []string{"only_beta"},
			AuthType:       models.AuthCustom,
			AuthConfig:     models.AuthConfig{Headers: map[string]string{"X-Custom-Secret": "REAL-CUSTOM-SECRET"}},
			RedirectStatus: http.StatusTemporaryRedirect,
			RedirectTo:     b.location(),
			RedirectOn:     "tools/call",
		},
	}, true, nil, nil, nil)

	rr := f.post(toolCall("1", "beta__only_beta"))
	if got := b.requests(); len(got) != 0 {
		t.Fatalf("the redirect target saw %d requests (307 replays the client's body too): %+v", len(got), got)
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
	if !strings.Contains(row.ErrorMessage, "redirected") || !strings.Contains(row.ErrorMessage, b.Host) {
		t.Errorf("error_message=%q want it to name the redirect and %q", row.ErrorMessage, b.Host)
	}
	if row.UpstreamID != "u2" {
		t.Errorf("row upstream_id=%q want %q: an operator has to know which member redirected", row.UpstreamID, "u2")
	}
}

// The sibling of the sink a refused redirect writes to, and the one that was
// left uncapped: an upstream that answers 200 with an error member has its
// error.message copied onto the row verbatim, out of a body the proxy will
// buffer up to 16 MiB of. The client still gets the answer it was sent; only
// the row is bounded.
func TestUpstreamRelayErrorMessageIsBounded(t *testing.T) {
	huge := strings.Repeat("A", 64<<10)
	f := newSingleFixture(t, upstreamSpec{
		Tools:    []string{"ping_tool"},
		CallBody: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"` + huge + `"}}`,
	}, nil, nil)

	rr := f.post(toolCall("1", "ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200: the upstream answered, badly; the transport did not fail", rr.Code)
	}
	row := f.waitAudit(models.LogFilter{Status: models.StatusError, Tool: "ping_tool"})[0]
	if len(row.ErrorMessage) > auditFieldBytes {
		t.Errorf("error_message is %d bytes, want at most %d: it is the upstream's own string", len(row.ErrorMessage), auditFieldBytes)
	}
}

// The policy lives on the shared client, not on the one function that reads a
// body today, so a refactor that stops going through mcpclient.Send still
// carries it. A tripwire for PORM-5's streaming path and PORM-64's discovery
// client, both of which are meant to reuse this construction.
func TestProxyClientRefusesRedirectsByConstruction(t *testing.T) {
	h := New(&config.Config{PublicURL: "http://localhost:8080"}, nil, nil, nil)
	if h.client.CheckRedirect == nil {
		t.Fatal("the proxy's client has no CheckRedirect; Go follows up to ten redirects with the real credential")
	}
	if err := h.client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect returned %v, want http.ErrUseLastResponse: any other error is wrapped in a *url.Error carrying the raw Location", err)
	}
	if _, ok := h.client.Transport.(upstreamTransport); !ok {
		t.Fatalf("the proxy's transport is %T, want upstreamTransport: without it a Location Go cannot parse reaches error_message verbatim", h.client.Transport)
	}
}
