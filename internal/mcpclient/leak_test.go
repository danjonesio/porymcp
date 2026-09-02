package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/netcasklabs/porymcp/internal/models"
)

// All four auth types reach the upstream, on every request of the handshake,
// and none of them reaches the response.
func TestDiscoverInjectsCredential(t *testing.T) {
	const token = "CREDENTIAL_MARKER_9f3a"
	for _, tc := range []struct {
		authType string
		config   string
		header   string
		want     string
	}{
		{models.AuthBearer, `{"token":"` + token + `"}`, "Authorization", "Bearer " + token},
		{models.AuthHeader, `{"header":"X-Docs-Token","value":"` + token + `"}`, "X-Docs-Token", token},
		{models.AuthAPIKey, `{"value":"` + token + `"}`, "X-API-Key", token},
		{models.AuthCustom, `{"headers":{"X-One":"` + token + `","X-Two":"second"}}`, "X-One", token},
	} {
		t.Run(tc.authType, func(t *testing.T) {
			f := newFixture(t)
			up := f.upstream()
			up.AuthType = tc.authType
			got := discover(t, up, json.RawMessage(tc.config))
			if !got.OK {
				t.Fatalf("ok=false error=%q", got.Error)
			}
			for _, r := range f.requests() {
				if v := r.Header.Get(tc.header); v != tc.want {
					t.Errorf("%s %s carried %s=%q, want %q", r.Method, r.RPC, tc.header, v, tc.want)
				}
			}
			absent(t, marshal(t, got), token)
		})
	}
}

// The headline failure: the token is wrong. The operator has to be told, and
// neither the token nor a byte of the server's page may travel back.
func TestDiscoverWrongCredentialLeaksNothing(t *testing.T) {
	const token = "WRONG_TOKEN_MARKER"
	f := newFixture(t)
	f.on["initialize"] = func(w http.ResponseWriter, _ request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="UPSTREAM_HEADER_MARKER"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<h1>UPSTREAM_BODY_MARKER</h1>"))
	}
	up := f.upstream()
	up.AuthType = models.AuthBearer
	got := discover(t, up, json.RawMessage(`{"token":"`+token+`"}`))

	if want := "upstream rejected the credential (401) at initialize"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	absent(t, marshal(t, got), token, "UPSTREAM_HEADER_MARKER", "UPSTREAM_BODY_MARKER")
}

// One table over every failure class, against a fixture that puts a marker in
// every channel a byte could escape through: status line, four headers, a
// cookie, a Location, the Content-Type's own parameter, and the body.
func TestDiscoverNeverEchoesUpstreamBytes(t *testing.T) {
	classes := map[string]func(f *fixture){
		"401 with an HTML page": func(f *fixture) { f.canary = true },
		"200 with an HTML page": func(f *fixture) {
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("Content-Type", "text/html; charset=CANARY_CHARSET")
				w.Header().Set("X-Powered-By", "CANARY_POWERED")
				_, _ = w.Write([]byte("<html>CANARY_BODY <!-- CANARY_COMMENT --></html>"))
			}
		},
		"500": func(f *fixture) {
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("X-Powered-By", "CANARY_POWERED")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("CANARY_BODY"))
			}
		},
		"302": func(f *fixture) {
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("Location", "https://evil.example/CANARY_LOC?code=CANARY_QUERY")
				w.WriteHeader(http.StatusFound)
			}
		},
		"JSON-RPC error": func(f *fixture) {
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Set-Cookie", "sess=CANARY_COOKIE; Path=/")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"nothing to see","data":"CANARY_BODY"}}`))
			}
		},
		"truncated stream": func(f *fixture) {
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"resu CANARY_BODY"))
			}
		},
	}
	for name, setup := range classes {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, setup)
			up := f.upstream()
			up.AuthType = models.AuthBearer
			// The URL dressed the way a hosted server's really is: the
			// credential in the userinfo AND in the query string, which is
			// where Go's own redaction stops helping.
			up.URL = f.withUserinfo("CANARY_USER", "CANARY_PASSWORD", "token=CANARY_QUERYTOKEN")
			got := discover(t, up, json.RawMessage(`{"token":"CANARY_CREDENTIAL"}`))

			if got.OK {
				t.Fatalf("ok=true for %s", name)
			}
			rendered := marshal(t, got)
			absent(t, rendered, canaries...)
			absent(t, rendered, "CANARY_USER", "CANARY_PASSWORD", "CANARY_QUERYTOKEN", "CANARY_CREDENTIAL")
		})
	}
}

// The issue's own version of this test used https://user:secret@host/mcp — and
// Go already masks the PASSWORD, so a leaky implementation passes it. What Go
// keeps is the username, the path and the whole query string, so those are
// what this asserts on.
func TestDiscoverRedactsURLCredentials(t *testing.T) {
	const host = "porm64-does-not-resolve.invalid"
	up := &models.Upstream{
		Slug:      "docs",
		URL:       "https://leakuser:leakpassword@" + host + "/mcp-endpoint?tok=QUERY-SECRET",
		Transport: models.TransportStreamableHTTP,
		AuthType:  models.AuthNone,
	}
	got := discover(t, up, nil)

	if got.OK {
		t.Fatal("ok=true against a host that does not resolve")
	}
	if !strings.Contains(got.Error, host) {
		t.Errorf("error=%q, want the host named — it is the one thing an operator can act on", got.Error)
	}
	absent(t, marshal(t, got), "leakpassword", "QUERY-SECRET", "leakuser", "/mcp-endpoint")
}

// Exact matches, not Contains: these sentences are printed to an operator
// unchanged and the dashboard never pattern-matches them, so the set has to be
// closed and pinned.
func TestDiscoverErrorAllowlist(t *testing.T) {
	// The classes that need a crafted transport error rather than a server.
	transport := []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "example.test", IsNotFound: true}, "cannot resolve example.test"},
		{"connect", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}, "cannot connect to example.test"},
		{"tls", fmt.Errorf("tls: failed to verify certificate: x509: certificate signed by unknown authority"), "tls handshake with example.test failed"},
		{"timeout", context.DeadlineExceeded, "upstream did not answer within 10s"},
		{"body over the read cap", BodyTooLarge{Limit: discoverBodyBytes},
			"upstream's answer to initialize is larger than discovery will read"},
		{"other", fmt.Errorf("something else entirely"), "cannot reach example.test"},
		// A 3xx whose Location named no host this is willing to write down.
		// The proxy writes the same sentence into an audit row.
		{"redirect with no location", Redirect{}, "upstream redirected"},
	}
	for _, tc := range transport {
		t.Run(tc.name, func(t *testing.T) {
			up := &models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone}
			got := clientWith(&countingTransport{err: tc.err}).Discover(t.Context(), up, nil)
			if got.Error != tc.want {
				t.Errorf("error=%q, want %q", got.Error, tc.want)
			}
		})
	}

	// The host is the ONE variable ever interpolated into these sentences, and
	// only when HostSafe says it is plain ASCII. An IDN in Unicode form or a
	// host carrying U+FEFF is upstream-chosen bytes headed for an operator's
	// page and a TEXT column, so it is not written down at all.
	t.Run("host not written down", func(t *testing.T) {
		for _, raw := range []string{
			"https://exämple.test/mcp",
			"https://ex\ufeffample.test/mcp",
		} {
			up := &models.Upstream{URL: raw, Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone}
			dns := &net.DNSError{Err: "no such host", Name: "whatever", IsNotFound: true}
			got := clientWith(&countingTransport{err: dns}).Discover(t.Context(), up, nil)
			if want := "cannot resolve the upstream"; got.Error != want {
				t.Errorf("error=%q for %q, want %q", got.Error, raw, want)
			}
		}
	})

	// The classes decided before any I/O.
	preflight := []struct {
		name string
		up   models.Upstream
		auth string
		want string
	}{
		{"sse transport", models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportSSE}, "",
			"the sse transport is not implemented yet; use streamable-http"},
		{"unknown transport", models.Upstream{URL: "https://example.test/mcp", Transport: "websocket"}, "",
			"unsupported transport"},
		{"non-http scheme", models.Upstream{URL: "file:///etc/passwd", Transport: models.TransportStreamableHTTP}, "",
			"url must be an absolute http or https URL"},
		{"bad auth header", models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportStreamableHTTP, AuthType: models.AuthHeader},
			`{"header":"X-Bad\r\nInject","value":"v"}`, "auth_config names a header that cannot be sent"},
		// PORM-52 security requirement 3: a credential its auth type cannot
		// send anything from is refused before any I/O, with one sentence.
		{"bearer with empty config", models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportStreamableHTTP, AuthType: models.AuthBearer},
			`{}`, "this auth type needs a credential; add one or choose None"},
		{"bearer with no config", models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportStreamableHTTP, AuthType: models.AuthBearer},
			``, "this auth type needs a credential; add one or choose None"},
	}
	for _, tc := range preflight {
		t.Run(tc.name, func(t *testing.T) {
			counter := &countingTransport{}
			got := clientWith(counter).Discover(t.Context(), &tc.up, json.RawMessage(tc.auth))
			if got.Error != tc.want {
				t.Errorf("error=%q, want %q", got.Error, tc.want)
			}
			if counter.count() != 0 {
				t.Errorf("%d requests made; this is decided before any I/O", counter.count())
			}
		})
	}

	// And the classes an answering server produces.
	// The row's name IS the status: it is parsed back out below, which is what
	// keeps the table to one column.
	served := []struct {
		name string
		want string
	}{
		{"401", "upstream rejected the credential (401) at initialize"},
		{"403", "upstream rejected the credential (403) at initialize"},
		{"404", "upstream answered 404 at initialize; check the url points at the mcp endpoint"},
		{"405", "upstream does not accept POST at this url (405)"},
		{"406", "upstream refused the Accept header (406)"},
		{"500", "upstream answered 500 at initialize"},
	}
	for _, tc := range served {
		t.Run(tc.name, func(t *testing.T) {
			var status int
			_, _ = fmt.Sscanf(tc.name, "%d", &status)
			f := newFixture(t)
			f.on["initialize"] = func(w http.ResponseWriter, _ request) { w.WriteHeader(status) }
			if got := discover(t, f.upstream(), nil); got.Error != tc.want {
				t.Errorf("error=%q, want %q", got.Error, tc.want)
			}
		})
	}

	bodies := []struct {
		name        string
		contentType string
		status      int
		body        string
		want        string
	}{
		{"json-rpc error", "application/json", http.StatusOK,
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
			"upstream refused initialize (JSON-RPC error -32601)"},
		{"no result", "application/json", http.StatusOK, `{"jsonrpc":"2.0","id":1}`,
			"upstream answered initialize with no result"},
		{"not json-rpc", "text/plain", http.StatusOK, "not json at all",
			"upstream did not answer initialize with JSON-RPC"},
		{"stream with no data event", "text/event-stream", http.StatusOK, ": a comment\nevent: message\n\n",
			"upstream answered initialize with an event stream carrying no response"},
		{"empty body", "application/json", http.StatusOK, "",
			"upstream answered initialize with an empty body"},
		{"result is not an object", "application/json", http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":"a string"}`,
			"upstream did not complete the MCP handshake"},
	}
	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}
			if got := discover(t, f.upstream(), nil); got.Error != tc.want {
				t.Errorf("error=%q, want %q", got.Error, tc.want)
			}
		})
	}

	// The third value of <step>. Without a row here the whole notification
	// failure branch can be deleted with the suite still green.
	t.Run("notification refused", func(t *testing.T) {
		f := newFixture(t)
		f.on["notifications/initialized"] = func(w http.ResponseWriter, _ request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		if want, got := "upstream answered 500 at notifications/initialized", discover(t, f.upstream(), nil).Error; got != want {
			t.Errorf("error=%q, want %q", got, want)
		}
	})

	t.Run("no protocolVersion", func(t *testing.T) {
		f := newFixture(t)
		f.on["initialize"] = func(w http.ResponseWriter, _ request) {
			f.writeResult(w, map[string]any{"serverInfo": map[string]any{"name": "x"}})
		}
		if want, got := "upstream did not complete the MCP handshake", discover(t, f.upstream(), nil).Error; got != want {
			t.Errorf("error=%q, want %q", got, want)
		}
	})

	t.Run("undecryptable credential", func(t *testing.T) {
		// Decided by the management API, before this package is reached, and
		// built through the same helper so the shape matches.
		if got := Failed("stored credential cannot be decrypted"); got.Error != "stored credential cannot be decrypted" || got.OK {
			t.Errorf("Failed() = %+v", got)
		}
	})
}

// A 3xx is a refusal, and it is reported with the same sentence the proxy
// writes to an audit row: the host and nothing else.
func TestDiscoverRefusesRedirect(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	f := newFixture(t)
	f.on["initialize"] = func(w http.ResponseWriter, _ request) {
		http.Redirect(w, &http.Request{}, target.URL+"/mcp?code=REDIRECT_QUERY_MARKER", http.StatusFound)
	}
	got := discover(t, f.upstream(), nil)

	want := "upstream redirected to " + strings.TrimPrefix(target.URL, "http://")
	if got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("the redirect target saw %d requests; the credential must never reach a host an upstream named", n)
	}
	absent(t, marshal(t, got), "REDIRECT_QUERY_MARKER", "/mcp?code=")
}

// CheckTarget is the only gate on where a discovery request may go, and it
// runs before a socket is opened. Asserted on a RoundTripper, because a server
// that is never dialled cannot testify that nothing arrived.
func TestDiscoverRejectsNonHTTPScheme(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://example.test:70/1",
		"ftp://example.test/mcp",
		"//example.test/mcp",      // scheme-relative: Go would follow it
		"localhost:1/mcp",         // parses as scheme "localhost", opaque "1/mcp"
		"",                        // an upstream stored before any validation existed
		"https:///mcp",            // no host
		"https://example.test/#f", // a fragment is not part of a request
	} {
		t.Run(raw, func(t *testing.T) {
			counter := &countingTransport{}
			up := &models.Upstream{URL: raw, Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone}
			got := clientWith(counter).Discover(t.Context(), up, nil)
			if want := "url must be an absolute http or https URL"; got.Error != want {
				t.Errorf("error=%q, want %q", got.Error, want)
			}
			if counter.count() != 0 {
				t.Errorf("%d requests made for %q", counter.count(), raw)
			}
		})
	}
}

// A header name net/http will not send makes Do fail late with the name quoted
// back. Refusing early keeps that string out of an error an operator reads.
func TestDiscoverRejectsBadAuthHeaderName(t *testing.T) {
	for name, cfg := range map[string]struct {
		authType string
		config   string
	}{
		"crlf in the name":  {models.AuthHeader, `{"header":"X-Bad\r\nInject","value":"v"}`},
		"space in the name": {models.AuthHeader, `{"header":"X Bad","value":"v"}`},
		"host":              {models.AuthHeader, `{"header":"Host","value":"evil.example"}`},
		"content-length":    {models.AuthHeader, `{"header":"Content-Length","value":"0"}`},
		"custom headers":    {models.AuthCustom, `{"headers":{"X-Fine":"a","Transfer-Encoding":"chunked"}}`},
		"api_key header":    {models.AuthAPIKey, `{"header":"X:Bad","value":"v"}`},
		// encoding/json keeps every field it decoded BEFORE the failure, so a
		// partially decodable config still leaves a bad name behind.
		// authHeadersSendable runs first so that name gets its own specific
		// sentence; ApplyAuth itself now refuses a value that does not decode
		// (ErrNoCredential), so it would never reach net/http either way —
		// the ordering is what keeps the better sentence (PORM-52).
		"partially decodable config": {models.AuthHeader, `{"header":"X-Bad\r\nInject","value":"v","headers":123}`},
		// The rest of the hop-by-hop set, which the transport owns.
		"upgrade":             {models.AuthCustom, `{"headers":{"Upgrade":"websocket"}}`},
		"proxy-authorization": {models.AuthHeader, `{"header":"Proxy-Authorization","value":"Basic x"}`},
		// PoryMCP's own half of the conversation. An auth_config does not get
		// to choose what Accept PoryMCP offers, or hand an upstream a session
		// id PoryMCP never minted.
		"accept":         {models.AuthCustom, `{"headers":{"Accept":"text/plain"}}`},
		"mcp-session-id": {models.AuthCustom, `{"headers":{"Mcp-Session-Id":"FORGED"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			counter := &countingTransport{}
			up := &models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportStreamableHTTP, AuthType: cfg.authType}
			got := clientWith(counter).Discover(t.Context(), up, json.RawMessage(cfg.config))
			if want := "auth_config names a header that cannot be sent"; got.Error != want {
				t.Errorf("error=%q, want %q", got.Error, want)
			}
			if counter.count() != 0 {
				t.Errorf("%d requests made", counter.count())
			}
		})
	}
}

// The refusals above are not a ban on custom headers: a name of an upstream's
// own is sent on every request, alongside — never instead of — the three
// PoryMCP writes for itself.
func TestDiscoverSendsCustomHeaders(t *testing.T) {
	f := newFixture(t)
	up := f.upstream()
	up.AuthType = models.AuthCustom
	got := discover(t, up, json.RawMessage(`{"headers":{"X-Whatever":"KEPT_MARKER"}}`))
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	for _, r := range f.requests() {
		if v := r.Header.Get("X-Whatever"); v != "KEPT_MARKER" {
			t.Errorf("%s %s carried X-Whatever=%q, want the operator's own header", r.Method, r.RPC, v)
		}
		if r.Accept != AcceptMCP {
			t.Errorf("%s %s sent Accept %q, want %q", r.Method, r.RPC, r.Accept, AcceptMCP)
		}
	}
	// The session the upstream minted, not one an auth_config chose.
	for _, r := range f.requests()[1:] {
		if r.Session != fixtureSession {
			t.Errorf("%s %s carried session %q, want the one initialize minted", r.Method, r.RPC, r.Session)
		}
	}
}
