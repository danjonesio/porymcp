package mcpclient

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/netguard"
)

// The policy lives on the construction, not on the one function that reads a
// body today, so a caller that stops going through Send still carries it. The
// twin of TestProxyClientRefusesRedirectsByConstruction, in the package that
// now owns the policy.
func TestClientRefusesRedirectsByConstruction(t *testing.T) {
	c := NewHTTPClient(Options{Timeout: 10 * time.Second})
	if c.CheckRedirect == nil {
		t.Fatal("the client has no CheckRedirect; Go follows up to ten redirects with the real credential")
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect returned %v, want http.ErrUseLastResponse: any other error is wrapped in a *url.Error carrying the raw Location", err)
	}
	if _, ok := c.Transport.(UpstreamTransport); !ok {
		t.Fatalf("transport is %T, want UpstreamTransport: without it a Location Go cannot parse reaches an operator verbatim", c.Transport)
	}
	if c.Timeout != 10*time.Second {
		t.Errorf("Timeout=%v, want the option's value: the timeout is the only knob", c.Timeout)
	}
}

// The default transport is cloned, then wrapped, so certificate verification
// is whatever Go does by default and HTTPS_PROXY still works (security
// requirement 7). Clone fills TLSClientConfig with the h2 defaults, so the
// pin is on the fields that would weaken it, not on nil. A patch that reaches
// for InsecureSkipVerify to test against a self-signed dev server, or for a
// DialTLSContext that would route https around the address guard, has to
// argue with this.
func TestClientDoesNotWeakenTLS(t *testing.T) {
	wrapped, ok := NewHTTPClient(Options{}).Transport.(UpstreamTransport)
	if !ok {
		t.Fatal("transport is not an UpstreamTransport")
	}
	tr, ok := wrapped.Next.(*http.Transport)
	if !ok {
		t.Fatalf("UpstreamTransport.Next is %T, want the cloned *http.Transport", wrapped.Next)
	}
	if tr == http.DefaultTransport {
		t.Fatal("Next is the shared http.DefaultTransport itself; the guard must go on a clone")
	}
	if c := tr.TLSClientConfig; c != nil {
		if c.InsecureSkipVerify || c.RootCAs != nil || c.VerifyPeerCertificate != nil || c.VerifyConnection != nil || c.ServerName != "" {
			t.Fatalf("TLSClientConfig weakened: skip=%v roots=%v verifyPeer=%v verifyConn=%v serverName=%q",
				c.InsecureSkipVerify, c.RootCAs != nil, c.VerifyPeerCertificate != nil, c.VerifyConnection != nil, c.ServerName)
		}
	}
	if tr.DialTLSContext != nil || tr.DialTLS != nil || tr.Dial != nil { //nolint:staticcheck // the deprecated fields are exactly the bypasses being pinned
		t.Fatal("a DialTLS or Dial hook is set; https would route around the address guard")
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext is nil; the address guard is not installed")
	}
	if reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Fatal("Proxy is not http.ProxyFromEnvironment; HTTPS_PROXY deployments would break")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 is off; the clone lost the default transport's HTTP/2")
	}
}

// Every 3xx, not the five Go would follow. CheckRedirect is consulted only for
// 301/302/303/307/308 carrying a Location; 300, 304 and a Location-less 3xx
// come back as ordinary responses, so the refusal has to be a status-class
// test in Send. The target server is the proof: it must see nothing at all.
func TestSendRefusesEveryRedirectClass(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// A path and a query on the Location, so the assertion below can say the
	// error names the host and nothing else.
	location := target.URL + "/redirected?code=REDIRECT_QUERY_MARKER"

	var status int
	var withLocation bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if withLocation {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}))
	defer origin.Close()

	client := NewHTTPClient(Options{Timeout: 5 * time.Second, Guard: testGuard})
	for _, code := range []int{300, 301, 302, 303, 304, 307, 308} {
		for _, loc := range []bool{true, false} {
			name := strconv.Itoa(code)
			if !loc {
				name += "/no-location"
			}
			t.Run(name, func(t *testing.T) {
				status, withLocation = code, loc
				req, err := http.NewRequest(http.MethodPost, origin.URL, strings.NewReader("{}"))
				if err != nil {
					t.Fatal(err)
				}
				body, gotStatus, hdr, err := Send(client, req, MaxBodyBytes)
				if !errors.Is(err, ErrRedirected) {
					t.Fatalf("Send err=%v, want ErrRedirected", err)
				}
				if body != nil || gotStatus != 0 || hdr != nil {
					t.Errorf("Send returned body=%q status=%d hdr=%v; a 3xx is refused before any of them is read", body, gotStatus, hdr)
				}
				if loc && !strings.Contains(err.Error(), target.Listener.Addr().String()) {
					t.Errorf("err=%q, want the host it pointed at", err)
				}
				if strings.Contains(err.Error(), "REDIRECT_QUERY_MARKER") || strings.Contains(err.Error(), "/redirected") {
					t.Errorf("err=%q carries the Location's path or query: an OAuth code lives there", err)
				}
			})
		}
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("the redirect target was called %d times, want 0: the credential must never reach a host an upstream named", n)
	}
}

// PORM-5 security requirement 2: the refusal lives in Open, which the proxy's
// streaming relay calls without ReadBody, so it is proved on Open itself and on
// every 3xx code, the ones Go never consults CheckRedirect for included. A
// refused response hands back no *http.Response at all, and its body has been
// closed, so nothing downstream could copy a redirect's headers to a client.
func TestOpenRefusesEveryRedirectClass(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	var status int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/elsewhere?code=REDIRECT_QUERY_MARKER")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "event: message\ndata: {}\n\n")
	}))
	defer origin.Close()

	client := NewHTTPClient(Options{Timeout: 5 * time.Second, Guard: testGuard})
	for code := 300; code <= 308; code++ {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			status = code
			req, err := http.NewRequest(http.MethodPost, origin.URL, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := Open(client, req)
			if !errors.Is(err, ErrRedirected) {
				t.Fatalf("Open err=%v, want ErrRedirected", err)
			}
			if resp != nil {
				t.Fatalf("Open returned a response on a %d; a 3xx is refused before the caller can read a header off it", code)
			}
			if strings.Contains(err.Error(), "REDIRECT_QUERY_MARKER") || strings.Contains(err.Error(), "/elsewhere") {
				t.Errorf("err=%q carries the Location's path or query", err)
			}
		})
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("the redirect target was called %d times, want 0", n)
	}
}

// The convention rots the moment a second client exists, so it is a test and
// not a comment. Anything that carries an upstream credential goes out on
// mcpclient.NewHTTPClient; the two exceptions carry none.
func TestNoSecondCredentialCarryingHTTPClient(t *testing.T) {
	// This package is allowed as a whole: it is where the construction lives.
	const allowedDir = "internal/mcpclient/"
	allowed := map[string]string{
		"cmd/server/main.go":     "the container healthcheck against 127.0.0.1, which sends no credential",
		"cmd/server/tls_test.go": "a test dialling the server's own listener",
	}
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".go" {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
			if _, ok := allowed[rel]; ok || strings.HasPrefix(rel, allowedDir) {
				return nil
			}
			found, err := ownHTTPClient(rel, string(b))
			if err != nil {
				t.Errorf("%s does not parse: %v", rel, err)
				return nil
			}
			for _, where := range found {
				t.Errorf("%s %s: if it carries an upstream credential it must use mcpclient.NewHTTPClient, which is the only place the no-redirect policy is set", rel, where)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestOAuthStubNeverImported keeps the test-only authorization server out of
// the binary (PORM-139 security requirement 13). oauthstub is a non-test
// package so five packages' tests can share it; nothing but a _test.go file
// may import it.
func TestOAuthStubNeverImported(t *testing.T) {
	const stub = `"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"`
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), stub) {
				t.Errorf("%s imports oauthstub, which is test-only", strings.TrimPrefix(filepath.ToSlash(path), "../../"))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// The shapes that build or reach for a client PoryMCP did not configure. The
// selector list matters as much as the composite literal: http.DefaultClient
// and the http.Get/Post/Head/PostForm helpers that use it have no
// CheckRedirect and no UpstreamTransport, so a caller reaching for one walks a
// Bearer token to whatever host a Location names.
var packageClients = map[string]bool{
	"DefaultClient": true, "Get": true, "Post": true, "Head": true, "PostForm": true,
}

// ownHTTPClient reports, as "line N: shape", every place in one file's source
// that builds an http.Client or reaches for the package-level one.
//
// It parses rather than greps. The substring this used to look for
// ("&http.Client{") matched a mention in a comment and missed every real
// bypass: new(http.Client), a value literal without the &, var c http.Client,
// an import alias, an extra space before the brace, and http.DefaultClient,
// which needs no literal at all.
func ownHTTPClient(name, src string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var found []string
	at := func(pos token.Pos, what string) {
		found = append(found, fmt.Sprintf("line %d: %s", fset.Position(pos).Line, what))
	}

	// The local name net/http is bound to in THIS file, so that an alias (or
	// a dot-import, which puts Client and DefaultClient in scope with no
	// qualifier at all) cannot walk past the check.
	locals := map[string]bool{}
	for _, spec := range file.Imports {
		if spec.Path.Value != `"net/http"` {
			continue
		}
		switch {
		case spec.Name == nil:
			locals["http"] = true
		case spec.Name.Name == ".":
			at(spec.Pos(), "dot-imports net/http, which puts Client and DefaultClient in scope unqualified")
		case spec.Name.Name != "_":
			locals[spec.Name.Name] = true
		}
	}
	if len(locals) == 0 {
		return found, nil
	}
	// isClient reports whether an expression names the http.Client TYPE.
	isClient := func(expr ast.Expr) bool {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Client" {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && locals[pkg.Name]
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit: // http.Client{…}, with or without a & in front
			if isClient(node.Type) {
				at(node.Pos(), "builds an http.Client")
			}
		case *ast.CallExpr: // new(http.Client)
			if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "new" && len(node.Args) == 1 && isClient(node.Args[0]) {
				at(node.Pos(), "builds an http.Client with new")
			}
		case *ast.ValueSpec: // var c http.Client
			if isClient(node.Type) {
				at(node.Pos(), "declares an http.Client value")
			}
		case *ast.Field: // a struct field or parameter of type http.Client
			if isClient(node.Type) {
				at(node.Pos(), "holds an http.Client by value")
			}
		case *ast.SelectorExpr: // http.DefaultClient, http.Get, …
			pkg, ok := node.X.(*ast.Ident)
			if ok && locals[pkg.Name] && packageClients[node.Sel.Name] {
				at(node.Pos(), "uses http."+node.Sel.Name)
			}
		}
		return true
	})
	return found, nil
}

// The checker is the test, so the checker gets a test: every shape that
// produced a redirect-following, credential-capable client while the old
// substring grep stayed green, and the mention in a comment that used to make
// it red.
func TestCredentialClientCheckerCatchesEveryShape(t *testing.T) {
	const head = "package x\n\nimport (\n\t\"net/http\"\n\t\"time\"\n)\n\nvar _ = time.Second\n"
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"new", head + "func f() *http.Client { return new(http.Client) }", true},
		{"value literal", head + "func f() *http.Client { c := http.Client{Timeout: time.Second}; return &c }", true},
		{"var declaration", head + "func f() *http.Client { var c http.Client; return &c }", true},
		{"aliased import", "package x\n\nimport h \"net/http\"\n\nfunc f() *h.Client { return &h.Client{} }", true},
		{"space before the brace", head + "func f() *http.Client { return &http.Client {} }", true},
		{"the package client", head + "func f() *http.Client { return http.DefaultClient }", true},
		{"a package helper", head + "func f() { _, _ = http.Get(\"https://example.test\") }", true},
		{"dot import", "package x\n\nimport . \"net/http\"\n\nfunc f() *Client { return DefaultClient }", true},
		{"struct field by value", head + "type s struct{ c http.Client }", true},
		// The false positive the grep had: prose is not code.
		{"a comment", head + "// This is the only place a &http.Client{ may be built.\nfunc f() {}", false},
		// And the shapes that are fine: holding a pointer to one built
		// elsewhere is what every caller of NewHTTPClient does.
		{"holds a pointer", head + "type s struct{ c *http.Client }\n\nfunc f(c *http.Client) *http.Client { return c }", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := ownHTTPClient(tc.name+".go", tc.src)
			if err != nil {
				t.Fatalf("the fixture does not parse: %v", err)
			}
			if got := len(found) > 0; got != tc.want {
				t.Errorf("flagged=%v (%v), want %v", got, found, tc.want)
			}
		})
	}
}

// TestOpenRelayPasses304Only pins the relay door's one exception to the 3xx
// refusal (PORM-146 security requirement 5): OpenRelay hands a 304 back with
// its headers and an open body, refuses every other 3xx exactly as Open does,
// and Open itself still refuses a 304.
func TestOpenRelayPasses304Only(t *testing.T) {
	var status int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/x?code=REDIRECT_QUERY_MARKER")
		w.Header().Set("ETag", `"v2"`)
		w.WriteHeader(status)
	}))
	defer origin.Close()
	client := NewHTTPClient(Options{Timeout: 5 * time.Second, Guard: testGuard})
	for code := 300; code <= 308; code++ {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			status = code
			req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
			resp, err := OpenRelay(client, req)
			if code == http.StatusNotModified {
				if err != nil || resp == nil || resp.StatusCode != 304 {
					t.Fatalf("OpenRelay on 304: resp=%v err=%v", resp, err)
				}
				if resp.Header.Get("ETag") != `"v2"` {
					t.Fatalf("headers not handed back: %v", resp.Header)
				}
				b, rerr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if rerr != nil || len(b) != 0 {
					t.Fatalf("304 body: %q %v", b, rerr)
				}
				return
			}
			if !errors.Is(err, ErrRedirected) || resp != nil {
				t.Fatalf("OpenRelay on %d: resp=%v err=%v, want ErrRedirected and no response", code, resp, err)
			}
			if strings.Contains(err.Error(), "REDIRECT_QUERY_MARKER") {
				t.Fatalf("the Location's query reached the error: %v", err)
			}
		})
	}
	status = http.StatusNotModified
	req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	if resp, err := Open(client, req); !errors.Is(err, ErrRedirected) || resp != nil {
		t.Fatalf("Open on 304: resp=%v err=%v; the MCP door's refusal must be unchanged", resp, err)
	}
}

// Security requirement 6: the guard goes on a clone and never on the shared
// http.DefaultTransport, which the container healthcheck and every test
// client dial loopback through.
func TestDefaultTransportUntouched(t *testing.T) {
	shared := http.DefaultTransport.(*http.Transport)
	before := reflect.ValueOf(shared.DialContext).Pointer()
	_ = NewHTTPClient(Options{})
	_ = NewHTTPClient(Options{Guard: testGuard})
	if after := reflect.ValueOf(shared.DialContext).Pointer(); after != before {
		t.Fatal("NewHTTPClient changed http.DefaultTransport.DialContext; the healthcheck would be refused")
	}
	if got := NewHTTPClient(Options{}).Transport.(UpstreamTransport).Next; got == http.RoundTripper(shared) {
		t.Fatal("the client wraps the shared default transport itself")
	}
}

// Security requirement 4: a refusal leaves Open as the bare Denied value.
// Do wraps it in a *url.Error whose text quotes the request URL, and that
// text is what the MCP door writes into an audit row.
func TestOpenReturnsBareDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the loopback server was reached under the default guard")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := NewHTTPClient(Options{Timeout: 5 * time.Second})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp?token=SECRET_QUERY_MARKER", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Open(client, req)
	if resp != nil {
		resp.Body.Close()
	}
	want := netguard.Denied{Class: netguard.ClassLoopback}
	if err != want {
		t.Fatalf("Open err=%v (%T), want exactly %v", err, err, want)
	}
	if msg := err.Error(); strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "http") || strings.Contains(msg, "SECRET_QUERY_MARKER") {
		t.Fatalf("error text %q carries the address or the URL", msg)
	}
}

// Security requirements 4 and 5: the closed sentence set names the class
// through both wrappings Do can apply, and a resolver error still reads as
// one.
func TestTransportFailureNamesClass(t *testing.T) {
	denied := netguard.Denied{Class: netguard.ClassLoopback}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"bare", denied, "upstream address denied: loopback"},
		{"url.Error", &url.Error{Op: "Post", URL: "http://127.0.0.1:1/mcp?q=1", Err: denied}, "upstream address denied: loopback"},
		{"proxyconnect", &url.Error{Op: "Post", URL: "http://127.0.0.1:1/mcp", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: denied}}, "upstream address denied: loopback"},
		{"metadata", netguard.Denied{Class: netguard.ClassMetadata}, "upstream address denied: metadata"},
		{"dns", &net.DNSError{Err: "no such host", Name: "example.test", IsNotFound: true}, "cannot resolve example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TransportFailure(tc.err, "example.test"); got != tc.want {
				t.Fatalf("TransportFailure=%q, want %q", got, tc.want)
			}
		})
	}
}
