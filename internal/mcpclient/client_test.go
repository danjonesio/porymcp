package mcpclient

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// The default transport is wrapped, not replaced, so certificate verification
// is whatever Go does by default and HTTPS_PROXY still works. A patch that
// reaches for InsecureSkipVerify to test against a self-signed dev server has
// to argue with this.
func TestClientDoesNotWeakenTLS(t *testing.T) {
	tr, ok := NewHTTPClient(Options{}).Transport.(UpstreamTransport)
	if !ok {
		t.Fatal("transport is not an UpstreamTransport")
	}
	if tr.Next != http.DefaultTransport {
		t.Fatalf("UpstreamTransport.Next is %T, want http.DefaultTransport: a replacement transport is where a TLSClientConfig would arrive", tr.Next)
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

	client := NewHTTPClient(Options{Timeout: 5 * time.Second})
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
