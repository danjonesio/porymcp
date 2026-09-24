package mcpclient

import (
	"errors"
	"net/url"
	"testing"
)

// joinSegmentCases is a copy of internal/models' pathSegmentCases: the one
// dot-segment rule, checked here through JoinBase so a case added there is
// added here. PORM-146 security requirement 1.
var joinSegmentCases = []struct {
	rest string
	ok   bool
}{
	{"", true},
	{"user", true},
	{"users/1", true},
	{"a%2Fb", true},
	{"a//b", true},
	{"a.b/c..d", true},
	{"x/%2e", false},
	{"../../admin", false},
	{"%2e%2e/admin", false},
	{"x/..%2f..%2fadmin", false},
	{"%2E%2e", false},
	{".%2e", false},
	{"..%5c", false},
	{"..;/x", false},
	{"../v1beta/x", false},
	{"%252e%252e", false},
	{"%zz", false},
	{"a%00b", false},
	{"a%2ffoo/..%2fb", false},
	{"./x", false},
	{"x/.", false},
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestJoinBase(t *testing.T) {
	base := mustURL(t, "https://api.example/v1")
	for _, c := range joinSegmentCases {
		got, err := JoinBase(base, c.rest)
		if c.ok && err != nil {
			t.Errorf("%q: refused: %v", c.rest, err)
		}
		if !c.ok && !errors.Is(err, ErrPathEscapes) {
			t.Errorf("%q: got %v %v, want ErrPathEscapes", c.rest, got, err)
		}
		if err == nil && (got.Host != base.Host || got.Scheme != base.Scheme) {
			t.Errorf("%q: host or scheme changed: %s", c.rest, got)
		}
	}

	joins := []struct {
		base, rest, want string
	}{
		// A host-only base is "/" (the plan's own example, https://api.github.com).
		{"https://api.github.com", "user", "/user"},
		{"https://api.github.com", "", "/"},
		{"https://api.example/v1", "users", "/v1/users"},
		{"https://api.example/v1/", "users", "/v1/users"},
		{"https://api.example/v1/", "", "/v1/"},
		{"https://api.example/v1", "", "/v1"},
		{"https://api.example/v1", "a%2Fb", "/v1/a%2Fb"},
		{"https://api.example/v1", "a//b", "/v1/a/b"},
		{"https://api.example/v1", "x/", "/v1/x/"},
		// A test path of //evil.example/x, trimmed of its leading slash, is a
		// path under the base and never a new host.
		{"https://api.example/v1", "/evil.example/x", "/v1/evil.example/x"},
		{"https://api.example/v1", "%C3%A9", "/v1/%C3%A9"},
	}
	for _, c := range joins {
		got, err := JoinBase(mustURL(t, c.base), c.rest)
		if err != nil {
			t.Errorf("%s + %q: %v", c.base, c.rest, err)
			continue
		}
		if got.EscapedPath() != c.want {
			t.Errorf("%s + %q: escaped path %q, want %q", c.base, c.rest, got.EscapedPath(), c.want)
		}
		if got.Host != mustURL(t, c.base).Host {
			t.Errorf("%s + %q: host became %q", c.base, c.rest, got.Host)
		}
		if got.RawQuery != "" {
			t.Errorf("%s + %q: query %q appeared", c.base, c.rest, got.RawQuery)
		}
	}
	if _, err := JoinBase(nil, "x"); !errors.Is(err, ErrPathEscapes) {
		t.Errorf("nil base: %v", err)
	}
	if s := ErrPathEscapes.Error(); s != "path escapes the upstream base" {
		t.Errorf("sentence = %q", s)
	}
}

func TestCheckHTTPBase(t *testing.T) {
	ok := []string{"https://api.github.com", "https://api.example/v1", "http://10.0.0.5:8080/api/", "https://api.example/v1?"}
	bad := map[string]string{
		"https://api.example/v1?key=x": "url must not carry a query string",
		"https://u:p@api.example/v1":   "url must not embed credentials",
		"https://api.example/v1#frag":  "url must not carry a fragment",
		"ftp://api.example/v1":         "scheme is not http or https",
	}
	for _, s := range ok {
		u := mustURL(t, s)
		if u.ForceQuery {
			// "?" with nothing after it is ForceQuery, which CheckHTTPBase
			// refuses like a query: the relay would otherwise drop it.
			if err := CheckHTTPBase(u); err == nil {
				t.Errorf("%s: accepted with ForceQuery", s)
			}
			continue
		}
		if err := CheckHTTPBase(u); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for s, want := range bad {
		if err := CheckHTTPBase(mustURL(t, s)); err == nil || err.Error() != want {
			t.Errorf("%s: got %v want %q", s, err, want)
		}
	}
}
