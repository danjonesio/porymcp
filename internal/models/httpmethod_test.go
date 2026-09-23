package models

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeHTTPMethods(t *testing.T) {
	ok := []struct {
		in   []string
		want []string
	}{
		{nil, []string{}},
		{[]string{}, []string{}},
		{[]string{"get", "POST"}, []string{"GET", "POST"}},
		{[]string{"DELETE", "GET"}, []string{"GET", "DELETE"}},
		{[]string{"patch", "Put", "HEAD"}, []string{"HEAD", "PUT", "PATCH"}},
	}
	for _, c := range ok {
		got, err := NormalizeHTTPMethods(c.in)
		if err != nil {
			t.Fatalf("%v: %v", c.in, err)
		}
		if got == nil {
			t.Fatalf("%v: nil result; want a non-nil list so it encodes as []", c.in)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%v: got %v want %v", c.in, got, c.want)
		}
	}
	bad := []struct {
		in   []string
		want string
	}{
		{[]string{"FETCH"}, "invalid http_methods: FETCH"},
		{[]string{"get", "GET"}, "duplicate http_methods entry: GET"},
		{[]string{" GET"}, "invalid http_methods:  GET"},
		{[]string{"OPTIONS"}, "invalid http_methods: OPTIONS"},
		{[]string{strings.Repeat("x", 40)}, "invalid http_methods: " + strings.Repeat("x", 16) + "..."},
	}
	for _, c := range bad {
		if _, err := NormalizeHTTPMethods(c.in); err == nil || err.Error() != c.want {
			t.Fatalf("%v: got %v want %q", c.in, err, c.want)
		}
	}
}

// pathSegmentCases is the one table for the dot-segment rule. The mcpclient
// package copies it for TestJoinBase, so a case added here is added there.
var pathSegmentCases = []struct {
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

func TestPathSegmentsError(t *testing.T) {
	for _, c := range pathSegmentCases {
		err := PathSegmentsError(c.rest)
		if c.ok && err != nil {
			t.Errorf("%q: refused: %v", c.rest, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q: accepted; want a refusal", c.rest)
		}
		if err != nil && strings.Contains(err.Error(), c.rest) && c.rest != "" {
			t.Errorf("%q: error text names the segment", c.rest)
		}
	}
}

func TestValidateTestPath(t *testing.T) {
	ok := []string{"", "/", "/user", "/v1/users/1", "//evil.example/x", "/a%2Fb", "/" + strings.Repeat("a", 255)}
	for _, p := range ok {
		if err := ValidateTestPath(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	bad := map[string]string{
		"user":                         "test_path must begin with /",
		"/x?y":                         "test_path must not contain a query or fragment",
		"/x#f":                         "test_path must not contain a query or fragment",
		"/" + strings.Repeat("a", 256): "test_path is longer than 256 bytes",
		"/a/../b":                      "test_path must not contain a .. segment",
		"/%2e%2e/x":                    "test_path must not contain a .. segment",
		"/a/..%2fb":                    "test_path must not contain a .. segment",
		"/%zz":                         "test_path must not contain a .. segment",
		"/a\x00b":                      "test_path must not contain a control character",
		"/a\nb":                        "test_path must not contain a control character",
	}
	for p, want := range bad {
		err := ValidateTestPath(p)
		if err == nil || err.Error() != want {
			t.Errorf("%q: got %v want %q", p, err, want)
		}
	}
}
