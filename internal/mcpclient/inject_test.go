package mcpclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/redact"
)

// TestApplyAuthReportsEmptyCredential pins PORM-52 security requirement 3:
// ApplyAuth says when it wrote no credential for an auth type that needs one,
// and CheckCredential is the same verdict without a request.
func TestApplyAuthReportsEmptyCredential(t *testing.T) {
	for name, tc := range map[string]struct {
		authType string
		raw      string
		wantErr  bool
		header   string // header expected on the request when wantErr is false
		value    string
	}{
		"none, nil":                         {models.AuthNone, ``, false, "", ""},
		"none, garbage":                     {models.AuthNone, `not json`, false, "", ""},
		"empty type, nil":                   {"", ``, false, "", ""},
		"bearer, nil":                       {models.AuthBearer, ``, true, "", ""},
		"bearer, empty object":              {models.AuthBearer, `{}`, true, "", ""},
		"bearer, not json":                  {models.AuthBearer, `{"token":`, true, "", ""},
		"bearer, partially decoded":         {models.AuthBearer, `{"token":"x","headers":123}`, true, "", ""},
		"bearer, empty token":               {models.AuthBearer, `{"token":""}`, true, "", ""},
		"bearer, token":                     {models.AuthBearer, `{"token":"sk"}`, false, "Authorization", "Bearer sk"},
		"bearer, value form":                {models.AuthBearer, `{"value":"Bearer sk"}`, false, "Authorization", "Bearer sk"},
		"header, no value":                  {models.AuthHeader, `{"header":"X-Token"}`, true, "", ""},
		"header, no name":                   {models.AuthHeader, `{"value":"v"}`, true, "", ""},
		"header, both":                      {models.AuthHeader, `{"header":"X-Token","value":"v"}`, false, "X-Token", "v"},
		"api_key, no value":                 {models.AuthAPIKey, `{"header":"X-Key"}`, true, "", ""},
		"api_key, default header":           {models.AuthAPIKey, `{"value":"k"}`, false, "X-API-Key", "k"},
		"api_key, token form":               {models.AuthAPIKey, `{"token":"k"}`, false, "X-API-Key", "k"},
		"custom, nothing":                   {models.AuthCustom, `{}`, true, "", ""},
		"custom, empty headers":             {models.AuthCustom, `{"headers":{}}`, true, "", ""},
		"custom, pair only":                 {models.AuthCustom, `{"header":"X-A","value":"1"}`, false, "X-A", "1"},
		"custom, headers":                   {models.AuthCustom, `{"headers":{"X-Whatever":"KEPT"}}`, false, "X-Whatever", "KEPT"},
		"custom, empty value still written": {models.AuthCustom, `{"headers":{"X-Foo":""}}`, false, "X-Foo", ""},
		"unknown type":                      {"kerberos", `{"token":"x"}`, true, "", ""},
		// PORM-139: an oauth set writes one bearer header from access_token
		// and nothing from a static-shaped blob left under the wrong type.
		"oauth, access token":       {models.AuthOAuth, `{"access_token":"at","refresh_token":"rt"}`, false, "Authorization", "Bearer at"},
		"oauth, client only":        {models.AuthOAuth, `{"client_id":"c","client_source":"supplied"}`, true, "", ""},
		"oauth, bearer-shaped blob": {models.AuthOAuth, `{"token":"sk"}`, true, "", ""},
		"oauth, not json":           {models.AuthOAuth, `{"access_token":`, true, "", ""},
		// PORM-27: a query credential writes no header at all, and a
		// header-shaped blob under the query kind has no param.
		"query, both":          {models.AuthQuery, `{"param":"api_key","value":"abcdefghijkl"}`, false, "", ""},
		"query, no param":      {models.AuthQuery, `{"value":"abcdefghijkl"}`, true, "", ""},
		"query, no value":      {models.AuthQuery, `{"param":"api_key"}`, true, "", ""},
		"query, header-shaped": {models.AuthQuery, `{"header":"X-Key","value":"abcdefghijkl"}`, true, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			raw := json.RawMessage(tc.raw)
			req, _ := http.NewRequest(http.MethodPost, "https://example.test/mcp", nil)
			req.Header.Set("Authorization", "Bearer virtual-key")
			err := ApplyAuth(req, tc.authType, raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ApplyAuth err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrNoCredential) {
				t.Fatalf("err=%v, want ErrNoCredential", err)
			}
			if got := req.Header.Get("Authorization"); tc.header != "Authorization" && got != "" {
				t.Fatalf("inbound Authorization survived: %q", got)
			}
			if tc.header != "" {
				if got, ok := req.Header[http.CanonicalHeaderKey(tc.header)]; !ok || got[0] != tc.value {
					t.Fatalf("header %s = %v, want %q", tc.header, got, tc.value)
				}
			} else if len(req.Header) != 0 {
				t.Fatalf("expected no headers written, got %v", req.Header)
			}
			if cerr := CheckCredential(tc.authType, raw); (cerr != nil) != tc.wantErr {
				t.Fatalf("CheckCredential err=%v disagrees with ApplyAuth (wantErr=%v)", cerr, tc.wantErr)
			}
		})
	}
}

// TestApplyAuthCustomOverrideIsDeterministic pins the write order a custom
// auth_config has always had: the header/value pair is Set after the headers
// map, so it wins when both name the same canonical header.
func TestApplyAuthCustomOverrideIsDeterministic(t *testing.T) {
	raw := json.RawMessage(`{"headers":{"x-api-key":"a"},"header":"X-Api-Key","value":"b"}`)
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://example.test/mcp", nil)
		if err := ApplyAuth(req, models.AuthCustom, raw); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Values("X-Api-Key"); len(got) != 1 || got[0] != "b" {
			t.Fatalf("iteration %d: X-Api-Key = %v, want [b]", i, got)
		}
	}
}

// TestLiterals is PORM-208 security requirements 1 and 5: the literal set
// is derived from the wire form of what wireFor writes, holds every
// piece an upstream may echo in its plain and encoded spellings, drops
// anything under redact.MinLiteralBytes, and never names the scheme word.
func TestLiterals(t *testing.T) {
	for name, tc := range map[string]struct {
		authType string
		raw      string
		want     []string // every entry must be in the set
		absent   []string // no entry may be in the set
		none     bool     // the set must be nil
	}{
		"bearer token":       {models.AuthBearer, `{"token":"abcdefghijkl"}`, []string{"abcdefghijkl"}, []string{"Bearer abcdefghijkl", "Bearer"}, false},
		"bearer value form":  {models.AuthBearer, `{"value":"Bearer abcdefghijkl"}`, []string{"abcdefghijkl"}, []string{"Bearer abcdefghijkl"}, false},
		"header labelled":    {models.AuthHeader, `{"header":"X-Token","value":"key=abcdefghijkl"}`, []string{"key=abcdefghijkl", "abcdefghijkl", "key%3Dabcdefghijkl", "key%3dabcdefghijkl"}, nil, false},
		"api_key value":      {models.AuthAPIKey, `{"value":"abcdefghijkl"}`, []string{"abcdefghijkl"}, nil, false},
		"api_key token":      {models.AuthAPIKey, `{"token":"abcdefghijkl"}`, []string{"abcdefghijkl"}, nil, false},
		"custom every value": {models.AuthCustom, `{"headers":{"X-Tenant":"acme-corp-europe"},"header":"X-Secret","value":"abcdefghijkl"}`, []string{"acme-corp-europe", "abcdefghijkl"}, nil, false},
		"oauth access token": {models.AuthOAuth, `{"access_token":"abcdefghijkl","refresh_token":"rt"}`, []string{"abcdefghijkl"}, []string{"Bearer abcdefghijkl"}, false},
		"none":               {models.AuthNone, ``, nil, nil, true},
		"seven bytes":        {models.AuthHeader, `{"header":"X-T","value":"abcdefg"}`, nil, nil, true},
		// A short bearer has no piece over the floor, so the whole wire
		// value is the literal: an echo with the scheme word is caught, an
		// echo of the bare token is left to the pattern rules.
		"seven-byte bearer": {models.AuthBearer, `{"token":"abcdefg"}`, []string{"Bearer abcdefg"}, []string{"abcdefg"}, false},
		"invalid raw":       {models.AuthBearer, `{"token":`, nil, nil, true},
		"padded value":      {models.AuthHeader, `{"header":"X-T","value":"\t abcdefghijkl \t"}`, []string{"abcdefghijkl"}, []string{"\t abcdefghijkl \t", " abcdefghijkl"}, false},
		"spaced, no long piece": {models.AuthHeader, `{"header":"X-T","value":"abcd efgh ijkl"}`,
			[]string{"abcd efgh ijkl", "efgh ijkl", "abcd+efgh+ijkl", "abcd%20efgh%20ijkl"}, []string{"abcd", "efgh", "ijkl"}, false},
		"scheme word, short pieces": {models.AuthHeader, `{"header":"Authorization","value":"Token abc1234 xyz9876"}`,
			[]string{"Token abc1234 xyz9876", "abc1234 xyz9876"}, []string{"abc1234", "xyz9876"}, false},
		"base64 bytes": {models.AuthBearer, `{"token":"ab+cd/ef=ghij"}`,
			[]string{"ab+cd/ef=ghij", "ab%2Bcd%2Fef%3Dghij", "ab%2bcd%2fef%3dghij", "ab+cd%2Fef=ghij", "ab+cd%2fef=ghij", "ab+cd/ef"}, []string{"ghij"}, false},
		// A piece under the floor gets no encoded spelling either, even
		// when the spelling would be long enough on its own.
		"short piece, long encoding": {models.AuthBearer, `{"token":"ab+/cd"}`,
			[]string{"Bearer ab+/cd"}, []string{"ab%2B%2Fcd", "ab%2b%2fcd", "ab+%2Fcd", "ab+%2fcd"}, false},
		"ampersand": {models.AuthHeader, `{"header":"X-T","value":"abc&defghijkl"}`,
			[]string{"abc&defghijkl", "abc&amp;defghijkl", "abc%26defghijkl", "defghijkl"}, nil, false},
		// PORM-27 security requirement 6: a query credential yields its
		// value, its encoded spellings and both wire pairs, never the name.
		"query value and pairs": {models.AuthQuery, `{"param":"api_key","value":"ab+cd/ef=ghij"}`,
			[]string{"ab+cd/ef=ghij", "ab%2Bcd%2Fef%3Dghij", "api_key=ab+cd/ef=ghij", "api_key=ab%2Bcd%2Fef%3Dghij", "api_key%3Dab%2Bcd%2Fef%3Dghij"},
			[]string{"api_key"}, false},
		// A short value is not a literal on its own, but the pair clears the
		// floor when the name is long enough.
		"query short value, long pair": {models.AuthQuery, `{"param":"api_key","value":"abc"}`,
			[]string{"api_key=abc", "api_key%3Dabc"}, []string{"abc", "api_key"}, false},
		"query pair under the floor": {models.AuthQuery, `{"param":"k","value":"abc"}`, nil, nil, true},
		"query long name never a literal": {models.AuthQuery, `{"param":"access_token","value":"abcdefghijkl"}`,
			[]string{"abcdefghijkl", "access_token=abcdefghijkl"}, []string{"access_token"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got := Literals(tc.authType, json.RawMessage(tc.raw))
			if tc.none {
				if got != nil {
					t.Fatalf("Literals = %q, want nil", got)
				}
				return
			}
			set := map[string]bool{}
			for i, l := range got {
				if len(l) < redact.MinLiteralBytes {
					t.Errorf("literal %q is under %d bytes", l, redact.MinLiteralBytes)
				}
				if set[l] {
					t.Errorf("literal %q appears twice", l)
				}
				set[l] = true
				if i > 0 && len(got[i-1]) < len(l) {
					t.Errorf("literals are not sorted longest first at %d: %q", i, got)
				}
			}
			for _, w := range tc.want {
				if !set[w] {
					t.Errorf("literal %q missing from %q", w, got)
				}
			}
			for _, a := range tc.absent {
				if set[a] {
					t.Errorf("literal %q present in %q", a, got)
				}
			}
		})
	}
}

// TestValidQueryParam pins PORM-27 security requirement 10: the parameter
// name is 1 to MaxQueryParamBytes bytes of [A-Za-z0-9._~-].
func TestValidQueryParam(t *testing.T) {
	for name, want := range map[string]bool{
		"":                                      false,
		"api_key":                               true,
		"x-y.z~w":                               true,
		"a b":                                   false,
		"a&b":                                   false,
		"a=b":                                   false,
		"a#b":                                   false,
		"a%20b":                                 false,
		strings.Repeat("a", MaxQueryParamBytes): true,
		strings.Repeat("a", MaxQueryParamBytes+1): false,
	} {
		if got := ValidQueryParam(name); got != want {
			t.Errorf("ValidQueryParam(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestWithQueryParam pins PORM-27 security requirement 4: every piece that
// names the parameter is dropped, in every spelling a lenient upstream
// parser could read as the name, every other piece keeps its bytes and
// order, and the credential is appended once, last.
func TestWithQueryParam(t *testing.T) {
	const pair = "api_key=abcdefghijkl"
	for name, tc := range map[string]struct{ in, want string }{
		"empty":                     {"", pair},
		"kept in order":             {"a=1&b=%20", "a=1&b=%20&" + pair},
		"repeated key":              {"api_key=old&a=1&api_key=old2", "a=1&" + pair},
		"percent-encoded key":       {"api%5Fkey=x&a=1", "a=1&" + pair},
		"case folded":               {"API_KEY=x&a=1", "a=1&" + pair},
		"no equals":                 {"api_key&a=1", "a=1&" + pair},
		"empty piece kept":          {"a=1&&b=2", "a=1&&b=2&" + pair},
		"semicolon sub-piece":       {"page=1;api_key=spoof&a=1", "a=1&" + pair},
		"undecodable escape":        {"api_key%zz=x&a=1", "a=1&" + pair},
		"nul padded":                {"api_key%00=x&a=1", "a=1&" + pair},
		"space padded":              {"api_key+=x&a=1", "a=1&" + pair},
		"prefix kept":               {"api_key2=x", "api_key2=x&" + pair},
		"every piece dropped":       {"api_key=x&API_KEY=y", pair},
		"already present, replaced": {"a=1&" + pair, "a=1&" + pair},
	} {
		t.Run(name, func(t *testing.T) {
			if got := withQueryParam(tc.in, "api_key", "abcdefghijkl"); got != tc.want {
				t.Fatalf("withQueryParam(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// A value needing encoding is escaped once, exactly as url.QueryEscape
	// spells it.
	if got := withQueryParam("", "api_key", "a+b/c=d&e"); got != "api_key=a%2Bb%2Fc%3Dd%26e" {
		t.Fatalf("encoded value: %q", got)
	}
}

// TestApplyAuthQueryAppendsParam pins PORM-27 security requirements 3 and
// 4 on a request: the stored URL's own parameters survive byte for byte, a
// same-named piece is replaced, the credential is the last piece, the
// inbound virtual key is gone and no credential header is written.
func TestApplyAuthQueryAppendsParam(t *testing.T) {
	raw := json.RawMessage(`{"param":"api_key","value":"ab+cd"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://example.test/mcp?a=1&api_key=old&b=%20", nil)
	req.Header.Set("Authorization", "Bearer virtual-key")
	if err := ApplyAuth(req, models.AuthQuery, raw); err != nil {
		t.Fatal(err)
	}
	if got := req.URL.RawQuery; got != "a=1&b=%20&api_key=ab%2Bcd" {
		t.Fatalf("RawQuery = %q", got)
	}
	if len(req.Header) != 0 {
		t.Fatalf("headers written: %v", req.Header)
	}
	if req.URL.ForceQuery {
		t.Fatal("ForceQuery left set")
	}
	// PORM-27: a second call gives the same request, because the drop
	// removes the pair the first call appended.
	if err := ApplyAuth(req, models.AuthQuery, raw); err != nil {
		t.Fatal(err)
	}
	if got := req.URL.RawQuery; got != "a=1&b=%20&api_key=ab%2Bcd" {
		t.Fatalf("second ApplyAuth changed the query: %q", got)
	}
	// A stored URL with an empty query and ForceQuery set serialises with
	// the pair alone.
	req, _ = http.NewRequest(http.MethodPost, "https://example.test/mcp?", nil)
	if err := ApplyAuth(req, models.AuthQuery, raw); err != nil {
		t.Fatal(err)
	}
	if got := req.URL.String(); got != "https://example.test/mcp?api_key=ab%2Bcd" {
		t.Fatalf("URL = %q", got)
	}
}

// TestApplyAuthQueryRefusesShape pins PORM-27 security requirement 10 at
// dial: a config the query kind cannot send is ErrNoCredential and the
// request is untouched.
func TestApplyAuthQueryRefusesShape(t *testing.T) {
	long := strings.Repeat("v", MaxQueryValueBytes+1)
	for name, raw := range map[string]string{
		"no param":      `{"value":"abcdefghijkl"}`,
		"no value":      `{"param":"api_key"}`,
		"space in name": `{"param":"a b","value":"abcdefghijkl"}`,
		"long value":    `{"param":"api_key","value":"` + long + `"}`,
		"header-shaped": `{"header":"X-Key","value":"abcdefghijkl"}`,
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "https://example.test/mcp?a=1", nil)
			err := ApplyAuth(req, models.AuthQuery, json.RawMessage(raw))
			if !errors.Is(err, ErrNoCredential) {
				t.Fatalf("err = %v, want ErrNoCredential", err)
			}
			if req.URL.RawQuery != "a=1" || len(req.Header) != 0 {
				t.Fatalf("request changed: %q %v", req.URL.RawQuery, req.Header)
			}
			if QueryParam(models.AuthQuery, json.RawMessage(raw)) != "" {
				t.Fatal("QueryParam named a parameter for an unusable config")
			}
		})
	}
	if got := QueryParam(models.AuthQuery, json.RawMessage(`{"param":"api_key","value":"abcdefghijkl"}`)); got != "api_key" {
		t.Fatalf("QueryParam = %q", got)
	}
	if got := QueryParam(models.AuthBearer, json.RawMessage(`{"token":"abcdefghijkl"}`)); got != "" {
		t.Fatalf("QueryParam for bearer = %q", got)
	}
}
