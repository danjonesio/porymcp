package mcpclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
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
// is derived from the wire form of what headersFor writes, holds every
// piece an upstream may echo in its plain and encoded spellings, drops
// anything under MinLiteralBytes, and never names the scheme word.
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
		"ampersand": {models.AuthHeader, `{"header":"X-T","value":"abc&defghijkl"}`,
			[]string{"abc&defghijkl", "abc&amp;defghijkl", "abc%26defghijkl", "defghijkl"}, nil, false},
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
				if len(l) < MinLiteralBytes {
					t.Errorf("literal %q is under %d bytes", l, MinLiteralBytes)
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
