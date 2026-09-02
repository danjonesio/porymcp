package mcpclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/netcasklabs/porymcp/internal/models"
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
