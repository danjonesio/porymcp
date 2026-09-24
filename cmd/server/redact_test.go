package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// fragments is every 8-byte window of tok: a returned fragment of a
// credential is a leak as much as the whole is.
func fragments(tok string) []string {
	var out []string
	for i := 0; i+8 <= len(tok); i++ {
		out = append(out, tok[i:i+8])
	}
	return out
}

// getLog runs one GET /api/v1/logs/{id} with the admin key.
func (f *blockFixture) getLog(t *testing.T, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/v1/logs/"+id, nil)
	req.Header.Set("Authorization", "Bearer test-admin")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// TestLogsAPINeverReturnsTheUpstreamCredential is PORM-72 criterion 4, as
// amended in the plan to token-shaped credentials, and security requirement
// 6: for each static credential kind, an upstream that echoes the credential
// it was sent produces a row that GET /api/v1/logs?status=error and
// GET /api/v1/logs/{id} return with the credential replaced, and neither
// response body carries any 8-byte fragment of it. It goes in through the
// router that ships, as an operator's request would.
func TestLogsAPINeverReturnsTheUpstreamCredential(t *testing.T) {
	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`
	cases := []struct {
		name, authType, cred string
		cfg                  models.AuthConfig
	}{
		{"bearer", models.AuthBearer, "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", models.AuthConfig{Token: "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}},
		{"api_key", models.AuthAPIKey, "sk-proj-abcdefghij1234567890ABCD", models.AuthConfig{Value: "sk-proj-abcdefghij1234567890ABCD"}},
		{"header", models.AuthHeader, "k3y-2026-Ab12Cd34Ef56Gh78Ij90", models.AuthConfig{Header: "X-Vendor-Key", Value: "k3y-2026-Ab12Cd34Ef56Gh78Ij90"}},
		{"custom", models.AuthCustom, "deadbeef0123456789abcdef0123456789abcdef", models.AuthConfig{Headers: map[string]string{"X-Custom-Auth": "deadbeef0123456789abcdef0123456789abcdef"}, Header: "X-Custom-Auth", Value: "deadbeef0123456789abcdef0123456789abcdef"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBlockFixture(t, models.TargetUpstream, "", tc.authType, tc.cfg)
			rr := f.call(t, call)
			if rr.Code != http.StatusOK {
				t.Fatalf("tools/call: status %d, body %s", rr.Code, rr.Body.String())
			}
			if n := f.stub.hits.Load(); n == 0 {
				t.Fatal("the upstream saw no request, so nothing was echoed")
			}
			rows := f.waitRows(t, models.StatusError, 1)
			if len(rows) != 1 {
				t.Fatalf("%d error rows, want 1", len(rows))
			}
			row := rows[0]
			if row.ErrorMessage != "invalid token [redacted]" {
				t.Errorf("row error_message=%q, want \"invalid token [redacted]\"", row.ErrorMessage)
			}
			bodies := map[string]string{
				"GET /api/v1/logs?status=error": f.queryLogs(t, "status=error", "test-admin").Body.String(),
			}
			single := f.getLog(t, row.ID)
			if single.Code != http.StatusOK {
				t.Fatalf("GET /api/v1/logs/%s: status %d, body %s", row.ID, single.Code, single.Body.String())
			}
			bodies["GET /api/v1/logs/{id}"] = single.Body.String()
			for route, body := range bodies {
				if !strings.Contains(body, "[redacted]") {
					t.Errorf("%s: body carries no [redacted]: %s", route, body)
				}
				for _, needle := range append([]string{tc.cred}, fragments(tc.cred)...) {
					if strings.Contains(body, needle) {
						t.Errorf("%s: body carries %q of the credential: %s", route, needle, body)
						break
					}
				}
			}
		})
	}
}
