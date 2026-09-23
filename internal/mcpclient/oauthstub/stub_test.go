package oauthstub

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestOAuthStubFullFlow drives the stub the way PoryMCP will: challenge,
// metadata, registration, an approved authorization URL, the code exchange
// with PKCE, a proxied call with the access token, a refresh that rotates the
// refresh token, and a revoke.
func TestOAuthStubFullFlow(t *testing.T) {
	s := New(t)

	// 1. The resource refuses without a token and names its metadata.
	resp, err := http.Post(s.MCPURL(), "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("status %d challenge %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 2. Metadata.
	var as map[string]any
	getJSON(t, s.URL()+"/.well-known/oauth-authorization-server", &as)
	if as["issuer"] != s.URL() || as["token_endpoint"] != s.TokenEndpoint() {
		t.Fatalf("metadata %v", as)
	}

	// 3. Registration.
	reg, err := http.Post(s.URL()+"/register", "application/json", strings.NewReader(`{"redirect_uris":["https://pory.test/api/v1/oauth/callback"],"application_type":"web"}`))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&client)
	reg.Body.Close()
	if client.ClientID == "" || s.Registrations() != 1 {
		t.Fatalf("registration: %+v, count %d", client, s.Registrations())
	}

	// 4. Authorization URL, approved.
	verifier := "verifier-verifier-verifier-verifier-verifier-1"
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", client.ClientID)
	q.Set("redirect_uri", "https://pory.test/api/v1/oauth/callback")
	q.Set("state", "st")
	q.Set("code_challenge", S256(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.MCPURL())
	rd, err := s.Approve(s.URL() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(rd.Location)
	if loc.Query().Get("code") != rd.Code || loc.Query().Get("state") != "st" || loc.Query().Get("iss") != s.URL() {
		t.Fatalf("redirect %s", rd.Location)
	}

	// 5. Exchange with the wrong verifier, then the right one.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", rd.Code)
	form.Set("redirect_uri", "https://pory.test/api/v1/oauth/callback")
	form.Set("resource", s.MCPURL())
	form.Set("code_verifier", "wrong")
	req, _ := http.NewRequest(http.MethodPost, s.TokenEndpoint(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, client.ClientSecret)
	bad, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong verifier answered %d", bad.StatusCode)
	}
	// The code is single use: approve again for the real exchange.
	rd, err = s.Approve(s.URL() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	form.Set("code", rd.Code)
	form.Set("code_verifier", verifier)
	req, _ = http.NewRequest(http.MethodPost, s.TokenEndpoint(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, client.ClientSecret)
	good, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	_ = json.NewDecoder(good.Body).Decode(&tokens)
	good.Body.Close()
	if good.StatusCode != http.StatusOK || tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.ExpiresIn != 3600 || tokens.TokenType != "Bearer" {
		t.Fatalf("exchange: %d %+v", good.StatusCode, tokens)
	}

	// 6. A call with the token reaches tools/list.
	req, _ = http.NewRequest(http.MethodPost, s.MCPURL(), strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	ok, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("tools/list answered %d", ok.StatusCode)
	}

	// 7. Refresh rotates: the old refresh token is spent.
	form = url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tokens.RefreshToken)
	form.Set("client_id", client.ClientID)
	form.Set("client_secret", client.ClientSecret)
	rf, err := http.PostForm(s.TokenEndpoint(), form)
	if err != nil {
		t.Fatal(err)
	}
	var fresh struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(rf.Body).Decode(&fresh)
	rf.Body.Close()
	if rf.StatusCode != http.StatusOK || fresh.RefreshToken == tokens.RefreshToken || s.RefreshValid(tokens.RefreshToken) || !s.RefreshValid(fresh.RefreshToken) {
		t.Fatalf("refresh: %d old valid %v new %q", rf.StatusCode, s.RefreshValid(tokens.RefreshToken), fresh.RefreshToken)
	}
	if s.Grants("refresh_token") != 1 || s.Grants("authorization_code") != 2 {
		t.Fatalf("grants: refresh %d code %d", s.Grants("refresh_token"), s.Grants("authorization_code"))
	}

	// 8. Revoke counts.
	rv, err := http.PostForm(s.RevocationEndpoint(), url.Values{"token": {fresh.RefreshToken}})
	if err != nil {
		t.Fatal(err)
	}
	rv.Body.Close()
	if s.Revocations() != 1 {
		t.Fatalf("revocations %d", s.Revocations())
	}
}

func getJSON(t *testing.T, u string, into any) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatal(err)
	}
}
