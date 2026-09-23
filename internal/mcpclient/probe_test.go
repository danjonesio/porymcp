package mcpclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// apiStub is a plain HTTP API for the probe: it records every request and
// answers with a scripted status, headers and body.
type apiStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	seen   []*http.Request
	status int
	header http.Header
	body   []byte
}

func newAPIStub(t *testing.T) *apiStub {
	t.Helper()
	s := &apiStub{status: http.StatusOK, header: http.Header{}, body: []byte(`{"login":"octocat"}`)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		r2 := r.Clone(context.Background())
		s.seen = append(s.seen, r2)
		status, header, body := s.status, s.header.Clone(), s.body
		s.mu.Unlock()
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *apiStub) requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.seen...)
}

func httpUpstream(base, testPath string) *models.Upstream {
	return &models.Upstream{
		ID: "22222222-2222-4222-8222-222222222222", Name: "API", Slug: "api1", Kind: models.KindHTTP,
		URL: base, TestPath: testPath, Transport: models.TransportStreamableHTTP,
		AuthType: models.AuthBearer, Enabled: true,
	}
}

var bearerAuth = json.RawMessage(`{"token":"secret-token-1"}`)

// TestHTTPProbe is the mcpclient half of the issue's TestHTTPProbe (PORM-146
// security requirement 12): one GET to the base joined with the test path,
// the credential on it, no initialize, and one closed sentence per outcome.
func TestHTTPProbe(t *testing.T) {
	c := New()
	ctx := context.Background()

	t.Run("200 is ok and sends exactly one GET with the credential", func(t *testing.T) {
		stub := newAPIStub(t)
		stub.header.Set("ETag", `"abc"`)
		d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", "/user"), bearerAuth)
		if !d.OK || d.Kind != models.KindHTTP || d.HTTPStatus != 200 || d.Error != "" {
			t.Fatalf("d = %+v", d)
		}
		if d.Tools == nil || len(d.Tools) != 0 || d.ToolCount != 0 || d.Era != "" || d.ServerInfo != nil {
			t.Fatalf("an http probe carries no catalogue: %+v", d)
		}
		reqs := stub.requests()
		if len(reqs) != 1 {
			t.Fatalf("%d requests, want 1", len(reqs))
		}
		r := reqs[0]
		if r.Method != http.MethodGet || r.URL.Path != "/v1/user" {
			t.Errorf("request was %s %s, want GET /v1/user", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token-1" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "*/*" {
			t.Errorf("Accept = %q, want */*", got)
		}
		if r.Header.Get("Mcp-Method") != "" || r.Header.Get("Mcp-Session-Id") != "" {
			t.Errorf("an MCP header on an http probe: %v", r.Header)
		}
		if d.LatencyMS < 0 {
			t.Errorf("latency %d", d.LatencyMS)
		}
	})

	statuses := map[int]string{
		401: "upstream rejected the credential (401)",
		403: "upstream rejected the credential (403)",
		404: "upstream answered 404; check the test path",
		500: "upstream answered 500",
		429: "upstream answered 429",
	}
	for status, want := range statuses {
		t.Run(want, func(t *testing.T) {
			stub := newAPIStub(t)
			stub.status = status
			d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", "/user"), bearerAuth)
			if d.OK || d.Error != want || d.HTTPStatus != status || d.Kind != models.KindHTTP {
				t.Fatalf("d = %+v, want error %q status %d", d, want, status)
			}
			if len(stub.requests()) != 1 {
				t.Fatalf("%d requests, want 1", len(stub.requests()))
			}
		})
	}

	t.Run("302 is a refused redirect naming only the host", func(t *testing.T) {
		stub := newAPIStub(t)
		stub.status = http.StatusFound
		stub.header.Set("Location", "https://elsewhere.example/login?code=SECRET_MARKER")
		d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", "/user"), bearerAuth)
		if d.OK || d.Error != "upstream redirected to elsewhere.example" {
			t.Fatalf("d = %+v", d)
		}
		if strings.Contains(d.Error, "SECRET_MARKER") {
			t.Fatalf("the Location's query reached the sentence: %q", d.Error)
		}
	})

	t.Run("a body past the drain cap is not an error and is closed", func(t *testing.T) {
		stub := newAPIStub(t)
		stub.body = make([]byte, 3<<20)
		d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", ""), bearerAuth)
		if !d.OK || d.HTTPStatus != 200 {
			t.Fatalf("d = %+v", d)
		}
		if p := stub.requests()[0].URL.Path; p != "/v1" {
			t.Errorf("an empty test path requests the base as stored, got %q", p)
		}
	})

	t.Run("a host-only base works with and without a test path", func(t *testing.T) {
		stub := newAPIStub(t)
		d := c.Probe(ctx, httpUpstream(stub.srv.URL, "/user"), bearerAuth)
		if !d.OK {
			t.Fatalf("d = %+v", d)
		}
		d = c.Probe(ctx, httpUpstream(stub.srv.URL, ""), bearerAuth)
		if !d.OK {
			t.Fatalf("d = %+v", d)
		}
		reqs := stub.requests()
		if reqs[0].URL.Path != "/user" || reqs[1].URL.Path != "/" {
			t.Errorf("paths %q %q, want /user and /", reqs[0].URL.Path, reqs[1].URL.Path)
		}
	})

	t.Run("a scheme-relative test path stays on the base host", func(t *testing.T) {
		stub := newAPIStub(t)
		d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", "//evil.example/x"), bearerAuth)
		if !d.OK {
			t.Fatalf("d = %+v", d)
		}
		if p := stub.requests()[0].URL.Path; p != "/v1/evil.example/x" {
			t.Errorf("path %q", p)
		}
	})

	t.Run("a base with a query or userinfo is refused before any request", func(t *testing.T) {
		stub := newAPIStub(t)
		for base, want := range map[string]string{
			stub.srv.URL + "/v1?key=x": "url must not carry a query string",
			strings.Replace(stub.srv.URL, "http://", "http://u:p@", 1) + "/v1": "url must not embed credentials",
		} {
			d := c.Probe(ctx, httpUpstream(base, "/user"), bearerAuth)
			if d.OK || d.Error != want || d.Kind != models.KindHTTP {
				t.Errorf("%s: d = %+v, want %q", base, d, want)
			}
		}
		if n := len(stub.requests()); n != 0 {
			t.Fatalf("%d requests went out on a refused base", n)
		}
	})

	t.Run("a bad test path is refused before any request", func(t *testing.T) {
		stub := newAPIStub(t)
		d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", "/a/../b"), bearerAuth)
		if d.OK || d.Error != "test_path must not contain a .. segment" {
			t.Fatalf("d = %+v", d)
		}
		if n := len(stub.requests()); n != 0 {
			t.Fatalf("%d requests went out on a refused test path", n)
		}
	})

	t.Run("a missing credential is refused before any request", func(t *testing.T) {
		stub := newAPIStub(t)
		d := c.Probe(ctx, httpUpstream(stub.srv.URL+"/v1", "/user"), nil)
		if d.OK || d.Error != errNeedsCredential {
			t.Fatalf("d = %+v", d)
		}
		if n := len(stub.requests()); n != 0 {
			t.Fatalf("%d requests went out with no credential", n)
		}
	})

	t.Run("an unreachable host is one closed sentence", func(t *testing.T) {
		stub := newAPIStub(t)
		base := stub.srv.URL + "/v1"
		stub.srv.Close()
		d := c.Probe(ctx, httpUpstream(base, "/user"), bearerAuth)
		if d.OK || !strings.HasPrefix(d.Error, "cannot connect to 127.0.0.1:") {
			t.Fatalf("d = %+v", d)
		}
	})
}

func TestFailedCarriesKind(t *testing.T) {
	d := Failed(models.KindHTTP, "stored credential cannot be decrypted")
	if d.Kind != models.KindHTTP || d.OK || d.Tools == nil || d.Error == "" {
		t.Fatalf("d = %+v", d)
	}
	raw, _ := json.Marshal(d)
	if !strings.Contains(string(raw), `"kind":"http"`) {
		t.Fatalf("kind absent from %s", raw)
	}
}
