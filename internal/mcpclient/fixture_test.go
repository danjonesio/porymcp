package mcpclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// The fixture is a real MCP server as the reference implementations behave,
// not as a hand-written stub would: it MINTS A SESSION and refuses anything
// but initialize without it, and it answers in SSE FRAMING. Both are the
// defaults because both are what @modelcontextprotocol/server-everything does,
// and a JSON-only, session-less fixture is how a discovery client comes to
// work against tests and fail against every real server.
type fixture struct {
	t   *testing.T
	srv *httptest.Server

	mu   sync.Mutex
	seen []request

	// sessionID is the id initialize hands back. Empty makes the server
	// stateless: no header, and nothing to DELETE.
	sessionID string
	// protocol is the version initialize negotiates. Every later request has
	// to declare this one, not the one PoryMCP asked for.
	protocol      string
	serverName    string
	serverVersion string
	// framing is how a result is wrapped: "sse", "json", or "none" for an SSE
	// body sent with no Content-Type at all, which real servers do.
	framing string
	// noisy puts the server's own JSON-RPC notifications on the stream BEFORE
	// the answer to the POST, which the Streamable HTTP transport allows and
	// the reference servers do: a client that reads only the first event sees
	// a notification and calls a working server broken.
	noisy        bool
	deleteStatus int
	tools        []map[string]any
	pageSize     int
	// canary answers EVERY request with a marker in every channel a byte
	// could escape through. See TestDiscoverNeverEchoesUpstreamBytes.
	canary bool
	// on takes over the answer for one JSON-RPC method, or for "DELETE".
	on map[string]func(w http.ResponseWriter, rq request)
}

// request is what the fixture recorded about one call.
type request struct {
	Method   string // the HTTP verb
	Path     string
	RawQuery string
	RPC      string // the JSON-RPC method, "" for a request with no body
	HasID    bool
	Cursor   string
	Session  string
	Protocol string
	Accept   string
	Header   http.Header
}

const (
	fixtureSession  = "sess-a1b2c3"
	fixtureProtocol = "2025-06-18"
)

func newFixture(t *testing.T, opts ...func(*fixture)) *fixture {
	t.Helper()
	f := &fixture{
		t:             t,
		sessionID:     fixtureSession,
		protocol:      fixtureProtocol,
		serverName:    "fixture-everything",
		serverVersion: "1.2.3",
		framing:       "sse",
		deleteStatus:  http.StatusMethodNotAllowed, // a normal answer; plenty of servers do this
		tools: []map[string]any{
			{"name": "echo", "description": "Echoes back the input string"},
			{"name": "add", "title": "Add", "description": "Adds two numbers"},
		},
		on: map[string]func(http.ResponseWriter, request){},
	}
	for _, opt := range opts {
		opt(f)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// upstream is the fixture as an operator would have configured it.
func (f *fixture) upstream() *models.Upstream {
	return &models.Upstream{
		ID:        "11111111-1111-4111-8111-111111111111",
		Name:      "Docs",
		Slug:      "docs",
		URL:       f.srv.URL + "/mcp",
		Transport: models.TransportStreamableHTTP,
		AuthType:  models.AuthNone,
		Enabled:   true,
	}
}

func (f *fixture) requests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.seen...)
}

// rpcCalls is the JSON-RPC methods seen, in order, with a DELETE recorded as
// "DELETE" so a whole handshake reads as one slice.
func (f *fixture) rpcCalls() []string {
	out := []string{}
	for _, r := range f.requests() {
		if r.Method == http.MethodDelete {
			out = append(out, "DELETE")
			continue
		}
		out = append(out, r.RPC)
	}
	return out
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	rq := request{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Session:  r.Header.Get("Mcp-Session-Id"),
		Protocol: r.Header.Get("MCP-Protocol-Version"),
		Accept:   r.Header.Get("Accept"),
		Header:   r.Header.Clone(),
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) > 0 {
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &probe)
		rq.RPC = probe.Method
		rq.HasID = len(probe.ID) > 0
		rq.Cursor = probe.Params.Cursor
	}
	f.mu.Lock()
	f.seen = append(f.seen, rq)
	f.mu.Unlock()

	if f.canary {
		writeCanary(w)
		return
	}
	key := rq.RPC
	if r.Method == http.MethodDelete {
		key = "DELETE"
	}
	if hook := f.on[key]; hook != nil {
		hook(w, rq)
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(f.deleteStatus)
		return
	}
	// The session gate: everything but initialize needs the id initialize
	// minted, which is what makes a client that skips the handshake fail here
	// the way it would against a real server.
	if f.sessionID != "" && rq.RPC != "initialize" && rq.Session != f.sessionID {
		f.writeRPCError(w, http.StatusBadRequest, -32000, "Bad Request: Server not initialized")
		return
	}

	switch rq.RPC {
	case "initialize":
		if f.sessionID != "" {
			w.Header().Set("Mcp-Session-Id", f.sessionID)
		}
		f.writeResult(w, map[string]any{
			"protocolVersion": f.protocol,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": f.serverName, "version": f.serverVersion},
		})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		f.writeResult(w, f.page(rq.Cursor))
	default:
		f.writeRPCError(w, http.StatusBadRequest, -32601, "Method not found")
	}
}

// page slices the catalogue the way a paging server would, with a cursor that
// is just the index of the next tool.
func (f *fixture) page(cursor string) map[string]any {
	start := 0
	if cursor != "" {
		_, _ = fmt.Sscanf(cursor, "p%d", &start)
	}
	size := f.pageSize
	if size <= 0 {
		size = len(f.tools)
	}
	end := min(start+size, len(f.tools))
	// Made with a length so an empty catalogue marshals as [] and not null.
	page := append([]map[string]any{}, f.tools[min(start, len(f.tools)):end]...)
	out := map[string]any{"tools": page}
	if end < len(f.tools) {
		out["nextCursor"] = fmt.Sprintf("p%d", end)
	}
	return out
}

// Errorf and a 500, never Fatalf: these run on the SERVER's goroutine, and
// t.Fatal outside the test goroutine Goexits the wrong one, the test then
// hangs until the package timeout instead of printing a line.
func (f *fixture) writeResult(w http.ResponseWriter, result any) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	if err != nil {
		f.t.Errorf("fixture could not marshal its own result: %v", err)
		http.Error(w, "fixture error", http.StatusInternalServerError)
		return
	}
	f.writeFramed(w, http.StatusOK, body)
}

func (f *fixture) writeRPCError(w http.ResponseWriter, status, code int, message string) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"error": map[string]any{"code": code, "message": message},
	})
	if err != nil {
		f.t.Errorf("fixture could not marshal its own error: %v", err)
		http.Error(w, "fixture error", http.StatusInternalServerError)
		return
	}
	f.writeFramed(w, status, body)
}

// writeFramed wraps a JSON-RPC document the way this fixture's framing says.
func (f *fixture) writeFramed(w http.ResponseWriter, status int, body []byte) {
	switch f.framing {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	case "none":
		// A nil value suppresses net/http's own Content-Type sniffing, which
		// is the only way to reproduce a server that sends none at all.
		w.Header()["Content-Type"] = nil
		w.WriteHeader(status)
		_, _ = w.Write(f.stream(body))
	default:
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(status)
		_, _ = w.Write(f.stream(body))
	}
}

// stream is the event stream one answer goes out as: the answer alone, or
// (when the fixture is noisy) the notifications a real server sends first.
func (f *fixture) stream(body []byte) []byte {
	if !f.noisy {
		return sseFrame(body)
	}
	out := sseFrame([]byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","logger":"NOISE_LOGGER","data":"NOISE_MARKER"}}`))
	out = append(out, sseFrame([]byte(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"NOISE_TOKEN","progress":1,"total":2}}`))...)
	return append(out, sseFrame(body)...)
}

func sseFrame(body []byte) []byte {
	return []byte("event: message\ndata: " + string(body) + "\n\n")
}

// The canary markers, one per channel an upstream byte could travel in.
var canaries = []string{
	"CANARY_HDR", "CANARY_COOKIE", "CANARY_LOC", "CANARY_QUERY", "CANARY_POWERED",
	"CANARY_CHARSET", "CANARY_SESSION", "CANARY_BODY", "CANARY_COMMENT",
}

func writeCanary(w http.ResponseWriter) {
	h := w.Header()
	h.Set("WWW-Authenticate", `Bearer realm="CANARY_HDR", error="invalid_token"`)
	h.Set("Set-Cookie", "sess=CANARY_COOKIE; Path=/")
	h.Set("Location", "https://evil.example/CANARY_LOC?code=CANARY_QUERY")
	h.Set("X-Powered-By", "CANARY_POWERED")
	h.Set("Content-Type", "text/html; charset=CANARY_CHARSET")
	h.Set("Mcp-Session-Id", "CANARY_SESSION")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("<html>CANARY_BODY <!-- CANARY_COMMENT --></html>"))
}

// withUserinfo returns the fixture's URL dressed the way a hosted MCP server's
// really is: a credential in the userinfo AND one in the query string, which
// is where Go's own redaction stops helping.
func (f *fixture) withUserinfo(user, password, query string) string {
	f.t.Helper()
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	u.User = url.UserPassword(user, password)
	u.Path = "/mcp"
	u.RawQuery = query
	return u.String()
}

// discover runs one discovery against the fixture with the default client.
func discover(t *testing.T, up *models.Upstream, auth json.RawMessage) Discovery {
	t.Helper()
	return New().Discover(t.Context(), up, auth)
}

// marshal renders a Discovery exactly as the management API would, so a leak
// assertion covers every field including the ones a test forgot to name.
func marshal(t *testing.T, d Discovery) string {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Discovery does not marshal: %v", err)
	}
	return string(b)
}

// absent fails when any needle survived into the rendered Discovery.
func absent(t *testing.T, rendered string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(rendered, n) {
			t.Errorf("%q reached the response: %s", n, rendered)
		}
	}
}

// countingTransport answers nothing and counts what it was asked to send. It
// is how "made no request at all" is asserted, since a server that is never
// dialled cannot testify to that itself.
type countingTransport struct {
	mu  sync.Mutex
	n   int
	err error
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	err := c.err
	if err == nil {
		err = fmt.Errorf("countingTransport refuses every request")
	}
	return nil, err
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// clientWith returns a discovery client whose transport is the caller's, so a
// test can assert on requests that never leave or hand back a crafted error.
func clientWith(tr http.RoundTripper) *Client {
	c := New()
	c.http.Transport = tr
	return c
}
