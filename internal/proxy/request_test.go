package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netcasklabs/porymcp/internal/models"
)

// The requests below all used to fall through peekRPC as ("", ""), which every
// check in ServeHTTP treats as a request carrying no tool, and were then
// forwarded verbatim to the first upstream with the real credential. Each test
// therefore asserts two things: the client is refused, and no upstream was
// contacted at all. Both key shapes are exercised, because the bypass did not
// need a group - on a single-upstream key it reached the upstream just as
// directly.

type namedFixture struct {
	name string
	f    *fixture
	// path is the absolute URL the probes are sent to. Empty means the shared
	// /mcp door, straight into the handler as most of the suite does; a member
	// endpoint has to go through the router, since which door was knocked on
	// is a property of the route.
	path string
}

// send is do or doPath, depending on which door this fixture stands at.
func (n namedFixture) send(method, rpc string) *httptest.ResponseRecorder {
	if n.path == "" {
		return n.f.do(method, rpc)
	}
	return n.f.doPath(method, n.path, rpc, nil)
}

func (n namedFixture) post(rpc string) *httptest.ResponseRecorder {
	return n.send(http.MethodPost, rpc)
}

// bypassFixtures builds the three key shapes a body can arrive at: one bound
// to a single upstream, one bound to a group whose tool_filter denies
// delete_repo, and one member endpoint of that same group. The parser runs
// before any of them is resolved, and it has to refuse the same bodies at all
// three doors — a member endpoint that parsed more leniently would forward a
// batch verbatim with the real credential, which is the bypass these rules
// exist to close.
func bypassFixtures(t *testing.T) []namedFixture {
	t.Helper()
	group := func() *fixture {
		return newGroupFixture(t, map[string][]string{
			"gh":   {"delete_repo"},
			"docs": {"search_docs"},
		}, json.RawMessage(`{"mode":"deny","tools":["delete_repo"]}`), nil, nil)
	}
	member := group()
	return []namedFixture{
		{name: "single", f: newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo", "safe_tool"}}, nil, nil)},
		{name: "group", f: group()},
		{name: "member", f: member, path: member.memberURL("gh")},
	}
}

// assertRejected pins the whole contract of a refused request: HTTP 400, the
// expected JSON-RPC code, a null id (the client's id is unusable - the body it
// arrived in never parsed), and an untouched set of upstreams.
func assertRejected(t *testing.T, f *fixture, rr *httptest.ResponseRecorder, wantCode int) string {
	t.Helper()
	if rr.Code != http.StatusBadRequest {
		t.Errorf("HTTP code=%d want 400; body=%s", rr.Code, rr.Body.String())
	}
	code, msg, id := rpcErrorOf(t, rr.Body.Bytes())
	if code != wantCode {
		t.Errorf("rpc code=%d want %d; body=%s", code, wantCode, rr.Body.String())
	}
	if id != nil {
		t.Errorf("id=%v want null; body=%s", id, rr.Body.String())
	}
	if !f.upstreamsIdle() {
		t.Errorf("rejected request reached an upstream; the credential was presented")
	}
	return msg
}

const batchBody = `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}]`

func TestBatchRequestRejected(t *testing.T) {
	for _, tc := range bypassFixtures(t) {
		t.Run(tc.name, func(t *testing.T) {
			msg := assertRejected(t, tc.f, tc.post(batchBody), codeInvalidRequest)
			if msg != "batch requests are not supported" {
				t.Errorf("message=%q", msg)
			}
		})
	}
}

func TestTrailingGarbageRejected(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}} {"x":1}`
	for _, tc := range bypassFixtures(t) {
		t.Run(tc.name, func(t *testing.T) {
			msg := assertRejected(t, tc.f, tc.post(body), codeParseError)
			if msg != "parse error" {
				t.Errorf("message=%q", msg)
			}
		})
	}
}

// forward replays the inbound HTTP method, so parsing that only ran on POST
// would leave DELETE as an open relay for the same bodies.
func TestBatchRejectedOnDeleteWithBody(t *testing.T) {
	for _, tc := range bypassFixtures(t) {
		t.Run(tc.name, func(t *testing.T) {
			assertRejected(t, tc.f, tc.send(http.MethodDelete, batchBody), codeInvalidRequest)
		})
	}
}

// rpcBody builds a request around a method name and lets json.Marshal do the
// escaping: what the proxy has to judge is the decoded method, not how it was
// spelled on the wire.
func rpcBody(method string) string {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  map[string]any{"name": "delete_repo"},
	})
	return string(b)
}

func TestMethodVariantsRejected(t *testing.T) {
	variants := []struct {
		name   string
		method string
	}{
		{"capitalised call", "Tools/Call"},
		{"upper call", "TOOLS/CALL"},
		{"trailing space", "tools/call "},
		{"leading space", " tools/call"},
		{"bom prefix", "\ufefftools/call"},
		{"nul suffix", "tools/call\x00"},
		{"upper list", "TOOLS/LIST"},
		{"capitalised list", "Tools/List"},
	}
	// One pair of fixtures for the whole table: a rejected request never
	// reaches an upstream, so the counters stay at zero across rows.
	fixtures := bypassFixtures(t)
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			for _, tc := range fixtures {
				t.Run(tc.name, func(t *testing.T) {
					assertRejected(t, tc.f, tc.post(rpcBody(v.method)), codeInvalidRequest)
				})
			}
		})
	}

	// The case rule covers exactly the two policy-relevant names. MCP's own
	// method set is mixed-case elsewhere, and rejecting those would break
	// honest clients.
	t.Run("mixed-case non-policy methods are forwarded", func(t *testing.T) {
		for _, method := range []string{"logging/setLevel", "sampling/createMessage"} {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, nil, nil)
			rr := f.post(`{"jsonrpc":"2.0","id":1,"method":"` + method + `"}`)
			if got := f.count("solo", method, ""); got != 1 {
				t.Errorf("upstream saw %d %s requests, want 1; proxy replied %d %s", got, method, rr.Code, rr.Body.String())
			}
		}
	})
}

// The gate judges one request and the upstream runs another when the body
// carries two spellings of one member name: Go binds the last match
// case-insensitively, a JavaScript or Python server looks the name up exactly,
// and the body is forwarded verbatim. Each probe below walks around a real
// rule — the key's denylist on the single shape, the group's tool_filter on
// the other — so a regression is a live bypass, not a lint failure.
func TestDuplicateEnvelopeKeysRejected(t *testing.T) {
	probes := []struct{ name, body string }{
		// Judged as tools/call safe_tool, executed as tools/call delete_repo.
		{"params and Params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"},"Params":{"name":"safe_tool"}}`},
		// Judged as ping, which takes the key-lists-only arm and never applies
		// the group's filter; executed as tools/call delete_repo.
		{"method and Method", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"delete_repo"}}`},
		// Same divergence one level down, inside params.
		{"name and Name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo","Name":"safe_tool"}}`},
	}
	// Not bypassFixtures: both shapes need a rule that refuses delete_repo,
	// because what these probes walk around is the rule, not the parser.
	fixtures := duplicateKeyFixtures(t)
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			for _, tc := range fixtures {
				t.Run(tc.name, func(t *testing.T) {
					msg := assertRejected(t, tc.f, tc.post(p.body), codeInvalidRequest)
					if msg != "invalid request" {
						t.Errorf("message=%q", msg)
					}
				})
			}
		})
	}

	// Positive control on fresh fixtures with the same policies: without it,
	// the zero-upstream assertion above would also pass on a proxy that
	// refused everything.
	t.Run("a permitted call still reaches its upstream", func(t *testing.T) {
		for _, tc := range duplicateKeyFixtures(t) {
			t.Run(tc.name, func(t *testing.T) {
				// call is what the client sends and tool is what the upstream
				// runs. They differ on the group's endpoint, where every tool is
				// advertised as its identity and the proxy rewrites the name
				// back before forwarding.
				slug, tool, call := "solo", "safe_tool", "safe_tool"
				if tc.name == "group" {
					slug, tool, call = "docs", "search_docs", "docs__search_docs"
				}
				rr := tc.post(toolCall("1", call))
				if got := tc.f.count(slug, "tools/call", tool); got != 1 {
					t.Errorf("upstream %s saw %d calls to %s, want 1; proxy replied %d %s",
						slug, got, tool, rr.Code, rr.Body.String())
				}
			})
		}
	})
}

// duplicateKeyFixtures is bypassFixtures with a denylist on the single-upstream
// key as well, so delete_repo is refused on both key shapes.
func duplicateKeyFixtures(t *testing.T) []namedFixture {
	t.Helper()
	return []namedFixture{
		{name: "single", f: newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo", "safe_tool"}}, nil, []string{"delete_repo"})},
		{name: "group", f: newGroupFixture(t, map[string][]string{
			"gh":   {"delete_repo"},
			"docs": {"search_docs"},
		}, json.RawMessage(`{"mode":"deny","tools":["delete_repo"]}`), nil, nil)},
	}
}

func TestNonScalarIDRejected(t *testing.T) {
	fixtures := bypassFixtures(t)
	for _, id := range []string{`{"a":1}`, `[1]`, `true`} {
		t.Run("id="+id, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"delete_repo"}}`
			for _, tc := range fixtures {
				t.Run(tc.name, func(t *testing.T) {
					assertRejected(t, tc.f, tc.post(body), codeInvalidRequest)
				})
			}
		})
	}

	// The three shapes JSON-RPC allows must still get through untouched.
	for _, id := range []string{`"abc"`, `7`, `null`} {
		t.Run("accepted id="+id, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, nil, nil)
			rr := f.post(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"safe_tool"}}`)
			if rr.Code != http.StatusOK {
				t.Errorf("code=%d body=%s", rr.Code, rr.Body.String())
			}
			if got := f.count("solo", "tools/call", "safe_tool"); got != 1 {
				t.Errorf("upstream saw %d calls, want 1", got)
			}
		})
	}
}

// A client correlates a reply by its id. Round-tripping the id through any
// would round 9007199254740993 down to ...992 and invent an id for a request
// that carried none, so the envelope is built from the raw bytes.
func TestErrorEnvelopeEchoesRawID(t *testing.T) {
	cases := []struct {
		name string
		id   json.RawMessage
		want string
	}{
		{"int64 beyond float64 precision", json.RawMessage(`9007199254740993`), `"id":9007199254740993`},
		{"string", json.RawMessage(`"x"`), `"id":"x"`},
		{"absent", nil, `"id":null`},
		{"explicit null", json.RawMessage(`null`), `"id":null`},
		{"non-scalar falls back to null", json.RawMessage(`{"a":1}`), `"id":null`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeRPCError(rr, http.StatusBadRequest, c.id, codeInvalidRequest, "invalid request")
			if !strings.Contains(rr.Body.String(), c.want) {
				t.Errorf("body=%s want it to contain %s", rr.Body.String(), c.want)
			}
			if got := rr.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("content-type=%q", got)
			}
			code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
			if code != codeInvalidRequest || msg != "invalid request" {
				t.Errorf("code=%d msg=%q", code, msg)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantCode   int // 0 = accepted
		wantMethod string
	}{
		{"empty body", "", 0, ""},
		{"whitespace only", "  \n\t", 0, ""},
		{"tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`, 0, "tools/call"},
		{"tools/list", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 0, "tools/list"},
		{"notification without id", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 0, "notifications/initialized"},

		{"batch array", batchBody, codeInvalidRequest, ""},
		{"batch after whitespace", "  \n[]", codeInvalidRequest, ""},
		{"trailing garbage", `{"jsonrpc":"2.0","id":1,"method":"ping"} {"x":1}`, codeParseError, ""},
		{"not json at all", `hello`, codeParseError, ""},
		{"bom before the envelope", "\ufeff{\"method\":\"ping\"}", codeParseError, ""},
		{"truncated json", `{"method":"ping"`, codeParseError, ""},

		{"object id", `{"id":{"a":1},"method":"ping"}`, codeInvalidRequest, "ping"},
		{"array id", `{"id":[1],"method":"ping"}`, codeInvalidRequest, "ping"},
		{"bool id", `{"id":true,"method":"ping"}`, codeInvalidRequest, "ping"},
		{"string id", `{"id":"abc","method":"ping"}`, 0, "ping"},
		{"negative id", `{"id":-3,"method":"ping"}`, 0, "ping"},
		{"int64 id", `{"id":9007199254740993,"method":"ping"}`, 0, "ping"},
		{"null id", `{"id":null,"method":"ping"}`, 0, "ping"},
		{"absent id", `{"method":"ping"}`, 0, "ping"},

		{"nul in method", `{"id":1,"method":"tools/call\u0000"}`, codeInvalidRequest, "tools/call\x00"},
		{"del in method", `{"id":1,"method":"tools/call\u007f"}`, codeInvalidRequest, "tools/call\x7f"},
		{"newline in method", `{"id":1,"method":"ping\n"}`, codeInvalidRequest, "ping\n"},
		{"trailing space", `{"id":1,"method":"tools/call "}`, codeInvalidRequest, "tools/call "},
		{"leading space", `{"id":1,"method":" tools/call"}`, codeInvalidRequest, " tools/call"},
		{"bom in method", `{"id":1,"method":"\ufefftools/call"}`, codeInvalidRequest, "\ufefftools/call"},
		{"capitalised tools/call", `{"id":1,"method":"Tools/Call"}`, codeInvalidRequest, "Tools/Call"},
		{"upper tools/list", `{"id":1,"method":"TOOLS/LIST"}`, codeInvalidRequest, "TOOLS/LIST"},

		// Two spellings of one member name: Go binds the last, an upstream
		// binds the one it looks for. The method recorded on the audit row is
		// the one Go bound, which is the one the operator can act on.
		{"method and Method", `{"id":1,"method":"ping","Method":"pong"}`, codeInvalidRequest, "pong"},
		{"params and Params", `{"id":1,"method":"tools/call","params":{"name":"a"},"Params":{"name":"b"}}`, codeInvalidRequest, "tools/call"},
		{"name and Name inside params", `{"id":1,"method":"tools/call","params":{"name":"a","Name":"b"}}`, codeInvalidRequest, "tools/call"},
		// Not the divergence — every decoder takes the last one — but folding
		// the name catches it as well, and no honest client sends it.
		{"same-case duplicate", `{"id":1,"method":"ping","method":"pong"}`, codeInvalidRequest, "pong"},
		// A non-object has no member names to bind, and arguments are
		// forwarded verbatim rather than bound, so neither is checked.
		{"array params", `{"id":1,"method":"ping","params":[1,2]}`, 0, "ping"},
		{"duplicate inside arguments", `{"id":1,"method":"tools/call","params":{"name":"x","arguments":{"n":1,"N":2}}}`, 0, "tools/call"},

		// Case-checking is scoped to the two names policy and routing have to
		// agree on; MCP's other methods are legitimately mixed-case.
		{"logging/setLevel", `{"id":1,"method":"logging/setLevel"}`, 0, "logging/setLevel"},
		{"sampling/createMessage", `{"id":1,"method":"sampling/createMessage"}`, 0, "sampling/createMessage"},
		{"unknown vendor method", `{"id":1,"method":"vendor/Thing"}`, 0, "vendor/Thing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, rpcErr := parseRequest([]byte(c.body))
			switch {
			case c.wantCode == 0 && rpcErr != nil:
				t.Fatalf("rejected with %d %q, want accepted", rpcErr.Code, rpcErr.Message)
			case c.wantCode != 0 && rpcErr == nil:
				t.Fatalf("accepted, want rejection with code %d", c.wantCode)
			case c.wantCode != 0 && rpcErr.Code != c.wantCode:
				t.Fatalf("code=%d %q, want %d", rpcErr.Code, rpcErr.Message, c.wantCode)
			}
			if req.Method != c.wantMethod {
				t.Errorf("method=%q want %q (the audit row records this)", req.Method, c.wantMethod)
			}
		})
	}

	// The leading-'[' check only improves the message: json.Unmarshal into an
	// rpcRequest already refuses an array. Pinning that here means a refactor
	// which drops the fast path cannot quietly reopen the batch bypass.
	t.Run("plain unmarshal also refuses an array", func(t *testing.T) {
		var req rpcRequest
		if err := json.Unmarshal([]byte(batchBody), &req); err == nil {
			t.Fatal("json.Unmarshal accepted a batch array into rpcRequest")
		}
	})
}

func TestParseRejectionIsAudited(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo"}}, nil, nil)
	f.post(batchBody)
	got := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
	if got.ErrorMessage != "batch requests are not supported" {
		t.Errorf("error_message=%q", got.ErrorMessage)
	}
	if got.Status != models.StatusError {
		t.Errorf("status=%q", got.Status)
	}
	// Nothing decoded, so there is no JSON-RPC method to record: the row keeps
	// the HTTP verb, as the pre-parse rejections above it do.
	if got.Method != http.MethodPost {
		t.Errorf("method=%q want %q", got.Method, http.MethodPost)
	}
	if got.VirtualKeyID != "a1" {
		t.Errorf("virtual_key_id=%q", got.VirtualKeyID)
	}
}

// A rejection that did decode records the method the client claimed, which is
// what makes a spelling variant visible to an operator reading the log.
func TestMethodVariantRejectionAuditsTheClaimedMethod(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo"}}, nil, nil)
	f.post(rpcBody("Tools/Call"))
	got := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
	if got.Method != "Tools/Call" || got.ErrorMessage != "invalid request" {
		t.Errorf("audit row=%+v", got)
	}
}
