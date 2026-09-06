package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// PORM-30. The proxy endpoints answer POST, DELETE and OPTIONS. Every other
// verb chi routes is refused 405 in serve, after the CORS block and the host
// check and before the key is read, with Allow naming the verbs that work,
// and nothing is forwarded or audited for it. Acceptance criteria 1, 2, 3 and
// 5 of the issue and security requirements 1 to 9 of the plan live here.
//
// The tests that aim at the member route use a group fixture with one member:
// a member path under a single-upstream key is a 404 before any dispatch, so
// "no upstream request" would hold there for the wrong reason. On a group
// key an empty-body GET is not aggregated and forwards to the first member,
// which is what the before-run of these tests shows.

// wantAllow is the Allow value pinned here as a literal rather than through
// the constant in proxy.go, so a change to the constant fails a test.
const wantAllow = "POST, DELETE, OPTIONS"

// assert405 pins the whole client-facing contract of a refused verb: the
// status, the Allow header RFC 9110 requires on a 405, the no-store the top of
// serve writes (the branch sits below it, and this is what stops a refactor
// lifting it above), the JSON-RPC envelope every proxy refusal uses with a
// null id, and not a single upstream request.
func assert405(t *testing.T, f *fixture, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("HTTP code=%d want 405; body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Allow"); got != wantAllow {
		t.Errorf("Allow=%q want %q", got, wantAllow)
	}
	if vs := rr.Header().Values("Cache-Control"); len(vs) != 1 || vs[0] != "no-store" {
		t.Errorf("Cache-Control=%q want exactly [no-store]", vs)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type=%q want application/json", ct)
	}
	code, msg, id := rpcErrorOf(t, rr.Body.Bytes())
	if code != -32000 || msg != "method not allowed" || id != nil {
		t.Errorf("rpc error code=%d message=%q id=%v want -32000 %q null", code, msg, id, "method not allowed")
	}
	if !f.upstreamsIdle() {
		t.Error("a refused verb reached an upstream: the credential was presented for a request the proxy does not relay")
	}
}

// Acceptance criteria 1 and 2; security requirements 1, 5 and 6. The same
// refusal on all three routes, with a body, and with an Origin.
func TestGetOnProxyReturns405(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"solo": {"ping_tool"}}, nil, nil, nil)
	for _, tc := range []struct {
		name   string
		send   func() *httptest.ResponseRecorder
		origin bool
	}{
		{"shared door", func() *httptest.ResponseRecorder { return f.do(http.MethodGet, "") }, false},
		{"key route", func() *httptest.ResponseRecorder { return f.doPath(http.MethodGet, f.keyURL(), "", nil) }, false},
		{"member route", func() *httptest.ResponseRecorder { return f.doPath(http.MethodGet, f.memberURL("solo"), "", nil) }, false},
		{"with a body", func() *httptest.ResponseRecorder {
			return f.doPath(http.MethodGet, f.keyURL(), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
		}, false},
		{"with Origin", func() *httptest.ResponseRecorder {
			return f.doPath(http.MethodGet, f.keyURL(), "", map[string]string{"Origin": "https://claude.ai"})
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			rr := tc.send()
			elapsed := time.Since(start)
			assert405(t, f, rr)
			if tc.origin {
				// Pins the CORS block's presence on a refusal: the branch sits
				// below applyCORS. Not the duplication header_test.go guards;
				// the 405 path relays nothing, so it cannot double the header.
				if vs := rr.Header().Values("Access-Control-Allow-Origin"); len(vs) != 1 || vs[0] != "https://claude.ai" {
					t.Errorf("Access-Control-Allow-Origin=%q want exactly [https://claude.ai]", vs)
				}
			}
			// Acceptance criterion 1's budget, some 600 times under the 60 s
			// stall it guards, measured around the handler call alone. The
			// assertions that catch a regression to forwarding at once are the
			// status and upstreamsIdle above; this one is the criterion's
			// letter, and last so a slow runner still reports the substance.
			if elapsed > 100*time.Millisecond {
				t.Errorf("the refusal took %v, want under 100ms", elapsed)
			}
		})
	}
}

// Security requirement 2. The refusal is written before the key is read, so
// it is the same answer with a valid key, a wrong one and none: a GET cannot
// tell a caller whether a key is live.
func TestGetNeedsNoKey(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"solo": {"ping_tool"}}, nil, nil, nil)
	keyed := f.doPath(http.MethodGet, f.keyURL(), "", nil)
	assert405(t, f, keyed)
	for _, tc := range []struct {
		name string
		rr   *httptest.ResponseRecorder
	}{
		{"no Authorization", f.doPathNoAuth(http.MethodGet, f.keyURL(), "", nil)},
		{"wrong bearer", f.doPath(http.MethodGet, f.keyURL(), "", map[string]string{"Authorization": "Bearer wrong"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert405(t, f, tc.rr)
			if tc.rr.Body.String() != keyed.Body.String() {
				t.Errorf("body=%s differs from the keyed refusal %s", tc.rr.Body.String(), keyed.Body.String())
			}
			if got, want := tc.rr.Header().Get("Allow"), keyed.Header().Get("Allow"); got != want {
				t.Errorf("Allow=%q differs from the keyed refusal %q", got, want)
			}
		})
	}
}

// Acceptance criterion 5; security requirement 3. A refused GET writes no
// audit row at all. The barrier is a POST that does write one: the audit
// logger is one consumer goroutine over a FIFO channel, so a row the GET had
// enqueued would land before the POST's, and the Logs filter cannot select an
// empty method, so the test lists every row and inspects it.
func TestGetWritesNoAuditRow(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
	assert405(t, f, f.doPath(http.MethodGet, f.keyURL(), "", nil))
	f.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	f.waitAudit(models.LogFilter{Method: "initialize"})
	rows := f.waitAudit(models.LogFilter{})
	if len(rows) != 1 || rows[0].Method != "initialize" {
		t.Fatalf("audit rows=%+v want exactly the initialize row: a refused verb is not something an agent did", rows)
	}
}

// Security requirement 1 on the verbs the issue names as edge cases. These
// are chi-routed verbs on purpose: a token outside chi's method map never
// reaches the handler and gets the router's bare 405 instead. No body
// assertion, because the recorder keeps a body the real server discards on a
// HEAD response.
func TestUnsupportedVerbsReturn405(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"solo": {"ping_tool"}}, nil, nil, nil)
	for _, verb := range []string{http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodTrace} {
		t.Run(verb, func(t *testing.T) {
			rr := f.doPath(verb, f.memberURL("solo"), "", nil)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("HTTP code=%d want 405", rr.Code)
			}
			if got := rr.Header().Get("Allow"); got != wantAllow {
				t.Errorf("Allow=%q want %q", got, wantAllow)
			}
			if !f.upstreamsIdle() {
				t.Errorf("%s reached an upstream", verb)
			}
		})
	}
}

// Security requirement 7. OPTIONS still short-circuits in applyCORS, the
// preflight's method list no longer names GET, the header list still names
// Last-Event-ID (the preflight's header check is what a browser's GET has to
// pass), and the 204 carries Allow whether or not an Origin was sent.
func TestOptionsStillPreflights(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
	t.Run("with Origin", func(t *testing.T) {
		rr := f.doPath(http.MethodOptions, f.keyURL(), "", map[string]string{"Origin": "https://claude.ai"})
		if rr.Code != http.StatusNoContent {
			t.Fatalf("HTTP code=%d want 204; body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Access-Control-Allow-Methods"); got != wantAllow {
			t.Errorf("Access-Control-Allow-Methods=%q want %q", got, wantAllow)
		}
		if got := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Last-Event-ID") {
			t.Errorf("Access-Control-Allow-Headers=%q no longer names Last-Event-ID", got)
		}
		if got := rr.Header().Get("Allow"); got != wantAllow {
			t.Errorf("Allow=%q want %q on the OPTIONS 204", got, wantAllow)
		}
		if !f.upstreamsIdle() {
			t.Error("a preflight reached an upstream")
		}
	})
	t.Run("without Origin", func(t *testing.T) {
		rr := f.doPathNoAuth(http.MethodOptions, f.keyURL(), "", nil)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("HTTP code=%d want 204; body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Allow"); got != wantAllow {
			t.Errorf("Allow=%q want %q on the OPTIONS 204", got, wantAllow)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin=%q on a request with no Origin", got)
		}
	})
}

// Acceptance criterion 3; security requirement 9. An empty-body DELETE is a
// session teardown and still reaches the upstream as a DELETE carrying the
// session id, on the shared door and on the key route. The member route's arm
// is TestPerUpstreamDeleteForwardsSession. Each sub-test builds its own
// fixture: the stub's request list is never reset.
func TestDeleteOnProxyForwards(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  func(f *fixture) string
	}{
		{"shared door", func(*fixture) string { return "http://localhost:8080/mcp" }},
		{"key route", func(f *fixture) string { return f.keyURL() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
			rr := f.doPath(http.MethodDelete, tc.url(f), "", map[string]string{"Mcp-Session-Id": "sess-1"})
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
			}
			reqs := f.requestsTo("solo")
			if len(reqs) != 1 {
				t.Fatalf("the upstream saw %d requests, want 1", len(reqs))
			}
			if reqs[0].HTTPMethod != http.MethodDelete {
				t.Errorf("the upstream saw %s, want DELETE: forward replays the client's verb", reqs[0].HTTPMethod)
			}
			if got := reqs[0].Header.Get("Mcp-Session-Id"); got != "sess-1" {
				t.Errorf("the upstream saw Mcp-Session-Id=%q want sess-1", got)
			}
			// Security requirement 8: the teardown's row records the verb,
			// found through the same filter the Logs page uses. It recorded
			// "" before, which that filter could never select.
			row := f.waitAudit(models.LogFilter{Method: http.MethodDelete})[0]
			if row.Status != models.StatusSuccess || row.VirtualKeyID != "a1" {
				t.Errorf("audit row=%+v want a success row for key a1", row)
			}
		})
	}
}

// Security requirement 8 on the POST shapes. A request whose body named no
// JSON-RPC method records the HTTP verb, on the forwarded path and in block,
// so no row is left with an empty method. The teardown DELETE is asserted in
// TestDeleteOnProxyForwards; here an empty body, and a body that names a
// tool and no method, which is the one shape that reaches block.
func TestMethodlessRequestRecordsTheVerb(t *testing.T) {
	t.Run("an empty body forwards and records POST", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
		f.post("{}")
		row := f.waitAudit(models.LogFilter{Method: http.MethodPost})[0]
		if row.VirtualKeyID != "a1" {
			t.Errorf("audit row=%+v want the key's own row", row)
		}
		if n := f.totalReqs("solo"); n != 1 {
			t.Errorf("the upstream saw %d requests, want 1: a POST with no method still forwards", n)
		}
	})
	t.Run("a tool name with no method is blocked and records POST", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"allowed_tool"}}, []string{"allowed_tool"}, nil)
		rr := f.post(`{"jsonrpc":"2.0","id":1,"params":{"name":"denied_tool"}}`)
		assertBlocked(t, f, rr)
		row := f.waitAudit(models.LogFilter{Method: http.MethodPost, Status: models.StatusBlocked})[0]
		if row.ToolName != "denied_tool" {
			t.Errorf("audit row=%+v want tool_name denied_tool", row)
		}
	})
}

// Security requirement 4. The host check runs before the verb is judged, so a
// GET with a wrong Host gets the diagnosable 403 with its seen and expected
// pair, not the 405: a refused verb is not a cheaper way to read the expected
// host, and an operator probing with curl -X GET sees what their client sees.
// The host check reads the request's host, which httptest.NewRequest takes
// from the URL, as host_test.go does.
func TestWrongHostBeatsTheVerb(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
	rr := f.doPath(http.MethodGet, "http://evil.example/a1/mcp", "", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("HTTP code=%d want 403; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %s", rr.Body.String())
	}
	if body["error"] != "invalid host" || body["seen"] == "" || body["expected"] == "" {
		t.Errorf("body=%v want the invalid-host refusal with seen and expected", body)
	}
	if got := rr.Header().Get("Allow"); got != "" {
		t.Errorf("Allow=%q on the host refusal: the verb was judged first", got)
	}
	if !f.upstreamsIdle() {
		t.Error("a request with a wrong host reached an upstream")
	}
}
