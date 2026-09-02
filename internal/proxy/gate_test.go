package proxy

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/netcasklabs/porymcp/internal/models"
)

// Every test here asserts the same two things about a refusal, because a tool
// policy that refuses the client but still contacts the upstream has not
// refused anything: the real credential was presented, the call may already
// have run, and the only thing the proxy saved was the response. So each
// blocked path checks both the envelope the client got and the request
// counters on every stub.

// toolCall builds a tools/call body. id is raw JSON so a test can send an
// integer larger than a float64 holds exactly, a string, or — with "" — no id
// at all, which makes the request a notification.
func toolCall(id, name string) string {
	if id == "" {
		return `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + name + `"}}`
	}
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + name + `"}}`
}

const listRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

// assertBlocked pins the whole client-facing contract of a block: HTTP 200
// (the call failed, the transport did not), -32602, one generic message that
// names no rule, and not a single upstream request.
func assertBlocked(t *testing.T, f *fixture, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Errorf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
	if code != codeInvalidParams {
		t.Errorf("rpc code=%d want %d; body=%s", code, codeInvalidParams, rr.Body.String())
	}
	if msg != "tool blocked" {
		t.Errorf("message=%q want %q", msg, "tool blocked")
	}
	if !f.upstreamsIdle() {
		t.Error("a blocked call reached an upstream: the credential was presented for a tool the policy refuses")
	}
}

// assertNotBlocked fails when the proxy refused something it has no rule
// against. what names the request, since these run in loops.
func assertNotBlocked(t *testing.T, rr *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rr.Code != http.StatusOK && rr.Code != http.StatusAccepted {
		t.Errorf("%s: HTTP code=%d body=%s", what, rr.Code, rr.Body.String())
		return
	}
	if len(bytes.TrimSpace(rr.Body.Bytes())) == 0 {
		return // an acknowledged notification has no body
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Errorf("%s: body is not JSON: %v (%s)", what, err, rr.Body.String())
		return
	}
	if raw, refused := env["error"]; refused {
		t.Errorf("%s: refused with %s", what, raw)
	}
}

// AC1. The filter used to be consulted only when the catalogue was built, so
// the tool it hid was callable with the real credential and left a row saying
// the call succeeded.
func TestGroupToolFilterBlocksCall(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"gh":   {"delete_repo", "list_issues"},
		"docs": {"search_docs"},
	}, json.RawMessage(`{"mode":"deny","tools":["gh__delete_repo"]}`), nil, nil)

	// An id past float64's exact range: this is the number the client will
	// match the reply against, and ...992 is a reply it never claims.
	rr := f.post(toolCall("9007199254740993", "gh__delete_repo"))
	assertBlocked(t, f, rr)
	if !strings.Contains(rr.Body.String(), `"id":9007199254740993`) {
		t.Errorf("id not echoed verbatim: %s", rr.Body.String())
	}
	if n, m := f.totalReqs("gh"), f.totalReqs("docs"); n != 0 || m != 0 {
		t.Errorf("members saw gh=%d docs=%d requests; a block happens before routing, so not even a tools/list should have gone out", n, m)
	}

	row := f.waitAudit(models.LogFilter{})[0]
	if row.Status != models.StatusBlocked || row.Method != "tools/call" || row.ToolName != "gh__delete_repo" {
		t.Errorf("row=%+v", row)
	}

	// Positive control, last so it cannot disturb the counters or the row
	// above: "no member was contacted" is also what a proxy that refused
	// everything would produce, and this is the test an AC is read against.
	assertNotBlocked(t, f.post(toolCall("1", "gh__list_issues")), "gh__list_issues, which the filter permits")
	if got := f.count("gh", "tools/call", "list_issues"); got != 1 {
		t.Errorf("gh saw %d calls to list_issues, want 1: the zero-request assertion above proves nothing if the stub was unreachable", got)
	}
}

// AC3. What the catalogue advertises and what a call is allowed to name are
// the same policy asked twice, so they cannot drift apart.
func TestGroupToolFilterHidesFromList(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"gh":   {"gh_create_issue", "gh_delete_repo"},
		"docs": {"docs_search", "docs_purge"},
	}, json.RawMessage(`{"mode":"allow","tools":["gh__gh_create_issue"],"prefixes":["docs__"]}`), nil, nil)

	// The hidden tool first, while the counters can still prove no upstream
	// was contacted; listing below necessarily contacts every member.
	assertBlocked(t, f, f.post(toolCall("1", "gh__gh_delete_repo")))

	listed := listedNames(t, f.post(listRequest).Body.Bytes())
	if got, want := strings.Join(listed, ","), "docs__docs_purge,docs__docs_search,gh__gh_create_issue"; got != want {
		t.Fatalf("listed %q want %q", got, want)
	}
	for _, name := range listed {
		assertNotBlocked(t, f.post(toolCall("1", name)), "advertised tool "+name)
	}

	// Two members advertising one tool are two tools with two identities, and
	// a rule naming one of them says nothing about the other.
	t.Run("each member's tool carries its own slug", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{
			"alpha": {"search"},
			"beta":  {"search"},
		}, json.RawMessage(`{"mode":"deny","tools":["alpha__search"]}`), nil, nil)

		assertBlocked(t, f, f.post(toolCall("1", "alpha__search")))
		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "beta__search" {
			t.Errorf("listed %q want beta__search", got)
		}
	})
}

// AC4 at the proxy level: the row an operator filters for is status=blocked,
// and it names the rule that fired. Returning early is what makes that true —
// falling through would let the error member in the response body relabel the
// row as an error.
func TestBlockedCallIsAuditedAsBlocked(t *testing.T) {
	t.Run("group filter", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"delete_repo"}},
			json.RawMessage(`{"mode":"deny","tools":["gh__delete_repo"]}`), nil, nil)

		assertBlocked(t, f, f.post(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gh__delete_repo","arguments":{"token":"hunter2"}}}`))

		row := f.waitAudit(models.LogFilter{})[0]
		if row.Status != models.StatusBlocked {
			t.Errorf("status=%q want %q", row.Status, models.StatusBlocked)
		}
		if row.Method != "tools/call" || row.ToolName != "gh__delete_repo" {
			t.Errorf("method=%q tool=%q", row.Method, row.ToolName)
		}
		if row.ErrorMessage != reasonGroupFilter {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
		}
		// Nothing was contacted, so there is no upstream to name. Empty is
		// honest under-reporting; naming one would mean resolving a route,
		// which is exactly the upstream traffic the block exists to avoid.
		if row.UpstreamID != "" {
			t.Errorf("upstream_id=%q want empty for a group block", row.UpstreamID)
		}
		params := string(row.Params)
		if !strings.Contains(params, "gh__delete_repo") {
			t.Errorf("params=%q: what the caller tried to pass is the first thing an operator asks about a block", params)
		}
		if strings.Contains(params, "hunter2") || !strings.Contains(params, "[redacted]") {
			t.Errorf("params=%q: the row is written through the redactor", params)
		}
	})

	// A key bound to one upstream shows the tool's own name and accepts both
	// spellings of a rule about it: the identity, whose head is that upstream's
	// slug, and the bare name. The two sub-tests are the same block written
	// each way, and the client's call is "delete_repo" in both — the entry
	// changes, never what a client has to send.
	t.Run("virtual key denylist", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo"}}, nil, []string{"solo__delete_repo"})
		assertBlocked(t, f, f.post(toolCall("1", "delete_repo")))

		row := f.waitAudit(models.LogFilter{})[0]
		if row.ErrorMessage != reasonKeyDenylist {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyDenylist)
		}
		// The single upstream is known without contacting anything, so the row
		// says which one the call was aimed at. "u1" is the only upstream the
		// fixture creates.
		if row.UpstreamID != "u1" {
			t.Errorf("upstream_id=%q want u1", row.UpstreamID)
		}
	})

	t.Run("virtual key denylist, unscoped entry", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo"}}, nil, []string{"delete_repo"})
		assertBlocked(t, f, f.post(toolCall("1", "delete_repo")))

		if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonKeyDenylist {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyDenylist)
		}
	})
}

// A key can always be narrowed below what its group permits. These two pin the
// precedence in the direction that matters: the key's lists are consulted
// first, so a group that permits a tool cannot re-permit one the key refuses.
func TestKeyDenylistBeatsGroupAllow(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"gh": {"safe_a", "safe_b"}},
		json.RawMessage(`{"mode":"allow","tools":["gh__safe_a","gh__safe_b"]}`), nil, []string{"gh__safe_a"})

	assertBlocked(t, f, f.post(toolCall("1", "gh__safe_a")))
	if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonKeyDenylist {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyDenylist)
	}
}

func TestKeyAllowlistNarrowsGroupAllow(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"gh": {"safe_a", "safe_b"}},
		json.RawMessage(`{"mode":"allow","tools":["gh__safe_a","gh__safe_b"]}`), []string{"gh__safe_a"}, nil)

	assertBlocked(t, f, f.post(toolCall("1", "gh__safe_b")))
	if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonKeyAllowlist {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyAllowlist)
	}
	assertNotBlocked(t, f.post(toolCall("1", "gh__safe_a")), "the one tool both lists permit")
}

// Tripwire. permits("") is false under any allowlist, so a gate that ran on
// every method — rather than only on the ones that name a tool — would refuse
// initialize, tools/list and ping for every key that has an allowlist, which
// is every one of those keys offline.
func TestKeyAllowlistDoesNotBlockNonToolMethods(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, []string{"safe_tool"}, nil)

	for _, m := range []string{"initialize", "tools/list", "ping"} {
		assertNotBlocked(t, f.post(`{"jsonrpc":"2.0","id":1,"method":"`+m+`"}`), m)
		if got := f.count("solo", m, ""); got != 1 {
			t.Errorf("upstream saw %d %s requests, want 1", got, m)
		}
	}
	m := "notifications/initialized"
	assertNotBlocked(t, f.post(`{"jsonrpc":"2.0","method":"`+m+`"}`), m)
	if got := f.count("solo", m, ""); got != 1 {
		t.Errorf("upstream saw %d %s requests, want 1", got, m)
	}
}

// The same tripwire on the group path, where initialize and
// notifications/initialized are answered by the proxy itself and tools/list is
// filtered rather than refused.
func TestGroupAllowFilterDoesNotBlockListOrInitialize(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"gh": {"gh_read", "danger"}},
		json.RawMessage(`{"mode":"allow","prefixes":["gh__gh_"]}`), nil, nil)

	assertNotBlocked(t, f.post(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`), "initialize")
	assertNotBlocked(t, f.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), "ping")
	if got := f.count("gh", "ping", ""); got != 1 {
		t.Errorf("upstream saw %d ping requests, want 1", got)
	}
	if rr := f.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); rr.Code != http.StatusAccepted {
		t.Errorf("notifications/initialized code=%d want 202; body=%s", rr.Code, rr.Body.String())
	}

	rr := f.post(listRequest)
	assertNotBlocked(t, rr, "tools/list")
	if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != "gh__gh_read" {
		t.Errorf("listed %q want gh__gh_read", got)
	}
}

// D2, pinned from both sides. A key's own lists have always applied to any
// method carrying a params.name, and neither PORM-19 nor the identity grammar
// widens or narrows that.
//
// The bare entry here is the tripwire for modeLiteral. A prompt name is not a
// tool identity: it is matched whole, with no slug composed into it and no
// unscoped entry skipped for naming no member. Rewrite this entry as
// "solo__secret_prompt" and it must stop matching — that is the failure the
// literal mode exists to prevent, and it would be silent.
func TestPromptsGetStillHonoursKeyDenylist(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, nil, []string{"secret_prompt"})

	assertBlocked(t, f, f.post(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"secret_prompt"}}`))
	row := f.waitAudit(models.LogFilter{})[0]
	if row.Method != "prompts/get" || row.ErrorMessage != reasonKeyDenylist {
		t.Errorf("row=%+v want prompts/get blocked by the key's denylist", row)
	}
}

// The other side of D2: a group's tool_filter is about tools. A filter so
// broken that every tool on the group is refused still says nothing about
// prompts, so prompts/get is forwarded.
func TestMalformedGroupFilterDoesNotGatePrompts(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}}, json.RawMessage(`"nonsense"`), nil, nil)

	rr := f.post(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"some_prompt"}}`)
	assertNotBlocked(t, rr, "prompts/get under a malformed group filter")
	if got := f.count("gh", "prompts/get", "some_prompt"); got != 1 {
		t.Errorf("upstream saw %d prompts/get requests, want 1", got)
	}
}

// A tools/call whose name the proxy cannot pin down is refused rather than
// forwarded for the upstream to interpret. Every row below used to reach the
// gate as the empty string, which every check treats as "no tool named here".
func TestToolCallWithoutStringNameFailsClosed(t *testing.T) {
	const head = `{"jsonrpc":"2.0","id":1,"method":"tools/call"`
	cases := []struct{ name, body string }{
		{"number", head + `,"params":{"name":123}}`},
		{"array", head + `,"params":{"name":["x"]}}`},
		{"null", head + `,"params":{"name":null}}`},
		{"empty string", head + `,"params":{"name":""}}`},
		{"absent name", head + `,"params":{"arguments":{}}}`},
		{"empty params", head + `,"params":{}}`},
		{"absent params", head + `}`},
		// Go's decoder turns a lone surrogate into U+FFFD while JavaScript and
		// Python clients keep it, and the body is forwarded verbatim — so the
		// name the proxy would authorise is not the one the upstream executes.
		{"lone surrogate", head + `,"params":{"name":"\ud800"}}`},
		{"control character", head + `,"params":{"name":"a\u0001b"}}`},
		{"tab", head + `,"params":{"name":"a\tb"}}`},
	}
	// One fixture for the table: none of these reaches an upstream, so the
	// counters stay at zero across every row.
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, nil, nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := f.post(c.body)
			if rr.Code != http.StatusOK {
				t.Errorf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
			}
			code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
			if code != codeInvalidParams || msg != "invalid params: tools/call requires a tool name" {
				t.Errorf("code=%d message=%q", code, msg)
			}
			if !f.upstreamsIdle() {
				t.Error("a tools/call with no usable name reached the upstream")
			}
		})
	}
	rows := f.waitAuditN(models.LogFilter{Status: models.StatusError}, len(cases))
	if len(rows) != len(cases) {
		t.Errorf("%d error rows for %d refused calls", len(rows), len(cases))
	}
	for _, row := range rows {
		if row.ErrorMessage != "tools/call without a tool name" {
			t.Errorf("error_message=%q", row.ErrorMessage)
		}
	}

	// A space is not one of these. Every JSON decoder preserves it, so the
	// name the gate judged is the name the upstream will run, and refusing it
	// would only break a client whose upstream advertises such a tool.
	t.Run("a name with a space is forwarded", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"odd name"}}, nil, nil)
		assertNotBlocked(t, f.post(toolCall("1", "odd name")), `tools/call "odd name"`)
		if got := f.count("solo", "tools/call", "odd name"); got != 1 {
			t.Errorf("upstream saw %d calls, want 1", got)
		}
	})
}

// The point of answering 200 with an error rather than 403 is that the client
// can match the reply to its request. That only holds if the id comes back as
// the bytes it arrived as.
func TestBlockResponseEchoesIdExactly(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"danger"}}, nil, []string{"solo__danger"})
	for _, c := range []struct{ id, want string }{
		{"9007199254740993", `"id":9007199254740993`},
		{`"abc"`, `"id":"abc"`},
		{"null", `"id":null`},
	} {
		t.Run("id="+c.id, func(t *testing.T) {
			rr := f.post(toolCall(c.id, "danger"))
			assertBlocked(t, f, rr)
			if !strings.Contains(rr.Body.String(), c.want) {
				t.Errorf("body=%s want it to contain %s", rr.Body.String(), c.want)
			}
		})
	}
}

// A notification has no id, so an error envelope would carry nothing to
// correlate against and an honest client would match it to whatever it
// numbered 1. It is acknowledged and audited instead.
func TestBlockedNotificationReturns202(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"danger"}}, nil, []string{"solo__danger"})

	rr := f.post(toolCall("", "danger"))
	if rr.Code != http.StatusAccepted {
		t.Errorf("code=%d want 202; body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body != "" {
		t.Errorf("body=%q want empty", body)
	}
	if !f.upstreamsIdle() {
		t.Error("a blocked notification reached the upstream")
	}
	if row := f.waitAudit(models.LogFilter{})[0]; row.Status != models.StatusBlocked || row.ToolName != "danger" {
		t.Errorf("row=%+v want a blocked row for danger", row)
	}
}

// Every filter below decodes without error into a ToolFilter that matches
// nothing, which is indistinguishable from having no filter at all. While the
// filter was cosmetic that was invisible; now it would be a silent
// authorization bypass that looks exactly like a working deny, so the group
// refuses everything until the filter is fixed.
func TestMalformedToolFilterFailsClosed(t *testing.T) {
	for _, filter := range []string{
		`{"mode":"Deny","tools":["x"]}`,
		`{"mode":"DENY","tools":["x"]}`,
		`{"mode":"deny ","tools":["x"]}`,
		`{"mode":"deny","tool":["x"]}`,
		`"nonsense"`,
	} {
		t.Run(filter, func(t *testing.T) {
			f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}}, json.RawMessage(filter), nil, nil)

			// By its identity: a bare name on a group endpoint is refused for
			// its shape before any policy is consulted, which would prove
			// nothing about the filter.
			assertBlocked(t, f, f.post(toolCall("1", "gh__safe_tool")))
			if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonInvalidFilter {
				t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonInvalidFilter)
			}

			// And the catalogue agrees: advertising tools that can no longer be
			// called would be the worst of both answers.
			rr := f.post(listRequest)
			if got := listedNames(t, rr.Body.Bytes()); len(got) != 0 {
				t.Errorf("listed %v want nothing", got)
			}
			if !strings.Contains(rr.Body.String(), `"tools":[]`) {
				t.Errorf("body=%s want an empty array, not null", rr.Body.String())
			}
		})
	}
}

// A blocked call costs zero upstream requests, so the audit write is the only
// cost of sending one — and audit.Record redacts params on the request
// goroutine before they are stored. Both ends of the row are bounded.
func TestBlockedAuditRowIsBounded(t *testing.T) {
	t.Run("params", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, []string{"solo__safe_tool"}, nil)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo","blob":"` +
			strings.Repeat("a", 1<<20) + `"}}`
		assertBlocked(t, f, f.post(body))

		row := f.waitAudit(models.LogFilter{})[0]
		var marker struct {
			Truncated bool `json:"truncated"`
			Bytes     int  `json:"bytes"`
		}
		if err := json.Unmarshal(row.Params, &marker); err != nil {
			t.Fatalf("params=%.120q: %v", row.Params, err)
		}
		if !marker.Truncated || marker.Bytes < 1<<20 {
			t.Errorf("params=%q want a truncation marker naming the original size", row.Params)
		}
	})

	t.Run("tool name", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, []string{"solo__safe_tool"}, nil)
		assertBlocked(t, f, f.post(toolCall("1", strings.Repeat("a", 1000))))

		if row := f.waitAudit(models.LogFilter{})[0]; len(row.ToolName) > auditFieldBytes {
			t.Errorf("tool_name is %d bytes, want at most %d", len(row.ToolName), auditFieldBytes)
		}
	})
}

// forward replays the inbound verb, so a gate that only ran on POST would
// leave DELETE and PUT as open relays for the calls it refuses.
func TestGateRunsOnDeleteWithBody(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"danger"}}, nil, []string{"solo__danger"})
	assertBlocked(t, f, f.do(http.MethodDelete, toolCall("1", "danger")))
}

// AC7, the headline. One entry, one meaning, both doors: a rule naming
// alpha__search refuses that tool whether the client calls it by its identity
// on the group's endpoint or by its own name on alpha's, and says nothing about
// the tool of the same name on beta.
func TestToolFilterIdentityAppliesOnBothPaths(t *testing.T) {
	members := map[string][]string{"alpha": {"search"}, "beta": {"search"}}
	const filter = `{"mode":"deny","tools":["alpha__search"]}`

	t.Run("aggregate endpoint", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertBlocked(t, f, f.post(toolCall("1", "alpha__search")))
		assertNotBlocked(t, f.post(toolCall("2", "beta__search")), "beta__search, which the entry does not name")
		if got := f.count("beta", "tools/call", "search"); got != 1 {
			t.Errorf("beta saw %d calls to search, want 1", got)
		}
	})

	t.Run("alpha's member endpoint", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertBlocked(t, f, f.postMember("alpha", toolCall("1", "search")))
		if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonGroupFilter {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
		}
	})

	t.Run("beta's member endpoint", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertNotBlocked(t, f.postMember("beta", toolCall("1", "search")), "search on beta, which the entry does not name")
		if got := f.count("beta", "tools/call", "search"); got != 1 {
			t.Errorf("beta saw %d calls to search, want 1", got)
		}
	})
}

// AC6. A key bound to one upstream is a pass-through: the client sees the
// upstream's own names and calls them by those names. Only the rules change
// shape, and both shapes are legal there — the identity, whose head must be
// that upstream's slug, and the bare name.
func TestSingleUpstreamKeyKeepsOriginalNames(t *testing.T) {
	t.Run("the catalogue is the upstream's own", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool", "danger"}}, nil, nil)
		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "danger,safe_tool" {
			t.Errorf("listed %q want danger,safe_tool — a 1:1 key prefixes nothing", got)
		}
	})

	t.Run("a scoped denylist entry", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool", "danger"}}, nil, []string{"solo__danger"})
		assertBlocked(t, f, f.post(toolCall("1", "danger")))
		assertNotBlocked(t, f.post(toolCall("2", "safe_tool")), "safe_tool")
	})

	t.Run("an unscoped denylist entry", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool", "danger"}}, nil, []string{"danger"})
		assertBlocked(t, f, f.post(toolCall("1", "danger")))
		assertNotBlocked(t, f.post(toolCall("2", "safe_tool")), "safe_tool")
	})

	// An unscoped allow entry admits nothing on a group. Here there is exactly
	// one upstream and every tool belongs to it, so it admits what it names.
	t.Run("an unscoped allowlist entry", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool", "danger"}}, []string{"safe_tool"}, nil)
		// The refusal first, while the counters can still prove nothing was
		// contacted; the positive control necessarily contacts the upstream.
		assertBlocked(t, f, f.post(toolCall("1", "danger")))
		assertNotBlocked(t, f.post(toolCall("2", "safe_tool")), "safe_tool, which the allowlist names")
	})

	// A scoped entry whose head is another upstream's slug names a tool this
	// key cannot reach, so it admits nothing here.
	t.Run("a foreign scoped allowlist entry admits nothing", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, []string{"other__safe_tool"}, nil)
		assertBlocked(t, f, f.post(toolCall("1", "safe_tool")))
	})
}

// D4. A prefixes entry names a shape of tool name, and the tool's own name is
// the only thing that shape can be measured against — on every path. Matched
// against a group's composed names instead, "delete_" would match nothing at
// all and the deny would fail open with the real credential presented.
func TestPrefixesMatchTheOriginalNameOnEveryPath(t *testing.T) {
	members := map[string][]string{
		"gh":   {"delete_repo", "read_issue"},
		"docs": {"delete_page"},
	}
	const filter = `{"mode":"deny","prefixes":["delete_"]}`

	t.Run("aggregate endpoint", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertBlocked(t, f, f.post(toolCall("1", "gh__delete_repo")))
		assertBlocked(t, f, f.post(toolCall("2", "docs__delete_page")))
		assertNotBlocked(t, f.post(toolCall("3", "gh__read_issue")), "gh__read_issue")
		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "gh__read_issue" {
			t.Errorf("listed %q want gh__read_issue", got)
		}
	})

	t.Run("member endpoint", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertBlocked(t, f, f.postMember("gh", toolCall("1", "delete_repo")))
		assertNotBlocked(t, f.postMember("gh", toolCall("2", "read_issue")), "read_issue")
	})
}

// A prefixes entry that ends at the separator is the useful "every tool on this
// member", and it is the one entry shape where an empty rest means something.
func TestScopedPrefixEmptyRest(t *testing.T) {
	members := map[string][]string{
		"docs": {"search", "purge"},
		"gh":   {"read_issue"},
	}
	const filter = `{"mode":"deny","prefixes":["docs__"]}`

	f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
	assertBlocked(t, f, f.post(toolCall("1", "docs__search")))
	assertBlocked(t, f, f.post(toolCall("2", "docs__purge")))
	assertNotBlocked(t, f.post(toolCall("3", "gh__read_issue")), "gh__read_issue, on the member the entry does not name")
	if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "gh__read_issue" {
		t.Errorf("listed %q want gh__read_issue", got)
	}

	// And on docs' own endpoint, where the client sees the bare names.
	member := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
	assertBlocked(t, member, member.postMember("docs", toolCall("1", "search")))
}

// The same entry read the wrong way round would be inert. "github__" is not a
// tool name and does not prefix any tool's own name, so an implementation that
// dropped the head or refused an empty rest would leave this filter matching
// nothing — a deny that looks written and enforces nothing.
func TestSlugShapedPrefixIsNotInert(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"github": {"create_issue", "delete_repo"},
		"docs":   {"search"},
	}, json.RawMessage(`{"mode":"deny","prefixes":["github__"]}`), nil, nil)

	assertBlocked(t, f, f.post(toolCall("1", "github__create_issue")))
	assertBlocked(t, f, f.post(toolCall("2", "github__delete_repo")))
	assertNotBlocked(t, f.post(toolCall("3", "docs__search")), "docs__search, which the entry does not name")
}

// The head of a scoped entry is a member check, not a string prefix of the
// composed name. gh advertises a tool actually called docs__exfiltrate, so an
// allow rule for the docs member must not admit it — reading the entry as a
// prefix of the tool's own name would.
func TestScopedAllowPrefixIsMemberScoped(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"gh":   {"docs__exfiltrate"},
		"docs": {"read"},
	}, json.RawMessage(`{"mode":"allow","prefixes":["docs__"]}`), nil, nil)

	assertBlocked(t, f, f.post(toolCall("1", "gh__docs__exfiltrate")))
	assertNotBlocked(t, f.post(toolCall("2", "docs__read")), "docs__read, which the entry admits")
	if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "docs__read" {
		t.Errorf("listed %q want docs__read", got)
	}
}

// An allow entry on a group that names no member admits nothing. The
// management API refuses to write one, so this seeds the filter straight
// through the store — which is also how a filter written before the identity
// grammar existed arrives. Reading it as "this name on every member" would
// widen an operator's rule to the whole group, so it is read as naming nothing
// instead, and the startup report says which group holds it.
func TestUnscopedAllowEntryAdmitsNothingOnAGroup(t *testing.T) {
	members := map[string][]string{"alpha": {"search", "lookup"}, "beta": {"search"}}
	const filter = `{"mode":"allow","tools":["search","alpha__lookup"]}`

	f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
	assertBlocked(t, f, f.post(toolCall("1", "alpha__search")))
	if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonGroupFilter {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
	}
	assertBlocked(t, f, f.post(toolCall("2", "beta__search")))
	// The scoped entry beside it still does exactly what it says.
	assertNotBlocked(t, f.post(toolCall("3", "alpha__lookup")), "alpha__lookup, the scoped entry")
	if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "alpha__lookup" {
		t.Errorf("listed %q want alpha__lookup", got)
	}

	// The member endpoint agrees: the same entry, the same nothing.
	member := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
	assertBlocked(t, member, member.postMember("alpha", toolCall("1", "search")))

	// And a key's own allowlist behaves the same way on a group key.
	key := newGroupFixture(t, members, nil, []string{"search"}, nil)
	assertBlocked(t, key, key.post(toolCall("1", "alpha__search")))
	if row := key.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonKeyAllowlist {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyAllowlist)
	}
}

// A group of one is still a group. Its member's tools are advertised as
// identities, and the allow rule that governs them must name the member even
// though there is only one it could mean — the alternative is a rule whose
// meaning changes the day a second member is added.
func TestOneMemberGroupIsAGroup(t *testing.T) {
	t.Run("an unscoped allow entry admits nothing", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"read", "danger"}},
			json.RawMessage(`{"mode":"allow","tools":["read"]}`), nil, nil)

		assertBlocked(t, f, f.post(toolCall("1", "gh__read")))
		if got := listedNames(t, f.post(listRequest).Body.Bytes()); len(got) != 0 {
			t.Errorf("listed %v want nothing", got)
		}
	})

	t.Run("the scoped entry admits what it names", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"read", "danger"}},
			json.RawMessage(`{"mode":"allow","tools":["gh__read"]}`), nil, nil)

		assertBlocked(t, f, f.post(toolCall("1", "gh__danger")))
		assertNotBlocked(t, f.post(toolCall("2", "gh__read")), "gh__read")
		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "gh__read" {
			t.Errorf("listed %q want gh__read", got)
		}
	})
}

// R5. A prompt name is not a tool identity, so a key's lists are matched
// against it whole: an entry holding the separator blocks the prompt of exactly
// that name, and a bare entry is not skipped for naming no member. Both halves
// fail silently if the tool grammar is reused here — the entry simply stops
// matching, and a denylist that reads as enforced enforces nothing.
func TestKeyListsOnlyMatchesEntriesLiterally(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"docs": {"search"}, "gh": {"read"}},
		nil, nil, []string{"docs__search", "secret_prompt"})

	const get = `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"`
	assertBlocked(t, f, f.post(get+`docs__search"}}`))
	if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonKeyDenylist {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyDenylist)
	}
	assertBlocked(t, f, f.post(get+`secret_prompt"}}`))

	// A prompt whose name is the rest of a scoped entry is not that prompt.
	assertNotBlocked(t, f.post(get+`search"}}`), "the prompt called search")
}

// The other side of R5: a group key's allowlist admits a prompt by its own
// name. The skip that makes an unscoped allow entry admit nothing is a rule
// about tools on a group; applied here it would take every prompt on the key
// offline, silently.
func TestKeyAllowlistStillAdmitsAPromptOnAGroupKey(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"docs": {"search"}, "gh": {"read"}},
		nil, []string{"read_docs"}, nil)

	// The tool first, while the counters can still prove nothing was
	// contacted: the same entry admits no tool, because on a group it names
	// none.
	assertBlocked(t, f, f.post(toolCall("1", "docs__search")))

	assertNotBlocked(t, f.post(`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"read_docs"}}`),
		"prompts/get read_docs, which the allowlist names")
	if got := f.count("docs", "prompts/get", "read_docs"); got != 1 {
		t.Errorf("the first member saw %d prompts/get, want 1", got)
	}
}

// The tripwire for the mode itself. serve is the only production caller that
// chooses one, it is a positional argument, and modeLiteral is the zero value:
// a call site that forgot it would judge a group's canonical names whole, so
// this unscoped deny would match none of them and fail open on the aggregate.
func TestServePassesTheIdentityMode(t *testing.T) {
	const filter = `{"mode":"deny","tools":["delete_repo"]}`
	members := map[string][]string{"gh": {"delete_repo", "read_issue"}, "docs": {"search"}}

	t.Run("aggregate parses the identity", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertBlocked(t, f, f.post(toolCall("1", "gh__delete_repo")))
		assertNotBlocked(t, f.post(toolCall("2", "gh__read_issue")), "gh__read_issue")
	})

	t.Run("member composes the identity", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(filter), nil, nil)
		assertBlocked(t, f, f.postMember("gh", toolCall("1", "delete_repo")))
		assertNotBlocked(t, f.postMember("gh", toolCall("2", "read_issue")), "read_issue")
	})

	t.Run("a single-upstream key composes it too", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"delete_repo", "read_issue"}}, nil, []string{"solo__delete_repo"})
		assertBlocked(t, f, f.post(toolCall("1", "delete_repo")))
		assertNotBlocked(t, f.post(toolCall("2", "read_issue")), "read_issue")
	})
}

// The catalogue and the gate are one policy asked twice, and this asks it over
// every name at once: everything listed is callable, and every name that is not
// listed is refused without an upstream running anything. A drift between the
// two is either a tool an agent cannot use or one it was never meant to see.
func TestPolicyGateAgreesWithCatalogue(t *testing.T) {
	members := map[string][]string{
		"gh":   {"read_issue", "delete_repo"},
		"docs": {"search", "purge"},
	}
	f := newGroupFixture(t, members,
		json.RawMessage(`{"mode":"deny","tools":["gh__delete_repo"],"prefixes":["docs__purge"]}`), nil, nil)

	listed := map[string]bool{}
	for _, n := range listedNames(t, f.post(listRequest).Body.Bytes()) {
		listed[n] = true
	}
	if len(listed) != 2 || !listed["gh__read_issue"] || !listed["docs__search"] {
		t.Fatalf("listed %v want gh__read_issue and docs__search", listed)
	}

	// Every name the group could possibly answer to, plus two that exist
	// nowhere: one well-formed, one not.
	for _, c := range []struct{ slug, name string }{
		{"gh", "read_issue"}, {"gh", "delete_repo"},
		{"docs", "search"}, {"docs", "purge"},
		{"gh", "no_such_tool"}, {"", "not_an_identity"},
	} {
		call := c.name
		if c.slug != "" {
			call = c.slug + "__" + c.name
		}
		rr := f.post(toolCall("1", call))
		if listed[call] {
			assertNotBlocked(t, rr, call+", which the catalogue advertises")
			if got := f.count(c.slug, "tools/call", c.name); got != 1 {
				t.Errorf("%s: the member ran it %d times, want 1", call, got)
			}
			continue
		}
		if rr.Code != http.StatusOK {
			t.Errorf("%s: HTTP code=%d want 200; body=%s", call, rr.Code, rr.Body.String())
		}
		if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); code != codeInvalidParams {
			t.Errorf("%s: rpc code=%d want %d — a name the catalogue withholds must be refused", call, code, codeInvalidParams)
		}
		if c.slug != "" {
			if got := f.count(c.slug, "tools/call", c.name); got != 0 {
				t.Errorf("%s: the member ran it %d times; a refused name must never execute", call, got)
			}
		}
	}
}

// A one-member group is still a group: its tools are advertised as
// gh__gh_read, and an allow rule on a group must name the member. The rule
// still reaches the tool because a prefixes entry's rest is matched against the
// tool's own name, so "gh__gh_" reads as "everything starting gh_ on gh".
func TestOneMemberGroupPrefixesOnlyAllow(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"gh": {"gh_read", "danger"}},
		json.RawMessage(`{"mode":"allow","prefixes":["gh__gh_"]}`), nil, nil)

	assertBlocked(t, f, f.post(toolCall("1", "gh__danger")))
	if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "gh__gh_read" {
		t.Errorf("listed %q want gh__gh_read", got)
	}
}

// corruptKeyList writes a value into one of the fixture key's list columns that
// no exported call could produce, through a second connection to the same file.
// A decoder that swallows the error is the thing under test, so the corruption
// has to be real: going through the store would only ever store valid JSON.
func corruptKeyList(t *testing.T, f *fixture, column, value string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file://"+f.DBPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE virtual_keys SET `+column+` = ? WHERE id = 'a1'`, value); err != nil {
		t.Fatalf("corrupt %s: %v", column, err)
	}
}

// A virtual key whose lists cannot be read refuses everything it is asked,
// rather than behaving like a key that has no lists at all. The two used to be
// the same thing: the column was decoded by a helper that answers nil for "",
// for "null" and for "this is not a list" alike, so a denylist damaged by a
// half-finished write, a bad restore or a hand-edit left the key working with
// its rules silently gone.
//
// prompts/get is here as well as tools/call because that path is judged by the
// key's lists alone (keyListsOnly). It is exactly the policy that cannot be
// read, so it is exactly the one that must not fall open.
func TestCorruptKeyListFailsClosed(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, nil, nil)
	// Both lists are empty, so this key has no rule of its own and no group:
	// every refusal below comes from the column being unreadable, and nothing
	// else. (The refusals are asserted against every stub's request counter, so
	// the fixture cannot be warmed up with a permitted call first.)
	corruptKeyList(t, f, "tool_denylist", `["unterminated`)

	assertBlocked(t, f, f.post(toolCall("2", "safe_tool")))
	assertBlocked(t, f, f.post(`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"some_prompt"}}`))

	rows := f.waitAuditN(models.LogFilter{Status: models.StatusBlocked}, 2)
	if len(rows) != 2 {
		t.Fatalf("got %d blocked rows, want 2", len(rows))
	}
	for _, row := range rows {
		if row.ErrorMessage != reasonInvalidKeyLists {
			t.Errorf("%s row: error_message = %q, want %q", row.Method, row.ErrorMessage, reasonInvalidKeyLists)
		}
	}
}
