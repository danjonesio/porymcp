package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// A group's aggregate endpoint advertises one name per tool per member, and
// that name is the tool's identity: the member's slug, two underscores, the
// tool's own name. Every test here is about that one string, that it is
// always composed, that distinct tools never share it, and that the call it
// carries reaches the member the slug names with the name that member
// advertises.

// The regression test for a live misroute. Two members whose slugs are
// themselves in a prefix relationship, each advertising both names: under the
// one-underscore scheme gh + "_" + enterprise_create_issue and gh_enterprise +
// "_" + create_issue are the same string, so one of the two overwrote the
// other in the route table and its calls executed against the wrong member's
// credential. Two underscores plus ValidSlug's no-double-separator rule make
// the composition injective, so all four names exist and each routes home.
func TestAggregateIdentityIsInjective(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"gh":            {"create_issue", "enterprise_create_issue"},
		"gh_enterprise": {"create_issue", "enterprise_create_issue"},
	}, nil, nil, nil)

	listed := listedNames(t, f.post(listRequest).Body.Bytes())
	want := "gh__create_issue,gh__enterprise_create_issue," +
		"gh_enterprise__create_issue,gh_enterprise__enterprise_create_issue"
	if got := strings.Join(listed, ","); got != want {
		t.Fatalf("listed %q\nwant     %q\nfour distinct tools must have four distinct names", got, want)
	}

	// Each of the four, called by the name the catalogue advertised, reaching
	// its own member with its own original name. The counters are what make
	// this a misroute test rather than a spelling test: a name that resolved to
	// the wrong upstream would still answer 200.
	for _, c := range []struct{ call, slug, original string }{
		{"gh__create_issue", "gh", "create_issue"},
		{"gh__enterprise_create_issue", "gh", "enterprise_create_issue"},
		{"gh_enterprise__create_issue", "gh_enterprise", "create_issue"},
		{"gh_enterprise__enterprise_create_issue", "gh_enterprise", "enterprise_create_issue"},
	} {
		assertNotBlocked(t, f.post(toolCall("1", c.call)), c.call)
		if got := f.count(c.slug, "tools/call", c.original); got != 1 {
			t.Errorf("%s: %s saw %d calls to %q, want 1: the name resolved to the wrong member's credential",
				c.call, c.slug, got, c.original)
		}
	}
	// And nothing reached the other member under any name.
	for _, slug := range []string{"gh", "gh_enterprise"} {
		for _, other := range []string{"create_issue", "enterprise_create_issue"} {
			if got := f.count(slug, "tools/call", other); got != 1 {
				t.Errorf("%s saw %d calls to %q, want exactly 1", slug, got, other)
			}
		}
	}
}

// AC1, AC2, AC4. Every tool on a group endpoint carries its member's slug,
// whether or not another member advertises the same tool, and whether or not
// the group has more than one member. The old scheme prefixed only on a clash,
// which made an advertised name a fact about the other members rather than
// about the tool.
func TestAggregateAlwaysPrefixes(t *testing.T) {
	t.Run("two members, nothing in common", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{
			"alpha": {"search"},
			"beta":  {"lookup"},
		}, nil, nil, nil)

		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "alpha__search,beta__lookup" {
			t.Errorf("listed %q want alpha__search,beta__lookup", got)
		}
	})

	t.Run("two members, the same tool", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{
			"alpha": {"create_issue"},
			"beta":  {"create_issue"},
		}, nil, nil, nil)

		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "alpha__create_issue,beta__create_issue" {
			t.Errorf("listed %q want alpha__create_issue,beta__create_issue", got)
		}
		assertNotBlocked(t, f.post(toolCall("1", "alpha__create_issue")), "alpha__create_issue")
		assertNotBlocked(t, f.post(toolCall("2", "beta__create_issue")), "beta__create_issue")
		for _, slug := range []string{"alpha", "beta"} {
			if got := f.count(slug, "tools/call", "create_issue"); got != 1 {
				t.Errorf("%s saw %d calls to create_issue, want 1", slug, got)
			}
		}
	})

	t.Run("one member still prefixes", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"read"}}, nil, nil, nil)

		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "gh__read" {
			t.Errorf("listed %q want gh__read", got)
		}
		assertNotBlocked(t, f.post(toolCall("1", "gh__read")), "gh__read")
		ran := f.count("gh", "tools/call", "read")
		if ran != 1 {
			t.Fatalf("gh saw %d calls to read, want 1", ran)
		}

		// The name this group used to advertise is not a name any more. A
		// client holding a stale catalogue is told so rather than served: the
		// counter above must not move.
		rr := f.post(toolCall("2", "read"))
		if rr.Code != 200 {
			t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
		}
		code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
		if code != codeInvalidParams || !strings.HasPrefix(msg, "unknown tool") {
			t.Errorf("code=%d message=%q want %d and a message naming an unknown tool", code, msg, codeInvalidParams)
		}
		if got := f.count("gh", "tools/call", "read"); got != ran {
			t.Errorf("gh ran %d calls to read, want %d: the unprefixed name executed something", got, ran)
		}
	})
}

// AC3. The client calls the identity; the member runs its own name. Everything
// else the client sent in params is its business and reaches the upstream
// untouched.
func TestAggregateCallRewritesToOriginalName(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"alpha": {"search"},
		"beta":  {"other"},
	}, nil, nil, nil)

	rr := f.post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"alpha__search","arguments":{"q":"pory"}}}`)
	assertNotBlocked(t, rr, "alpha__search")
	if got := f.count("alpha", "tools/call", "search"); got != 1 {
		t.Errorf("alpha saw %d calls to search, want 1", got)
	}
	if n := f.count("beta", "tools/call", "search"); n != 0 {
		t.Errorf("beta saw %d calls; the slug named alpha", n)
	}

	var body []byte
	for _, req := range f.requestsTo("alpha") {
		if req.RPCMethod == "tools/call" {
			body = req.Body
		}
	}
	if body == nil {
		t.Fatal("alpha saw no tools/call")
	}
	var call struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &call); err != nil {
		t.Fatalf("alpha's request is not JSON: %v (%s)", err, body)
	}
	if call.Params.Name != "search" {
		t.Errorf("params.name=%q want search: the member knows its tool by its own name", call.Params.Name)
	}
	if got, want := string(call.Params.Arguments), `{"q":"pory"}`; got != want {
		t.Errorf("arguments=%s want %s: rewriting the name must not disturb the rest of params", got, want)
	}
}

// A tool whose own name holds the separator, which is what an upstream that is
// itself a proxy advertises. The split is at the FIRST separator, so a name
// survives the round trip whatever it contains, and a member whose slug is the
// head of another member's tool name gets a different string, not a fight over
// the same one.
func TestAggregateToolNameContainingSeparator(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"alpha": {"inner__x", "_search"},
		"inner": {"x"},
	}, nil, nil, nil)

	if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "alpha___search,alpha__inner__x,inner__x" {
		t.Errorf("listed %q want alpha___search,alpha__inner__x,inner__x", got)
	}
	for _, c := range []struct{ call, slug, original string }{
		{"alpha__inner__x", "alpha", "inner__x"},
		{"inner__x", "inner", "x"},
		{"alpha___search", "alpha", "_search"},
	} {
		assertNotBlocked(t, f.post(toolCall("1", c.call)), c.call)
		if got := f.count(c.slug, "tools/call", c.original); got != 1 {
			t.Errorf("%s: %s saw %d calls to %q, want 1", c.call, c.slug, got, c.original)
		}
	}
}

// R6. A tool the call gate could never authorise is not advertised either: an
// empty name composes to "alpha__", and a name carrying a control character is
// one the proxy cannot hold a caller to, because Go's decoder and a JavaScript
// client do not agree on what the client sent. Advertising either would hand a
// client a tool that answers -32602 for ever.
func TestAggregateDropsNamelessTools(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		// The middle name carries U+0001, JSON-escaped exactly as an upstream
		// would send it on the wire.
		"alpha": {RawList: `{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
			`{"name":""},{"name":"bad\u0001name"},{"name":"good"}]}}`},
	}, true, nil, nil, nil)

	if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "alpha__good" {
		t.Errorf("listed %q want alpha__good", got)
	}
	rr := f.post(toolCall("1", "alpha__"))
	code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
	if code != codeInvalidParams || !strings.HasPrefix(msg, "unknown tool") {
		t.Errorf("code=%d message=%q want %d and a message naming an unknown tool", code, msg, codeInvalidParams)
	}
	if got := f.count("alpha", "tools/call", ""); got != 0 {
		t.Errorf("alpha ran %d nameless calls", got)
	}
}

// The audit row for a block on the aggregate records the name the client used,
// which is the identity, so the operator reading the row and the agent that
// sent the call are talking about the same string.
func TestAggregateBlockAuditsTheNameTheClientUsed(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"alpha": {"search"},
		"beta":  {"search"},
	}, json.RawMessage(`{"mode":"deny","tools":["alpha__search"]}`), nil, nil)

	assertBlocked(t, f, f.post(toolCall("1", "alpha__search")))
	row := f.waitAudit(models.LogFilter{})[0]
	if row.ToolName != "alpha__search" {
		t.Errorf("tool_name=%q want alpha__search", row.ToolName)
	}
	if row.UpstreamID != "" {
		t.Errorf("upstream_id=%q want empty: nothing was contacted, so there is no upstream to name", row.UpstreamID)
	}
	if row.ErrorMessage != reasonGroupFilter {
		t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
	}
}

// The aggregate twin of gate_test.go's "a name with a space is forwarded".
// Every JSON decoder preserves a space, so the name the gate judged is the name
// the upstream runs, and the only thing the proxy adds in front of it is the
// slug.
func TestAggregateForwardsANameWithASpace(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"odd name"}}, nil, nil, nil)

	if got, want := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","), "alpha__odd name"; got != want {
		t.Errorf("listed %q want %q", got, want)
	}
	assertNotBlocked(t, f.post(toolCall("1", "alpha__odd name")), `tools/call "alpha__odd name"`)
	if got := f.count("alpha", "tools/call", "odd name"); got != 1 {
		t.Errorf("alpha saw %d calls to %q, want 1", got, "odd name")
	}
}

// AC5. A name that is not an identity names no tool on a group endpoint, and
// saying so costs one string scan: no group is read, no member is asked, and
// no credential is presented. The refusal is the same for a slug this
// deployment has and one it has never heard of, so it answers no question about
// what sits behind the group.
func TestAggregateUnknownToolIsRefusedBeforeAnyUpstream(t *testing.T) {
	cases := []struct{ name, tool string }{
		{"a bare tool name", "search"},
		{"nothing after the separator", "alpha__"},
		{"nothing before it", "__search"},
		{"separators only", "____"},
		{"a slug and no tool", "alpha"},
		{"a head that is not a slug", "Alpha__x"},
		{"a head too long to be a slug", strings.Repeat("a", 300) + "__x"},
	}
	// One fixture for the table: none of these reaches an upstream, so the
	// counters stay at zero across every row.
	f := newGroupFixture(t, map[string][]string{"alpha": {"search"}, "beta": {"search"}}, nil, nil, nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := f.post(toolCall("1", c.tool))
			if rr.Code != http.StatusOK {
				t.Errorf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
			}
			code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
			if want := "unknown tool: " + truncate(c.tool, auditFieldBytes); code != codeInvalidParams || msg != want {
				t.Errorf("code=%d message=%q want %d %q", code, msg, codeInvalidParams, want)
			}
			if !f.upstreamsIdle() {
				t.Error("a name that identifies no tool reached a member: not even a catalogue request should have gone out")
			}
		})
	}

	rows := f.waitAuditN(models.LogFilter{Status: models.StatusError}, len(cases))
	if len(rows) != len(cases) {
		t.Errorf("%d error rows for %d refused calls", len(rows), len(cases))
	}
	for _, row := range rows {
		// An error, not a block: no rule fired, so an operator filtering for
		// blocked calls is not shown a probe for a name that never existed.
		if row.ErrorMessage != "unknown tool" {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, "unknown tool")
		}
		if row.UpstreamID != "" {
			t.Errorf("upstream_id=%q want empty: nothing was contacted", row.UpstreamID)
		}
		if row.ToolName == "" || len(row.ToolName) > auditFieldBytes {
			t.Errorf("tool_name is %d bytes; the row must name the client's tool and bound it", len(row.ToolName))
		}
	}

	// The row and the reply are the only cost of sending one of these, so both
	// are bounded whatever the client sends. 4 MiB rather than 8: the body
	// limit in serve is 8 MiB, and a body cut in half is a parse error, which
	// would be a different test.
	t.Run("an enormous name", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"alpha": {"search"}}, nil, nil, nil)
		huge := strings.Repeat("z", 4<<20)
		rr := f.post(toolCall("1", huge))
		if n := rr.Body.Len(); n > 1024 {
			t.Errorf("the reply is %d bytes; the echo must be bounded", n)
		}
		if !f.upstreamsIdle() {
			t.Error("an enormous name reached a member")
		}
		row := f.waitAudit(models.LogFilter{})[0]
		if len(row.ToolName) > auditFieldBytes {
			t.Errorf("tool_name is %d bytes, want at most %d", len(row.ToolName), auditFieldBytes)
		}
		var marker struct {
			Truncated bool `json:"truncated"`
			Bytes     int  `json:"bytes"`
		}
		if err := json.Unmarshal(row.Params, &marker); err != nil {
			t.Fatalf("params=%.120q: %v", row.Params, err)
		}
		if !marker.Truncated || marker.Bytes < 4<<20 {
			t.Errorf("params=%.120q want a truncation marker naming the original size", row.Params)
		}
	})
}

// The other half of the same promise, for a name that IS an identity but names
// no tool the group holds, an unknown slug, a member that could not be listed,
// a tool that has gone. This one is answered after the catalogues have been
// fetched, so it is not free; the reply and the row are bounded all the same,
// because the string in them is still the client's.
func TestAggregateRouteMissIsBounded(t *testing.T) {
	t.Run("an enormous tool name under a valid slug", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"alpha": {"search"}}, nil, nil, nil)
		huge := "x__" + strings.Repeat("z", 4<<20)

		rr := f.post(toolCall("1", huge))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%.200s", rr.Code, rr.Body.String())
		}
		if n := rr.Body.Len(); n > 1024 {
			t.Errorf("the reply is %d bytes; the echo must be bounded", n)
		}
		if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); code != codeInvalidParams {
			t.Errorf("rpc code=%d want %d", code, codeInvalidParams)
		}
		if got := f.count("alpha", "tools/call", ""); got != 0 {
			t.Errorf("alpha ran %d calls for a name it does not advertise", got)
		}
		row := f.waitAudit(models.LogFilter{})[0]
		if row.Status != models.StatusError {
			t.Errorf("status=%q want %q", row.Status, models.StatusError)
		}
		if len(row.ToolName) > auditFieldBytes {
			t.Errorf("tool_name is %d bytes, want at most %d", len(row.ToolName), auditFieldBytes)
		}
		if len(row.ErrorMessage) > auditFieldBytes*2 {
			t.Errorf("error_message is %d bytes; the client's string must be bounded there too", len(row.ErrorMessage))
		}
		if !strings.Contains(string(row.Params), `"truncated":true`) {
			t.Errorf("params=%.120q want a truncation marker", row.Params)
		}
	})

	t.Run("a well-formed slug no member carries", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"alpha": {"search"}}, nil, nil, nil)

		rr := f.post(toolCall("1", "zzz__search"))
		code, msg, _ := rpcErrorOf(t, rr.Body.Bytes())
		if code != codeInvalidParams || msg != "unknown tool: zzz__search" {
			t.Errorf("code=%d message=%q want %d %q", code, msg, codeInvalidParams, "unknown tool: zzz__search")
		}
		if got := f.count("alpha", "tools/call", "search"); got != 0 {
			t.Errorf("alpha ran %d calls; the slug named no member", got)
		}
		row := f.waitAudit(models.LogFilter{})[0]
		if row.ToolName != "zzz__search" || row.UpstreamID != "" {
			t.Errorf("row tool_name=%q upstream_id=%q want zzz__search and no upstream", row.ToolName, row.UpstreamID)
		}
	})
}
