package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
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

// Acceptance criterion 4; security requirement 8. On a group's aggregate
// endpoint the client names a tool by its identity, and both halves of that
// identity are rewritten together on the way to the member: params.name by
// rewriteToolCallParams and Mcp-Name by memberRoutingHeaders, so the member
// compares a header and a body that agree. A member's own name that is not
// header-safe crosses sentinel-encoded, and a client that sent no Mcp-Name
// leaves the member seeing none.
func TestAggregateRewritesMcpName(t *testing.T) {
	members := map[string][]string{"github": {"create_issue"}, "docs": {"search"}, "alpha": {"créer"}}
	strict := func(name string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	}
	headers := func(name string) map[string]string {
		return map[string]string{
			"MCP-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             name,
		}
	}
	// theCall is the one tools/call a member received; the catalogue
	// requests the aggregate composes for itself are not it.
	theCall := func(t *testing.T, f *fixture, slug string) recordedRequest {
		t.Helper()
		var calls []recordedRequest
		for _, r := range f.requestsTo(slug) {
			if r.RPCMethod == "tools/call" {
				calls = append(calls, r)
			}
		}
		if len(calls) != 1 {
			t.Fatalf("%s saw %d tools/call requests, want 1", slug, len(calls))
		}
		return calls[0]
	}
	noCall := func(t *testing.T, f *fixture, slug string) {
		t.Helper()
		for _, r := range f.requestsTo(slug) {
			if r.RPCMethod == "tools/call" {
				t.Errorf("%s saw a tools/call it was not the target of", slug)
			}
		}
	}

	t.Run("the composed name becomes the member's own in both places", func(t *testing.T) {
		f := newGroupFixture(t, members, nil, nil, nil)
		rr := f.postWith(strict("github__create_issue"), headers("github__create_issue"))
		assertNotBlocked(t, rr, "a strict tools/call by identity")
		got := theCall(t, f, "github")
		if v := got.Header.Get("Mcp-Name"); v != "create_issue" {
			t.Errorf("github saw Mcp-Name=%q want create_issue", v)
		}
		if v := got.Header.Get("Mcp-Method"); v != "tools/call" {
			t.Errorf("github saw Mcp-Method=%q want tools/call", v)
		}
		var sent struct {
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.Unmarshal(got.Body, &sent); err != nil || sent.Params.Name != "create_issue" {
			t.Errorf("github saw params.name=%q (err=%v) want create_issue", sent.Params.Name, err)
		}
		noCall(t, f, "docs")
		noCall(t, f, "alpha")
	})

	t.Run("a name that is not header-safe crosses sentinel-encoded", func(t *testing.T) {
		f := newGroupFixture(t, members, nil, nil, nil)
		rr := f.postWith(strict("alpha__créer"), headers(encodeHeaderValue("alpha__créer")))
		assertNotBlocked(t, rr, "a strict tools/call naming a non-ASCII tool")
		got := theCall(t, f, "alpha")
		if v := got.Header.Get("Mcp-Name"); v != "=?base64?Y3LDqWVy?=" {
			t.Errorf("alpha saw Mcp-Name=%q want the sentinel form of its own name", v)
		}
		if dec, ok := decodeHeaderValue(got.Header.Get("Mcp-Name")); !ok || dec != "créer" {
			t.Errorf("decoded=%q ok=%v want créer", dec, ok)
		}
	})

	t.Run("a client that sent no Mcp-Name leaves the member seeing none", func(t *testing.T) {
		f := newGroupFixture(t, members, nil, nil, nil)
		assertNotBlocked(t, f.post(toolCall("1", "github__create_issue")), "a legacy tools/call by identity")
		got := theCall(t, f, "github")
		if v := got.Header.Get("Mcp-Name"); v != "" {
			t.Errorf("github saw Mcp-Name=%q on a call whose client sent none", v)
		}
	})
}

// Acceptance criterion 6, the aggregate's half. The merged list is PoryMCP's
// own document and carries the revision's cache and result fields: private,
// because it is composed per key, and complete, because no client input is
// needed to finish it. ttlMs is PORM-153's and is not pinned either way.
func TestAggregateListIsPrivate(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"search"}, "beta": {"lookup"}}, nil, nil, nil)
	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		Result struct {
			CacheScope string `json:"cacheScope"`
			ResultType string `json:"resultType"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rr.Body.String())
	}
	if env.Result.CacheScope != "private" || env.Result.ResultType != "complete" {
		t.Errorf("cacheScope=%q resultType=%q want private and complete", env.Result.CacheScope, env.Result.ResultType)
	}
	if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != "alpha__search,beta__lookup" {
		t.Errorf("listed %q want both members' tools beside the new members", got)
	}
}

// eraGroup is a group of four members, one per kind of era verdict: alpha is
// a handshake server, dead refuses every connection, modern speaks only
// 2026-07-28, and refused answers the era probe with -32022 and a version
// PoryMCP does not speak. Sorted by slug they are u1 to u4.
//
// modern's stored credential is a custom auth_config that names the two
// headers a modern request declares itself with. The API has refused such a
// config on write since PORM-150, but a row saved before that still holds one,
// and on this plane nothing but the order of two lines in listTools stops it
// choosing what a member is told (PORM-151 security requirement 9).
func eraGroup(t *testing.T) *fixture {
	t.Helper()
	return newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"search"}},
		"dead":  {Tools: []string{"unreachable"}, Dead: true},
		"modern": {
			Tools: []string{"lookup"}, Modern: true,
			AuthType: models.AuthCustom,
			AuthConfig: models.AuthConfig{Headers: map[string]string{
				"X-Stored-Key":         "REAL-CUSTOM-SECRET",
				"Mcp-Method":           "resources/read",
				"MCP-Protocol-Version": "2099-01-01",
			}},
		},
		"refused": {
			Tools:        []string{"never"},
			DiscoverCode: http.StatusBadRequest,
			DiscoverBody: `{"jsonrpc":"2.0","id":null,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2027-01-01"]}}}`,
		},
	}, true, nil, nil, nil)
}

// PORM-151 criterion 8, as amended, and security requirements 8, 9 and 10. A
// group lists a modern member and a handshake member side by side, each the
// way it speaks; the era is asked once and remembered; a member that stops
// listing is asked again after the retry floor and not before; saving the
// upstream forgets what was learned; and a modern member that cannot be
// spoken to is skipped without a catalogue request.
func TestListToolsEraCache(t *testing.T) {
	f := eraGroup(t)
	logs := captureLogs(f)
	base := time.Now()
	now := base
	f.H.eras.SetClock(func() time.Time { return now })
	probes := func(slug string) int { return f.count(slug, "server/discover", "") }
	// dead's stub is closed and counts nothing, so its probes are read off the
	// one line every probe writes.
	deadProbes := func() int {
		t.Helper()
		n := 0
		for _, r := range logRecords(t, logs) {
			if r["msg"] == "member era probed" && r["slug"] == "dead" {
				if r["reached"] != false || r["era"] != "legacy" {
					t.Errorf("dead's probe logged reached=%v era=%v, want false and legacy", r["reached"], r["era"])
				}
				n++
			}
		}
		return n
	}
	list := func() string {
		t.Helper()
		rr := f.post(listRequest)
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		return strings.Join(listedNames(t, rr.Body.Bytes()), ",")
	}

	if got := list(); got != "alpha__search,modern__lookup" {
		t.Fatalf("listed %q, want both eras' tools", got)
	}

	// The modern member: the probe, then a catalogue request that declares
	// itself and carries _meta.
	reqs := f.requestsTo("modern")
	if len(reqs) != 2 || reqs[0].RPCMethod != "server/discover" || reqs[1].RPCMethod != "tools/list" {
		t.Fatalf("modern saw %d requests, want the probe then the listing: %+v", len(reqs), reqs)
	}
	for _, r := range reqs {
		if v := r.Header.Get("Mcp-Protocol-Version"); v != mcpclient.RevisionModern {
			t.Errorf("modern: %s declared version %q, want %q", r.RPCMethod, v, mcpclient.RevisionModern)
		}
		if v := r.Header.Get("Mcp-Method"); v != r.RPCMethod {
			t.Errorf("modern: %s carried Mcp-Method %q", r.RPCMethod, v)
		}
		var body struct {
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.Unmarshal(r.Body, &body); err != nil || len(body.Params.Meta) != 3 {
			t.Errorf("modern: %s body carries no _meta: %s", r.RPCMethod, r.Body)
		}
		// The stored credential rode along, and its two protocol headers lost
		// to the proxy's own, which are written after it.
		if v := r.Header.Get("X-Stored-Key"); v != "REAL-CUSTOM-SECRET" {
			t.Errorf("modern: %s carried X-Stored-Key %q, want the stored credential", r.RPCMethod, v)
		}
	}

	// The handshake member: the probe it does not know, then exactly the
	// request it has always received.
	reqs = f.requestsTo("alpha")
	if len(reqs) != 2 || reqs[0].RPCMethod != "server/discover" {
		t.Fatalf("alpha saw %d requests, want the probe then the listing: %+v", len(reqs), reqs)
	}
	if got := string(reqs[1].Body); got != listToolsRequest {
		t.Errorf("alpha's catalogue request is %s, want the legacy bytes %s", got, listToolsRequest)
	}
	for _, h := range []string{"Mcp-Method", "Mcp-Protocol-Version"} {
		if v := reqs[1].Header.Get(h); v != "" {
			t.Errorf("alpha's catalogue request carried %s %q; a handshake member gets none", h, v)
		}
	}

	// The member that cannot be spoken to: probed, never listed.
	if n := f.count("refused", "tools/list", ""); n != 0 || probes("refused") != 1 {
		t.Errorf("refused saw %d tools/list and %d probes, want 0 and 1", n, probes("refused"))
	}

	// The member nothing answers for: probed once, skipped, and not an error.
	if n := deadProbes(); n != 1 {
		t.Errorf("dead was probed %d times on the first call, want 1", n)
	}

	// A second call asks nobody's era again, and lists the modern member from
	// the CACHED verdict: the names prove the cached era and version composed
	// a request the member accepted, which a probe count alone would not.
	if got := list(); got != "alpha__search,modern__lookup" {
		t.Fatalf("second call listed %q, want both eras' tools again", got)
	}
	for _, slug := range []string{"alpha", "modern", "refused"} {
		if n := probes(slug); n != 1 {
			t.Errorf("%s saw %d probes after a second call, want 1", slug, n)
		}
	}
	if n := deadProbes(); n != 1 {
		t.Errorf("dead was probed %d times after a second call, want 1", n)
	}
	if reqs := f.requestsTo("modern"); len(reqs) != 3 || reqs[2].Header.Get("Mcp-Method") != "tools/list" ||
		reqs[2].Header.Get("Mcp-Protocol-Version") != mcpclient.RevisionModern {
		t.Errorf("modern's listing from the cached verdict did not declare itself: %+v", reqs[len(reqs)-1].Header)
	}

	// modern's listing starts failing. Inside the retry floor it is listed the
	// way the verdict says and not asked again, however many calls arrive.
	f.Stubs["modern"].failListing(true)
	if got := list(); got != "alpha__search" {
		t.Fatalf("listed %q, want alpha alone while modern fails", got)
	}
	now = base.Add(eraRetry - time.Second)
	_ = list()
	if n := probes("modern"); n != 1 {
		t.Errorf("modern saw %d probes inside the retry floor, want 1: a failing member must not cost a probe per call", n)
	}
	if n := deadProbes(); n != 1 {
		t.Errorf("dead was probed %d times inside the retry floor, want 1: a probe nothing answered lives thirty seconds", n)
	}
	// Past the floor, the first call asks again. So does the refused member's.
	now = base.Add(eraRetry + time.Second)
	_ = list()
	if n := probes("modern"); n != 2 {
		t.Errorf("modern saw %d probes after the retry floor, want 2", n)
	}
	if n := probes("refused"); n != 2 {
		t.Errorf("refused saw %d probes after the retry floor, want 2", n)
	}
	if n := deadProbes(); n != 2 {
		t.Errorf("dead was probed %d times after the retry floor, want 2: thirty seconds, not ten minutes", n)
	}
	if n := probes("alpha"); n != 1 {
		t.Errorf("alpha saw %d probes; a healthy member's verdict lasts ten minutes", n)
	}
	f.Stubs["modern"].failListing(false)
	if got := list(); got != "alpha__search,modern__lookup" {
		t.Fatalf("listed %q once modern recovered, want both eras' tools", got)
	}

	// Saving the upstream moves updated_at, and that is a miss. Through the
	// real store, with nothing but updated_at changed.
	ctx := t.Context()
	up, err := f.Store.GetUpstream(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	up.UpdatedAt = up.UpdatedAt.Add(time.Second)
	if err := f.Store.UpdateUpstream(ctx, up, store.KeepTest, store.KeepAuth); err != nil {
		t.Fatal(err)
	}
	_ = list()
	if n := probes("alpha"); n != 2 {
		t.Errorf("alpha saw %d probes after it was saved, want 2", n)
	}

	// And a healthy verdict is asked again when its ten minutes are up.
	now = now.Add(eraTTL + time.Second)
	_ = list()
	if n := probes("alpha"); n != 3 {
		t.Errorf("alpha saw %d probes after the verdict expired, want 3", n)
	}
}

// The boundary PORM-151 ships with, pinned so it is a named fact and not a
// surprise: a group lists a modern-only member's tools, and a call to one is
// still the CLIENT's request, relayed with the client's headers and body. A
// handshake-era client sends neither the routing headers nor _meta, so the
// member refuses the call with -32020. Composing a modern call on a legacy
// client's behalf belongs to PORM-153.
func TestGroupCallToModernMemberFromLegacyClient(t *testing.T) {
	// Its own group, with no stored credential: eraGroup's modern member holds
	// a custom auth_config naming Mcp-Method, which the relay path writes onto
	// the client's call as it always has, and that is not what is under test.
	f := newFixture(t, map[string]upstreamSpec{
		"alpha":  {Tools: []string{"search"}},
		"modern": {Tools: []string{"lookup"}, Modern: true},
	}, true, nil, nil, nil)
	rr := f.post(toolCall("7", "modern__lookup"))

	calls := 0
	for _, r := range f.requestsTo("modern") {
		if r.RPCMethod != "tools/call" {
			continue
		}
		calls++
		if v := r.Header.Get("Mcp-Method"); v != "" {
			t.Errorf("the relayed call carried Mcp-Method %q; the proxy composed nothing for the client", v)
		}
	}
	if calls != 1 {
		t.Fatalf("modern saw %d tools/call, want the one relayed call", calls)
	}
	code, _, _ := rpcErrorOf(t, rr.Body.Bytes())
	if code != mcpclient.CodeHeaderMismatch {
		t.Errorf("client got JSON-RPC code %d, want the member's own %d; body=%s", code, mcpclient.CodeHeaderMismatch, rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{})[0]
	if row.Status != models.StatusError || row.ToolName != "modern__lookup" {
		t.Errorf("audit row status=%q tool=%q, want an error row naming the tool", row.Status, row.ToolName)
	}
}

// cancelAfterAnswer is a transport that cancels a context once an upstream has
// answered in full, which is a client hanging up just after a member's probe
// came back. The body is read and replaced first, so the cancellation cannot
// turn an answered probe into a failed read.
type cancelAfterAnswer struct {
	next   http.RoundTripper
	cancel context.CancelFunc
}

func (c cancelAfterAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if err != nil {
		return resp, err
	}
	body, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if rerr != nil {
		return nil, rerr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	c.cancel()
	return resp, nil
}

// A verdict is remembered unless the caller going away is the reason there is
// none. A probe that was answered is kept even when nobody waited for it:
// otherwise a client that always hangs up early costs a member one probe per
// call, with no retry floor, which docs/07-security.md says cannot happen.
func TestMemberEraAndACallerWhoWentAway(t *testing.T) {
	f := eraGroup(t)
	logs := captureLogs(f)
	up, err := f.Store.GetUpstream(t.Context(), "u1") // alpha, auth none
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the probe was answered", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		real := f.H.client.Transport
		f.H.client.Transport = cancelAfterAnswer{next: real, cancel: cancel}
		got := f.H.memberEra(ctx, up, nil)
		f.H.client.Transport = real
		if ctx.Err() == nil {
			t.Fatal("the context was never cancelled; the test proves nothing")
		}
		if got.era != mcpclient.EraLegacy {
			t.Fatalf("verdict era=%q, want legacy", got.era)
		}
		if _, ok := f.H.eras.get(up.ID, up.UpdatedAt); !ok {
			t.Error("an answered probe was not remembered because its caller had gone")
		}
		_ = f.H.memberEra(t.Context(), up, nil)
		if n := f.count("alpha", "server/discover", ""); n != 1 {
			t.Errorf("alpha saw %d probes, want 1: the second lookup should have hit", n)
		}
	})

	t.Run("the caller's going away is why nothing answered", func(t *testing.T) {
		gone, cancel := context.WithCancel(t.Context())
		cancel()
		dead, err := f.Store.GetUpstream(t.Context(), "u2")
		if err != nil {
			t.Fatal(err)
		}
		got := f.H.memberEra(gone, dead, nil)
		if got.era != mcpclient.EraLegacy {
			t.Fatalf("verdict era=%q, want the legacy fallback", got.era)
		}
		if _, ok := f.H.eras.get(dead.ID, dead.UpdatedAt); ok {
			t.Error("nothing-answered was remembered against a member whose caller had simply gone")
		}
	})

	// A probe nothing answered, with the caller still there, is remembered for
	// the retry floor and not for ten minutes. Read off the entry itself,
	// straight after the probe: in a group walk the listing that follows fails
	// too and retrySoon reaches the same expiry, so only this tells the two
	// apart. docs/04-architecture.md promises thirty seconds for a member that
	// never answers the probe and then lists fine.
	t.Run("nothing answered, and the caller waited", func(t *testing.T) {
		now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
		f.H.eras.SetClock(func() time.Time { return now })
		defer f.H.eras.SetClock(nil)
		dead, err := f.Store.GetUpstream(t.Context(), "u2")
		if err != nil {
			t.Fatal(err)
		}
		_ = f.H.memberEra(t.Context(), dead, nil)
		got, ok := f.H.eras.get(dead.ID, dead.UpdatedAt)
		if !ok {
			t.Fatal("an unanswered probe was not remembered at all; every call would probe again")
		}
		if want := now.Add(eraRetry); !got.expires.Equal(want) {
			t.Errorf("entry expires %v after now, want the %v retry floor", got.expires.Sub(now), eraRetry)
		}
	})

	// One line per probe that was sent, the unremembered one included.
	n := 0
	for _, r := range logRecords(t, logs) {
		if r["msg"] == "member era probed" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d member era probed lines, want 3: one per probe, whether or not it was remembered", n)
	}
}
