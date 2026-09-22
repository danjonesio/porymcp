package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
// rewriteToolCallParams and Mcp-Name by memberCallHeaders, so the member
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

// theCallTo is the one tools/call a member received; the catalogue requests and
// probes the aggregate composes for itself are not it.
func theCallTo(t *testing.T, f *fixture, slug string) recordedRequest {
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

// callMeta is params._meta of a recorded tools/call, member by member.
func callMeta(t *testing.T, r recordedRequest) (name string, meta map[string]json.RawMessage) {
	t.Helper()
	var body struct {
		Params struct {
			Name string                     `json:"name"`
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatalf("the member's request body is not JSON: %v (%s)", err, r.Body)
	}
	return body.Params.Name, body.Params.Meta
}

var reservedMeta = []string{
	"io.modelcontextprotocol/protocolVersion",
	"io.modelcontextprotocol/clientInfo",
	"io.modelcontextprotocol/clientCapabilities",
}

// PORM-153. The boundary PORM-151 shipped with, removed: a group listed a
// modern-only member's tools, and a call to one was the client's own request
// relayed as sent, which a handshake-era client's is refused for with -32020.
// The group endpoint now composes that call for the member's era.
//
// Security requirements 3 and 5. It is eraGroup's modern member on purpose: its
// stored custom auth_config names Mcp-Method and MCP-Protocol-Version, and what
// the member reads has to be PoryMCP's values and not the stored ones.
func TestAggregateLegacyClientModernMember(t *testing.T) {
	f := eraGroup(t)
	rr := f.post(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"modern__lookup","arguments":{"q":"x"},"_meta":{"progressToken":"tok-1"}}}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("HTTP code=%d body=%s, want the member's answer", rr.Code, rr.Body.String())
	}

	call := theCallTo(t, f, "modern")
	for name, want := range map[string]string{
		"Mcp-Protocol-Version": mcpclient.RevisionModern,
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "lookup",
		"X-Stored-Key":         "REAL-CUSTOM-SECRET",
	} {
		if got := call.Header.Get(name); got != want {
			t.Errorf("the member read %s %q, want %q", name, got, want)
		}
	}
	name, meta := callMeta(t, call)
	if name != "lookup" {
		t.Errorf("params.name=%q want the member's own name", name)
	}
	for _, k := range reservedMeta {
		if len(meta[k]) == 0 {
			t.Errorf("params._meta lacks %s: %s", k, call.Body)
		}
	}
	if v, _ := jsonString(meta["io.modelcontextprotocol/protocolVersion"]); v != mcpclient.RevisionModern {
		t.Errorf("_meta version %q, want the same constant the header carries", v)
	}
	// _meta is an object, not the object's text in a string, and what the
	// client put there is still there.
	if string(meta["progressToken"]) != `"tok-1"` {
		t.Errorf("the client's progressToken did not cross: %s", call.Body)
	}
	row := f.waitAudit(models.LogFilter{Method: "tools/call"})[0]
	if row.Status != models.StatusSuccess || row.ToolName != "modern__lookup" || row.UpstreamID != "u3" {
		t.Errorf("row status=%q tool=%q upstream=%q, want a normal success row against the member", row.Status, row.ToolName, row.UpstreamID)
	}
}

// The issue's own case, and the one the merge cannot reach: a handshake-era
// client that sends no _meta at all. And the case a merge invites: a client
// whose _meta spells a reserved member another way, which the version check
// reads and an exact-key write would leave beside PoryMCP's own.
func TestAggregateComposedMeta(t *testing.T) {
	group := func(t *testing.T) *fixture {
		t.Helper()
		return newFixture(t, map[string]upstreamSpec{
			"alpha":  {Tools: []string{"search"}},
			"modern": {Tools: []string{"lookup"}, Modern: true},
		}, true, nil, nil, nil)
	}
	t.Run("no _meta at all", func(t *testing.T) {
		f := group(t)
		rr := f.post(toolCall("7", "modern__lookup"))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok":true`) {
			t.Fatalf("HTTP code=%d body=%s, want the member's answer", rr.Code, rr.Body.String())
		}
		_, meta := callMeta(t, theCallTo(t, f, "modern"))
		if len(meta) != len(reservedMeta) {
			t.Errorf("_meta=%v, want exactly the three reserved members", meta)
		}
		if string(meta["io.modelcontextprotocol/clientCapabilities"]) != "{}" {
			t.Errorf("clientCapabilities=%s want an empty object", meta["io.modelcontextprotocol/clientCapabilities"])
		}
		var info struct{ Name, Version string }
		if json.Unmarshal(meta["io.modelcontextprotocol/clientInfo"], &info) != nil || info.Name != "porymcp" || info.Version == "" {
			t.Errorf("clientInfo=%s want PoryMCP's own", meta["io.modelcontextprotocol/clientInfo"])
		}
	})
	t.Run("a handshake client's case-variant version does not sit beside PoryMCP's", func(t *testing.T) {
		f := group(t)
		f.post(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"modern__lookup","_meta":{"IO.ModelContextProtocol/ProtocolVersion":"2025-11-25","progressToken":1}}}`)
		_, meta := callMeta(t, theCallTo(t, f, "modern"))
		for k := range meta {
			if strings.EqualFold(k, "io.modelcontextprotocol/protocolVersion") && k != "io.modelcontextprotocol/protocolVersion" {
				t.Errorf("_meta still carries %q beside the composed version: %v", k, meta)
			}
		}
		if string(meta["progressToken"]) != "1" {
			t.Errorf("the client's progressToken did not cross: %v", meta)
		}
	})
	t.Run("a modern client's case-variant members do not reach a handshake member", func(t *testing.T) {
		f := group(t)
		f.postWith(
			`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"alpha__search","_meta":{"IO.ModelContextProtocol/ProtocolVersion":"2026-07-28","Io.Modelcontextprotocol/ClientInfo":{"name":"c","version":"1"},"progressToken":2}}}`,
			map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "alpha__search"})
		_, meta := callMeta(t, theCallTo(t, f, "alpha"))
		for k := range meta {
			if strings.HasPrefix(strings.ToLower(k), "io.modelcontextprotocol/") {
				t.Errorf("the handshake member was sent the reserved member %q: %v", k, meta)
			}
		}
		if string(meta["progressToken"]) != "2" {
			t.Errorf("the client's progressToken did not cross: %v", meta)
		}
	})
}

// PORM-153, amendment A1. Once the group endpoint answers server/discover, a
// modern client speaks 2026-07-28 for every call, and a handshake-era member
// MUST refuse a version header it does not support: hosted Firecrawl answered
// one with -32000. So the call is composed for that member's era too.
func TestAggregateModernClientLegacyMember(t *testing.T) {
	const call = `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"alpha__search","arguments":{"q":"x"},"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"claude-code","version":"2"},` +
		`"io.modelcontextprotocol/clientCapabilities":{},"progressToken":"tok-2"}}}`
	headers := map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "alpha__search",
		"Mcp-Param-Region":     "eu",
	}
	probes := func(f *fixture) int { return f.count("alpha", "server/discover", "") }

	t.Run("the member is sent a handshake-era call", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha":  {Tools: []string{"search"}},
			"modern": {Tools: []string{"lookup"}, Modern: true},
		}, true, nil, nil, nil)
		body, hdr := modernRequest("1", "tools/list", mcpclient.RevisionModern)
		f.postWith(body, hdr)
		before := probes(f)

		rr := f.postWith(call, headers)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok":true`) {
			t.Fatalf("HTTP code=%d body=%s, want the member's answer", rr.Code, rr.Body.String())
		}
		// To this client the group endpoint is a 2026-07-28 server, and the
		// revision requires resultType on every result such a server sends. The
		// handshake member sent none, and the reference SDK refuses a result
		// without one from a server that declared the stateless revision.
		if !strings.Contains(rr.Body.String(), `"resultType":"complete"`) {
			t.Errorf("body=%s, want the result completed with a resultType", rr.Body.String())
		}
		got := theCallTo(t, f, "alpha")
		if v, sent := got.Header["Mcp-Protocol-Version"]; sent {
			t.Errorf("the member was sent MCP-Protocol-Version %q; a handshake server must refuse a version it does not speak", v)
		}
		// What still crosses, stated so it reads as a decision: a handshake
		// server ignores names it does not know, and the revision tells an
		// intermediary to forward Mcp-Param-.
		for name, want := range map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "search", "Mcp-Param-Region": "eu"} {
			if v := got.Header.Get(name); v != want {
				t.Errorf("the member read %s %q, want %q", name, v, want)
			}
		}
		name, meta := callMeta(t, got)
		if name != "search" {
			t.Errorf("params.name=%q want the member's own name", name)
		}
		for _, k := range reservedMeta {
			if _, present := meta[k]; present {
				t.Errorf("params._meta still declares %s to a handshake member: %s", k, got.Body)
			}
		}
		if string(meta["progressToken"]) != `"tok-2"` {
			t.Errorf("the client's progressToken did not cross: %s", got.Body)
		}
		// Security requirement 12: the era came from the cache. The call sent
		// no probe of its own.
		if after := probes(f); after != before {
			t.Errorf("alpha saw %d probes before the call and %d after it", before, after)
		}
		row := f.waitAudit(models.LogFilter{Method: "tools/call"})[0]
		if row.Status != models.StatusSuccess || row.UpstreamID != "u1" {
			t.Errorf("row status=%q upstream=%q, want success against alpha", row.Status, row.UpstreamID)
		}
	})

	t.Run("a _meta of nothing but the reserved members goes altogether", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{"alpha": {Tools: []string{"search"}}}, true, nil, nil, nil)
		f.postWith(strings.Replace(call, `,"progressToken":"tok-2"`, "", 1), headers)
		if _, meta := callMeta(t, theCallTo(t, f, "alpha")); meta != nil {
			t.Errorf("an empty _meta was left behind: %v", meta)
		}
	})

	t.Run("a member that still refuses is relayed as it answers", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{"alpha": {
			Tools: []string{"search"}, CallCode: http.StatusBadRequest,
			CallBody: `{"jsonrpc":"2.0","id":8,"error":{"code":-32000,"message":"Bad Request: Server not initialized"}}`,
		}}, true, nil, nil, nil)
		rr := f.postWith(call, headers)
		if code, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); rr.Code != http.StatusBadRequest || code != -32000 || msg != "Bad Request: Server not initialized" {
			t.Errorf("HTTP code=%d rpc code=%d message=%q, want the member's own refusal", rr.Code, code, msg)
		}
		row := f.waitAudit(models.LogFilter{Method: "tools/call"})[0]
		if row.Status != models.StatusError || row.ErrorMessage != "Bad Request: Server not initialized" {
			t.Errorf("row status=%q error=%q, want an error row with the member's message", row.Status, row.ErrorMessage)
		}
	})
}

// memberCallHeaders, row by row, the cache miss included. Within one request
// the catalogue walk has just stored the verdict, so a miss needs an eviction
// at the bound under concurrent load; it cannot be staged through serve, and
// it must still relay the client's request as it came and never probe.
func TestMemberCallHeaders(t *testing.T) {
	modern := eraVerdict{era: mcpclient.EraModern, version: mcpclient.RevisionModern}
	unusable := eraVerdict{era: mcpclient.EraModern, fail: "upstream supports no protocol version PoryMCP speaks"}
	legacy := eraVerdict{era: mcpclient.EraLegacy}
	named := http.Header{"Mcp-Name": {"alpha__search"}, "Mcp-Protocol-Version": {"2026-07-28"}}
	unnamed := http.Header{}

	for _, c := range []struct {
		name         string
		src          http.Header
		v            eraVerdict
		known        bool
		clientModern bool
		wantSet      map[string]string
		wantDrop     string
		wantMeta     metaAction
	}{
		{"legacy client, modern member", unnamed, modern, true, false,
			map[string]string{"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "search"}, "", metaCompose},
		{"modern client, legacy member, name sent", named, legacy, true, true, map[string]string{"Mcp-Name": "search"}, "Mcp-Protocol-Version", metaStrip},
		{"modern client, legacy member, no name sent", unnamed, legacy, true, true, nil, "Mcp-Protocol-Version", metaStrip},
		{"modern client, modern member", named, modern, true, true, map[string]string{"Mcp-Name": "search"}, "", metaKeep},
		{"legacy client, legacy member, name sent", named, legacy, true, false, map[string]string{"Mcp-Name": "search"}, "", metaKeep},
		{"legacy client, legacy member, no name sent", unnamed, legacy, true, false, nil, "", metaKeep},
		{"legacy client, a modern member that cannot be spoken to", unnamed, unusable, true, false, nil, "", metaKeep},
		{"cache miss, modern client", named, eraVerdict{}, false, true, map[string]string{"Mcp-Name": "search"}, "", metaKeep},
		{"cache miss, legacy client", unnamed, modern, false, false, nil, "", metaKeep},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, meta := memberCallHeaders(c.src, "search", c.v, c.known, c.clientModern)
			if meta != c.wantMeta {
				t.Errorf("meta action %d, want %d", meta, c.wantMeta)
			}
			if c.wantSet == nil && c.wantDrop == "" {
				if got != nil {
					t.Errorf("got %+v, want nil: the client's request relayed as it came", got)
				}
				return
			}
			if got == nil {
				t.Fatal("got nil")
			}
			if len(got.set) != len(c.wantSet) {
				t.Errorf("set=%v want %v", got.set, c.wantSet)
			}
			for k, v := range c.wantSet {
				if got.set.Get(k) != v {
					t.Errorf("set %s=%q want %q", k, got.set.Get(k), v)
				}
			}
			if strings.Join(got.drop, ",") != c.wantDrop {
				t.Errorf("drop=%v want %q", got.drop, c.wantDrop)
			}
		})
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

// sseFrame frames one JSON-RPC document the way the reference SDKs do.
func sseFrame(doc string) string { return "event: message\ndata: " + doc + "\n\n" }

// sseCatalogue is a tools/list answer to the proxy's own request (id 1) naming
// the given tools, as one JSON document.
func sseCatalogue(id string, names ...string) string {
	tools := make([]string, 0, len(names))
	for _, n := range names {
		tools = append(tools, `{"name":"`+n+`"}`)
	}
	return `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[` + strings.Join(tools, ",") + `]}}`
}

// skipWarnings is the "group member skipped" records in what captureLogs kept.
func skipWarnings(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range logRecords(t, logs) {
		if r["msg"] == "group member skipped" {
			out = append(out, r)
		}
	}
	return out
}

// PORM-171. A group used to drop any member that answered tools/list as an
// event stream, which is what the reference SDKs do by default: the member's
// tools never appeared on the aggregate endpoint and could not be called
// through it, while the same upstream listed everywhere else. The answer is now
// reduced to the one document that answers the proxy's request, by mcpclient's
// reader, whichever framing the member chose.
func TestGroupListsMemberAnsweringInSSE(t *testing.T) {
	const notification = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"warming up"}}`
	const sse = "text/event-stream"

	t.Run("a JSON member and an SSE member both list, and a call routes to the SSE member", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search_docs"}},
			"beta":  {ListCT: sse, RawList: sseFrame(sseCatalogue("1", "scrape", "crawl"))},
		}, true, nil, nil, nil)
		logs := captureLogs(f)

		rr := f.post(listRequest)
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got, want := strings.Join(listedNames(t, rr.Body.Bytes()), ","), "alpha__search_docs,beta__crawl,beta__scrape"; got != want {
			t.Errorf("listed %q want %q", got, want)
		}
		if w := skipWarnings(t, logs); len(w) != 0 {
			t.Errorf("a member was skipped: %v", w)
		}

		rr = f.post(toolCall("2", "beta__scrape"))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok":true`) {
			t.Fatalf("call: HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		if n := f.count("beta", "tools/call", "scrape"); n != 1 {
			t.Errorf("beta saw %d calls of scrape, want 1", n)
		}
		if n := f.count("alpha", "tools/call", "scrape") + f.count("alpha", "tools/call", "beta__scrape"); n != 0 {
			t.Errorf("alpha saw %d calls meant for beta", n)
		}
	})

	// Each row is one SSE member beside a JSON one, and what the group lists.
	for _, c := range []struct {
		name string
		spec upstreamSpec
		want string
	}{
		{
			name: "a notification ahead of the answer",
			spec: upstreamSpec{ListCT: sse, RawList: sseFrame(notification) + sseFrame(sseCatalogue("1", "scrape"))},
			want: "alpha__search_docs,beta__scrape",
		},
		{
			name: "another id's document ahead of the proxy's own",
			spec: upstreamSpec{ListCT: sse, RawList: sseFrame(sseCatalogue("9", "not_this")) + sseFrame(sseCatalogue("1", "scrape"))},
			want: "alpha__search_docs,beta__scrape",
		},
		{
			// The documented fallback: nothing carries the proxy's id, so the one
			// answering document is read. It cannot reach another member's names,
			// because every name is prefixed with this member's own slug.
			name: "a single document under another id",
			spec: upstreamSpec{ListCT: sse, RawList: sseFrame(sseCatalogue("9", "scrape"))},
			want: "alpha__search_docs,beta__scrape",
		},
		{
			name: "an event stream sent with no Content-Type at all",
			spec: upstreamSpec{ListCT: "-", RawList: sseFrame(sseCatalogue("1", "scrape"))},
			want: "alpha__search_docs,beta__scrape",
		},
		{
			name: "CRLF line endings and a data field over two lines",
			spec: upstreamSpec{ListCT: sse, RawList: "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\r\ndata: \"result\":{\"tools\":[{\"name\":\"scrape\"}]}}\r\n\r\n"},
			want: "alpha__search_docs,beta__scrape",
		},
		{
			// A lone document that answers nothing is a member with no tools, not
			// a member that failed: it lists nothing and nothing is logged.
			name: "one notification and nothing else",
			spec: upstreamSpec{ListCT: sse, RawList: sseFrame(notification)},
			want: "alpha__search_docs",
		},
		{
			name: "a modern member answering in an event stream",
			spec: upstreamSpec{Modern: true, ListCT: sse, RawList: sseFrame(
				`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"scrape"}],"resultType":"complete","ttlMs":60000,"cacheScope":"public"}}`)},
			want: "alpha__search_docs,beta__scrape",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, map[string]upstreamSpec{
				"alpha": {Tools: []string{"search_docs"}},
				"beta":  c.spec,
			}, true, nil, nil, nil)
			logs := captureLogs(f)
			rr := f.post(listRequest)
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
			}
			if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != c.want {
				t.Errorf("listed %q want %q", got, c.want)
			}
			if w := skipWarnings(t, logs); len(w) != 0 {
				t.Errorf("a member was skipped: %v", w)
			}
			if c.spec.Modern {
				// The verbatim answer sits behind the stub's era check, so the
				// member was still told its version and method.
				last := f.requestsTo("beta")[len(f.requestsTo("beta"))-1]
				if last.RPCMethod != "tools/list" || last.Header.Get("Mcp-Method") != "tools/list" ||
					last.Header.Get("Mcp-Protocol-Version") != mcpclient.RevisionModern {
					t.Errorf("the modern member's listing was not declared: %s %v", last.RPCMethod, last.Header)
				}
			}
		})
	}

	// What cannot be read skips the member, once, and the warning's err is one
	// of mcpclient's fixed sentences: compared with ==, because an event stream
	// is upstream-controlled text and none of it may reach a log line.
	for _, c := range []struct {
		name    string
		spec    upstreamSpec
		wantErr string
	}{
		{
			name:    "two notifications and no answer",
			spec:    upstreamSpec{ListCT: sse, RawList: sseFrame(notification) + sseFrame(notification)},
			wantErr: "response carried no answer to this request",
		},
		{
			name:    "a lone data line that is not JSON",
			spec:    upstreamSpec{ListCT: sse, RawList: "data: <b>SECRET-FROM-UPSTREAM</b>\n\n"},
			wantErr: "response carried no answer to this request",
		},
		{
			name:    "neither JSON nor an event stream",
			spec:    upstreamSpec{ListCT: "text/html", RawList: "<html>SECRET-FROM-UPSTREAM</html>"},
			wantErr: "media type is not a JSON-RPC response",
		},
		{
			name:    "an event stream with no data event",
			spec:    upstreamSpec{ListCT: sse, RawList: ": SECRET-FROM-UPSTREAM\n\n"},
			wantErr: "event stream carried no data event",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, map[string]upstreamSpec{
				"alpha": {Tools: []string{"search_docs"}},
				"beta":  c.spec,
			}, true, nil, nil, nil)
			logs := captureLogs(f)
			rr := f.post(listRequest)
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
			}
			if got, want := strings.Join(listedNames(t, rr.Body.Bytes()), ","), "alpha__search_docs"; got != want {
				t.Errorf("listed %q want %q: one member's unreadable answer must cost only that member", got, want)
			}
			w := skipWarnings(t, logs)
			if len(w) != 1 {
				t.Fatalf("%d skip warnings, want exactly 1: %s", len(w), logs.String())
			}
			if w[0]["slug"] != "beta" || w[0]["err"] != c.wantErr {
				t.Errorf("warning slug=%v err=%q, want beta and %q", w[0]["slug"], w[0]["err"], c.wantErr)
			}
			if strings.Contains(logs.String(), "SECRET-FROM-UPSTREAM") {
				t.Errorf("an upstream byte reached the log: %s", logs.String())
			}
		})
	}

	// A JSON-RPC error inside a frame is read as the error it is, and skips the
	// member with the upstream's own message, bounded, as the JSON path does.
	t.Run("a JSON-RPC error inside a frame", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search_docs"}},
			"beta":  {ListCT: sse, RawList: sseFrame(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Bad Request: Server not initialized"}}`)},
		}, true, nil, nil, nil)
		logs := captureLogs(f)
		rr := f.post(listRequest)
		if got, want := strings.Join(listedNames(t, rr.Body.Bytes()), ","), "alpha__search_docs"; got != want {
			t.Errorf("listed %q want %q", got, want)
		}
		w := skipWarnings(t, logs)
		if len(w) != 1 {
			t.Fatalf("%d skip warnings, want exactly 1: %s", len(w), logs.String())
		}
		if errText, _ := w[0]["err"].(string); !strings.Contains(errText, "Server not initialized") || len(errText) > auditFieldBytes {
			t.Errorf("warning err=%q, want the member's own message, bounded", errText)
		}
	})
}

// PORM-171, amendment A2. Listing an SSE member is no use if its tools cannot
// be called: aggregate returned no member headers, so a member's event-stream
// answer to a routed tools/call reached the group's client labelled
// application/json, and serve, reading it as JSON, audited a failed call as a
// success. The answer is now reduced to the one document the client asked for.
func TestAggregateCallFromSSEMember(t *testing.T) {
	const sse = "text/event-stream"
	list := sseFrame(sseCatalogue("1", "scrape"))
	group := func(t *testing.T, beta upstreamSpec) *fixture {
		t.Helper()
		return newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"search_docs"}},
			"beta":  beta,
		}, true, nil, nil, nil)
	}

	t.Run("the client is sent the one document, as JSON", func(t *testing.T) {
		const result = `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"scraped"}],"isError":false}}`
		f := group(t, upstreamSpec{
			// A member that frames everything, as the reference SDKs do, and
			// offers a session the group's client must never be handed.
			RespHeaders: map[string]string{"Content-Type": sse, "Mcp-Session-Id": "MEMBER-SESSION"},
			RawList:     list,
			CallBody:    sseFrame(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`) + sseFrame(result),
		})
		rr := f.post(toolCall("2", "beta__scrape"))
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type=%q want application/json", got)
		}
		if got := rr.Body.String(); got != result {
			t.Errorf("body=%q want the member's one answering document %q", got, result)
		}
		if got := rr.Header().Get("Mcp-Session-Id"); got != "" {
			t.Errorf("a member's Mcp-Session-Id %q reached a group client", got)
		}
		if row := methodRow(t, f, "tools/call"); row.Status != models.StatusSuccess || row.UpstreamID != "u2" {
			t.Errorf("row status=%q upstream=%q, want success against u2", row.Status, row.UpstreamID)
		}
	})

	t.Run("an error inside a frame is audited as the error it is", func(t *testing.T) {
		f := group(t, upstreamSpec{
			RespHeaders: map[string]string{"Content-Type": sse},
			RawList:     list,
			CallBody:    sseFrame(`{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"rate limit reached"}}`),
		})
		rr := f.post(toolCall("2", "beta__scrape"))
		if code, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); code != -32000 || msg != "rate limit reached" {
			t.Errorf("client saw code=%d message=%q, want the member's own error", code, msg)
		}
		if row := methodRow(t, f, "tools/call"); row.Status != models.StatusError || row.ErrorMessage != "rate limit reached" {
			t.Errorf("row status=%q error=%q, want error and the member's message", row.Status, row.ErrorMessage)
		}
	})

	// rewriteMethod re-marshals the envelope, so the member is sent, and echoes,
	// another spelling of an integer a float64 cannot hold. The wanted id is
	// read off what was sent, so the match still finds the answer behind a
	// decoy that the first-answer fallback would have picked.
	for _, c := range []struct{ name, id, echoed string }{
		{"an integer id past 2^53", "9007199254740993", "9007199254740992"},
		{"a string id", `"abc"`, `"abc"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			real := `{"jsonrpc":"2.0","id":` + c.echoed + `,"result":{"real":true}}`
			f := group(t, upstreamSpec{
				RespHeaders: map[string]string{"Content-Type": sse},
				RawList:     list,
				CallBody:    sseFrame(`{"jsonrpc":"2.0","id":5,"result":{"decoy":true}}`) + sseFrame(real),
			})
			rr := f.post(toolCall(c.id, "beta__scrape"))
			if got := rr.Body.String(); got != real {
				t.Errorf("body=%q want %q", got, real)
			}
		})
	}

	// Both eras of the transport say a 202 carries no body. The stub cannot send
	// an empty one (an empty CallBody means its default answer), so it sends a
	// space, and the client must be sent nothing at all.
	t.Run("a notification's 202 is passed on with no body", func(t *testing.T) {
		f := group(t, upstreamSpec{Tools: []string{"scrape"}, CallCode: http.StatusAccepted, CallBody: " "})
		rr := f.post(toolCall("", "beta__scrape"))
		if rr.Code != http.StatusAccepted || rr.Body.Len() != 0 {
			t.Errorf("HTTP code=%d body=%q, want 202 and zero bytes", rr.Code, rr.Body.String())
		}
	})

	// What cannot be reduced is passed on as it came, under a media type PoryMCP
	// writes itself. This is the one path where aggregate returns a header built
	// from a member's response, so it is where a member's session id could
	// cross if anything but that one name were copied. The row is judged by the
	// HTTP status alone, and the warning is the only place that says why.
	// PORM-172: the same table holds on a method the group relays to its first
	// member (alpha, u1), whose answer now goes through the same reader. The
	// warning names the bounded method the row carries.
	relays := []struct {
		method, slug, upstreamID string
		build                    func(t *testing.T, spec upstreamSpec) *fixture
		send                     func(f *fixture) *httptest.ResponseRecorder
	}{
		{"tools/call", "beta", "u2", group, func(f *fixture) *httptest.ResponseRecorder { return f.post(toolCall("2", "beta__scrape")) }},
		{"resources/read", "alpha", "u1", func(t *testing.T, spec upstreamSpec) *fixture {
			t.Helper()
			spec.RelayCT = spec.CallCT
			return newFixture(t, map[string]upstreamSpec{"alpha": spec, "beta": {Tools: []string{"other"}}}, true, nil, nil, nil)
		}, func(f *fixture) *httptest.ResponseRecorder { return f.post(relayRequest("2", "resources/read")) }},
	}
	for _, c := range []struct {
		name, callCT, body, wantCT, wantWhy string
	}{
		{"an event stream with no answer in it", sse + "; charset=utf-8", ": keepalive\n\n", sse, "event stream carried no data event"},
		{"an event stream sent with no Content-Type", "-", ": keepalive\n\n", sse, "event stream carried no data event"},
		{"a lone notification in answer to a call", sse, sseFrame(`{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"x"}}`), sse, "answer carried neither a result nor an error"},
		{"JSON that is not a JSON-RPC envelope", "application/json", `"NOT-AN-ENVELOPE"`, "application/json", "response carried no answer to this request"},
	} {
		for _, r := range relays {
			t.Run(c.name+" is relayed unreduced on "+r.method, func(t *testing.T) {
				f := r.build(t, upstreamSpec{
					Tools: []string{"scrape"}, CallCT: c.callCT, CallBody: c.body,
					RespHeaders: map[string]string{"Mcp-Session-Id": "MEMBER-SESSION"},
				})
				logs := captureLogs(f)
				rr := r.send(f)
				if rr.Code != http.StatusOK || rr.Body.String() != c.body {
					t.Errorf("HTTP code=%d body=%q, want 200 and the member's bytes", rr.Code, rr.Body.String())
				}
				// The bare media type PoryMCP chose, not the member's header value.
				if got := rr.Header().Get("Content-Type"); got != c.wantCT {
					t.Errorf("Content-Type=%q want %q", got, c.wantCT)
				}
				if got := rr.Header().Get("Mcp-Session-Id"); got != "" {
					t.Errorf("a member's Mcp-Session-Id %q reached a group client", got)
				}
				if row := methodRow(t, f, r.method); row.Status != models.StatusSuccess || row.UpstreamID != r.upstreamID {
					t.Errorf("row status=%q upstream=%q: an unreduced answer is judged by its HTTP status and its raw bytes, as it always was", row.Status, row.UpstreamID)
				}
				var warned []map[string]any
				for _, rec := range logRecords(t, logs) {
					if rec["msg"] == "group answer relayed unreduced" {
						warned = append(warned, rec)
					}
				}
				if len(warned) != 1 || warned[0]["slug"] != r.slug || warned[0]["err"] != c.wantWhy || warned[0]["method"] != r.method {
					t.Errorf("warnings=%v, want one for %s on %s with err %q", warned, r.slug, r.method, c.wantWhy)
				}
			})
		}
	}

	// A gateway in front of a member may label a bodyless 202. The member still
	// accepted the notification exactly as the transport requires, and a label
	// on zero bytes mislabels nothing.
	t.Run("a bodyless 202 with a stray Content-Type is still a 202", func(t *testing.T) {
		f := group(t, upstreamSpec{Tools: []string{"scrape"}, CallCode: http.StatusAccepted, CallCT: "text/plain", CallBody: " "})
		rr := f.post(toolCall("", "beta__scrape"))
		if rr.Code != http.StatusAccepted || rr.Body.Len() != 0 {
			t.Errorf("HTTP code=%d body=%q, want 202 and zero bytes", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); strings.Contains(got, "text/plain") {
			t.Errorf("Content-Type=%q: the member's label crossed", got)
		}
	})

	// The same third media type, reached by sending no label at all: a body that
	// is neither an event stream nor JSON is not sent out as JSON.
	t.Run("an unlabelled body that is not JSON is a failed upstream request", func(t *testing.T) {
		f := group(t, upstreamSpec{Tools: []string{"scrape"}, CallCT: "-", CallBody: "<html>SECRET-FROM-UPSTREAM</html>"})
		rr := f.post(toolCall("2", "beta__scrape"))
		if rr.Code != http.StatusBadGateway || strings.Contains(rr.Body.String(), "SECRET-FROM-UPSTREAM") {
			t.Errorf("HTTP code=%d body=%s, want 502 and none of the member's bytes", rr.Code, rr.Body.String())
		}
	})

	t.Run("a third media type is a failed upstream request", func(t *testing.T) {
		f := group(t, upstreamSpec{Tools: []string{"scrape"}, CallCT: "text/plain", CallBody: "SECRET-FROM-UPSTREAM"})
		rr := f.post(toolCall("2", "beta__scrape"))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("HTTP code=%d want 502; body=%s", rr.Code, rr.Body.String())
		}
		if _, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); msg != "upstream request failed" {
			t.Errorf("client message=%q want the one every failed upstream request gets", msg)
		}
		if got := rr.Header().Get("Content-Type"); strings.Contains(got, "text/plain") {
			t.Errorf("Content-Type=%q: a member's media type reached a response of PoryMCP's own", got)
		}
		if strings.Contains(rr.Body.String(), "SECRET-FROM-UPSTREAM") {
			t.Errorf("the member's bytes reached the client: %s", rr.Body.String())
		}
		row := methodRow(t, f, "tools/call")
		if row.Status != models.StatusError || row.ErrorMessage != "upstream answered with a media type the proxy cannot relay" || row.UpstreamID != "u2" {
			t.Errorf("row status=%q error=%q upstream=%q, want error, the fixed sentence, u2", row.Status, row.ErrorMessage, row.UpstreamID)
		}
	})
}

// modernRequest is a 2026-07-28 request for method with no name to route on,
// and the headers that declare it, for version.
func modernRequest(id, method, version string) (string, map[string]string) {
	idPart := ""
	if id != "" {
		idPart = `"id":` + id + `,`
	}
	body := `{"jsonrpc":"2.0",` + idPart + `"method":"` + method + `","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + version + `","io.modelcontextprotocol/clientInfo":{"name":"test","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	return body, map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": method}
}

// PORM-153. Three methods the group endpoint cannot serve used to be relayed to
// whichever member came first. subscriptions/listen held that member's stream
// open until the client gave up and tried again. They are refused the way the
// revision's transport prescribes, 404 and -32601, and no member is contacted.
// Security requirement 9: the row names no upstream and the id is echoed by
// writeRPCError's rule.
func TestAggregateRefusesUnservableModernMethods(t *testing.T) {
	for _, method := range []string{"subscriptions/listen", "tasks/get", "tasks/update"} {
		t.Run(method, func(t *testing.T) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
			body, hdr := modernRequest("7", method, mcpclient.RevisionModern)
			rr := f.postWith(body, hdr)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("HTTP code=%d want 404; body=%s", rr.Code, rr.Body.String())
			}
			code, msg, id := rpcErrorOf(t, rr.Body.Bytes())
			if code != -32601 || msg != "method not found" || id != float64(7) {
				t.Errorf("code=%d message=%q id=%v, want -32601, method not found, 7", code, msg, id)
			}
			if n := f.totalReqs("alpha") + f.totalReqs("beta"); n != 0 {
				t.Errorf("the members saw %d requests, want none", n)
			}
			row := f.waitAudit(models.LogFilter{})[0]
			if row.Status != models.StatusError || row.ErrorMessage != "method not found" || row.UpstreamID != "" || row.Method != method {
				t.Errorf("row method=%q status=%q error=%q upstream=%q, want %s, error, method not found, no upstream", row.Method, row.Status, row.ErrorMessage, row.UpstreamID, method)
			}

			// A member endpoint is a 1:1 door: the same method reaches the member.
			if mr := f.postMemberWith("alpha", body, hdr); mr.Code != http.StatusOK || f.count("alpha", method, "") != 1 {
				t.Errorf("member endpoint: HTTP code=%d, alpha saw %d %s, want 200 and 1", mr.Code, f.count("alpha", method, ""), method)
			}
		})
	}

	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
	t.Run("a handshake-era client is refused the same way", func(t *testing.T) {
		rr := f.post(`{"jsonrpc":"2.0","id":3,"method":"tasks/get","params":{"taskId":"x"}}`)
		if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); rr.Code != http.StatusNotFound || code != -32601 {
			t.Errorf("HTTP code=%d rpc code=%d, want 404 and -32601", rr.Code, code)
		}
	})
	t.Run("a notification is answered with a null id, not an invented one", func(t *testing.T) {
		body, hdr := modernRequest("", "subscriptions/listen", mcpclient.RevisionModern)
		rr := f.postWith(body, hdr)
		if !strings.Contains(rr.Body.String(), `"id":null`) {
			t.Errorf("body=%s, want an id of null", rr.Body.String())
		}
	})
	t.Run("an id past 2^53 comes back byte for byte", func(t *testing.T) {
		body, hdr := modernRequest("9007199254740993", "subscriptions/listen", mcpclient.RevisionModern)
		rr := f.postWith(body, hdr)
		if !strings.Contains(rr.Body.String(), `"id":9007199254740993,`) {
			t.Errorf("body=%s, want the id as it was sent", rr.Body.String())
		}
	})
	// The order a client can observe: the headers are judged before the method.
	t.Run("a strict request with no Mcp-Method is still a header mismatch", func(t *testing.T) {
		body, hdr := modernRequest("1", "subscriptions/listen", mcpclient.RevisionModern)
		delete(hdr, "Mcp-Method")
		rr := f.postWith(body, hdr)
		if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); rr.Code != http.StatusBadRequest || code != -32020 {
			t.Errorf("HTTP code=%d rpc code=%d, want 400 and -32020", rr.Code, code)
		}
	})
	if n := f.totalReqs("alpha"); n != 0 {
		t.Errorf("alpha saw %d requests across the refusals, want none", n)
	}
}

// PORM-153, amendment A10. The group endpoint's server/discover says it speaks
// one stateless revision, and strictRevision accepts any date from that one
// onward, so a request declaring a later revision was served as if PoryMCP
// spoke it. The revision makes the refusal a MUST and names its data.
func TestAggregateUnsupportedVersion(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
	body, hdr := modernRequest("4", "tools/list", "2027-01-01")
	rr := f.postWith(body, hdr)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("HTTP code=%d want 400; body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rr.Body.String())
	}
	if env.Error.Code != -32022 || env.Error.Message != "unsupported protocol version" || string(env.ID) != "4" ||
		len(env.Error.Data.Supported) != 1 || env.Error.Data.Supported[0] != "2026-07-28" || env.Error.Data.Requested != "2027-01-01" {
		t.Errorf("answer=%s, want -32022 with data.supported [2026-07-28] and data.requested 2027-01-01", rr.Body.String())
	}
	if n := f.totalReqs("alpha"); n != 0 {
		t.Errorf("alpha saw %d requests, want none", n)
	}
	row := f.waitAudit(models.LogFilter{})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "unsupported protocol version" || row.UpstreamID != "" {
		t.Errorf("row status=%q error=%q upstream=%q, want error, the fixed message, no upstream", row.Status, row.ErrorMessage, row.UpstreamID)
	}

	// The revision the endpoint does speak is served.
	body, hdr = modernRequest("5", "tools/list", mcpclient.RevisionModern)
	if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
		t.Errorf("2026-07-28: HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
	}

	// A single-upstream key on the same path is a 1:1 door: the upstream answers
	// for itself, for a later revision and for server/discover alike.
	single := newSingleFixture(t, upstreamSpec{Tools: []string{"a"}}, nil, nil)
	body, hdr = modernRequest("6", "tools/list", "2027-01-01")
	if rr := single.postWith(body, hdr); rr.Code != http.StatusOK || single.count("solo", "tools/list", "") != 1 {
		t.Errorf("single upstream, 2027-01-01: HTTP code=%d, upstream saw %d tools/list, want 200 and 1", rr.Code, single.count("solo", "tools/list", ""))
	}
	body, hdr = modernRequest("7", "server/discover", mcpclient.RevisionModern)
	if rr := single.postWith(body, hdr); rr.Code != http.StatusOK || single.count("solo", "server/discover", "") != 1 {
		t.Errorf("single upstream, server/discover: HTTP code=%d, upstream saw %d, want 200 and 1", rr.Code, single.count("solo", "server/discover", ""))
	}
}

// PORM-153, amendment A12 and security requirement 9. upstream_id is how an
// operator reads which credential a request presented. The group endpoint
// answers initialize and notifications/initialized itself and dials nobody, so
// their rows name no upstream, as a group's tools/list row never has.
func TestAggregateLocalAnswersNameNoUpstream(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
	f.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	f.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	rows := f.waitAuditN(models.LogFilter{}, 2)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	for _, row := range rows {
		if row.UpstreamID != "" || row.Status != models.StatusSuccess {
			t.Errorf("%s row: upstream=%q status=%q, want no upstream and success", row.Method, row.UpstreamID, row.Status)
		}
	}
	if n := f.totalReqs("alpha") + f.totalReqs("beta"); n != 0 {
		t.Errorf("the members saw %d requests, want none", n)
	}
}

// PORM-153. The group endpoint answered every initialize with 2024-11-05. It
// now follows the handshake's rule, and the answer comes out of mcpclient's
// closed set, never out of the client's string (security requirement 10).
func TestAggregateInitializeNegotiates(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
	for _, c := range []struct{ name, params, want string }{
		{"2025-06-18", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}`, "2025-06-18"},
		{"2025-11-25", `{"protocolVersion":"2025-11-25"}`, "2025-11-25"},
		{"2025-03-26", `{"protocolVersion":"2025-03-26"}`, "2025-03-26"},
		{"2024-11-05", `{"protocolVersion":"2024-11-05"}`, "2024-11-05"},
		{"a revision PoryMCP does not speak", `{"protocolVersion":"2030-01-01"}`, "2025-11-25"},
		{"the stateless revision, which has no initialize", `{"protocolVersion":"2026-07-28"}`, "2025-11-25"},
		{"no version", `{}`, "2025-11-25"},
		{"a number", `{"protocolVersion":20250618}`, "2025-11-25"},
		{"a string that is not a version", `{"protocolVersion":"<script>2025-06-18"}`, "2025-11-25"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rr := f.post(`{"jsonrpc":"2.0","id":9,"method":"initialize","params":` + c.params + `}`)
			var env struct {
				ID     json.RawMessage `json:"id"`
				Result struct {
					ProtocolVersion string `json:"protocolVersion"`
					Capabilities    struct {
						Tools *struct {
							ListChanged *bool `json:"listChanged"`
						} `json:"tools"`
					} `json:"capabilities"`
					ServerInfo struct{ Name, Version string } `json:"serverInfo"`
				} `json:"result"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil || rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d err=%v body=%s", rr.Code, err, rr.Body.String())
			}
			r := env.Result
			if r.ProtocolVersion != c.want || string(env.ID) != "9" {
				t.Errorf("protocolVersion=%q id=%s, want %q and 9", r.ProtocolVersion, env.ID, c.want)
			}
			if r.ServerInfo.Name != "porymcp" || r.ServerInfo.Version != "dev" {
				t.Errorf("serverInfo=%+v, want porymcp and the build's version", r.ServerInfo)
			}
			if r.Capabilities.Tools == nil || r.Capabilities.Tools.ListChanged == nil || *r.Capabilities.Tools.ListChanged {
				t.Errorf("capabilities in %s, want tools with listChanged false", rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "script") {
				t.Errorf("the client's string was echoed: %s", rr.Body.String())
			}
		})
	}
	if n := f.totalReqs("alpha") + f.totalReqs("beta"); n != 0 {
		t.Errorf("the members saw %d requests, want none", n)
	}
}

// PORM-153, amendment A3. ping is answered by the group endpoint in both eras
// and no member is asked. The stateless revision removed ping and requires
// resultType on every result, so its answer is not an empty object.
func TestAggregatePing(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)

	rr := f.post(`{"jsonrpc":"2.0","id":11,"method":"ping"}`)
	if rr.Code != http.StatusOK || rr.Body.String() != `{"jsonrpc":"2.0","id":11,"result":{}}` {
		t.Errorf("handshake era: HTTP code=%d body=%s, want 200 and an empty result with the request's id", rr.Code, rr.Body.String())
	}
	body, hdr := modernRequest("12", "ping", mcpclient.RevisionModern)
	rr = f.postWith(body, hdr)
	if rr.Code != http.StatusOK || rr.Body.String() != `{"jsonrpc":"2.0","id":12,"result":{"resultType":"complete"}}` {
		t.Errorf("stateless era: HTTP code=%d body=%s, want 200 and a result carrying resultType", rr.Code, rr.Body.String())
	}
	if n := f.totalReqs("alpha") + f.totalReqs("beta"); n != 0 {
		t.Errorf("the members saw %d requests, want none", n)
	}
	for _, row := range f.waitAuditN(models.LogFilter{Method: "ping"}, 2) {
		if row.UpstreamID != "" || row.Status != models.StatusSuccess {
			t.Errorf("ping row: upstream=%q status=%q, want no upstream and success", row.UpstreamID, row.Status)
		}
	}
}

// PORM-153. server/discover on a group used to be relayed to the first member,
// so a modern client was told one upstream's name, version and capabilities as
// if they were the group's. The group endpoint answers for itself, from
// constants, and no member is contacted (security requirements 8 and 11).
func TestAggregateServerDiscover(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Modern: true, Tools: []string{"a"}},
		"beta":  {Tools: []string{"b"}},
	}, true, nil, nil, nil)

	body, hdr := modernRequest("21", "server/discover", mcpclient.RevisionModern)
	rr := f.postWith(body, hdr)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	const want = `{"jsonrpc":"2.0","id":21,"result":{"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"porymcp","version":"dev"}},` +
		`"cacheScope":"private","capabilities":{"tools":{"listChanged":false}},"resultType":"complete",` +
		`"supportedVersions":["2026-07-28"],"ttlMs":3600000}}`
	if got := rr.Body.String(); got != want {
		t.Errorf("result\n got %s\nwant %s", got, want)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	if n := f.totalReqs("alpha") + f.totalReqs("beta"); n != 0 {
		t.Errorf("the members saw %d requests, want none: the answer is PoryMCP's own", n)
	}
	row := f.waitAudit(models.LogFilter{Method: "server/discover"})[0]
	if row.UpstreamID != "" || row.Status != models.StatusSuccess {
		t.Errorf("row upstream=%q status=%q, want no upstream and success", row.UpstreamID, row.Status)
	}

	// PORM-150's check still runs first: a body that declares one version under
	// a header that declares another never reaches the answer.
	t.Run("a _meta version that disagrees with the header is refused", func(t *testing.T) {
		body, hdr := modernRequest("22", "server/discover", mcpclient.RevisionModern)
		hdr["MCP-Protocol-Version"] = "2025-11-25"
		rr := f.postWith(body, hdr)
		if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); rr.Code != http.StatusBadRequest || code != -32020 {
			t.Errorf("HTTP code=%d rpc code=%d, want 400 and -32020", rr.Code, code)
		}
	})

	// A key whose rules leave it no tools is still told the endpoint serves tools.
	t.Run("a key with every tool filtered away", func(t *testing.T) {
		g := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, []string{"alpha__nothing"}, nil)
		body, hdr := modernRequest("23", "server/discover", mcpclient.RevisionModern)
		if rr := g.postWith(body, hdr); !strings.Contains(rr.Body.String(), `"capabilities":{"tools":{"listChanged":false}}`) {
			t.Errorf("body=%s, want the tools capability", rr.Body.String())
		}
	})
}

// modernList is a verbatim tools/list answer for a Modern stub: the named tools
// (each a raw JSON object) and, when ttl is not empty, a ttlMs written exactly
// as given, so a test can send 3600000.0, "60" or -5.
func modernList(ttl string, tools ...string) string {
	member := ""
	if ttl != "" {
		member = `,"ttlMs":` + ttl
	}
	return `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + strings.Join(tools, ",") + `],"resultType":"complete","cacheScope":"public"` + member + `}}`
}

// PORM-153, amendments A6, A7 and A8; security requirement 8. The merged list is
// PoryMCP's own document. The revision requires ttlMs on it, and a client that
// validates what it is sent rejects a list without one, which is what Claude
// Code did to a group. ttlMs is the one value on it a member has a say in.
func TestAggregateListFields(t *testing.T) {
	type listResult struct {
		TTL        *int64          `json:"ttlMs"`
		CacheScope string          `json:"cacheScope"`
		ResultType string          `json:"resultType"`
		Cursor     json.RawMessage `json:"nextCursor"`
		Meta       map[string]struct {
			Name, Version string
		} `json:"_meta"`
		Tools []struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	list := func(t *testing.T, specs map[string]upstreamSpec) listResult {
		t.Helper()
		f := newFixture(t, specs, true, nil, nil, nil)
		body, hdr := modernRequest("1", "tools/list", mcpclient.RevisionModern)
		rr := f.postWith(body, hdr)
		var env struct {
			Result listResult `json:"result"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d err=%v body=%s", rr.Code, err, rr.Body.String())
		}
		return env.Result
	}
	modern := func(ttl string) upstreamSpec {
		return upstreamSpec{Modern: true, RawList: modernList(ttl, `{"name":"t","inputSchema":{"type":"object"}}`)}
	}
	legacy := upstreamSpec{Tools: []string{"t"}}

	for _, c := range []struct {
		name  string
		specs map[string]upstreamSpec
		want  int64
	}{
		{"the smaller of two modern members", map[string]upstreamSpec{"a": modern("30000"), "b": modern("90000")}, 30000},
		{"two handshake members report nothing", map[string]upstreamSpec{"a": legacy, "b": legacy}, 60000},
		{"a handshake member counts as the default beside a larger value", map[string]upstreamSpec{"a": modern("90000"), "b": legacy}, 60000},
		{"zero is held at the floor", map[string]upstreamSpec{"a": modern("0"), "b": legacy}, 10000},
		{"a whole number written as a float is a report", map[string]upstreamSpec{"a": modern("3600000.0")}, 3600000},
		{"a huge value is held at the ceiling", map[string]upstreamSpec{"a": modern("99999999")}, 3600000},
		{"a negative is not a report", map[string]upstreamSpec{"a": modern("-5")}, 60000},
		{"a fraction is not a report", map[string]upstreamSpec{"a": modern("1.5")}, 60000},
		{"a string is not a report", map[string]upstreamSpec{"a": modern(`"60"`)}, 60000},
		{"a number too large to hold is not a report", map[string]upstreamSpec{"a": modern("1e30")}, 60000},
		{"a null is not a report", map[string]upstreamSpec{"a": modern("null")}, 60000},
		{"an absent member is not a report", map[string]upstreamSpec{"a": modern("")}, 60000},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := list(t, c.specs)
			if got.TTL == nil || *got.TTL != c.want {
				t.Fatalf("ttlMs=%v want %d", got.TTL, c.want)
			}
			if got.CacheScope != "private" || got.ResultType != "complete" || len(got.Cursor) != 0 {
				t.Errorf("cacheScope=%q resultType=%q nextCursor=%s, want private, complete and no cursor: a member's public scope must not cross", got.CacheScope, got.ResultType, got.Cursor)
			}
			if si := got.Meta["io.modelcontextprotocol/serverInfo"]; si.Name != "porymcp" || si.Version != "dev" || len(got.Meta) != 1 {
				t.Errorf("_meta=%v, want PoryMCP's serverInfo and nothing else", got.Meta)
			}
		})
	}

	// A8: members in stored order, each member's tools in its own order, read
	// unsorted. listedNames sorts, so it cannot see this.
	t.Run("the merged order is the stored order", func(t *testing.T) {
		got := list(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"zebra", "apple"}},
			"beta":  {Tools: []string{"mango", "banana"}},
		})
		var names []string
		for _, tl := range got.Tools {
			names = append(names, tl.Name)
		}
		if s := strings.Join(names, ","); s != "alpha__zebra,alpha__apple,beta__mango,beta__banana" {
			t.Errorf("order %q, want members in stored order and each member's own order", s)
		}
	})

	// A7: the revision requires inputSchema on every tool, an object whose type
	// is "object". One tool that does not conform would cost a validating
	// client the whole list, so the merge supplies the least a schema may be.
	t.Run("every merged tool carries an object schema", func(t *testing.T) {
		const conforming = `{"type":"object","properties":{"q":{"type":"string","description":"a <b> & c"}},"required":["q"]}`
		got := list(t, map[string]upstreamSpec{"a": {Modern: true, RawList: modernList("60000",
			`{"name":"none"}`,
			`{"name":"null","inputSchema":null}`,
			`{"name":"untyped","inputSchema":{"properties":{"q":{"type":"string"}},"required":["q"]}}`,
			`{"name":"nullable","inputSchema":{"type":["object","null"],"properties":{"q":{"type":"string"}}}}`,
			`{"name":"string","inputSchema":{"type":"string"}}`,
			`{"name":"array","inputSchema":["object"]}`,
			`{"name":"good","inputSchema":`+conforming+`}`,
		)}})
		// A schema that is an object is repaired and keeps what it declared: a
		// tool whose parameters were erased can be called and cannot be used.
		want := map[string]string{
			"a__none":     `{"type":"object"}`,
			"a__null":     `{"type":"object"}`,
			"a__untyped":  `{"properties":{"q":{"type":"string"}},"required":["q"],"type":"object"}`,
			"a__nullable": `{"properties":{"q":{"type":"string"}},"type":"object"}`,
			"a__string":   `{"type":"object"}`,
			"a__array":    `{"type":"object"}`,
			"a__good":     conforming,
		}
		if len(got.Tools) != len(want) {
			t.Fatalf("%d tools, want %d", len(got.Tools), len(want))
		}
		for _, tl := range got.Tools {
			if string(tl.InputSchema) != want[tl.Name] {
				t.Errorf("%s inputSchema=%s want %s", tl.Name, tl.InputSchema, want[tl.Name])
			}
		}
	})
}

// PORM-153, security requirements 4 and 5. What the aggregate decides about a
// routing header is what the member must read. The override used to be written
// before the stored credential, so a custom auth_config that names Mcp-Name
// (the API has refused to save one since PORM-150; a row saved before that
// still holds it) replaced the rewritten name, and a member that routes on the
// header would have run the stored name, not the one the policy gate judged.
func TestAggregateNameBeatsStoredAuthConfig(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"search"}},
		"beta": {
			Tools:    []string{"scrape"},
			AuthType: models.AuthCustom,
			AuthConfig: models.AuthConfig{Headers: map[string]string{
				"X-Stored-Key": "REAL-CUSTOM-SECRET",
				"Mcp-Name":     "delete_everything",
			}},
		},
	}, true, nil, nil, nil)

	rr := f.postWith(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"beta__scrape","arguments":{}}}`,
		map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "beta__scrape"})
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	var call *recordedRequest
	for _, r := range f.requestsTo("beta") {
		if r.RPCMethod == "tools/call" {
			r := r
			call = &r
		}
	}
	if call == nil {
		t.Fatal("beta saw no tools/call")
	}
	if got := call.Header.Get("Mcp-Name"); got != "scrape" {
		t.Errorf("the member read Mcp-Name %q, want the name the aggregate rewrote, scrape", got)
	}
	if got := call.Header.Get("X-Stored-Key"); got != "REAL-CUSTOM-SECRET" {
		t.Errorf("the stored credential did not cross: X-Stored-Key=%q", got)
	}
}

// PORM-153, amendment A9. The version a handshake-era client declares on every
// request is the one the group endpoint's initialize agreed to, for itself. A
// method the endpoint relays to the group's first member must not carry it: a
// member on an older revision MUST refuse a version it does not support, and
// initialize used to answer 2024-11-05 where it now answers up to 2025-11-25.
func TestAggregateRelayDropsNegotiatedVersion(t *testing.T) {
	const setLevel = `{"jsonrpc":"2.0","id":5,"method":"logging/setLevel","params":{"level":"info"}}`
	relayed := func(t *testing.T, f *fixture, slug, method string) recordedRequest {
		t.Helper()
		for _, r := range f.requestsTo(slug) {
			if r.RPCMethod == method {
				return r
			}
		}
		t.Fatalf("%s saw no %s", slug, method)
		return recordedRequest{}
	}

	t.Run("a handshake-era client on a group", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
		rr := f.postWith(setLevel, map[string]string{"MCP-Protocol-Version": "2025-11-25", "Mcp-Session-Id": "client-session"})
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		got := relayed(t, f, "alpha", "logging/setLevel")
		if v, sent := got.Header["Mcp-Protocol-Version"]; sent {
			t.Errorf("the first member was sent MCP-Protocol-Version %q, a version only the group endpoint agreed to", v)
		}
		// Only that one header: the rest of the client's request still crosses.
		if v := got.Header.Get("Mcp-Session-Id"); v != "client-session" {
			t.Errorf("Mcp-Session-Id=%q, want the client's own", v)
		}
		if n := f.totalReqs("beta"); n != 0 {
			t.Errorf("beta saw %d requests", n)
		}
	})

	// PORM-172 (D8): to a handshake-era first member the version header no
	// longer crosses (TestGroupRelayComposesForLegacyMember); to a modern one
	// the request is relayed as it came.
	t.Run("a modern client on a group is relayed as it came to a modern member", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{"alpha": {Tools: []string{"a"}, Modern: true,
			CallBody: `{"jsonrpc":"2.0","id":6,"result":{"resources":[],"resultType":"complete"}}`}}, true, nil, nil, nil)
		body, hdr := modernRequest("6", "resources/list", mcpclient.RevisionModern)
		f.postWith(body, hdr)
		if v := relayed(t, f, "alpha", "resources/list").Header.Get("Mcp-Protocol-Version"); v != mcpclient.RevisionModern {
			t.Errorf("Mcp-Protocol-Version=%q, want the client's own", v)
		}
	})

	t.Run("a member endpoint and a single-upstream key still forward it", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
		f.postMemberWith("alpha", setLevel, map[string]string{"MCP-Protocol-Version": "2025-11-25"})
		if v := relayed(t, f, "alpha", "logging/setLevel").Header.Get("Mcp-Protocol-Version"); v != "2025-11-25" {
			t.Errorf("member endpoint: Mcp-Protocol-Version=%q, want the client's own", v)
		}
		single := newSingleFixture(t, upstreamSpec{Tools: []string{"a"}}, nil, nil)
		single.postWith(setLevel, map[string]string{"MCP-Protocol-Version": "2025-11-25"})
		if v := relayed(t, single, "solo", "logging/setLevel").Header.Get("Mcp-Protocol-Version"); v != "2025-11-25" {
			t.Errorf("single upstream: Mcp-Protocol-Version=%q, want the client's own", v)
		}
	})
}

// completeResult adds one member to one kind of document and leaves every
// other byte a member sent alone.
func TestCompleteResult(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"a handshake member's result", `{"jsonrpc":"2.0","id":9007199254740993,"result":{"content":[{"type":"text","text":"a <b> & c"}],"isError":false}}`,
			`{"id":9007199254740993,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"a <b> & c"}],"isError":false,"resultType":"complete"}}`},
		{"a null resultType counts as none", `{"jsonrpc":"2.0","id":1,"result":{"content":[],"resultType":null}}`,
			`{"id":1,"jsonrpc":"2.0","result":{"content":[],"resultType":"complete"}}`},
		{"a modern member's own resultType is left alone", `{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":{}}}`, ""},
		{"an error answer", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no"}}`, ""},
		{"a result that is not an object", `{"jsonrpc":"2.0","id":1,"result":"ok"}`, ""},
		{"not JSON", `<html>`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := c.want
			if want == "" {
				want = c.in
			}
			if got := string(completeResult([]byte(c.in))); got != want {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
}

// A request with no method on a group URL (a DELETE, a body that names none) is
// relayed to the first member under the same two rules as any relayed request,
// because on that URL the version a client declares is the group endpoint's
// own: a handshake-era version does not cross, and a stateless revision the
// endpoint does not speak is refused. Pinned because checkRoutingHeaders
// returns before it reads the version of such a request.
func TestAggregateRequestWithNoMethod(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)

	rr := f.doPath(http.MethodDelete, "http://localhost:8080/mcp", "", map[string]string{"MCP-Protocol-Version": "2025-11-25", "Mcp-Session-Id": "s1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE: HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	var del *recordedRequest
	for _, r := range f.requestsTo("alpha") {
		if r.HTTPMethod == http.MethodDelete {
			r := r
			del = &r
		}
	}
	if del == nil {
		t.Fatal("alpha saw no DELETE")
	}
	if v, sent := del.Header["Mcp-Protocol-Version"]; sent {
		t.Errorf("the relayed DELETE carried MCP-Protocol-Version %q", v)
	}
	if v := del.Header.Get("Mcp-Session-Id"); v != "s1" {
		t.Errorf("Mcp-Session-Id=%q, want the client's own", v)
	}

	before := f.totalReqs("alpha")
	rr = f.doPath(http.MethodDelete, "http://localhost:8080/mcp", "", map[string]string{"MCP-Protocol-Version": "2027-01-01"})
	if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); rr.Code != http.StatusBadRequest || code != -32022 {
		t.Errorf("DELETE declaring 2027-01-01: HTTP code=%d rpc code=%d, want 400 and -32022", rr.Code, code)
	}
	if after := f.totalReqs("alpha"); after != before {
		t.Errorf("alpha saw %d more requests for a refused DELETE", after-before)
	}

	// The same later revision on a member endpoint is the member's to answer.
	body, hdr := modernRequest("9", "tools/list", "2027-01-01")
	if mr := f.postMemberWith("alpha", body, hdr); mr.Code != http.StatusOK || f.count("alpha", "tools/list", "") == 0 {
		t.Errorf("member endpoint, 2027-01-01: HTTP code=%d, want it relayed", mr.Code)
	}
}

// PORM-172 security requirement 9: the relay's rewrite for a handshake-era
// member touches the reserved _meta members and nothing else. Every other
// value crosses as the bytes the client sent, which rewriteToolCallParams,
// built on map[string]any, does not promise.
func TestStripReservedMeta(t *testing.T) {
	const big = `12345678901234567890`
	cases := []struct {
		name    string
		params  string
		want    string
		changed bool
	}{
		{"empty params", "", "", false},
		{"no _meta", `{"name":"x","n":` + big + `}`, `{"name":"x","n":` + big + `}`, false},
		{"_meta with no reserved member", `{"_meta":{"progressToken":"p<1>"}}`, `{"_meta":{"progressToken":"p<1>"}}`, false},
		{"not an object", `[1,2]`, `[1,2]`, false},
		{"reserved members beside a progressToken", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"io.modelcontextprotocol/clientCapabilities":{},"progressToken":"p<1>"},"n":` + big + `,"s":"a&b"}`, `{"_meta":{"progressToken":"p<1>"},"n":` + big + `,"s":"a&b"}`, true},
		{"only reserved members", `{"_meta":{"IO.ModelContextProtocol/ProtocolVersion":"2026-07-28"},"n":` + big + `}`, `{"n":` + big + `}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, changed := stripReservedMeta(json.RawMessage(c.params))
			if changed != c.changed || string(got) != c.want {
				t.Fatalf("stripReservedMeta(%s) = %s, %v; want %s, %v", c.params, got, changed, c.want, c.changed)
			}
		})
	}
}

func TestReplaceParams(t *testing.T) {
	params := json.RawMessage(`{"a":1}`)
	cases := []struct {
		name, body, want string
	}{
		{"lowercase", `{"jsonrpc":"2.0","id":12345678901234567890,"method":"prompts/get","params":{"b":2}}`, `{"id":12345678901234567890,"jsonrpc":"2.0","method":"prompts/get","params":{"a":1}}`},
		{"capitalised spelling replaced by one params", `{"jsonrpc":"2.0","id":"x<y>","method":"prompts/get","Params":{"b":2}}`, `{"id":"x<y>","jsonrpc":"2.0","method":"prompts/get","params":{"a":1}}`},
		{"no params member", `{"jsonrpc":"2.0","id":1,"method":"prompts/get"}`, `{"id":1,"jsonrpc":"2.0","method":"prompts/get","params":{"a":1}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := string(replaceParams(json.RawMessage(c.body), params)); got != c.want {
				t.Fatalf("replaceParams = %s, want %s", got, c.want)
			}
		})
	}
}

// methodRow is the one audit row for method, or a failure.
func methodRow(t *testing.T, f *fixture, method string) models.AuditLog {
	t.Helper()
	rows := f.waitAudit(models.LogFilter{Method: method})
	if len(rows) != 1 {
		t.Fatalf("%d %s rows, want 1", len(rows), method)
	}
	return rows[0]
}

// relayRequest is a handshake-era client's request for a method the group
// endpoint relays to its first member.
func relayRequest(id, method string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":{"uri":"x"}}`
}

// modernMeta is the three reserved _meta members a 2026-07-28 client sends.
const modernMeta = `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}`

// firstMember builds a group whose first member (alpha, u1) is spec and whose
// second is a plain handshake member, so a relayed method reaches spec.
func firstMember(t *testing.T, spec upstreamSpec) *fixture {
	t.Helper()
	if spec.Tools == nil && spec.RawList == "" {
		spec.Tools = []string{"a"}
	}
	return newFixture(t, map[string]upstreamSpec{"alpha": spec, "beta": {Tools: []string{"other"}}}, true, nil, nil, nil)
}

// resultTypeOf reads result.resultType from an answer, "" when absent.
func resultTypeOf(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("answer is not JSON: %v (%s)", err, body)
	}
	return strings.Trim(string(env.Result["resultType"]), `"`)
}

// discoverCount is how many era probes a stub answered.
func discoverCount(f *fixture, slug string) int {
	n := 0
	for _, r := range f.requestsTo(slug) {
		if r.RPCMethod == "server/discover" {
			n++
		}
	}
	return n
}

// lastRequest is the most recent request a stub saw for method.
func lastRequest(t *testing.T, f *fixture, slug, method string) recordedRequest {
	t.Helper()
	reqs := f.requestsTo(slug)
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].RPCMethod == method {
			return reqs[i]
		}
	}
	t.Fatalf("%s saw no %s request", slug, method)
	return recordedRequest{}
}

// PORM-172 criterion 3, security requirements 3 and 4. A first member that
// answers everything in SSE framing, with its own session id, is relayed to
// the group client as one JSON document under a bare label, and the row is
// judged from that document.
func TestGroupRelayFromSSEMember(t *testing.T) {
	const sse = "text/event-stream"
	doc := `{"jsonrpc":"2.0","id":3,"error":{"code":-32002,"message":"no such resource"}}`
	f := firstMember(t, upstreamSpec{
		RawList:     sseFrame(sseCatalogue("1", "a")),
		RespHeaders: map[string]string{"Content-Type": sse, "Mcp-Session-Id": "MEMBER-SESSION"},
		CallBody:    sseFrame(doc),
	})
	req := relayRequest("3", "resources/read")
	rr := f.post(req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	if got := rr.Header().Get("Mcp-Session-Id"); got != "" {
		t.Errorf("a member's Mcp-Session-Id %q reached a group client", got)
	}
	if strings.TrimSpace(rr.Body.String()) != doc {
		t.Errorf("body=%q want the one answering document", rr.Body.String())
	}
	if got := string(lastRequest(t, f, "alpha", "resources/read").Body); got != req {
		t.Errorf("member saw %q want the client's bytes", got)
	}
	if row := methodRow(t, f, "resources/read"); row.Status != models.StatusError || row.ErrorMessage != "no such resource" || row.UpstreamID != "u1" {
		t.Errorf("row status=%q error_message=%q upstream=%q", row.Status, row.ErrorMessage, row.UpstreamID)
	}
}

// PORM-172 criterion 4 as amended (D8), security requirement 9. A modern
// client's relayed request to a first member held as handshake-era loses its
// version header and the three reserved _meta members, and nothing else.
func TestGroupRelayComposesForLegacyMember(t *testing.T) {
	hdr := map[string]string{"MCP-Protocol-Version": mcpclient.RevisionModern, "Mcp-Method": "prompts/get"}
	result := `{"jsonrpc":"2.0","id":4,"result":{"messages":[]}}`
	const big = `12345678901234567890`

	t.Run("reserved members go, every other byte stays", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: result})
		body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"_meta":{` + modernMeta + `,"progressToken":"p<1>"},"n":` + big + `}}`
		rr := f.postWith(body, hdr)
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		got := lastRequest(t, f, "alpha", "prompts/get")
		if v := got.Header.Get("Mcp-Protocol-Version"); v != "" {
			t.Errorf("member saw MCP-Protocol-Version %q, want none", v)
		}
		b := string(got.Body)
		for _, want := range []string{`"progressToken":"p<1>"`, `"n":` + big, `"id":4`} {
			if !strings.Contains(b, want) {
				t.Errorf("member body %s lacks %s", b, want)
			}
		}
		if strings.Contains(b, "io.modelcontextprotocol/") {
			t.Errorf("member body %s still carries a reserved _meta member", b)
		}
	})
	t.Run("a Params spelling arrives as one params", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: result})
		body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","Params":{"_meta":{` + modernMeta + `}}}`
		if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		b := string(lastRequest(t, f, "alpha", "prompts/get").Body)
		if strings.Count(strings.ToLower(b), `"params"`) != 1 || strings.Contains(b, `"Params"`) {
			t.Errorf("member body %s, want one params member", b)
		}
	})
	t.Run("nothing to strip crosses untouched", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: result})
		body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"uri":"x"}}`
		if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		got := lastRequest(t, f, "alpha", "prompts/get")
		if string(got.Body) != body || got.Header.Get("Mcp-Protocol-Version") != "" {
			t.Errorf("member saw %q with version %q, want the client's bytes and no version", got.Body, got.Header.Get("Mcp-Protocol-Version"))
		}
	})
	t.Run("a handshake client's request is unchanged", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: result})
		body := relayRequest("4", "prompts/get")
		if rr := f.post(body); rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		if got := string(lastRequest(t, f, "alpha", "prompts/get").Body); got != body {
			t.Errorf("member saw %q want the client's bytes", got)
		}
		if n := discoverCount(f, "alpha"); n != 0 {
			t.Errorf("a handshake client's relay cost %d probes, want 0", n)
		}
	})
}

// PORM-172 D6, security requirement 6. A modern client's relay probes the
// first member's era once per eraTTL, never once per request; a probe the
// member did not answer is retried after eraRetry; a handshake client's relay
// never probes.
func TestGroupRelayProbesOncePerTTL(t *testing.T) {
	hdr := map[string]string{"MCP-Protocol-Version": mcpclient.RevisionModern, "Mcp-Method": "prompts/get"}
	body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"_meta":{` + modernMeta + `}}}`
	result := `{"jsonrpc":"2.0","id":4,"result":{"messages":[]}}`

	t.Run("one probe per TTL", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: result})
		now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
		f.H.eras.SetClock(func() time.Time { return now })
		for i := 0; i < 2; i++ {
			if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
			}
		}
		if n := discoverCount(f, "alpha"); n != 1 {
			t.Fatalf("two relays cost %d probes, want 1", n)
		}
		if n := f.count("alpha", "prompts/get", ""); n != 2 {
			t.Fatalf("member saw %d prompts/get, want 2", n)
		}
		now = now.Add(eraTTL + time.Second)
		if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		if n := discoverCount(f, "alpha"); n != 2 {
			t.Fatalf("a relay past the TTL cost %d probes in all, want 2", n)
		}
	})
	t.Run("an unanswered probe is retried after eraRetry", func(t *testing.T) {
		// A modern member whose probe answered with a version PoryMCP cannot
		// speak is an unusable verdict, kept for eraRetry only (a member the
		// probe cannot reach at all would fail the relay too).
		f := firstMember(t, upstreamSpec{CallBody: result, DiscoverCode: http.StatusBadRequest,
			DiscoverBody: `{"jsonrpc":"2.0","id":null,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2027-01-01"]}}}`})
		now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
		f.H.eras.SetClock(func() time.Time { return now })
		for i := 0; i < 2; i++ {
			if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
			}
		}
		if n := discoverCount(f, "alpha"); n != 1 {
			t.Fatalf("two relays cost %d probes, want 1", n)
		}
		now = now.Add(eraRetry + time.Second)
		if rr := f.postWith(body, hdr); rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		if n := discoverCount(f, "alpha"); n != 2 {
			t.Fatalf("a relay past eraRetry cost %d probes in all, want 2", n)
		}
		if n := f.count("alpha", "prompts/get", ""); n != 3 {
			t.Fatalf("member saw %d prompts/get, want 3: the relay goes out whatever the probe learned", n)
		}
	})
}

// PORM-172 criterion 4, security requirement 5. A handshake-era first
// member's result reaches a modern client with resultType, whether its era
// was cached by a tools/list or found by the relay's own probe.
func TestGroupRelayCompletesResultForModernClient(t *testing.T) {
	hdr := map[string]string{"MCP-Protocol-Version": mcpclient.RevisionModern, "Mcp-Method": "prompts/get"}
	body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"_meta":{` + modernMeta + `}}}`
	result := `{"jsonrpc":"2.0","id":4,"result":{"messages":[]}}`
	for name, warm := range map[string]bool{"era cached by tools/list": true, "era found by the relay's probe": false} {
		t.Run(name, func(t *testing.T) {
			f := firstMember(t, upstreamSpec{CallBody: result})
			if warm {
				list, lh := modernRequest("1", "tools/list", mcpclient.RevisionModern)
				if rr := f.postWith(list, lh); rr.Code != http.StatusOK {
					t.Fatalf("tools/list code=%d body=%s", rr.Code, rr.Body.String())
				}
			}
			rr := f.postWith(body, hdr)
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
			}
			if got := resultTypeOf(t, rr.Body.Bytes()); got != "complete" {
				t.Errorf("resultType=%q want complete; body=%s", got, rr.Body.String())
			}
		})
	}
}

// PORM-172: a modern member's relayed result is the member's own document,
// with the version header and _meta the client sent.
func TestGroupRelayLeavesModernMemberAlone(t *testing.T) {
	hdr := map[string]string{"MCP-Protocol-Version": mcpclient.RevisionModern, "Mcp-Method": "prompts/get"}
	body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"_meta":{` + modernMeta + `}}}`
	f := firstMember(t, upstreamSpec{Modern: true, CallBody: `{"jsonrpc":"2.0","id":4,"result":{"messages":[]}}`})
	rr := f.postWith(body, hdr)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := resultTypeOf(t, rr.Body.Bytes()); got != "" {
		t.Errorf("resultType=%q want none added to a modern member's own document", got)
	}
	got := lastRequest(t, f, "alpha", "prompts/get")
	if got.Header.Get("Mcp-Protocol-Version") != mcpclient.RevisionModern || string(got.Body) != body {
		t.Errorf("member saw version %q body %q, want the client's", got.Header.Get("Mcp-Protocol-Version"), got.Body)
	}
}

// PORM-172 D5. A notification's 202 passes with no body; a request with no
// id member is never given a resultType; a DELETE's answer carries no member
// session id.
func TestGroupRelayNotificationAndDelete(t *testing.T) {
	t.Run("a notification's 202 passes with no body", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{RelayCode: http.StatusAccepted, RespHeaders: map[string]string{"Mcp-Session-Id": "MEMBER-SESSION"}})
		rr := f.post(`{"jsonrpc":"2.0","method":"notifications/foo"}`)
		if rr.Code != http.StatusAccepted || rr.Body.Len() != 0 || rr.Header().Get("Content-Type") != "" || rr.Header().Get("Mcp-Session-Id") != "" {
			t.Errorf("code=%d body=%q ct=%q session=%q, want 202, no body, no label, no session", rr.Code, rr.Body.String(), rr.Header().Get("Content-Type"), rr.Header().Get("Mcp-Session-Id"))
		}
	})
	t.Run("a modern notification answered with a result is not completed", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: `{"jsonrpc":"2.0","id":null,"result":{}}`, RespHeaders: map[string]string{"Mcp-Session-Id": "MEMBER-SESSION"}})
		body := `{"jsonrpc":"2.0","method":"notifications/foo","params":{"_meta":{` + modernMeta + `}}}`
		rr := f.postWith(body, map[string]string{"MCP-Protocol-Version": mcpclient.RevisionModern, "Mcp-Method": "notifications/foo"})
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		if got := resultTypeOf(t, rr.Body.Bytes()); got != "" {
			t.Errorf("resultType=%q on the answer to a request with no id", got)
		}
		if got := rr.Header().Get("Mcp-Session-Id"); got != "" {
			t.Errorf("a member's Mcp-Session-Id %q reached a group client", got)
		}
	})
	t.Run("a DELETE's answer carries no member session id", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{CallBody: `{"jsonrpc":"2.0","id":null,"result":{}}`, RespHeaders: map[string]string{"Mcp-Session-Id": "MEMBER-SESSION"}})
		rr := f.doPath(http.MethodDelete, "http://localhost:8080/mcp", "", map[string]string{"Mcp-Session-Id": "CLIENT-SESSION"})
		if rr.Code != http.StatusOK {
			t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type=%q want application/json", got)
		}
		if got := rr.Header().Get("Mcp-Session-Id"); got != "" {
			t.Errorf("a member's Mcp-Session-Id %q reached a group client", got)
		}
	})
}

// PORM-172 D3 (Dan, 2026-09-22), security requirement 3. A member body that
// is neither JSON nor SSE keeps its status with no body when the status says
// failure, and is a 502 on a success status. Either way the member's bytes
// and label never reach the client.
func TestGroupRelayUnreadableAnswerKeepsStatus(t *testing.T) {
	t.Run("a 404 in HTML keeps its status with no body", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{RelayCode: http.StatusNotFound, RelayCT: "text/html", CallBody: "<html>nope</html>", RespHeaders: map[string]string{"Mcp-Session-Id": "MEMBER-SESSION"}})
		logs := captureLogs(f)
		rr := f.post(relayRequest("5", "resources/read"))
		if rr.Code != http.StatusNotFound || rr.Body.Len() != 0 || rr.Header().Get("Content-Type") != "" || rr.Header().Get("Mcp-Session-Id") != "" {
			t.Errorf("code=%d body=%q ct=%q session=%q, want 404, no body, no label, no session", rr.Code, rr.Body.String(), rr.Header().Get("Content-Type"), rr.Header().Get("Mcp-Session-Id"))
		}
		if row := methodRow(t, f, "resources/read"); row.Status != models.StatusError || row.ErrorMessage != "" {
			t.Errorf("row status=%q error_message=%q, want error and no message", row.Status, row.ErrorMessage)
		}
		warned := 0
		for _, rec := range logRecords(t, logs) {
			if rec["msg"] == "group answer relayed unreduced" && rec["err"] == errUnrelayableAnswer.Error() {
				warned++
			}
		}
		if warned != 1 {
			t.Errorf("%d warnings, want one naming the unrelayable answer", warned)
		}
	})
	t.Run("a 200 in HTML is a 502", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{RelayCT: "text/html", CallBody: "<html>nope</html>"})
		rr := f.post(relayRequest("5", "resources/read"))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("HTTP code=%d body=%s want 502", rr.Code, rr.Body.String())
		}
		if code, _, _ := rpcErrorOf(t, rr.Body.Bytes()); code != -32000 {
			t.Errorf("code=%d want -32000", code)
		}
		if row := methodRow(t, f, "resources/read"); row.Status != models.StatusError || row.ErrorMessage != errUnrelayableAnswer.Error() {
			t.Errorf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
	})
}

// PORM-172 D4 (Dan, 2026-09-22). Retry-After crosses on a relayed method and
// on a routed call alike, in either body shape, and never with the member's
// session id.
func TestGroupRelayKeepsRetryAfter(t *testing.T) {
	errDoc := `{"jsonrpc":"2.0","id":5,"error":{"code":-32000,"message":"slow down"}}`
	headers := map[string]string{"Retry-After": "3", "Mcp-Session-Id": "MEMBER-SESSION"}
	check := func(t *testing.T, rr *httptest.ResponseRecorder) {
		t.Helper()
		if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "3" || rr.Header().Get("Mcp-Session-Id") != "" {
			t.Errorf("code=%d Retry-After=%q session=%q, want 429, 3, none", rr.Code, rr.Header().Get("Retry-After"), rr.Header().Get("Mcp-Session-Id"))
		}
	}
	t.Run("relay, text/plain", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{RelayCode: http.StatusTooManyRequests, RelayCT: "text/plain", CallBody: "slow down", RespHeaders: headers})
		rr := f.post(relayRequest("5", "resources/read"))
		check(t, rr)
		if rr.Body.Len() != 0 {
			t.Errorf("body=%q want none", rr.Body.String())
		}
		if row := methodRow(t, f, "resources/read"); row.Status != models.StatusError {
			t.Errorf("row status=%q want error", row.Status)
		}
	})
	t.Run("relay, JSON error", func(t *testing.T) {
		f := firstMember(t, upstreamSpec{RelayCode: http.StatusTooManyRequests, CallBody: errDoc, RespHeaders: headers})
		rr := f.post(relayRequest("5", "resources/read"))
		check(t, rr)
		if row := methodRow(t, f, "resources/read"); row.Status != models.StatusError || row.ErrorMessage != "slow down" {
			t.Errorf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
	})
	t.Run("routed call", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"a"}},
			"beta":  {Tools: []string{"b"}, CallCode: http.StatusTooManyRequests, CallBody: errDoc, RespHeaders: headers},
		}, true, nil, nil, nil)
		check(t, f.post(toolCall("5", "beta__b")))
	})
}

// PORM-172 D9, security requirement 7. The unreduced warning carries the
// bounded method name the row carries, never the client's raw string.
func TestGroupRelayWarnCarriesBoundedMethod(t *testing.T) {
	f := firstMember(t, upstreamSpec{RelayCT: "text/event-stream", CallBody: sseFrame(`{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"x"}}`)})
	logs := captureLogs(f)
	method := strings.Repeat("m", 300)
	if rr := f.post(relayRequest("6", method)); rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, rec := range logRecords(t, logs) {
		if rec["msg"] == "group answer relayed unreduced" {
			if got, _ := rec["method"].(string); len(got) != auditFieldBytes {
				t.Errorf("warning method is %d bytes, want %d", len(got), auditFieldBytes)
			}
			return
		}
	}
	t.Fatal("no unreduced warning")
}
