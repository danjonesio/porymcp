package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// A member endpoint is the aggregate endpoint's opposite: nothing is merged,
// nothing is synthesised and nothing is renamed. Every test here therefore
// asserts two things at once, what the one named member saw, and that the
// other members of the same group saw nothing at all. The aggregate contrast
// is pinned beside it in the same test wherever the two could drift, because
// the failure this route has is silent: serve the merged catalogue at
// /{keyID}/{slug}/mcp and every assertion about "the member's own answer"
// still passes on a one-member group.

// memberList is a tools/list with an id no proxy-composed request uses, so a
// forwarded request can be told from one the proxy wrote itself (listTools
// sends id 1, proxy.go's listToolsRequest).
const memberList = `{"jsonrpc":"2.0","id":4242,"method":"tools/list"}`

// AC1. The route reaches exactly one member, and the names it advertises are
// that member's own. Both members advertise search on purpose: the aggregate
// endpoint calls them alpha__search and beta__search, so a member endpoint
// serving the merged catalogue would be visible here.
func TestPerUpstreamRouteHitsOnlyThatMember(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"alpha": {"search", "only_alpha"},
		"beta":  {"search", "only_beta"},
	}, nil, nil, nil)

	rr := f.postMember("alpha", memberList)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got, want := strings.Join(listedNames(t, rr.Body.Bytes()), ","), "only_alpha,search"; got != want {
		t.Errorf("listed %q want %q: a member endpoint advertises the member's own names, unprefixed", got, want)
	}
	if n := f.totalReqs("beta"); n != 0 {
		t.Errorf("beta saw %d requests for a list on alpha's endpoint; the member route must not merge", n)
	}
	// Forwarded, not composed: the client's own id reached the member. The
	// aggregate path replaces the client's request with one of the proxy's
	// own (listTools), which is what makes this distinguishable.
	reqs := f.requestsTo("alpha")
	if len(reqs) != 1 {
		t.Fatalf("alpha saw %d requests, want 1", len(reqs))
	}
	if reqs[0].RPCMethod != "tools/list" || reqs[0].HTTPMethod != http.MethodPost {
		t.Errorf("alpha saw %s %s", reqs[0].HTTPMethod, reqs[0].RPCMethod)
	}
	if !strings.Contains(string(reqs[0].Body), `"id":4242`) {
		t.Errorf("alpha's request body=%s; the client's own request is forwarded on this path, not replaced by the proxy's", reqs[0].Body)
	}

	rr = f.postMember("alpha", toolCall("1", "search"))
	assertNotBlocked(t, rr, "search on alpha's own endpoint")
	if got := f.count("alpha", "tools/call", "search"); got != 1 {
		t.Errorf("alpha saw %d calls to search, want 1", got)
	}
	if n := f.totalReqs("beta"); n != 0 {
		t.Errorf("beta saw %d requests; the URL named alpha", n)
	}

	// The aggregate endpoint of the same key is the contrast: every name
	// carries its member's slug, whether or not anything else advertises it,
	// and both members are still asked.
	t.Run("the aggregate prefixes every name", func(t *testing.T) {
		got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ",")
		if want := "alpha__only_alpha,alpha__search,beta__only_beta,beta__search"; got != want {
			t.Errorf("aggregate listed %q want %q", got, want)
		}
	})
}

// AC2a. initialize on a member endpoint is the member's own answer, byte for
// byte, its protocol version, its serverInfo, its capabilities, its
// instructions. The aggregate endpoint synthesises one instead, and a client
// that got the synthesised answer from a 1:1 endpoint would believe the server
// has no prompts and no resources.
func TestPerUpstreamInitializeIsTheMembersOwn(t *testing.T) {
	const alphaInit = `{"jsonrpc":"2.0","id":5,"result":{"protocolVersion":"2025-06-18",` +
		`"capabilities":{"tools":{},"prompts":{},"resources":{}},` +
		`"serverInfo":{"name":"alpha-server","version":"9.9.9"},"instructions":"be careful"}}`
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"only_alpha"}, CallBody: alphaInit},
		"beta":  {Tools: []string{"only_beta"}},
	}, true, nil, nil, nil)

	rr := f.postMember("alpha", `{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != alphaInit {
		t.Errorf("body=%s\nwant the member's own answer verbatim:\n%s", got, alphaInit)
	}
	for _, s := range []string{"porymcp", "2024-11-05"} {
		if strings.Contains(rr.Body.String(), s) {
			t.Errorf("body contains %q: the member endpoint answered initialize itself instead of forwarding it", s)
		}
	}
	if reqs := f.requestsTo("alpha"); len(reqs) != 1 || reqs[0].RPCMethod != "initialize" {
		t.Errorf("alpha saw %+v, want one forwarded initialize", reqs)
	}
	if n := f.totalReqs("beta"); n != 0 {
		t.Errorf("beta saw %d requests during an initialize on alpha's endpoint", n)
	}

	// The aggregate endpoint still answers for itself. PORM-23 owns changing
	// that; this is the tripwire if it ever changes by accident.
	t.Run("aggregate initialize is still synthesised", func(t *testing.T) {
		body := f.post(`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}`).Body.String()
		if !strings.Contains(body, `"porymcp"`) || !strings.Contains(body, "2024-11-05") {
			t.Errorf("aggregate initialize=%s want the proxy's own serverInfo", body)
		}
	})
}

// AC2b. A member endpoint is a transport for one server, so the session that
// server mints has to survive the round trip in both directions. Nothing in
// the proxy does this on purpose: forward returns the upstream's headers and
// serve copies them back, which only holds while the member path takes the
// forward branch.
func TestPerUpstreamSessionRoundTrips(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"ping_tool"}, SessionID: "sess-alpha-1", Bearer: "sk-alpha-real"},
		"beta":  {Tools: []string{"other"}},
	}, true, nil, nil, nil)

	rr := f.postMember("alpha", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if got := rr.Header().Get("Mcp-Session-Id"); got != "sess-alpha-1" {
		t.Fatalf("Mcp-Session-Id=%q want sess-alpha-1; without it a client cannot hold a session with the member", got)
	}

	rr = f.postMemberWith("alpha", toolCall("2", "ping_tool"), map[string]string{"Mcp-Session-Id": "sess-alpha-1"})
	assertNotBlocked(t, rr, "a call carrying the member's session id")
	reqs := f.requestsTo("alpha")
	if len(reqs) != 2 {
		t.Fatalf("alpha saw %d requests, want 2", len(reqs))
	}
	if got := reqs[1].Header.Get("Mcp-Session-Id"); got != "sess-alpha-1" {
		t.Errorf("the member saw Mcp-Session-Id=%q on the next call; a session it minted must come back to it", got)
	}
	if got := reqs[1].Header.Get("Authorization"); got != "Bearer sk-alpha-real" {
		t.Errorf("Authorization=%q want the upstream's own credential", got)
	}
	if n := f.totalReqs("beta"); n != 0 {
		t.Errorf("beta saw %d requests", n)
	}
	// The virtual key authenticates the client to the proxy and stops there.
	for _, got := range reqs {
		for k, vs := range got.Header {
			for _, v := range vs {
				if strings.Contains(v, f.Key) {
					t.Errorf("%s request leaked the client's virtual key upstream in %s", got.RPCMethod, k)
				}
			}
		}
	}

	// The aggregate endpoint answers initialize itself and returns no upstream
	// headers, so it hands out no session at all. PORM-23's tripwire.
	t.Run("aggregate hands out no session", func(t *testing.T) {
		agg := f.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
		if got := agg.Header().Get("Mcp-Session-Id"); got != "" {
			t.Errorf("aggregate Mcp-Session-Id=%q want none", got)
		}
	})
}

// AC3. Every way a member endpoint can fail to resolve answers identically,
// same status, same code, same message, same echoed id, same audit shape, and
// no upstream contacted. That uniformity is the whole security property: a
// valid key must not be able to walk this route and learn which slugs the
// deployment has, which of them its own group holds, or which are disabled.
func TestPerUpstreamUnresolvableSlugIsNotFound(t *testing.T) {
	// The id is the same in every case so the bodies can be compared byte for
	// byte at the end.
	const probe = `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"anything"}}`

	cases := []struct {
		name string
		// setup returns the fixture and the absolute URL to probe.
		setup func(t *testing.T) (*fixture, string)
	}{
		{"unknown slug", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
			return f, f.memberURL("nope")
		}},
		{"slug of an upstream outside the group", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
			now := time.Now().UTC()
			if err := f.Store.CreateUpstream(context.Background(), &models.Upstream{
				ID: "u9", Name: "Gamma", Slug: "gamma", URL: "http://127.0.0.1:9",
				Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone,
				Enabled: true, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			return f, f.memberURL("gamma")
		}},
		{"disabled member", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
			disable(t, f, "u1")
			return f, f.memberURL("alpha")
		}},
		{"single-upstream key", func(t *testing.T) (*fixture, string) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"safe_tool"}}, nil, nil)
			return f, f.memberURL("solo")
		}},
		{"group whose only member is disabled", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
			disable(t, f, "u1")
			// resolveTargets alone would answer this 400 "group has no enabled
			// upstreams", which is a different answer from the four above.
			return f, f.memberURL("alpha")
		}},
		{"invalid slug: dot-dot", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
			return f, "http://localhost:8080/a1/../mcp"
		}},
		{"invalid slug: uppercase", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
			return f, f.memberURL("GitHub")
		}},
		{"invalid slug: percent-encoded NUL", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
			return f, f.memberURL("a%00b")
		}},
		{"group deleted under the key", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
			// DeleteGroup refuses while a key references the group, so the
			// only way here is a key whose target has gone: resolveTargets
			// returns store.ErrNotFound, and resolveMember must swallow it
			// into the same miss as every other.
			vk, err := f.Store.GetVirtualKey(t.Context(), "a1")
			if err != nil {
				t.Fatal(err)
			}
			vk.TargetID = "no-such-group"
			if err := f.Store.UpdateVirtualKey(t.Context(), vk); err != nil {
				t.Fatal(err)
			}
			return f, "http://localhost:8080/a1/alpha/mcp"
		}},
		{"empty slug", func(t *testing.T) (*fixture, string) {
			f := newGroupFixture(t, map[string][]string{"alpha": {"a"}}, nil, nil, nil)
			// chi binds /a1//mcp to the three-segment pattern with slug "",
			// which is why member-ness is a property of the route and not of
			// the parameter's value.
			return f, "http://localhost:8080/a1//mcp"
		}},
	}

	bodies := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, url := c.setup(t)
			rr := f.postTo(url, probe)
			// Recorded before any per-case assertion can bail out, so the
			// cross-case check below sees every case that ran.
			bodies[rr.Body.String()] = true

			if rr.Code != http.StatusNotFound {
				t.Fatalf("code=%d want 404; body=%s", rr.Code, rr.Body.String())
			}
			code, msg, id := rpcErrorOf(t, rr.Body.Bytes())
			if code != -32000 {
				t.Errorf("rpc code=%d want -32000", code)
			}
			if msg != "unknown endpoint" {
				t.Errorf("message=%q want %q: every miss says the same thing", msg, "unknown endpoint")
			}
			if id != float64(9) {
				t.Errorf("id=%v want 9; a client that cannot match the error waits out its own timeout", id)
			}
			if !f.upstreamsIdle() {
				t.Error("an unresolvable endpoint reached an upstream")
			}
			row := f.waitAudit(models.LogFilter{})[0]
			if row.Status != models.StatusBlocked {
				t.Errorf("status=%q want %q", row.Status, models.StatusBlocked)
			}
			if row.UpstreamID != "" {
				t.Errorf("upstream_id=%q want empty: no member resolved, so there is none to name", row.UpstreamID)
			}
			if !strings.HasPrefix(row.ErrorMessage, "unknown endpoint") {
				t.Errorf("error_message=%q", row.ErrorMessage)
			}
		})
	}

	// The security assertion. Anything that told these cases apart (a
	// different message, a different id, a stray space) would be an oracle a
	// valid key could walk to enumerate the deployment's slugs.
	if len(bodies) != 1 {
		keys := make([]string, 0, len(bodies))
		for b := range bodies {
			keys = append(keys, b)
		}
		sort.Strings(keys)
		t.Errorf("the 404 has %d distinct bodies, want 1:\n%s", len(bodies), strings.Join(keys, ""))
	}
}

// disable flips one seeded upstream to enabled=false through the real store,
// so resolveTargets drops it exactly as it would in production.
func disable(t *testing.T, f *fixture, id string) {
	t.Helper()
	ctx := context.Background()
	up, err := f.Store.GetUpstream(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	up.Enabled = false
	if err := f.Store.UpdateUpstream(ctx, up, store.KeepTest, store.WriteAuth); err != nil {
		t.Fatal(err)
	}
}

// AC6. A rule is written against a tool's identity, and a member endpoint is
// the path where the client's spelling and the rule's differ: the client sends
// the member's own bare name and the entry names {slug}__{tool}, so the policy
// composes the slug the URL already carries. An entry's rest (and every
// prefixes entry) is matched against the tool's own name, which is what lets
// one entry mean the same thing here as on the group's endpoint.
func TestPerUpstreamToolFilterBlocksWithComposedIdentity(t *testing.T) {
	// Slugs sort docs, github, so the seeded ids are u1 and u2.
	const githubID = "u2"
	members := map[string][]string{
		"github": {"create_issue", "read_issue"},
		"docs":   {"search"},
	}

	t.Run("group filter names the composed identity", func(t *testing.T) {
		f := newGroupFixture(t, members, json.RawMessage(`{"mode":"deny","tools":["github__create_issue"]}`), nil, nil)

		assertBlocked(t, f, f.postMember("github", toolCall("11", "create_issue")))
		row := f.waitAudit(models.LogFilter{})[0]
		if row.ErrorMessage != reasonGroupFilter {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
		}
		if row.UpstreamID != githubID {
			t.Errorf("upstream_id=%q want %q: a member endpoint names its upstream in the URL, so a block can say which credential the call was aimed at", row.UpstreamID, githubID)
		}

		// Positive control: without it, "no upstream was contacted" also
		// passes on a proxy that refuses everything.
		assertNotBlocked(t, f.postMember("github", toolCall("12", "read_issue")), "read_issue, which the filter permits")
		if got := f.count("github", "tools/call", "read_issue"); got != 1 {
			t.Errorf("github saw %d calls to read_issue, want 1", got)
		}
		// The catalogue agrees with the gate, through the same policy.
		if got := strings.Join(listedNames(t, f.postMember("github", memberList).Body.Bytes()), ","); got != "read_issue" {
			t.Errorf("listed %q want read_issue", got)
		}
	})

	t.Run("the key's own lists compose the same way", func(t *testing.T) {
		f := newGroupFixture(t, members, nil, nil, []string{"github__create_issue"})
		assertBlocked(t, f, f.postMember("github", toolCall("1", "create_issue")))
		row := f.waitAudit(models.LogFilter{})[0]
		if row.ErrorMessage != reasonKeyDenylist {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonKeyDenylist)
		}
		if row.UpstreamID != githubID {
			t.Errorf("upstream_id=%q want %q", row.UpstreamID, githubID)
		}
	})

	// A deny written with prefixes must still deny. Composed first it would
	// match nothing at all: "github__delete_repo" does not start "delete_",
	// so the tool would be forwarded with the real credential.
	t.Run("deny prefixes match the advertised name", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{
			"github": {"delete_repo", "read_issue"},
			"docs":   {"search"},
		}, json.RawMessage(`{"mode":"deny","prefixes":["delete_"]}`), nil, nil)

		assertBlocked(t, f, f.postMember("github", toolCall("1", "delete_repo")))
		if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonGroupFilter {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
		}
		assertNotBlocked(t, f.postMember("github", toolCall("2", "read_issue")), "read_issue, which the prefix does not name")
	})

	// The member-path twin of TestOneMemberGroupPrefixesOnlyAllow. The client
	// sees gh_read here and gh__gh_read there, and one entry has to reach both:
	// it does because a prefixes entry's rest is matched against the tool's own
	// name on every path. Matching it against the composed name instead would
	// admit everything on the aggregate, since every name there begins "gh__".
	t.Run("allow prefixes agree on both paths of a one-member group", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"gh_read", "danger"}},
			json.RawMessage(`{"mode":"allow","prefixes":["gh__gh_"]}`), nil, nil)

		assertBlocked(t, f, f.postMember("gh", toolCall("1", "danger")))
		if got := strings.Join(listedNames(t, f.postMember("gh", memberList).Body.Bytes()), ","); got != "gh_read" {
			t.Errorf("member listed %q want gh_read", got)
		}
		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "gh__gh_read" {
			t.Errorf("aggregate listed %q want gh__gh_read", got)
		}
		assertNotBlocked(t, f.postMember("gh", toolCall("2", "gh_read")), "gh_read, which the prefix names")
	})
}

// The inverse of the composition, and the property that makes one rule enough:
// an unscoped entry names a tool by its own name on every path. Before the
// identity grammar a bare entry was a rule about the aggregate endpoint alone,
// where the advertised name happened to be bare too, and the same entry was
// inert on a member endpoint and on a single-upstream key. Nothing about that
// was a decision an operator could have made on purpose.
func TestUnscopedEntryMatchesOnEveryPath(t *testing.T) {
	const filter = `{"mode":"deny","tools":["create_issue"]}`

	t.Run("member endpoint", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{
			"github": {"create_issue", "read_issue"},
			"docs":   {"search"},
		}, json.RawMessage(filter), nil, nil)

		assertBlocked(t, f, f.postMember("github", toolCall("1", "create_issue")))
		if row := f.waitAudit(models.LogFilter{})[0]; row.ErrorMessage != reasonGroupFilter {
			t.Errorf("error_message=%q want %q", row.ErrorMessage, reasonGroupFilter)
		}
		assertNotBlocked(t, f.postMember("github", toolCall("2", "read_issue")), "read_issue, which the entry does not name")
	})

	t.Run("aggregate endpoint", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{
			"github": {"create_issue", "read_issue"},
			"docs":   {"search"},
		}, json.RawMessage(filter), nil, nil)

		assertBlocked(t, f, f.post(toolCall("1", "github__create_issue")))
		assertNotBlocked(t, f.post(toolCall("2", "github__read_issue")), "github__read_issue")
		// And on every member, which is what "on every path" costs: one
		// unscoped deny covers a tool of that name wherever it appears.
		if got := strings.Join(listedNames(t, f.post(listRequest).Body.Bytes()), ","); got != "docs__search,github__read_issue" {
			t.Errorf("listed %q want docs__search,github__read_issue", got)
		}
	})

	t.Run("single-upstream key", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"create_issue", "read_issue"}}, nil, []string{"create_issue"})

		assertBlocked(t, f, f.post(toolCall("1", "create_issue")))
		assertNotBlocked(t, f.post(toolCall("2", "read_issue")), "read_issue")
	})
}

// N1. notifications/initialized is one of the four methods the aggregate
// endpoint answers itself. On a member endpoint it is a message for that
// server, so it goes through and the member's own answer comes back.
func TestPerUpstreamNotificationIsForwarded(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)
	const notif = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

	rr := f.postMember("alpha", notif)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got, want := rr.Body.String(), `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`; got != want {
		t.Errorf("body=%s want the member's own answer %s", got, want)
	}
	if got := f.count("alpha", "notifications/initialized", ""); got != 1 {
		t.Errorf("alpha saw %d notifications, want 1", got)
	}
	if n := f.totalReqs("beta"); n != 0 {
		t.Errorf("beta saw %d requests", n)
	}

	t.Run("the aggregate still answers it itself", func(t *testing.T) {
		agg := f.post(notif)
		if agg.Code != http.StatusAccepted || agg.Body.String() != `{}` {
			t.Errorf("aggregate code=%d body=%s want 202 {}", agg.Code, agg.Body.String())
		}
	})
}

// N2. A DELETE with no body is an MCP session teardown. It has to reach the
// member carrying the session id the client is tearing down, or the upstream
// keeps the session forever.
func TestPerUpstreamDeleteForwardsSession(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"alpha": {"a"}, "beta": {"b"}}, nil, nil, nil)

	rr := f.doPath(http.MethodDelete, f.memberURL("alpha"), "", map[string]string{"Mcp-Session-Id": "sess-alpha-1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	reqs := f.requestsTo("alpha")
	if len(reqs) != 1 {
		t.Fatalf("alpha saw %d requests, want 1", len(reqs))
	}
	if reqs[0].HTTPMethod != http.MethodDelete {
		t.Errorf("alpha saw %s, want DELETE: forward replays the client's verb", reqs[0].HTTPMethod)
	}
	if got := reqs[0].Header.Get("Mcp-Session-Id"); got != "sess-alpha-1" {
		t.Errorf("alpha saw Mcp-Session-Id=%q want sess-alpha-1", got)
	}
	if n := f.totalReqs("beta"); n != 0 {
		t.Errorf("beta saw %d requests", n)
	}
}

// N3. A blocked notification has no id to correlate an error envelope
// against, so it is acknowledged and audited, exactly as on the other paths.
func TestPerUpstreamBlockedNotificationReturns202(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{"gh": {"danger"}}, nil, nil, []string{"gh__danger"})

	rr := f.postMember("gh", toolCall("", "danger"))
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

// N4. Authentication runs before anything else, on every route. A key that is
// revoked, expired or over its budget is refused on a member URL without the
// slug being looked at, so an invalid key learns nothing about the
// deployment's members, and a revoked one cannot keep using the new route.
func TestPerUpstreamAuthRunsBeforeAnySlugWork(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}}, nil, nil, nil)
		now := time.Now().UTC()
		mutateKey(t, f, func(vk *models.VirtualKey) { vk.RevokedAt = &now })

		rr := f.postMember("gh", toolCall("1", "safe_tool"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("code=%d want 401; body=%s", rr.Code, rr.Body.String())
		}
		if !f.upstreamsIdle() {
			t.Error("a revoked key reached an upstream")
		}
		row := f.waitAudit(models.LogFilter{})[0]
		if row.Status != models.StatusBlocked || row.ErrorMessage != errRevoked.Error() {
			t.Errorf("row=%+v want a blocked row naming the revocation", row)
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}}, nil, nil, nil)
		past := time.Now().UTC().Add(-time.Hour)
		mutateKey(t, f, func(vk *models.VirtualKey) { vk.ExpiresAt = &past })

		rr := f.postMember("gh", toolCall("1", "safe_tool"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("code=%d want 401; body=%s", rr.Code, rr.Body.String())
		}
		if !f.upstreamsIdle() {
			t.Error("an expired key reached an upstream")
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}}, nil, nil, nil)
		one := 1
		mutateKey(t, f, func(vk *models.VirtualKey) { vk.RateLimit = &one })

		// One request per minute: the first spends the budget on the member
		// endpoint, the second is refused there. One budget, all three doors.
		if rr := f.postMember("gh", toolCall("1", "safe_tool")); rr.Code != http.StatusOK {
			t.Fatalf("first call code=%d body=%s", rr.Code, rr.Body.String())
		}
		if rr := f.postMember("gh", toolCall("2", "safe_tool")); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("second call code=%d want 429; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// mutateKey rewrites the fixture's one virtual key through the real store.
func mutateKey(t *testing.T, f *fixture, fn func(*models.VirtualKey)) {
	t.Helper()
	ctx := context.Background()
	vk, err := f.Store.GetVirtualKey(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	fn(vk)
	if err := f.Store.UpdateVirtualKey(ctx, vk); err != nil {
		t.Fatal(err)
	}
}

// D21. Two URL shapes the router produces that no document advertises, pinned
// so a later change to the route table has to argue with a test.
func TestPerUpstreamRouteEdgeShapes(t *testing.T) {
	// "mcp" is a reserved slug, so no upstream can carry it, but the reserved
	// list is not what makes /a1/mcp/mcp unambiguous. chi routes it as a
	// member endpoint with slug "mcp", and it 404s like any other slug no
	// member has. The reserved list is defence in depth, not the mechanism.
	t.Run("a slug of mcp is just an unknown member", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}}, nil, nil, nil)
		rr := f.postTo("http://localhost:8080/a1/mcp/mcp", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("code=%d want 404; body=%s", rr.Code, rr.Body.String())
		}
		if _, msg, _ := rpcErrorOf(t, rr.Body.Bytes()); msg != "unknown endpoint" {
			t.Errorf("message=%q want %q", msg, "unknown endpoint")
		}
		if !f.upstreamsIdle() {
			t.Error("an unknown member endpoint reached an upstream")
		}
	})

	// The member analogue of the shared /mcp door: an empty keyID skips the
	// endpoint-binding check, so the request resolves against the caller's own
	// key. No cross-key reach (the key still only ever reaches its own
	// members) but it is a second URL for every member. PORM-66 covers the
	// trailing-slash sibling of this.
	t.Run("an empty key id is the keyless member door", func(t *testing.T) {
		f := newGroupFixture(t, map[string][]string{"gh": {"safe_tool"}, "docs": {"other"}}, nil, nil, nil)
		rr := f.postTo("http://localhost:8080//gh/mcp", toolCall("1", "safe_tool"))
		assertNotBlocked(t, rr, "a member endpoint reached with no key id in the path")
		if got := f.count("gh", "tools/call", "safe_tool"); got != 1 {
			t.Errorf("gh saw %d calls, want 1: an empty key id resolves against the caller's own key", got)
		}
		if n := f.totalReqs("docs"); n != 0 {
			t.Errorf("docs saw %d requests; the URL named gh", n)
		}
	})
}
