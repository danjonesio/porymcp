package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Building a group's catalogue means asking every member what it can do, and
// what those answers decide is what the client may see and reach. So the
// request doing the asking has to be the proxy's own: anything the client can
// put into it is something the client can use to change the answer.
//
// The sharpest form of that is gone. While a tool was prefixed only when more
// than one member advertised it, a client that could make a member drop out of
// the merge un-collided a name and walked out from under the rule written
// against the collided one, a bogus session id was enough. Every name now
// carries its member's slug whatever else answered, so a dropout can only
// remove that member's own tools. It can still do that, which is why the
// header hygiene below is still a control and not a tidy-up: a client that can
// silence a member decides what a group advertises and what it can route.

// clientHopHeaders are the headers forward copies from the client. They are
// listed here rather than read from copyHopHeaders on purpose: if that list
// grows, this test should keep asserting the ones that matter.
var clientHopHeaders = map[string]string{
	"Mcp-Session-Id":       "bogus",
	"Accept":               "text/event-stream",
	"Last-Event-ID":        "7",
	"Mcp-Protocol-Version": "9999",
}

// Both members advertise search, so the catalogue holds alpha__search and
// beta__search and the filter denies the first. Every header the client sent is
// dropped on the way to each member: one it refuses would take that member's
// half of the catalogue away, and the client would have chosen what this group
// is.
func TestRoutingListsIgnoreClientHopHeaders(t *testing.T) {
	f := newGroupFixture(t, map[string][]string{
		"alpha": {"search"},
		"beta":  {"search"},
	}, json.RawMessage(`{"mode":"deny","tools":["alpha__search"]}`), nil, nil)

	// memberList carries an id no proxy-composed request uses, so a catalogue
	// request the proxy wrote can be told from a copy of the client's.
	rr := f.postWith(memberList, clientHopHeaders)

	for _, slug := range []string{"alpha", "beta"} {
		reqs := f.requestsTo(slug)
		if len(reqs) == 0 {
			t.Fatalf("%s was never asked for its catalogue, so the call was routed off an incomplete merge", slug)
		}
		for i, got := range reqs {
			if got.RPCMethod != "tools/list" {
				t.Errorf("%s request %d was %q; a call that resolves to no tool must not reach any member", slug, i, got.RPCMethod)
				continue
			}
			if got.HTTPMethod != http.MethodPost {
				t.Errorf("%s: catalogue request used %s, want POST", slug, got.HTTPMethod)
			}
			if v, want := got.Header.Get("Accept"), "application/json, text/event-stream"; v != want {
				t.Errorf("%s: Accept=%q want %q: the client chose what the member was allowed to answer with", slug, v, want)
			}
			if v, want := got.Header.Get("Content-Type"), "application/json"; v != want {
				t.Errorf("%s: Content-Type=%q want %q", slug, v, want)
			}
			for _, h := range []string{"Mcp-Session-Id", "Last-Event-ID", "Mcp-Protocol-Version"} {
				if v := got.Header.Get(h); v != "" {
					t.Errorf("%s: client %s reached the member as %q; a member that refuses it drops out of the merge and renames a tool", slug, h, v)
				}
			}
			var sent struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if err := json.Unmarshal(got.Body, &sent); err != nil {
				t.Fatalf("%s: catalogue request body is not JSON: %v (%s)", slug, err, got.Body)
			}
			if string(sent.ID) == "4242" {
				t.Errorf("%s: catalogue request carried the client's id; it is the proxy's request, not the client's", slug)
			}
			if len(sent.ID) == 0 {
				t.Errorf("%s: catalogue request has no id, so its answer cannot be matched to it", slug)
			}
			if sent.Method != "tools/list" {
				t.Errorf("%s: catalogue request method=%q", slug, sent.Method)
			}
		}
	}

	// Both members answered with headers of the proxy's choosing, so both
	// halves of the catalogue are here and the deny applies to the one it
	// names.
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != "beta__search" {
		t.Fatalf("listed %q want beta__search", got)
	}
}

// The client's headers are dropped; the upstream's credential is not. A
// catalogue request that arrived unauthenticated would be answered with an
// empty or partial tool list, which is the same dropout by another route.
func TestRoutingListsStillCarryUpstreamCredential(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"gh": {Tools: []string{"list_issues"}, Bearer: "sk-real-secret"},
	}, true, nil, nil, nil)

	rr := f.postWith(memberList, clientHopHeaders)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != "gh__list_issues" {
		t.Fatalf("listed %q want gh__list_issues; an unauthenticated catalogue request answers with nothing", got)
	}

	reqs := f.requestsTo("gh")
	listed := false
	for _, got := range reqs {
		if got.RPCMethod == "tools/list" {
			listed = true
			if auth := got.Header.Get("Authorization"); auth != "Bearer sk-real-secret" {
				t.Errorf("catalogue request Authorization=%q, want the upstream's own credential", auth)
			}
		}
		for k, vs := range got.Header {
			for _, v := range vs {
				if strings.Contains(v, f.Key) {
					t.Errorf("%s request leaked the client's virtual key upstream in %s", got.RPCMethod, k)
				}
			}
		}
	}
	if !listed {
		t.Fatal("no catalogue request reached the member")
	}
	if strings.Contains(rr.Body.String(), "sk-real-secret") {
		t.Fatal("real secret leaked to the client")
	}
}

// A member that is genuinely down is still skipped, and the rest of the group
// still works. Refusing the call instead was considered and rejected (plan
// D3): one member's outage would take the whole group offline, and since a
// member answering over SSE is unreadable here today, that outage would be
// permanent. This test is what pins that decision.
func TestGroupCallStillSkipsFailingMember(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"search_docs"}},
		"beta":  {ListCode: http.StatusInternalServerError, RawList: "upstream on fire"},
	}, true, nil, nil, nil)

	rr := f.post(toolCall("1", "alpha__search_docs"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"error"`) {
		t.Fatalf("a healthy member's tool was refused because another member is down: %s", rr.Body.String())
	}
	if n := f.count("alpha", "tools/call", "search_docs"); n != 1 {
		t.Errorf("alpha saw %d tools/call for search_docs, want 1", n)
	}
}
