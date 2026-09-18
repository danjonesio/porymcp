package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/danjonesio/porymcp/internal/models"
)

// The whole handshake, against a server that behaves like the reference one:
// it mints a session, refuses tools/list without it, and answers in SSE.
func TestDiscoverSendsInitializeFirst(t *testing.T) {
	f := newFixture(t)
	got := discover(t, f.upstream(), nil)

	if !got.OK || got.Error != "" {
		t.Fatalf("ok=%v error=%q, want a clean discovery", got.OK, got.Error)
	}
	if got.ToolCount != 2 || len(got.Tools) != 2 {
		t.Errorf("tool_count=%d len(tools)=%d, want 2", got.ToolCount, len(got.Tools))
	}
	if got.ProtocolVersion != fixtureProtocol {
		t.Errorf("protocol_version=%q, want %q", got.ProtocolVersion, fixtureProtocol)
	}
	if got.ServerInfo == nil || got.ServerInfo.Name != "fixture-everything" || got.ServerInfo.Version != "1.2.3" {
		t.Errorf("server_info=%+v, want the fixture's own name and version", got.ServerInfo)
	}
	// Rounded to 10 ms. An operator cannot use finer than that, and the
	// difference between a refused connection and a filtered port is exactly
	// the signal that would turn this route into a port scanner's stopwatch.
	if got.LatencyMS%10 != 0 {
		t.Errorf("latency_ms=%d, want it rounded to 10ms", got.LatencyMS)
	}

	// The era probe goes first (PORM-151). This fixture refuses it the way a
	// session-enforcing server does, so the handshake follows unchanged.
	want := []string{"server/discover", "initialize", "notifications/initialized", "tools/list", "DELETE"}
	if calls := f.rpcCalls(); !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v, want %v", calls, want)
	}
	reqs := f.requests()
	if reqs[1].Session != "" || reqs[1].Protocol != "" {
		t.Errorf("initialize carried session=%q protocol=%q; there is nothing negotiated to declare yet", reqs[1].Session, reqs[1].Protocol)
	}
	if reqs[2].HasID {
		t.Error("notifications/initialized carried an id; a notification has none, and a server that got one would owe a response")
	}
	for _, r := range reqs[2:] {
		if r.Session != fixtureSession {
			t.Errorf("%s carried session %q, want the one initialize minted", r.RPC, r.Session)
		}
		if r.Accept != AcceptMCP {
			t.Errorf("%s sent Accept %q, want %q: the reference servers 406 anything else", r.RPC, r.Accept, AcceptMCP)
		}
	}
}

// SSE at every step, including the no-Content-Type variant real servers send.
func TestDiscoverReadsSSEFramedResponses(t *testing.T) {
	for _, framing := range []string{"sse", "none", "json"} {
		t.Run(framing, func(t *testing.T) {
			f := newFixture(t, func(f *fixture) { f.framing = framing })
			got := discover(t, f.upstream(), nil)
			if !got.OK {
				t.Fatalf("ok=false error=%q for %s framing", got.Error, framing)
			}
			if got.ToolCount != 2 {
				t.Errorf("tool_count=%d, want 2", got.ToolCount)
			}
		})
	}
}

// A Streamable HTTP server may put its own notifications on the stream it
// answers a POST with, ahead of the answer, and the reference servers do. The
// answer is picked out of the whole stream (on initialize AND on tools/list)
// rather than assumed to be the first event, and not a byte of the
// notifications travels.
func TestDiscoverSkipsNotificationsOnTheStream(t *testing.T) {
	f := newFixture(t, func(f *fixture) {
		f.noisy = true
		f.tools = nil
		for i := range 13 {
			f.tools = append(f.tools, map[string]any{"name": fmt.Sprintf("tool_%d", i)})
		}
	})
	got := discover(t, f.upstream(), nil)

	if !got.OK || got.Error != "" {
		t.Fatalf("ok=%v error=%q; a server that logs before it answers is not a broken server", got.OK, got.Error)
	}
	if got.ToolCount != 13 || len(got.Tools) != 13 {
		t.Errorf("tool_count=%d len(tools)=%d, want the 13 the fixture serves", got.ToolCount, len(got.Tools))
	}
	if got.ProtocolVersion != fixtureProtocol || got.ServerInfo == nil {
		t.Errorf("protocol_version=%q server_info=%+v; initialize's own answer was behind two notifications", got.ProtocolVersion, got.ServerInfo)
	}
	absent(t, marshal(t, got), "NOISE_MARKER", "NOISE_LOGGER", "NOISE_TOKEN")
}

// The reference server answers an uninitialised tools/list with 400 and
// -32000. The code is what the error names; the message is the operator's, in
// its own field, and no other byte of the body travels.
func TestDiscoverReadsErrorEnvelopeOnNon2xx(t *testing.T) {
	f := newFixture(t)
	f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"token lacks the repo scope","data":{"trace":"RAW_BODY_MARKER"}}}`))
	}
	got := discover(t, f.upstream(), nil)

	if want := "upstream refused tools/list (JSON-RPC error -32000)"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	if got.UpstreamMessage != "token lacks the repo scope" {
		t.Errorf("upstream_message=%q, want the server's own sentence", got.UpstreamMessage)
	}
	// initialize worked, so what it learned survives the later failure.
	if got.ProtocolVersion != fixtureProtocol || got.ServerInfo == nil {
		t.Errorf("protocol_version=%q server_info=%+v; a tools/list failure must keep what initialize learned", got.ProtocolVersion, got.ServerInfo)
	}
	absent(t, marshal(t, got), "RAW_BODY_MARKER")
}

// The version the server chose, not the one PoryMCP asked for: a strict
// 2025-06-18 server answers 400 when the header disagrees with its choice.
func TestDiscoverSendsNegotiatedProtocolVersion(t *testing.T) {
	f := newFixture(t, func(f *fixture) { f.protocol = "2025-03-26" })
	got := discover(t, f.upstream(), nil)
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	if got.ProtocolVersion != "2025-03-26" {
		t.Errorf("protocol_version=%q, want the negotiated one", got.ProtocolVersion)
	}
	// From the notification on: [0] is the era probe, which declares PoryMCP's
	// own revision, and [1] is initialize, which has nothing to declare yet.
	for _, r := range f.requests()[2:] {
		if r.Protocol != "2025-03-26" {
			t.Errorf("%s declared MCP-Protocol-Version %q, want the negotiated 2025-03-26", r.RPC, r.Protocol)
		}
	}
}

// A stateless server mints nothing, so nothing is echoed and there is no
// session to tear down.
func TestDiscoverStatelessServer(t *testing.T) {
	f := newFixture(t, func(f *fixture) { f.sessionID = "" })
	got := discover(t, f.upstream(), nil)
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	for _, r := range f.requests() {
		if r.Session != "" {
			t.Errorf("%s carried Mcp-Session-Id %q against a server that minted none", r.RPC, r.Session)
		}
		if r.Method == http.MethodDelete {
			t.Error("a stateless server got a DELETE; there is no session to end")
		}
	}
}

// The session PoryMCP opened is the session PoryMCP closes, at the upstream's
// own configured URL, never one derived from a response, and with the
// credential, because a server needs auth to end its own session.
func TestDiscoverEndsTheSession(t *testing.T) {
	check := func(t *testing.T, f *fixture) {
		t.Helper()
		reqs := f.requests()
		last := reqs[len(reqs)-1]
		if last.Method != http.MethodDelete {
			t.Fatalf("last call was %s %s, want a DELETE", last.Method, last.RPC)
		}
		if last.Session != fixtureSession {
			t.Errorf("DELETE carried session %q, want %q", last.Session, fixtureSession)
		}
		if last.Path != "/mcp" || last.RawQuery != "" {
			t.Errorf("DELETE went to %q?%q, want the upstream's own url", last.Path, last.RawQuery)
		}
		if last.Header.Get("Authorization") != "Bearer sekrit" {
			t.Errorf("DELETE Authorization=%q, want the real credential", last.Header.Get("Authorization"))
		}
	}
	auth := json.RawMessage(`{"token":"sekrit"}`)

	t.Run("after a clean catalogue", func(t *testing.T) {
		f := newFixture(t)
		up := f.upstream()
		up.AuthType = models.AuthBearer
		if got := discover(t, up, auth); !got.OK {
			t.Fatalf("ok=false error=%q", got.Error)
		}
		check(t, f)
	})

	// Deferred before the paging loop, so a failure halfway through still ends
	// the session rather than leaking one per look at the upstream.
	t.Run("after a failure mid-catalogue", func(t *testing.T) {
		f := newFixture(t)
		f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		up := f.upstream()
		up.AuthType = models.AuthBearer
		if got := discover(t, up, auth); got.OK {
			t.Fatal("ok=true against a 500 catalogue")
		}
		check(t, f)
	})

	// The one step between minting a session and the paging loop. A server
	// that answers the notification with a 500 (a token that expired
	// mid-handshake does exactly this) used to keep its session forever, and
	// every press of Refresh minted another.
	t.Run("after the notification fails", func(t *testing.T) {
		f := newFixture(t)
		f.on["notifications/initialized"] = func(w http.ResponseWriter, _ request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		up := f.upstream()
		up.AuthType = models.AuthBearer
		got := discover(t, up, auth)
		if want := "upstream answered 500 at notifications/initialized"; got.Error != want {
			t.Fatalf("error=%q, want %q", got.Error, want)
		}
		check(t, f)
	})
}

// A catalogue cut short still says how many tools it is showing: tool_count is
// the field an API client trusts, and it described an empty list beside a full
// one on every failure after the first page.
func TestDiscoverCountsThePagesThatArrived(t *testing.T) {
	f := newFixture(t)
	page := 0
	f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
		page++
		if page > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.writeResult(w, map[string]any{
			"tools":      []map[string]any{{"name": "first"}, {"name": "second"}},
			"nextCursor": "p2",
		})
	}
	got := discover(t, f.upstream(), nil)

	if got.OK {
		t.Fatal("ok=true against a catalogue whose second page failed")
	}
	if want := "upstream answered 500 at tools/list"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	if len(got.Tools) == 0 {
		t.Fatal("the first page's tools were dropped; they are what the operator can still see")
	}
	if got.ToolCount != len(got.Tools) {
		t.Errorf("tool_count=%d beside %d tools; the count describes the list it is next to", got.ToolCount, len(got.Tools))
	}
}

func TestDiscoverFollowsCursors(t *testing.T) {
	f := newFixture(t, func(f *fixture) {
		f.tools = nil
		for i := range 120 {
			f.tools = append(f.tools, map[string]any{"name": fmt.Sprintf("tool_%d", i)})
		}
		f.pageSize = 40
	})
	got := discover(t, f.upstream(), nil)
	if !got.OK || got.ToolCount != 120 || got.Truncated {
		t.Fatalf("ok=%v tool_count=%d truncated=%v, want a complete 120", got.OK, got.ToolCount, got.Truncated)
	}
	if n := strings.Count(strings.Join(f.rpcCalls(), " "), "tools/list"); n != 3 {
		t.Errorf("%d tools/list calls, want 3 pages of 40", n)
	}
	if got.Tools[0].Name != "tool_0" || got.Tools[119].Name != "tool_119" {
		t.Errorf("pages came back out of order: first=%q last=%q", got.Tools[0].Name, got.Tools[119].Name)
	}
}

// A server that never runs out is shown 500 tools and told so.
func TestDiscoverTruncatesAtFiveHundred(t *testing.T) {
	f := newFixture(t)
	page := 0
	f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
		tools := []map[string]any{}
		for i := range 40 {
			tools = append(tools, map[string]any{"name": fmt.Sprintf("t_%d_%d", page, i)})
		}
		page++
		f.writeResult(w, map[string]any{"tools": tools, "nextCursor": fmt.Sprintf("p%d", page)})
	}
	got := discover(t, f.upstream(), nil)
	if !got.OK || got.ToolCount != maxTools || !got.Truncated {
		t.Fatalf("ok=%v tool_count=%d truncated=%v, want 500 and truncated", got.OK, got.ToolCount, got.Truncated)
	}
}

// The 500-tool cap does not bound a server that pages forever with EMPTY
// pages: it never reaches 500 and would spin until the deadline, spending an
// authenticated request a turn. maxPages is what stops it.
func TestDiscoverBoundsEmptyPageLoop(t *testing.T) {
	f := newFixture(t)
	page := 0
	f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
		page++
		f.writeResult(w, map[string]any{"tools": []map[string]any{}, "nextCursor": fmt.Sprintf("p%d", page)})
	}
	start := time.Now()
	got := discover(t, f.upstream(), nil)
	if elapsed := time.Since(start); elapsed > discoverBudget {
		t.Fatalf("took %v; the page bound must stop this well before the deadline", elapsed)
	}
	if !got.OK || got.ToolCount != 0 || !got.Truncated {
		t.Fatalf("ok=%v tool_count=%d truncated=%v, want an honest empty truncated catalogue", got.OK, got.ToolCount, got.Truncated)
	}
	// The era probe + initialize + notification + maxPages + DELETE.
	if n := len(f.requests()); n > maxPages+4 {
		t.Errorf("%d requests, want at most %d", n, maxPages+4)
	}
}

// A cursor is only followed when it is a bounded JSON string. Anything else is
// "there may be more, but not by a cursor this will send", said out loud
// rather than passed off as a complete catalogue, and never sent back.
func TestDiscoverRefusesAnUnusableCursor(t *testing.T) {
	for name, cursor := range map[string]any{
		"2 KiB of text": strings.Repeat("c", 2<<10),
		"a number":      42,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
				f.writeResult(w, map[string]any{
					"tools":      []map[string]any{{"name": "one"}},
					"nextCursor": cursor,
				})
			}
			got := discover(t, f.upstream(), nil)
			if !got.OK || !got.Truncated {
				t.Fatalf("ok=%v truncated=%v, want an honest truncated catalogue", got.OK, got.Truncated)
			}
			if got.ToolCount != 1 {
				t.Errorf("tool_count=%d, want the page that did arrive", got.ToolCount)
			}
			if n := strings.Count(strings.Join(f.rpcCalls(), " "), "tools/list"); n != 1 {
				t.Errorf("%d tools/list calls, want 1: an unusable cursor is not sent back", n)
			}
		})
	}
}

// One string compare catches the actual bug shape maxPages only bounds.
func TestDiscoverStopsOnRepeatedCursor(t *testing.T) {
	f := newFixture(t)
	f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
		f.writeResult(w, map[string]any{
			"tools":      []map[string]any{{"name": "one"}},
			"nextCursor": "same-forever",
		})
	}
	got := discover(t, f.upstream(), nil)
	if !got.OK || !got.Truncated {
		t.Fatalf("ok=%v truncated=%v, want ok and truncated", got.OK, got.Truncated)
	}
	if n := strings.Count(strings.Join(f.rpcCalls(), " "), "tools/list"); n != 2 {
		t.Errorf("%d tools/list calls, want 2: the second repeat is the stop", n)
	}
}

// The catalogue is what an operator will write rules against, so the identity
// comes from models.ToolIdentity and only from a stored, valid slug.
func TestDiscoverScopedNames(t *testing.T) {
	for _, tc := range []struct {
		slug, want string
	}{
		{"docs", "docs__echo"},
		{"", ""},
		{"Not A Slug", ""},
		{"trailing_", ""},
		{"double__sep", ""},
	} {
		t.Run("slug="+tc.slug, func(t *testing.T) {
			f := newFixture(t)
			up := f.upstream()
			up.Slug = tc.slug
			got := discover(t, up, nil)
			if !got.OK {
				t.Fatalf("ok=false error=%q", got.Error)
			}
			if got.Tools[0].ScopedName != tc.want {
				t.Errorf("scoped_name=%q, want %q", got.Tools[0].ScopedName, tc.want)
			}
			if tc.want == "" && got.Slug != "" {
				t.Errorf("slug=%q returned for an unusable slug", got.Slug)
			}
		})
	}
}

// Exactly what buildRoutes drops, dropped here, counted and never named.
func TestDiscoverDropsUnnameableTools(t *testing.T) {
	long := "DROPME_LONG_" + strings.Repeat("z", 300)
	f := newFixture(t, func(f *fixture) {
		f.tools = []map[string]any{
			{"name": "keeper"},
			{"name": ""},
			{"name": "DROPME_CTL\x01x"},
			{"name": "DROPME_FFFD�x"},
			{"name": long},
			{"name": "keeper_two"},
		}
	})
	got := discover(t, f.upstream(), nil)
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	if got.ToolCount != 2 || len(got.Tools) != 2 {
		t.Errorf("tool_count=%d, want the 2 nameable ones", got.ToolCount)
	}
	if got.Unnameable != 4 {
		t.Errorf("unnameable_tools=%d, want 4", got.Unnameable)
	}
	absent(t, marshal(t, got), "DROPME_LONG", "DROPME_CTL", "DROPME_FFFD")
	// Pinned against the predicate itself, so the two can never drift.
	for _, name := range []string{"", "DROPME_CTL\x01x", "DROPME_FFFD�x"} {
		if models.UsableToolName(name) {
			t.Fatalf("models.UsableToolName(%q) is true; this test and buildRoutes now disagree about which tools exist", name)
		}
	}
}

// An upstream advertising one name twice is showing the operator its own
// ambiguity. Deduping would hide it.
func TestDiscoverKeepsDuplicateNames(t *testing.T) {
	f := newFixture(t, func(f *fixture) {
		f.tools = []map[string]any{
			{"name": "search", "description": "the first one"},
			{"name": "search", "description": "the second one"},
		}
	})
	got := discover(t, f.upstream(), nil)
	if got.ToolCount != 2 {
		t.Fatalf("tool_count=%d, want both entries", got.ToolCount)
	}
	if got.Tools[0].Description == got.Tools[1].Description {
		t.Error("the two entries were merged; an operator cannot see the ambiguity")
	}
}

func TestDiscoverClampsUpstreamStrings(t *testing.T) {
	// A three-byte rune, so every cap's cut lands mid-rune.
	huge := strings.Repeat("€", 100_000)
	f := newFixture(t, func(f *fixture) {
		f.serverName = huge
		f.serverVersion = huge
		f.protocol = huge
		f.tools = []map[string]any{
			{"name": "big", "description": huge, "title": huge,
				"annotations": map[string]any{"title": huge, "readOnlyHint": true}},
			{"name": "small", "description": "short"},
		}
	})
	got := discover(t, f.upstream(), nil)
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	for _, c := range []struct {
		what string
		s    string
		max  int
	}{
		{"description", got.Tools[0].Description, maxDescriptionBytes},
		{"title", got.Tools[0].Title, maxTitleBytes},
		{"annotations.title", got.Tools[0].Annotations.Title, maxTitleBytes},
		{"server_info.name", got.ServerInfo.Name, maxServerNameBytes},
		{"server_info.version", got.ServerInfo.Version, maxServerVersionBytes},
		{"protocol_version", got.ProtocolVersion, maxProtocolVersionBytes},
	} {
		if len(c.s) > c.max {
			t.Errorf("%s is %d bytes, want at most %d", c.what, len(c.s), c.max)
		}
		if !utf8.ValidString(c.s) {
			t.Errorf("%s was cut mid-rune", c.what)
		}
	}
	if !got.Tools[0].DescriptionTruncated {
		t.Error("description_truncated is false on a clamped description")
	}
	if got.Tools[1].DescriptionTruncated {
		t.Error("description_truncated is set on a description that fitted")
	}
}

// nasty carries one of each character class an upstream string must not
// deliver: a NUL, an ANSI colour escape, a BEL, a DEL, a U+FFFD, and an
// embedded newline that would otherwise make one field two lines.
const nasty = "before\x00\x1b[31m\x07\x7f\ufffd mid\nline after"

// assertScrubbed is the same check for every field: not one of those
// characters survives, in the value or in the JSON an operator reads.
func assertScrubbed(t *testing.T, what, value, rendered string) {
	t.Helper()
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			t.Errorf("%s kept %q: %q", what, r, value)
		}
	}
	// json.Marshal escapes the control characters and passes DEL and U+FFFD
	// through, so both spellings are checked.
	absent(t, rendered, `\u0000`, `\u001b`, `\u0007`, "\x7f", "\ufffd")
}

// Every upstream string that reaches a response is scrubbed, not just the one
// the design calls the deliberate exception. An operator reading the API with
// `curl | jq -r` gets these bytes raw, and \x1b[31m from a server nobody at
// PoryMCP controls is somebody else's escape sequence in their terminal.
func TestDiscoverScrubsControlCharacters(t *testing.T) {
	for _, tc := range []struct {
		field string
		setup func(f *fixture)
		get   func(d Discovery) string
	}{
		{"description", func(f *fixture) {
			f.tools = []map[string]any{{"name": "t", "description": nasty}}
		}, func(d Discovery) string { return d.Tools[0].Description }},
		{"title", func(f *fixture) {
			f.tools = []map[string]any{{"name": "t", "title": nasty}}
		}, func(d Discovery) string { return d.Tools[0].Title }},
		{"annotations.title", func(f *fixture) {
			f.tools = []map[string]any{{"name": "t", "annotations": map[string]any{"title": nasty}}}
		}, func(d Discovery) string { return d.Tools[0].Annotations.Title }},
		{"server_info.name", func(f *fixture) { f.serverName = nasty },
			func(d Discovery) string { return d.ServerInfo.Name }},
		{"server_info.version", func(f *fixture) { f.serverVersion = nasty },
			func(d Discovery) string { return d.ServerInfo.Version }},
		{"protocol_version", func(f *fixture) { f.protocol = nasty },
			func(d Discovery) string { return d.ProtocolVersion }},
		{"upstream_message", func(f *fixture) {
			f.on["tools/list"] = func(w http.ResponseWriter, _ request) {
				f.writeRPCError(w, http.StatusOK, -32000, nasty)
			}
		}, func(d Discovery) string { return d.UpstreamMessage }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			f := newFixture(t, tc.setup)
			got := discover(t, f.upstream(), nil)
			value := tc.get(got)
			if value == "" {
				t.Fatalf("%s came back empty; the row proves nothing: %+v", tc.field, got)
			}
			assertScrubbed(t, tc.field, value, marshal(t, got))
			// The newline became a space rather than being dropped, so two
			// words do not become one.
			if !strings.Contains(value, "mid line after") {
				t.Errorf("%s = %q, want the newline turned into a space", tc.field, value)
			}
		})
	}
}

// UpstreamMessage is the ONE field that repeats an upstream's own words, so
// the sanitiser it goes through gets its own test: one line, none of those
// characters, at most 200 bytes, and cut at a rune boundary.
func TestDiscoverSanitisesUpstreamMessage(t *testing.T) {
	message := "level\x1b[31m one\x7f�\ntwo\t" + strings.Repeat("€", 5<<10)
	f := newFixture(t)
	f.on["initialize"] = func(w http.ResponseWriter, _ request) {
		f.writeRPCError(w, http.StatusOK, -32000, message)
	}
	got := discover(t, f.upstream(), nil)

	if want := "upstream refused initialize (JSON-RPC error -32000)"; got.Error != want {
		t.Fatalf("error=%q, want %q", got.Error, want)
	}
	msg := got.UpstreamMessage
	if msg == "" {
		t.Fatal("upstream_message is empty; the server's own words are the point of the field")
	}
	if len(msg) > maxUpstreamMessageBytes {
		t.Errorf("upstream_message is %d bytes, want at most %d", len(msg), maxUpstreamMessageBytes)
	}
	if !utf8.ValidString(msg) {
		t.Errorf("upstream_message was cut mid-rune: %q", msg)
	}
	if strings.ContainsAny(msg, "\n\r") {
		t.Errorf("upstream_message is more than one line: %q", msg)
	}
	assertScrubbed(t, "upstream_message", msg, marshal(t, got))
}

// Absent hints stay absent: nil is "the server said nothing", which is not
// false. PORM-95 will act on these, so the shape has to be typed.
func TestDiscoverTypesAnnotations(t *testing.T) {
	f := newFixture(t, func(f *fixture) {
		f.tools = []map[string]any{
			{"name": "reader", "annotations": map[string]any{
				"title": "Read a file", "readOnlyHint": true, "destructiveHint": false,
			}},
			{"name": "plain"},
		}
	})
	got := discover(t, f.upstream(), nil)
	a := got.Tools[0].Annotations
	if a == nil || a.Title != "Read a file" {
		t.Fatalf("annotations=%+v, want the upstream's own title", a)
	}
	if a.ReadOnlyHint == nil || !*a.ReadOnlyHint {
		t.Errorf("readOnlyHint=%v, want true", a.ReadOnlyHint)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("destructiveHint=%v, want an explicit false", a.DestructiveHint)
	}
	if a.IdempotentHint != nil || a.OpenWorldHint != nil {
		t.Errorf("a hint the server never sent came back as %v/%v", a.IdempotentHint, a.OpenWorldHint)
	}
	if got.Tools[1].Annotations != nil {
		t.Error("a tool with no annotations grew an empty block")
	}
	rendered := marshal(t, got)
	if strings.Contains(rendered, `"idempotentHint"`) {
		t.Errorf("an unsent hint was serialised: %s", rendered)
	}
}

// A server that answered, with nothing to offer, is a success.
func TestDiscoverZeroTools(t *testing.T) {
	f := newFixture(t, func(f *fixture) { f.tools = nil })
	got := discover(t, f.upstream(), nil)
	if !got.OK || got.ToolCount != 0 {
		t.Fatalf("ok=%v tool_count=%d, want an empty success", got.OK, got.ToolCount)
	}
	if !strings.Contains(marshal(t, got), `"tools":[]`) {
		t.Errorf("tools did not marshal as an array: %s", marshal(t, got))
	}
}

// Tools is never null. A dashboard that maps over it, and a client that loops,
// both break on null where they cope with [].
func TestDiscoveryMarshalsEmptyToolsAsArray(t *testing.T) {
	if s := marshal(t, Failed("stored credential cannot be decrypted")); !strings.Contains(s, `"tools":[]`) {
		t.Errorf("Failed() marshals as %s, want tools:[]", s)
	}
	// Every early refusal inside Discover goes out through the same zero
	// value, so one that forgot the empty slice would be caught here.
	f := newFixture(t)
	up := f.upstream()
	up.Transport = models.TransportSSE
	if s := marshal(t, discover(t, up, nil)); !strings.Contains(s, `"tools":[]`) {
		t.Errorf("a refused discovery marshals as %s, want tools:[]", s)
	}
}

func TestDiscoverSSETransport(t *testing.T) {
	f := newFixture(t)
	up := f.upstream()
	up.Transport = models.TransportSSE
	got := discover(t, up, nil)
	if want := "the sse transport is not implemented yet; use streamable-http"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests made; an unimplemented transport costs the upstream nothing", n)
	}
}

// A body past the read cap is refused rather than half-decoded. 300 tools with
// 8 KiB of description each is inside the MCP norm, and before this the cut
// document failed to parse and a working server was reported as one that does
// not speak JSON-RPC.
func TestDiscoverRefusesAnOversizedBody(t *testing.T) {
	t.Run("over the cap", func(t *testing.T) {
		f := newFixture(t)
		f.on["initialize"] = func(w http.ResponseWriter, _ request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","pad":"`)
			_, _ = io.WriteString(w, strings.Repeat("p", 4<<20))
			_, _ = io.WriteString(w, `"}}`)
		}
		got := discover(t, f.upstream(), nil)
		if want := "upstream's answer to initialize is larger than discovery will read"; got.Error != want {
			t.Errorf("error=%q, want %q", got.Error, want)
		}
		// The era probe and initialize, and nothing after: nothing was learned,
		// and the upstream minted no session this could have ended.
		if n := len(f.requests()); n != 2 {
			t.Errorf("%d requests, want 2", n)
		}
	})

	// The +1 in the read is what makes this the boundary and not an off-by-one:
	// a body of exactly the cap is a body discovery reads.
	t.Run("exactly the cap", func(t *testing.T) {
		f := newFixture(t)
		head := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"edge","version":"1"},"pad":"`
		tail := `"}}`
		body := head + strings.Repeat("p", discoverBodyBytes-len(head)-len(tail)) + tail
		if len(body) != discoverBodyBytes {
			t.Fatalf("the fixture body is %d bytes, want exactly %d", len(body), discoverBodyBytes)
		}
		f.on["initialize"] = func(w http.ResponseWriter, _ request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", fixtureSession)
			_, _ = io.WriteString(w, body)
		}
		got := discover(t, f.upstream(), nil)
		if !got.OK || got.Error != "" {
			t.Fatalf("ok=%v error=%q; a body of exactly the cap is one discovery reads", got.OK, got.Error)
		}
		if got.ServerInfo == nil || got.ServerInfo.Name != "edge" {
			t.Errorf("server_info=%+v, want the answer parsed", got.ServerInfo)
		}
	})
}

// An HTML error page is readable news, not a panic and not a quoted page.
func TestDiscoverNonJSON(t *testing.T) {
	f := newFixture(t)
	f.on["initialize"] = func(w http.ResponseWriter, _ request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>HTML_PAGE_MARKER</body></html>"))
	}
	got := discover(t, f.upstream(), nil)
	if want := "upstream did not answer initialize with JSON-RPC"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	absent(t, marshal(t, got), "HTML_PAGE_MARKER", "text/html")
}

// A session id PoryMCP will put back on its own requests is checked first:
// net/http accepted a 100 KB value in a probe, and a value with a space or a
// control byte in it makes Do fail with the header NAME quoted, which would be
// misread as a transport failure. (Go's own server rewrites a CRLF in a header
// value to a space before it ever reaches the wire, so that is the shape the
// CRLF case actually arrives in.)
func TestDiscoverBoundsSessionID(t *testing.T) {
	for name, id := range map[string]string{
		"100 KB":            strings.Repeat("s", 100_000),
		"space (was CRLF)":  "abc\r\nX-Evil: 1",
		"space":             "abc def",
		"just over the cap": strings.Repeat("s", maxSessionIDBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.on["initialize"] = func(w http.ResponseWriter, _ request) {
				w.Header().Set("Mcp-Session-Id", id)
				f.writeResult(w, map[string]any{
					"protocolVersion": fixtureProtocol,
					"serverInfo":      map[string]any{"name": "x", "version": "1"},
				})
			}
			got := discover(t, f.upstream(), nil)
			if want := "upstream sent an unusable session id"; got.Error != want {
				t.Errorf("error=%q, want %q", got.Error, want)
			}
			for _, r := range f.requests() {
				if r.Method == http.MethodDelete {
					t.Error("a DELETE went out with a session id that was refused")
				}
			}
		})
	}
}

func TestDiscoverTimesOut(t *testing.T) {
	// The shipped budget, pinned before it is shortened: the sentence an
	// operator reads names it.
	if discoverBudget != 10*time.Second {
		t.Fatalf("discoverBudget=%v, want 10s: the shipped whole-sequence budget", discoverBudget)
	}
	// A package var, mutated here and read by TestDiscoverBoundsEmptyPageLoop.
	// Safe only because NOTHING in this package calls t.Parallel: the first
	// test that does turns this into a data race. Do not add one.
	restore := discoverBudget
	discoverBudget = 300 * time.Millisecond
	t.Cleanup(func() { discoverBudget = restore })

	f := newFixture(t)
	f.on["initialize"] = func(w http.ResponseWriter, _ request) {
		// Held open until the client gives up, so httptest.Server.Close (which
		// waits for outstanding requests) is not the thing under test.
		<-t.Context().Done()
	}
	start := time.Now()
	got := New().Discover(t.Context(), f.upstream(), nil)
	elapsed := time.Since(start)

	if want := "upstream did not answer within 300ms"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	if got.OK {
		t.Error("ok=true against a server that never answered")
	}
	if elapsed > 3*time.Second {
		t.Errorf("took %v; the whole-sequence budget did not fire", elapsed)
	}
}

// The dashboard aborts a fetch, chi cancels, and the upstream request unwinds
// with it. Nothing keeps running after Discover returns.
func TestDiscoverCancelledByCaller(t *testing.T) {
	// step is where the fixture blocks until the caller gives up.
	run := func(t *testing.T, step string) *fixture {
		t.Helper()
		f := newFixture(t)
		reached := make(chan struct{})
		f.on[step] = func(w http.ResponseWriter, _ request) {
			close(reached)
			<-t.Context().Done()
		}
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-reached
			cancel()
		}()

		start := time.Now()
		got := New().Discover(ctx, f.upstream(), nil)
		if got.OK {
			t.Error("ok=true after the caller went away")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("took %v after cancellation; the request did not unwind", elapsed)
		}
		for _, r := range f.requests() {
			if r.Method == http.MethodDelete {
				t.Error("a teardown was sent after the caller cancelled; there is nobody left to be slow for")
			}
		}
		return f
	}

	// Nothing was opened yet, so there is nothing to skip tearing down.
	t.Run("during initialize", func(t *testing.T) { run(t, "initialize") })

	// The case the "skip the teardown when the browser is gone" rule is FOR:
	// initialize has already minted a session, so endSession is registered and
	// has a session to end, and only the cancelled-context check stops it.
	t.Run("after the session is open", func(t *testing.T) {
		f := run(t, "tools/list")
		if calls := f.rpcCalls(); len(calls) < 4 || calls[3] != "tools/list" {
			t.Fatalf("calls=%v; the session was never opened, so this is the initialize case again", calls)
		}
	})
}

// modernServer turns a fixture into a 2026-07-28 server: it answers
// server/discover with result (echoing the probe's id, as a real server does),
// lists tools only for a request that declares itself and carries _meta, and
// has no handshake. result is the DiscoverResult as raw JSON.
func modernServer(f *fixture, result string) {
	f.sessionID = ""
	f.on[stepDiscover] = func(w http.ResponseWriter, _ request) {
		f.writeFramed(w, http.StatusOK, []byte(`{"jsonrpc":"2.0","id":`+idDiscover+`,"result":`+result+`}`))
	}
	f.on["tools/list"] = func(w http.ResponseWriter, rq request) {
		var body struct {
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		_ = json.Unmarshal([]byte(rq.Body), &body)
		declared := rq.Protocol == RevisionModern && rq.Header.Get("Mcp-Method") == "tools/list"
		if !declared || len(body.Params.Meta[metaProtocol]) == 0 || len(body.Params.Meta[metaClientInfo]) == 0 {
			f.writeRPCError(w, http.StatusBadRequest, CodeHeaderMismatch, "header mismatch")
			return
		}
		f.writeResult(w, f.page(rq.Cursor))
	}
	f.on["initialize"] = func(w http.ResponseWriter, _ request) {
		f.writeRPCError(w, http.StatusBadRequest, -32601, "Method not found")
	}
}

const modernResult = `{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.example/search":{}}},` +
	`"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"stateless-server","version":"2.0.0"}}}`

// PORM-151 criterion 1. A server that has no handshake at all is discovered,
// and is never sent the three things the modern era removed.
func TestDiscoverModernServer(t *testing.T) {
	f := newFixture(t, func(f *fixture) { modernServer(f, modernResult) })
	got := discover(t, f.upstream(), nil)
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	if got.Era != "modern" || got.ProtocolVersion != RevisionModern {
		t.Errorf("era=%q protocol_version=%q, want modern and %s", got.Era, got.ProtocolVersion, RevisionModern)
	}
	if !reflect.DeepEqual(got.SupportedVersions, []string{"2026-07-28"}) {
		t.Errorf("supported_versions=%v", got.SupportedVersions)
	}
	if !reflect.DeepEqual(got.Capabilities, []string{"tools", "io.example/search"}) {
		t.Errorf("capabilities=%v", got.Capabilities)
	}
	if got.ServerInfo == nil || got.ServerInfo.Name != "stateless-server" || got.ServerInfo.Version != "2.0.0" {
		t.Errorf("server_info=%+v, want what the server put in _meta", got.ServerInfo)
	}
	if got.ToolCount != 2 || got.Tools[0].ScopedName != "docs__echo" {
		t.Errorf("tool_count=%d tools=%+v", got.ToolCount, got.Tools)
	}
	if want := []string{"server/discover", "tools/list"}; !reflect.DeepEqual(f.rpcCalls(), want) {
		t.Errorf("calls=%v, want %v: no initialize, no notification and no DELETE in the modern era", f.rpcCalls(), want)
	}
	for _, r := range f.requests() {
		if r.Session != "" {
			t.Errorf("%s carried session %q; a modern server has none", r.RPC, r.Session)
		}
	}
}

// A modern catalogue pages like any other, and every page declares itself.
func TestDiscoverModernServerPages(t *testing.T) {
	f := newFixture(t, func(f *fixture) {
		modernServer(f, modernResult)
		f.pageSize = 1
	})
	got := discover(t, f.upstream(), nil)
	if !got.OK || got.ToolCount != 2 {
		t.Fatalf("ok=%v tool_count=%d error=%q, want both pages", got.OK, got.ToolCount, got.Error)
	}
	if want := []string{"server/discover", "tools/list", "tools/list"}; !reflect.DeepEqual(f.rpcCalls(), want) {
		t.Errorf("calls=%v, want %v", f.rpcCalls(), want)
	}
}

// PORM-151 criterion 2. Three ways a handshake server says it has never heard
// of server/discover, and one host that says nothing at all. The probe's
// outcome must leave no mark on a discovery the handshake then completes.
func TestDiscoverLegacyServer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe func(f *fixture) func(http.ResponseWriter, request)
	}{
		// The fixture's own session gate: 400 and -32000 "Server not initialized".
		{"not initialized", nil},
		{"method not found", func(f *fixture) func(http.ResponseWriter, request) {
			return func(w http.ResponseWriter, _ request) {
				f.writeRPCError(w, http.StatusOK, -32601, "Method not found")
			}
		}},
		{"a 404 page", func(*fixture) func(http.ResponseWriter, request) {
			return func(w http.ResponseWriter, _ request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, "<html>no such page</html>")
			}
		}},
		{"a result that is not a DiscoverResult", func(f *fixture) func(http.ResponseWriter, request) {
			return func(w http.ResponseWriter, _ request) {
				f.writeFramed(w, http.StatusOK, []byte(`{"jsonrpc":"2.0","id":`+idDiscover+`,"result":{"ok":true}}`))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.probe != nil {
				f.on[stepDiscover] = tc.probe(f)
			}
			got := discover(t, f.upstream(), nil)
			if !got.OK || got.Error != "" || got.UpstreamMessage != "" {
				t.Fatalf("ok=%v error=%q upstream_message=%q, want a clean handshake after the fallback", got.OK, got.Error, got.UpstreamMessage)
			}
			if got.Era != "legacy" || got.ProtocolVersion != fixtureProtocol {
				t.Errorf("era=%q protocol_version=%q, want legacy and the negotiated %s", got.Era, got.ProtocolVersion, fixtureProtocol)
			}
			if got.SupportedVersions != nil {
				t.Errorf("supported_versions=%v; this server advertised none", got.SupportedVersions)
			}
			if !reflect.DeepEqual(got.Capabilities, []string{"tools"}) {
				t.Errorf("capabilities=%v, want what initialize advertised", got.Capabilities)
			}
			if got.ServerInfo == nil || got.ServerInfo.Name != "fixture-everything" || got.ToolCount != 2 {
				t.Errorf("server_info=%+v tool_count=%d", got.ServerInfo, got.ToolCount)
			}
			want := []string{"server/discover", "initialize", "notifications/initialized", "tools/list", "DELETE"}
			if !reflect.DeepEqual(f.rpcCalls(), want) {
				t.Errorf("calls=%v, want %v", f.rpcCalls(), want)
			}
		})
	}

	// era is evidence, never a default: a host that answered nothing has none.
	t.Run("nothing answered", func(t *testing.T) {
		up := &models.Upstream{URL: "https://example.test/mcp", Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone}
		got := clientWith(&countingTransport{}).Discover(t.Context(), up, nil)
		if got.OK || got.Era != "" {
			t.Errorf("ok=%v era=%q, want a failure that claims no era", got.OK, got.Era)
		}
		if strings.Contains(marshal(t, got), `"era"`) {
			t.Errorf("era reached the response: %s", marshal(t, got))
		}
	})

	// A probe that was answered and a handshake that then failed: the era is
	// known, and the failure is the handshake's own sentence.
	t.Run("answered, then the handshake fails", func(t *testing.T) {
		f := newFixture(t)
		f.on["initialize"] = func(w http.ResponseWriter, _ request) { w.WriteHeader(http.StatusInternalServerError) }
		got := discover(t, f.upstream(), nil)
		if got.Era != "legacy" || got.Error != "upstream answered 500 at initialize" {
			t.Errorf("era=%q error=%q", got.Era, got.Error)
		}
	})
}

// PORM-151 criterion 3, and the configuration the spec's versioning page
// describes: a server that answers both eras is spoken to the modern way, and
// one that answers server/discover but lists only handshake revisions is
// spoken to by the handshake, with the list it gave shown as the reason.
func TestDiscoverDualEraServer(t *testing.T) {
	t.Run("both eras", func(t *testing.T) {
		f := newFixture(t, func(f *fixture) {
			modernServer(f, `{"supportedVersions":["2025-11-25","2026-07-28"],"capabilities":{"tools":{}}}`)
			delete(f.on, "initialize") // it has a working handshake too
		})
		got := discover(t, f.upstream(), nil)
		if !got.OK || got.Era != "modern" {
			t.Fatalf("ok=%v era=%q error=%q", got.OK, got.Era, got.Error)
		}
		for _, call := range f.rpcCalls() {
			if call == "initialize" {
				t.Errorf("calls=%v; a server that speaks the modern era is not sent initialize", f.rpcCalls())
			}
		}
		if got.ServerInfo != nil {
			t.Errorf("server_info=%+v; this server sent none, which is allowed", got.ServerInfo)
		}
	})

	t.Run("configured for the handshake only", func(t *testing.T) {
		f := newFixture(t)
		f.on[stepDiscover] = func(w http.ResponseWriter, _ request) {
			f.writeFramed(w, http.StatusOK, []byte(`{"jsonrpc":"2.0","id":`+idDiscover+`,"result":{"supportedVersions":["2025-11-25"]}}`))
		}
		got := discover(t, f.upstream(), nil)
		if !got.OK || got.Era != "legacy" || got.ProtocolVersion != fixtureProtocol {
			t.Fatalf("ok=%v era=%q protocol_version=%q error=%q", got.OK, got.Era, got.ProtocolVersion, got.Error)
		}
		if !reflect.DeepEqual(got.SupportedVersions, []string{"2025-11-25"}) {
			t.Errorf("supported_versions=%v, want the list that caused the fallback", got.SupportedVersions)
		}
	})
}

// PORM-151 criterion 4, as amended: the sentence is fixed, the advertised
// versions are data in supported_versions, upstream_message stays the server's
// own words, and a modern server is never walked through a handshake.
func TestDiscoverUnsupportedVersion(t *testing.T) {
	f := newFixture(t)
	f.on[stepDiscover] = func(w http.ResponseWriter, _ request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2027-01-01"]}}}`)
	}
	got := discover(t, f.upstream(), nil)
	if got.OK || got.Error != "upstream supports no protocol version PoryMCP speaks" {
		t.Fatalf("ok=%v error=%q", got.OK, got.Error)
	}
	if got.Era != "modern" || got.ProtocolVersion != "" {
		t.Errorf("era=%q protocol_version=%q, want modern and no version agreed", got.Era, got.ProtocolVersion)
	}
	if !reflect.DeepEqual(got.SupportedVersions, []string{"2027-01-01"}) {
		t.Errorf("supported_versions=%v, want what the server said it supports", got.SupportedVersions)
	}
	if got.UpstreamMessage != "Unsupported protocol version" {
		t.Errorf("upstream_message=%q, want the server's own message", got.UpstreamMessage)
	}
	if want := []string{"server/discover"}; !reflect.DeepEqual(f.rpcCalls(), want) {
		t.Errorf("calls=%v, want %v: no fallback", f.rpcCalls(), want)
	}
}

// The other two recognised modern errors: their own sentences, no fallback.
func TestDiscoverModernHeaderCodes(t *testing.T) {
	for code, want := range map[int]string{
		CodeHeaderMismatch:          "upstream refused the routing headers PoryMCP sent (-32020)",
		CodeMissingClientCapability: "upstream requires a client capability PoryMCP does not offer (-32021)",
	} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newFixture(t)
			f.on[stepDiscover] = func(w http.ResponseWriter, _ request) {
				f.writeRPCError(w, http.StatusBadRequest, code, "no")
			}
			got := discover(t, f.upstream(), nil)
			if got.OK || got.Error != want || got.Era != "modern" {
				t.Errorf("ok=%v era=%q error=%q, want %q", got.OK, got.Era, got.Error, want)
			}
			if got.SupportedVersions != nil || got.Capabilities != nil || got.ServerInfo != nil {
				t.Errorf("an error body carries nothing to report: %+v", got)
			}
			if calls := f.rpcCalls(); len(calls) != 1 {
				t.Errorf("calls=%v, want the probe alone", calls)
			}
		})
	}
}

// PORM-151 criterion 5, as amended: the new lists are bounded, a bad entry is
// dropped, and none of it touches truncated, which is about the tool
// catalogue and which the dashboard reports in words.
func TestDiscoverModernFieldsBounded(t *testing.T) {
	versions := []string{"2026-07-28", strings.Repeat("v", 33), "2026\x0107-29"}
	for i := 0; i < 9; i++ {
		versions = append(versions, fmt.Sprintf("2030-01-%02d", i+1))
	}
	extensions := map[string]any{}
	for i := 0; i < 17; i++ {
		extensions[fmt.Sprintf("io.example/ext-%02d", i)] = map[string]any{}
	}
	result, _ := json.Marshal(map[string]any{
		"supportedVersions": versions,
		"capabilities":      map[string]any{"extensions": extensions},
	})
	f := newFixture(t, func(f *fixture) { modernServer(f, string(result)) })
	got := discover(t, f.upstream(), nil)
	if !got.OK {
		t.Fatalf("ok=false error=%q", got.Error)
	}
	if len(got.SupportedVersions) != 8 || got.SupportedVersions[0] != "2026-07-28" || got.SupportedVersions[1] != "2030-01-01" {
		t.Errorf("supported_versions=%q, want eight, with the long one and the one carrying a control byte dropped", got.SupportedVersions)
	}
	if len(got.Capabilities) != 16 {
		t.Errorf("%d capabilities, want 16 of the 17", len(got.Capabilities))
	}
	if got.Truncated {
		t.Error("truncated=true; the whole tool catalogue was listed")
	}

	// A server that answers with no version PoryMCP speaks still named itself.
	t.Run("unusable, and what it said is kept", func(t *testing.T) {
		f := newFixture(t, func(f *fixture) {
			modernServer(f, strings.Replace(modernResult, `["2026-07-28"]`, `[]`, 1))
		})
		got := discover(t, f.upstream(), nil)
		if got.OK || got.Error != "upstream supports no protocol version PoryMCP speaks" || got.Era != "modern" {
			t.Fatalf("ok=%v era=%q error=%q", got.OK, got.Era, got.Error)
		}
		if got.ServerInfo == nil || got.ServerInfo.Name != "stateless-server" || len(got.Capabilities) != 2 {
			t.Errorf("server_info=%+v capabilities=%v, want both kept", got.ServerInfo, got.Capabilities)
		}
	})
}

// PORM-151 criterion 7, as amended: the probe spends the discovery budget and
// does not add to it. The server never answers server/discover; no test here
// sleeps, because httptest.Server.Close waits for the handler.
func TestDiscoverBudgetIncludesProbe(t *testing.T) {
	// The same package var TestDiscoverTimesOut shortens, under the same rule:
	// nothing in this package calls t.Parallel. Set before New(), which reads it.
	restore := discoverBudget
	discoverBudget = 300 * time.Millisecond
	t.Cleanup(func() { discoverBudget = restore })

	f := newFixture(t)
	f.on[stepDiscover] = func(http.ResponseWriter, request) { <-t.Context().Done() }

	start := time.Now()
	got := New().Discover(t.Context(), f.upstream(), nil)
	elapsed := time.Since(start)

	if want := "upstream did not answer within 300ms"; got.Error != want {
		t.Errorf("error=%q, want %q", got.Error, want)
	}
	if got.OK || got.Era != "" {
		t.Errorf("ok=%v era=%q against a server that never answered", got.OK, got.Era)
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v; the probe must sit inside the whole-sequence budget", elapsed)
	}
}
