package mcpclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// discoverResult is a server/discover result body, as raw JSON, for the rows
// below: the versions a server lists and nothing else unless a row adds it.
func discoverResult(versions ...string) json.RawMessage {
	// Made with a length so no versions marshals as [] and not null, which is
	// a different row of the table.
	versions = append([]string{}, versions...)
	b, _ := json.Marshal(map[string]any{"supportedVersions": versions})
	return b
}

func supportedData(versions ...string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"supported": versions})
	return b
}

// TestClassify pins the verdict table (PORM-151 security requirements 1, 2 and
// 5): one row per line of it, plus the handshake-revision fallback and the
// shapes an upstream could use to steer its own verdict.
func TestClassify(t *testing.T) {
	huge := json.RawMessage(`["` + strings.Repeat("2026-07-28\",\"", 600) + `2026-07-28"]`)
	if len(huge) <= maxVersionListBytes {
		t.Fatalf("the oversized list is %d bytes, not past the %d cap", len(huge), maxVersionListBytes)
	}
	hugeResult, _ := json.Marshal(map[string]json.RawMessage{"supportedVersions": huge})
	hugeData, _ := json.Marshal(map[string]json.RawMessage{"supported": huge})

	for _, tc := range []struct {
		name      string
		res       stepResult
		era       Era
		reached   bool
		version   string
		fail      string
		supported []string
	}{
		{name: "nothing came back", res: stepResult{fail: "cannot connect to "}, era: EraLegacy},

		{name: "400 -32020", res: stepResult{status: 400, code: CodeHeaderMismatch},
			era: EraModern, reached: true, fail: errRoutingRefused},
		{name: "400 -32021", res: stepResult{status: 400, code: CodeMissingClientCapability},
			era: EraModern, reached: true, fail: errCapabilityRequired},
		{name: "400 -32022 naming a future version", res: stepResult{status: 400, code: CodeUnsupportedVersion, data: supportedData("2027-01-01")},
			era: EraModern, reached: true, fail: errNoSharedVersion, supported: []string{"2027-01-01"}},
		{name: "400 -32022 with no data", res: stepResult{status: 400, code: CodeUnsupportedVersion},
			era: EraModern, reached: true, fail: errNoSharedVersion},
		{name: "400 -32022 with an oversized list", res: stepResult{status: 400, code: CodeUnsupportedVersion, data: hugeData},
			era: EraModern, reached: true, fail: errNoSharedVersion},
		{name: "400 -32022 naming a handshake revision", res: stepResult{status: 400, code: CodeUnsupportedVersion, data: supportedData("2025-06-18")},
			era: EraLegacy, reached: true, supported: []string{"2025-06-18"}},
		{name: "400 -32000, the reference server's not-initialized", res: stepResult{status: 400, code: -32000},
			era: EraLegacy, reached: true},
		{name: "400 -32601", res: stepResult{status: 400, code: -32601}, era: EraLegacy, reached: true},
		{name: "a modern code on a 500", res: stepResult{status: 500, code: CodeUnsupportedVersion, data: supportedData("2027-01-01")},
			era: EraLegacy, reached: true},
		{name: "a modern code on a 200", res: stepResult{status: 200, code: CodeHeaderMismatch, id: idDiscover},
			era: EraLegacy, reached: true},
		{name: "404 with a page", res: stepResult{status: 404, fail: "upstream answered 404"}, era: EraLegacy, reached: true},

		{name: "200 listing the modern revision", res: stepResult{status: 200, id: idDiscover, result: discoverResult("2026-07-28")},
			era: EraModern, reached: true, version: RevisionModern, supported: []string{"2026-07-28"}},
		{name: "200 listing both eras", res: stepResult{status: 200, id: idDiscover, result: discoverResult("2025-11-25", "2026-07-28")},
			era: EraModern, reached: true, version: RevisionModern, supported: []string{"2025-11-25", "2026-07-28"}},
		{name: "200 listing only a handshake revision", res: stepResult{status: 200, id: idDiscover, result: discoverResult("2025-11-25")},
			era: EraLegacy, reached: true, supported: []string{"2025-11-25"}},
		{name: "200 listing only a future version", res: stepResult{status: 200, id: idDiscover, result: discoverResult("2027-01-01")},
			era: EraModern, reached: true, fail: errNoSharedVersion, supported: []string{"2027-01-01"}},
		{name: "200 with an empty list", res: stepResult{status: 200, id: idDiscover, result: discoverResult()},
			era: EraModern, reached: true, fail: errNoSharedVersion},
		{name: "200 with an oversized list", res: stepResult{status: 200, id: idDiscover, result: hugeResult},
			era: EraModern, reached: true, fail: errNoSharedVersion},
		{name: "200 with no supportedVersions, a lenient legacy server", res: stepResult{status: 200, id: idDiscover, result: json.RawMessage(`{"ok":true}`)},
			era: EraLegacy, reached: true},
		{name: "200 with a null list", res: stepResult{status: 200, id: idDiscover, result: json.RawMessage(`{"supportedVersions":null}`)},
			era: EraLegacy, reached: true},
		{name: "200 with a list that is not an array", res: stepResult{status: 200, id: idDiscover, result: json.RawMessage(`{"supportedVersions":"2026-07-28"}`)},
			era: EraLegacy, reached: true},
		{name: "200 with a list of numbers", res: stepResult{status: 200, id: idDiscover, result: json.RawMessage(`{"supportedVersions":[20260728]}`)},
			era: EraLegacy, reached: true},
		{name: "200 with a result that is not an object", res: stepResult{status: 200, id: idDiscover, result: json.RawMessage(`[1,2]`)},
			era: EraLegacy, reached: true},
		{name: "200 from a document that answers another id", res: stepResult{status: 200, id: "1", result: discoverResult("2026-07-28")},
			era: EraLegacy, reached: true},
		{name: "200 from a document with no id", res: stepResult{status: 200, result: discoverResult("2026-07-28")},
			era: EraLegacy, reached: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.res)
			if got.Era != tc.era || got.Reached != tc.reached || got.Version != tc.version || got.Fail != tc.fail {
				t.Errorf("classify = era %q reached %v version %q fail %q, want era %q reached %v version %q fail %q",
					got.Era, got.Reached, got.Version, got.Fail, tc.era, tc.reached, tc.version, tc.fail)
			}
			if !reflect.DeepEqual(got.Supported, tc.supported) {
				t.Errorf("supported = %v, want %v", got.Supported, tc.supported)
			}
		})
	}
}

// TestClassifyKeepsWhatAnUnusableServerSaid: a 200 DiscoverResult that yields
// no usable version still named itself and its capabilities, and the operator
// is shown both. Only the three error bodies carry none.
func TestClassifyKeepsWhatAnUnusableServerSaid(t *testing.T) {
	result := json.RawMessage(`{"supportedVersions":["2027-01-01"],"capabilities":{"tools":{}},` +
		`"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"future","version":"9"}}}`)
	got := classify(stepResult{status: 200, id: idDiscover, result: result})
	if got.Fail != errNoSharedVersion {
		t.Fatalf("fail = %q, want the unsupported sentence", got.Fail)
	}
	if got.Info == nil || got.Info.Name != "future" || got.Info.Version != "9" {
		t.Errorf("info = %+v, want the server's own name for itself", got.Info)
	}
	if !reflect.DeepEqual(got.Capabilities, []string{"tools"}) {
		t.Errorf("capabilities = %v, want [tools]", got.Capabilities)
	}
}

// TestProbeEraReadsItsOwnAnswer covers security requirement 2 end to end: the
// verdict comes from the document that answers the probe's own id, wherever it
// sits in the stream, and from no other.
func TestProbeEraReadsItsOwnAnswer(t *testing.T) {
	foreign := `{"jsonrpc":"2.0","id":99,"error":{"code":-32022,"message":"not yours","data":{"supported":["2027-01-01"]}}}`
	own := `{"jsonrpc":"2.0","id":` + idDiscover + `,"result":{"supportedVersions":["2026-07-28"]}}`

	t.Run("a foreign error ahead of the real answer", func(t *testing.T) {
		f := newFixture(t)
		f.on[stepDiscover] = func(w http.ResponseWriter, _ request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(append(sseFrame([]byte(foreign)), sseFrame([]byte(own))...))
		}
		got := ProbeEra(t.Context(), New().http, f.upstream(), nil)
		if got.Era != EraModern || got.Version != RevisionModern || got.Fail != "" {
			t.Errorf("probe = %+v, want a usable modern verdict", got)
		}
	})

	t.Run("only a foreign document", func(t *testing.T) {
		f := newFixture(t)
		f.on[stepDiscover] = func(w http.ResponseWriter, _ request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(sseFrame([]byte(strings.Replace(own, `"id":`+idDiscover, `"id":99`, 1))))
		}
		got := ProbeEra(t.Context(), New().http, f.upstream(), nil)
		if got.Era != EraLegacy || !got.Reached || got.Fail != "" {
			t.Errorf("probe = %+v, want a reached legacy verdict", got)
		}
	})

	t.Run("the probe declares itself and carries _meta", func(t *testing.T) {
		f := newFixture(t)
		_ = ProbeEra(t.Context(), New().http, f.upstream(), nil)
		reqs := f.requests()
		if len(reqs) != 1 || reqs[0].RPC != stepDiscover {
			t.Fatalf("requests = %+v, want one server/discover", reqs)
		}
		if got := reqs[0].Protocol; got != RevisionModern {
			t.Errorf("MCP-Protocol-Version = %q, want %q", got, RevisionModern)
		}
		if got := reqs[0].Header.Get("Mcp-Method"); got != stepDiscover {
			t.Errorf("Mcp-Method = %q, want %q", got, stepDiscover)
		}
		if reqs[0].Session != "" {
			t.Errorf("the probe carried session %q; the modern era has none", reqs[0].Session)
		}
	})
}

// TestBoundVersions covers security requirement 4: an entry that is not a
// plain token is dropped, never repaired into a different version.
func TestBoundVersions(t *testing.T) {
	got := boundVersions([]string{"2026\x0107-28", "2026-07-28", strings.Repeat("v", 33), "", "2025 11 25", strings.Repeat("v", 32)})
	want := []string{"2026-07-28", strings.Repeat("v", 32)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("boundVersions = %q, want %q", got, want)
	}
	for _, v := range got {
		if v == "202607-28" {
			t.Error("a version carrying a control byte was rewritten into another version")
		}
	}

	nine := []string{"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"}
	if got := boundVersions(nine); !reflect.DeepEqual(got, nine[:8]) {
		t.Errorf("nine versions = %v, want the first eight", got)
	}
}

// TestCapabilityFamiliesOrdered covers security requirement 6: the order is
// fixed, so an upstream with many extensions cannot push tools out of the list
// and two calls never disagree. Fifty runs because a map range is what would
// break it, and Go randomises that per range.
func TestCapabilityFamiliesOrdered(t *testing.T) {
	extensions := map[string]any{}
	for i := 0; i < 20; i++ {
		extensions[fmt.Sprintf("io.example/ext-%02d", i)] = map[string]any{}
	}
	extensions["bad name"] = map[string]any{}
	extensions[strings.Repeat("x", 129)] = map[string]any{}
	extensions["tools"] = map[string]any{}
	raw, _ := json.Marshal(map[string]any{
		"tools": map[string]any{}, "prompts": map[string]any{}, "logging": map[string]any{},
		"extensions": extensions,
	})

	first := capabilityFamilies(raw)
	if len(first) != maxCapabilities {
		t.Fatalf("got %d families, want %d: %v", len(first), maxCapabilities, first)
	}
	if first[0] != "tools" || first[1] != "prompts" || first[2] != "io.example/ext-00" {
		t.Errorf("order = %v, want the known families first and the extensions sorted after", first)
	}
	for _, name := range first {
		if name == "logging" || name == "bad name" || len(name) > maxCapabilityBytes {
			t.Errorf("%q reached the list", name)
		}
	}
	for i := 0; i < 50; i++ {
		if got := capabilityFamilies(raw); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d = %v, want %v", i, got, first)
		}
	}

	if got := capabilityFamilies(nil); got != nil {
		t.Errorf("no capabilities = %v, want nil", got)
	}
	if got := capabilityFamilies(json.RawMessage(`[1]`)); got != nil {
		t.Errorf("capabilities that are not an object = %v, want nil", got)
	}
}

// TestModernListRequest pins the one composer of a modern catalogue request:
// valid JSON, the id it was given, and the same _meta the probe sends.
func TestModernListRequest(t *testing.T) {
	for _, cursor := range []string{"", `p"2`} {
		var body struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params struct {
				Cursor string                     `json:"cursor"`
				Meta   map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(ModernListRequest("7", cursor)), &body); err != nil {
			t.Fatalf("cursor %q: not JSON: %v", cursor, err)
		}
		if body.ID != 7 || body.Method != stepList || body.Params.Cursor != cursor {
			t.Errorf("cursor %q: id %d method %q cursor %q", cursor, body.ID, body.Method, body.Params.Cursor)
		}
		if string(body.Params.Meta[metaProtocol]) != `"`+RevisionModern+`"` {
			t.Errorf("_meta protocol = %s", body.Params.Meta[metaProtocol])
		}
		if string(body.Params.Meta[metaClientInfo]) != `{"name":"porymcp","version":"dev"}` {
			t.Errorf("_meta clientInfo = %s", body.Params.Meta[metaClientInfo])
		}
		if string(body.Params.Meta[metaClientCaps]) != `{}` {
			t.Errorf("_meta clientCapabilities = %s", body.Params.Meta[metaClientCaps])
		}
	}
}

// TestProbeBudget pins the probe's own deadline (PORM-151 security requirement
// 10). On the proxy plane nothing else bounds it short of the client's sixty
// seconds, so a member that accepts a connection and never answers costs a
// group call this much and no more. TestDiscoverBudgetIncludesProbe cannot
// stand in for this: it shortens discoverBudget, so the parent deadline fires
// first and the probe's own bound is never the one under test.
func TestProbeBudget(t *testing.T) {
	// The shipped value first: three docs state it.
	if probeBudget != 5*time.Second {
		t.Fatalf("probeBudget=%v, want 5s: the shipped budget for one server/discover", probeBudget)
	}
	// A package var, mutated here under the same rule as discoverBudget:
	// nothing in this package calls t.Parallel.
	restore := probeBudget
	probeBudget = 100 * time.Millisecond
	t.Cleanup(func() { probeBudget = restore })

	f := newFixture(t)
	// Held open until the test ends, so httptest.Server.Close (which waits for
	// outstanding requests) is not the thing under test. No sleep.
	f.on[stepDiscover] = func(http.ResponseWriter, request) { <-t.Context().Done() }

	// The proxy's own kind of client: a timeout far longer than the budget, and
	// a caller's context with no deadline at all.
	hc := NewHTTPClient(Options{Timeout: time.Minute})
	start := time.Now()
	got := ProbeEra(t.Context(), hc, f.upstream(), nil)
	elapsed := time.Since(start)

	if got.Reached || got.Era != EraLegacy || got.Fail != "" {
		t.Errorf("probe = %+v, want an unreached legacy verdict and no sentence", got)
	}
	if elapsed > time.Second {
		t.Errorf("took %v; the probe's own budget did not fire", elapsed)
	}
}

// TestNegotiateHandshake pins the version the group endpoint answers an
// initialize with (PORM-153, security requirement 10): the revision asked for
// when PoryMCP speaks it, the newest handshake revision otherwise, and never
// the stateless revision, which has no initialize to answer.
func TestNegotiateHandshake(t *testing.T) {
	for asked, want := range map[string]string{
		"2025-11-25":  "2025-11-25",
		"2025-06-18":  "2025-06-18",
		"2025-03-26":  "2025-03-26",
		"2024-11-05":  "2024-11-05",
		"2030-01-01":  "2025-11-25",
		"":            "2025-11-25",
		"2026-07-28":  "2025-11-25",
		" 2025-06-18": "2025-11-25",
	} {
		if got := NegotiateHandshake(asked); got != want {
			t.Errorf("NegotiateHandshake(%q) = %q, want %q", asked, got, want)
		}
	}
	if got := SelfInfo(); got.Name != "porymcp" || got.Version == "" {
		t.Errorf("SelfInfo() = %+v, want porymcp and a version both eras require", got)
	}
}
