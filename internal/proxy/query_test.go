package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// queryCred is the query credential the door tests store (PORM-27).
func queryCred(value string) upstreamSpec {
	return upstreamSpec{Tools: []string{"ping_tool"}, AuthType: models.AuthQuery, AuthConfig: models.AuthConfig{Param: "api_key", Value: value}}
}

// assertQueryOnly checks one recorded upstream request carried the
// credential as its only api_key parameter, no Authorization header, and
// nothing carrying the virtual key.
func assertQueryOnly(t *testing.T, r recordedRequest, value, key string) {
	t.Helper()
	if n := strings.Count(r.RawQuery, "api_key="); n != 1 || !strings.Contains(r.RawQuery, "api_key="+value) {
		t.Errorf("upstream saw query %q, want api_key=%s exactly once", r.RawQuery, value)
	}
	if strings.Contains(strings.ToLower(r.RawQuery), "spoof") || strings.Contains(r.RawQuery, "API_KEY") {
		t.Errorf("a client parameter naming the credential survived: %q", r.RawQuery)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
	if strings.Contains(r.RawQuery, key) {
		t.Errorf("the virtual key reached the upstream URL: %q", r.RawQuery)
	}
	for name, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(v, key) {
				t.Errorf("%s carried the virtual key upstream: %q", name, v)
			}
		}
	}
}

// TestQueryCredentialOnEveryDoor pins PORM-27 security requirements 3 and 4
// on every door that sends to an upstream: the single-key MCP door, the
// group's member catalogue walk, a group call routed to a member, and the
// HTTP relay with a client that names the parameter itself.
func TestQueryCredentialOnEveryDoor(t *testing.T) {
	const value = "QUERY_VALUE_MARKER_abcdefgh"
	t.Run("single key tools/call", func(t *testing.T) {
		f := newSingleFixture(t, queryCred(value), nil, nil)
		rr := f.post(toolCall("1", "ping_tool"))
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
		reqs := f.requestsTo("solo")
		if len(reqs) == 0 {
			t.Fatal("the upstream saw no request")
		}
		assertQueryOnly(t, reqs[len(reqs)-1], value, f.Key)
	})
	t.Run("group member tools/list and tools/call", func(t *testing.T) {
		alpha, beta := queryCred(value), queryCred(value+"B")
		alpha.Tools, beta.Tools = []string{"a_tool"}, []string{"b_tool"}
		f := newFixture(t, map[string]upstreamSpec{"alpha": alpha, "beta": beta}, true, nil, nil, nil)
		if rr := f.post(listRequest); rr.Code != http.StatusOK {
			t.Fatalf("list: status %d body %s", rr.Code, rr.Body.String())
		}
		if rr := f.post(toolCall("2", "alpha__a_tool")); rr.Code != http.StatusOK {
			t.Fatalf("call: status %d body %s", rr.Code, rr.Body.String())
		}
		for slug, want := range map[string]string{"alpha": value, "beta": value + "B"} {
			reqs := f.requestsTo(slug)
			if len(reqs) == 0 {
				t.Fatalf("%s saw no request", slug)
			}
			for _, r := range reqs {
				assertQueryOnly(t, r, want, f.Key)
			}
		}
		if f.count("alpha", "tools/call", "a_tool") != 1 {
			t.Fatal("the group call did not reach alpha")
		}
	})
	t.Run("relay with a spoofed parameter", func(t *testing.T) {
		f := newRelayFixture(t, nil, map[string]httpSpec{"q": {Base: "/v1", QueryParam: "api_key", QueryValue: value}}, false)
		rr := f.send(http.MethodGet, "/a1/api/items?api_key=spoof&page=2&API_KEY=x", "", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
		reqs := f.APIs["q"].requests()
		if len(reqs) != 1 {
			t.Fatalf("%d upstream requests, want 1", len(reqs))
		}
		up := reqs[0]
		if up.RawQuery != "page=2&api_key="+value {
			t.Errorf("upstream saw query %q", up.RawQuery)
		}
		if got := up.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q", got)
		}
		for name, vals := range up.Header {
			for _, v := range vals {
				if strings.Contains(v, f.Key) {
					t.Errorf("%s carried the virtual key upstream: %q", name, v)
				}
			}
		}
	})
}

// TestQueryCredentialUnreachableUpstream pins PORM-27 security requirement
// 7: a query upstream that cannot be reached leaves a row, a client answer
// and, on a group, a skip log line that name the host at most. The request
// URL now carries the credential and the *url.Error would quote it; the
// closed sentences never do. A 6-byte value sits under the literal floor on
// its own, so this also proves the wire pair covers a short value.
func TestQueryCredentialUnreachableUpstream(t *testing.T) {
	const value = "abc123"
	const pair = "api_key=" + value
	forbidden := []string{value, pair, "api_key%3D" + value}
	t.Run("single key", func(t *testing.T) {
		spec := queryCred(value)
		spec.URL = "http://127.0.0.1:1/mcp"
		f := newSingleFixture(t, spec, nil, nil)
		rr := f.post(toolCall("1", "ping_tool"))
		row := f.waitAudit(models.LogFilter{Status: models.StatusError})[0]
		if !strings.Contains(row.ErrorMessage, "127.0.0.1:1") {
			t.Errorf("error_message %q does not name the host", row.ErrorMessage)
		}
		assertNoLeak(t, "row error_message", row.ErrorMessage, forbidden...)
		assertNoLeak(t, "client body", rr.Body.String(), forbidden...)
	})
	t.Run("relay", func(t *testing.T) {
		f := newRelayFixture(t, nil, map[string]httpSpec{"q": {Base: "/v1", QueryParam: "api_key", QueryValue: value}}, false)
		f.APIs["q"].srv.Close()
		rr := f.send(http.MethodGet, "/a1/api/items", "", nil)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
		row := f.lastRow(1)
		if row.Status != models.StatusError || !strings.Contains(row.ErrorMessage, "127.0.0.1") {
			t.Errorf("row = %+v", row)
		}
		assertNoLeak(t, "row error_message", row.ErrorMessage, forbidden...)
		assertNoLeak(t, "client body", rr.Body.String(), forbidden...)
	})
	t.Run("group skip line", func(t *testing.T) {
		dead := queryCred(value)
		dead.Dead = true
		f := newFixture(t, map[string]upstreamSpec{"alpha": {Tools: []string{"a_tool"}}, "dead": dead}, true, nil, nil, nil)
		logs := captureLogs(f)
		if rr := f.post(listRequest); rr.Code != http.StatusOK {
			t.Fatalf("list: status %d body %s", rr.Code, rr.Body.String())
		}
		var skipped []map[string]any
		for _, r := range logRecords(t, logs) {
			if r["msg"] == "group member skipped" && r["slug"] == "dead" {
				skipped = append(skipped, r)
			}
		}
		if len(skipped) != 1 {
			t.Fatalf("%d skip lines for dead, want 1: %s", len(skipped), logs.String())
		}
		errText, _ := skipped[0]["err"].(string)
		if !strings.Contains(errText, "127.0.0.1") {
			t.Errorf("skip line %q does not name the host", errText)
		}
		assertNoLeak(t, "skip log line", logs.String(), forbidden...)
	})
}
