package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

// PORM-28: a stored transport the proxy cannot dial is refused before any
// dispatch. The client sees the generic 502 every upstream failure produces;
// the audit row names the row and carries the fixed sentence; no request
// reaches any upstream. The fixture sorts slugs and numbers ids in that order,
// so in the group tests "alpha" is u1 (Streamable HTTP) and "zeta" is u2 (sse):
// a gate that only looked at upstreams[0] would pass alpha and fail every one
// of them.

const initializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

// sseSentence is what the audit row must say for a stored sse row, read from
// the one predicate that owns it so the proxy cannot drift from discovery.
func sseSentence() string {
	return mcpclient.TransportError(models.TransportSSE).Error()
}

// assertNamedAuditRow: exactly n error rows, each carrying the sentence and
// naming the upstream that was refused.
func assertNamedAuditRow(t *testing.T, f *fixture, n int, upstreamID, sentence string) []models.AuditLog {
	t.Helper()
	rows := f.waitAuditN(models.LogFilter{Status: models.StatusError}, n)
	if len(rows) != n {
		t.Fatalf("error rows = %d, want %d: %+v", len(rows), n, rows)
	}
	for _, row := range rows {
		if row.ErrorMessage != sentence {
			t.Fatalf("audit error_message = %q, want %q", row.ErrorMessage, sentence)
		}
		if row.UpstreamID != upstreamID {
			t.Fatalf("audit upstream_id = %q, want %q", row.UpstreamID, upstreamID)
		}
	}
	return rows
}

// TestProxyRefusesSSETransport: security requirements 1 and 3 on a
// single-upstream key. The client gets the generic 502, the audit row reads
// the sse sentence and names the row, and the stub is never contacted.
func TestProxyRefusesSSETransport(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Transport: models.TransportSSE}, nil, nil)

	rr := f.post(listRequest)
	assert502Generic(t, rr.Body.String(), rr.Code)
	if strings.Contains(rr.Body.String(), "sse") || strings.Contains(rr.Body.String(), "transport") {
		t.Fatalf("the client was told about the transport: %s", rr.Body.String())
	}
	if n := f.totalReqs("solo"); n != 0 {
		t.Fatalf("solo saw %d requests; nothing may be dialled", n)
	}
	assertNamedAuditRow(t, f, 1, "u1", sseSentence())
}

// TestProxyMemberEndpointRefusesSSETransport: security requirement 2. The sse
// member's own endpoint answers the generic 502 with a named audit row, not
// 404 unknown endpoint, and the healthy member's endpoint is unaffected.
func TestProxyMemberEndpointRefusesSSETransport(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}},
		"zeta":  {Tools: []string{"z_tool"}, Transport: models.TransportSSE},
	}, true, nil, nil, nil)

	rr := f.postMember("zeta", toolCall("1", "z_tool"))
	assert502Generic(t, rr.Body.String(), rr.Code)
	if n := f.totalReqs("zeta"); n != 0 {
		t.Fatalf("zeta saw %d requests", n)
	}
	assertNamedAuditRow(t, f, 1, "u2", sseSentence())

	if rr := f.postMember("alpha", toolCall("2", "a_tool")); rr.Code != http.StatusOK {
		t.Fatalf("alpha's own endpoint: %d %s", rr.Code, rr.Body.String())
	}
	if n := f.totalReqs("alpha"); n != 1 {
		t.Fatalf("alpha saw %d requests, want the one call", n)
	}
}

// TestProxyGroupFailsWhenEnabledMemberIsSSE is the group decision: an enabled
// sse member fails every aggregate method, initialize included, rather than
// being skipped into a silent partial catalogue. Each audit row names zeta;
// no stub is contacted.
func TestProxyGroupFailsWhenEnabledMemberIsSSE(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}},
		"zeta":  {Tools: []string{"z_tool"}, Transport: models.TransportSSE},
	}, true, nil, nil, nil)

	for name, rpc := range map[string]string{
		"initialize": initializeRequest,
		"tools/list": listRequest,
		"tools/call": toolCall("3", "alpha__a_tool"),
	} {
		rr := f.post(rpc)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("%s on the aggregate: %d %s, want 502", name, rr.Code, rr.Body.String())
		}
		assert502Generic(t, rr.Body.String(), rr.Code)
	}
	if !f.upstreamsIdle() {
		t.Fatalf("a stub was contacted; alpha=%d zeta=%d", f.totalReqs("alpha"), f.totalReqs("zeta"))
	}
	assertNamedAuditRow(t, f, 3, "u2", sseSentence())
}

// TestProxyGroupServesWhenSSEMemberDisabled is the operator's escape hatch:
// disabling the sse member takes it out of resolveTargets, and the aggregate
// serves the remaining member's catalogue.
func TestProxyGroupServesWhenSSEMemberDisabled(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}},
		"zeta":  {Tools: []string{"z_tool"}, Transport: models.TransportSSE},
	}, true, nil, nil, nil)
	disable(t, f, "u2")

	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list after disabling zeta: %d %s", rr.Code, rr.Body.String())
	}
	if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != "alpha__a_tool" {
		t.Fatalf("listed %q, want alpha's tool alone", got)
	}
	if n := f.totalReqs("zeta"); n != 0 {
		t.Fatalf("the disabled sse member saw %d requests", n)
	}
}

// TestProxyRefusesUnknownTransport is security requirement 7: a hand-edited
// column is refused with the fixed "unsupported transport" sentence, and the
// value itself appears nowhere the key holder or the operator reads.
func TestProxyRefusesUnknownTransport(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Transport: "websocket"}, nil, nil)

	rr := f.post(listRequest)
	assert502Generic(t, rr.Body.String(), rr.Code)
	if strings.Contains(rr.Body.String(), "websocket") {
		t.Fatalf("the client was told the stored value: %s", rr.Body.String())
	}
	if n := f.totalReqs("solo"); n != 0 {
		t.Fatalf("solo saw %d requests", n)
	}
	rows := assertNamedAuditRow(t, f, 1, "u1", "unsupported transport")
	if s := rowText(rows[0]); strings.Contains(s, "websocket") {
		t.Fatalf("the audit row repeats the stored value: %s", s)
	}
}

// rowText flattens the fields of an audit row a hand-edited value could have
// leaked into.
func rowText(row models.AuditLog) string {
	return strings.Join([]string{row.Method, row.ToolName, row.ErrorMessage, row.UpstreamID, string(row.Params)}, " ")
}
