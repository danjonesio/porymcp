package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// BenchmarkRelayJSON measures the buffered JSON relay end to end: one
// tools/call through serve, forward and the row, against a stub that answers
// JSON. It is the figure for the path every ordinary answer takes, recorded
// before PORM-5's budgets and streaming decision land and again after each of
// them, so the pull request carries the cost of the change as numbers. The
// numbers are figures, not a gate (PORM-5 security requirement 11); the gate
// on the JSON path's allocations is TestAnswerStatusJSONAllocs. Nothing here
// runs under make test.
func BenchmarkRelayJSON(b *testing.B) {
	f := newSingleFixture(b, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
	rpc := toolCall("1", "ping_tool")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := f.post(rpc)
		if rr.Code != http.StatusOK {
			b.Fatalf("HTTP code=%d want 200", rr.Code)
		}
	}
}

// setBudget shortens one of budget.go's package vars for a test and restores
// it afterwards. The relay reads each var once per request, so the restore
// cannot race a request that is still running only if the test waits for its
// own requests to end before returning, which every test here does.
func setBudget(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

// rpcMethodOf reads the JSON-RPC method out of a request a stub handler is
// answering; the fixture rewound the body after recording it.
func rpcMethodOf(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Method
}

// answerAfter is a stub handler that answers a tools/call with JSON after d,
// and everything else at once. It waits on the request's context as well as
// the clock, so a proxy that gave up does not leave the stub holding the
// connection past the test.
func answerAfter(d time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rpcMethodOf(r) == "tools/call" {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}
}

// Criterion 2: a call that takes longer than the old 60 s completes. At test
// scale the budget is 50 ms and the upstream answers at 25 ms.
func TestSlowAnswerWithinBudgetCompletes(t *testing.T) {
	setBudget(t, &answerBudget, 50*time.Millisecond)
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: answerAfter(25 * time.Millisecond)}, nil, nil)
	rr := f.post(toolCall("1", "ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200: %s", rr.Code, rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusSuccess {
		t.Fatalf("row status=%q error_message=%q, want success", row.Status, row.ErrorMessage)
	}
}

// Criterion 2's other half: past the budget the call fails, and the row says
// which budget in the proxy's own words, not the transport's.
func TestAnswerPastBudgetFails(t *testing.T) {
	setBudget(t, &answerBudget, 50*time.Millisecond)
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: answerAfter(150 * time.Millisecond)}, nil, nil)
	rr := f.post(toolCall("1", "ping_tool"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502: %s", rr.Code, rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "upstream did not answer within 50ms" {
		t.Fatalf("row status=%q error_message=%q, want error / upstream did not answer within 50ms", row.Status, row.ErrorMessage)
	}
}

// Criterion 2 at its stated scale: the default must clear a 90 s call.
func TestAnswerBudgetCoversANinetySecondCall(t *testing.T) {
	if answerBudget <= 90*time.Second {
		t.Fatalf("answerBudget=%v, want more than 90s", answerBudget)
	}
}

// Criterion 3: an upstream that refuses the connection fails at once, as it
// did before the budgets; this is the guard that it still does.
func TestUnreachableUpstreamFailsFast(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Dead: true}, nil, nil)
	start := time.Now()
	rr := f.post(toolCall("1", "ping_tool"))
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("a refused upstream took %v, want under 2s", took)
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502", rr.Code)
	}
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusError {
		t.Fatalf("row status=%q want error", row.Status)
	}
}

// Criterion 3 for the case the transport's own 30 s dial timeout used to own:
// a host that accepts the connection and never completes the handshake fails
// at connectBudget, and the row names that budget.
func TestConnectBudgetBoundsAStalledHandshake(t *testing.T) {
	setBudget(t, &connectBudget, 50*time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, URL: "https://" + ln.Addr().String()}, nil, nil)
	start := time.Now()
	rr := f.post(toolCall("1", "ping_tool"))
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a stalled handshake took %v, want under 1s", took)
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502", rr.Code)
	}
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "upstream did not connect within 50ms" {
		t.Fatalf("row status=%q error_message=%q, want error / upstream did not connect within 50ms", row.Status, row.ErrorMessage)
	}
}

// D3: with no client timeout, a group member's listing is bounded by
// listBudget instead, so a member that never answers tools/list still costs
// the walk that budget and no more, and the other member's tools are served.
func TestGroupListingStillBoundedBySilentMember(t *testing.T) {
	setBudget(t, &listBudget, 50*time.Millisecond)
	silent := func(w http.ResponseWriter, r *http.Request) {
		if rpcMethodOf(r) == "tools/list" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
	}
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}},
		"beta":  {Tools: []string{"b_tool"}, Handler: silent},
	}, true, nil, nil, nil)
	start := time.Now()
	rr := f.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the group listing took %v, want under 1s", took)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200: %s", rr.Code, rr.Body.String())
	}
	if names := listedNames(t, rr.Body.Bytes()); len(names) != 1 || names[0] != "alpha__a_tool" {
		t.Fatalf("listed %v, want the answering member's tool only", names)
	}
}

// The aggregate's routed call runs under the same budget as a call on a
// member endpoint, and a budget that fires there is recorded as the budget,
// not as a cancelled context.
func TestRoutedCallPastBudgetRecordsTheBudget(t *testing.T) {
	setBudget(t, &answerBudget, 50*time.Millisecond)
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}, Handler: func(w http.ResponseWriter, r *http.Request) {
			switch rpcMethodOf(r) {
			case "tools/list":
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a_tool","inputSchema":{"type":"object"}}]}}`)
			case "tools/call":
				<-r.Context().Done()
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
			}
		}},
	}, true, nil, nil, nil)
	rr := f.post(toolCall("1", "alpha__a_tool"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("HTTP code=%d want 502: %s", rr.Code, rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{Tool: "alpha__a_tool"})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "upstream did not answer within 50ms" {
		t.Fatalf("row status=%q error_message=%q, want error / upstream did not answer within 50ms", row.Status, row.ErrorMessage)
	}
}

// D3: the client carries no timeout of its own; the budgets are the bound.
func TestClientTimeoutIsZero(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}}, nil, nil)
	if f.H.client.Timeout != 0 {
		t.Fatalf("client.Timeout=%v, want 0", f.H.client.Timeout)
	}
}
