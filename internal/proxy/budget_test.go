package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
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
// own requests to end before returning, which every test here does. The rule
// for t.Parallel: a test that calls setBudget stays sequential; its own
// subtests may run in parallel, because the parent's Cleanup restores the var
// only after they finish; a test that shortens no var may call t.Parallel,
// because Go starts parallel tests after every sequential test has finished.
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
// scale the budget is 200 ms and the upstream answers at 25 ms: the wide
// margin is what keeps this from flaking on a loaded runner, and it costs the
// suite only the 25 ms.
func TestSlowAnswerWithinBudgetCompletes(t *testing.T) {
	setBudget(t, &answerBudget, 200*time.Millisecond)
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

// The three contexts an upstream request can be in when its client returns
// an error: live, cancelled by a budget with its own cause, and cancelled by
// the client's request context with no cause of its own.
func failureContexts(t *testing.T) (live, budget, client context.Context) {
	t.Helper()
	live = t.Context()
	b, cancelB := context.WithCancelCause(t.Context())
	cancelB(&budgetError{what: "did not connect within", d: 50 * time.Millisecond})
	c, cancelC := context.WithCancel(t.Context())
	cancelC()
	return live, b, c
}

// A refused dial as http.Client.Do hands it back: the *net.OpError inside a
// *url.Error that quotes the whole URL.
func refusedURLError(rawURL string) error {
	return &url.Error{Op: "Post", URL: rawURL, Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
}

// PORM-191 security requirements 2, 3, 4 and 8. Exact matches: the sentences
// reach an operator unchanged and the Logs page never pattern-matches them.
func TestUpstreamFailureText(t *testing.T) {
	live, budget, client := failureContexts(t)
	const leaky = "http://h:1/secret-path?tok=QUERY-MARKER"
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		host string
		want string
	}{
		{"refused with a port", live, refusedURLError(leaky), "h:1", "cannot connect to h:1"},
		{"refused without a port", live, refusedURLError(leaky), "h", "cannot connect to h"},
		{"dns", live, &url.Error{Op: "Post", URL: leaky, Err: &net.DNSError{Err: "no such host", Name: "h", IsNotFound: true}}, "h:1", "cannot resolve h:1"},
		{"tls", live, &url.Error{Op: "Post", URL: leaky, Err: &tls.CertificateVerificationError{Err: errors.New("x509: unknown authority")}}, "h:1", "tls handshake with h:1 failed"},
		{"redirect with a host", live, mcpclient.Redirect{Host: "x.test"}, "h:1", "upstream redirected to x.test"},
		{"redirect without a host", live, mcpclient.Redirect{}, "h:1", "upstream redirected"},
		{"body too large", live, mcpclient.BodyTooLarge{Limit: 16777216}, "h:1", "upstream body exceeds 16777216 bytes"},
		{"guard refusal", live, netguard.Denied{Class: "loopback"}, "h:1", "upstream address denied: loopback"},
		{"host not HostSafe", live, refusedURLError(leaky), "up+stream.test", "cannot connect to the upstream"},
		{"budget over a refusal", budget, refusedURLError(leaky), "h:1", "upstream did not connect within 50ms"},
		{"client went away", client, &url.Error{Op: "Post", URL: leaky, Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}}, "h:1", "client went away before the answer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := upstreamFailureText(tc.ctx, tc.err, tc.host)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "QUERY-MARKER") || strings.Contains(got, "secret-path") {
				t.Fatalf("%q carries the URL", got)
			}
		})
	}
	// The budget wins over the client's own cancellation too: both are set
	// on a context whose parent went away after a budget fired.
	t.Run("budget over a client that went away", func(t *testing.T) {
		parent, cancelParent := context.WithCancel(t.Context())
		ctx, cancel := context.WithCancelCause(parent)
		cancel(&budgetError{what: "did not answer within", d: 50 * time.Millisecond})
		cancelParent()
		if got, want := upstreamFailureText(ctx, refusedURLError(leaky), "h:1"), "upstream did not answer within 50ms"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	up := &models.Upstream{URL: leaky}
	t.Run("upstreamFailed keeps the guard refusal", func(t *testing.T) {
		var denied netguard.Denied
		if err := upstreamFailed(live, netguard.Denied{Class: "loopback"}, up); !errors.As(err, &denied) || denied.Class != "loopback" {
			t.Fatalf("errors.As lost the refusal: %v", err)
		}
	})
	t.Run("upstreamFailed drops the raw error from the chain", func(t *testing.T) {
		err := upstreamFailed(live, refusedURLError(leaky), up)
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			t.Fatalf("the *url.Error is still in the chain: %v", err)
		}
		if got, want := err.Error(), "cannot connect to h:1"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

// PORM-191 security requirements 4, 7 and 8: a body that failed while it was
// read is one of two fixed sentences, after the budget and the client's own
// cancellation, and never the read error's text, which names an address.
func TestReadFailureText(t *testing.T) {
	live, budget, client := failureContexts(t)
	reset := &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 3001}, Err: syscall.ECONNRESET}
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{"cut short", live, io.ErrUnexpectedEOF, "unexpected EOF"},
		{"reset", live, reset, "upstream connection failed"},
		{"body too large", live, mcpclient.BodyTooLarge{Limit: 16777216}, "upstream body exceeds 16777216 bytes"},
		{"budget over a cut body", budget, io.ErrUnexpectedEOF, "upstream did not connect within 50ms"},
		{"client went away", client, reset, "client went away before the answer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := readFailureText(tc.ctx, tc.err)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "10.0.0.5") {
				t.Fatalf("%q names the address", got)
			}
		})
	}
	if got := readFailed(live, reset).Error(); got != "upstream connection failed" {
		t.Fatalf("readFailed=%q", got)
	}
}
