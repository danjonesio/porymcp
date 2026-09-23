package proxy

import (
	"net/http"
	"testing"
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
