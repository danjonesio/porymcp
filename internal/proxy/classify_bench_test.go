package proxy

import (
	"strings"
	"testing"
)

// BenchmarkClassifyAnswer measures what answerStatus costs per answer shape
// (PORM-172, security requirement 8). The before/ pair runs the two calls the
// classification site made until PORM-172 over the same JSON bodies, so one
// run gives the before and after numbers for the path every JSON answer
// takes; those two must match in allocs/op and B/op. The SSE shapes have no
// baseline, because the old classification failed on their first byte: their
// numbers are figures for the pull request, not gates. The 4095 case is the
// largest stream PickResponse still reduces; the next one is past its bound
// and records the fallback. Nothing here runs under make test.
func BenchmarkClassifyAnswer(b *testing.B) {
	small := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	big := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + strings.Repeat("x", 16<<20) + `"}]}}`)
	sseError := []byte(sseFrame(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"rate limited"}}`))
	stream := func(notifications int) []byte {
		var sb strings.Builder
		for i := 0; i < notifications; i++ {
			sb.WriteString(sseFrame(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"tick"}}`))
		}
		sb.WriteString(sseFrame(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
		return []byte(sb.String())
	}
	past := stream(maxPickDocumentsForBench)
	within := stream(maxPickDocumentsForBench - 1)

	old := func(body []byte) {
		if 200 >= 400 || rpcFailed(body) {
			_ = rpcErrorMessage(body)
		}
	}
	cases := []struct {
		name string
		ct   string
		body []byte
		fn   func([]byte)
	}{
		{"before/json-small", "application/json", small, old},
		{"before/json-16mib", "application/json", big, old},
		{"json-small", "application/json", small, nil},
		{"json-16mib", "application/json", big, nil},
		{"sse-error", "text/event-stream", sseError, nil},
		{"sse-4095-then-answer", "text/event-stream", within, nil},
		{"sse-past-bound", "text/event-stream", past, nil},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if c.fn != nil {
					c.fn(c.body)
					continue
				}
				_, _ = answerStatus(200, c.ct, c.body, "1")
			}
		})
	}
}

// maxPickDocumentsForBench mirrors mcpclient's maxPickDocuments, which is not
// exported; a change there moves this constant in the same commit.
const maxPickDocumentsForBench = 4096
