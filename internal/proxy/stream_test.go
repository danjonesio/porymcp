package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/go-chi/chi/v5"
)

// PORM-5: an upstream's event stream is relayed as it arrives on the
// single-upstream and member routes, and the row is written once, when the
// stream ends. Every test here runs over a real listener (fixture.serve),
// because a recorder cannot be read while the handler runs and cannot
// disconnect. Budgets are shortened through setBudget, and every test waits
// for its streams to end before returning (waitNoStreams), so a Cleanup never
// restores a var under a relay that is still reading it.

const (
	progressDoc = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`
	ackDoc      = `{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{}}`
	resultDoc   = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`
	errorDoc    = `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Subscription limit reached"}}`
	listenRPC   = `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`
)

// writeEvents writes each event and flushes it, so the stub's bytes reach the
// proxy one event at a time.
func writeEvents(w http.ResponseWriter, events ...string) {
	rc := http.NewResponseController(w)
	for _, e := range events {
		_, _ = io.WriteString(w, e)
		_ = rc.Flush()
	}
}

// sseHeader labels the answer an event stream and sends the status line, so
// the proxy's own headers go out before any event.
func sseHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
}

// holdOpen is a stub that writes events and then holds the stream until the
// proxy cancels the request, as a listen's upstream does. gone is closed when
// the proxy's cancellation reached the stub.
func holdOpen(gone chan struct{}, events ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sseHeader(w)
		writeEvents(w, events...)
		<-r.Context().Done()
		if gone != nil {
			close(gone)
		}
	}
}

// thenClose is a stub that writes events and ends the stream.
func thenClose(events ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sseHeader(w)
		writeEvents(w, events...)
	}
}

// lineStream reads a response body line by line on its own goroutine, so a
// test can wait for one line with a deadline and count the bytes it read.
type lineStream struct {
	lines chan string
	done  chan error
	read  atomic.Int64
}

func readLines(body io.Reader) *lineStream {
	s := &lineStream{lines: make(chan string, 1024), done: make(chan error, 1)}
	go func() {
		br := bufio.NewReader(body)
		for {
			line, err := br.ReadString('\n')
			s.read.Add(int64(len(line)))
			if line != "" {
				s.lines <- line
			}
			if err != nil {
				s.done <- err
				return
			}
		}
	}()
	return s
}

// next is the next line, or a failure after within.
func (s *lineStream) next(t *testing.T, within time.Duration) string {
	t.Helper()
	select {
	case l := <-s.lines:
		return l
	default:
	}
	select {
	case l := <-s.lines:
		return l
	case err := <-s.done:
		// The reader may have queued the last lines and the end together;
		// a queued line comes first, and the end is put back for end.
		s.done <- err
		select {
		case l := <-s.lines:
			return l
		default:
		}
		t.Fatalf("the stream ended (%v) before the next line", err)
	case <-time.After(within):
		t.Fatalf("no line within %v: the proxy is buffering", within)
	}
	return ""
}

// event reads one complete event: lines up to and including the blank one.
func (s *lineStream) event(t *testing.T, within time.Duration) string {
	t.Helper()
	var sb strings.Builder
	for {
		l := s.next(t, within)
		sb.WriteString(l)
		if strings.TrimSpace(l) == "" {
			return sb.String()
		}
	}
}

// end is how the stream ended, or a failure after within.
func (s *lineStream) end(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-s.done:
		return err
	case <-time.After(within):
		t.Fatalf("the stream did not end within %v", within)
	}
	return nil
}

// open sends a stream request and returns the response and the request id.
func open(t *testing.T, f *fixture, srv *httptest.Server, path, rpc string) (*http.Response, string) {
	t.Helper()
	req, id := f.streamRequest(srv, path, rpc, nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, id
}

// oneRow is the single row a stream must write.
func oneRow(t *testing.T, f *fixture, id string) models.AuditLog {
	t.Helper()
	f.waitNoStreams()
	rows := f.rows(id)
	if len(rows) != 1 {
		t.Fatalf("%d rows for request %s, want exactly 1: %+v", len(rows), id, rows)
	}
	return rows[0]
}

// rawStreamClient opens a stream over a bare TCP connection with a small
// receive buffer and never reads it: the client that stops reading. It
// returns the connection and the request id.
func rawStreamClient(t *testing.T, f *fixture, srv *httptest.Server, path, rpc string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	id := fmt.Sprintf("raw-%d", time.Now().UnixNano())
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nX-Request-Id: %s\r\nContent-Length: %d\r\n\r\n%s",
		path, f.Key, id, len(rpc), rpc)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	return conn, id
}

// flood is a stub that writes 32 KiB chunks for as long as the proxy reads
// them, so the proxy's write to a client that stopped reading is what blocks.
func flood() http.HandlerFunc {
	chunk := "data: " + strings.Repeat("x", 32<<10) + "\n\n"
	return func(w http.ResponseWriter, r *http.Request) {
		sseHeader(w)
		rc := http.NewResponseController(w)
		for r.Context().Err() == nil {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

// rebuild replaces the fixture's handler with one over st, before any
// request: how a test gives the proxy a store that fails or counts reads.
func (f *fixture) rebuild(st store.Store) {
	f.H = New(f.H.cfg, st, f.H.audit, nil)
	rt := chi.NewRouter()
	rt.HandleFunc("/mcp", f.H.ServeHTTP)
	rt.HandleFunc(KeyRoute, f.H.ServeHTTP)
	rt.HandleFunc(MemberRoute, f.H.ServeMember)
	f.Router = rt
}

// Criterion 1: three events released one at a time reach the client one at a
// time. The stub writes the next event only after the test has read the
// previous one, so a proxy that buffered would never deliver event 1 and the
// test fails on its deadline, not on timing. Criterion 4's streamed half: the
// upstream's Mcp-Session-Id reaches the client on a stream.
func TestStreamReachesClientEventByEvent(t *testing.T) {
	t.Parallel()
	next := make(chan struct{})
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Mcp-Session-Id", "sess-7")
		sseHeader(w)
		for i, e := range []string{sseFrame(progressDoc), sseFrame(progressDoc), sseFrame(resultDoc)} {
			if i > 0 {
				select {
				case <-next:
				case <-r.Context().Done():
					return
				}
			}
			writeEvents(w, e)
		}
	}}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP code=%d", resp.StatusCode)
	}
	for k, want := range map[string]string{"Content-Type": "text/event-stream", "X-Accel-Buffering": "no", "Mcp-Session-Id": "sess-7"} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s=%q want %q", k, got, want)
		}
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Errorf("Content-Length=%q on a stream", resp.Header.Get("Content-Length"))
	}
	ls := readLines(resp.Body)
	for i := 0; i < 3; i++ {
		ev := ls.event(t, 5*time.Second)
		want := progressDoc
		if i == 2 {
			want = resultDoc
		}
		if !strings.Contains(ev, want) {
			t.Fatalf("event %d = %q, want it to carry %s", i+1, ev, want)
		}
		if i < 2 {
			next <- struct{}{}
		}
	}
	if err := ls.end(t, 2*time.Second); err != io.EOF {
		t.Fatalf("stream ended with %v, want EOF", err)
	}
	row := oneRow(t, f, id)
	if row.Status != models.StatusSuccess || int64(row.ResponseSizeBytes) != ls.read.Load() {
		t.Fatalf("row status=%q size=%d, want success and %d bytes", row.Status, row.ResponseSizeBytes, ls.read.Load())
	}
}

// Criterion 9 at test scale: a listen the upstream holds open reaches the
// client as the upstream writes it, keep-alive comment lines included, and its
// row is a success with the bytes relayed when the client closes it.
func TestListenHeldOpenRelaysKeepAlives(t *testing.T) {
	t.Parallel()
	gone := make(chan struct{})
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: func(w http.ResponseWriter, r *http.Request) {
		sseHeader(w)
		writeEvents(w, sseFrame(ackDoc))
		for i := 0; i < 5; i++ {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-r.Context().Done():
				close(gone)
				return
			}
			writeEvents(w, ":\r\n")
		}
		writeEvents(w, sseFrame(progressDoc), sseFrame(progressDoc))
		<-r.Context().Done()
		close(gone)
	}}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", listenRPC)
	ls := readLines(resp.Body)
	if ev := ls.event(t, 2*time.Second); !strings.Contains(ev, ackDoc) {
		t.Fatalf("first event %q, want the acknowledgement", ev)
	}
	for i := 0; i < 5; i++ {
		if l := ls.next(t, time.Second); l != ":\r\n" {
			t.Fatalf("line %d = %q, want a keep-alive comment line", i+1, l)
		}
	}
	for i := 0; i < 2; i++ {
		if ev := ls.event(t, time.Second); !strings.Contains(ev, progressDoc) {
			t.Fatalf("notification %d = %q", i+1, ev)
		}
	}
	resp.Body.Close()
	select {
	case <-gone:
	case <-time.After(time.Second):
		t.Fatal("the upstream did not see the client close within 1s")
	}
	row := oneRow(t, f, id)
	if row.Status != models.StatusSuccess || row.ErrorMessage != "" {
		t.Fatalf("row status=%q error_message=%q, want success", row.Status, row.ErrorMessage)
	}
	if int64(row.ResponseSizeBytes) != ls.read.Load() {
		t.Fatalf("row size=%d, want the %d bytes the client read", row.ResponseSizeBytes, ls.read.Load())
	}
}

// A tools/call answered as a stream shows its progress before its result, and
// the row is judged from the result.
func TestStreamedToolsCallShowsProgressFirst(t *testing.T) {
	t.Parallel()
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: thenClose(sseFrame(progressDoc), sseFrame(progressDoc), sseFrame(resultDoc))}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	defer resp.Body.Close()
	ls := readLines(resp.Body)
	for i, want := range []string{progressDoc, progressDoc, resultDoc} {
		if ev := ls.event(t, 2*time.Second); !strings.Contains(ev, want) {
			t.Fatalf("event %d = %q", i+1, ev)
		}
	}
	if err := ls.end(t, 2*time.Second); err != io.EOF {
		t.Fatalf("stream ended with %v", err)
	}
	if row := oneRow(t, f, id); row.Status != models.StatusSuccess {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}

// Criterion 7: a streamed JSON-RPC error is an error row with its message.
func TestStreamedErrorAudited(t *testing.T) {
	t.Parallel()
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: thenClose(sseFrame(progressDoc), sseFrame(errorDoc))}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	row := oneRow(t, f, id)
	if row.Status != models.StatusError || row.ErrorMessage != "Subscription limit reached" {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}

// The answer is judged before the end: a result the client received whole is
// a success row even when the upstream then dropped the connection.
func TestStreamAnsweredThenResetIsSuccess(t *testing.T) {
	t.Parallel()
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: func(w http.ResponseWriter, r *http.Request) {
		sseHeader(w)
		writeEvents(w, sseFrame(resultDoc))
		panic(http.ErrAbortHandler)
	}}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	ls := readLines(resp.Body)
	if ev := ls.event(t, 2*time.Second); !strings.Contains(ev, resultDoc) {
		t.Fatalf("event %q", ev)
	}
	_ = ls.end(t, 2*time.Second)
	resp.Body.Close()
	if row := oneRow(t, f, id); row.Status != models.StatusSuccess {
		t.Fatalf("row status=%q error_message=%q, want success", row.Status, row.ErrorMessage)
	}
}

// A stream with more notifications than PickResponse will walk is still
// judged, because the judge reads the last complete event first.
func TestStreamWithManyNotificationsThenResultIsSuccess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, last, status, msg string
	}{
		{"result", resultDoc, models.StatusSuccess, ""},
		{"error", errorDoc, models.StatusError, "Subscription limit reached"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sb strings.Builder
			for i := 0; i < 5000; i++ {
				sb.WriteString(sseFrame(progressDoc))
			}
			body := sb.String()
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: thenClose(body, sseFrame(tc.last))}, nil, nil)
			srv := f.serve()
			resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(got) != len(body)+len(sseFrame(tc.last)) {
				t.Fatalf("client read %d bytes, want %d", len(got), len(body)+len(sseFrame(tc.last)))
			}
			row := oneRow(t, f, id)
			if row.Status != tc.status || row.ErrorMessage != tc.msg {
				t.Fatalf("row status=%q error_message=%q, want %q / %q", row.Status, row.ErrorMessage, tc.status, tc.msg)
			}
		})
	}
}

// Criterion 7: a client that closes mid-stream cancels the upstream request,
// and the row is an error that says so, with the bytes the client received.
func TestClientDisconnectCancelsUpstream(t *testing.T) {
	t.Parallel()
	gone := make(chan struct{})
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(progressDoc))}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	ls := readLines(resp.Body)
	ls.event(t, 2*time.Second)
	resp.Body.Close()
	select {
	case <-gone:
	case <-time.After(time.Second):
		t.Fatal("the upstream did not see its request cancelled within 1s of the client closing")
	}
	row := oneRow(t, f, id)
	if row.Status != models.StatusError || row.ErrorMessage != "client closed the stream before the answer" {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
	if int64(row.ResponseSizeBytes) != ls.read.Load() {
		t.Fatalf("row size=%d, want the %d bytes the client read", row.ResponseSizeBytes, ls.read.Load())
	}
}

// An upstream that ends a tools/call stream without answering is an error row.
func TestStreamEndedWithoutAnswer(t *testing.T) {
	t.Parallel()
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: thenClose(sseFrame(progressDoc))}, nil, nil)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	row := oneRow(t, f, id)
	if row.Status != models.StatusError || row.ErrorMessage != "upstream closed the stream before the answer" {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}

// Security requirement 6: an upstream that goes quiet is cut at the idle
// bound. The client sees the stream cut short, not a clean end; the row names
// the bound for a call, and is a success for a listen, whose upstream going
// quiet is one of its normal ends.
func TestStreamIdleBoundCloses(t *testing.T) {
	setBudget(t, &streamIdleBudget, 100*time.Millisecond)
	for _, tc := range []struct {
		name, rpc, status, msg string
	}{
		{"call", toolCall("1", "ping_tool"), models.StatusError, "upstream sent nothing for 100ms"},
		{"listen", listenRPC, models.StatusSuccess, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gone := make(chan struct{})
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(progressDoc))}, nil, nil)
			srv := f.serve()
			resp, id := open(t, f, srv, "/a1/mcp", tc.rpc)
			defer resp.Body.Close()
			ls := readLines(resp.Body)
			ls.event(t, 2*time.Second)
			if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("stream ended with %v, want an unexpected EOF: the proxy drops a stream it cut", err)
			}
			<-gone
			row := oneRow(t, f, id)
			if row.Status != tc.status || row.ErrorMessage != tc.msg {
				t.Fatalf("row status=%q error_message=%q, want %q / %q", row.Status, row.ErrorMessage, tc.status, tc.msg)
			}
		})
	}
}

// Security requirement 6: a client that stops reading cannot hold the handler.
// The write to it carries the idle bound as a deadline, so the relay returns
// within the bound and writes its one row.
func TestStreamIdleBoundEndsAStreamWhoseClientStoppedReading(t *testing.T) {
	setBudget(t, &streamIdleBudget, 50*time.Millisecond)
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: flood()}, nil, nil)
	srv := f.serve()
	_, id := rawStreamClient(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	deadline := time.Now().Add(2 * time.Second)
	for f.H.openStreams.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	f.waitNoStreams()
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("the relay held a stalled client for %v", took)
	}
	if rows := f.rows(id); len(rows) != 1 || rows[0].Status != models.StatusError {
		t.Fatalf("rows=%+v want one error row", rows)
	}
}

// Security requirement 7: StopStreams ends an open stream, which writes its
// row and returns. A listen ends as a success; a call as the stopped error. A
// stream that starts after the stop ends at once.
func TestStopStreamsEndsAnOpenStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, rpc, status, msg string
		stopFirst              bool
	}{
		{"listen", listenRPC, models.StatusSuccess, "", false},
		{"call", toolCall("1", "ping_tool"), models.StatusError, "proxy stopped before the answer", false},
		{"after-stop", toolCall("1", "ping_tool"), models.StatusError, "proxy stopped before the answer", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gone := make(chan struct{})
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(progressDoc))}, nil, nil)
			srv := f.serve()
			if tc.stopFirst {
				f.H.StopStreams()
			}
			resp, id := open(t, f, srv, "/a1/mcp", tc.rpc)
			defer resp.Body.Close()
			ls := readLines(resp.Body)
			if !tc.stopFirst {
				ls.event(t, 2*time.Second)
				f.H.StopStreams()
			}
			start := time.Now()
			ls.end(t, 2*time.Second)
			if took := time.Since(start); took > time.Second {
				t.Fatalf("the stream took %v to end after StopStreams", took)
			}
			<-gone
			row := oneRow(t, f, id)
			if row.Status != tc.status || row.ErrorMessage != tc.msg {
				t.Fatalf("row status=%q error_message=%q, want %q / %q", row.Status, row.ErrorMessage, tc.status, tc.msg)
			}
		})
	}
}

// Security requirement 7 with the client that stopped reading: the stop sets
// the write deadline to now, so a Write blocked on that client returns too.
func TestStopStreamsEndsAStreamWhoseClientStoppedReading(t *testing.T) {
	t.Parallel()
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: flood()}, nil, nil)
	srv := f.serve()
	_, id := rawStreamClient(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	deadline := time.Now().Add(2 * time.Second)
	for f.H.openStreams.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the client's buffers fill
	start := time.Now()
	f.H.StopStreams()
	f.waitNoStreams()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the relay took %v to return after StopStreams", took)
	}
	if rows := f.rows(id); len(rows) != 1 {
		t.Fatalf("rows=%+v want exactly one", rows)
	}
}

// updateKey reads the fixture's key, lets the test change it and writes it
// back, which is what the management API does for a revoke, an expiry, a
// rotation or a retarget.
func updateKey(t *testing.T, f *fixture, change func(*models.VirtualKey)) {
	t.Helper()
	ctx := context.Background()
	vk, err := f.Store.GetVirtualKey(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	change(vk)
	if err := f.Store.UpdateVirtualKey(ctx, vk); err != nil {
		t.Fatal(err)
	}
}

// Security requirement 12: a key that stops being valid ends its open streams
// within the re-check interval, whichever way it stopped being valid, and even
// when the client has stopped reading.
func TestRevokedKeyEndsItsStream(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	changes := map[string]func(*models.VirtualKey){
		"revoked":    func(vk *models.VirtualKey) { vk.RevokedAt = &past },
		"expired":    func(vk *models.VirtualKey) { vk.ExpiresAt = &past },
		"rotated":    func(vk *models.VirtualKey) { vk.KeyLookup = "rotated-lookup" },
		"retargeted": func(vk *models.VirtualKey) { vk.TargetID = "some-other-target" },
	}
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gone := make(chan struct{})
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(ackDoc))}, nil, nil)
			srv := f.serve()
			resp, id := open(t, f, srv, "/a1/mcp", listenRPC)
			defer resp.Body.Close()
			ls := readLines(resp.Body)
			ls.event(t, 2*time.Second)
			updateKey(t, f, change)
			if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("stream ended with %v, want an unexpected EOF", err)
			}
			<-gone
			row := oneRow(t, f, id)
			if row.Status != models.StatusError || row.ErrorMessage != errStreamRevoked.Error() {
				t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
			}
		})
	}
	t.Run("revoked-client-not-reading", func(t *testing.T) {
		t.Parallel()
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: flood()}, nil, nil)
		srv := f.serve()
		_, id := rawStreamClient(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
		deadline := time.Now().Add(2 * time.Second)
		for f.H.openStreams.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		updateKey(t, f, changes["revoked"])
		start := time.Now()
		f.waitNoStreams()
		if took := time.Since(start); took > time.Second {
			t.Fatalf("the relay held a revoked key's stream for %v", took)
		}
		if rows := f.rows(id); len(rows) != 1 || rows[0].Status != models.StatusError {
			t.Fatalf("rows=%+v want one error row", rows)
		}
	})
}

// failingKeyStore is the fixture's store with one read that fails, so the
// re-check's fail-open rule can be seen.
type failingKeyStore struct{ store.Store }

func (failingKeyStore) GetVirtualKey(context.Context, string) (*models.VirtualKey, error) {
	return nil, errors.New("store unavailable")
}

// Security requirement 12: an upstream the route no longer resolves to ends the
// stream, on the key route (disabled) and the member route (removed from the
// group); a store that cannot be read leaves the stream open and is logged.
func TestRemovedUpstreamEndsItsStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	t.Run("disabled-on-key-route", func(t *testing.T) {
		t.Parallel()
		gone := make(chan struct{})
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(ackDoc))}, nil, nil)
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/mcp", listenRPC)
		defer resp.Body.Close()
		ls := readLines(resp.Body)
		ls.event(t, 2*time.Second)
		ctx := context.Background()
		up, err := f.Store.GetUpstream(ctx, "u1")
		if err != nil {
			t.Fatal(err)
		}
		up.Enabled = false
		if err := f.Store.UpdateUpstream(ctx, up, false, false); err != nil {
			t.Fatal(err)
		}
		if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("stream ended with %v", err)
		}
		<-gone
		row := oneRow(t, f, id)
		if row.Status != models.StatusError || row.ErrorMessage != errUpstreamRemoved.Error() {
			t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
	})
	t.Run("removed-from-group-on-member-route", func(t *testing.T) {
		t.Parallel()
		gone := make(chan struct{})
		f := singleMember(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(ackDoc))})
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/solo/mcp", listenRPC)
		defer resp.Body.Close()
		ls := readLines(resp.Body)
		ls.event(t, 2*time.Second)
		ctx := context.Background()
		vk, err := f.Store.GetVirtualKey(ctx, "a1")
		if err != nil {
			t.Fatal(err)
		}
		g, err := f.Store.GetGroup(ctx, vk.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		g.UpstreamIDs = nil
		if err := f.Store.UpdateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
		if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("stream ended with %v", err)
		}
		<-gone
		row := oneRow(t, f, id)
		if row.Status != models.StatusError || row.ErrorMessage != errUpstreamRemoved.Error() {
			t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
	})
	t.Run("store-error-fails-open", func(t *testing.T) {
		t.Parallel()
		gone := make(chan struct{})
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(ackDoc))}, nil, nil)
		f.rebuild(failingKeyStore{f.Store})
		logs := captureLogs(f)
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/mcp", listenRPC)
		ls := readLines(resp.Body)
		ls.event(t, 2*time.Second)
		time.Sleep(120 * time.Millisecond) // two re-checks, each failing
		if n := f.H.openStreams.Load(); n != 1 {
			t.Fatalf("open_streams=%d after a failing re-check, want the stream still open", n)
		}
		resp.Body.Close()
		<-gone
		row := oneRow(t, f, id)
		if row.Status != models.StatusSuccess {
			t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
		if !strings.Contains(logs.String(), "stream re-check could not read the store") {
			t.Fatalf("no warning for the failed re-check: %s", logs.String())
		}
	})
}

// countingStore counts key reads, so a re-check that outlives its stream shows
// up as reads that keep coming.
type countingStore struct {
	store.Store
	reads atomic.Int64
}

func (c *countingStore) GetVirtualKey(ctx context.Context, id string) (*models.VirtualKey, error) {
	c.reads.Add(1)
	return c.Store.GetVirtualKey(ctx, id)
}

// Security requirement 15: no timer outlives its stream. With the re-check at
// 1 ms a leaked timer would read the store hundreds of times after the stream
// ended; a second request on the same connection is served as usual.
func TestStreamCallbacksDoNotOutliveTheStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, time.Millisecond)
	setBudget(t, &streamIdleBudget, 200*time.Millisecond)
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: func(w http.ResponseWriter, r *http.Request) {
		if rpcMethodOf(r) == "tools/list" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`)
			return
		}
		thenClose(sseFrame(resultDoc))(w, r)
	}}, nil, nil)
	cs := &countingStore{Store: f.Store}
	f.rebuild(cs)
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	oneRow(t, f, id)
	time.Sleep(20 * time.Millisecond)
	before := cs.reads.Load()
	time.Sleep(40 * time.Millisecond)
	if after := cs.reads.Load(); after != before {
		t.Fatalf("the re-check read the store %d times after its stream ended", after-before)
	}
	req, _ := f.streamRequest(srv, "/a1/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, nil)
	resp2, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("the next request on the connection answered %d", resp2.StatusCode)
	}
}

// Security requirement 5: an event larger than the judge keeps is relayed
// whole and the capture stays bounded. A client that closes after it is an
// error row; an upstream that closes after it is a success, because the
// answer was that event.
func TestStreamOverTailCapThenClientCloseIsError(t *testing.T) {
	t.Parallel()
	big := "event: message\ndata: " + strings.Repeat("x", judgeTailBytes+judgeTailBytes/4) + "\n\n"
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		close   bool
		status  string
		msg     string
	}{
		{"client-closes", holdOpen(nil, big), true, models.StatusError, "client closed the stream before the answer"},
		{"upstream-closes", thenClose(big), false, models.StatusSuccess, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: tc.handler}, nil, nil)
			srv := f.serve()
			resp, id := open(t, f, srv, "/a1/mcp", toolCall("1", "ping_tool"))
			defer resp.Body.Close()
			got := make([]byte, len(big))
			if _, err := io.ReadFull(resp.Body, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(big)) {
				t.Fatal("the oversized event did not reach the client intact")
			}
			if tc.close {
				resp.Body.Close()
			} else if _, err := io.ReadAll(resp.Body); err != nil {
				t.Fatal(err)
			}
			row := oneRow(t, f, id)
			if row.Status != tc.status || row.ErrorMessage != tc.msg {
				t.Fatalf("row status=%q error_message=%q, want %q / %q", row.Status, row.ErrorMessage, tc.status, tc.msg)
			}
			if row.ResponseSizeBytes != len(big) {
				t.Fatalf("row size=%d want %d", row.ResponseSizeBytes, len(big))
			}
		})
	}
}

// Security requirement 13: an upstream that refuses a listen with an error
// event carrying the request id is an error row with its message, on the key
// route and on the member route. The listen-is-success rule never swallows it.
func TestListenRefusedByUpstreamIsAnErrorRow(t *testing.T) {
	t.Parallel()
	spec := upstreamSpec{Tools: []string{"ping_tool"}, Handler: thenClose(sseFrame(errorDoc))}
	t.Run("key-route", func(t *testing.T) {
		f := newSingleFixture(t, spec, nil, nil)
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/mcp", listenRPC)
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		row := oneRow(t, f, id)
		if row.Status != models.StatusError || row.ErrorMessage != "Subscription limit reached" {
			t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
	})
	t.Run("member-route", func(t *testing.T) {
		f := singleMember(t, spec)
		srv := f.serve()
		resp, id := open(t, f, srv, "/a1/solo/mcp", listenRPC)
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		row := oneRow(t, f, id)
		if row.Status != models.StatusError || row.ErrorMessage != "Subscription limit reached" {
			t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
		}
	})
}

// Security requirement 8: a stream is visible while it is open. The opened and
// closed lines carry the bounded method and never the params.
func TestStreamLogsOpenAndClose(t *testing.T) {
	t.Parallel()
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: thenClose(sseFrame(resultDoc))}, nil, nil)
	logs := captureLogs(f)
	srv := f.serve()
	long := strings.Repeat("m", 400)
	rpc := `{"jsonrpc":"2.0","id":1,"method":"` + long + `","params":{"secret":"SHOULD-NOT-BE-LOGGED"}}`
	resp, id := open(t, f, srv, "/a1/mcp", rpc)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	oneRow(t, f, id)
	var opened, closed map[string]any
	for _, rec := range logRecords(t, logs) {
		switch rec["msg"] {
		case "stream opened":
			opened = rec
		case "stream closed":
			closed = rec
		}
	}
	if opened == nil || closed == nil {
		t.Fatalf("want a stream opened and a stream closed line: %s", logs.String())
	}
	for _, rec := range []map[string]any{opened, closed} {
		for _, k := range []string{"request_id", "virtual_key_id", "upstream_id", "method", "open_streams"} {
			if _, ok := rec[k]; !ok {
				t.Errorf("%s line lacks %s: %v", rec["msg"], k, rec)
			}
		}
		if m, _ := rec["method"].(string); len(m) > auditFieldBytes {
			t.Errorf("logged method is %d bytes, want at most %d", len(m), auditFieldBytes)
		}
		if _, ok := rec["params"]; ok {
			t.Errorf("%s line carries params", rec["msg"])
		}
	}
	for _, k := range []string{"bytes", "ms", "end"} {
		if _, ok := closed[k]; !ok {
			t.Errorf("stream closed line lacks %s: %v", k, closed)
		}
	}
	if closed["end"] != "upstream" {
		t.Errorf("end=%v want upstream", closed["end"])
	}
	if strings.Contains(logs.String(), "SHOULD-NOT-BE-LOGGED") {
		t.Fatal("a param reached the log")
	}
}

// Security requirement 5: the capture reads the same head and last event
// whatever the chunking, for both blank-line forms and a boundary split across
// two writes, and a stream with no boundary at all stays bounded.
func TestStreamCaptureSplitAtEveryOffset(t *testing.T) {
	t.Parallel()
	sample := []byte("event: message\ndata: {\"a\":1}\n\n" +
		"data: {\"b\":2}\r\n\r\n" +
		": keepalive\n\n" +
		"data: {\"c\":3}\ndata: more\n\n" +
		"data: {\"d\":4}\r\n\r\n")
	var whole streamCapture
	whole.Write(sample)
	if string(whole.last) != "data: {\"d\":4}\r\n\r\n" || len(whole.pending) != 0 || whole.tailOverflowed() {
		t.Fatalf("whole: last=%q pending=%q overflowed=%v", whole.last, whole.pending, whole.tailOverflowed())
	}
	for i := 1; i < len(sample); i++ {
		var c streamCapture
		c.Write(sample[:i])
		c.Write(sample[i:])
		if !bytes.Equal(c.head, whole.head) || !bytes.Equal(c.last, whole.last) || len(c.pending) != 0 || c.tailOverflowed() {
			t.Fatalf("split at %d: head=%q last=%q pending=%q overflowed=%v", i, c.head, c.last, c.pending, c.tailOverflowed())
		}
	}
	var partial streamCapture
	partial.Write(sample[:len(sample)-5])
	if string(partial.last) != "data: {\"c\":3}\ndata: more\n\n" || len(partial.pending) == 0 {
		t.Fatalf("partial: last=%q pending=%q", partial.last, partial.pending)
	}
	var endless streamCapture
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for i := 0; i < 128; i++ { // 4 MiB with no blank line
		endless.Write(chunk)
	}
	if !endless.tailOverflowed() || cap(endless.pending) > judgeTailBytes || len(endless.head) != judgeHeadBytes {
		t.Fatalf("endless: overflowed=%v cap(pending)=%d head=%d", endless.tailOverflowed(), cap(endless.pending), len(endless.head))
	}
	endless.Write([]byte("\n\n"))
	if !endless.tailOverflowed() || len(endless.last) != 0 {
		t.Fatalf("after the oversized event's boundary: overflowed=%v last=%q, want overflowed with nothing kept", endless.tailOverflowed(), endless.last)
	}
	endless.Write([]byte("data: {\"e\":5}\n\n"))
	if endless.tailOverflowed() || string(endless.last) != "data: {\"e\":5}\n\n" {
		t.Fatalf("after a normal event: overflowed=%v last=%q", endless.tailOverflowed(), endless.last)
	}
}

// Security requirement 10 and the verdict rules, as a table: what a row says
// for every way a stream can end, with and without an answer.
func TestStreamVerdictTable(t *testing.T) {
	t.Parallel()
	const ct = "text/event-stream"
	capOf := func(body string, overflowed bool) *streamCapture {
		var c streamCapture
		c.Write([]byte(body))
		c.lastOverflow = overflowed
		return &c
	}
	long := errors.New(strings.Repeat("e", 4096))
	cases := []struct {
		name       string
		method     string
		body       string
		overflowed bool
		end        streamEnd
		err        error
		status     string
		msg        string
	}{
		{"one notification then EOF", "tools/call", sseFrame(progressDoc), false, endUpstream, nil, models.StatusError, "upstream closed the stream before the answer"},
		{"two notifications then EOF", "tools/call", sseFrame(progressDoc) + sseFrame(progressDoc), false, endUpstream, nil, models.StatusError, "upstream closed the stream before the answer"},
		{"matching result", "tools/call", sseFrame(progressDoc) + sseFrame(resultDoc), false, endClient, nil, models.StatusSuccess, ""},
		{"matching error", "tools/call", sseFrame(errorDoc), false, endUpstream, nil, models.StatusError, "Subscription limit reached"},
		{"off-id result", "tools/call", sseFrame(`{"jsonrpc":"2.0","id":9,"result":{}}`), false, endUpstream, nil, models.StatusError, "upstream closed the stream before the answer"},
		{"unframed JSON error under the label", "tools/call", errorDoc, false, endUpstream, nil, models.StatusError, "Subscription limit reached"},
		{"read error text is bounded", "tools/call", sseFrame(progressDoc), false, endReadError, long, models.StatusError, strings.Repeat("e", auditFieldBytes)},
		{"overflow then upstream EOF", "tools/call", "", true, endUpstream, nil, models.StatusSuccess, ""},
		{"overflow then client close", "tools/call", "", true, endClient, nil, models.StatusError, "client closed the stream before the answer"},
		{"listen client close", "subscriptions/listen", sseFrame(ackDoc), false, endClient, nil, models.StatusSuccess, ""},
		{"listen upstream EOF", "subscriptions/listen", sseFrame(ackDoc), false, endUpstream, nil, models.StatusSuccess, ""},
		{"listen stopped", "subscriptions/listen", sseFrame(ackDoc), false, endStopped, errStreamStopped, models.StatusSuccess, ""},
		{"listen idle", "subscriptions/listen", sseFrame(ackDoc), false, endIdle, &budgetError{what: "sent nothing for", d: time.Minute}, models.StatusSuccess, ""},
		{"listen revoked", "subscriptions/listen", sseFrame(ackDoc), false, endRevoked, errStreamRevoked, models.StatusError, errStreamRevoked.Error()},
		{"listen refused", "subscriptions/listen", sseFrame(errorDoc), false, endUpstream, nil, models.StatusError, "Subscription limit reached"},
		{"call stopped", "tools/call", "", false, endStopped, errStreamStopped, models.StatusError, "proxy stopped before the answer"},
		{"call idle", "tools/call", "", false, endIdle, &budgetError{what: "sent nothing for", d: time.Minute}, models.StatusError, "upstream sent nothing for 1m0s"},
		{"call upstream removed", "tools/call", "", false, endRevoked, errUpstreamRemoved, models.StatusError, errUpstreamRemoved.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := streamVerdict(tc.method, 200, ct, capOf(tc.body, tc.overflowed), "1", tc.end, tc.err)
			msg = truncate(msg, auditFieldBytes)
			if status != tc.status || msg != tc.msg {
				t.Fatalf("status=%q msg=%q, want %q / %q", status, msg, tc.status, tc.msg)
			}
		})
	}
}

// Security requirement 11: the decision to stream reads one header and
// allocates nothing, so the JSON path pays nothing for it.
func TestStreamableAllocsNothing(t *testing.T) {
	for _, ct := range []string{"application/json", "application/json; charset=utf-8"} {
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ct}}}
		if n := testing.AllocsPerRun(100, func() { _ = streamable(false, "tools/call", resp) }); n != 0 {
			t.Errorf("streamable allocates %v per call for %q", n, ct)
		}
	}
}

// D1: a JSON answer and a non-2xx event stream stay buffered and
// byte-identical to the upstream's, with no X-Accel-Buffering, and their rows
// are what they were.
func TestJSONAnswerRelayedByteIdentical(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		spec   upstreamSpec
		code   int
		ct     string
		status string
	}{
		{"json", upstreamSpec{Tools: []string{"ping_tool"}, CallBody: resultDoc}, 200, "application/json", models.StatusSuccess},
		{"500-event-stream", upstreamSpec{Tools: []string{"ping_tool"}, CallBody: sseFrame(errorDoc), CallCode: 500, CallCT: "text/event-stream"}, 500, "text/event-stream", models.StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSingleFixture(t, tc.spec, nil, nil)
			rr := f.post(toolCall("1", "ping_tool"))
			if rr.Code != tc.code || rr.Body.String() != tc.spec.CallBody {
				t.Fatalf("code=%d body=%q, want %d and the upstream's bytes", rr.Code, rr.Body.String(), tc.code)
			}
			if got := rr.Header().Get("Content-Type"); got != tc.ct {
				t.Fatalf("Content-Type=%q want %q", got, tc.ct)
			}
			if rr.Header().Get("X-Accel-Buffering") != "" {
				t.Fatal("X-Accel-Buffering on a buffered answer")
			}
			row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
			if row.Status != tc.status || row.ResponseSizeBytes != len(tc.spec.CallBody) {
				t.Fatalf("row status=%q size=%d, want %q and %d", row.Status, row.ResponseSizeBytes, tc.status, len(tc.spec.CallBody))
			}
		})
	}
}

// D1: a tools/list answered as an event stream is read whole and filtered as
// before, never streamed, so the per-key filter still applies.
func TestToolsListSSEStaysBuffered(t *testing.T) {
	t.Parallel()
	list := sseFrame(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping_tool","inputSchema":{"type":"object"}},{"name":"hidden_tool","inputSchema":{"type":"object"}}]}}`)
	f := newSingleFixture(t, upstreamSpec{RawList: list, ListCT: "text/event-stream"}, []string{"ping_tool"}, nil)
	rr := f.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Accel-Buffering") != "" {
		t.Fatal("X-Accel-Buffering on a tools/list answer")
	}
	if strings.Contains(rr.Body.String(), "hidden_tool") {
		t.Fatal("the filter did not run on the event-stream listing")
	}
	row := f.waitAudit(models.LogFilter{Method: "tools/list"})[0]
	if row.ResponseSizeBytes != rr.Body.Len() {
		t.Fatalf("row size=%d want %d", row.ResponseSizeBytes, rr.Body.Len())
	}
}

// A2: the group endpoint never streams. A member's event-stream answer to a
// routed call is reduced to its one JSON document, as before.
func TestAggregateNeverStreams(t *testing.T) {
	t.Parallel()
	f := singleMember(t, upstreamSpec{Tools: []string{"ping_tool"}, CallCT: "text/event-stream", CallBody: sseFrame(progressDoc) + sseFrame(resultDoc)})
	rr := f.post(toolCall("1", "solo__ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json: the aggregate reduces, it does not stream", got)
	}
	if rr.Header().Get("X-Accel-Buffering") != "" {
		t.Fatal("X-Accel-Buffering on a group answer")
	}
	if strings.Contains(rr.Body.String(), "notifications/progress") {
		t.Fatal("the group relayed the member's notifications instead of reducing")
	}
	if row := f.waitAudit(models.LogFilter{Tool: "solo__ping_tool"})[0]; row.Status != models.StatusSuccess {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}
