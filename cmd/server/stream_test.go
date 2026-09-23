package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/auth"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// PORM-5 at the level of the server that ships: the router with its whole
// middleware chain on a real listener, an upstream that streams, a key, and
// the shutdown sequence main runs.

// lockedLog collects the server's log lines from every goroutine.
type lockedLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// streamServer is the shipping server over one streaming upstream and one key.
type streamServer struct {
	srv     *http.Server
	ln      net.Listener
	st      store.Store
	auditor *audit.Logger
	key     string
	logs    *lockedLog
}

// newStreamServer builds the store, the upstream stub, the key, the router
// (with the shutdown hook registered as main does) and serves it on a
// loopback listener. The caller owns Shutdown and auditor.Close, in that
// order, which is main's order.
func newStreamServer(t *testing.T, upstream http.HandlerFunc) *streamServer {
	t.Helper()
	encKey, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	stub := httptest.NewServer(upstream)
	t.Cleanup(stub.Close)

	cfg := &config.Config{AdminAPIKey: "test-admin", EncryptionKey: encKey, PublicURL: "http://localhost:8080", ListenAddr: "127.0.0.1:0"}
	logs := &lockedLog{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditor := audit.New(st, log)

	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.CreateUpstream(ctx, &models.Upstream{
		ID: "u1", Name: "Streamer", Slug: "streamer", URL: stub.URL,
		Transport: models.TransportStreamableHTTP, AuthType: models.AuthNone,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	plain, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVirtualKey(ctx, &models.VirtualKey{
		ID: "k1", Name: "bot", KeyLookup: lookup, KeyPrefix: prefix,
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	r, stopStreams := newRouter(cfg, st, auditor, log, nil, webutil.EncryptionOK)
	srv := newHTTPServer(cfg, r)
	srv.RegisterOnShutdown(stopStreams)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	return &streamServer{srv: srv, ln: ln, st: st, auditor: auditor, key: plain, logs: logs}
}

// open sends one proxy request to the key's endpoint over the listener, with
// the public host the host check expects.
func (s *streamServer) open(t *testing.T, rpc string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+s.ln.Addr().String()+"/k1/mcp", strings.NewReader(rpc))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "localhost:8080"
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// readEvent reads lines up to and including a blank one, with a deadline.
func readEvent(t *testing.T, br *bufio.Reader, within time.Duration) string {
	t.Helper()
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			sb.WriteString(line)
			if err != nil {
				ch <- result{sb.String(), err}
				return
			}
			if strings.TrimSpace(line) == "" {
				ch <- result{sb.String(), nil}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("the stream ended (%v) before an event: %q", r.err, r.s)
		}
		return r.s
	case <-time.After(within):
		t.Fatalf("no event within %v", within)
	}
	return ""
}

func sseListenStub(gone chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{}}\n\n")
		_ = rc.Flush()
		if strings.Contains(string(body), "subscriptions/listen") {
			<-r.Context().Done()
			close(gone)
		}
	}
}

// PORM-5 security requirement 7, end to end: with a listen held open,
// Shutdown returns at once because the hook ended the stream, the stream's
// row was queued, and auditor.Close drains it into the store before main
// would exit.
func TestShutdownEndsOpenStreamsAndStoresRows(t *testing.T) {
	gone := make(chan struct{})
	s := newStreamServer(t, sseListenStub(gone))
	resp := s.open(t, `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("code=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	br := bufio.NewReader(resp.Body)
	if ev := readEvent(t, br, 2*time.Second); !strings.Contains(ev, "acknowledged") {
		t.Fatalf("first event %q", ev)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Shutdown took %v with a listen open, want under 1s", took)
	}
	select {
	case <-gone:
	case <-time.After(time.Second):
		t.Fatal("the upstream did not see its request cancelled")
	}
	s.auditor.Close()
	rows, _, err := s.st.ListAuditLogs(context.Background(), models.LogFilter{Method: "subscriptions/listen", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != models.StatusSuccess {
		t.Fatalf("rows=%+v want one success row for the listen, in the store when Close returned", rows)
	}
	if !strings.Contains(s.logs.String(), `"end":"stopped"`) {
		t.Fatalf("no stream closed line with end=stopped: %s", s.logs.String())
	}
}

// A stream lives for as long as the upstream and the client keep it, so the
// server must never carry a write timeout or a read timeout: either would cut
// every listen at the timeout. This pins the two fields at zero.
func TestServerNeverSetsWriteTimeout(t *testing.T) {
	cfg := &config.Config{ListenAddr: "127.0.0.1:0"}
	srv := newHTTPServer(cfg, http.NotFoundHandler())
	if srv.WriteTimeout != 0 || srv.ReadTimeout != 0 {
		t.Fatalf("WriteTimeout=%v ReadTimeout=%v, want both 0: a relayed stream would be cut", srv.WriteTimeout, srv.ReadTimeout)
	}
	if srv.ReadHeaderTimeout == 0 {
		t.Fatal("ReadHeaderTimeout is 0; the header bound is what protects the server from a slow client")
	}
}

// PORM-5 criterion 1 through the shipping middleware chain: requestLogger
// wraps the writer in chi's WrapResponseWriter, and the relay's flush has to
// reach the connection through it. The upstream writes event 2 only after the
// test has read event 1, so a wrapper that swallowed the flush would never
// deliver event 1 and the test fails on its deadline. The http log line the
// logger writes when the stream ends counts the stream's bytes.
func TestRouterRelaysAStreamIncrementally(t *testing.T) {
	next := make(chan struct{})
	events := []string{
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n",
	}
	s := newStreamServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		for i, e := range events {
			if i > 0 {
				select {
				case <-next:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = io.WriteString(w, e)
			_ = rc.Flush()
		}
	})
	defer s.auditor.Close()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	}()
	resp := s.open(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code=%d", resp.StatusCode)
	}
	br := bufio.NewReader(resp.Body)
	if ev := readEvent(t, br, 5*time.Second); ev != events[0] {
		t.Fatalf("event 1 = %q", ev)
	}
	next <- struct{}{}
	if ev := readEvent(t, br, 5*time.Second); ev != events[1] {
		t.Fatalf("event 2 = %q", ev)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("after the last event: %v, want EOF", err)
	}
	want := len(events[0]) + len(events[1])
	deadline := time.Now().Add(2 * time.Second)
	for {
		if strings.Contains(s.logs.String(), `"msg":"http"`) && strings.Contains(s.logs.String(), `"path":"/k1/mcp"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no http log line for the stream: %s", s.logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	var httpLine string
	for _, line := range strings.Split(s.logs.String(), "\n") {
		if strings.Contains(line, `"msg":"http"`) && strings.Contains(line, `"path":"/k1/mcp"`) {
			httpLine = line
		}
	}
	if !strings.Contains(httpLine, `"bytes":`+strconv.Itoa(want)) {
		t.Fatalf("http line %s, want bytes=%d", httpLine, want)
	}
}
