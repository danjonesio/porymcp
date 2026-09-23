package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

func TestRedactSecrets(t *testing.T) {
	in := json.RawMessage(`{"name":"search","arguments":{"q":"ok"},"token":"sk-live","Authorization":"Bearer x"}`)
	out := Redact(in)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["token"] != "[redacted]" {
		t.Fatalf("token=%v", m["token"])
	}
	if m["Authorization"] != "[redacted]" {
		t.Fatalf("Authorization=%v", m["Authorization"])
	}
	args := m["arguments"].(map[string]any)
	if args["q"] != "ok" {
		t.Fatalf("innocent field redacted: %v", args["q"])
	}
}

// countingStore is the real store with its inserts counted and, when delay is
// set, slowed, so a queue of rows is still draining when Close runs and the
// number that reached the store is known without paging the list (which the
// store caps at 50 rows a page).
type countingStore struct {
	store.Store
	delay    time.Duration
	inserted atomic.Int64
}

func (s *countingStore) InsertAuditLog(ctx context.Context, e *models.AuditLog) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.inserted.Add(1)
	return s.Store.InsertAuditLog(ctx, e)
}

// lockedBuffer collects log lines from the logger's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func openStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// PORM-5 security requirement 7: every row queued before Close is in the
// store when Close returns, so a stream ended at shutdown keeps its row.
func TestCloseDrainsQueuedRows(t *testing.T) {
	st := &countingStore{Store: openStore(t), delay: 2 * time.Millisecond}
	l := New(st, nil)
	for i := 0; i < 50; i++ {
		l.Record(models.AuditLog{VirtualKeyID: "k", Method: "tools/call", Status: models.StatusSuccess, RequestID: "r"})
	}
	l.Close()
	if n := st.inserted.Load(); n != 50 {
		t.Fatalf("%d rows in the store when Close returned, want 50", n)
	}
}

// PORM-5 security requirement 7: a row recorded while Close runs, or after
// it, is either stored or dropped with a log line, and nothing panics. The
// store is slowed so the queue (1,024 slots) fills and the fallback send runs
// and is parked when Close starts. Run under -race: the send and the close
// share one lock.
func TestRecordAfterCloseDoesNotPanic(t *testing.T) {
	st := &countingStore{Store: openStore(t), delay: 200 * time.Microsecond}
	logs := &lockedBuffer{}
	l := New(st, slog.New(slog.NewJSONHandler(logs, nil)))
	const workers, each = 100, 15
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				l.Record(models.AuditLog{VirtualKeyID: "k", Method: "tools/call", Status: models.StatusSuccess, RequestID: "r"})
			}
		}()
	}
	time.Sleep(2 * time.Millisecond)
	l.Close()
	wg.Wait()
	l.Record(models.AuditLog{VirtualKeyID: "k", Method: "after", Status: models.StatusSuccess, RequestID: "late"})
	l.Close() // a second Close is harmless
	stored := st.inserted.Load()
	dropped := int64(strings.Count(logs.String(), "audit row dropped after close"))
	if stored+dropped != workers*each+1 {
		t.Fatalf("%d stored + %d dropped, want %d", stored, dropped, workers*each+1)
	}
	if l.parked.Load() == 0 {
		t.Fatal("no send fell back to enqueue: the queue never filled, so the parked-send path was not exercised")
	}
	if dropped == 0 || !strings.Contains(logs.String(), `"method":"after"`) {
		t.Fatalf("the late row was not logged as dropped: %s", logs.String())
	}
	for _, rec := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(rec, "error_message") || strings.Contains(rec, "params") {
			t.Fatalf("a dropped-row line carries more than id, method and request id: %s", rec)
		}
	}
}

// blockingStore is a store whose inserts wait until the test releases them.
type blockingStore struct {
	store.Store
	release chan struct{}
}

func (s *blockingStore) InsertAuditLog(ctx context.Context, e *models.AuditLog) error {
	<-s.release
	return s.Store.InsertAuditLog(ctx, e)
}

// PORM-5 security requirement 7: Close returns at the drain bound whatever the
// store does, and says how many rows were still queued. A parked fallback send
// gives way to Close instead of holding it.
func TestCloseReturnsAtTheDrainBound(t *testing.T) {
	old := drainTimeout
	drainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })
	st := &blockingStore{Store: openStore(t), release: make(chan struct{})}
	t.Cleanup(func() { close(st.release) })
	logs := &lockedBuffer{}
	l := New(st, slog.New(slog.NewJSONHandler(logs, nil)))
	// Fill the queue and park a fallback send on it.
	for i := 0; i < 1024+8; i++ {
		l.Record(models.AuditLog{VirtualKeyID: "k", Method: "tools/call", Status: models.StatusSuccess, RequestID: "r"})
	}
	time.Sleep(5 * time.Millisecond)
	start := time.Now()
	l.Close()
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("Close took %v with a blocked store, want about the 100 ms bound", took)
	}
	if !strings.Contains(logs.String(), "audit rows not written before exit") || !strings.Contains(logs.String(), `"pending":`) {
		t.Fatalf("no pending line: %s", logs.String())
	}
	if dropped := strings.Count(logs.String(), "audit row dropped after close"); dropped == 0 {
		t.Fatalf("the parked fallback sends did not give way: %s", logs.String())
	}
}
