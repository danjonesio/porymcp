package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/google/uuid"
)

// Logger writes audit entries asynchronously so proxy latency stays low.
//
// Close drains what has been queued before it returns (PORM-5): a relayed
// stream writes its row when the proxy stops it at shutdown, which makes that
// row the last thing queued and, without the drain, the first thing lost on
// every redeploy. A row recorded after Close is dropped with a log line rather
// than sent on a closed channel.
type Logger struct {
	store store.Store
	ch    chan models.AuditLog
	log   *slog.Logger
	// mu orders every send against Close: a send holds it shared, Close holds
	// it exclusively while it marks the logger closed and closes ch, so no
	// send can slip between the check and the close.
	mu     sync.RWMutex
	closed bool
	done   chan struct{} // closed when loop has drained ch
}

func New(s store.Store, log *slog.Logger) *Logger {
	l := &Logger{
		store: s,
		ch:    make(chan models.AuditLog, 1024),
		log:   log,
		done:  make(chan struct{}),
	}
	go l.loop()
	return l
}

func (l *Logger) loop() {
	defer close(l.done)
	for e := range l.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := l.store.InsertAuditLog(ctx, &e); err != nil && l.log != nil {
			l.log.Error("audit write failed", "err", err, "id", e.ID)
		}
		cancel()
	}
}

func (l *Logger) Record(e models.AuditLog) {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	e.Params = Redact(e.Params)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		l.dropped(e)
		return
	}
	select {
	case l.ch <- e:
	default:
		// Channel full: fall back to a blocking send on its own goroutine,
		// under the same lock, so it too cannot send on a closed channel.
		go l.enqueue(e)
	}
}

// enqueue is the blocking send Record falls back to. It holds the read lock
// while it waits, which delays Close until loop has made room, and loop keeps
// draining, so the wait ends.
func (l *Logger) enqueue(e models.AuditLog) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		l.dropped(e)
		return
	}
	l.ch <- e
}

// dropped says a row was lost, by id, method and request id only: the row's
// error_message can quote an upstream URL, and its params are the caller's.
func (l *Logger) dropped(e models.AuditLog) {
	if l.log != nil {
		l.log.Error("audit row dropped after close", "id", e.ID, "method", e.Method, "request_id", e.RequestID)
	}
}

// Close stops accepting rows, closes the queue and waits for loop to drain it,
// for at most five seconds. Rows still queued when that runs out are counted
// in the log and lost.
func (l *Logger) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	close(l.ch)
	l.mu.Unlock()
	select {
	case <-l.done:
	case <-time.After(5 * time.Second):
		if l.log != nil {
			l.log.Error("audit rows not written before exit", "pending", len(l.ch))
		}
	}
}

var secretKeys = map[string]struct{}{
	"authorization": {},
	"token":         {},
	"api_key":       {},
	"apikey":        {},
	"password":      {},
	"secret":        {},
	"access_token":  {},
	"refresh_token": {},
	"value":         {},
}

// Redact recursively replaces sensitive JSON fields with "[redacted]".
func Redact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return raw
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if _, secret := secretKeys[strings.ToLower(k)]; secret {
				if s, ok := val.(string); ok && s != "" {
					out[k] = "[redacted]"
					continue
				}
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}
