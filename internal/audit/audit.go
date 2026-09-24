package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	// send can slip between the check and the close. A send that is parked
	// on a full queue holds it shared too, so Close first closes closing,
	// which every parked send selects on, and none of them can hold Close
	// past the drain bound.
	mu        sync.RWMutex
	closed    bool
	closing   chan struct{} // closed first by Close: a parked send gives way
	closeOnce sync.Once
	done      chan struct{} // closed when loop has drained ch
	// parked counts the sends that fell back to enqueue, so a test can tell
	// it reached that path.
	parked atomic.Int64
}

// drainTimeout bounds how long Close waits for the writer to drain the queue.
// A package var, as the proxy's budgets are, so a test can shorten it.
var drainTimeout = 5 * time.Second

func New(s store.Store, log *slog.Logger) *Logger {
	l := &Logger{
		store:   s,
		ch:      make(chan models.AuditLog, 1024),
		log:     log,
		closing: make(chan struct{}),
		done:    make(chan struct{}),
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
	e.ErrorMessage = errorText(e.ErrorMessage)
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
// while it waits, and gives way the moment Close starts, so the row it holds
// is dropped with a line rather than delaying the drain.
func (l *Logger) enqueue(e models.AuditLog) {
	l.parked.Add(1)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		l.dropped(e)
		return
	}
	select {
	case l.ch <- e:
	case <-l.closing:
		l.dropped(e)
	}
}

// dropped says a row was lost, by id, method and request id only: the row's
// error_message can carry an upstream's own error text, and its params are
// the caller's.
func (l *Logger) dropped(e models.AuditLog) {
	if l.log != nil {
		l.log.Error("audit row dropped after close", "id", e.ID, "method", e.Method, "request_id", e.RequestID)
	}
}

// Close stops accepting rows, closes the queue and waits for loop to drain it,
// for at most drainTimeout measured from the call. Rows still queued when that
// runs out are counted in the log and lost, and loop goes on inserting them
// until the store closes under it. A second Close returns at once.
func (l *Logger) Close() {
	deadline := time.NewTimer(drainTimeout)
	defer deadline.Stop()
	l.closeOnce.Do(func() { close(l.closing) })
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.ch)
	}
	l.mu.Unlock()
	select {
	case <-l.done:
	case <-deadline.C:
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

// queryOnlySecretKeys is the second set of credential names, read only by
// RedactQuery: the names an HTTP API takes a key under in a query string
// (PORM-146). It is separate from secretKeys on purpose: Redact runs over
// every audit row, MCP tool arguments included, and a tool argument named
// "code" or "key" is not a secret there. Matching is on the lower-cased name
// with "-" read as "_", so api-key and api_key are one name.
var queryOnlySecretKeys = map[string]struct{}{
	"key":                  {},
	"api_key":              {},
	"access_token":         {},
	"id_token":             {},
	"client_secret":        {},
	"client_assertion":     {},
	"assertion":            {},
	"code":                 {},
	"sig":                  {},
	"signature":            {},
	"private_token":        {},
	"auth":                 {},
	"jwt":                  {},
	"session":              {},
	"oauth_token":          {},
	"oauth_signature":      {},
	"passwd":               {},
	"pwd":                  {},
	"x_amz_signature":      {},
	"x_amz_credential":     {},
	"x_amz_security_token": {},
	"x_goog_signature":     {},
	"x_goog_credential":    {},
}

// RedactQuery turns a relayed request's query string into the object the
// relay door records under params.query: one string per name, repeated
// values joined with ",", and a value replaced by "[redacted]" when its name
// is in secretKeys or queryOnlySecretKeys. Values are strings, never arrays,
// because redactValue (which Record still runs over the whole row) replaces
// only a string under a secret name; an array of secrets would pass it in
// clear.
func RedactQuery(q url.Values) map[string]string {
	out := make(map[string]string, len(q))
	for name, vals := range q {
		norm := strings.ReplaceAll(strings.ToLower(name), "-", "_")
		_, a := secretKeys[norm]
		_, b := queryOnlySecretKeys[norm]
		if a || b {
			out[name] = redacted
			continue
		}
		out[name] = strings.Join(vals, ",")
	}
	return out
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
					out[k] = redacted
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
