package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
)

// Logger writes audit entries asynchronously so proxy latency stays low.
type Logger struct {
	store store.Store
	ch    chan models.AuditLog
	log   *slog.Logger
}

func New(s store.Store, log *slog.Logger) *Logger {
	l := &Logger{
		store: s,
		ch:    make(chan models.AuditLog, 1024),
		log:   log,
	}
	go l.loop()
	return l
}

func (l *Logger) loop() {
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
	select {
	case l.ch <- e:
	default:
		// Channel full: fall back to a blocking send with a short timeout via goroutine.
		go func() { l.ch <- e }()
	}
}

func (l *Logger) Close() { close(l.ch) }

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
