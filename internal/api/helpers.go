package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// logReadTimeout bounds one read of the audit log on GET /logs and GET
// /admin-events, the wait for the database connection included. On SQLite
// that connection is shared with the proxy's key lookups and the audit writer,
// whose insert gives up after 5 s (internal/audit). An indexed page reads in
// under a millisecond, so 2 s stops only a walk of the period. A package var,
// as the proxy's budgets are, so a test can shorten it.
var logReadTimeout = 2 * time.Second

// errLogReadTimeout is the answer to a read logReadTimeout stopped. The
// dashboard matches it (web/src/lib/logs-view.ts LOG_READ_TIMEOUT) to show its
// own sentence; TestLogReadTimeoutMatchesTheDashboard keeps the two equal.
const errLogReadTimeout = "log query took too long"

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// tooManyRequests answers a caller a limiter turned away, carrying the wait the
// limiter itself computed. The rounding rule (whole seconds, never zero) is
// webutil.RetryAfterSeconds, shared with the proxy's relay door. There is more
// than one budget on this server now, so the header and the shape of the body
// are written in one place rather than at each of them.
func tooManyRequests(w http.ResponseWriter, retry time.Duration, msg string) {
	w.Header().Set("Retry-After", webutil.RetryAfterSeconds(retry))
	writeError(w, http.StatusTooManyRequests, msg)
}

func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrInUse):
		writeError(w, http.StatusConflict, "resource is still referenced")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	case errors.Is(err, store.ErrInvalidCursor):
		writeError(w, http.StatusBadRequest, "invalid cursor")
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// readFailed answers a bounded store read that returned err under ctx, a
// WithTimeout child of r's context. It is decided on the context, not the
// error, because SQLite and pgx report an interrupted query differently.
// Past the deadline it is a 503 with slow and one warning line naming the
// path and request id. When the caller has gone (the dashboard aborts a
// request it no longer wants) nothing is written: nobody reads it, and a 500
// would log a store failure for an ordinary filter change. Anything else is
// storeError's, so an invalid cursor stays a 400, and the store error goes to
// the server log only.
func (s *Server) readFailed(ctx context.Context, w http.ResponseWriter, r *http.Request, err error, slow string) {
	gone := r.Context().Err() != nil
	switch {
	case !gone && errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.log.Warn("store read stopped", "path", r.URL.Path, "request_id", middleware.GetReqID(r.Context()))
		writeError(w, http.StatusServiceUnavailable, slow)
	case gone:
		// Nothing written.
	default:
		s.log.Warn("store read failed", "path", r.URL.Path, "request_id", middleware.GetReqID(r.Context()), "error", err)
		storeError(w, err)
	}
}

func parseTimeParam(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, s)
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}
