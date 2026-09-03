package api

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/netcasklabs/porymcp/internal/store"
)

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
// limiter itself computed. Retry-After is whole seconds and never zero, because
// a client that honours a "0" backs off for no time at all, which is the one
// thing a budget exists to prevent. There is more than one budget on this
// server now, so the header and the shape of the body are written in one place
// rather than at each of them.
func tooManyRequests(w http.ResponseWriter, retry time.Duration, msg string) {
	sec := int(math.Ceil(retry.Seconds()))
	if sec < 1 {
		sec = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(sec))
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
