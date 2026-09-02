package webutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWriteHealthOK(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteHealth(rr, nil, true, 2, EncryptionOK)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type=%q", ct)
	}
	var body HealthBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Service != "porymcp" || !body.SchemeEnforced || body.TrustedProxies != 2 || body.Encryption != "ok" {
		t.Fatalf("body=%+v", body)
	}
	if _, err := time.Parse(time.RFC3339, body.Time); err != nil {
		t.Fatalf("time %q: %v", body.Time, err)
	}
	if strings.Contains(rr.Body.String(), "/") && strings.Contains(rr.Body.String(), "10.") {
		t.Fatalf("must not include CIDRs: %s", rr.Body.String())
	}
}

func TestWriteHealthUnhealthy(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteHealth(rr, errors.New("store ping failed"), false, 0, EncryptionOK)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	var body HealthBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "unhealthy" || body.Error != "database unavailable" {
		t.Fatalf("body=%+v", body)
	}
	if body.SchemeEnforced || body.TrustedProxies != 0 {
		t.Fatalf("policy fields=%+v", body)
	}
	if body.Service != "" || body.Time != "" {
		t.Fatalf("unhealthy should omit service/time: %+v", body)
	}
}

// TestWriteHealthDegraded covers PORM-52 acceptance criterion 4 and security
// requirement 6: a key mismatch is a 503 "degraded" body that still says the
// process is serving (service/time), carries the verdict and nothing else
// derived from the key.
func TestWriteHealthDegraded(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteHealth(rr, nil, false, 0, EncryptionMismatch)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	var body HealthBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "degraded" || body.Encryption != "mismatch" || body.Error != "" {
		t.Fatalf("body=%+v", body)
	}
	if body.Service != "porymcp" || body.Time == "" {
		t.Fatalf("degraded must still carry service/time: %+v", body)
	}
	for _, k := range []string{"fingerprint", "count", "upstream", "name"} {
		if strings.Contains(strings.ToLower(rr.Body.String()), k) {
			t.Fatalf("degraded body carries %q: %s", k, rr.Body.String())
		}
	}
}

// TestWriteHealthUnhealthyWinsOverMismatch pins the precedence: a failed
// store ping is the worse fact and keeps today's shape, while the encryption
// verdict is still reported.
func TestWriteHealthUnhealthyWinsOverMismatch(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteHealth(rr, errors.New("store ping failed"), false, 0, EncryptionMismatch)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	var body HealthBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "unhealthy" || body.Encryption != "mismatch" || body.Error != "database unavailable" {
		t.Fatalf("body=%+v", body)
	}
	if body.Service != "" || body.Time != "" {
		t.Fatalf("unhealthy keeps today's shape (no service/time): %+v", body)
	}
}

// TestWriteHealthUnhealthyFixedError covers PORM-25 security requirement 8:
// the unauthenticated body carries the fixed string, never the real store
// error, which can quote DSN detail (a pgx ConnectError formats
// `user=… database=…` plus host:port; an SQLite error quotes the file path).
func TestWriteHealthUnhealthyFixedError(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteHealth(rr, errors.New("failed to connect to `user=porymcp database=porymcp`: postgres:5432"), false, 0, EncryptionOK)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
	var body HealthBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "database unavailable" {
		t.Fatalf("error=%q", body.Error)
	}
	for _, k := range []string{"user=", "database=", "5432"} {
		if strings.Contains(rr.Body.String(), k) {
			t.Fatalf("body carries %q: %s", k, rr.Body.String())
		}
	}
}

// TestLogPingFailureThrottles covers PORM-25 security requirement 8's second
// half: the real store error is logged server-side at most once per throttle
// window — /health is unauthenticated and fetched on every dashboard page
// load, so an unthrottled per-request line would hand anonymous callers a log
// amplifier. Same-package on purpose: it resets the unexported throttle state
// so test ordering cannot couple.
func TestLogPingFailureThrottles(t *testing.T) {
	pingLogMu.Lock()
	lastPingLog = time.Time{}
	pingLogMu.Unlock()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	LogPingFailure(log, errors.New("boom"))
	LogPingFailure(log, errors.New("boom again"))
	if got := strings.Count(buf.String(), "store ping failed"); got != 1 {
		t.Fatalf("want exactly one line in the window, got %d: %q", got, buf.String())
	}
	if !strings.Contains(buf.String(), "boom") {
		t.Fatalf("the real error must reach the log line: %q", buf.String())
	}
	// Nil guards, each against a FRESH throttle window — asserted inside the
	// window they would otherwise hide in, a deleted guard goes unnoticed
	// (the nil-logger call would return at the throttle branch before ever
	// dereferencing nil).
	reset := func() {
		pingLogMu.Lock()
		lastPingLog = time.Time{}
		pingLogMu.Unlock()
	}
	reset()
	LogPingFailure(nil, errors.New("boom")) // must not panic
	reset()
	before := buf.Len()
	LogPingFailure(log, nil) // must not log
	if buf.Len() != before {
		t.Fatalf("nil error must not log: %q", buf.String())
	}
}
