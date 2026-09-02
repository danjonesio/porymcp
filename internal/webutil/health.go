package webutil

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// The two values /health reports for the encryption key. A closed set of
// constant strings on purpose: /health is unauthenticated on both routes, so
// it carries a verdict and never a fingerprint, a count or a name — a
// fingerprint would let an unauthenticated caller test whether a particular
// key is in use.
const (
	EncryptionOK       = "ok"
	EncryptionMismatch = "mismatch"
)

// HealthBody is the shared /health JSON. Trusted-proxy policy is reported as
// a count only — the CIDR strings must never appear in the payload — and the
// encryption key as a verdict only.
type HealthBody struct {
	Status         string `json:"status"`
	Service        string `json:"service,omitempty"`
	Time           string `json:"time,omitempty"`
	SchemeEnforced bool   `json:"scheme_enforced"`
	TrustedProxies int    `json:"trusted_proxies"`
	// Encryption is EncryptionOK or EncryptionMismatch: the boot integrity
	// check's verdict on whether every stored credential opens under the
	// configured key(s). Present on every body. It is a boot fact — the
	// restart that ends a rotation refreshes it.
	Encryption string `json:"encryption"`
	Error      string `json:"error,omitempty"`
}

// WriteHealth writes the JSON health payload. Precedence: pingErr != nil is
// "unhealthy" (503, today's shape — no service/time) and outranks the
// encryption verdict, which is still reported; else encryption ==
// EncryptionMismatch is "degraded" (503, with service/time: the process is
// serving and the dashboard is reachable, but stored credentials cannot be
// read); else "ok" (200). schemeEnforced, trustedCount and encryption are
// policy facts, so an operator sees them whatever the status.
func WriteHealth(w http.ResponseWriter, pingErr error, schemeEnforced bool, trustedCount int, encryption string) {
	body := HealthBody{
		SchemeEnforced: schemeEnforced,
		TrustedProxies: trustedCount,
		Encryption:     encryption,
	}
	status := http.StatusOK
	switch {
	case pingErr != nil:
		body.Status = "unhealthy"
		// Never pingErr.Error(): it can quote DSN detail — an SQLite file
		// path, or pgx's `user=… database=…` plus host:port — and /health
		// is anonymous on both routes (the internal/crypto/aes.go doctrine:
		// never return an error that could quote input). LogPingFailure
		// carries the real error to the server log.
		body.Error = dbUnavailableMsg
		status = http.StatusServiceUnavailable
	case encryption == EncryptionMismatch:
		body.Status = "degraded"
		body.Service = "porymcp"
		body.Time = time.Now().UTC().Format(time.RFC3339)
		status = http.StatusServiceUnavailable
	default:
		body.Status = "ok"
		body.Service = "porymcp"
		body.Time = time.Now().UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// dbUnavailableMsg is the only store-error detail the unauthenticated /health
// body ever carries; the real error goes to the server log via LogPingFailure.
const dbUnavailableMsg = "database unavailable"

// pingLogEvery throttles LogPingFailure: /health is unauthenticated and the
// dashboard fetches it on every page load, so an unthrottled per-request
// Error line would let any anonymous caller amplify a down database into
// unbounded log volume. One line per minute is the diagnostic that survives
// LOG_LEVEL=error (requestLogger's per-request Info line is filtered there).
// The throttle is deliberate — do not "fix" it back to per-request logging.
const pingLogEvery = time.Minute

var (
	pingLogMu   sync.Mutex
	lastPingLog time.Time
)

// LogPingFailure records a store ping failure server-side, at most once per
// pingLogEvery, mirroring logInsecureOnce. The error text never reaches the
// response body — see dbUnavailableMsg.
func LogPingFailure(log *slog.Logger, pingErr error) {
	if pingErr == nil || log == nil {
		return
	}
	now := time.Now()
	pingLogMu.Lock()
	defer pingLogMu.Unlock()
	if !lastPingLog.IsZero() && now.Sub(lastPingLog) < pingLogEvery {
		return
	}
	lastPingLog = now
	log.Error("store ping failed", "err", pingErr)
}
