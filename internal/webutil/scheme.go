package webutil

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const (
	insecureSchemeMsg = "insecure scheme"
	insecureLogEvery  = time.Minute
)

var (
	insecureLogMu   sync.Mutex
	lastInsecureLog time.Time
)

// EnforceHTTPS refuses clear-text requests when active is true (the caller
// decides that from config.SchemeEnforced so /health and the middleware
// cannot drift). Loopback is skipped so the container healthcheck
// (http://127.0.0.1) keeps working when the process itself terminates TLS
// or sits behind an edge. Rejection is 426 with a JSON body that names the
// scheme only, never CIDRs or PUBLIC_URL.
func EnforceHTTPS(active bool, trusted []netip.Prefix, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !active || socketLoopback(r) {
				next.ServeHTTP(w, r)
				return
			}
			scheme := RequestScheme(r, trusted)
			if scheme != "http" {
				next.ServeHTTP(w, r)
				return
			}
			writeInsecureScheme(w, r, trusted, log, scheme)
		})
	}
}

func socketLoopback(r *http.Request) bool {
	if r == nil {
		return false
	}
	ip, ok := parseRemoteAddr(r.RemoteAddr)
	return ok && ip.IsLoopback()
}

func writeInsecureScheme(w http.ResponseWriter, r *http.Request, trusted []netip.Prefix, log *slog.Logger, scheme string) {
	if origin := r.Header.Get("Origin"); origin != "" {
		// Surface 426 to a browser instead of a CORS failure when the edge
		// is misconfigured. Localhost origins are not special-cased.
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Vary", "Origin")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Session-Id, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	}
	logInsecureOnce(log, scheme, RequestHost(r, trusted))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUpgradeRequired)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  insecureSchemeMsg,
		"scheme": scheme,
	})
}

func logInsecureOnce(log *slog.Logger, scheme, host string) {
	if log == nil {
		return
	}
	now := time.Now()
	insecureLogMu.Lock()
	defer insecureLogMu.Unlock()
	if !lastInsecureLog.IsZero() && now.Sub(lastInsecureLog) < insecureLogEvery {
		return
	}
	lastInsecureLog = now
	log.Warn("rejected insecure scheme", "scheme", scheme, "host", host)
}
