package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// BearerToken extracts a Bearer credential from Authorization.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		// Some MCP clients send the key as X-Api-Key.
		return r.Header.Get("X-Api-Key")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func AdminAuthorized(r *http.Request, adminKey string) bool {
	if adminKey == "" {
		return false
	}
	got := BearerToken(r)
	if got == "" {
		return false
	}
	if len(got) != len(adminKey) {
		// Still compare to keep timing closer to constant.
		subtle.ConstantTimeCompare([]byte(got), []byte(adminKey))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(adminKey)) == 1
}
