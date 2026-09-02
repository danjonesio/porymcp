package webutil

import (
	"net/http"
	"net/netip"
	"strings"
)

// RequestScheme is the scheme the caller used, as observed by PoryMCP.
// Forwarded proto= (RFC 7239) and X-Forwarded-Proto are honoured only when
// the socket is a trusted proxy; otherwise the local TLS state is used so a
// client cannot claim https on a clear-text hop. Only http and https are
// accepted; anything else falls through to the next source.
func RequestScheme(r *http.Request, trusted []netip.Prefix) string {
	if !socketTrusted(r, trusted) {
		return socketScheme(r)
	}
	if s := rightmostForwardedScheme(parseForwardedHops(r.Header.Values("Forwarded"))); s != "" {
		return s
	}
	if s := canonicalScheme(rightmostToken(headerCSV(r, "X-Forwarded-Proto"))); s != "" {
		return s
	}
	return socketScheme(r)
}

// RequestHost is the Host the caller presented. Forwarded host= and
// X-Forwarded-Host are honoured only from a trusted socket, so a rewritten
// container Host (the usual reverse-proxy default) can still match PUBLIC_URL.
// The value is returned as sent — port and IPv6 brackets are left intact.
func RequestHost(r *http.Request, trusted []netip.Prefix) string {
	if r == nil {
		return ""
	}
	if !socketTrusted(r, trusted) {
		return r.Host
	}
	if h := rightmostForwardedHost(parseForwardedHops(r.Header.Values("Forwarded"))); h != "" {
		return h
	}
	if h := rightmostToken(headerCSV(r, "X-Forwarded-Host")); h != "" {
		return h
	}
	return r.Host
}

func socketScheme(r *http.Request) string {
	if r != nil && r.TLS != nil {
		return "https"
	}
	return "http"
}

func canonicalScheme(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "http":
		return "http"
	case "https":
		return "https"
	default:
		return ""
	}
}

// rightmostForwardedScheme uses only the rightmost hop's proto. An earlier
// hop is the client and is spoofable; if the edge omitted proto we fall
// through to X-Forwarded-Proto instead of walking left.
func rightmostForwardedScheme(hops []forwardedHop) string {
	if len(hops) == 0 {
		return ""
	}
	return canonicalScheme(hops[len(hops)-1].proto)
}

func rightmostForwardedHost(hops []forwardedHop) string {
	if len(hops) == 0 {
		return ""
	}
	return hops[len(hops)-1].host
}
