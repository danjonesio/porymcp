package webutil

import (
	"net"
	"net/url"
	"strings"
)

// HostAllowed reports whether seen (already resolved via RequestHost) is
// acceptable for publicURL. Empty publicURL allows everything — that is
// today's hostAllowed short-circuit, kept so an unset PUBLIC_URL does not
// lock operators out. Comparison is case-insensitive and IPv6-safe
// (net/url.Parse, not TrimPrefix).
func HostAllowed(seen, publicURL string, extra []string, allowLocalhost bool) bool {
	if publicURL == "" {
		return true
	}
	if strings.TrimSpace(seen) == "" {
		return false
	}

	u, err := url.Parse(publicURL)
	scheme := ""
	if err == nil && u != nil {
		scheme = u.Scheme
		if publicHostMatches(seen, u) {
			return true
		}
		if localhostAllowed(seen, u.Host, allowLocalhost) {
			return true
		}
	} else if isLocalhostClass(seen) && allowLocalhost {
		return true
	}

	for _, e := range extra {
		if extraHostMatches(seen, e, scheme) {
			return true
		}
	}
	return false
}

// ExpectedHost is the host[:port] of publicURL, or "" if empty or unparsable.
// Callers use it in 403 bodies so the operator can see what was expected
// without guessing how PUBLIC_URL was split.
func ExpectedHost(publicURL string) string {
	if publicURL == "" {
		return ""
	}
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func publicHostMatches(seen string, u *url.URL) bool {
	if u == nil || u.Host == "" {
		return false
	}
	seenHost, seenPort, _ := splitOptionalPort(seen)
	if !strings.EqualFold(seenHost, u.Hostname()) {
		return false
	}
	if u.Port() == "" {
		// Portless PUBLIC_URL: the request port is not part of the identity.
		return true
	}
	return samePort(seenPort, u.Port(), u.Scheme)
}

func extraHostMatches(seen, extra, scheme string) bool {
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return false
	}
	seenHost, seenPort, _ := splitOptionalPort(seen)
	extraHost, extraPort, extraHasPort := splitOptionalPort(extra)
	if extraHost == "" || !strings.EqualFold(seenHost, extraHost) {
		return false
	}
	if !extraHasPort {
		return true
	}
	return samePort(seenPort, extraPort, scheme)
}

func localhostAllowed(seen, publicHost string, allowLocalhost bool) bool {
	if !isLocalhostClass(seen) {
		return false
	}
	return allowLocalhost || isLocalhostClass(publicHost)
}

func isLocalhostClass(hostport string) bool {
	host, _, _ := splitOptionalPort(hostport)
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func samePort(seenPort, wantPort, scheme string) bool {
	return stripDefaultPort(seenPort, scheme) == stripDefaultPort(wantPort, scheme)
}

func stripDefaultPort(port, scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		if port == "443" {
			return ""
		}
	case "http":
		if port == "80" {
			return ""
		}
	}
	return port
}

// splitOptionalPort separates host[:port] without assuming a port is present.
// Bracketed IPv6 is unwrapped so "[::1]" and "::1" compare equal.
func splitOptionalPort(hostport string) (host, port string, hasPort bool) {
	hostport = strings.TrimSpace(hostport)
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return unwrapHost(h), p, true
	}
	return unwrapHost(hostport), "", false
}

func unwrapHost(host string) string {
	return strings.Trim(host, "[]")
}
