package webutil

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// forwardedHop is one RFC 7239 forwarded-element. proto and host are empty
// when that parameter was absent; forAddr is zero when for= was missing or
// not a parsable IP (obfuscated tokens, "unknown").
type forwardedHop struct {
	forAddr netip.Addr
	proto   string
	host    string
}

// parseForwardedHops walks every Forwarded header value: comma-separated
// elements, then semicolon-separated parameters. Keys are matched
// case-insensitively. Quoted values are unquoted. for= uses the same hop
// parser as X-Forwarded-For so IPv6 "[addr]:port" stays consistent.
func parseForwardedHops(values []string) []forwardedHop {
	var hops []forwardedHop
	for _, v := range values {
		for _, elem := range strings.Split(v, ",") {
			hop := parseForwardedElement(elem)
			if !hop.forAddr.IsValid() && hop.proto == "" && hop.host == "" {
				continue
			}
			hops = append(hops, hop)
		}
	}
	return hops
}

func parseForwardedElement(elem string) forwardedHop {
	var hop forwardedHop
	for _, param := range strings.Split(elem, ";") {
		param = strings.TrimSpace(param)
		key, val, found := strings.Cut(param, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		switch {
		case strings.EqualFold(key, "for"):
			if ip, ok := parseHop(val); ok {
				hop.forAddr = ip
			}
		case strings.EqualFold(key, "proto"):
			hop.proto = unquoteForwarded(val)
		case strings.EqualFold(key, "host"):
			hop.host = unquoteForwarded(val)
		}
	}
	return hop
}

func unquoteForwarded(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseXForwardedFor extracts IPs from a comma-separated X-Forwarded-For
// value. Tokens that are not addresses are skipped.
func parseXForwardedFor(v string) []netip.Addr {
	var hops []netip.Addr
	for _, part := range strings.Split(v, ",") {
		if ip, ok := parseHop(part); ok {
			hops = append(hops, ip)
		}
	}
	return hops
}

// parseHop turns one forwarded address token into an IP. It accepts a bare
// address, host:port, or bracketed IPv6 with an optional port, and treats
// "unknown" as absent, those tokens are not client IPs.
func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	if s == "" || strings.EqualFold(s, "unknown") {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

// headerCSV joins every value of a header so rightmost-token and hop
// parsers see lines that were added (not only comma-appended to the first).
func headerCSV(r *http.Request, name string) string {
	if r == nil {
		return ""
	}
	return strings.Join(r.Header.Values(name), ",")
}

// rightmostToken returns the last non-empty comma-separated token, trimmed.
// Proxies append, so the rightmost value is what the trusted edge wrote.
func rightmostToken(header string) string {
	last := ""
	for _, part := range strings.Split(header, ",") {
		if t := strings.TrimSpace(part); t != "" {
			last = t
		}
	}
	return last
}

// socketTrusted reports whether r.RemoteAddr parses as an IP inside trusted.
// An empty trusted list means trust nobody, forwarding headers stay ignored.
func socketTrusted(r *http.Request, trusted []netip.Prefix) bool {
	if r == nil || len(trusted) == 0 {
		return false
	}
	ip, ok := parseRemoteAddr(r.RemoteAddr)
	return ok && ipTrusted(ip, trusted)
}
