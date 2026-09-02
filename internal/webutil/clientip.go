package webutil

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses a comma-separated list of CIDRs or bare IPs
// (a bare IPv4 becomes /32, a bare IPv6 becomes /128). Empty input is valid
// and means "trust nobody": ClientIP will then always return the socket
// address and ignore forwarding headers.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
			continue
		}
		ip, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// ClientIP returns the remote address that subsequent per-IP controls should
// key on. Forwarded (RFC 7239) and X-Forwarded-For are honoured only when the
// socket address falls inside trusted; otherwise the socket address is used
// and the headers are ignored. When several hops are listed, the rightmost
// address that is not itself trusted is the client.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	socket, ok := parseRemoteAddr(r.RemoteAddr)
	if !ok {
		if r.RemoteAddr != "" {
			return r.RemoteAddr
		}
		return "unknown"
	}
	if !socketTrusted(r, trusted) {
		return socket.String()
	}
	hops := forwardedHops(r)
	if len(hops) == 0 {
		return socket.String()
	}
	return pickClient(hops, trusted, socket).String()
}

func parseRemoteAddr(remote string) (netip.Addr, bool) {
	if remote == "" {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remote = strings.Trim(remote, "[]")
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

func ipTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedHops prefers RFC 7239 Forwarded hops that have a parsable for=,
// then falls back to X-Forwarded-For. RequestScheme / RequestHost read proto
// and host from the same parser; this helper only needs the addresses.
func forwardedHops(r *http.Request) []netip.Addr {
	if values := r.Header.Values("Forwarded"); len(values) > 0 {
		var hops []netip.Addr
		for _, h := range parseForwardedHops(values) {
			if h.forAddr.IsValid() {
				hops = append(hops, h.forAddr)
			}
		}
		if len(hops) > 0 {
			return hops
		}
	}
	return parseXForwardedFor(headerCSV(r, "X-Forwarded-For"))
}

func pickClient(hops []netip.Addr, trusted []netip.Prefix, socket netip.Addr) netip.Addr {
	for i := len(hops) - 1; i >= 0; i-- {
		if !ipTrusted(hops[i], trusted) {
			return hops[i]
		}
	}
	if len(hops) > 0 {
		return hops[0]
	}
	return socket
}
