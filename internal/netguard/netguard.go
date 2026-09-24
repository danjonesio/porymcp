// Package netguard is the dial-time check on where a request carrying an
// upstream credential may connect (PORM-79). It resolves the host itself,
// classifies every address the resolver returned, and dials only an address
// it has checked. A pre-flight lookup at save time would not do: Go resolves
// again at dial time, and a name that answers with a public address once and
// a loopback address the next time (DNS rebinding) would pass the check and
// reach the loopback. The check therefore sits on the transport's DialContext,
// and the dial target is always the address that was classified, never the
// host text.
//
// The refused classes are loopback (unless AllowLoopback), link-local,
// multicast, unspecified, and a short list of cloud metadata addresses that
// no option reopens. Private ranges stay open by default because that is
// where a Docker upstream lives; DenyPrivate closes them.
//
// The package imports the standard library and nothing else, so config,
// mcpclient and their tests can all import it without a cycle.
package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Options is the operator's two switches. The zero value denies loopback and
// allows private ranges, so a construction site that forgets to pass the
// configured options fails closed.
type Options struct {
	// AllowLoopback permits 127.0.0.0/8 and ::1 (UPSTREAM_ALLOW_LOOPBACK).
	// It reopens loopback only: unspecified, multicast, link-local and
	// metadata addresses stay refused.
	AllowLoopback bool
	// DenyPrivate refuses RFC 1918, ULA and CGNAT ranges
	// (UPSTREAM_DENY_PRIVATE).
	DenyPrivate bool
}

// ErrAddressDenied is the sentinel every refusal unwraps to.
var ErrAddressDenied = errors.New("upstream address denied")

// Denied is a refusal. It carries the class and nothing else: the sentence an
// audit row or an operator sees names the class, never the address the host
// resolved to, so the proxy cannot be used to learn which internal names
// resolve to which ranges. It never wraps a *net.OpError or a *net.DNSError,
// so a resolver failure stays distinct from a refusal.
type Denied struct{ Class string }

func (d Denied) Error() string { return ErrAddressDenied.Error() + ": " + d.Class }

func (d Denied) Unwrap() error { return ErrAddressDenied }

// The classes a refusal can name.
const (
	ClassMetadata    = "metadata"
	ClassLoopback    = "loopback"
	ClassUnspecified = "unspecified"
	ClassMulticast   = "multicast"
	ClassLinkLocal   = "link-local"
	ClassPrivate     = "private"
)

// metadata is the list of cloud metadata addresses refused whatever the
// options say. Checked first, because the AWS and GCP IPv6 addresses are
// ULA (which DenyPrivate alone would leave open) and the IPv4 ones are
// link-local or CGNAT.
var metadata = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS, Azure, GCP, most others
	netip.MustParsePrefix("fd00:ec2::/64"),      // AWS IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer
	netip.MustParsePrefix("fd20:ce::254/128"),   // GCP IPv6
}

var (
	// zeroNet is 0.0.0.0/8. netip reports only 0.0.0.0 as unspecified, but
	// Linux connects the whole range to the local host.
	zeroNet = netip.MustParsePrefix("0.0.0.0/8")
	// cgnat is RFC 6598 shared address space, which netip's IsPrivate leaves
	// out; tailnets and one cloud's metadata live there.
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	// nat64 and v4compat embed an IPv4 address in the last four bytes. They
	// are classified by that address and dialled as themselves.
	nat64    = netip.MustParsePrefix("64:ff9b::/96")
	v4compat = netip.MustParsePrefix("::/96")
)

// attemptFloor is the least a single dial attempt gets when the deadline is
// split across candidates, the same floor net.Dialer applies.
const attemptFloor = 2 * time.Second

// dialBudget bounds a whole dial, every candidate included, when the caller's
// context carries no deadline. That is the production case: http.Transport
// detaches the context it hands DialContext from the request's, deadline
// included, so the request's own budget never reaches here. It is the
// default dialer's 30 s connect timeout, split across the permitted
// candidates. A variable so a test can shorten it.
var dialBudget = 30 * time.Second

type lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Dialer returns the DialContext for a transport carrying an upstream
// credential. It resolves through net.DefaultResolver and connects through a
// net.Dialer with the default transport's keep-alive.
func Dialer(o Options) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{KeepAlive: 30 * time.Second}
	return dialer(o, net.DefaultResolver.LookupNetIP, d.DialContext)
}

// dialer is Dialer with the resolver and the connect step as arguments, so a
// test can hand it a fixed answer and record what it dials.
func dialer(o Options, lookup lookupFunc, dial dialFunc) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		var candidates []netip.Addr
		if a, perr := netip.ParseAddr(host); perr == nil {
			candidates = []netip.Addr{a}
		} else {
			// A resolver error goes back as it came, *net.DNSError included,
			// so "no such host" is never mistaken for a refusal.
			candidates, err = lookup(ctx, ipNetwork(network), host)
			if err != nil {
				return nil, err
			}
			if len(candidates) == 0 {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
		}

		// Classify every candidate; keep the permitted ones in resolver
		// order. The zone is stripped and an embedded IPv4 address extracted
		// for the check only. The dial target is the candidate itself, so a
		// NAT64 answer is dialled as the IPv6 address the resolver gave.
		var permitted []netip.Addr
		firstClass := ""
		for _, c := range candidates {
			c = c.Unmap()
			if class := classify(embeddedIPv4(c.WithZone("")), o); class != "" {
				if firstClass == "" {
					firstClass = class
				}
				continue
			}
			permitted = append(permitted, c)
		}
		if len(permitted) == 0 {
			return nil, Denied{Class: firstClass}
		}

		// One bound for the whole dial: the caller's deadline when it has
		// one, dialBudget when it has none. Cancelling it after a connection
		// was made does not affect that connection.
		overall := ctx
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			overall, cancel = context.WithTimeout(ctx, dialBudget)
			defer cancel()
		}

		// Serial, in resolver order, each attempt on its share of what is
		// left of the bound. A denied candidate is never a fallback.
		var last error
		for i, a := range permitted {
			if err := overall.Err(); err != nil {
				return nil, err
			}
			attempt, cancel := attemptContext(overall, len(permitted)-i)
			conn, err := dial(attempt, network, netip.AddrPortFrom(a, uint16(port)).String())
			cancel()
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}

// attemptContext bounds one dial attempt: an equal share of what is left of
// the overall bound across the candidates still to try, with net.Dialer's
// floor. The caller always passes a context with a deadline; a context
// without one gets dialBudget as a whole.
func attemptContext(ctx context.Context, remainingCandidates int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithTimeout(ctx, dialBudget)
	}
	remaining := time.Until(deadline)
	share := remaining / time.Duration(remainingCandidates)
	if share < attemptFloor && remaining > attemptFloor {
		share = attemptFloor
	}
	return context.WithTimeout(ctx, share)
}

// ipNetwork maps the transport's network to the resolver's: LookupNetIP
// accepts ip, ip4 and ip6 and rejects tcp.
func ipNetwork(network string) string {
	switch network {
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	}
	return "ip"
}

// embeddedIPv4 returns the IPv4 address a NAT64 or IPv4-compatible IPv6
// address embeds, and every other address unchanged. :: and ::1 sit inside
// ::/96 and are their own classes, so they pass through.
func embeddedIPv4(a netip.Addr) netip.Addr {
	if !a.Is6() || a.IsUnspecified() || a.IsLoopback() {
		return a
	}
	if nat64.Contains(a) || v4compat.Contains(a) {
		b := a.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return a
}

// classify names the class an address is refused under, or "" when it may
// be dialled. a is already unmapped, zone-stripped and IPv4-extracted. The
// order matters: the metadata addresses are also link-local or ULA, ::1
// sits inside ::/96, and 224.0.0.0/24 is both multicast and link-local.
func classify(a netip.Addr, o Options) string {
	for _, p := range metadata {
		if p.Contains(a) {
			return ClassMetadata
		}
	}
	if a.IsLoopback() {
		if o.AllowLoopback {
			return ""
		}
		return ClassLoopback
	}
	if a.IsUnspecified() || zeroNet.Contains(a) {
		return ClassUnspecified
	}
	if a.IsMulticast() {
		return ClassMulticast
	}
	if a.IsLinkLocalUnicast() {
		return ClassLinkLocal
	}
	if o.DenyPrivate && (a.IsPrivate() || cgnat.Contains(a)) {
		return ClassPrivate
	}
	return ""
}
