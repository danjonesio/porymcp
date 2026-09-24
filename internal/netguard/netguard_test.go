package netguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a dial step that records every target and answers as told.
type recorder struct {
	mu      sync.Mutex
	targets []string
	fail    func(target string) error
}

func (r *recorder) dial(_ context.Context, _ string, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.targets = append(r.targets, addr)
	r.mu.Unlock()
	if r.fail != nil {
		if err := r.fail(addr); err != nil {
			return nil, err
		}
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func (r *recorder) dialled() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...)
}

func fixed(addrs ...string) lookupFunc {
	return func(context.Context, string, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func noLookup(t *testing.T) lookupFunc {
	return func(_ context.Context, _, host string) ([]netip.Addr, error) {
		t.Fatalf("lookup called for %q; a literal must not be resolved", host)
		return nil, nil
	}
}

// Security requirements 1, 2, 3 and 5: every refused class through the real
// Dialer (a literal is classified before any socket opens), the class names
// the refusal, the error never carries the literal, and a permitted private
// address is attempted by default and refused under DenyPrivate.
func TestGuardRefusesClasses(t *testing.T) {
	cases := []struct {
		addr, class string
	}{
		{"127.0.0.1:1", ClassLoopback},
		{"[::1]:1", ClassLoopback},
		{"[::ffff:127.0.0.1]:1", ClassLoopback},
		{"[::7f00:1]:1", ClassLoopback},
		{"[64:ff9b::7f00:1]:1", ClassLoopback},
		{"169.254.169.254:80", ClassMetadata},
		{"[::ffff:169.254.169.254]:80", ClassMetadata},
		{"[fd00:ec2::254]:80", ClassMetadata},
		{"[fd00:ec2::254%lo]:80", ClassMetadata},
		{"100.100.100.200:80", ClassMetadata},
		{"168.63.129.16:80", ClassMetadata},
		{"[fd20:ce::254]:80", ClassMetadata},
		{"[fe80::1%lo]:80", ClassLinkLocal},
		{"224.0.0.1:80", ClassMulticast},
		{"[ff02::1]:80", ClassMulticast},
		{"0.0.0.0:80", ClassUnspecified},
		{"0.1.2.3:80", ClassUnspecified},
		{"[::]:80", ClassUnspecified},
		{"[::%lo]:80", ClassUnspecified},
	}
	dial := Dialer(Options{})
	for _, tc := range cases {
		conn, err := dial(context.Background(), "tcp", tc.addr)
		if conn != nil {
			conn.Close()
		}
		var denied Denied
		if !errors.As(err, &denied) || !errors.Is(err, ErrAddressDenied) {
			t.Errorf("%s: err=%v, want a Denied refusal", tc.addr, err)
			continue
		}
		if denied.Class != tc.class {
			t.Errorf("%s: class=%q want %q", tc.addr, denied.Class, tc.class)
		}
		host, _, _ := net.SplitHostPort(tc.addr)
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if !strings.Contains(err.Error(), tc.class) || strings.Contains(err.Error(), host) {
			t.Errorf("%s: error text %q must name the class and never the address", tc.addr, err)
		}
	}

	// Private ranges: attempted by default, refused under DenyPrivate. A
	// real dial to an unrouted address would depend on the network the test
	// runs on, so the connect step is recorded instead.
	private := []struct{ addr, target string }{
		{"10.0.0.1:80", "10.0.0.1:80"},
		{"[fd12::1]:80", "[fd12::1]:80"},
		{"100.64.0.1:80", "100.64.0.1:80"},
		// NAT64: classified by the embedded 10.0.0.1, dialled as itself.
		{"[64:ff9b::a00:1]:80", "[64:ff9b::a00:1]:80"},
	}
	for _, tc := range private {
		rec := &recorder{}
		open := dialer(Options{}, noLookup(t), rec.dial)
		conn, err := open(context.Background(), "tcp", tc.addr)
		if err != nil {
			t.Errorf("%s: default options should attempt the dial, got %v", tc.addr, err)
		}
		if conn != nil {
			conn.Close()
		}
		if got := rec.dialled(); len(got) != 1 || got[0] != tc.target {
			t.Errorf("%s: dialled %v, want exactly [%s]", tc.addr, got, tc.target)
		}
		rec = &recorder{}
		deny := dialer(Options{DenyPrivate: true}, noLookup(t), rec.dial)
		_, err = deny(context.Background(), "tcp", tc.addr)
		var denied Denied
		if !errors.As(err, &denied) || denied.Class != ClassPrivate {
			t.Errorf("%s: under DenyPrivate err=%v, want class private", tc.addr, err)
		}
		if got := rec.dialled(); len(got) != 0 {
			t.Errorf("%s: under DenyPrivate dialled %v, want nothing", tc.addr, got)
		}
	}
}

// Security requirements 1 and 5: the dial target is the address that was
// checked, a denied answer is never dialled, a resolver error passes through
// as itself, and the resolver is asked for the family the transport wants.
func TestGuardDialsCheckedAddress(t *testing.T) {
	for _, answers := range [][]string{
		{"93.184.216.34", "127.0.0.1"},
		{"127.0.0.1", "93.184.216.34"},
	} {
		rec := &recorder{}
		open := dialer(Options{}, fixed(answers...), rec.dial)
		conn, err := open(context.Background(), "tcp", "upstream.example:80")
		if err != nil {
			t.Fatalf("answers %v: %v", answers, err)
		}
		conn.Close()
		if got := rec.dialled(); len(got) != 1 || got[0] != "93.184.216.34:80" {
			t.Fatalf("answers %v: dialled %v, want exactly [93.184.216.34:80]", answers, got)
		}
	}

	rec := &recorder{}
	open := dialer(Options{}, fixed("127.0.0.1"), rec.dial)
	_, err := open(context.Background(), "tcp", "upstream.example:80")
	var denied Denied
	if !errors.As(err, &denied) || denied.Class != ClassLoopback {
		t.Fatalf("loopback-only answer: err=%v, want class loopback", err)
	}
	if got := rec.dialled(); len(got) != 0 {
		t.Fatalf("loopback-only answer dialled %v", got)
	}

	// A trailing-dot name goes through the resolver like any other name.
	asked := ""
	network := ""
	open = dialer(Options{}, func(_ context.Context, net, host string) ([]netip.Addr, error) {
		asked, network = host, net
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}, rec.dial)
	if _, err := open(context.Background(), "tcp4", "localhost.:80"); err != nil {
		t.Fatal(err)
	}
	if asked != "localhost." || network != "ip4" {
		t.Fatalf("resolver asked for %q on %q, want localhost. on ip4", asked, network)
	}

	// A resolver failure is the resolver's error, not a refusal.
	want := &net.DNSError{Err: "no such host", Name: "nowhere.example", IsNotFound: true}
	open = dialer(Options{}, func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, want
	}, rec.dial)
	_, err = open(context.Background(), "tcp", "nowhere.example:80")
	var dns *net.DNSError
	if !errors.As(err, &dns) || err != want {
		t.Fatalf("resolver error came back as %v, want the *net.DNSError itself", err)
	}
	if errors.Is(err, ErrAddressDenied) {
		t.Fatal("a resolver error must not read as a refusal")
	}
}

// Security requirement 1 and the split deadline: after a connect failure the
// next permitted candidate is tried, a denied one never is, a stalled first
// attempt yields to the second inside its share of the deadline, and a
// cancelled context makes no attempt.
func TestGuardTriesRemainingPermitted(t *testing.T) {
	refuse := func(target string) error {
		if target == "93.184.216.34:80" {
			return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		}
		return nil
	}
	rec := &recorder{fail: refuse}
	open := dialer(Options{}, fixed("93.184.216.34", "93.184.216.35"), rec.dial)
	conn, err := open(context.Background(), "tcp", "upstream.example:80")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := rec.dialled(); len(got) != 2 || got[1] != "93.184.216.35:80" {
		t.Fatalf("dialled %v, want the second permitted candidate after the first failed", got)
	}

	rec = &recorder{fail: refuse}
	open = dialer(Options{}, fixed("93.184.216.34", "127.0.0.1"), rec.dial)
	_, err = open(context.Background(), "tcp", "upstream.example:80")
	if err == nil || errors.Is(err, ErrAddressDenied) {
		t.Fatalf("err=%v, want the connect failure itself: the loopback answer is not a fallback", err)
	}
	if got := rec.dialled(); len(got) != 1 {
		t.Fatalf("dialled %v, want only the permitted candidate", got)
	}

	// The first attempt blocks until its context ends; the second must be
	// reached within the first's share of a 1s deadline, not after it all.
	stall := &recorder{}
	stall.fail = func(target string) error {
		if target == "93.184.216.34:80" {
			return errors.New("stalled")
		}
		return nil
	}
	blocking := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "93.184.216.34:80" {
			<-ctx.Done()
			stall.mu.Lock()
			stall.targets = append(stall.targets, addr)
			stall.mu.Unlock()
			return nil, ctx.Err()
		}
		return stall.dial(ctx, network, addr)
	}
	open = dialer(Options{}, fixed("93.184.216.34", "93.184.216.35"), blocking)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	conn, err = open(ctx, "tcp", "upstream.example:80")
	if err != nil {
		t.Fatalf("second candidate should have connected: %v", err)
	}
	conn.Close()
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Fatalf("second candidate reached after %v; the first attempt kept the whole deadline", took)
	}

	rec = &recorder{}
	open = dialer(Options{}, fixed("93.184.216.34"), rec.dial)
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if _, err := open(done, "tcp", "upstream.example:80"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: err=%v", err)
	}
	if got := rec.dialled(); len(got) != 0 {
		t.Fatalf("cancelled context dialled %v", got)
	}
}

// AllowLoopback reopens loopback for both families, and only loopback; and
// the guarded dialer sits under Go's TLS verification, not beside it
// (security requirement 7).
func TestGuardAllowLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	// The servers' own clients carry the guarded transport: this package
	// builds no http.Client of its own, that construction is mcpclient's.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = Dialer(Options{AllowLoopback: true})
	plain := srv.Client()
	plain.Transport = tr
	resp, err := plain.Get(srv.URL)
	if err != nil {
		t.Fatalf("AllowLoopback should reach a loopback server: %v", err)
	}
	resp.Body.Close()

	rec := &recorder{}
	open := dialer(Options{AllowLoopback: true}, noLookup(t), rec.dial)
	conn, err := open(context.Background(), "tcp", "[::1]:1")
	if err != nil {
		t.Fatalf("AllowLoopback should reopen ::1 as well: %v", err)
	}
	conn.Close()
	for _, still := range []string{"[::]:1", "0.0.0.0:1", "224.0.0.1:1", "[fe80::1%lo]:1", "169.254.169.254:80"} {
		if _, err := open(context.Background(), "tcp", still); !errors.Is(err, ErrAddressDenied) {
			t.Errorf("%s: AllowLoopback must not reopen it, got %v", still, err)
		}
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tlsSrv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	trusted := http.DefaultTransport.(*http.Transport).Clone()
	trusted.DialContext = Dialer(Options{AllowLoopback: true})
	trusted.TLSClientConfig = &tls.Config{RootCAs: pool}
	tlsClient := tlsSrv.Client()
	tlsClient.Transport = trusted
	resp, err = tlsClient.Get(tlsSrv.URL)
	if err != nil {
		t.Fatalf("with the server's certificate trusted: %v", err)
	}
	resp.Body.Close()
	untrusted := http.DefaultTransport.(*http.Transport).Clone()
	untrusted.DialContext = Dialer(Options{AllowLoopback: true})
	tlsClient.Transport = untrusted
	if resp, err := tlsClient.Get(tlsSrv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("a self-signed certificate was accepted; the guarded dialer must leave verification on")
	}
}

// The production case: http.Transport detaches the dial context from the
// request, deadline included, so the guard's own budget has to bound the
// whole dial and each candidate gets a share of it. Two stalling candidates
// are both attempted, and the dial as a whole ends inside the budget.
func TestGuardBoundsDialWithoutDeadline(t *testing.T) {
	restore := dialBudget
	dialBudget = 600 * time.Millisecond
	t.Cleanup(func() { dialBudget = restore })

	rec := &recorder{}
	stalling := func(ctx context.Context, network, addr string) (net.Conn, error) {
		rec.mu.Lock()
		rec.targets = append(rec.targets, addr)
		rec.mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	open := dialer(Options{}, fixed("93.184.216.34", "93.184.216.35"), stalling)
	start := time.Now()
	_, err := open(context.Background(), "tcp", "upstream.example:80")
	took := time.Since(start)
	if err == nil {
		t.Fatal("two stalling candidates connected")
	}
	if got := rec.dialled(); len(got) != 2 {
		t.Fatalf("dialled %v, want both candidates on their share of the budget", got)
	}
	if took > 1200*time.Millisecond {
		t.Fatalf("the dial took %v; the budget of %v did not bound it", took, dialBudget)
	}
}

// Through a real *http.Transport, which hands DialContext a context with no
// deadline: a first candidate that never answers yields to the second inside
// the guard's budget, and the request succeeds.
func TestGuardThroughTransportFallsBack(t *testing.T) {
	restore := dialBudget
	dialBudget = 2 * time.Second
	t.Cleanup(func() { dialBudget = restore })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	var direct net.Dialer
	mixed := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "93.184.216.34:") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return direct.DialContext(ctx, network, addr)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dialer(Options{AllowLoopback: true}, fixed("93.184.216.34", "127.0.0.1"), mixed)
	client := srv.Client()
	client.Transport = tr
	client.Timeout = 5 * time.Second

	start := time.Now()
	resp, err := client.Get("http://upstream.example:" + port + "/")
	if err != nil {
		t.Fatalf("the second candidate should have answered: %v", err)
	}
	resp.Body.Close()
	if took := time.Since(start); took > 1800*time.Millisecond {
		t.Fatalf("took %v; the first candidate kept more than its share of the %v budget", took, dialBudget)
	}
}
