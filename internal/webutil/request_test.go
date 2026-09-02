package webutil

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestRequestHostAndSchemeUntrustedIgnoresHeaders(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "203.0.113.9:1234",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	r.Header.Set("X-Forwarded-Host", "porymcp.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https;host=evil.example`)

	if got := RequestHost(r, nil); got != "porymcp:8080" {
		t.Fatalf("nil trusted host=%q", got)
	}
	if got := RequestHost(r, trusted); got != "porymcp:8080" {
		t.Fatalf("untrusted socket host=%q", got)
	}
	if got := RequestScheme(r, trusted); got != "http" {
		t.Fatalf("untrusted socket scheme=%q", got)
	}
	r.TLS = &tls.ConnectionState{}
	if got := RequestScheme(r, trusted); got != "https" {
		t.Fatalf("untrusted TLS scheme=%q", got)
	}
}

func TestRequestHostTrustedXForwardedHost(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	r.Header.Set("X-Forwarded-Host", "porymcp.example.com")
	if got := RequestHost(r, trusted); got != "porymcp.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequestRightmostForwardedProtoHost(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	// Leftmost is the original client (spoofable). The trusted edge appended
	// proto=http and the public host; those must win.
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https;host=client.example, for=10.0.0.5;proto=http;host=porymcp.example.com`)
	if got := RequestScheme(r, trusted); got != "http" {
		t.Fatalf("scheme=%q, client-spoofed https must not win", got)
	}
	if got := RequestHost(r, trusted); got != "porymcp.example.com" {
		t.Fatalf("host=%q", got)
	}
}

func TestRequestForwardedWithoutProtoFallsBackToXFP(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	r.Header.Set("Forwarded", `for=1.2.3.4;host=porymcp.example.com`)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := RequestScheme(r, trusted); got != "https" {
		t.Fatalf("scheme=%q, want X-Forwarded-Proto fallback", got)
	}
	if got := RequestHost(r, trusted); got != "porymcp.example.com" {
		t.Fatalf("host=%q", got)
	}
}

func TestRequestForwardedWithoutHostFallsBackToXFH(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https`)
	r.Header.Set("X-Forwarded-Host", "edge.example.com, porymcp.example.com")
	if got := RequestHost(r, trusted); got != "porymcp.example.com" {
		t.Fatalf("host=%q, want rightmost X-Forwarded-Host", got)
	}
}

func TestRequestInvalidProtoFallsThrough(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Header:     http.Header{},
	}
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=ftp`)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := RequestScheme(r, trusted); got != "https" {
		t.Fatalf("scheme=%q, invalid proto should fall through", got)
	}
}

func TestRequestIPv6Host(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "[2001:db8::1]:8080",
		Header:     http.Header{},
	}
	if got := RequestHost(r, trusted); got != "[2001:db8::1]:8080" {
		t.Fatalf("no header: got %q", got)
	}
	r.Header.Set("X-Forwarded-Host", "[2001:db8::2], [2001:db8::3]:443")
	if got := RequestHost(r, trusted); got != "[2001:db8::3]:443" {
		t.Fatalf("xff host=%q", got)
	}

	untrusted := &http.Request{
		RemoteAddr: "203.0.113.9:9",
		Host:       "[2001:db8::1]:8080",
		Header:     http.Header{},
	}
	untrusted.Header.Set("X-Forwarded-Host", "[2001:db8::9]")
	if got := RequestHost(untrusted, trusted); got != "[2001:db8::1]:8080" {
		t.Fatalf("untrusted IPv6 host=%q", got)
	}
}

func TestRequestForwardedPreferredOverXForwarded(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	r.Header.Set("X-Forwarded-Host", "xff.example.com")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https;host=fwd.example.com`)
	if got := RequestHost(r, trusted); got != "fwd.example.com" {
		t.Fatalf("host=%q", got)
	}
	if got := RequestScheme(r, trusted); got != "https" {
		t.Fatalf("scheme=%q", got)
	}
}

func TestRequestMultiValueXForwardedHeaders(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	// A hop that adds a header instead of comma-appending leaves the
	// client value on the first line. Get() would see only that line.
	r.Header.Add("X-Forwarded-Host", "client.example")
	r.Header.Add("X-Forwarded-Host", "porymcp.example.com")
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Proto", "https")
	if got := RequestHost(r, trusted); got != "porymcp.example.com" {
		t.Fatalf("host=%q", got)
	}
	if got := RequestScheme(r, trusted); got != "https" {
		t.Fatalf("scheme=%q", got)
	}
}

func TestRequestEdgeHopWithoutHostFallsToXFHNotClientHop(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		RemoteAddr: "10.0.0.1:443",
		Host:       "porymcp:8080",
		Header:     http.Header{},
	}
	// Client wrote host=; the trusted edge appended only for=/proto=.
	// Walking left would trust the client host.
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https;host=evil.example, for=10.0.0.5;proto=https`)
	r.Header.Set("X-Forwarded-Host", "porymcp.example.com")
	if got := RequestHost(r, trusted); got != "porymcp.example.com" {
		t.Fatalf("host=%q, client Forwarded host must not win", got)
	}
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https, for=10.0.0.5`)
	r.Header.Set("X-Forwarded-Proto", "http")
	if got := RequestScheme(r, trusted); got != "http" {
		t.Fatalf("scheme=%q, client Forwarded proto must not win", got)
	}
}
