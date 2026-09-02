package webutil

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.0/8, 2001:db8::/32, 192.0.2.1 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[2].Contains(netip.MustParseAddr("192.0.2.1")) || got[2].Bits() != 32 {
		t.Fatalf("bare IPv4 should become /32, got %s", got[2])
	}
	if _, err := ParseTrustedProxies("not-a-cidr"); err == nil {
		t.Fatal("expected error")
	}
	empty, err := ParseTrustedProxies("")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty: %v %v", empty, err)
	}
}

func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("untrusted socket ignores X-Forwarded-For", func(t *testing.T) {
		r := &http.Request{RemoteAddr: "203.0.113.9:1234", Header: http.Header{}}
		r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5")
		if got := ClientIP(r, nil); got != "203.0.113.9" {
			t.Fatalf("nil trusted: got %q", got)
		}
		if got := ClientIP(r, trusted); got != "203.0.113.9" {
			t.Fatalf("socket outside trusted: got %q", got)
		}
	})

	t.Run("trusted socket uses rightmost untrusted hop", func(t *testing.T) {
		r := &http.Request{RemoteAddr: "10.0.0.1:443", Header: http.Header{}}
		r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5")
		if got := ClientIP(r, trusted); got != "1.2.3.4" {
			t.Fatalf("got %q, want 1.2.3.4", got)
		}
	})

	t.Run("Forwarded is preferred over X-Forwarded-For", func(t *testing.T) {
		r := &http.Request{RemoteAddr: "10.0.0.1:443", Header: http.Header{}}
		r.Header.Set("X-Forwarded-For", "9.9.9.9")
		r.Header.Set("Forwarded", `for=1.2.3.4;proto=https, for=10.0.0.5`)
		if got := ClientIP(r, trusted); got != "1.2.3.4" {
			t.Fatalf("got %q, want 1.2.3.4", got)
		}
	})

	t.Run("IPv6 socket and hop", func(t *testing.T) {
		v6, err := ParseTrustedProxies("2001:db8::/32")
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{RemoteAddr: "[2001:db8::1]:443", Header: http.Header{}}
		r.Header.Set("X-Forwarded-For", "2001:db8:cafe::17, 2001:db8::5")
		if got := ClientIP(r, v6); got != "2001:db8:cafe::17" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("untrusted IPv6 socket ignores X-Forwarded-For", func(t *testing.T) {
		v6, err := ParseTrustedProxies("2001:db8::/32")
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{RemoteAddr: "[2001:db9::9]:443", Header: http.Header{}}
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		if got := ClientIP(r, v6); got != "2001:db9::9" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("multi-value X-Forwarded-For uses the last line", func(t *testing.T) {
		r := &http.Request{RemoteAddr: "10.0.0.1:443", Header: http.Header{}}
		r.Header.Add("X-Forwarded-For", "9.9.9.9")
		r.Header.Add("X-Forwarded-For", "1.2.3.4, 10.0.0.5")
		if got := ClientIP(r, trusted); got != "1.2.3.4" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("trusted socket with no forwarding headers", func(t *testing.T) {
		r := &http.Request{RemoteAddr: "10.0.0.1:443", Header: http.Header{}}
		if got := ClientIP(r, trusted); got != "10.0.0.1" {
			t.Fatalf("got %q", got)
		}
	})
}
