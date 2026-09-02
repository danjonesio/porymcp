package webutil

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestParseForwardedHops(t *testing.T) {
	hops := parseForwardedHops([]string{
		`for=1.2.3.4;proto=https;host=client.example, for="[2001:db8::1]:4711";PROTO=HTTP;Host="[2001:db8::1]"`,
	})
	if len(hops) != 2 {
		t.Fatalf("len=%d", len(hops))
	}
	if hops[0].forAddr.String() != "1.2.3.4" || hops[0].proto != "https" || hops[0].host != "client.example" {
		t.Fatalf("hop0=%+v", hops[0])
	}
	if hops[1].forAddr.String() != "2001:db8::1" || hops[1].proto != "HTTP" || hops[1].host != "[2001:db8::1]" {
		t.Fatalf("hop1=%+v", hops[1])
	}
}

func TestParseForwardedHopsSkipsEmpty(t *testing.T) {
	if hops := parseForwardedHops([]string{"", "   ,  ;  "}); len(hops) != 0 {
		t.Fatalf("got %+v", hops)
	}
}

func TestRightmostToken(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https", "https"},
		{"http, https", "https"},
		{"porymcp.example.com,  porymcp:8080 ", "porymcp:8080"},
		{"a, , b,  ", "b"},
	}
	for _, tc := range cases {
		if got := rightmostToken(tc.in); got != tc.want {
			t.Fatalf("rightmostToken(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestSocketTrusted(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	inside := &http.Request{RemoteAddr: "10.0.0.1:443"}
	outside := &http.Request{RemoteAddr: "203.0.113.9:1234"}
	if socketTrusted(inside, nil) {
		t.Fatal("empty trusted must not trust anyone")
	}
	if socketTrusted(inside, []netip.Prefix{}) {
		t.Fatal("empty slice must not trust anyone")
	}
	if !socketTrusted(inside, trusted) {
		t.Fatal("10.0.0.1 should be trusted")
	}
	if socketTrusted(outside, trusted) {
		t.Fatal("public socket must not be trusted")
	}
	if socketTrusted(&http.Request{RemoteAddr: "not-an-ip"}, trusted) {
		t.Fatal("unparsable RemoteAddr is not trusted")
	}
}

func TestParseXForwardedForIPv6(t *testing.T) {
	hops := parseXForwardedFor(`2001:db8:cafe::17, "[2001:db8::5]:4711"`)
	if len(hops) != 2 {
		t.Fatalf("len=%d", len(hops))
	}
	if hops[0].String() != "2001:db8:cafe::17" || hops[1].String() != "2001:db8::5" {
		t.Fatalf("hops=%v", hops)
	}
}
