package webutil

import "testing"

func TestHostAllowedEmptyPublicURL(t *testing.T) {
	if !HostAllowed("anything", "", nil, false) {
		t.Fatal("empty publicURL must allow everything")
	}
	if !HostAllowed("", "", nil, false) {
		t.Fatal("empty publicURL allows empty seen")
	}
}

func TestHostAllowedEmptySeen(t *testing.T) {
	if HostAllowed("", "https://porymcp.example.com", nil, false) {
		t.Fatal("empty seen must not match a set publicURL")
	}
	if HostAllowed("   ", "https://porymcp.example.com", nil, true) {
		t.Fatal("whitespace seen is empty")
	}
}

func TestHostAllowedPortlessVsDefaultPort(t *testing.T) {
	public := "https://porymcp.example.com"
	if !HostAllowed("porymcp.example.com", public, nil, false) {
		t.Fatal("exact host")
	}
	if !HostAllowed("porymcp.example.com:443", public, nil, false) {
		t.Fatal("portless PUBLIC_URL should accept :443")
	}
	if !HostAllowed("porymcp.example.com:8080", public, nil, false) {
		t.Fatal("portless PUBLIC_URL ignores the request port")
	}
	if !HostAllowed("PORYMCP.EXAMPLE.COM", public, nil, false) {
		t.Fatal("hostname compare is case-insensitive")
	}
}

func TestHostAllowedExplicitPort(t *testing.T) {
	public := "https://porymcp.example.com:8443"
	if !HostAllowed("porymcp.example.com:8443", public, nil, false) {
		t.Fatal("same explicit port")
	}
	if HostAllowed("porymcp.example.com", public, nil, false) {
		t.Fatal("missing port must not match explicit PUBLIC_URL port")
	}
	if HostAllowed("porymcp.example.com:443", public, nil, false) {
		t.Fatal("wrong port")
	}

	// Explicit default port is equivalent to no port after stripping.
	if !HostAllowed("porymcp.example.com", "https://porymcp.example.com:443", nil, false) {
		t.Fatal(":443 on https PUBLIC_URL should strip to match a portless seen host")
	}
	if !HostAllowed("porymcp.example.com:443", "https://porymcp.example.com:443", nil, false) {
		t.Fatal("matching default https port")
	}
}

func TestHostAllowedLocalhostClass(t *testing.T) {
	public := "https://porymcp.example.com"
	if HostAllowed("localhost", public, nil, false) {
		t.Fatal("localhost must not bypass a public PUBLIC_URL")
	}
	if !HostAllowed("localhost", public, nil, true) {
		t.Fatal("allowLocalhost should accept localhost")
	}
	if !HostAllowed("127.0.0.1:8080", public, nil, true) {
		t.Fatal("allowLocalhost should accept 127.0.0.1")
	}
	if !HostAllowed("[::1]", public, nil, true) {
		t.Fatal("allowLocalhost should accept [::1]")
	}

	localPublic := "http://localhost:8080"
	if !HostAllowed("localhost", localPublic, nil, false) {
		t.Fatal("PUBLIC_URL in the localhost class allows localhost")
	}
	if !HostAllowed("127.0.0.1", localPublic, nil, false) {
		t.Fatal("127.0.0.1 is the same localhost class")
	}
	if !HostAllowed("[::1]:8080", localPublic, nil, false) {
		t.Fatal("::1 is the same localhost class")
	}
	if !HostAllowed("::1", "https://[::1]", nil, false) {
		t.Fatal("unbracketed ::1 should match PUBLIC_URL [::1]")
	}
}

func TestHostAllowedExtraHosts(t *testing.T) {
	public := "https://porymcp.example.com"
	extra := []string{"alt.example.com", "api.example.com:8443"}
	if !HostAllowed("alt.example.com", public, extra, false) {
		t.Fatal("extra host without port")
	}
	if !HostAllowed("alt.example.com:443", public, extra, false) {
		t.Fatal("portless extra host ignores request port")
	}
	if !HostAllowed("api.example.com:8443", public, extra, false) {
		t.Fatal("extra host with explicit port")
	}
	if HostAllowed("api.example.com", public, extra, false) {
		t.Fatal("extra host with explicit port requires that port")
	}
	if HostAllowed("other.example.com", public, extra, false) {
		t.Fatal("unknown extra host")
	}
	if !HostAllowed("api.example.com", "https://porymcp.example.com", []string{"api.example.com:443"}, false) {
		t.Fatal("extra :443 on https should strip to match a portless seen host")
	}
}

func TestHostAllowedIPv6(t *testing.T) {
	if !HostAllowed("[2001:db8::1]", "https://[2001:db8::1]", nil, false) {
		t.Fatal("IPv6 exact")
	}
	if !HostAllowed("[2001:db8::1]:443", "https://[2001:db8::1]", nil, false) {
		t.Fatal("IPv6 portless PUBLIC_URL vs :443")
	}
	if !HostAllowed("[::1]:443", "https://[::1]", nil, false) {
		t.Fatal("[::1] with default https port")
	}
	if HostAllowed("[2001:db8::2]", "https://[2001:db8::1]", nil, false) {
		t.Fatal("different IPv6")
	}
}

func TestExpectedHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https://porymcp.example.com", "porymcp.example.com"},
		{"https://porymcp.example.com:8443/path", "porymcp.example.com:8443"},
		{"https://[::1]:8080", "[::1]:8080"},
		{"https://[2001:db8::1]/", "[2001:db8::1]"},
	}
	for _, tc := range cases {
		if got := ExpectedHost(tc.in); got != tc.want {
			t.Fatalf("ExpectedHost(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
