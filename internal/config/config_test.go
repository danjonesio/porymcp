package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/crypto"
)

func TestLoadTrustedProxies(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Fatalf("proxies=%v", cfg.TrustedProxies)
	}
	if !cfg.TrustedProxies[0].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("10.0.0.0/8 should contain 10.1.2.3")
	}
	if cfg.TrustedProxyCount() != 2 {
		t.Fatalf("TrustedProxyCount=%d", cfg.TrustedProxyCount())
	}

	t.Setenv("TRUSTED_PROXIES", "not-a-cidr")
	if _, err := Load(); err == nil {
		t.Fatal("malformed TRUSTED_PROXIES should fail startup")
	}
}

func TestLoadTrustedProxiesDefaultEmpty(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("TRUSTED_PROXIES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("default should trust nobody, got %v", cfg.TrustedProxies)
	}
	if cfg.TrustedProxyCount() != 0 {
		t.Fatalf("TrustedProxyCount=%d", cfg.TrustedProxyCount())
	}
}

func TestLoadBoolFlags(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")

	cases := []struct {
		value string
		want  bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"Yes", true},
		{" yes ", true},
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"maybe", false},
	}
	for _, tc := range cases {
		t.Setenv("ALLOW_INSECURE_HTTP", tc.value)
		t.Setenv("ALLOW_LOCALHOST", tc.value)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("value %q: %v", tc.value, err)
		}
		if cfg.AllowInsecureHTTP != tc.want || cfg.AllowLocalhost != tc.want {
			t.Fatalf("value %q: insecure=%v localhost=%v want %v",
				tc.value, cfg.AllowInsecureHTTP, cfg.AllowLocalhost, tc.want)
		}
	}
}

func TestLoadExtraAllowedHosts(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("EXTRA_ALLOWED_HOSTS", "porymcp.example.com, porymcp.internal:8080, ,localhost")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"porymcp.example.com", "porymcp.internal:8080", "localhost"}
	if len(cfg.ExtraAllowedHosts) != len(want) {
		t.Fatalf("hosts=%v", cfg.ExtraAllowedHosts)
	}
	for i, h := range want {
		if cfg.ExtraAllowedHosts[i] != h {
			t.Fatalf("hosts[%d]=%q want %q", i, cfg.ExtraAllowedHosts[i], h)
		}
	}
}

func TestLoadExtraAllowedHostsRejectsURL(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("EXTRA_ALLOWED_HOSTS", "https://porymcp.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("EXTRA_ALLOWED_HOSTS with :// should fail startup")
	}
}

func TestLoadTLSOnlyOneFileFails(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")

	t.Setenv("TLS_CERT_FILE", "/tmp/cert.pem")
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TLS_CERT_FILE") || !strings.Contains(err.Error(), "TLS_KEY_FILE") {
		t.Fatalf("cert-only: want error naming both vars, got %v", err)
	}

	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "/tmp/key.pem")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TLS_CERT_FILE") || !strings.Contains(err.Error(), "TLS_KEY_FILE") {
		t.Fatalf("key-only: want error naming both vars, got %v", err)
	}
}

func TestLoadTLSBothFiles(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")
	certFile, keyFile := writeTempTLSPair(t)
	t.Setenv("TLS_CERT_FILE", certFile)
	t.Setenv("TLS_KEY_FILE", keyFile)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLSEnabled() {
		t.Fatal("TLSEnabled should be true when both files are set")
	}
	if cfg.TLSCertFile != certFile || cfg.TLSKeyFile != keyFile {
		t.Fatalf("paths cert=%q key=%q", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

func TestSchemeEnforced(t *testing.T) {
	cases := []struct {
		name          string
		publicURL     string
		allowInsecure bool
		want          bool
	}{
		{"http", "http://localhost:8080", false, false},
		{"https", "https://porymcp.example.com", false, true},
		{"https allow insecure", "https://porymcp.example.com", true, false},
		{"HTTPS uppercase scheme", "HTTPS://porymcp.example.com", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{PublicURL: tc.publicURL, AllowInsecureHTTP: tc.allowInsecure}
			if got := cfg.SchemeEnforced(); got != tc.want {
				t.Fatalf("SchemeEnforced()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestLogWarningsHTTPSWithoutTrust(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := &Config{PublicURL: "https://porymcp.example.com"}
	cfg.LogWarnings(log)
	out := buf.String()
	if !strings.Contains(out, "HTTPS") || !strings.Contains(out, "TRUSTED_PROXIES") {
		t.Fatalf("expected https-without-trust warning, got %q", out)
	}
	if strings.Contains(out, "10.0.0.0/8") || strings.Contains(out, "0.0.0.0/0") || strings.Contains(out, "::/0") {
		t.Fatalf("warning must not contain a CIDR string: %q", out)
	}
}

func writeTempTLSPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// TestEphemeralKeyRefusesNonEmptyDatabase covers PORM-52 acceptance criterion
// 2 and security requirement 9: a key generated at boot may not run against
// stored credentials, and an empty database still gets an ephemeral key.
func TestEphemeralKeyRefusesNonEmptyDatabase(t *testing.T) {
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("ENCRYPTION_KEY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EphemeralEnc {
		t.Fatal("expected an ephemeral key")
	}
	err = cfg.CheckEphemeralKey(3)
	if err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY is not set") || !strings.Contains(err.Error(), "3 stored credentials") {
		t.Fatalf("want a refusal naming the problem, got %v", err)
	}
	if err := cfg.CheckEphemeralKey(0); err != nil {
		t.Fatalf("an empty database must keep the ephemeral key: %v", err)
	}
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("ab", 32))
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.CheckEphemeralKey(3); err != nil {
		t.Fatalf("a real key is never refused: %v", err)
	}
}

// TestLoadPreviousKeys pins security requirement 10: ENCRYPTION_KEY_PREVIOUS
// is bounded, ordered, de-duplicated, loud on a bad entry and silent on an
// empty one.
func TestLoadPreviousKeys(t *testing.T) {
	const cur = "0000000000000000000000000000000000000000000000000000000000000001"
	const a = "0000000000000000000000000000000000000000000000000000000000000002"
	const b = "0000000000000000000000000000000000000000000000000000000000000003"
	bB64 := base64OfHex(t, b)
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("ENCRYPTION_KEY", cur)

	t.Run("parse, order, skip empties", func(t *testing.T) {
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", " , "+a+" ,,"+bB64+", ")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.EncryptionKeyPrevious) != 2 {
			t.Fatalf("got %d previous keys", len(cfg.EncryptionKeyPrevious))
		}
		if hexOf(cfg.EncryptionKeyPrevious[0]) != a || hexOf(cfg.EncryptionKeyPrevious[1]) != b {
			t.Fatal("order was not preserved, or base64 was not accepted")
		}
		k := cfg.Keyring()
		if k.Fingerprint() == "" || !k.Covers(fingerprintOfHex(t, a)) || !k.Covers(fingerprintOfHex(t, b)) {
			t.Fatal("Keyring does not carry the previous keys")
		}
	})
	t.Run("empty means unset", func(t *testing.T) {
		for _, v := range []string{"", " ", ",,"} {
			t.Setenv("ENCRYPTION_KEY_PREVIOUS", v)
			cfg, err := Load()
			if err != nil || len(cfg.EncryptionKeyPrevious) != 0 {
				t.Fatalf("%q: got (%v, %v)", v, cfg, err)
			}
		}
	})
	t.Run("raw form is refused with the hex conversion", func(t *testing.T) {
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", a+",correct-horse-battery-staple-x9!")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "entry 2") || !strings.Contains(err.Error(), "xxd -p") {
			t.Fatalf("want a position-named error naming the conversion, got %v", err)
		}
		if strings.Contains(err.Error(), "correct-horse") {
			t.Fatalf("the error echoes the value: %v", err)
		}
	})
	t.Run("garbage is refused by position", func(t *testing.T) {
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", "zz")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "entry 1") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cap", func(t *testing.T) {
		var six []string
		for i := 2; i <= 7; i++ {
			six = append(six, strings.Repeat("0", 63)+string(rune('0'+i)))
		}
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", strings.Join(six, ","))
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "entry 6") || !strings.Contains(err.Error(), "at most 5") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("set without ENCRYPTION_KEY is refused", func(t *testing.T) {
		t.Setenv("ENCRYPTION_KEY", "")
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", a)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY_PREVIOUS is set but ENCRYPTION_KEY is not") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("duplicates dropped, current key dropped with a warning", func(t *testing.T) {
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", a+","+a+","+cur)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("a redundant entry must not stop the boot: %v", err)
		}
		if len(cfg.EncryptionKeyPrevious) != 1 {
			t.Fatalf("got %d previous keys, want 1", len(cfg.EncryptionKeyPrevious))
		}
		var buf bytes.Buffer
		cfg.LogWarnings(slog.New(slog.NewTextHandler(&buf, nil)))
		out := buf.String()
		if !strings.Contains(out, "is the current key; ignoring it") || !strings.Contains(out, "entry=3") {
			t.Fatalf("want the ignored-entry warning, got %q", out)
		}
		if !strings.Contains(out, "previous_keys=1") || strings.Contains(out, "rekey") {
			t.Fatalf("want the count and no instruction, got %q", out)
		}
		if strings.Contains(out, a) || strings.Contains(out, cur) {
			t.Fatalf("a key value reached the log: %q", out)
		}
	})
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func base64OfHex(t *testing.T, h string) string {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func fingerprintOfHex(t *testing.T, h string) string {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.Fingerprint(raw)
}
