package config

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/webutil"
)

type Config struct {
	ListenAddr    string
	AdminAPIKey   string
	EncryptionKey []byte
	DatabaseURL   string
	PublicURL     string
	LogLevel      string
	DataDir       string
	// TrustedProxies are CIDRs whose socket address may present Forwarded /
	// X-Forwarded-For, and whose forwarded host/scheme are trusted for
	// request resolution (PORM-50). Empty means trust nobody, the default,
	// and what the admin-auth limiter keys on until an operator opts in.
	TrustedProxies []netip.Prefix
	// TLSCertFile and TLSKeyFile enable built-in TLS when both are set.
	TLSCertFile string
	TLSKeyFile  string
	// AllowInsecureHTTP disables scheme enforcement when PUBLIC_URL is https.
	AllowInsecureHTTP bool
	// AllowLocalhost keeps the localhost Host allowance when PUBLIC_URL is
	// not itself localhost.
	AllowLocalhost bool
	// ExtraAllowedHosts are additional Host values accepted besides PUBLIC_URL.
	ExtraAllowedHosts []string
	// EncryptionKeyPrevious holds ENCRYPTION_KEY_PREVIOUS, oldest last: keys a
	// stored credential may still be sealed under during a rotation. Decrypt
	// only, nothing is ever sealed under one. At most maxPreviousKeys, 64-hex
	// or base64 only (a raw 32-byte value cannot survive the comma split),
	// de-duplicated, and never the current key. Remove after `porymcp rekey`.
	EncryptionKeyPrevious [][]byte
	// previousIgnored records the 1-based positions of ENCRYPTION_KEY_PREVIOUS
	// entries that named the current key and were dropped, for LogWarnings.
	previousIgnored []int
	// EphemeralEnc is true when ENCRYPTION_KEY was generated at boot.
	EphemeralEnc bool
	// GeneratedAdmin is true when ADMIN_API_KEY was generated at boot.
	GeneratedAdmin bool
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        env("LISTEN_ADDR", ":8080"),
		PublicURL:         strings.TrimRight(env("PUBLIC_URL", "http://localhost:8080"), "/"),
		LogLevel:          env("LOG_LEVEL", "info"),
		DataDir:           env("DATA_DIR", "./data"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		TLSCertFile:       strings.TrimSpace(os.Getenv("TLS_CERT_FILE")),
		TLSKeyFile:        strings.TrimSpace(os.Getenv("TLS_KEY_FILE")),
		AllowInsecureHTTP: envTruthy("ALLOW_INSECURE_HTTP"),
		AllowLocalhost:    envTruthy("ALLOW_LOCALHOST"),
	}

	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = filepath.Join(cfg.DataDir, "porymcp.db")
	}

	if key := os.Getenv("ADMIN_API_KEY"); key != "" {
		cfg.AdminAPIKey = key
	} else {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		cfg.AdminAPIKey = "pory_admin_" + hex.EncodeToString(raw)
		cfg.GeneratedAdmin = true
	}

	if raw := os.Getenv("ENCRYPTION_KEY"); raw != "" {
		key, err := crypto.ParseKey(raw)
		if err != nil {
			return nil, fmt.Errorf("ENCRYPTION_KEY: %w", err)
		}
		cfg.EncryptionKey = key
	} else {
		key, err := crypto.RandomKey()
		if err != nil {
			return nil, err
		}
		cfg.EncryptionKey = key
		cfg.EphemeralEnc = true
	}

	if err := cfg.parsePreviousKeys(os.Getenv("ENCRYPTION_KEY_PREVIOUS")); err != nil {
		return nil, err
	}

	if raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")); raw != "" {
		proxies, err := webutil.ParseTrustedProxies(raw)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %w", err)
		}
		cfg.TrustedProxies = proxies
	}

	hosts, err := parseExtraAllowedHosts(os.Getenv("EXTRA_ALLOWED_HOSTS"))
	if err != nil {
		return nil, err
	}
	cfg.ExtraAllowedHosts = hosts

	if err := cfg.validateTLSPair(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) LogWarnings(log *slog.Logger) {
	if c.GeneratedAdmin {
		log.Warn("ADMIN_API_KEY was not set; generated a random admin key for this process only", "admin_api_key", c.AdminAPIKey)
	}
	if c.EphemeralEnc {
		log.Warn("ENCRYPTION_KEY was not set; generated an ephemeral key. Upstream secrets will not survive a restart.")
	}
	// The fact only. Whether `porymcp rekey` still needs running is known only
	// after the store is open, and the boot verdict in cmd/server says so.
	for _, n := range c.previousIgnored {
		log.Warn("ENCRYPTION_KEY_PREVIOUS entry is the current key; ignoring it", "entry", n)
	}
	if n := len(c.EncryptionKeyPrevious); n > 0 {
		log.Warn("ENCRYPTION_KEY_PREVIOUS is set; previous keys are accepted for decryption only", "previous_keys", n)
	}
	if c.publicURLIsHTTPS() && !c.TLSEnabled() && len(c.TrustedProxies) == 0 {
		log.Warn("HTTPS is required by PUBLIC_URL but neither built-in TLS nor TRUSTED_PROXIES is set; scheme enforcement will reject non-loopback HTTP")
	}
}

// maxPreviousKeys bounds ENCRYPTION_KEY_PREVIOUS: each entry is one more
// AES-GCM attempt on a legacy blob that the current key did not open.
const maxPreviousKeys = 5

// Keyring is the process's decryption material: the current key plus every
// previous key, in the order given.
func (c *Config) Keyring() crypto.Keyring {
	return crypto.NewKeyring(c.EncryptionKey, c.EncryptionKeyPrevious)
}

// CheckEphemeralKey refuses to run a key generated at startup against a
// database that already holds stored credentials: every one of them would be
// unreadable, and the operator has to be told before the proxy starts calling
// upstreams naked. storedCredentials is the count of rows that need a
// credential and hold a blob (credential.Report.Credentials); an empty
// database, or one of auth_type none upstreams, keeps the ephemeral-key path.
func (c *Config) CheckEphemeralKey(storedCredentials int) error {
	if !c.EphemeralEnc || storedCredentials <= 0 {
		return nil
	}
	return fmt.Errorf("ENCRYPTION_KEY is not set and this database holds %d stored credentials; set ENCRYPTION_KEY to the key they were encrypted with, or start against an empty database", storedCredentials)
}

// parsePreviousKeys reads ENCRYPTION_KEY_PREVIOUS: split on commas, trimmed,
// empties skipped (so the compose pass-through `${ENCRYPTION_KEY_PREVIOUS:-}`
// means unset). Errors name the entry's position, never its value.
func (c *Config) parsePreviousKeys(raw string) error {
	var entries []string
	for _, part := range strings.Split(raw, ",") {
		if e := strings.TrimSpace(part); e != "" {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return nil
	}
	if c.EphemeralEnc {
		// A key generated at boot can never be the successor to anything.
		return fmt.Errorf("ENCRYPTION_KEY_PREVIOUS is set but ENCRYPTION_KEY is not; set the current key too")
	}
	current := crypto.Fingerprint(c.EncryptionKey)
	seen := map[string]bool{}
	for i, entry := range entries {
		n := i + 1
		key, err := crypto.ParseKey(entry)
		// ParseKey's last resort accepts any 32-byte string as the key
		// itself; that form has no alphabet and cannot be listed here.
		if err != nil || string(key) == entry {
			return fmt.Errorf("ENCRYPTION_KEY_PREVIOUS: entry %d: must be 64 hex characters or base64; convert a raw key with: printf %%s \"$KEY\" | xxd -p", n)
		}
		fp := crypto.Fingerprint(key)
		if fp == current {
			c.previousIgnored = append(c.previousIgnored, n)
			continue
		}
		if seen[fp] {
			continue
		}
		if len(c.EncryptionKeyPrevious) == maxPreviousKeys {
			return fmt.Errorf("ENCRYPTION_KEY_PREVIOUS: entry %d: at most %d previous keys", n, maxPreviousKeys)
		}
		seen[fp] = true
		c.EncryptionKeyPrevious = append(c.EncryptionKeyPrevious, key)
	}
	return nil
}

// SchemeEnforced is true when PublicURL is https and AllowInsecureHTTP is off.
func (c *Config) SchemeEnforced() bool {
	return c.publicURLIsHTTPS() && !c.AllowInsecureHTTP
}

// TLSEnabled is true when both certificate and key paths are set.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// TrustedProxyCount is the number of configured trusted CIDRs. Callers must
// not log or return the prefixes themselves.
func (c *Config) TrustedProxyCount() int {
	return len(c.TrustedProxies)
}

func (c *Config) publicURLIsHTTPS() bool {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}

func (c *Config) validateTLSPair() error {
	certSet := c.TLSCertFile != ""
	keySet := c.TLSKeyFile != ""
	if certSet != keySet {
		return fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must both be set or both empty")
	}
	if !certSet {
		return nil
	}
	if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
		return fmt.Errorf("TLS_CERT_FILE/TLS_KEY_FILE: %w", err)
	}
	return nil
}

func parseExtraAllowedHosts(raw string) ([]string, error) {
	var hosts []string
	for _, part := range strings.Split(raw, ",") {
		host := strings.TrimSpace(part)
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") || strings.Contains(host, "/") || strings.ContainsAny(host, " \t") {
			return nil, fmt.Errorf("EXTRA_ALLOWED_HOSTS: %q is not a host (no scheme or path)", host)
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envTruthy(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}
