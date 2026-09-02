package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// v1Prefix marks the ciphertext form written since PORM-52:
//
//	v1:<fingerprint>:<base64(nonce || ciphertext)>
//
// The fingerprint names the key that sealed the value and is also the
// AES-GCM additional authenticated data, so a value cannot even be attempted
// under a key that does not match its label. Standard base64 has no ':', so a
// legacy (unprefixed) value can never be mistaken for a v1 one.
const v1Prefix = "v1:"

// fingerprintLabel domain-separates the fingerprint from a plain hash of the
// key: a fingerprint is useless against anything but PoryMCP's own labels.
const fingerprintLabel = "porymcp-key-fp"

// fingerprintLen is the number of hex characters kept (64 bits).
const fingerprintLen = 16

// ErrUnknownKey reports a v1 ciphertext whose fingerprint names a key this
// process does not hold — the distinguishable "wrong key" outcome, as opposed
// to ErrInvalidCipher for bytes that no key would open. The text carries no
// fingerprint: it can reach an audit row, and audit error_message is not
// redacted.
var ErrUnknownKey = errors.New("ciphertext was sealed under a key this process does not hold")

// Keyring is the process's decryption material: the key new ciphertexts are
// sealed under, plus ENCRYPTION_KEY_PREVIOUS in the order it was given
// (oldest last). Previous keys decrypt only; nothing is ever sealed under one.
type Keyring struct {
	current  []byte
	previous [][]byte
}

// NewKeyring builds a keyring. previous may be nil.
func NewKeyring(current []byte, previous [][]byte) Keyring {
	prev := make([][]byte, 0, len(previous))
	for _, p := range previous {
		if len(p) > 0 {
			prev = append(prev, p)
		}
	}
	return Keyring{current: current, previous: prev}
}

// Fingerprint is the fingerprint of the current key, or "" when there is none.
func (k Keyring) Fingerprint() string {
	if len(k.current) == 0 {
		return ""
	}
	return Fingerprint(k.current)
}

// Covers reports whether fp names the current key or any previous key.
func (k Keyring) Covers(fp string) bool {
	_, found := k.byFingerprint(fp)
	return found
}

// Seal encrypts plaintext under the current key and always writes the v1 form.
func (k Keyring) Seal(plaintext []byte) (string, error) {
	fp := k.Fingerprint()
	sealed, err := seal(k.current, plaintext, []byte(fp))
	if err != nil {
		return "", err
	}
	return v1Prefix + fp + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts either form and reports the fingerprint of the key that
// opened it, so a caller can tell a value sealed under a previous key from one
// sealed under the current key.
//
// A v1 value is parsed strictly and opened only under the key its fingerprint
// names: an unknown fingerprint is ErrUnknownKey, anything else that fails is
// ErrInvalidCipher, and a v1 value never falls back to the legacy path. A
// legacy (unprefixed) value is tried under the current key and then each
// previous key with nil AAD, and is accepted indefinitely: an operator who
// never runs `porymcp rekey` is never broken.
func (k Keyring) Open(encoded string) ([]byte, string, error) {
	if strings.HasPrefix(encoded, v1Prefix) {
		fp, body, ok := strings.Cut(strings.TrimPrefix(encoded, v1Prefix), ":")
		if !ok || !IsFingerprint(fp) {
			return nil, "", ErrInvalidCipher
		}
		key, found := k.byFingerprint(fp)
		if !found {
			return nil, "", ErrUnknownKey
		}
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, "", ErrInvalidCipher
		}
		plain, err := open(key, raw, []byte(fp))
		if err != nil {
			return nil, "", ErrInvalidCipher
		}
		return plain, fp, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", ErrInvalidCipher
	}
	for _, key := range k.all() {
		if plain, err := open(key, raw, nil); err == nil {
			return plain, Fingerprint(key), nil
		}
	}
	return nil, "", ErrInvalidCipher
}

// byFingerprint selects the key fp names — the current key first, then the
// previous keys in the order they were given.
func (k Keyring) byFingerprint(fp string) ([]byte, bool) {
	for _, key := range k.all() {
		if Fingerprint(key) == fp {
			return key, true
		}
	}
	return nil, false
}

// all lists the keys in decryption order: current, then previous.
func (k Keyring) all() [][]byte {
	keys := make([][]byte, 0, 1+len(k.previous))
	if len(k.current) > 0 {
		keys = append(keys, k.current)
	}
	return append(keys, k.previous...)
}

// Fingerprint is hex(sha256("porymcp-key-fp" || key))[:16]: one-way and
// domain-separated, so it is safe to store beside the ciphertext it labels and
// to print in a log line. It stores no key material; for a key that is 32
// random bytes it reveals nothing (for a passphrase it is an offline oracle,
// which is why the docs require a random key).
func Fingerprint(key []byte) string {
	msg := make([]byte, 0, len(fingerprintLabel)+len(key))
	msg = append(msg, fingerprintLabel...)
	msg = append(msg, key...)
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:])[:fingerprintLen]
}

// IsV1 reports whether encoded is in the v1 form (as opposed to a legacy
// unprefixed value). `porymcp rekey` uses it to leave a v1 value under the
// current key alone while always rewriting a legacy one, which has no AAD.
func IsV1(encoded string) bool {
	return strings.HasPrefix(encoded, v1Prefix)
}

// IsFingerprint reports whether s has the exact shape Fingerprint produces:
// sixteen lowercase hex characters. It gates every fingerprint read from the
// database or a ciphertext before the value is compared or logged.
func IsFingerprint(s string) bool {
	if len(s) != fingerprintLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
