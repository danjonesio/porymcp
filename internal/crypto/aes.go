package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

var (
	ErrInvalidKey    = errors.New("encryption key must be 32 bytes (64 hex chars or base64)")
	ErrInvalidCipher = errors.New("ciphertext is not valid AES-256-GCM")
)

// ParseKey accepts a 32-byte AES key as hex or standard/raw base64.
func ParseKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, ErrInvalidKey
	}
	if len(raw) == 64 {
		key, err := hex.DecodeString(raw)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, ErrInvalidKey
}

func RandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptLegacy seals plaintext in the pre-PORM-52 form: base64(nonce ||
// ciphertext), no version prefix, no additional authenticated data. It exists
// so tests can seed the rows a database written by an older build holds;
// nothing in production may call it — every production write goes through
// Keyring.Seal, which always writes the v1 form. Keyring.Open reads both.
func EncryptLegacy(key, plaintext []byte) (string, error) {
	sealed, err := seal(key, plaintext, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// seal is AES-256-GCM with a fresh random 96-bit nonce per call, returning
// nonce || ciphertext. aad is nil for the legacy form and the key fingerprint
// for v1; it is never derived from the row or the fingerprint as a nonce.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// open reverses seal. Every authentication failure is ErrInvalidCipher; the
// underlying error is never returned because it could quote input.
func open(key, raw, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, ErrInvalidCipher
	}
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], aad)
	if err != nil {
		return nil, ErrInvalidCipher
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
