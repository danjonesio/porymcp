package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	KeyPrefix        = "pory_"
	keyRandomBytes   = 32
	DisplayPrefixLen = 12 // "pory_" + 7 hex chars shown in the dashboard

	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	ErrInvalidKey = errors.New("invalid virtual key")
	ErrMalformed  = errors.New("malformed key hash")
)

// GenerateKey returns a high-entropy virtual key, its argon2id hash, a SHA-256
// lookup digest (for O(1) auth), and a short display prefix.
func GenerateKey() (plaintext, hash, lookup, prefix string, err error) {
	raw := make([]byte, keyRandomBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", "", err
	}
	plaintext = KeyPrefix + hex.EncodeToString(raw)
	hash, err = HashKey(plaintext)
	if err != nil {
		return "", "", "", "", err
	}
	lookup = LookupDigest(plaintext)
	prefix = DisplayPrefix(plaintext)
	return plaintext, hash, lookup, prefix, nil
}

func DisplayPrefix(plaintext string) string {
	if len(plaintext) <= DisplayPrefixLen {
		return plaintext
	}
	return plaintext[:DisplayPrefixLen]
}

// LookupDigest is a keyed-independent SHA-256 of the plaintext. High-entropy
// keys make this safe for indexed lookup; argon2id remains the verifier.
func LookupDigest(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func HashKey(plaintext string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(plaintext), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

func VerifyKey(plaintext, encodedHash string) error {
	if !strings.HasPrefix(plaintext, KeyPrefix) || len(plaintext) < len(KeyPrefix)+16 {
		return ErrInvalidKey
	}
	salt, want, time, memory, threads, keyLen, err := parseHash(encodedHash)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(plaintext), salt, time, memory, threads, keyLen)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidKey
	}
	return nil
}

func parseHash(encoded string) (salt, hash []byte, time, memory uint32, threads uint8, keyLen uint32, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, 0, ErrMalformed
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, 0, 0, 0, 0, ErrMalformed
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return nil, nil, 0, 0, 0, 0, ErrMalformed
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, 0, ErrMalformed
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, 0, ErrMalformed
	}
	return salt, hash, time, memory, threads, uint32(len(hash)), nil
}
