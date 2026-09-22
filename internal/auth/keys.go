package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	KeyPrefix        = "pory_"
	keyRandomBytes   = 32
	DisplayPrefixLen = 12 // "pory_" + 7 hex chars shown in the dashboard

	// keyLen is the length of every issued key: the prefix plus 32 random
	// bytes as hex. The format has not changed since the first commit.
	keyLen = len(KeyPrefix) + 2*keyRandomBytes
)

var ErrInvalidKey = errors.New("invalid virtual key")

// GenerateKey returns a high-entropy virtual key, its SHA-256 lookup digest,
// which is also what VerifyLookup checks, and a short display prefix.
func GenerateKey() (plaintext, lookup, prefix string, err error) {
	raw := make([]byte, keyRandomBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", err
	}
	plaintext = KeyPrefix + hex.EncodeToString(raw)
	lookup = LookupDigest(plaintext)
	prefix = DisplayPrefix(plaintext)
	return plaintext, lookup, prefix, nil
}

func DisplayPrefix(plaintext string) string {
	if len(plaintext) <= DisplayPrefixLen {
		return plaintext
	}
	return plaintext[:DisplayPrefixLen]
}

// LookupDigest is the unkeyed SHA-256 of the plaintext, hex encoded. It is
// both the index the proxy finds a key by and the value VerifyLookup checks,
// which is safe only while keys carry at least 128 random bits
// (docs/07-security.md).
func LookupDigest(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// VerifyLookup reports whether plaintext is the key whose SHA-256 digest is
// storedLookup. Keys carry 256 random bits, so a fast hash is the right
// verifier; docs/07-security.md states the precondition. The presented
// token is always hashed: no part of it is ever compared to the stored
// digest raw.
func VerifyLookup(plaintext, storedLookup string) error {
	if !strings.HasPrefix(plaintext, KeyPrefix) || len(plaintext) != keyLen {
		return ErrInvalidKey
	}
	if subtle.ConstantTimeCompare([]byte(LookupDigest(plaintext)), []byte(storedLookup)) != 1 {
		return ErrInvalidKey
	}
	return nil
}
