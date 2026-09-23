package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomToken returns n bytes from crypto/rand as unpadded base64url. It is
// the one source for the OAuth state value and the PKCE verifier (RFC 7636
// wants that alphabet; 32 bytes give 43 characters). A failure of the
// system's random source is not recoverable, so it panics like GenerateKey's
// callers would on an empty key.
func RandomToken(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic("auth.RandomToken: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
