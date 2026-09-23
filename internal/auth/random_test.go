package auth

import (
	"regexp"
	"testing"
)

// TestRandomToken pins the shape the OAuth state and PKCE verifier rely on:
// 32 bytes give 43 unpadded base64url characters, the alphabet is URL-safe,
// and two calls differ.
func TestRandomToken(t *testing.T) {
	a := RandomToken(32)
	b := RandomToken(32)
	if len(a) != 43 || len(b) != 43 {
		t.Fatalf("length: %d and %d, want 43", len(a), len(b))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(a) {
		t.Fatalf("alphabet: %q", a)
	}
	if a == b {
		t.Fatal("two tokens are equal")
	}
}
