package auth

import "testing"

// BenchmarkVerifyLookup measures what one verification of a virtual key costs
// (PORM-44, acceptance criterion 2): one SHA-256 of the presented token and
// one constant-time comparison. The verifier it replaced was
// benchmarked the same way before it went (commit a7071f4); the pull request
// quotes both. Nothing here runs under make test.
func BenchmarkVerifyLookup(b *testing.B) {
	plain, lookup, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyLookup(plain, lookup); err != nil {
			b.Fatal(err)
		}
	}
}
