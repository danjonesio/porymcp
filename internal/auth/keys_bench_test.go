package auth

import "testing"

// BenchmarkVerifyKey measures what one verification of a virtual key costs
// (PORM-44, acceptance criterion 2). It runs against the argon2id verifier the
// proxy has used on every call, and its output is the baseline the pull
// request quotes before the SHA-256 verifier replaces it. Nothing here runs
// under make test.
func BenchmarkVerifyKey(b *testing.B) {
	plain, hash, _, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyKey(plain, hash); err != nil {
			b.Fatal(err)
		}
	}
}
