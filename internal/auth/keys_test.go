package auth

import "testing"

func TestGenerateAndVerifyKey(t *testing.T) {
	plain, hash, lookup, prefix, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrefix(plain, KeyPrefix) {
		t.Fatalf("key %q missing prefix", plain)
	}
	if lookup != LookupDigest(plain) {
		t.Fatal("lookup digest mismatch")
	}
	if prefix != DisplayPrefix(plain) {
		t.Fatal("prefix mismatch")
	}
	if err := VerifyKey(plain, hash); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKey(plain+"x", hash); err == nil {
		t.Fatal("expected verification to fail for a mutated key")
	}
	if err := VerifyKey("pory_deadbeef", hash); err == nil {
		t.Fatal("expected verification to fail for a different key")
	}
}

func TestVerifyRejectsPlaintextSecretsPattern(t *testing.T) {
	if err := VerifyKey("not-a-key", "$argon2id$v=19$m=1,t=1,p=1$YQ$YQ"); err == nil {
		t.Fatal("expected invalid key")
	}
}

func TestHashIsNotPlaintext(t *testing.T) {
	plain, hash, _, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if hash == plain {
		t.Fatal("hash must not equal plaintext")
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
