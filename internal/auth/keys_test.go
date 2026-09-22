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

// TestVerifyLookup covers PORM-44 acceptance criterion 1 and security
// requirement 1: the presented token is hashed and compared in constant time,
// and the stored digest itself, bare or behind the prefix, is not a key.
func TestVerifyLookup(t *testing.T) {
	plain, _, lookup, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	last := plain[len(plain)-1]
	flipped := "0"
	if last == '0' {
		flipped = "1"
	}
	alteredLookup := "0" + lookup[1:]
	if lookup[0] == '0' {
		alteredLookup = "1" + lookup[1:]
	}
	cases := []struct {
		name   string
		plain  string
		stored string
		ok     bool
	}{
		{"valid key", plain, lookup, true},
		{"wrong key", other, lookup, false},
		{"wrong prefix", "pory-" + plain[len(KeyPrefix):], lookup, false},
		{"truncated key", plain[:len(plain)-1], lookup, false},
		{"one character too long", plain + "x", lookup, false},
		{"altered last character", plain[:len(plain)-1] + flipped, lookup, false},
		{"bare digest as the key", lookup, lookup, false},
		{"prefixed digest as the key", KeyPrefix + lookup, lookup, false},
		{"empty stored digest", plain, "", false},
		{"altered stored digest", plain, alteredLookup, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyLookup(c.plain, c.stored)
			if c.ok && err != nil {
				t.Fatalf("VerifyLookup returned %v, want nil", err)
			}
			if !c.ok && err != ErrInvalidKey {
				t.Fatalf("VerifyLookup returned %v, want ErrInvalidKey", err)
			}
		})
	}
	if len(KeyPrefix+lookup) != keyLen {
		t.Fatalf("the prefixed digest is %d bytes, not %d: the case would not reach the compare", len(KeyPrefix+lookup), keyLen)
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
