package auth

import "testing"

func TestGenerateKey(t *testing.T) {
	plain, lookup, prefix, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrefix(plain, KeyPrefix) {
		t.Fatalf("key %q missing prefix", plain)
	}
	if len(plain) != keyLen {
		t.Fatalf("key is %d bytes, want %d", len(plain), keyLen)
	}
	if lookup != LookupDigest(plain) || len(lookup) != 64 {
		t.Fatalf("lookup digest %q is not the 64-hex SHA-256 of the key", lookup)
	}
	if prefix != DisplayPrefix(plain) || len(prefix) != DisplayPrefixLen {
		t.Fatalf("prefix %q is not the %d-character display prefix", prefix, DisplayPrefixLen)
	}
}

func TestLookupIsNotPlaintext(t *testing.T) {
	plain, lookup, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if lookup == plain || hasPrefix(lookup, KeyPrefix) {
		t.Fatal("the stored digest must not be the key or carry its prefix")
	}
}

// TestVerifyLookup covers PORM-44 acceptance criterion 1 and security
// requirement 1: the presented token is hashed and compared in constant time,
// and the stored digest itself, bare or behind the prefix, is not a key.
func TestVerifyLookup(t *testing.T) {
	plain, lookup, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := GenerateKey()
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
