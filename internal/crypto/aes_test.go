package crypto

import (
	"errors"
	"testing"
)

// TestEncryptDecryptRoundTrip covers acceptance criterion 1: the v1 form
// round-trips under the current key with the fingerprint as AAD, and the
// legacy form still opens through the same keyring.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"header":"Authorization","value":"Bearer sk-secret"}`)

	k := NewKeyring(key, nil)
	enc, err := k.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if enc == string(plain) {
		t.Fatal("ciphertext should not equal plaintext")
	}
	got, by, err := k.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %s want %s", got, plain)
	}
	if by != k.Fingerprint() {
		t.Fatalf("opened by %q, want the current fingerprint %q", by, k.Fingerprint())
	}

	legacy, err := EncryptLegacy(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err = k.Open(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("legacy: got %s want %s", got, plain)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	key, _ := RandomKey()
	other, _ := RandomKey()

	enc, err := NewKeyring(key, nil).Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewKeyring(other, nil).Open(enc); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("v1 under the wrong key: got %v, want ErrUnknownKey", err)
	}

	legacy, err := EncryptLegacy(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewKeyring(other, nil).Open(legacy); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("legacy under the wrong key: got %v, want ErrInvalidCipher", err)
	}
}

func TestParseKeyHex(t *testing.T) {
	raw := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	key, err := ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len=%d", len(key))
	}
}

func TestParseKeyRejectsShort(t *testing.T) {
	if _, err := ParseKey("too-short"); err == nil {
		t.Fatal("expected error")
	}
}
