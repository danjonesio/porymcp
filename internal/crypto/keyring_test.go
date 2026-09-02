package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	key, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSealAlwaysWritesV1 pins security requirement 11: every production write
// is the v1 form, labelled with the current key's fingerprint.
func TestSealAlwaysWritesV1(t *testing.T) {
	k := NewKeyring(mustKey(t), [][]byte{mustKey(t)})
	enc, err := k.Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	want := "v1:" + k.Fingerprint() + ":"
	if !strings.HasPrefix(enc, want) {
		t.Fatalf("got %q, want prefix %q", enc, want)
	}
	if !IsFingerprint(k.Fingerprint()) {
		t.Fatalf("fingerprint %q is not 16 lowercase hex", k.Fingerprint())
	}
}

// TestAAD covers acceptance criterion 1's middle clause: the same ciphertext
// relabelled with another fingerprint fails, distinguishably, ErrUnknownKey
// when the label names no held key, ErrInvalidCipher when it names a held key
// that did not seal it.
func TestAAD(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	k := NewKeyring(a, [][]byte{b})
	enc, err := k.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(enc, "v1:"+Fingerprint(a)+":")

	unknown := "v1:" + Fingerprint(mustKey(t)) + ":" + body
	if _, _, err := k.Open(unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown label: got %v, want ErrUnknownKey", err)
	}
	relabelled := "v1:" + Fingerprint(b) + ":" + body
	if _, _, err := k.Open(relabelled); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("relabelled to a held key: got %v, want ErrInvalidCipher", err)
	}
}

// TestLegacyCiphertext covers acceptance criterion 1's last clause: an
// unprefixed, nil-AAD value written by an older build still opens, under the
// current key and under a previous one, and reports which key opened it.
func TestLegacyCiphertext(t *testing.T) {
	cur, old := mustKey(t), mustKey(t)
	k := NewKeyring(cur, [][]byte{old})
	for name, key := range map[string][]byte{"current": cur, "previous": old} {
		enc, err := EncryptLegacy(key, []byte("legacy-"+name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(enc, "v1:") {
			t.Fatalf("EncryptLegacy wrote a v1 value: %q", enc)
		}
		got, by, err := k.Open(enc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != "legacy-"+name {
			t.Fatalf("%s: got %q", name, got)
		}
		if by != Fingerprint(key) {
			t.Fatalf("%s: opened by %q, want %q", name, by, Fingerprint(key))
		}
	}
}

// TestPreviousKeyDecrypts covers acceptance criterion 7: a value sealed under
// the old key opens when that key is supplied as a previous key, and new
// writes use the current key.
func TestPreviousKeyDecrypts(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	enc, err := NewKeyring(old, nil).Seal([]byte("rotated"))
	if err != nil {
		t.Fatal(err)
	}
	k := NewKeyring(cur, [][]byte{old})
	got, by, err := k.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "rotated" || by != Fingerprint(old) {
		t.Fatalf("got %q by %q", got, by)
	}
	if !k.Covers(Fingerprint(old)) || !k.Covers(Fingerprint(cur)) || k.Covers(Fingerprint(mustKey(t))) {
		t.Fatal("Covers does not match the keyring's keys")
	}
	fresh, err := k.Seal([]byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fresh, "v1:"+Fingerprint(cur)+":") {
		t.Fatalf("Seal used something other than the current key: %q", fresh)
	}
	if _, _, err := NewKeyring(old, nil).Open(fresh); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("the old key alone should not open a new value: %v", err)
	}
}

// TestFingerprintIsStableAndDomainSeparated pins security requirement 5.
func TestFingerprintIsStableAndDomainSeparated(t *testing.T) {
	key := mustKey(t)
	fp := Fingerprint(key)
	if fp != Fingerprint(key) {
		t.Fatal("fingerprint is not stable")
	}
	if !IsFingerprint(fp) {
		t.Fatalf("%q is not 16 lowercase hex", fp)
	}
	sum := sha256.Sum256(key)
	if fp == hex.EncodeToString(sum[:])[:16] {
		t.Fatal("fingerprint equals a plain sha256 of the key; the label is missing")
	}
	if Fingerprint(mustKey(t)) == fp {
		t.Fatal("two keys share a fingerprint")
	}
}

func TestIsFingerprint(t *testing.T) {
	for s, want := range map[string]bool{
		"0123456789abcdef":  true,
		"0123456789ABCDEF":  false,
		"0123456789abcde":   false,
		"0123456789abcdef0": false,
		"0123456789abcdeg":  false,
		"":                  false,
	} {
		if got := IsFingerprint(s); got != want {
			t.Errorf("IsFingerprint(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestV1NeverFallsBackToLegacy pins security requirement 11's second half: a
// legacy body relabelled as v1 under its own key is refused, not quietly
// opened with nil AAD.
func TestV1NeverFallsBackToLegacy(t *testing.T) {
	key := mustKey(t)
	k := NewKeyring(key, nil)
	legacy, err := EncryptLegacy(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Open("v1:" + Fingerprint(key) + ":" + legacy); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("got %v, want ErrInvalidCipher (no legacy fallback)", err)
	}
}

func TestV1WithUnknownFingerprintIsErrUnknownKey(t *testing.T) {
	enc, err := NewKeyring(mustKey(t), nil).Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = NewKeyring(mustKey(t), [][]byte{mustKey(t)}).Open(enc)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
	if len(ErrUnknownKey.Error()) == 0 || IsFingerprint(ErrUnknownKey.Error()[len(ErrUnknownKey.Error())-16:]) {
		t.Fatal("ErrUnknownKey must not carry a fingerprint")
	}
}

func TestV1MalformedIsInvalidCipher(t *testing.T) {
	k := NewKeyring(mustKey(t), nil)
	fp := k.Fingerprint()
	body := base64.StdEncoding.EncodeToString([]byte("0123456789ab0123456789ab"))
	for _, s := range []string{
		"v1:",
		"v1:" + fp,
		"v1:zz:" + body,
		"v1:" + fp[:15] + ":" + body,
		"v1:" + strings.ToUpper(fp) + ":" + body,
		"v1:" + fp + ":not*base64!",
		"v1::" + body,
	} {
		if _, _, err := k.Open(s); !errors.Is(err, ErrInvalidCipher) {
			t.Errorf("Open(%q) = %v, want ErrInvalidCipher", s, err)
		}
	}
}
