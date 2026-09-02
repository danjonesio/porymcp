package credential

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/models"
)

func keyring(t *testing.T, previous int) (crypto.Keyring, [][]byte) {
	t.Helper()
	cur, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	var prev [][]byte
	for i := 0; i < previous; i++ {
		p, err := crypto.RandomKey()
		if err != nil {
			t.Fatal(err)
		}
		prev = append(prev, p)
	}
	return crypto.NewKeyring(cur, prev), prev
}

func seal(t *testing.T, k crypto.Keyring, plain string) []byte {
	t.Helper()
	enc, err := k.Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(enc)
}

// TestReadNoneIsNilWithoutDecrypting: a none upstream sends no credential, so
// whatever sits in the column is not consulted (the dashboard stores {} on
// every create, and an old blob can outlive an auth_type change).
func TestReadNoneIsNilWithoutDecrypting(t *testing.T) {
	k, _ := keyring(t, 0)
	for _, stored := range [][]byte{nil, []byte("garbage"), seal(t, k, `{}`)} {
		plain, err := Read(k, models.AuthNone, stored)
		if err != nil || plain != nil {
			t.Fatalf("stored=%q: got (%q, %v), want (nil, nil)", stored, plain, err)
		}
		if got := Status(k, models.AuthNone, stored); got != StatusNone {
			t.Fatalf("Status = %q, want none", got)
		}
	}
}

func TestReadEmptyIsUnreadable(t *testing.T) {
	k, _ := keyring(t, 0)
	if _, err := Read(k, models.AuthBearer, nil); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("got %v, want ErrUnreadable", err)
	}
	if got := Status(k, models.AuthBearer, nil); got != StatusUnreadable {
		t.Fatalf("Status = %q, want unreadable", got)
	}
}

func TestReadWrongKeyIsUndecryptable(t *testing.T) {
	sealer, _ := keyring(t, 0)
	stored := seal(t, sealer, `{"token":"sk"}`)
	k, _ := keyring(t, 1)
	if _, err := Read(k, models.AuthBearer, stored); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("got %v, want ErrUndecryptable", err)
	}
	if got := Status(k, models.AuthBearer, stored); got != StatusUndecryptable {
		t.Fatalf("Status = %q", got)
	}
	corrupt := []byte("v1:0123456789abcdef:!!!")
	if _, err := Read(k, models.AuthBearer, corrupt); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("corrupt bytes: got %v, want ErrUndecryptable", err)
	}
}

func TestReadLegacyBlob(t *testing.T) {
	cur, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := crypto.EncryptLegacy(cur, []byte(`{"token":"sk"}`))
	if err != nil {
		t.Fatal(err)
	}
	k := crypto.NewKeyring(cur, nil)
	plain, err := Read(k, models.AuthBearer, []byte(legacy))
	if err != nil || string(plain) != `{"token":"sk"}` {
		t.Fatalf("got (%q, %v)", plain, err)
	}
	if got := Status(k, models.AuthBearer, []byte(legacy)); got != StatusOK {
		t.Fatalf("Status = %q", got)
	}
}

func TestReadUnderPreviousKey(t *testing.T) {
	k, prev := keyring(t, 1)
	stored := seal(t, crypto.NewKeyring(prev[0], nil), `{"token":"sk"}`)
	plain, by, err := read(k, models.AuthBearer, stored)
	if err != nil || string(plain) != `{"token":"sk"}` {
		t.Fatalf("got (%q, %v)", plain, err)
	}
	if by != crypto.Fingerprint(prev[0]) || by == k.Fingerprint() {
		t.Fatalf("openedBy = %q, want the previous key's fingerprint", by)
	}
}

// TestReadUnreadablePlaintext pins security requirement 3 and the PORM-64
// hand-off: a blob that decrypts but holds nothing its auth type can send
// fails closed as unreadable, never as a key problem.
func TestReadUnreadablePlaintext(t *testing.T) {
	k, _ := keyring(t, 0)
	for name, tc := range map[string]struct{ authType, plain string }{
		"bearer {}":            {models.AuthBearer, `{}`},
		"bearer truncated":     {models.AuthBearer, `{"token":`},
		"bearer empty token":   {models.AuthBearer, `{"token":""}`},
		"custom with token":    {models.AuthCustom, `{"token":"x"}`},
		"header without value": {models.AuthHeader, `{"header":"X-A"}`},
	} {
		t.Run(name, func(t *testing.T) {
			stored := seal(t, k, tc.plain)
			if _, err := Read(k, tc.authType, stored); !errors.Is(err, ErrUnreadable) {
				t.Fatalf("got %v, want ErrUnreadable", err)
			}
			if got := Status(k, tc.authType, stored); got != StatusUnreadable {
				t.Fatalf("Status = %q", got)
			}
		})
	}
	// {} on a none row is fine, none consults nothing.
	if got := Status(k, models.AuthNone, seal(t, k, `{}`)); got != StatusNone {
		t.Fatalf("none with {} = %q", got)
	}
}

// TestSentinelsCarryNoDetail pins security requirement 1: the error text is
// the sentinel and nothing else, because audit error_message is not redacted.
func TestSentinelsCarryNoDetail(t *testing.T) {
	sealer, _ := keyring(t, 0)
	k, _ := keyring(t, 0)
	_, err := Read(k, models.AuthBearer, seal(t, sealer, `{"token":"sk-SECRET"}`))
	if err == nil || err.Error() != "credential undecryptable" {
		t.Fatalf("err = %v", err)
	}
	_, err = Read(k, models.AuthBearer, seal(t, k, `{"value":"", "token":""}`))
	if err == nil || err.Error() != "credential unreadable" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(fmt.Sprint(ErrUndecryptable, ErrUnreadable), sealer.Fingerprint()) {
		t.Fatal("a sentinel carries a fingerprint")
	}
}

func TestStatusFourValues(t *testing.T) {
	k, _ := keyring(t, 0)
	other, _ := keyring(t, 0)
	cases := map[string]struct {
		authType string
		stored   []byte
		want     string
	}{
		"none":          {models.AuthNone, seal(t, other, `{"token":"x"}`), StatusNone},
		"ok":            {models.AuthBearer, seal(t, k, `{"token":"x"}`), StatusOK},
		"undecryptable": {models.AuthBearer, seal(t, other, `{"token":"x"}`), StatusUndecryptable},
		"unreadable":    {models.AuthBearer, seal(t, k, `{}`), StatusUnreadable},
		"missing":       {models.AuthAPIKey, nil, StatusUnreadable},
	}
	for name, tc := range cases {
		if got := Status(k, tc.authType, tc.stored); got != tc.want {
			t.Errorf("%s: Status = %q, want %q", name, got, tc.want)
		}
	}
}

// TestSweepCountsAndNames pins the Report contract: none rows are skipped,
// Credentials counts stored blobs that need a credential, each row lands in
// exactly one bucket, lists are capped, and no plaintext reaches any field.
func TestSweepCountsAndNames(t *testing.T) {
	k, prev := keyring(t, 1)
	other, _ := keyring(t, 0)
	oldKeyring := crypto.NewKeyring(prev[0], nil)
	const secret = "sk-PLAINTEXT-MARKER"
	ups := []models.Upstream{
		{ID: "n1", Name: "None", AuthType: models.AuthNone, AuthConfig: seal(t, other, `{"token":"`+secret+`"}`)},
		{ID: "ok1", Name: "OK", AuthType: models.AuthBearer, AuthConfig: seal(t, k, `{"token":"`+secret+`"}`)},
		{ID: "prev1", Name: "Prev", AuthType: models.AuthBearer, AuthConfig: seal(t, oldKeyring, `{"token":"`+secret+`"}`)},
		{ID: "bad1", Name: "Bad", AuthType: models.AuthBearer, AuthConfig: seal(t, other, `{"token":"`+secret+`"}`)},
		{ID: "empty1", Name: "Empty", AuthType: models.AuthBearer, AuthConfig: seal(t, k, `{}`)},
		{ID: "missing1", Name: "Missing", AuthType: models.AuthHeader, AuthConfig: nil},
	}
	r := Sweep(k, ups)
	if r.Credentials != 4 {
		t.Errorf("Credentials = %d, want 4 (none skipped, missing has no blob)", r.Credentials)
	}
	if r.Undecryptable != 1 || r.Unreadable != 2 || r.UnderPrevious != 1 {
		t.Errorf("Undecryptable=%d Unreadable=%d UnderPrevious=%d", r.Undecryptable, r.Unreadable, r.UnderPrevious)
	}
	if fmt.Sprint(r.IDs) != "[bad1]" || fmt.Sprint(r.Names) != "[Bad]" {
		t.Errorf("IDs=%v Names=%v", r.IDs, r.Names)
	}
	if fmt.Sprint(r.UnreadableIDs) != "[empty1 missing1]" {
		t.Errorf("UnreadableIDs=%v", r.UnreadableIDs)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), secret) {
		t.Fatal("a plaintext reached the report")
	}

	// The cap: 25 undecryptable rows list 20 and count 5 as not listed.
	var many []models.Upstream
	for i := 0; i < 25; i++ {
		many = append(many, models.Upstream{ID: fmt.Sprint("u", i), Name: fmt.Sprint("U", i), AuthType: models.AuthBearer, AuthConfig: seal(t, other, `{"token":"x"}`)})
	}
	r = Sweep(k, many)
	if r.Undecryptable != 25 || len(r.IDs) != 20 || r.NotListed != 5 {
		t.Errorf("cap: Undecryptable=%d listed=%d NotListed=%d", r.Undecryptable, len(r.IDs), r.NotListed)
	}
}
