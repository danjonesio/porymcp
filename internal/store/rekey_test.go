package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/models"
)

// openTemp opens a fresh SQLite store and hands back its path, so a test can
// open a second, independent connection to the same file, a second process,
// as far as SQLite is concerned.
func openTemp(t *testing.T) (*SQLStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rekey.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealWith(t *testing.T, key []byte, plain string) string {
	t.Helper()
	enc, err := crypto.NewKeyring(key, nil).Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func createUpstream(t *testing.T, s *SQLStore, id, authType, authConfig string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	err := s.CreateUpstream(context.Background(), &models.Upstream{
		ID: id, Name: "Up " + id, Slug: id, URL: "https://example.test/" + id, Transport: models.TransportStreamableHTTP,
		AuthType: authType, AuthConfig: rawOrNil(authConfig), Enabled: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func storedAuth(t *testing.T, s *SQLStore, id string) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(s.q(`SELECT COALESCE(auth_config,'') FROM upstreams WHERE id = ?`), id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// rekeyWith is the callback cmd/server's rekey uses, in miniature: open every
// row with the keyring, leave a v1 value under the current key alone, re-seal
// everything else, and name every row that will not open in one error.
func rekeyWith(t *testing.T, k crypto.Keyring) func([]RekeyRow) ([]string, error) {
	t.Helper()
	return func(rows []RekeyRow) ([]string, error) {
		next := make([]string, len(rows))
		var dead []string
		for i, r := range rows {
			plain, by, err := k.Open(r.Stored)
			if err != nil {
				dead = append(dead, r.ID)
				continue
			}
			if strings.HasPrefix(r.Stored, "v1:") && by == k.Fingerprint() {
				continue
			}
			enc, err := k.Seal(plain)
			if err != nil {
				return nil, err
			}
			next[i] = enc
		}
		if len(dead) > 0 {
			return nil, fmt.Errorf("undecryptable rows: %v", dead)
		}
		return next, nil
	}
}

// TestMigrateStep5IsANoOp: the version-5 stamp changes no column and no index,
// is idempotent, and a version-2 database migrates through it to 5.
func TestMigrateStep5IsANoOp(t *testing.T) {
	s, _ := openTemp(t)
	if v, err := s.currentSchemaVersion(); err != nil || v != 5 {
		t.Fatalf("fresh database at version %d (%v), want 5", v, err)
	}
	cols, idx := tableColumns(t, s, "upstreams"), indexNames(t, s)
	if err := s.migrateStep(5); err != nil {
		t.Fatalf("second run of step 5: %v", err)
	}
	if got := tableColumns(t, s, "upstreams"); strings.Join(got, ",") != strings.Join(cols, ",") {
		t.Errorf("step 5 changed upstreams columns: %v -> %v", cols, got)
	}
	if got := indexNames(t, s); strings.Join(got, ",") != strings.Join(idx, ",") {
		t.Errorf("step 5 changed indexes: %v -> %v", idx, got)
	}
	if v, _ := s.currentSchemaVersion(); v != 5 {
		t.Errorf("version after re-run = %d", v)
	}
	s2, _ := v2Store(t)
	if got := s2.LastMigration(); !got.Applied || got.Version != 5 {
		t.Errorf("v2 database migrated to %+v, want Applied at version 5", got)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if v, err := s.Meta(ctx, EncryptionKeyFPKey); err != nil || v != "" {
		t.Fatalf("absent key: got (%q, %v), want (\"\", nil)", v, err)
	}
	if err := s.SetMeta(ctx, EncryptionKeyFPKey, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(ctx, EncryptionKeyFPKey, "fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Meta(ctx, EncryptionKeyFPKey); err != nil || v != "fedcba9876543210" {
		t.Fatalf("after two upserts: got (%q, %v)", v, err)
	}
	if v, _ := s.Meta(ctx, schemaVersionKey); v != "5" {
		t.Fatalf("schema_version through Meta = %q", v)
	}
}

// TestRekeyUpstreams covers acceptance criterion 8's happy path: every row
// that needs it is re-sealed under the current key in one transaction, the
// three counts are right, the fingerprint is stamped in the same transaction,
// rows that need nothing are untouched, and a second run rewrites nothing.
func TestRekeyUpstreams(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	old, cur := newKey(t), newKey(t)
	k := crypto.NewKeyring(cur, [][]byte{old})
	legacy, err := crypto.EncryptLegacy(cur, []byte(`{"token":"legacy"}`))
	if err != nil {
		t.Fatal(err)
	}
	createUpstream(t, s, "r1", models.AuthBearer, legacy)                              // legacy under current: rewritten
	createUpstream(t, s, "r2", models.AuthBearer, sealWith(t, old, `{"token":"old"}`)) // v1 under previous: rewritten
	createUpstream(t, s, "r3", models.AuthBearer, sealWith(t, cur, `{"token":"cur"}`)) // v1 under current: already current
	createUpstream(t, s, "r4", models.AuthNone, sealWith(t, old, `{}`))                // none: not a credential, untouched
	createUpstream(t, s, "r5", models.AuthAPIKey, "")                                  // needs one, has none: no_credential
	before3, before4 := storedAuth(t, s, "r3"), storedAuth(t, s, "r4")

	sum, err := s.RekeyUpstreams(ctx, k.Fingerprint(), rekeyWith(t, k))
	if err != nil {
		t.Fatal(err)
	}
	if want := (RekeySummary{Rewritten: 2, AlreadyCurrent: 1, NoCredential: 1}); sum != want {
		t.Fatalf("summary = %+v, want %+v", sum, want)
	}
	for _, id := range []string{"r1", "r2"} {
		got := storedAuth(t, s, id)
		if !strings.HasPrefix(got, "v1:"+k.Fingerprint()+":") {
			t.Errorf("%s = %q, want a v1 value under the current key", id, got)
		}
		plain, _, err := k.Open(got)
		if err != nil {
			t.Errorf("%s does not open after rekey: %v", id, err)
		}
		if id == "r1" && string(plain) != `{"token":"legacy"}` {
			t.Errorf("r1 plaintext changed: %s", plain)
		}
	}
	if storedAuth(t, s, "r3") != before3 || storedAuth(t, s, "r4") != before4 {
		t.Error("a row that needed nothing was rewritten")
	}
	if fp, _ := s.Meta(ctx, EncryptionKeyFPKey); fp != k.Fingerprint() {
		t.Errorf("fingerprint = %q, want %q", fp, k.Fingerprint())
	}

	again, err := s.RekeyUpstreams(ctx, k.Fingerprint(), rekeyWith(t, k))
	if err != nil {
		t.Fatal(err)
	}
	if want := (RekeySummary{Rewritten: 0, AlreadyCurrent: 3, NoCredential: 1, PreviousFingerprint: k.Fingerprint()}); again != want {
		t.Fatalf("second run = %+v, want %+v", again, want)
	}
}

// TestRekeyUpstreamsRollsBackOnRewriteError pins security requirement 7 and
// acceptance criterion 8's failure clause: one row the keyring cannot open
// aborts the run with nothing written, not the rows that would have worked,
// not the fingerprint.
func TestRekeyUpstreamsRollsBackOnRewriteError(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	stranger, cur := newKey(t), newKey(t)
	k := crypto.NewKeyring(cur, nil)
	legacy, _ := crypto.EncryptLegacy(cur, []byte(`{"token":"fine"}`))
	createUpstream(t, s, "good", models.AuthBearer, legacy)
	createUpstream(t, s, "dead", models.AuthBearer, sealWith(t, stranger, `{"token":"lost"}`))
	if err := s.SetMeta(ctx, EncryptionKeyFPKey, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	beforeGood := storedAuth(t, s, "good")

	sum, err := s.RekeyUpstreams(ctx, k.Fingerprint(), rekeyWith(t, k))
	if err == nil || !strings.Contains(err.Error(), "dead") {
		t.Fatalf("want an error naming the dead row, got %v", err)
	}
	if sum != (RekeySummary{}) {
		t.Errorf("summary on failure = %+v, want zero", sum)
	}
	if storedAuth(t, s, "good") != beforeGood {
		t.Error("a healthy row was rewritten on a failed run")
	}
	if fp, _ := s.Meta(ctx, EncryptionKeyFPKey); fp != "0123456789abcdef" {
		t.Errorf("fingerprint moved on a failed run: %q", fp)
	}
}

// TestRekeyUpstreamsSerialisesWithConcurrentWrites pins the live-server
// property on SQLite: the rekey transaction holds the write lock from BEGIN
// (_txlock=immediate), so a credential edit started while the callback runs
// queues behind busy_timeout, applies after the commit, and wins, the
// operator's fresh, current-key value is the final state and nothing is lost.
// (On Postgres, where writers do not queue, the same interleaving makes the
// ciphertext CAS match zero rows and abort, that branch is unreachable on
// SQLite by construction and is asserted by review of the statement.)
func TestRekeyUpstreamsSerialisesWithConcurrentWrites(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	old, cur := newKey(t), newKey(t)
	k := crypto.NewKeyring(cur, [][]byte{old})
	createUpstream(t, s, "row", models.AuthBearer, sealWith(t, old, `{"token":"old"}`))
	fresh := sealWith(t, cur, `{"token":"REPLACED-BY-OPERATOR"}`)

	inner := rekeyWith(t, k)
	edited := make(chan error, 1)
	rewrite := func(rows []RekeyRow) ([]string, error) {
		// Another process replaces the credential while this run is deciding.
		// It blocks on the write lock this transaction already holds and lands
		// after the commit.
		go func() {
			s2, err := Open(path)
			if err != nil {
				edited <- err
				return
			}
			defer s2.Close()
			u, err := s2.GetUpstream(ctx, "row")
			if err != nil {
				edited <- err
				return
			}
			u.AuthConfig = []byte(fresh)
			edited <- s2.UpdateUpstream(ctx, u, KeepTest, WriteAuth)
		}()
		time.Sleep(200 * time.Millisecond)
		return inner(rows)
	}
	sum, err := s.RekeyUpstreams(ctx, k.Fingerprint(), rewrite)
	if err != nil {
		t.Fatalf("a queued writer must not abort the run: %v", err)
	}
	if sum.Rewritten != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if err := <-edited; err != nil {
		t.Fatalf("the concurrent edit should queue and then succeed: %v", err)
	}
	if got := storedAuth(t, s, "row"); got != fresh {
		t.Errorf("final state = %q, want the operator's edit to win", got)
	}
	if fp, _ := s.Meta(ctx, EncryptionKeyFPKey); fp != k.Fingerprint() {
		t.Errorf("fingerprint = %q", fp)
	}
}

// TestRekeyProceedsPastUnrelatedCommits pins the fix for the WAL snapshot
// hazard: an unrelated commit from another connection (one proxied call's
// audit row) while the callback runs must queue, not abort the rotation
// blaming a credential nobody touched.
func TestRekeyProceedsPastUnrelatedCommits(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	old, cur := newKey(t), newKey(t)
	k := crypto.NewKeyring(cur, [][]byte{old})
	createUpstream(t, s, "row", models.AuthBearer, sealWith(t, old, `{"token":"old"}`))

	inner := rekeyWith(t, k)
	audited := make(chan error, 1)
	rewrite := func(rows []RekeyRow) ([]string, error) {
		go func() {
			s2, err := Open(path)
			if err != nil {
				audited <- err
				return
			}
			defer s2.Close()
			audited <- s2.InsertAuditLog(ctx, &models.AuditLog{
				ID: "al1", Timestamp: time.Now().UTC(), VirtualKeyID: "a1", VirtualKeyName: "bot",
				Method: "tools/call", Status: models.StatusSuccess,
			})
		}()
		time.Sleep(200 * time.Millisecond)
		return inner(rows)
	}
	if _, err := s.RekeyUpstreams(ctx, k.Fingerprint(), rewrite); err != nil {
		t.Fatalf("an unrelated audit write aborted the rotation: %v", err)
	}
	if err := <-audited; err != nil {
		t.Fatalf("the audit write should queue and then succeed: %v", err)
	}
	if fp, _ := s.Meta(ctx, EncryptionKeyFPKey); fp != k.Fingerprint() {
		t.Errorf("fingerprint = %q", fp)
	}
}

// TestRekeyLeavesUpdatedAtAndTestColumns: re-wrapping is not an edit, and
// RecordUpstreamTest's compare-and-swap on updated_at must keep matching.
func TestRekeyLeavesUpdatedAtAndTestColumns(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	old, cur := newKey(t), newKey(t)
	k := crypto.NewKeyring(cur, [][]byte{old})
	createUpstream(t, s, "row", models.AuthBearer, sealWith(t, old, `{"token":"x"}`))
	before, err := s.GetUpstream(ctx, "row")
	if err != nil {
		t.Fatal(err)
	}
	at := before.UpdatedAt.Add(time.Minute)
	if err := s.RecordUpstreamTest(ctx, "row", at, true, before.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RekeyUpstreams(ctx, k.Fingerprint(), rekeyWith(t, k)); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetUpstream(ctx, "row")
	if err != nil {
		t.Fatal(err)
	}
	if !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Errorf("updated_at moved: %v -> %v", before.UpdatedAt, after.UpdatedAt)
	}
	if after.LastTestAt == nil || !after.LastTestAt.Equal(at) || after.LastTestOK == nil || !*after.LastTestOK {
		t.Errorf("test columns changed: at=%v ok=%v", after.LastTestAt, after.LastTestOK)
	}
	if err := s.RecordUpstreamTest(ctx, "row", at.Add(time.Minute), false, after.UpdatedAt); err != nil {
		t.Errorf("RecordUpstreamTest's CAS no longer matches after rekey: %v", err)
	}
}

// TestUpdateUpstreamKeepAuthLeavesCiphertext pins security requirement 8: a
// PATCH that carried no credential does not write the ciphertext it read.
func TestUpdateUpstreamKeepAuthLeavesCiphertext(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	cur := newKey(t)
	a, b := sealWith(t, cur, `{"token":"a"}`), sealWith(t, cur, `{"token":"b"}`)
	createUpstream(t, s, "row", models.AuthBearer, a)
	u, err := s.GetUpstream(ctx, "row")
	if err != nil {
		t.Fatal(err)
	}
	u.Name = "Renamed"
	u.AuthConfig = []byte(b)
	if err := s.UpdateUpstream(ctx, u, KeepTest, KeepAuth); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUpstream(ctx, "row")
	if got.Name != "Renamed" || storedAuth(t, s, "row") != a {
		t.Fatalf("KeepAuth: name=%q auth=%q, want the rename and ciphertext a", got.Name, storedAuth(t, s, "row"))
	}
	if err := s.UpdateUpstream(ctx, u, ResetTest, WriteAuth); err != nil {
		t.Fatal(err)
	}
	if storedAuth(t, s, "row") != b {
		t.Fatal("WriteAuth did not write the new ciphertext")
	}
	if err := s.UpdateUpstream(ctx, &models.Upstream{ID: "missing"}, KeepTest, KeepAuth); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row: %v", err)
	}
}
