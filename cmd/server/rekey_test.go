package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
)

const rekeySecret = "sk-REKEY-PLAINTEXT-MARKER"

// rekeyDB seeds a database for a rotation from old to cur and returns its
// path plus the ciphertexts as seeded, so a test can tell a rewritten row from
// an untouched one.
func rekeyDB(t *testing.T, old, cur []byte) (path string, seeded map[string]string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "rekey.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := crypto.EncryptLegacy(cur, []byte(`{"token":"`+rekeySecret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	seeded = map[string]string{
		"legacy":   legacy,
		"underOld": sealUnder(t, old, `{"token":"old-`+rekeySecret+`"}`),
		"current":  sealUnder(t, cur, `{"token":"cur"}`),
		"none":     sealUnder(t, old, `{}`),
	}
	ctx := context.Background()
	now := time.Now().UTC()
	for id, authType := range map[string]string{"legacy": models.AuthBearer, "underOld": models.AuthBearer, "current": models.AuthBearer, "none": models.AuthNone} {
		if err := st.CreateUpstream(ctx, &models.Upstream{
			ID: id, Name: "Up " + id, Slug: strings.ToLower(id), URL: "https://example.test/" + id, Transport: models.TransportStreamableHTTP,
			AuthType: authType, AuthConfig: []byte(seeded[id]), Enabled: true, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path, seeded
}

func rekeyEnv(t *testing.T, path string, cur, old []byte) {
	t.Helper()
	t.Setenv("ADMIN_API_KEY", "test-admin")
	t.Setenv("DATABASE_URL", path)
	if cur != nil {
		t.Setenv("ENCRYPTION_KEY", hex.EncodeToString(cur))
	} else {
		t.Setenv("ENCRYPTION_KEY", "")
	}
	if old != nil {
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", hex.EncodeToString(old))
	} else {
		t.Setenv("ENCRYPTION_KEY_PREVIOUS", "")
	}
}

func rawColumn(t *testing.T, path, id string) string {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.GetUpstream(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return string(u.AuthConfig)
}

func storedFP(t *testing.T, path string) string {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fp, err := st.Meta(context.Background(), store.EncryptionKeyFPKey)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func rekeyRecord(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for _, r := range decodeLogRecords(t, buf) {
		if r["msg"] == msg {
			return r
		}
	}
	t.Fatalf("no %q record in %s", msg, buf.String())
	return nil
}

// TestRekeyRefusesEphemeralKey pins security requirement 7's first guard:
// with no ENCRYPTION_KEY nothing is touched, and no admin key is printed.
func TestRekeyRefusesEphemeralKey(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	path, seeded := rekeyDB(t, old, cur)
	rekeyEnv(t, path, nil, nil)
	t.Setenv("ADMIN_API_KEY", "") // a generated one must not be printed either
	var out bytes.Buffer
	if code := rekey(&out); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "rekey needs ENCRYPTION_KEY") || strings.Contains(out.String(), "pory_admin_") {
		t.Fatalf("output: %s", out.String())
	}
	for id, enc := range seeded {
		if rawColumn(t, path, id) != enc {
			t.Fatalf("%s was rewritten under an ephemeral key", id)
		}
	}
	if storedFP(t, path) != "" {
		t.Fatal("a fingerprint was stamped")
	}
}

// TestRekeyRewritesLegacyAndPreviousRows covers acceptance criterion 8's
// happy path end to end through config.Load, store.Open and the transaction.
func TestRekeyRewritesLegacyAndPreviousRows(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	path, seeded := rekeyDB(t, old, cur)
	rekeyEnv(t, path, cur, old)
	var out bytes.Buffer
	if code := rekey(&out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	rec := rekeyRecord(t, &out, "rekey complete")
	if rec["rewritten"] != float64(2) || rec["already_current"] != float64(1) || rec["no_credential"] != float64(0) {
		t.Fatalf("counts: %v", rec)
	}
	if rec["previous_fingerprint"] != "none" || rec["fingerprint"] != crypto.Fingerprint(cur) {
		t.Fatalf("fingerprints: %v", rec)
	}
	k := crypto.NewKeyring(cur, nil)
	for _, id := range []string{"legacy", "underOld"} {
		got := rawColumn(t, path, id)
		if got == seeded[id] || !crypto.IsV1(got) {
			t.Fatalf("%s not rewritten: %q", id, got)
		}
		if _, by, err := k.Open(got); err != nil || by != k.Fingerprint() {
			t.Fatalf("%s does not open under the current key alone: %v", id, err)
		}
	}
	if rawColumn(t, path, "current") != seeded["current"] || rawColumn(t, path, "none") != seeded["none"] {
		t.Fatal("a row that needed nothing was rewritten")
	}
	if storedFP(t, path) != crypto.Fingerprint(cur) {
		t.Fatalf("stored fingerprint = %q", storedFP(t, path))
	}
}

func TestRekeyIsIdempotent(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	path, _ := rekeyDB(t, old, cur)
	rekeyEnv(t, path, cur, old)
	var first, second bytes.Buffer
	if code := rekey(&first); code != 0 {
		t.Fatalf("first run: %d %s", code, first.String())
	}
	if code := rekey(&second); code != 0 {
		t.Fatalf("second run: %d %s", code, second.String())
	}
	rec := rekeyRecord(t, &second, "rekey complete")
	if rec["rewritten"] != float64(0) || rec["already_current"] != float64(3) || rec["previous_fingerprint"] != crypto.Fingerprint(cur) {
		t.Fatalf("second run: %v", rec)
	}
}

// TestRekeyFailsClosedOnUnopenableRow covers acceptance criterion 8's failure
// clause: exit 1, every dead row named in one run, nothing written.
func TestRekeyFailsClosedOnUnopenableRow(t *testing.T) {
	old, cur, stranger := mustKey(t), mustKey(t), mustKey(t)
	path, seeded := rekeyDB(t, old, cur)
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"dead1", "dead2"} {
		if err := st.CreateUpstream(ctx, &models.Upstream{
			ID: id, Name: "Lost " + id, Slug: id, URL: "https://example.test/" + id, Transport: models.TransportStreamableHTTP,
			AuthType: models.AuthBearer, AuthConfig: []byte(sealUnder(t, stranger, `{"token":"gone"}`)), Enabled: true, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	rekeyEnv(t, path, cur, old)
	var out bytes.Buffer
	if code := rekey(&out); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, out.String())
	}
	rec := rekeyRecord(t, &out, "rekey failed: a stored credential cannot be decrypted with any configured key; no credentials were changed")
	ids, _ := rec["upstream_ids"].([]any)
	names, _ := rec["upstream_names"].([]any)
	if len(ids) != 2 || ids[0] != "dead1" || ids[1] != "dead2" || len(names) != 2 || names[0] != "Lost dead1" {
		t.Fatalf("dead rows: ids=%v names=%v", ids, names)
	}
	for id, enc := range seeded {
		if rawColumn(t, path, id) != enc {
			t.Fatalf("%s was rewritten on a failed run", id)
		}
	}
	if storedFP(t, path) != "" {
		t.Fatal("a fingerprint was stamped on a failed run")
	}
}

// TestRekeyPrintsNoCredentialValues pins security requirement 1 on the
// command's output, on success and on failure.
func TestRekeyPrintsNoCredentialValues(t *testing.T) {
	old, cur, stranger := mustKey(t), mustKey(t), mustKey(t)
	for _, previous := range [][]byte{old, stranger} {
		path, seeded := rekeyDB(t, old, cur)
		rekeyEnv(t, path, cur, previous)
		var out bytes.Buffer
		rekey(&out)
		for _, forbidden := range []string{rekeySecret, seeded["legacy"], seeded["underOld"], hex.EncodeToString(cur), hex.EncodeToString(old), "example.test"} {
			if strings.Contains(out.String(), forbidden) {
				t.Fatalf("output carries %q: %s", forbidden, out.String())
			}
		}
	}
}

// TestRekeyPrintsCountsUnderLogLevelWarn: the result is a command's output,
// not telemetry; LOG_LEVEL cannot suppress it.
func TestRekeyPrintsCountsUnderLogLevelWarn(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	path, _ := rekeyDB(t, old, cur)
	rekeyEnv(t, path, cur, old)
	t.Setenv("LOG_LEVEL", "warn")
	var out bytes.Buffer
	if code := rekey(&out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	rekeyRecord(t, &out, "rekey complete")
}

// TestRekeyVerifiesRoundTrip: a writer that produces a value which does not
// open back to the plaintext is refused before anything is written.
func TestRekeyVerifiesRoundTrip(t *testing.T) {
	cur := mustKey(t)
	k := crypto.NewKeyring(cur, nil)
	legacy, err := crypto.EncryptLegacy(cur, []byte(`{"token":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	badSeal := func([]byte) (string, error) { return k.Seal([]byte(`{"token":"SOMETHING ELSE"}`)) }
	_, err = rekeyRewriter(k, badSeal)([]store.RekeyRow{{ID: "u1", Name: "A", Stored: legacy}})
	if err == nil || !strings.Contains(err.Error(), "does not round-trip") {
		t.Fatalf("want the round-trip refusal, got %v", err)
	}
	next, err := rekeyRewriter(k, k.Seal)([]store.RekeyRow{{ID: "u1", Name: "A", Stored: legacy}})
	if err != nil || len(next) != 1 || !crypto.IsV1(next[0]) {
		t.Fatalf("the real sealer: next=%v err=%v", next, err)
	}
}
