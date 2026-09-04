package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

const bootSecret = "sk-BOOT-PLAINTEXT-MARKER"

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealUnder(t *testing.T, key []byte, plain string) string {
	t.Helper()
	enc, err := crypto.NewKeyring(key, nil).Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// bootRow is one upstream a boot case seeds: its auth type and stored blob.
type bootRow struct {
	id, name, authType, stored string
}

// boot runs checkEncryption over a fresh store seeded with rows and an
// optional pre-existing fingerprint, capturing the log as decoded records.
func boot(t *testing.T, cfg *config.Config, stored string, rows []bootRow) (verdict string, err error, records []map[string]any, storedAfter string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "boot.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, r := range rows {
		var raw []byte
		if r.stored != "" {
			raw = []byte(r.stored)
		}
		if err := st.CreateUpstream(ctx, &models.Upstream{
			ID: r.id, Name: r.name, Slug: r.id, URL: "https://example.test/" + r.id, Transport: models.TransportStreamableHTTP,
			AuthType: r.authType, AuthConfig: raw, Enabled: true, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if stored != "" {
		if err := st.SetMeta(ctx, store.EncryptionKeyFPKey, stored); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	verdict, err = checkEncryption(ctx, st, cfg, log)
	storedAfter, _ = st.Meta(ctx, store.EncryptionKeyFPKey)
	return verdict, err, decodeLogRecords(t, &buf), storedAfter
}

func recordsAt(records []map[string]any, level string) []map[string]any {
	var out []map[string]any
	for _, r := range records {
		if r["level"] == level {
			out = append(out, r)
		}
	}
	return out
}

func msgs(records []map[string]any) string {
	var out []string
	for _, r := range records {
		out = append(out, r["msg"].(string))
	}
	return strings.Join(out, " | ")
}

// TestBootEncryptionMismatchLogsFingerprintsAndNames covers acceptance
// criterion 3: exactly one Error record, both fingerprints, the counts, the
// affected names, and the hint names the fix.
func TestBootEncryptionMismatchLogsFingerprintsAndNames(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	cfg := &config.Config{EncryptionKey: cur}
	rows := []bootRow{
		{"u1", "GitHub", models.AuthBearer, sealUnder(t, old, `{"token":"`+bootSecret+`"}`)},
		{"u2", "Linear", models.AuthBearer, sealUnder(t, old, `{"token":"x"}`)},
		{"u3", "Docs", models.AuthNone, sealUnder(t, old, `{}`)},
	}
	verdict, err, records, storedAfter := boot(t, cfg, crypto.Fingerprint(old), rows)
	if err != nil || verdict != webutil.EncryptionMismatch {
		t.Fatalf("verdict=%q err=%v", verdict, err)
	}
	errs := recordsAt(records, "ERROR")
	if len(errs) != 1 {
		t.Fatalf("want exactly one Error record, got %d: %s", len(errs), msgs(errs))
	}
	e := errs[0]
	if !strings.Contains(e["msg"].(string), "does not match") {
		t.Errorf("msg = %q", e["msg"])
	}
	if e["stored_fingerprint"] != crypto.Fingerprint(old) || e["current_fingerprint"] != crypto.Fingerprint(cur) {
		t.Errorf("fingerprints: stored=%v current=%v", e["stored_fingerprint"], e["current_fingerprint"])
	}
	if e["undecryptable"] != float64(2) || e["credentials"] != float64(2) {
		t.Errorf("counts: %v", e)
	}
	names, _ := e["upstream_names"].([]any)
	if len(names) != 2 || names[0] != "GitHub" || names[1] != "Linear" {
		t.Errorf("upstream_names = %v", e["upstream_names"])
	}
	if hint, _ := e["hint"].(string); !strings.Contains(hint, "ENCRYPTION_KEY_PREVIOUS") || !strings.Contains(hint, "rekey") {
		t.Errorf("hint = %q", hint)
	}
	if storedAfter != crypto.Fingerprint(old) {
		t.Errorf("a mismatch moved the stored fingerprint to %q", storedAfter)
	}
}

// TestBootSweepLogsNoCredentialValues covers acceptance criterion 12 and
// security requirement 1: no plaintext, no ciphertext, no url in any record.
func TestBootSweepLogsNoCredentialValues(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	enc := sealUnder(t, old, `{"token":"`+bootSecret+`"}`)
	for _, cfg := range []*config.Config{
		{EncryptionKey: cur},
		{EncryptionKey: cur, EncryptionKeyPrevious: [][]byte{old}},
	} {
		_, _, records, _ := boot(t, cfg, "", []bootRow{
			{"u1", "GitHub", models.AuthBearer, enc},
			{"u2", "Blank", models.AuthBearer, sealUnder(t, cur, `{}`)},
		})
		var all []string
		for _, r := range records {
			for k, v := range r {
				all = append(all, k, strings.ToLower(strings.TrimSpace(strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(fmtAny(v), "\n", " "), "\t", " "), "\r", " ")), " "))))
			}
		}
		joined := strings.Join(all, " ")
		for _, forbidden := range []string{strings.ToLower(bootSecret), strings.ToLower(enc), "example.test"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("log carries %q: %v", forbidden, records)
			}
		}
	}
}

func fmtAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var parts []string
		for _, p := range x {
			parts = append(parts, fmtAny(p))
		}
		return strings.Join(parts, " ")
	default:
		return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(fmtDefault(x), "\n", " "), "\t", " "))
	}
}

func fmtDefault(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestBootStampsOnlyWhenProven pins security requirement 5's write rule, one
// branch per row, with the seventh (absent + empty table) the first-boot case.
func TestBootStampsOnlyWhenProven(t *testing.T) {
	old, cur, stranger := mustKey(t), mustKey(t), mustKey(t)
	fpCur, fpStranger := crypto.Fingerprint(cur), crypto.Fingerprint(stranger)
	withPrev := &config.Config{EncryptionKey: cur, EncryptionKeyPrevious: [][]byte{old}}
	plain := &config.Config{EncryptionKey: cur}
	underCur := sealUnder(t, cur, `{"token":"x"}`)
	underOld := sealUnder(t, old, `{"token":"x"}`)
	underStranger := sealUnder(t, stranger, `{"token":"x"}`)
	for name, tc := range map[string]struct {
		cfg         *config.Config
		stored      string
		rows        []bootRow
		wantVerdict string
		wantStored  string
		wantWarn    string // substring of a Warn msg, "" for none expected
	}{
		"absent, all open under current":  {plain, "", []bootRow{{"u1", "A", models.AuthBearer, underCur}}, "ok", fpCur, ""},
		"absent, one undecryptable":       {plain, "", []bootRow{{"u1", "A", models.AuthBearer, underCur}, {"u2", "B", models.AuthBearer, underStranger}}, "mismatch", "", ""},
		"absent, under previous":          {withPrev, "", []bootRow{{"u1", "A", models.AuthBearer, underOld}}, "ok", "", "rotation pending"},
		"differs, all open under current": {plain, fpStranger, []bootRow{{"u1", "A", models.AuthBearer, underCur}}, "ok", fpCur, "recording the current fingerprint"},
		"differs, zero credentials":       {plain, fpStranger, []bootRow{{"u1", "Docs", models.AuthNone, ""}}, "ok", fpStranger, ""},
		"current, under previous":         {withPrev, fpCur, []bootRow{{"u1", "A", models.AuthBearer, underOld}}, "ok", fpCur, "rotation pending"},
		"absent, empty table":             {plain, "", nil, "ok", fpCur, ""},
	} {
		t.Run(name, func(t *testing.T) {
			verdict, err, records, storedAfter := boot(t, tc.cfg, tc.stored, tc.rows)
			if err != nil {
				t.Fatal(err)
			}
			if verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q", verdict, tc.wantVerdict)
			}
			if storedAfter != tc.wantStored {
				t.Errorf("stored fingerprint after boot = %q, want %q", storedAfter, tc.wantStored)
			}
			warns := msgs(recordsAt(records, "WARN"))
			if tc.wantWarn == "" && strings.Contains(warns, "rotation pending") {
				t.Errorf("unexpected rotation Warn: %s", warns)
			}
			if tc.wantWarn != "" && !strings.Contains(warns, tc.wantWarn) {
				t.Errorf("want a Warn containing %q, got %q", tc.wantWarn, warns)
			}
		})
	}
}

func TestBootNeverStampsOnMismatch(t *testing.T) {
	cur, stranger := mustKey(t), mustKey(t)
	for _, stored := range []string{"", crypto.Fingerprint(stranger)} {
		_, _, _, after := boot(t, &config.Config{EncryptionKey: cur}, stored, []bootRow{
			{"u1", "A", models.AuthBearer, sealUnder(t, stranger, `{"token":"x"}`)},
		})
		if after != stored {
			t.Errorf("stored %q became %q on a mismatch", stored, after)
		}
	}
}

// TestBootRotationPendingIsNotDegraded: the documented rotation window
// (stored fingerprint = the key now in ENCRYPTION_KEY_PREVIOUS, every
// row opens) is ok, one Warn, no stamp, no Error.
func TestBootRotationPendingIsNotDegraded(t *testing.T) {
	old, cur := mustKey(t), mustKey(t)
	cfg := &config.Config{EncryptionKey: cur, EncryptionKeyPrevious: [][]byte{old}}
	verdict, err, records, after := boot(t, cfg, crypto.Fingerprint(old), []bootRow{
		{"u1", "A", models.AuthBearer, sealUnder(t, old, `{"token":"x"}`)},
		{"u2", "B", models.AuthBearer, sealUnder(t, old, `{"token":"y"}`)},
	})
	if err != nil || verdict != webutil.EncryptionOK {
		t.Fatalf("verdict=%q err=%v", verdict, err)
	}
	if n := len(recordsAt(records, "ERROR")); n != 0 {
		t.Fatalf("a planned rotation logged %d Error records", n)
	}
	warns := recordsAt(records, "WARN")
	if len(warns) != 1 || !strings.Contains(warns[0]["msg"].(string), "rotation pending") || warns[0]["under_previous"] != float64(2) {
		t.Fatalf("warns = %s (%v)", msgs(warns), warns)
	}
	if after != crypto.Fingerprint(old) {
		t.Fatalf("the boot moved the fingerprint to %q; only rekey may", after)
	}
}

// TestBootUnreadableIsNotMismatch: a blank token stored as {} is a Warn naming
// the row, never the key-mismatch Error, and /health stays ok.
func TestBootUnreadableIsNotMismatch(t *testing.T) {
	cur := mustKey(t)
	verdict, err, records, after := boot(t, &config.Config{EncryptionKey: cur}, "", []bootRow{
		{"u1", "Blank", models.AuthBearer, sealUnder(t, cur, `{}`)},
		{"u2", "Missing", models.AuthAPIKey, ""},
		{"u3", "Fine", models.AuthBearer, sealUnder(t, cur, `{"token":"x"}`)},
	})
	if err != nil || verdict != webutil.EncryptionOK {
		t.Fatalf("verdict=%q err=%v", verdict, err)
	}
	if n := len(recordsAt(records, "ERROR")); n != 0 {
		t.Fatalf("%d Error records for a blank token", n)
	}
	warns := recordsAt(records, "WARN")
	if len(warns) != 1 || warns[0]["unreadable"] != float64(2) {
		t.Fatalf("warns = %v", warns)
	}
	names, _ := warns[0]["upstream_names"].([]any)
	if len(names) != 2 || names[0] != "Blank" || names[1] != "Missing" {
		t.Fatalf("upstream_names = %v", warns[0]["upstream_names"])
	}
	if after != crypto.Fingerprint(cur) {
		t.Fatalf("stored = %q; the healthy row proved the key", after)
	}
}

func TestBootLogsVerifiedEveryStart(t *testing.T) {
	cur := mustKey(t)
	for i, stored := range []string{"", crypto.Fingerprint(cur)} {
		_, _, records, _ := boot(t, &config.Config{EncryptionKey: cur}, stored, []bootRow{
			{"u1", "A", models.AuthBearer, sealUnder(t, cur, `{"token":"x"}`)},
		})
		infos := recordsAt(records, "INFO")
		if len(infos) != 1 || infos[0]["msg"] != "encryption key verified" || infos[0]["fingerprint"] != crypto.Fingerprint(cur) {
			t.Fatalf("boot %d: infos = %v", i, infos)
		}
		if infos[0]["recorded"] != (i == 0) {
			t.Fatalf("boot %d: recorded = %v", i, infos[0]["recorded"])
		}
	}
}

func TestBootIgnoresMalformedFingerprint(t *testing.T) {
	cur := mustKey(t)
	const junk = "\x1b[31mnot-a-fingerprint\n{\"forged\":true}"
	verdict, err, records, after := boot(t, &config.Config{EncryptionKey: cur}, junk, []bootRow{
		{"u1", "A", models.AuthBearer, sealUnder(t, cur, `{"token":"x"}`)},
	})
	if err != nil || verdict != webutil.EncryptionOK {
		t.Fatalf("verdict=%q err=%v", verdict, err)
	}
	if !strings.Contains(msgs(recordsAt(records, "WARN")), "malformed") {
		t.Fatalf("want a malformed-fingerprint Warn: %s", msgs(records))
	}
	for _, r := range records {
		for _, v := range r {
			if s, ok := v.(string); ok && strings.Contains(s, "not-a-fingerprint") {
				t.Fatalf("the malformed value was echoed: %v", r)
			}
		}
	}
	if after != crypto.Fingerprint(cur) {
		t.Fatalf("stored = %q, want the proven current fingerprint", after)
	}
}

// TestEphemeralKeyAgainstCredentialsExits covers acceptance criterion 2 at
// the boot seam: the guard's error is what main exits on.
func TestEphemeralKeyAgainstCredentialsExits(t *testing.T) {
	old := mustKey(t)
	cfg := &config.Config{EncryptionKey: mustKey(t), EphemeralEnc: true}
	_, err, _, after := boot(t, cfg, "", []bootRow{
		{"u1", "A", models.AuthBearer, sealUnder(t, old, `{"token":"x"}`)},
	})
	if err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY is not set") {
		t.Fatalf("want the guard's refusal, got %v", err)
	}
	if after != "" {
		t.Fatalf("an ephemeral boot stamped %q", after)
	}
}

// TestEphemeralKeyStartsWithNoneUpstreams: the ephemeral-key path keeps working
// with upstreams that need no credential, whatever the dashboard stored.
func TestEphemeralKeyStartsWithNoneUpstreams(t *testing.T) {
	old := mustKey(t)
	cfg := &config.Config{EncryptionKey: mustKey(t), EphemeralEnc: true}
	verdict, err, records, after := boot(t, cfg, "", []bootRow{
		{"u1", "Docs", models.AuthNone, sealUnder(t, old, `{}`)},
	})
	if err != nil || verdict != webutil.EncryptionOK {
		t.Fatalf("verdict=%q err=%v", verdict, err)
	}
	if after != "" || len(records) != 0 {
		t.Fatalf("ephemeral boot must neither stamp nor log: stored=%q records=%v", after, records)
	}
}

func TestHealthcheckResult(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		body     webutil.HealthBody
		wantCode int
		wantMsg  bool
	}{
		"ok":          {200, webutil.HealthBody{Status: "ok"}, 0, false},
		"degraded":    {503, webutil.HealthBody{Status: "degraded", Encryption: "mismatch"}, 0, true},
		"unhealthy":   {503, webutil.HealthBody{Status: "unhealthy"}, 1, false},
		"garbage":     {503, webutil.HealthBody{}, 1, false},
		"unavailable": {502, webutil.HealthBody{Status: "degraded"}, 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			code, msg := healthcheckResult(tc.status, tc.body)
			if code != tc.wantCode || (msg != "") != tc.wantMsg {
				t.Fatalf("got (%d, %q)", code, msg)
			}
		})
	}
}

// TestUnknownSubcommandExits2 pins security requirement 12: a mistyped
// command is a usage error, never a second server on the live database.
func TestUnknownSubcommandExits2(t *testing.T) {
	var out, errOut bytes.Buffer
	if code, handled := dispatch([]string{"porymcp", "rekeyy"}, &out, &errOut); !handled || code != 2 {
		t.Fatalf("got (%d, %v)", code, handled)
	}
	if !strings.Contains(errOut.String(), "usage") || !strings.Contains(errOut.String(), "rekeyy") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if _, handled := dispatch([]string{"porymcp"}, &out, &errOut); handled {
		t.Fatal("a bare invocation must start the server")
	}
}
