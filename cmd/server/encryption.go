package main

import (
	"context"
	"log/slog"

	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
)

// checkEncryption is the boot integrity pass (PORM-52). It reads every stored
// credential once (through credential.Sweep, which keeps no plaintext and
// reports counts, ids and names only) and decides three things in this order:
//
//  1. The ephemeral-key guard. ENCRYPTION_KEY unset against a database that
//     holds stored credentials is the one refusal to start: every one of them
//     would be unreadable, and the proxy must not begin calling upstreams
//     naked. Under an ephemeral key with nothing stored the verdict is ok
//     with no compare and no stamp (a per-boot random key must never be
//     recorded). Note store.Open has already migrated by now; "refuses to
//     start" is not "touched nothing".
//  2. Rows decide. One or more rows that no configured key opens is the
//     mismatch verdict: one Error record carrying the stored and current
//     fingerprints, the counts, the affected ids and names and a hint, never
//     a value, and /health degrades. The fingerprint comparison explains,
//     it never triggers: a fingerprint that differs while every credential
//     opens (a rotation window, a key replaced on an empty install, a
//     restored backup) is not an outage. A mismatch never stamps.
//  3. Otherwise ok. Unusable rows (nothing stored, or a value the auth type
//     cannot send) get a Warn naming them, the fix is the credential, never the key, and
//     /health is not touched. Rows that opened only under a previous key get
//     the "rotation pending" Warn and no stamp: only `porymcp rekey` moves an
//     existing fingerprint. The current fingerprint is recorded iff the sweep
//     proved it, no row under a previous key, the stored value differs, and
//     either nothing was stored or at least one credential opened under it
//     (never on the vacuous evidence of an empty table over an existing
//     fingerprint). Every start logs one Info line with the fingerprint, so a
//     rotation is visible as the fingerprint changing between two boots even
//     when the rekey command's own output was lost.
//
// Ids and names reach the log; urls and decrypted bytes never do. The stored
// fingerprint is operator-writable text and is validated before it is
// compared or logged.
func checkEncryption(ctx context.Context, st *store.SQLStore, cfg *config.Config, log *slog.Logger) (string, error) {
	ups, err := st.ListUpstreams(ctx)
	if err != nil {
		return "", err
	}
	keys := cfg.Keyring()
	rep := credential.Sweep(keys, ups)

	if err := cfg.CheckEphemeralKey(rep.Credentials); err != nil {
		return "", err
	}
	if cfg.EphemeralEnc {
		return webutil.EncryptionOK, nil
	}

	current := keys.Fingerprint()
	stored, err := st.Meta(ctx, store.EncryptionKeyFPKey)
	if err != nil {
		return "", err
	}
	if stored != "" && !crypto.IsFingerprint(stored) {
		log.Warn("ignoring malformed encryption_key_fp in schema_meta; treating it as absent")
		stored = ""
	}
	storedField := stored
	if storedField == "" {
		storedField = "none"
	}

	if rep.Undecryptable >= 1 {
		log.Error("ENCRYPTION_KEY does not match the key that encrypted this database; stored credentials cannot be read",
			"stored_fingerprint", storedField, "current_fingerprint", current,
			"credentials", rep.Credentials, "undecryptable", rep.Undecryptable, "under_previous", rep.UnderPrevious,
			"upstream_ids", rep.IDs, "upstream_names", rep.Names, "not_listed", rep.NotListed,
			"hint", "restore the previous key, or set ENCRYPTION_KEY_PREVIOUS to it, restart, and run porymcp rekey. A row whose key is gone can instead be switched to auth_type none (PATCH /api/v1/upstreams/{id}), which removes the stored credential without it; restart afterwards so /health reports encryption: ok")
		return webutil.EncryptionMismatch, nil
	}

	if rep.Unreadable >= 1 {
		log.Warn("stored credentials are not usable for their auth type; re-enter them, or switch the upstream to auth_type none",
			"unreadable", rep.Unreadable, "upstream_ids", rep.UnreadableIDs, "upstream_names", rep.UnreadableNames,
			"not_listed", rep.UnreadableNotListed)
	}
	if rep.UnderPrevious >= 1 {
		log.Warn("encryption key rotation pending; run porymcp rekey, then remove ENCRYPTION_KEY_PREVIOUS and restart",
			"under_previous", rep.UnderPrevious, "stored_fingerprint", storedField, "current_fingerprint", current)
	}

	recorded := false
	if rep.UnderPrevious == 0 && stored != current && (stored == "" || rep.Credentials >= 1) {
		if stored != "" {
			log.Warn("stored fingerprint differs from the current key but every credential opens under it; recording the current fingerprint",
				"stored_fingerprint", stored, "current_fingerprint", current, "credentials", rep.Credentials)
		}
		if err := st.SetMeta(ctx, store.EncryptionKeyFPKey, current); err != nil {
			log.Error("could not record the encryption key fingerprint", "err", err)
		} else {
			recorded = true
		}
	}
	log.Info("encryption key verified", "fingerprint", current, "credentials", rep.Credentials, "recorded", recorded)
	return webutil.EncryptionOK, nil
}
