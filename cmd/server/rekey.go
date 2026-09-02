package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/store"
)

// rekey is the `porymcp rekey` subcommand (PORM-52): it re-seals every stored
// credential under the current ENCRYPTION_KEY and stamps that key's
// fingerprint, in one transaction, so a rotation begun with
// ENCRYPTION_KEY_PREVIOUS can finish and the previous key can be dropped.
//
// It is a deliberate, once-per-rotation manual step: run it from the shipped
// image with `docker compose exec porymcp /porymcp rekey`, never from an
// entrypoint, an init container or a deploy hook. It opens the database,
// which runs the schema migration, so it must not run before every replica is
// on this build. It is safe against a live server: a credential written while
// it runs aborts the whole run (see store.RekeyUpstreams) and re-running the
// command is the retry.
//
// Its output is the binary's one log format, slog JSON on stdout, at a FIXED
// level: the counts are the command's result, not telemetry, and LOG_LEVEL
// must not be able to hide them. Fingerprints, counts, ids and names only,
// never a key, a ciphertext or a plaintext. Exit 0 on success (a second run
// reports rewritten=0), 1 on any failure, with nothing written.
func rekey(out io.Writer) int {
	log := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		log.Error("rekey failed: config", "err", err)
		return 1
	}
	// Never cfg.LogWarnings here: it prints a generated admin key.
	if cfg.EphemeralEnc {
		log.Error("rekey needs ENCRYPTION_KEY; refusing to re-encrypt under a key generated at startup")
		return 1
	}
	st, err := store.Open(cfg.DatabaseURL)
	if err != nil {
		log.Error("rekey failed: database", "err", err)
		return 1
	}
	defer st.Close()

	keys := cfg.Keyring()
	sum, err := st.RekeyUpstreams(context.Background(), keys.Fingerprint(), rekeyRewriter(keys, keys.Seal))
	if err != nil {
		var dead *undecryptableRows
		if errors.As(err, &dead) {
			log.Error("rekey failed: a stored credential cannot be decrypted with any configured key; no credentials were changed",
				"undecryptable", len(dead.ids), "upstream_ids", dead.ids, "upstream_names", dead.names,
				"hint", "re-enter the credential (PATCH /api/v1/upstreams/{id}) or delete the upstream, then re-run")
			return 1
		}
		log.Error("rekey failed; no credentials were changed", "err", err)
		return 1
	}
	prev := sum.PreviousFingerprint
	if prev == "" {
		prev = "none"
	}
	log.Info("rekey complete", "rewritten", sum.Rewritten, "already_current", sum.AlreadyCurrent,
		"no_credential", sum.NoCredential, "previous_fingerprint", prev, "fingerprint", keys.Fingerprint())
	return 0
}

// undecryptableRows is the one error the rewriter returns for rows no
// configured key opens: every such row in one run, ids and names only.
type undecryptableRows struct{ ids, names []string }

func (e *undecryptableRows) Error() string {
	return fmt.Sprintf("%d stored credentials cannot be decrypted with any configured key", len(e.ids))
}

// rekeyRewriter is the crypto half of RekeyUpstreams: it classifies EVERY row
// before deciding (so one run names every dead row) and returns one
// replacement per row. A v1 value already under the current key is left alone
// (""); a legacy value is always rewritten, whatever key it opens under,
// because it carries no AAD. Every new value is opened again and compared to
// the plaintext before it is handed back: a bug in the writer must not convert
// the whole table to unrecoverable bytes in one commit. seal is the keyring's
// Seal in production and a parameter so that check can be tested.
func rekeyRewriter(k crypto.Keyring, seal func([]byte) (string, error)) func([]store.RekeyRow) ([]string, error) {
	return func(rows []store.RekeyRow) ([]string, error) {
		next := make([]string, len(rows))
		var dead undecryptableRows
		for i, r := range rows {
			plain, by, err := k.Open(r.Stored)
			if err != nil {
				dead.ids = append(dead.ids, r.ID)
				dead.names = append(dead.names, r.Name)
				continue
			}
			if crypto.IsV1(r.Stored) && by == k.Fingerprint() {
				continue
			}
			enc, err := seal(plain)
			if err != nil {
				return nil, fmt.Errorf("rekey: upstream %s: %w", r.ID, err)
			}
			check, _, err := k.Open(enc)
			if err != nil || !bytes.Equal(check, plain) {
				return nil, fmt.Errorf("rekey: upstream %s: the re-sealed value does not round-trip; nothing written", r.ID)
			}
			next[i] = enc
		}
		if len(dead.ids) > 0 {
			return nil, &dead
		}
		return next, nil
	}
}
