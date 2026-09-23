// Package credential is the one answer to "can PoryMCP use this stored
// credential?". The proxy (before it dials), the management API (auth_status,
// /stats, the discover gate) and the boot integrity sweep all ask through
// Read, Status and Sweep, so a row cannot read green in the table while the
// proxy sends a bare request, and a wrong ENCRYPTION_KEY cannot be reported as
// a bad token.
//
// Nothing here logs, stores or returns a plaintext beyond the caller that
// asked for it: Sweep classifies each row and drops the bytes, and the two
// sentinels carry no wrapped detail, because they reach audit error_message,
// which is not redacted.
package credential

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

// The five values auth_status can take. none is decided by auth_type alone
// (whatever blob the dashboard happened to store beside it) so the API's
// "none" means exactly "this upstream sends no credential". expired is an
// oauth row whose access token has lapsed with no refresh token to renew it
// (PORM-139); it is derived from the plaintext by Expired and never stored.
const (
	StatusNone          = "none"
	StatusOK            = "ok"
	StatusUndecryptable = "undecryptable"
	StatusUnreadable    = "unreadable"
	StatusExpired       = "expired"
)

var (
	// ErrUndecryptable: no configured key opens the stored bytes, the key
	// changed, or the bytes are corrupt. The operator's fix is a key.
	ErrUndecryptable = errors.New("credential undecryptable")
	// ErrUnreadable: nothing is stored, or the bytes open but hold nothing the
	// auth type can send (mcpclient.CheckCredential refused them). The
	// operator's fix is the credential, and it is never a key problem.
	ErrUnreadable = errors.New("credential unreadable")
	// ErrExpired: an oauth access token has lapsed and the vendor refused to
	// renew it, or issued no refresh token. Returned by Presenter.Present
	// only, never by Read. The operator's fix is Connect again. Distinct from
	// the proxy's "virtual key expired" on purpose.
	ErrExpired = errors.New("credential expired")
	// ErrRefreshFailed: an oauth access token has lapsed and the vendor's
	// token endpoint could not be reached or answered something unusable.
	// The next call retries after a hold-off. Returned by Present only.
	ErrRefreshFailed = errors.New("credential refresh failed")
)

// Read returns the plaintext auth_config the proxy should present, or the
// reason it cannot. auth_type none is (nil, nil) without touching the blob:
// such an upstream sends no credential, so nothing stored beside it matters
// until auth_type changes. Both errors are the bare sentinels.
func Read(k crypto.Keyring, authType string, stored []byte) (json.RawMessage, error) {
	plain, _, err := read(k, authType, stored)
	return plain, err
}

// read is Read plus the fingerprint of the key that opened the blob, which
// Sweep needs to tell "sealed under the current key" from "sealed under a
// previous one". openedBy is set whenever Open succeeded, even when the
// plaintext then turned out to be unusable.
func read(k crypto.Keyring, authType string, stored []byte) (json.RawMessage, string, error) {
	if authType == models.AuthNone || authType == "" {
		return nil, "", nil
	}
	if len(stored) == 0 {
		return nil, "", ErrUnreadable
	}
	plain, by, err := k.Open(string(stored))
	if err != nil {
		return nil, "", ErrUndecryptable
	}
	if err := mcpclient.CheckCredential(authType, plain); err != nil {
		return nil, by, ErrUnreadable
	}
	return plain, by, nil
}

// Status classifies one row for the API: none iff auth_type is none, then
// Read's outcome through StatusOf.
func Status(k crypto.Keyring, authType string, stored []byte) string {
	if authType == models.AuthNone || authType == "" {
		return StatusNone
	}
	plain, err := Read(k, authType, stored)
	return StatusOf(authType, plain, err, time.Now())
}

// StatusFor maps Read's outcome to the auth_status value. An error Read never
// returns classifies as undecryptable rather than ok, a future error value
// must fail visible, not green. StatusOf is the one mapping callers use; this
// is its expiry-blind half.
func StatusFor(err error) string {
	switch {
	case err == nil:
		return StatusOK
	case errors.Is(err, ErrUnreadable):
		return StatusUnreadable
	default:
		return StatusUndecryptable
	}
}

// StatusOf is the one expiry-aware mapping: StatusFor on Read's error, then
// expired when the plaintext Read handed back has lapsed with no refresh
// token. presentUpstream calls it beside its own Read (which it keeps for
// auth_hint's plaintext), and Status calls it, so the API's answer and
// Status's cannot drift.
func StatusOf(authType string, plain json.RawMessage, readErr error, now time.Time) string {
	if readErr != nil {
		return StatusFor(readErr)
	}
	if Expired(authType, plain, now) {
		return StatusExpired
	}
	return StatusOK
}

// Expired reports an oauth plaintext whose access token has lapsed with no
// refresh token to renew it: expires_at set, not after now, refresh_token
// empty. It is the one rule behind the expired status, and it covers both
// "the vendor issued no refresh token" and "the vendor refused the refresh",
// because a refused refresh drops the refresh token (Presenter). It needs no
// network and never stores anything.
func Expired(authType string, plain json.RawMessage, now time.Time) bool {
	if authType != models.AuthOAuth || len(plain) == 0 {
		return false
	}
	var set models.OAuthTokenSet
	if json.Unmarshal(plain, &set) != nil {
		return false
	}
	return !set.ExpiresAt.IsZero() && !set.ExpiresAt.After(now) && set.RefreshToken == ""
}

// maxListed bounds the id and name lists a Report carries, so one boot line
// stays one line on a large deployment; NotListed says how many were cut.
const maxListed = 20

// Report is what Sweep learned about every upstream, as counts and names,
// never a value. Rows with auth_type none are skipped entirely: they need no
// credential, so they are never counted and never degrade anything.
type Report struct {
	// Credentials is the number of rows that need a credential and hold a
	// stored blob, the rows an ephemeral key would make unreadable.
	Credentials int
	// Undecryptable is the number of rows no configured key opens. Only this
	// count drives the mismatch verdict.
	Undecryptable int
	// Unreadable is the number of rows that need a credential and either hold
	// nothing or hold bytes their auth type cannot send. Never a key problem.
	Unreadable int
	// Unconnected is the subset of Unreadable that are oauth rows: nothing
	// stored, or a client id with no token yet. Their fix is Connect on the
	// Upstreams page, not a re-entered value, so the boot line says so. They
	// stay inside Unreadable, so /stats and the row status agree. Sweep is
	// expiry-blind: a connected row whose token lapsed counts as fine here.
	Unconnected int
	// UnderPrevious is the number of rows that opened only under a previous
	// key, a rotation that has not been finished with `porymcp rekey`.
	UnderPrevious int
	// IDs and Names list the undecryptable rows, in ListUpstreams order.
	IDs, Names []string
	NotListed  int
	// UnreadableIDs and UnreadableNames list the unreadable rows.
	UnreadableIDs, UnreadableNames []string
	UnreadableNotListed            int
}

// Sweep classifies every upstream once. Each plaintext is dropped as soon as
// the row is classified; nothing is retained.
func Sweep(k crypto.Keyring, ups []models.Upstream) Report {
	var r Report
	current := k.Fingerprint()
	for i := range ups {
		u := &ups[i]
		if u.AuthType == models.AuthNone || u.AuthType == "" {
			continue
		}
		if len(u.AuthConfig) > 0 {
			r.Credentials++
		}
		_, by, err := read(k, u.AuthType, u.AuthConfig)
		if by != "" && by != current {
			r.UnderPrevious++
		}
		switch {
		case errors.Is(err, ErrUndecryptable):
			r.Undecryptable++
			if len(r.IDs) < maxListed {
				r.IDs = append(r.IDs, u.ID)
				r.Names = append(r.Names, u.Name)
			} else {
				r.NotListed++
			}
		case errors.Is(err, ErrUnreadable):
			r.Unreadable++
			if u.AuthType == models.AuthOAuth {
				r.Unconnected++
			}
			if len(r.UnreadableIDs) < maxListed {
				r.UnreadableIDs = append(r.UnreadableIDs, u.ID)
				r.UnreadableNames = append(r.UnreadableNames, u.Name)
			} else {
				r.UnreadableNotListed++
			}
		}
	}
	return r
}
