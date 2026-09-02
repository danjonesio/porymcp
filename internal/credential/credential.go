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

	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/mcpclient"
	"github.com/netcasklabs/porymcp/internal/models"
)

// The four values auth_status can take. none is decided by auth_type alone —
// whatever blob the dashboard happened to store beside it — so the API's
// "none" means exactly "this upstream sends no credential".
const (
	StatusNone          = "none"
	StatusOK            = "ok"
	StatusUndecryptable = "undecryptable"
	StatusUnreadable    = "unreadable"
)

var (
	// ErrUndecryptable: no configured key opens the stored bytes — the key
	// changed, or the bytes are corrupt. The operator's fix is a key.
	ErrUndecryptable = errors.New("credential undecryptable")
	// ErrUnreadable: nothing is stored, or the bytes open but hold nothing the
	// auth type can send (mcpclient.CheckCredential refused them). The
	// operator's fix is the credential, and it is never a key problem.
	ErrUnreadable = errors.New("credential unreadable")
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
// Read's outcome through StatusFor.
func Status(k crypto.Keyring, authType string, stored []byte) string {
	if authType == models.AuthNone || authType == "" {
		return StatusNone
	}
	_, err := Read(k, authType, stored)
	return StatusFor(err)
}

// StatusFor maps Read's outcome to the auth_status value. It is the one
// mapping: presentUpstream calls it beside its own Read (which it keeps for
// auth_hint's plaintext), so the API's answer and Status's cannot drift. An
// error Read never returns classifies as undecryptable rather than ok — a
// future error value must fail visible, not green.
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

// maxListed bounds the id and name lists a Report carries, so one boot line
// stays one line on a large deployment; NotListed says how many were cut.
const maxListed = 20

// Report is what Sweep learned about every upstream, as counts and names —
// never a value. Rows with auth_type none are skipped entirely: they need no
// credential, so they are never counted and never degrade anything.
type Report struct {
	// Credentials is the number of rows that need a credential and hold a
	// stored blob — the rows an ephemeral key would make unreadable.
	Credentials int
	// Undecryptable is the number of rows no configured key opens. Only this
	// count drives the mismatch verdict.
	Undecryptable int
	// Unreadable is the number of rows that need a credential and either hold
	// nothing or hold bytes their auth type cannot send. Never a key problem.
	Unreadable int
	// UnderPrevious is the number of rows that opened only under a previous
	// key — a rotation that has not been finished with `porymcp rekey`.
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
