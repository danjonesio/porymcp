package store

import (
	"context"
	"errors"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrInUse         = errors.New("resource is still referenced")
	ErrInvalidCursor = errors.New("invalid cursor")
)

type Store interface {
	CreateUpstream(ctx context.Context, u *models.Upstream) error
	GetUpstream(ctx context.Context, id string) (*models.Upstream, error)
	GetUpstreamBySlug(ctx context.Context, slug string) (*models.Upstream, error)
	ListUpstreams(ctx context.Context) ([]models.Upstream, error)

	// UpdateUpstream writes every mutable field except slug and, unless
	// writeAuth, except auth_config. Both flags shape the one statement
	// (UpdateUpstream runs with no transaction, so there is no second statement
	// for a crash to land between). resetTest appends `last_test_at=NULL,
	// last_test_ok=NULL` (the caller passes ResetTest when url, transport,
	// auth_type or auth_config changed) so a dot never vouches for a
	// configuration nobody tested; the two columns are never written from the
	// struct. writeAuth adds auth_config to the SET list (the caller passes
	// WriteAuth only when the request carried a credential) so an edit that did
	// not touch the credential never rewrites the ciphertext it read.
	UpdateUpstream(ctx context.Context, u *models.Upstream, resetTest, writeAuth bool) error

	// RecordUpstreamTest stamps one row with the outcome of one deliberate
	// connection test. One statement, its own method rather than two more fields
	// on UpdateUpstream: the two writers race (an operator can save an edit while
	// a ten-second handshake is in flight), and a full-row UPDATE built from a row
	// read before the handshake would resurrect the pre-edit url and credential.
	//
	// seen is the row's updated_at as read before the handshake; the UPDATE is
	// conditioned on it, so a result for a configuration edited in the meantime is
	// dropped rather than vouching for settings it never tested. The compare is on
	// the canonical string fmtTime(seen): every writer of updated_at is fmtTime, the
	// column is TEXT on both drivers, and schema step 6 rewrote every stored value
	// to that layout, so the reformat reproduces the stored bytes exactly. A row
	// edited by hand after that into some other spelling can never match and
	// records nothing, fail closed, the same way the migration steps treat
	// hand-edited rows. updated_at is
	// not bumped: a test is not an edit. Returns ErrNotFound when no row matched,
	// deleted, or edited since seen. Between two overlapping tests of one unchanged
	// row the later write wins, deliberately.
	RecordUpstreamTest(ctx context.Context, id string, at time.Time, ok bool, seen time.Time) error

	// SwapUpstreamAuth replaces auth_config when it still holds expect, in one
	// statement, the compare-and-swap RekeyUpstreams uses. It is the write a
	// token refresh makes (PORM-139): updated_at, last_test_at and last_test_ok
	// are untouched, because a refresh is not an edit, the era cache keys on
	// updated_at, and RecordUpstreamTest's compare must keep matching across
	// a refresh. Returns ErrNotFound when no row matched: deleted, or changed
	// since expect was read (another refresh, a rekey re-wrap, a PATCH, a
	// revoke). The caller re-reads to tell those apart; it never retries
	// blind, because a rotated refresh token is spent the moment it is used.
	SwapUpstreamAuth(ctx context.Context, id string, expect, next []byte) error

	// ConnectUpstreamAuth writes auth_config (nil writes the empty string),
	// sets updated_at to at and clears the last test, conditioned on
	// updated_at = seen and auth_type = 'oauth'. It is the write the OAuth
	// callback and revoke make: an operator change, so open streams end and
	// the era cache resets, and one that must not land on a row edited since
	// the flow started (the token was minted for the old URL). Returns
	// ErrNotFound on a miss, as RecordUpstreamTest does.
	ConnectUpstreamAuth(ctx context.Context, id string, next []byte, seen, at time.Time) error

	DeleteUpstream(ctx context.Context, id string) error

	CreateGroup(ctx context.Context, g *models.Group) error
	GetGroup(ctx context.Context, id string) (*models.Group, error)
	ListGroups(ctx context.Context) ([]models.Group, error)
	UpdateGroup(ctx context.Context, g *models.Group) error
	DeleteGroup(ctx context.Context, id string) error

	CreateVirtualKey(ctx context.Context, a *models.VirtualKey) error
	GetVirtualKey(ctx context.Context, id string) (*models.VirtualKey, error)
	GetVirtualKeyByLookup(ctx context.Context, lookup string) (*models.VirtualKey, error)
	ListVirtualKeys(ctx context.Context) ([]models.VirtualKey, error)
	UpdateVirtualKey(ctx context.Context, a *models.VirtualKey) error
	DeleteVirtualKey(ctx context.Context, id string) error
	TouchVirtualKey(ctx context.Context, id string) error

	InsertAuditLog(ctx context.Context, e *models.AuditLog) error
	ListAuditLogs(ctx context.Context, f models.LogFilter) (logs []models.AuditLog, next string, err error)
	GetAuditLog(ctx context.Context, id string) (*models.AuditLog, error)

	// InsertAdminEvent writes one management-plane event. It is a separate
	// statement from the mutation it describes: Store exposes no transaction
	// and every mutating method runs standalone, so a crash between the two
	// loses the event and keeps the change. The API accepts that and logs a
	// failed write at Error (internal/api/admin_events.go).
	InsertAdminEvent(ctx context.Context, e *models.AdminEvent) error
	// ListAdminEvents returns the newest page first, with the cursor for the
	// next page or "" on the last one. Limit outside 1..200 becomes 50.
	ListAdminEvents(ctx context.Context, f models.AdminEventFilter) (events []models.AdminEvent, next string, err error)

	Stats(ctx context.Context) (*models.Stats, error)
	Ping(ctx context.Context) error
	Close() error
}
