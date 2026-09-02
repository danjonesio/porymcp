package store

import (
	"context"
	"errors"
	"time"

	"github.com/netcasklabs/porymcp/internal/models"
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
	// the canonical string fmtTime(seen): every writer of updated_at is fmtTime and
	// the column is TEXT on both drivers, so the reformat reproduces the stored
	// bytes exactly. A row whose updated_at came from outside PoryMCP (a +00:00
	// offset, trailing zeros in the fraction) can never match and records nothing,
	// fail closed, the same way steps 1 and 3 treat hand-edited rows. updated_at is
	// not bumped: a test is not an edit. Returns ErrNotFound when no row matched,
	// deleted, or edited since seen. Between two overlapping tests of one unchanged
	// row the later write wins, deliberately.
	RecordUpstreamTest(ctx context.Context, id string, at time.Time, ok bool, seen time.Time) error

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

	Stats(ctx context.Context) (*models.Stats, error)
	Ping(ctx context.Context) error
	Close() error
}
