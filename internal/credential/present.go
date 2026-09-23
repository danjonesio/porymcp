package credential

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// The refresh path (PORM-139). Read answers "can this stored credential be
// presented"; Present answers it too, and for an oauth row renews the token
// set first when it is about to lapse. The renewal is the one place PoryMCP
// spends a refresh token, and most vendors rotate that token on every use
// and treat a second use as theft, so everything below is shaped to spend it
// exactly once per process: one lock per upstream shared by every Presenter,
// a re-read under the lock, a compare-and-swap that never retries blind, and
// a vendor call that runs on its own context so a caller who gives up cannot
// abandon a token the vendor has already rotated.

const (
	// refreshWindow is how close to expires_at a refresh starts. Inside it
	// the stored token is still good, so a vendor that cannot be reached
	// costs nothing until the token actually lapses.
	refreshWindow = 60 * time.Second
	// refreshVendorBudget bounds the token endpoint call. With the write
	// budget it stays inside the server's 10 s shutdown grace, and the call
	// runs in the caller's goroutine so Shutdown waits for it.
	refreshVendorBudget = 8 * time.Second
	// refreshWriteBudget bounds the store write after the vendor answered.
	refreshWriteBudget = 2 * time.Second
	// refreshHoldOff is how long a transient failure keeps the vendor from
	// being asked again by the next callers, so a token endpoint that is
	// down is not hammered once per agent call.
	refreshHoldOff = 30 * time.Second
)

// Caller is who asked for the credential, for the refresh event: the proxy
// (actor proxy, no address) or an administrator through the discover route
// (actor admin, the client address). RequestID is the caller's own id so the
// event joins the audit row of the call that caused the refresh.
type Caller struct {
	Actor      string
	RemoteAddr string
	RequestID  string
}

// lockEntry is one upstream's lock plus the hold-off a transient failure
// set. The channel has one slot: holding its token is holding the lock, and
// acquiring through select is what lets a waiter give up on its context,
// which a sync.Mutex cannot.
type lockEntry struct {
	ch         chan struct{}
	retryAfter time.Time
}

var locks = struct {
	mu sync.Mutex
	m  map[string]*lockEntry
}{m: map[string]*lockEntry{}}

func lockFor(id string) *lockEntry {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	e := locks.m[id]
	if e == nil {
		e = &lockEntry{ch: make(chan struct{}, 1)}
		locks.m[id] = e
	}
	return e
}

// resetLocks forgets every lock and hold-off. Tests only.
func resetLocks() {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	locks.m = map[string]*lockEntry{}
}

// LockUpstream takes the process-wide per-upstream lock and returns the
// function that releases it. The map is package-level on purpose: the API's
// discover route and the proxy each hold their own Presenter, and the lock is
// what must be shared. The callback, revoke and an oauth PATCH take it too,
// so a connect, a disconnect and a refresh on one row never interleave. The
// wait is bounded by ctx.
func LockUpstream(ctx context.Context, id string) (unlock func(), err error) {
	e := lockFor(id)
	select {
	case e.ch <- struct{}{}:
		return func() { <-e.ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Presenter is Read plus the refresh. One per package that presents
// credentials (the API builds one on its discovery client, the proxy on a
// client of its own); the lock they share is package state.
type Presenter struct {
	keys   crypto.Keyring
	store  store.Store
	client *mcpclient.Client
	log    *slog.Logger
	now    func() time.Time
}

func NewPresenter(k crypto.Keyring, st store.Store, c *mcpclient.Client, log *slog.Logger) *Presenter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Presenter{keys: k, store: st, client: c, log: log, now: time.Now}
}

// SetClock replaces the time source. Pass nil to restore time.Now. Tests use
// it to reach an expiry without sleeping, as they do with auth.Limiter.
func (p *Presenter) SetClock(now func() time.Time) {
	if now == nil {
		p.now = time.Now
		return
	}
	p.now = now
}

// Present returns the plaintext to present for u. For every auth type but
// oauth it is Read. For oauth it refuses a set whose resource is not the
// row's URL or that holds no access token (ErrUnreadable), returns the set
// as stored when expires_at is more than refreshWindow away, and otherwise
// refreshes under the per-upstream lock. When the refresh fails it keeps
// presenting the stored token until that token lapses, then returns
// ErrExpired (the vendor refused the grant, or there was no refresh token)
// or ErrRefreshFailed (the vendor could not be reached). It never runs
// inside a store transaction.
func (p *Presenter) Present(ctx context.Context, u *models.Upstream, by Caller) (json.RawMessage, error) {
	if u.AuthType != models.AuthOAuth {
		return Read(p.keys, u.AuthType, u.AuthConfig)
	}
	plain, set, err := p.open(u)
	if err != nil {
		return nil, err
	}
	now := p.now()
	if !due(set, now) {
		return plain, nil
	}

	unlock, err := LockUpstream(ctx, u.ID)
	if err != nil {
		// The caller gave up waiting: a bare sentinel, because the text
		// reaches an audit row.
		return nil, ErrRefreshFailed
	}
	unlocked := false
	release := func() {
		if !unlocked {
			unlocked = true
			unlock()
		}
	}
	defer release()

	// The row again, under the lock: a waiter finds the leader's set here and
	// never calls the vendor; a stale reader (one that read before an earlier
	// refresh finished) is caught the same way.
	fresh, err := p.store.GetUpstream(ctx, u.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnreadable
		}
		p.log.Error("upstream oauth row could not be read before a refresh", "upstream_id", u.ID, "request_id", by.RequestID, "err_class", errClass(err))
		return nil, ErrRefreshFailed
	}
	if fresh.AuthType != models.AuthOAuth {
		return nil, ErrUnreadable
	}
	plain, set, err = p.open(fresh)
	if err != nil {
		return nil, err
	}
	if !due(set, now) {
		return plain, nil
	}
	e := lockFor(u.ID)
	if now.Before(e.retryAfter) {
		return stillValid(plain, set, now, ErrRefreshFailed)
	}
	if set.RefreshToken == "" {
		return stillValid(plain, set, now, ErrExpired)
	}

	// The vendor call, on its own context: the caller's may be cancelled by
	// an agent that went away, or, on the proxy, carry a budget whose trace
	// hook must not fire on this request.
	vctx, cancel := context.WithTimeout(context.Background(), refreshVendorBudget)
	renewed, err := p.client.Refresh(vctx, set, now)
	cancel()
	if err != nil {
		var oe *mcpclient.OAuthError
		reason := "transport"
		if errors.As(err, &oe) && oe.Code != "" {
			reason = oe.Code
		}
		if errors.Is(err, mcpclient.ErrGrantRejected) {
			// The grant is dead. Drop the refresh token so the row reads
			// expired once the access token lapses and nothing retries a
			// spent token on every call.
			dropped := set
			dropped.RefreshToken = ""
			p.swap(u.ID, fresh.AuthConfig, dropped)
			p.log.Warn("upstream oauth refresh rejected", "upstream_id", u.ID, "request_id", by.RequestID, "reason", reason)
			return stillValid(plain, set, now, ErrExpired)
		}
		e.retryAfter = now.Add(refreshHoldOff)
		p.log.Warn("upstream oauth refresh failed", "upstream_id", u.ID, "request_id", by.RequestID, "reason", reason, "retry_after_s", int(refreshHoldOff/time.Second))
		return stillValid(plain, set, now, ErrRefreshFailed)
	}

	next, err := p.seal(renewed)
	if err != nil {
		return nil, err
	}
	renewedPlain, _ := json.Marshal(renewed)
	rotated := renewed.RefreshToken != set.RefreshToken
	wctx, wcancel := context.WithTimeout(context.Background(), refreshWriteBudget)
	err = p.store.SwapUpstreamAuth(wctx, u.ID, fresh.AuthConfig, next)
	wcancel()
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		// The bytes moved since the re-read. Either the row was re-wrapped
		// (a rekey, a re-seal) and still holds the refresh token just spent,
		// in which case the new set is the only valid one and is written
		// against the new bytes; or another writer replaced the grant, and
		// theirs wins.
		rctx, rcancel := context.WithTimeout(context.Background(), refreshWriteBudget)
		again, gerr := p.store.GetUpstream(rctx, u.ID)
		rcancel()
		if gerr != nil && !errors.Is(gerr, store.ErrNotFound) {
			// The vendor has the new grant; a store that cannot even be read
			// must not cost it. This call succeeds on the new token.
			p.log.Error("upstream oauth token set not stored after refresh; the upstream may need Connect again", "upstream_id", u.ID, "request_id", by.RequestID, "err_class", errClass(gerr))
			return renewedPlain, nil
		}
		if gerr != nil || again.AuthType != models.AuthOAuth || len(again.AuthConfig) == 0 {
			return nil, ErrUnreadable
		}
		theirs, theirSet, rerr := p.open(again)
		if rerr != nil {
			return nil, rerr
		}
		if theirSet.RefreshToken != set.RefreshToken {
			return stillValid(theirs, theirSet, now, ErrExpired)
		}
		wctx, wcancel := context.WithTimeout(context.Background(), refreshWriteBudget)
		err = p.store.SwapUpstreamAuth(wctx, u.ID, again.AuthConfig, next)
		wcancel()
		if err != nil {
			p.log.Error("upstream oauth token set not stored after refresh; the upstream may need Connect again", "upstream_id", u.ID, "request_id", by.RequestID, "err_class", errClass(err))
			return renewedPlain, nil
		}
	default:
		// The vendor has the new grant and the store refused to keep it.
		// This call still succeeds on the new token; the next refresh may
		// find the old refresh token spent and mark the row expired.
		p.log.Error("upstream oauth token set not stored after refresh; the upstream may need Connect again", "upstream_id", u.ID, "request_id", by.RequestID, "err_class", errClass(err))
		return renewedPlain, nil
	}

	// The lock is released before the event insert: a callback or a revoke
	// waiting on it should not queue behind an audit write.
	release()
	audit.RecordAdmin(context.Background(), p.store, p.log, models.AdminEvent{
		Actor:        by.Actor,
		Action:       models.ActionUpstreamOAuthRefresh,
		ResourceID:   u.ID,
		ResourceName: fresh.Name,
		RequestID:    by.RequestID,
		RemoteAddr:   by.RemoteAddr,
	})
	p.log.Info("upstream oauth token refreshed", "upstream_id", u.ID, "request_id", by.RequestID, "refresh_token_rotated", rotated)
	return renewedPlain, nil
}

// open reads an oauth row and refuses a set that must never be presented: one
// whose resource is not the row's URL (the token was minted for another
// server) or one with no access token (Read already says so).
func (p *Presenter) open(u *models.Upstream) (json.RawMessage, models.OAuthTokenSet, error) {
	plain, err := Read(p.keys, u.AuthType, u.AuthConfig)
	if err != nil {
		return nil, models.OAuthTokenSet{}, err
	}
	var set models.OAuthTokenSet
	if json.Unmarshal(plain, &set) != nil || set.Resource != u.URL {
		return nil, models.OAuthTokenSet{}, ErrUnreadable
	}
	return plain, set, nil
}

func (p *Presenter) seal(set models.OAuthTokenSet) ([]byte, error) {
	raw, err := json.Marshal(set)
	if err != nil {
		return nil, ErrUnreadable
	}
	enc, err := p.keys.Seal(raw)
	if err != nil {
		return nil, ErrUnreadable
	}
	return []byte(enc), nil
}

// swap writes set over expect, best effort: a miss means another writer got
// there and their bytes stand.
func (p *Presenter) swap(id string, expect []byte, set models.OAuthTokenSet) {
	next, err := p.seal(set)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshWriteBudget)
	defer cancel()
	_ = p.store.SwapUpstreamAuth(ctx, id, expect, next)
}

// due reports whether a set is inside the refresh window.
func due(set models.OAuthTokenSet, now time.Time) bool {
	return !set.ExpiresAt.IsZero() && !set.ExpiresAt.After(now.Add(refreshWindow))
}

// stillValid presents the stored token while it has not lapsed, and lapsed
// afterwards.
func stillValid(plain json.RawMessage, set models.OAuthTokenSet, now time.Time, lapsed error) (json.RawMessage, error) {
	if set.ExpiresAt.After(now) {
		return plain, nil
	}
	return nil, lapsed
}

// errClass names a store error without its text, which can carry a path.
func errClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "store"
}
