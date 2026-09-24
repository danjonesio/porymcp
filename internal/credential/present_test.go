package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/crypto"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/google/uuid"
)

// The Presenter tests (PORM-139 step 7, security requirement 8 and
// criteria 5 and 6). Every row uses a uuid id, because the lock map and its
// hold-offs are process-wide.

type rig struct {
	t     *testing.T
	st    *store.SQLStore
	keys  crypto.Keyring
	stub  *oauthstub.Server
	p     *Presenter
	log   *bytes.Buffer
	now   time.Time
	clock func() time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	resetLocks()
	st, err := store.Open(filepath.Join(t.TempDir(), "present.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	k, _ := keyring(t, 0)
	r := &rig{t: t, st: st, keys: k, stub: oauthstub.New(t), log: &bytes.Buffer{}, now: time.Now().UTC().Truncate(time.Second)}
	r.p = NewPresenter(k, st, mcpclient.New(netguard.Options{AllowLoopback: true}), slog.New(slog.NewJSONHandler(r.log, nil)))
	r.p.SetClock(func() time.Time { return r.now })
	return r
}

// set is a connected token set for the stub, expiring at exp.
func (r *rig) set(exp time.Time) models.OAuthTokenSet {
	access, refresh := r.stub.Seed()
	return models.OAuthTokenSet{
		AccessToken: access, RefreshToken: refresh, ExpiresAt: exp,
		TokenEndpoint: r.stub.TokenEndpoint(), RevocationEndpoint: r.stub.RevocationEndpoint(), Issuer: r.stub.Issuer(),
		ClientID: "cid", ClientSource: "supplied", Resource: r.stub.MCPURL(),
	}
}

func (r *rig) sealSet(set models.OAuthTokenSet) []byte {
	raw, _ := json.Marshal(set)
	return seal(r.t, r.keys, string(raw))
}

// row stores an oauth upstream holding set and returns it as the proxy would
// have read it.
func (r *rig) row(set models.OAuthTokenSet) *models.Upstream {
	r.t.Helper()
	u := &models.Upstream{
		ID: uuid.NewString(), Name: "Stub", Slug: "stub-" + uuid.NewString()[:8], URL: r.stub.MCPURL(),
		Transport: models.TransportStreamableHTTP, AuthType: models.AuthOAuth, Enabled: true,
		CreatedAt: r.now, UpdatedAt: r.now,
	}
	if set.Resource != "" || set.ClientID != "" {
		u.AuthConfig = r.sealSet(set)
	}
	if err := r.st.CreateUpstream(context.Background(), u); err != nil {
		r.t.Fatal(err)
	}
	got, err := r.st.GetUpstream(context.Background(), u.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

func (r *rig) stored(id string) models.OAuthTokenSet {
	r.t.Helper()
	u, err := r.st.GetUpstream(context.Background(), id)
	if err != nil {
		r.t.Fatal(err)
	}
	plain, err := Read(r.keys, models.AuthOAuth, u.AuthConfig)
	if err != nil {
		r.t.Fatalf("stored set: %v", err)
	}
	var set models.OAuthTokenSet
	_ = json.Unmarshal(plain, &set)
	return set
}

func decode(t *testing.T, plain json.RawMessage) models.OAuthTokenSet {
	t.Helper()
	var set models.OAuthTokenSet
	if err := json.Unmarshal(plain, &set); err != nil {
		t.Fatal(err)
	}
	return set
}

var proxyCaller = Caller{Actor: models.ActorProxy, RequestID: "req-1"}

func (r *rig) events(id string) []models.AdminEvent {
	r.t.Helper()
	all, _, err := r.st.ListAdminEvents(context.Background(), models.AdminEventFilter{})
	if err != nil {
		r.t.Fatal(err)
	}
	var out []models.AdminEvent
	for _, e := range all {
		if e.ResourceID == id {
			out = append(out, e)
		}
	}
	return out
}

func TestPresentIsReadForStaticTypes(t *testing.T) {
	r := newRig(t)
	u := &models.Upstream{ID: uuid.NewString(), AuthType: models.AuthBearer, AuthConfig: seal(t, r.keys, `{"token":"sk"}`)}
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || string(plain) != `{"token":"sk"}` {
		t.Fatalf("got %q %v", plain, err)
	}
	if _, err := r.p.Present(context.Background(), &models.Upstream{AuthType: models.AuthBearer}, proxyCaller); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("empty bearer: %v", err)
	}
}

func TestPresentReturnsFreshTokenWithoutLock(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(time.Hour))
	u := r.row(set)
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || decode(t, plain).AccessToken != set.AccessToken {
		t.Fatalf("got %s %v", plain, err)
	}
	if r.stub.Grants("refresh_token") != 0 {
		t.Fatal("a fresh token was refreshed")
	}
}

// Security requirement 5: a set minted for another resource is never
// presented, whatever the row's URL now says.
func TestPresentRefusesResourceMismatch(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(time.Hour))
	u := r.row(set)
	u.URL = r.stub.URL() + "/other"
	if err := r.st.UpdateUpstream(context.Background(), u, false, false); err != nil {
		t.Fatal(err)
	}
	u, _ = r.st.GetUpstream(context.Background(), u.ID)
	if _, err := r.p.Present(context.Background(), u, proxyCaller); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("err=%v, want ErrUnreadable", err)
	}
	if len(r.stub.Requests()) != 0 || r.stub.Grants("refresh_token") != 0 {
		t.Fatal("the stub was reached")
	}
}

func TestPresentRefreshesWithinSixtySeconds(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(30 * time.Second))
	u := r.row(set)
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil {
		t.Fatal(err)
	}
	got := decode(t, plain)
	if got.AccessToken == set.AccessToken || !r.stub.AccessValid(got.AccessToken) || got.RefreshToken == set.RefreshToken {
		t.Fatalf("not renewed: %+v", got)
	}
	if got.ExpiresAt != r.now.Add(time.Hour) {
		t.Fatalf("expires_at %v, want now+1h", got.ExpiresAt)
	}
	after, _ := r.st.GetUpstream(context.Background(), u.ID)
	if bytes.Equal(after.AuthConfig, u.AuthConfig) || !after.UpdatedAt.Equal(u.UpdatedAt) {
		t.Fatalf("blob changed=%v updated_at moved=%v", !bytes.Equal(after.AuthConfig, u.AuthConfig), !after.UpdatedAt.Equal(u.UpdatedAt))
	}
	if r.stored(u.ID).AccessToken != got.AccessToken {
		t.Fatal("the stored set is not the presented one")
	}
	// The fields refresh must not touch survive.
	if s := r.stored(u.ID); s.ClientID != "cid" || s.Resource != r.stub.MCPURL() || s.Issuer != r.stub.Issuer() {
		t.Fatalf("stored %+v", s)
	}
}

// Criterion 5: ten concurrent callers on an expired row, plus one that read
// the row before the refresh finished, cost exactly one refresh, and every
// one of them presents the new token.
func TestPresentTenConcurrentOneRefresh(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	release := r.stub.HoldToken()
	var wg sync.WaitGroup
	results := make([]models.OAuthTokenSet, 10)
	errs := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			row := *u // each caller holds its own stale copy of the row
			plain, err := r.p.Present(context.Background(), &row, proxyCaller)
			errs[i] = err
			if err == nil {
				results[i] = decode(t, plain)
			}
		}(i)
	}
	// Let the leader reach the vendor, then let everyone through.
	deadline := time.Now().Add(5 * time.Second)
	for r.stub.Grants("refresh_token") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	release()
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i].AccessToken != results[0].AccessToken || results[i].AccessToken == set.AccessToken {
			t.Fatalf("caller %d presented %q", i, results[i].AccessToken)
		}
	}
	// The late reader: it holds the pre-refresh row and asks after the fact.
	late := *u
	plain, err := r.p.Present(context.Background(), &late, proxyCaller)
	if err != nil || decode(t, plain).AccessToken != results[0].AccessToken {
		t.Fatalf("late reader: %s %v", plain, err)
	}
	if n := r.stub.Grants("refresh_token"); n != 1 {
		t.Fatalf("refresh_token grants = %d, want 1", n)
	}
	if ev := r.events(u.ID); len(ev) != 1 || ev[0].Action != models.ActionUpstreamOAuthRefresh {
		t.Fatalf("events %+v", ev)
	}
}

// Criterion 6: a rejected refresh drops the refresh token, the row reads
// expired, and the sentinel carries no token.
func TestPresentRejectedRefreshDropsRefreshToken(t *testing.T) {
	r := newRig(t)
	r.stub.RejectRefresh = true
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	_, err := r.p.Present(context.Background(), u, proxyCaller)
	if !errors.Is(err, ErrExpired) || err.Error() != "credential expired" {
		t.Fatalf("err=%v, want the bare ErrExpired", err)
	}
	stored := r.stored(u.ID)
	if stored.RefreshToken != "" || stored.AccessToken != set.AccessToken {
		t.Fatalf("stored %+v", stored)
	}
	after, _ := r.st.GetUpstream(context.Background(), u.ID)
	if got := Status(r.keys, models.AuthOAuth, after.AuthConfig); got != StatusExpired {
		t.Fatalf("status %q, want expired", got)
	}
	if len(r.events(u.ID)) != 0 {
		t.Fatal("a rejected refresh recorded an event")
	}
	// Nothing retries the dead grant.
	if _, err := r.p.Present(context.Background(), after, proxyCaller); !errors.Is(err, ErrExpired) {
		t.Fatalf("second call: %v", err)
	}
	if r.stub.Grants("refresh_token") != 1 {
		t.Fatalf("grants %d, want 1", r.stub.Grants("refresh_token"))
	}
}

func TestPresentRejectedInsideWindowPresentsUntilLapse(t *testing.T) {
	r := newRig(t)
	r.stub.RejectRefresh = true
	set := r.set(r.now.Add(30 * time.Second))
	u := r.row(set)
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || decode(t, plain).AccessToken != set.AccessToken {
		t.Fatalf("inside the window: %s %v, want the stored token", plain, err)
	}
	r.now = r.now.Add(31 * time.Second)
	after, _ := r.st.GetUpstream(context.Background(), u.ID)
	if _, err := r.p.Present(context.Background(), after, proxyCaller); !errors.Is(err, ErrExpired) {
		t.Fatalf("after the lapse: %v", err)
	}
	if r.stub.Grants("refresh_token") != 1 {
		t.Fatalf("grants %d, want 1", r.stub.Grants("refresh_token"))
	}
}

func TestPresentTransientFailureInsideWindowStillPresents(t *testing.T) {
	r := newRig(t)
	r.stub.RejectRefreshTransient = true
	set := r.set(r.now.Add(30 * time.Second))
	u := r.row(set)
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || decode(t, plain).AccessToken != set.AccessToken {
		t.Fatalf("503 inside the window: %s %v", plain, err)
	}
	// The hold-off: a second call inside it never reaches the vendor.
	r.now = r.now.Add(10 * time.Second)
	if _, err := r.p.Present(context.Background(), u, proxyCaller); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if r.stub.Grants("refresh_token") != 1 {
		t.Fatalf("grants %d, want 1 (hold-off)", r.stub.Grants("refresh_token"))
	}
	if r.stored(u.ID).RefreshToken != set.RefreshToken {
		t.Fatal("a transient failure touched the stored set")
	}
}

func TestPresentTransientFailureAfterLapseIsRefreshFailed(t *testing.T) {
	r := newRig(t)
	r.stub.RejectRefreshTransient = true
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	_, err := r.p.Present(context.Background(), u, proxyCaller)
	if !errors.Is(err, ErrRefreshFailed) || err.Error() != "credential refresh failed" {
		t.Fatalf("err=%v", err)
	}
	if _, err := r.p.Present(context.Background(), u, proxyCaller); !errors.Is(err, ErrRefreshFailed) || r.stub.Grants("refresh_token") != 1 {
		t.Fatalf("inside hold-off: err=%v grants=%d", err, r.stub.Grants("refresh_token"))
	}
	r.now = r.now.Add(refreshHoldOff + time.Second)
	r.stub.RejectRefreshTransient = false
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || !r.stub.AccessValid(decode(t, plain).AccessToken) || r.stub.Grants("refresh_token") != 2 {
		t.Fatalf("after hold-off: %s %v grants=%d", plain, err, r.stub.Grants("refresh_token"))
	}
}

// A rekey that lands between the vendor answer and the swap re-wraps the
// spent refresh token; the rotated set must still be stored.
func TestPresentConflictAfterRekeyStillStoresNewTokens(t *testing.T) {
	r := newRig(t)
	cur, _ := crypto.RandomKey()
	old, _ := crypto.RandomKey()
	oldRing := crypto.NewKeyring(old, nil)
	newRing := crypto.NewKeyring(cur, [][]byte{old})
	r.keys = oldRing
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	r.keys = newRing
	r.p = NewPresenter(newRing, r.st, mcpclient.New(netguard.Options{AllowLoopback: true}), slog.New(slog.NewJSONHandler(r.log, nil)))
	r.p.SetClock(func() time.Time { return r.now })

	release := r.stub.HoldToken()
	done := make(chan error, 1)
	var plain json.RawMessage
	go func() {
		var err error
		plain, err = r.p.Present(context.Background(), u, proxyCaller)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.stub.Grants("refresh_token") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// The rekey, as a second process would run it.
	if _, err := r.st.RekeyUpstreams(context.Background(), newRing.Fingerprint(), func(rows []store.RekeyRow) ([]string, error) {
		out := make([]string, len(rows))
		for i, row := range rows {
			p, _, err := newRing.Open(row.Stored)
			if err != nil {
				return nil, err
			}
			enc, err := newRing.Seal(p)
			if err != nil {
				return nil, err
			}
			out[i] = enc
		}
		return out, nil
	}); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := decode(t, plain)
	stored := r.stored(u.ID)
	if stored.RefreshToken != got.RefreshToken || stored.RefreshToken == set.RefreshToken || !r.stub.RefreshValid(stored.RefreshToken) {
		t.Fatalf("stored refresh %q presented %q original %q", stored.RefreshToken, got.RefreshToken, set.RefreshToken)
	}
	if len(r.events(u.ID)) != 1 {
		t.Fatalf("events %d, want 1", len(r.events(u.ID)))
	}
}

// A reconnect that lands during a refresh wins: the refresh presents the
// reconnect's set and does not overwrite it.
func TestPresentConflictWithReconnectKeepsTheirs(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	release := r.stub.HoldToken()
	done := make(chan error, 1)
	var plain json.RawMessage
	go func() {
		var err error
		plain, err = r.p.Present(context.Background(), u, proxyCaller)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.stub.Grants("refresh_token") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	theirs := r.set(r.now.Add(2 * time.Hour))
	if err := r.st.ConnectUpstreamAuth(context.Background(), u.ID, r.sealSet(theirs), u.UpdatedAt, r.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if decode(t, plain).AccessToken != theirs.AccessToken || r.stored(u.ID).AccessToken != theirs.AccessToken {
		t.Fatalf("presented %q stored %q, want theirs %q", decode(t, plain).AccessToken, r.stored(u.ID).AccessToken, theirs.AccessToken)
	}
	if len(r.events(u.ID)) != 0 {
		t.Fatal("a lost refresh recorded an event")
	}
}

func TestPresentConflictWithClientOnlyBlobIsUnreadable(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	release := r.stub.HoldToken()
	done := make(chan error, 1)
	go func() {
		_, err := r.p.Present(context.Background(), u, proxyCaller)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.stub.Grants("refresh_token") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	clientOnly := models.OAuthTokenSet{ClientID: "new", ClientSource: "supplied"}
	if err := r.st.ConnectUpstreamAuth(context.Background(), u.ID, r.sealSet(clientOnly), u.UpdatedAt, r.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; !errors.Is(err, ErrUnreadable) {
		t.Fatalf("err=%v, want ErrUnreadable", err)
	}
}

type failingSwap struct {
	store.Store
	fail bool
}

func (f *failingSwap) SwapUpstreamAuth(ctx context.Context, id string, expect, next []byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.SwapUpstreamAuth(ctx, id, expect, next)
}

func TestPresentStoreErrorStillPresentsNewToken(t *testing.T) {
	r := newRig(t)
	fs := &failingSwap{Store: r.st, fail: true}
	r.p = NewPresenter(r.keys, fs, mcpclient.New(netguard.Options{AllowLoopback: true}), slog.New(slog.NewJSONHandler(r.log, nil)))
	r.p.SetClock(func() time.Time { return r.now })
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || !r.stub.AccessValid(decode(t, plain).AccessToken) || decode(t, plain).AccessToken == set.AccessToken {
		t.Fatalf("got %s %v", plain, err)
	}
	if r.stored(u.ID).AccessToken != set.AccessToken {
		t.Fatal("the failing store stored something")
	}
	if !strings.Contains(r.log.String(), "not stored after refresh") || strings.Contains(r.log.String(), "disk full") {
		t.Fatalf("log %s", r.log.String())
	}
	if len(r.events(u.ID)) != 0 {
		t.Fatal("an unstored refresh recorded an event")
	}
}

// A store that cannot be read on the conflict path must not cost a grant the
// vendor has already rotated: the call succeeds on the new token.
type conflictThenReadFail struct {
	store.Store
	swaps int
}

func (c *conflictThenReadFail) SwapUpstreamAuth(ctx context.Context, id string, expect, next []byte) error {
	c.swaps++
	if c.swaps == 1 {
		return store.ErrNotFound
	}
	return c.Store.SwapUpstreamAuth(ctx, id, expect, next)
}

func (c *conflictThenReadFail) GetUpstream(ctx context.Context, id string) (*models.Upstream, error) {
	if c.swaps >= 1 {
		return nil, errors.New("database is locked")
	}
	return c.Store.GetUpstream(ctx, id)
}

func TestPresentConflictReadErrorStillPresentsNewToken(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	r.p = NewPresenter(r.keys, &conflictThenReadFail{Store: r.st}, mcpclient.New(netguard.Options{AllowLoopback: true}), slog.New(slog.NewJSONHandler(r.log, nil)))
	r.p.SetClock(func() time.Time { return r.now })
	plain, err := r.p.Present(context.Background(), u, proxyCaller)
	if err != nil || !r.stub.AccessValid(decode(t, plain).AccessToken) || decode(t, plain).AccessToken == set.AccessToken {
		t.Fatalf("got %s %v", plain, err)
	}
	if !strings.Contains(r.log.String(), "not stored after refresh") || strings.Contains(r.log.String(), "database is locked") {
		t.Fatalf("log %s", r.log.String())
	}
}

func TestPresentRecordsOneRefreshEventWithCaller(t *testing.T) {
	r := newRig(t)
	u := r.row(r.set(r.now.Add(-time.Minute)))
	by := Caller{Actor: models.ActorAdmin, RemoteAddr: "203.0.113.9", RequestID: "req-admin-7"}
	if _, err := r.p.Present(context.Background(), u, by); err != nil {
		t.Fatal(err)
	}
	ev := r.events(u.ID)
	if len(ev) != 1 {
		t.Fatalf("events %d", len(ev))
	}
	e := ev[0]
	if e.Action != models.ActionUpstreamOAuthRefresh || e.Actor != models.ActorAdmin || e.RemoteAddr != "203.0.113.9" || e.RequestID != "req-admin-7" || e.ResourceType != models.ResourceUpstream || e.ResourceName != "Stub" {
		t.Fatalf("event %+v", e)
	}
	if string(e.Details) != "{}" {
		t.Fatalf("details %s", e.Details)
	}
	// And the proxy's shape: actor proxy, no address.
	u2 := r.row(r.set(r.now.Add(-time.Minute)))
	if _, err := r.p.Present(context.Background(), u2, proxyCaller); err != nil {
		t.Fatal(err)
	}
	if e := r.events(u2.ID)[0]; e.Actor != models.ActorProxy || e.RemoteAddr != "" || e.RequestID != "req-1" {
		t.Fatalf("proxy event %+v", e)
	}
}

// The vendor call runs off the caller's context: a caller cancelled after the
// vendor rotated the token cannot lose the new set.
func TestPresentRunsOffCallerContext(t *testing.T) {
	r := newRig(t)
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	release := r.stub.HoldToken()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.p.Present(ctx, u, proxyCaller)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.stub.Grants("refresh_token") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	release()
	if err := <-done; err != nil {
		t.Fatalf("cancelled caller: %v", err)
	}
	if stored := r.stored(u.ID); stored.RefreshToken == set.RefreshToken || !r.stub.RefreshValid(stored.RefreshToken) {
		t.Fatalf("stored %+v", stored)
	}
}

func TestPresentLockWaitRespectsContext(t *testing.T) {
	r := newRig(t)
	u := r.row(r.set(r.now.Add(-time.Minute)))
	unlock, err := LockUpstream(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := r.p.Present(ctx, u, proxyCaller); !errors.Is(err, ErrRefreshFailed) {
		t.Fatalf("err=%v, want the bare ErrRefreshFailed for a caller that gave up", err)
	}
	if r.stub.Grants("refresh_token") != 0 {
		t.Fatal("a waiter refreshed")
	}
}

func TestExpiredRule(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339)
	for name, tc := range map[string]struct {
		authType string
		plain    string
		want     bool
	}{
		"lapsed, no refresh":    {models.AuthOAuth, `{"access_token":"a","expires_at":"` + past + `"}`, true},
		"lapsed, refresh token": {models.AuthOAuth, `{"access_token":"a","refresh_token":"r","expires_at":"` + past + `"}`, false},
		"future, no refresh":    {models.AuthOAuth, `{"access_token":"a","expires_at":"` + future + `"}`, false},
		"no expiry":             {models.AuthOAuth, `{"access_token":"a"}`, false},
		"bearer never expires":  {models.AuthBearer, `{"token":"x"}`, false},
		"empty":                 {models.AuthOAuth, ``, false},
		"not json":              {models.AuthOAuth, `{`, false},
	} {
		if got := Expired(tc.authType, json.RawMessage(tc.plain), now); got != tc.want {
			t.Errorf("%s: Expired=%v, want %v", name, got, tc.want)
		}
	}
}

func TestStatusOfExpired(t *testing.T) {
	k, _ := keyring(t, 0)
	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	stored := seal(t, k, `{"access_token":"a","expires_at":"`+past+`","resource":"https://r"}`)
	if got := Status(k, models.AuthOAuth, stored); got != StatusExpired {
		t.Fatalf("Status=%q, want expired", got)
	}
	if got := StatusOf(models.AuthOAuth, nil, ErrUnreadable, time.Now()); got != StatusUnreadable {
		t.Fatalf("StatusOf(unreadable)=%q", got)
	}
	if got := StatusOf(models.AuthOAuth, json.RawMessage(`{"access_token":"a","refresh_token":"r","expires_at":"`+past+`"}`), nil, time.Now()); got != StatusOK {
		t.Fatalf("lapsed with a refresh token reads %q, want ok (the next call refreshes)", got)
	}
	// A client-only blob reads unreadable, never expired.
	if got := Status(k, models.AuthOAuth, seal(t, k, `{"client_id":"c"}`)); got != StatusUnreadable {
		t.Fatalf("client-only=%q", got)
	}
}

// Amendment A12: an unconnected oauth row stays inside Unreadable (so /stats
// and the row agree) and is counted again as Unconnected for the boot line;
// a lapsed connected row counts as fine, Sweep is expiry-blind.
func TestSweepCountsUnconnectedInsideUnreadable(t *testing.T) {
	k, _ := keyring(t, 0)
	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	ups := []models.Upstream{
		{ID: "o1", Name: "Empty", AuthType: models.AuthOAuth},
		{ID: "o2", Name: "Client", AuthType: models.AuthOAuth, AuthConfig: seal(t, k, `{"client_id":"c"}`)},
		{ID: "o3", Name: "Lapsed", AuthType: models.AuthOAuth, AuthConfig: seal(t, k, `{"access_token":"a","expires_at":"`+past+`"}`)},
		{ID: "b1", Name: "Bearer", AuthType: models.AuthBearer, AuthConfig: seal(t, k, `{}`)},
	}
	r := Sweep(k, ups)
	if r.Unreadable != 3 || r.Unconnected != 2 || r.Undecryptable != 0 {
		t.Fatalf("Unreadable=%d Unconnected=%d Undecryptable=%d", r.Unreadable, r.Unconnected, r.Undecryptable)
	}
}

// Security requirement 9: the refresh lines carry ids and a reason code, no
// token, no vendor words.
func TestRefreshLogCarriesNoToken(t *testing.T) {
	r := newRig(t)
	r.stub.RejectRefresh = true
	r.stub.ErrorDescriptionMarker = "VENDOR_WORDS_MARKER"
	set := r.set(r.now.Add(-time.Minute))
	u := r.row(set)
	_, _ = r.p.Present(context.Background(), u, proxyCaller)
	r2 := newRig(t)
	set2 := r2.set(r2.now.Add(-time.Minute))
	u2 := r2.row(set2)
	if _, err := r2.p.Present(context.Background(), u2, proxyCaller); err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{set.AccessToken, set.RefreshToken, "VENDOR_WORDS_MARKER", set2.AccessToken, set2.RefreshToken, r2.stored(u2.ID).AccessToken, r2.stored(u2.ID).RefreshToken} {
		if strings.Contains(r.log.String()+r2.log.String(), needle) {
			t.Fatalf("%q reached the log:\n%s%s", needle, r.log.String(), r2.log.String())
		}
	}
	if !strings.Contains(r.log.String(), `"reason":"invalid_grant"`) || !strings.Contains(r2.log.String(), "upstream oauth token refreshed") {
		t.Fatalf("expected lines missing:\n%s%s", r.log.String(), r2.log.String())
	}
}
