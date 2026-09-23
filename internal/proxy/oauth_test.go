package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/mcpclient/oauthstub"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// The proxy half of PORM-139 (step 8): an oauth upstream is dialled with
// exactly one bearer, refreshed before the upstream budget is armed, and a
// refresh never ends an open stream.

const listRPC = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

// oauthSet is a connected set for the stub s, minted for resource, expiring
// at exp.
func oauthSet(s *oauthstub.Server, resource string, exp time.Time) models.OAuthTokenSet {
	access, refresh := s.Seed()
	return models.OAuthTokenSet{
		AccessToken: access, RefreshToken: refresh, ExpiresAt: exp,
		TokenEndpoint: s.TokenEndpoint(), RevocationEndpoint: s.RevocationEndpoint(), Issuer: s.Issuer(),
		ClientID: "cid", ClientSource: "supplied", Resource: resource,
	}
}

// toOAuth turns the fixture's upstream id into an oauth row at url holding
// set, and returns the row as stored.
func toOAuth(t *testing.T, f *fixture, id, url string, set models.OAuthTokenSet) *models.Upstream {
	t.Helper()
	ctx := context.Background()
	u, err := f.Store.GetUpstream(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	enc, err := f.H.keys.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.URL = url
	u.AuthType = models.AuthOAuth
	u.AuthConfig = []byte(enc)
	u.UpdatedAt = time.Now().UTC()
	if err := f.Store.UpdateUpstream(ctx, u, store.ResetTest, store.WriteAuth); err != nil {
		t.Fatal(err)
	}
	u, err = f.Store.GetUpstream(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func storedSet(t *testing.T, f *fixture, id string) models.OAuthTokenSet {
	t.Helper()
	u, err := f.Store.GetUpstream(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := credential.Read(f.H.keys, models.AuthOAuth, u.AuthConfig)
	if err != nil {
		t.Fatalf("stored set: %v", err)
	}
	var set models.OAuthTokenSet
	_ = json.Unmarshal(plain, &set)
	return set
}

func adminEvents(t *testing.T, f *fixture, action string) []models.AdminEvent {
	t.Helper()
	all, _, err := f.Store.ListAdminEvents(context.Background(), models.AdminEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []models.AdminEvent
	for _, e := range all {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// Criterion 4, proxy half: the stub sees Authorization: Bearer <access
// token> and nothing else that could be a credential, and never the virtual
// key.
func TestOAuthToolsListCarriesBearerOnly(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	s := oauthstub.New(t)
	set := oauthSet(s, s.MCPURL(), time.Now().Add(time.Hour))
	toOAuth(t, f, "u1", s.MCPURL(), set)

	rr := f.post(listRPC)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	reqs := s.Requests()
	if len(reqs) != 1 {
		t.Fatalf("stub saw %d requests, want 1", len(reqs))
	}
	if v := reqs[0].Header.Values("Authorization"); len(v) != 1 || v[0] != "Bearer "+set.AccessToken {
		t.Fatalf("Authorization %v, want the access token once", v)
	}
	for name, vals := range reqs[0].Header {
		for _, v := range vals {
			if strings.Contains(v, f.Key) || strings.Contains(v, set.RefreshToken) {
				t.Fatalf("%s carried a secret: %q", name, v)
			}
		}
	}
	for _, name := range []string{"X-Api-Key", "Cookie"} {
		if reqs[0].Header.Get(name) != "" {
			t.Fatalf("%s was sent", name)
		}
	}
	if n := f.totalReqs("solo"); n != 0 {
		t.Fatalf("the fixture's own stub saw %d requests", n)
	}
	if s.Grants("refresh_token") != 0 {
		t.Fatal("a fresh token was refreshed")
	}
}

// Criterion 5: an expired row is refreshed first, once, the blob changes,
// one event carries the audit row's request id, and the call succeeds.
func TestOAuthExpiredRefreshesThenCalls(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	s := oauthstub.New(t)
	set := oauthSet(s, s.MCPURL(), time.Now().Add(-time.Minute))
	before := toOAuth(t, f, "u1", s.MCPURL(), set)

	rr := f.post(listRPC)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if s.Grants("refresh_token") != 1 {
		t.Fatalf("refresh grants %d, want 1", s.Grants("refresh_token"))
	}
	after := storedSet(t, f, "u1")
	if after.AccessToken == set.AccessToken || !s.AccessValid(after.AccessToken) {
		t.Fatalf("stored set not renewed: %+v", after)
	}
	row, _ := f.Store.GetUpstream(context.Background(), "u1")
	if !row.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("a refresh moved updated_at")
	}
	if got := s.Requests()[0].Header.Get("Authorization"); got != "Bearer "+after.AccessToken {
		t.Fatalf("the call carried %q, want the renewed token", got)
	}
	audit := f.waitAudit(models.LogFilter{Status: models.StatusSuccess})
	events := adminEvents(t, f, models.ActionUpstreamOAuthRefresh)
	if len(events) != 1 || len(audit) != 1 {
		t.Fatalf("events %d audit rows %d", len(events), len(audit))
	}
	if events[0].RequestID != audit[0].RequestID || events[0].Actor != models.ActorProxy || events[0].RemoteAddr != "" || events[0].ResourceID != "u1" {
		t.Fatalf("event %+v, audit request id %q", events[0], audit[0].RequestID)
	}
}

// A slow vendor must not eat the connect budget: ten concurrent calls held
// at the token endpoint for longer than connectBudget all succeed, and a
// stalled upstream dial after a refresh still ends at that budget.
func TestOAuthSlowRefreshKeepsConnectBudget(t *testing.T) {
	setBudget(t, &connectBudget, 100*time.Millisecond)
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	s := oauthstub.New(t)
	toOAuth(t, f, "u1", s.MCPURL(), oauthSet(s, s.MCPURL(), time.Now().Add(-time.Minute)))

	release := s.HoldToken()
	var wg sync.WaitGroup
	codes := make([]int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = f.post(listRPC).Code
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Grants("refresh_token") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(3 * connectBudget)
	release()
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("caller %d: %d", i, c)
		}
	}
	if s.Grants("refresh_token") != 1 {
		t.Fatalf("refresh grants %d, want 1", s.Grants("refresh_token"))
	}

	// The stalled dial: a listener that accepts and never completes the
	// handshake, behind a token set that refreshes at the stub first.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	stalled := "https://" + ln.Addr().String()
	toOAuth(t, f, "u1", stalled, oauthSet(s, stalled, time.Now().Add(-time.Minute)))
	start := time.Now()
	rr := f.post(listRPC)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a stalled dial after a refresh took %v", took)
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rr.Code)
	}
	if s.Grants("refresh_token") != 2 {
		t.Fatalf("refresh grants %d, want 2", s.Grants("refresh_token"))
	}
	rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(rows) != 1 || !strings.Contains(rows[0].ErrorMessage, "did not connect") {
		t.Fatalf("rows %+v, want the connect budget's sentence", rows)
	}
}

// Criterion 6: a rejected refresh on a lapsed row is the generic 502, the
// row reads credential expired and carries no token, the upstream is never
// dialled.
func TestOAuthRejectedRefreshIs502WithExpiredMessage(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	s := oauthstub.New(t)
	s.RejectRefresh = true
	s.ErrorDescriptionMarker = "VENDOR_WORDS_MARKER"
	set := oauthSet(s, s.MCPURL(), time.Now().Add(-time.Minute))
	toOAuth(t, f, "u1", s.MCPURL(), set)

	rr := f.post(listRPC)
	assert502Generic(t, rr.Body.String(), rr.Code)
	if len(s.Requests()) != 0 {
		t.Fatal("the upstream was dialled with a lapsed token")
	}
	rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(rows) != 1 || rows[0].ErrorMessage != "credential expired" {
		t.Fatalf("rows %+v, want one reading credential expired", rows)
	}
	rendered, _ := json.Marshal(rows[0])
	for _, needle := range []string{set.AccessToken, set.RefreshToken, "VENDOR_WORDS_MARKER"} {
		if strings.Contains(string(rendered), needle) {
			t.Fatalf("%q reached the audit row", needle)
		}
	}
	u, _ := f.Store.GetUpstream(context.Background(), "u1")
	if got := credential.Status(f.H.keys, models.AuthOAuth, u.AuthConfig); got != credential.StatusExpired {
		t.Fatalf("status %q, want expired", got)
	}
}

func TestOAuthTransientRefreshAfterLapseIs502RefreshFailed(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	s := oauthstub.New(t)
	s.RejectRefreshTransient = true
	toOAuth(t, f, "u1", s.MCPURL(), oauthSet(s, s.MCPURL(), time.Now().Add(-time.Minute)))
	rr := f.post(listRPC)
	assert502Generic(t, rr.Body.String(), rr.Code)
	rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(rows) != 1 || rows[0].ErrorMessage != "credential refresh failed" {
		t.Fatalf("rows %+v", rows)
	}
	if len(s.Requests()) != 0 {
		t.Fatal("the upstream was dialled")
	}
}

// openOAuthStream opens a listen stream on an oauth upstream whose MCP side
// is the fixture's own stub (which holds the stream) and whose token endpoint
// is the oauthstub. It returns the fixture, the stub, the line reader, the
// request id, the row as stored and the channel closed when the stream ends.
func openOAuthStream(t *testing.T) (*fixture, *oauthstub.Server, *lineStream, string, *models.Upstream, chan struct{}) {
	t.Helper()
	gone := make(chan struct{})
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, Handler: holdOpen(gone, sseFrame(ackDoc))}, nil, nil)
	s := oauthstub.New(t)
	mcp := f.Stubs["solo"].srv.URL
	u := toOAuth(t, f, "u1", mcp, oauthSet(s, mcp, time.Now().Add(time.Hour)))
	srv := f.serve()
	resp, id := open(t, f, srv, "/a1/mcp", listenRPC)
	t.Cleanup(func() { resp.Body.Close() })
	ls := readLines(resp.Body)
	ls.event(t, 2*time.Second)
	return f, s, ls, id, u, gone
}

// refreshRow simulates what Present writes after a vendor that rotates: a
// new access token and a new refresh token, updated_at untouched.
func refreshRow(t *testing.T, f *fixture, s *oauthstub.Server, u *models.Upstream) {
	t.Helper()
	set := storedSet(t, f, u.ID)
	access, refresh := s.Seed()
	set.AccessToken = access
	set.RefreshToken = refresh
	set.ExpiresAt = time.Now().Add(time.Hour)
	raw, _ := json.Marshal(set)
	enc, err := f.H.keys.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Store.SwapUpstreamAuth(context.Background(), u.ID, u.AuthConfig, []byte(enc)); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshDoesNotEndOpenStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	f, s, _, _, u, _ := openOAuthStream(t)
	refreshRow(t, f, s, u)
	time.Sleep(150 * time.Millisecond) // three re-checks
	if n := f.H.openStreams.Load(); n != 1 {
		t.Fatalf("open_streams=%d after a refresh, want the stream still open", n)
	}
}

func TestRenameAfterRefreshKeepsOpenStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	f, s, _, _, u, _ := openOAuthStream(t)
	refreshRow(t, f, s, u)
	// The refresh is absorbed at the next recheck; the rename then compares
	// equal bytes against the adopted baseline.
	time.Sleep(150 * time.Millisecond)
	ctx := context.Background()
	row, _ := f.Store.GetUpstream(ctx, u.ID)
	row.Name = "Renamed"
	row.UpdatedAt = time.Now().UTC()
	if err := f.Store.UpdateUpstream(ctx, row, store.KeepTest, store.KeepAuth); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if n := f.H.openStreams.Load(); n != 1 {
		t.Fatalf("open_streams=%d after a rename over refreshed bytes, want the stream still open", n)
	}
}

func TestReconnectEndsOpenStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	f, s, ls, id, u, gone := openOAuthStream(t)
	other := oauthSet(s, u.URL, time.Now().Add(time.Hour)) // a different grant
	raw, _ := json.Marshal(other)
	enc, _ := f.H.keys.Seal(raw)
	if err := f.Store.ConnectUpstreamAuth(context.Background(), u.ID, []byte(enc), u.UpdatedAt, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("stream ended with %v", err)
	}
	<-gone
	row := oneRow(t, f, id)
	if row.Status != models.StatusError || row.ErrorMessage != errUpstreamChanged.Error() {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}

// A reconnect at a vendor that issues no refresh token is still a new grant:
// two sets with empty refresh tokens are told apart by their access tokens.
func TestReconnectWithoutRefreshTokenEndsOpenStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	f, s, ls, id, u, gone := openOAuthStream(t)
	first := storedSet(t, f, u.ID)
	first.RefreshToken = ""
	raw, _ := json.Marshal(first)
	enc, _ := f.H.keys.Seal(raw)
	// The stream opened on a set with a refresh token; make the baseline a
	// set without one through a refresh-shaped swap (bytes only).
	if err := f.Store.SwapUpstreamAuth(context.Background(), u.ID, u.AuthConfig, []byte(enc)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // absorbed at a recheck
	other := oauthSet(s, u.URL, time.Now().Add(time.Hour))
	other.RefreshToken = ""
	raw, _ = json.Marshal(other)
	enc, _ = f.H.keys.Seal(raw)
	if err := f.Store.ConnectUpstreamAuth(context.Background(), u.ID, []byte(enc), u.UpdatedAt, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("stream ended with %v", err)
	}
	<-gone
	row := oneRow(t, f, id)
	if row.Status != models.StatusError || row.ErrorMessage != errUpstreamChanged.Error() {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}

func TestDisconnectEndsOpenStream(t *testing.T) {
	setBudget(t, &streamRecheckBudget, 50*time.Millisecond)
	f, _, ls, id, u, gone := openOAuthStream(t)
	if err := f.Store.ConnectUpstreamAuth(context.Background(), u.ID, nil, u.UpdatedAt, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := ls.end(t, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("stream ended with %v", err)
	}
	<-gone
	row := oneRow(t, f, id)
	if row.Status != models.StatusError || row.ErrorMessage != errUpstreamChanged.Error() {
		t.Fatalf("row status=%q error_message=%q", row.Status, row.ErrorMessage)
	}
}

// A group skips a member whose token has lapsed with a dead grant, exactly as
// it skips an undecryptable one, and lists the healthy member.
func TestGroupSkipsExpiredMember(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}},
		"beta":  {Tools: []string{"b_tool"}},
	}, true, nil, nil, nil)
	s := oauthstub.New(t)
	s.RejectRefresh = true
	toOAuth(t, f, "u1", s.MCPURL(), oauthSet(s, s.MCPURL(), time.Now().Add(-time.Minute)))

	rr := f.post(listRPC)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	names := listedNames(t, rr.Body.Bytes())
	var sawBeta bool
	for _, n := range names {
		if strings.Contains(n, "a_tool") {
			t.Fatalf("the expired member's tool was listed: %v", names)
		}
		if strings.Contains(n, "b_tool") {
			sawBeta = true
		}
	}
	if !sawBeta {
		t.Fatalf("beta's tool missing: %v", names)
	}
	if len(s.Requests()) != 0 {
		t.Fatal("the expired member was dialled")
	}
}

// A token endpoint that answers 302 is not followed: the redirect target sees
// nothing and the lapsed row fails as a refresh failure.
func TestRefreshTokenEndpointRedirectIsNotFollowed(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/token?refresh=REDIRECT_QUERY_MARKER", http.StatusFound)
	}))
	defer redirecting.Close()

	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	s := oauthstub.New(t)
	set := oauthSet(s, s.MCPURL(), time.Now().Add(-time.Minute))
	set.TokenEndpoint = redirecting.URL + "/token"
	toOAuth(t, f, "u1", s.MCPURL(), set)

	rr := f.post(listRPC)
	assert502Generic(t, rr.Body.String(), rr.Code)
	if targetHits.Load() != 0 {
		t.Fatalf("the redirect target was dialled %d times", targetHits.Load())
	}
	rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(rows) != 1 || rows[0].ErrorMessage != "credential refresh failed" || strings.Contains(rows[0].ErrorMessage, "REDIRECT") {
		t.Fatalf("rows %+v", rows)
	}
}
