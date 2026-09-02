package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netcasklabs/porymcp/internal/store"
)

// mcpStub is an MCP server as the reference implementations behave: it MINTS A
// SESSION on initialize and refuses tools/list without one. Both matter — a
// stub that answered any request in any order is how a discovery client comes
// to work against tests and fail against every real server.
//
// mcpclient's own fixture is a _test.go file in another package and cannot be
// reached from here. This is the second copy of "what a real MCP server does";
// the third caller should promote it to a package both can import.
type mcpStub struct {
	srv *httptest.Server

	mu   sync.Mutex
	seen []stubRequest

	// tools is the catalogue tools/list answers with.
	tools []map[string]any
	// extra is added to every response, for the test that pins that no
	// upstream header reaches the operator's browser.
	extra http.Header
	// started and release make tools/list block, so a test can hold requests
	// in flight and watch the concurrency cap turn the next one away.
	started chan struct{}
	release chan struct{}
}

type stubRequest struct {
	Method  string // the HTTP verb
	RPC     string // the JSON-RPC method, "" when the body carries none
	Session string
	Header  http.Header
}

const stubSession = "sess-api-test"

func newMCPStub(t *testing.T, opts ...func(*mcpStub)) *mcpStub {
	t.Helper()
	s := &mcpStub{tools: []map[string]any{
		{"name": "echo", "description": "Echoes back the input string"},
		{"name": "add", "description": "Adds two numbers"},
	}}
	for _, o := range opts {
		o(s)
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *mcpStub) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var rpc struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &rpc)
	s.mu.Lock()
	s.seen = append(s.seen, stubRequest{
		Method:  r.Method,
		RPC:     rpc.Method,
		Session: r.Header.Get("Mcp-Session-Id"),
		Header:  r.Header.Clone(),
	})
	s.mu.Unlock()
	for k, vs := range s.extra {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	switch {
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusMethodNotAllowed) // a normal answer; plenty of servers do this
	case rpc.Method == "initialize":
		w.Header().Set("Mcp-Session-Id", stubSession)
		s.result(w, map[string]any{
			"protocolVersion": "2025-06-18",
			"serverInfo":      map[string]any{"name": "stub-everything", "version": "1.2.3"},
		})
	case rpc.Method == "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case rpc.Method == "tools/list":
		if r.Header.Get("Mcp-Session-Id") != stubSession {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"session required"}}`)
			return
		}
		if s.started != nil {
			s.started <- struct{}{}
			// Bounded, so that a regression which lets the fifth caller
			// through fails in seconds instead of deadlocking the suite until
			// the package timeout.
			select {
			case <-s.release:
			case <-time.After(5 * time.Second):
			}
		}
		s.result(w, map[string]any{"tools": s.tools})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *mcpStub) result(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
}

func (s *mcpStub) requests() []stubRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubRequest(nil), s.seen...)
}

// discovery decodes a discovery response, insisting on the 200 that says the
// request itself was answered.
func discovery(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200; body %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %s: %v", rr.Body.String(), err)
	}
	return out
}

func TestDiscoverSavedUpstream(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, slug := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil))
	if d["ok"] != true {
		t.Fatalf("ok = %v: %v", d["ok"], d)
	}
	if d["tool_count"] != float64(2) || d["slug"] != slug {
		t.Fatalf("tool_count = %v, slug = %v (stored slug %q)", d["tool_count"], d["slug"], slug)
	}
	if d["protocol_version"] != "2025-06-18" {
		t.Fatalf("protocol_version = %v", d["protocol_version"])
	}
	// Rounded to 10 ms, which is the timing-oracle mitigation: the difference
	// between a refused connection and a filtered port is exactly the signal
	// that would make this route a port scanner's stopwatch.
	latency, ok := d["latency_ms"].(float64)
	if !ok || int(latency)%10 != 0 {
		t.Fatalf("latency_ms = %v, want a number rounded to 10ms", d["latency_ms"])
	}
	tools, _ := d["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools = %v", d["tools"])
	}
	// The identity a rule is written against, composed once by the client and
	// not by string concatenation anywhere near here.
	for i, want := range []string{slug + "__echo", slug + "__add"} {
		got, _ := tools[i].(map[string]any)
		if got["scoped_name"] != want {
			t.Fatalf("tool %d scoped_name = %v, want %q", i, got["scoped_name"], want)
		}
	}
	// The session it opened is the session it ends.
	last := stub.requests()[len(stub.requests())-1]
	if last.Method != http.MethodDelete || last.Session != stubSession {
		t.Fatalf("last request %+v, want a DELETE carrying the session", last)
	}
}

func TestDiscoverUnsavedPayloadPersistsNothing(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	// A saved upstream at the very URL the payload names. Counting rows alone
	// would miss the case this exists for: the unsaved route has no id, so
	// there is nothing for it to stamp — by construction, not by care.
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	count := func() int {
		t.Helper()
		rr := doJSON(t, h, http.MethodGet, "/upstreams", "test-admin", nil)
		var out struct {
			Upstreams []map[string]any `json:"upstreams"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return len(out.Upstreams)
	}
	before := count()
	// Stamped first, so this assertion has something to lose. While both
	// fields are null, a route that recorded nothing and a route that tried to
	// record and missed leave the row looking identical; against a real result
	// any write at all — a stamp, a reset, a cleared pair — shows up.
	recordTestOn(t, h, id)
	wantAt, wantOK, wantUpdated := upstreamTest(t, h, id)

	rr := doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", map[string]any{
		"url": stub.srv.URL, // no name: the button is enabled on a URL alone
	})
	d := discovery(t, rr)
	if d["ok"] != true || d["tool_count"] != float64(2) {
		t.Fatalf("discovery = %v", d)
	}
	if _, ok := d["slug"]; ok {
		t.Fatalf("an unsaved payload has no slug to report: %v", d)
	}
	// No provisional identity either: create may well store this upstream
	// under a different slug, and a deny rule written from a guess fails open.
	if strings.Contains(rr.Body.String(), "scoped_name") {
		t.Fatalf("unsaved discovery must carry no scoped_name: %s", rr.Body.String())
	}
	if after := count(); after != before {
		t.Fatalf("upstream count %d → %d; discovery must persist nothing", before, after)
	}
	gotAt, gotOK, gotUpdated := upstreamTest(t, h, id)
	if gotAt != wantAt || gotOK != wantOK || gotUpdated != wantUpdated {
		t.Fatalf("the unsaved route touched the saved row at the same url: at %v → %v, ok %v → %v, updated_at %q → %q",
			wantAt, gotAt, wantOK, gotOK, wantUpdated, gotUpdated)
	}
}

// upstreamTest reads an upstream's recorded test result through the API, the
// way the dashboard does. Both keys are always present — the Status cell is
// three-state, so "never tested" has to arrive as an explicit null rather than
// as a missing key — and that is asserted here rather than in one test.
func upstreamTest(t *testing.T, h http.Handler, id string) (at, ok any, updatedAt string) {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/upstreams/"+id, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /upstreams/%s: %d %s", id, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"last_test_at", "last_test_ok"} {
		if _, present := out[k]; !present {
			t.Fatalf("%s is missing; a three-state cell needs an explicit null: %s", k, rr.Body.String())
		}
	}
	updatedAt, _ = out["updated_at"].(string)
	return out["last_test_at"], out["last_test_ok"], updatedAt
}

// upstreamTestFromList reads the same two fields out of GET /upstreams, which
// is the route the dashboard's refresh() calls when a run settles and the only
// one the table is ever built from. A presenter that carried the result on the
// single-upstream response and dropped it from the list would leave every row
// reading "Not tested" for ever, and every other assertion in this file would
// still pass.
//
// The raw map, not a typed struct, for the same reason upstreamTest uses one:
// a missing key and an explicit null decode identically into a pointer field,
// and a three-state cell has to tell them apart.
func upstreamTestFromList(t *testing.T, h http.Handler, id string) (at, ok any) {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/upstreams", "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /upstreams: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Upstreams []map[string]any `json:"upstreams"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, row := range out.Upstreams {
		if row["id"] != id {
			continue
		}
		for _, k := range []string{"last_test_at", "last_test_ok"} {
			if _, present := row[k]; !present {
				t.Fatalf("%s is missing from the list row; a three-state cell needs an explicit null: %s", k, rr.Body.String())
			}
		}
		return row["last_test_at"], row["last_test_ok"]
	}
	t.Fatalf("upstream %s is not in GET /upstreams: %s", id, rr.Body.String())
	return nil, nil
}

// wantRecentTest asserts that at is a timestamp this test could have produced.
func wantRecentTest(t *testing.T, at any) {
	t.Helper()
	raw, isString := at.(string)
	if !isString {
		t.Fatalf("last_test_at = %v, want an RFC3339 timestamp", at)
	}
	when, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("last_test_at = %q: %v", raw, err)
	}
	if d := time.Since(when); d < -time.Minute || d > time.Minute {
		t.Fatalf("last_test_at = %q, which is %v away from now; the server clock writes it", raw, d)
	}
}

// TestDiscoverSavedUpstreamRecordsTheTest is the feature: a press of Tools or
// Refresh leaves a durable record of when it ran and whether it passed.
func TestDiscoverSavedUpstreamRecordsTheTest(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	at, ok, updatedBefore := upstreamTest(t, h, id)
	if at != nil || ok != nil {
		t.Fatalf("a fresh upstream reads back tested: at=%v ok=%v", at, ok)
	}

	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}

	at, ok, updatedAfter := upstreamTest(t, h, id)
	if ok != true {
		t.Fatalf("last_test_ok = %v, want true", ok)
	}
	wantRecentTest(t, at)
	// A test is not an edit.
	if updatedAfter != updatedBefore {
		t.Fatalf("updated_at moved %q → %q; recording a test must not bump it", updatedBefore, updatedAfter)
	}
	// And the table sees it. The dashboard never reads the row route: it
	// re-reads the list, so the same two values have to survive the list
	// presenter as well, byte for byte.
	listAt, listOK := upstreamTestFromList(t, h, id)
	if listAt != at || listOK != ok {
		t.Fatalf("GET /upstreams carries at=%v ok=%v; GET /upstreams/{id} carries %v/%v", listAt, listOK, at, ok)
	}
}

// TestDiscoverRecordsAFailedTest pins the half that matters most: a run that
// could not reach the upstream is recorded as a failure, so the table is red
// rather than silent.
func TestDiscoverRecordsAFailedTest(t *testing.T) {
	_, h, _ := testAPI(t)
	// Port 1 refuses on this machine; whichever failure sentence comes back,
	// what is asserted here is the flag, never the words.
	id, _ := mustUpstream(t, h, "Closed", map[string]any{"url": "http://127.0.0.1:1/mcp"})

	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != false {
		t.Fatalf("discovery = %v", d)
	}
	at, ok, _ := upstreamTest(t, h, id)
	if ok != false {
		t.Fatalf("last_test_ok = %v, want false", ok)
	}
	wantRecentTest(t, at)
}

// recordSpy is the Store the Server is given, with one method watched. Both
// facts it exists to check — that the record is made BEFORE the response is
// written, and that it is made on a context the caller's cancel cannot reach —
// are true only for the instant the store is called, and no assertion made
// after the handler returns can see either.
type recordSpy struct {
	store.Store
	// onRecord runs on the handler's own goroutine, before the write is
	// delegated. Set before the request is served and never afterwards.
	onRecord func(write context.Context)
}

func (s *recordSpy) RecordUpstreamTest(ctx context.Context, id string, at time.Time, ok bool, seen time.Time) error {
	if s.onRecord != nil {
		s.onRecord(ctx)
	}
	return s.Store.RecordUpstreamTest(ctx, id, at, ok, seen)
}

// TestDiscoverRecordsBeforeRespondingOnADetachedContext pins the two things
// about recordTest's placement that the row's contents cannot show.
//
// Order: the dashboard re-reads the table the moment the response lands, so a
// record written after the response races the read it exists to feed and the
// operator sees the previous result.
//
// Detachment: the gate on r.Context() has already been passed by the time the
// store is called, so a cancel arriving in between — a reload, a closed tab —
// must not lose a result whose handshake actually happened. That is what
// context.WithoutCancel buys, and swapping it for r.Context() leaves every
// other test in this file green.
func TestDiscoverRecordsBeforeRespondingOnADetachedContext(t *testing.T) {
	stub := newMCPStub(t)
	spy := &recordSpy{}
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store {
		spy.Store = st
		return spy
	})
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/upstreams/"+id+"/discover", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer test-admin")
	rr := httptest.NewRecorder()

	called := false
	spy.onRecord = func(write context.Context) {
		called = true
		if n := rr.Body.Len(); n != 0 {
			t.Errorf("%d bytes of the response were already written when the record was made", n)
		}
		// The caller goes away mid-record. The write context must not notice.
		cancel()
		if err := write.Err(); err != nil {
			t.Errorf("the write context died with the request: %v", err)
		}
	}
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("the store was never asked to record the test")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	// And the write it was handed actually landed, cancel and all.
	if at, ok, _ := upstreamTest(t, h, id); at == nil || ok != true {
		t.Fatalf("the record did not land: at=%v ok=%v", at, ok)
	}
}

// TestDiscoverCancelledRequestRecordsNothing pins the gate in recordTest. A
// reload or a closed tab cancels the request mid-handshake, and the client has
// no branch for that — it comes back as "cannot reach <host>", which would put
// a red dot on an upstream nobody tested. The cancel has to land WHILE the
// handshake is running: a request cancelled before it starts dies at
// GetUpstream and never reaches the gate at all.
func TestDiscoverCancelledRequestRecordsNothing(t *testing.T) {
	stub := newMCPStub(t, func(s *mcpStub) {
		s.started = make(chan struct{}, 1)
		s.release = make(chan struct{})
	})
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/upstreams/"+id+"/discover", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer test-admin")
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()

	release := sync.OnceFunc(func() { close(stub.release) })
	defer release()
	<-stub.started
	cancel()
	release()
	<-done

	if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
		t.Fatalf("a cancelled request recorded at=%v ok=%v; it tested nothing", at, ok)
	}
}

// TestDiscoverEditedDuringHandshakeRecordsNothing pins the compare-and-set. An
// operator can save a new URL while a ten-second handshake is in flight; the
// result that comes back describes the configuration as it was, and stamping it
// on the row would vouch for settings nobody tested.
func TestDiscoverEditedDuringHandshakeRecordsNothing(t *testing.T) {
	stub := newMCPStub(t, func(s *mcpStub) {
		s.started = make(chan struct{}, 1)
		s.release = make(chan struct{})
	})
	_, h, st, _ := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	codes := make(chan int, 1)
	go func() {
		codes <- doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil).Code
	}()

	release := sync.OnceFunc(func() { close(stub.release) })
	defer release()
	<-stub.started

	ctx := context.Background()
	u, err := st.GetUpstream(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	before := u.UpdatedAt
	u.UpdatedAt = time.Now().UTC()
	if err := st.UpdateUpstream(ctx, u, store.KeepTest, store.WriteAuth); err != nil {
		t.Fatal(err)
	}
	// The bump is what makes the compare miss; if it did not move, this test
	// would pass for the wrong reason.
	if u.UpdatedAt.Equal(before) {
		t.Fatalf("updated_at did not move (%v); the edit this test simulates never happened", before)
	}
	release()
	if code := <-codes; code != http.StatusOK {
		t.Fatalf("discovery: %d, want 200 — a dropped record is not a failed request", code)
	}

	if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
		t.Fatalf("a result for an edited configuration was recorded: at=%v ok=%v", at, ok)
	}
}

// TestDiscoverRateLimitedRecordsNothing: a spent budget answers before any
// handshake, so there is no result to record.
func TestDiscoverRateLimitedRecordsNothing(t *testing.T) {
	stub := newMCPStub(t)
	s, h, _ := testAPI(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	s.discoverLimit.SetClock(func() time.Time { return now })
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	unknown := "/upstreams/" + uuid.NewString() + "/discover"
	for i := 0; i < discoverRPM; i++ {
		if rr := doJSON(t, h, http.MethodPost, unknown, "test-admin", nil); rr.Code != http.StatusNotFound {
			t.Fatalf("call %d: %d, want 404", i+1, rr.Code)
		}
	}
	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", rr.Code)
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("stub saw %d requests", n)
	}
	if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
		t.Fatalf("a 429 recorded at=%v ok=%v; no test ran", at, ok)
	}
}

// TestDiscoverRecordWarnsWithIdOnly pins the one line this package may write
// when a result cannot be stored: an upstream id and the store's error, never
// the name, the url or a credential. A failed write is not a failed request —
// the operator asked what the upstream offers and that answer is composed.
func TestDiscoverRecordWarnsWithIdOnly(t *testing.T) {
	stub := newMCPStub(t, func(s *mcpStub) {
		s.started = make(chan struct{}, 1)
		s.release = make(chan struct{})
	})
	srv, h, st, _ := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	var logs bytes.Buffer
	srv.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	codes := make(chan int, 1)
	go func() {
		codes <- doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil).Code
	}()

	release := sync.OnceFunc(func() { close(stub.release) })
	defer release()
	// Closed while the handshake is held open, so the row was read before the
	// store went away and only the write can fail.
	<-stub.started
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	if code := <-codes; code != http.StatusOK {
		t.Fatalf("discovery: %d, want 200", code)
	}

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("wrote %d log lines, want exactly 1: %s", len(lines), logs.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("log line %q: %v", lines[0], err)
	}
	if rec["level"] != "WARN" || rec["upstream_id"] != id {
		t.Fatalf("log line = %v, want a WARN naming upstream_id %q", rec, id)
	}
	for _, secret := range []string{stub.srv.URL, "GitHub"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("the log repeats %q: %s", secret, logs.String())
		}
	}
}

// The unsaved route's whole reason to exist is "connects to the URL above
// USING THESE CREDENTIALS": an operator is checking a token before they store
// it. Passing nil instead of the payload's auth_config would leave every other
// test in this file green, and the dialog would report a 401 for a token that
// is fine.
func TestDiscoverUnsavedPayloadSendsItsCredential(t *testing.T) {
	const token = "UNSAVED_TOKEN_MARKER"
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)

	rr := doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", map[string]any{
		"url":         stub.srv.URL,
		"auth_type":   "bearer",
		"auth_config": map[string]string{"token": token},
	})
	if d := discovery(t, rr); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}
	requests := stub.requests()
	if len(requests) == 0 {
		t.Fatal("the stub saw no requests")
	}
	for _, rq := range requests {
		if got := rq.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("%s %s carried Authorization %q, want the payload's own credential", rq.Method, rq.RPC, got)
		}
	}
	// Presented upstream, never repeated back.
	if strings.Contains(rr.Body.String(), token) {
		t.Fatalf("the response repeats the credential: %s", rr.Body.String())
	}
}

func TestDiscoverRequiresAdmin(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	for _, path := range []string{"/upstreams/discover", "/upstreams/" + id + "/discover"} {
		for _, key := range []string{"", "wrong"} {
			rr := doJSON(t, h, http.MethodPost, path, key, map[string]any{"url": stub.srv.URL})
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("POST %s with key %q: %d, want 401", path, key, rr.Code)
			}
		}
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("stub saw %d requests; an unauthorized caller must reach no upstream", n)
	}
}

func TestDiscoverRateLimited(t *testing.T) {
	stub := newMCPStub(t)
	s, h, _ := testAPI(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	s.discoverLimit.SetClock(func() time.Time { return now })
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	// One real discovery, then 29 that never reach an upstream. The budget is
	// spent before the store is read, so a flood of unknown ids costs exactly
	// what a flood of real ones does.
	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("first discovery: %v", d)
	}
	unknown := "/upstreams/" + uuid.NewString() + "/discover"
	for i := 0; i < 29; i++ {
		if rr := doJSON(t, h, http.MethodPost, unknown, "test-admin", nil); rr.Code != http.StatusNotFound {
			t.Fatalf("call %d: %d, want 404", i+2, rr.Code)
		}
	}

	rr := doJSON(t, h, http.MethodPost, unknown, "test-admin", nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("31st call: %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"error":"too many discovery requests"}` {
		t.Fatalf("429 body %q", got)
	}
	// The unsaved route draws on the same bucket: one budget for the two.
	rr = doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", map[string]any{"url": stub.srv.URL})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("unsaved route while the budget is spent: %d, want 429", rr.Code)
	}
	// And the OTHER budget is untouched. adminFails is the per-IP failure
	// budget; spending it from here would let a burst of discoveries lock an
	// operator out of the dashboard, which is why there are two limiters.
	if rr := doJSON(t, h, http.MethodPost, unknown, "wrong-key", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong admin key while the discovery budget is spent: %d, want 401", rr.Code)
	}

	now = now.Add(time.Minute)
	if rr := doJSON(t, h, http.MethodPost, unknown, "test-admin", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("after the window: %d, want 404", rr.Code)
	}
}

func TestDiscoverConcurrencyCapped(t *testing.T) {
	stub := newMCPStub(t, func(s *mcpStub) {
		s.started = make(chan struct{}, maxInFlightDiscoveries+1)
		s.release = make(chan struct{})
	})
	_, h, _ := testAPI(t)
	body := map[string]any{"url": stub.srv.URL}
	// The fifth call is made against a SAVED upstream, so the refusal can be
	// asked the second question too: a caller turned away at the door tested
	// nothing, and a row that came back "Failed" because the door was busy
	// would blame the upstream for PoryMCP's own cap.
	id, _ := mustUpstream(t, h, "GitHub", body)

	codes := make(chan int, maxInFlightDiscoveries)
	for i := 0; i < maxInFlightDiscoveries; i++ {
		go func() {
			codes <- doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", body).Code
		}()
	}
	// Deferred as well as closed below: without it a failed assertion leaves
	// four goroutines blocked in the stub for its 5 s bound, writing to codes
	// after the test has finished.
	release := sync.OnceFunc(func() { close(stub.release) })
	defer release()
	// Wait until all four are held inside tools/list, so the fifth meets a
	// full semaphore rather than a race.
	for i := 0; i < maxInFlightDiscoveries; i++ {
		<-stub.started
	}

	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("call %d: %d, want 429", maxInFlightDiscoveries+1, rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"error":"too many concurrent discoveries"}` {
		t.Fatalf("429 body %q", got)
	}
	if rr.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q, want 5", rr.Header().Get("Retry-After"))
	}

	// The four in flight are unaffected: the cap turns callers away, it does
	// not abandon work already started.
	release()
	for i := 0; i < maxInFlightDiscoveries; i++ {
		if code := <-codes; code != http.StatusOK {
			t.Fatalf("in-flight discovery %d: %d, want 200", i, code)
		}
	}

	// Nothing was recorded for the call that never ran. The refusal happens
	// before the handshake, so there is no outcome to stamp — and the four that
	// did run were unsaved payloads with no row of their own.
	if at, ok, _ := upstreamTest(t, h, id); at != nil || ok != nil {
		t.Fatalf("the refused call recorded at=%v ok=%v; no handshake ran", at, ok)
	}
}

func TestDiscoverUnknownUpstream(t *testing.T) {
	_, h, _ := testAPI(t)
	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		get := doJSON(t, h, http.MethodGet, "/upstreams/"+id, "test-admin", nil)
		rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
		// Byte-identical to the GET: whether an upstream exists is one answer,
		// and a discovery route that phrased it differently would be a second.
		if rr.Code != http.StatusNotFound || rr.Code != get.Code || rr.Body.String() != get.Body.String() {
			t.Fatalf("id %q: discover %d %q, get %d %q", id, rr.Code, rr.Body.String(), get.Code, get.Body.String())
		}
	}
}

func TestDiscoverRejectsInvalidPayload(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	for _, tc := range []struct {
		name string
		body any
		want string
	}{
		{"no body at all", nil, ""},
		{"blank url", map[string]any{"url": "   "}, "url is required"},
		{"missing url", map[string]any{"name": "GitHub"}, "url is required"},
		{"unknown transport", map[string]any{"url": stub.srv.URL, "transport": "carrier-pigeon"}, "invalid transport or auth_type"},
		{"unknown auth_type", map[string]any{"url": stub.srv.URL, "auth_type": "kerberos"}, "invalid transport or auth_type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400; body %s", rr.Code, rr.Body.String())
			}
			if tc.want != "" {
				wantsBody(t, rr, tc.want)
			}
		})
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("stub saw %d requests; a rejected payload must reach no upstream", n)
	}
}

// TestDiscoverUndecryptableCredentialMakesNoRequest is the gate that keeps a
// rotated ENCRYPTION_KEY from being reported as a bad token.
//
// Without the gate the handshake would go out unauthenticated, collect the
// upstream's 401, and tell the operator to check a token that is fine. The
// load-bearing half of this test is the count of zero requests: the message
// alone would be a guess if the request still went. PORM-52 security
// requirement 2/3; auth_status on the row carries the cause.
func TestDiscoverUndecryptableCredentialMakesNoRequest(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{
		"url":         stub.srv.URL,
		"auth_type":   "bearer",
		"auth_config": map[string]string{"token": "sk-real"},
	})

	// Written through a second connection to the same file: nothing exported
	// could store ciphertext this key will not open.
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE upstreams SET auth_config = ? WHERE id = ?`, "not-ciphertext", id); err != nil {
		t.Fatal(err)
	}

	d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil))
	if d["ok"] != false || d["error"] != "stored credential cannot be decrypted" {
		t.Fatalf("discovery = %v", d)
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("stub saw %d requests; an undecryptable credential must stop before any of them", n)
	}
	// Recorded as a failure all the same: no call went out, but PoryMCP cannot
	// use this upstream, and that is what the dot answers. It is also the one
	// failure a rotated ENCRYPTION_KEY deals to every row at once.
	at, ok, _ := upstreamTest(t, h, id)
	if ok != false {
		t.Fatalf("last_test_ok = %v, want false", ok)
	}
	wantRecentTest(t, at)
}

// TestDiscoverUnreadableCredentialMakesNoRequest is the sibling gate for a
// blob that opens fine but holds nothing its auth type can send — the
// dashboard stores {} for a blank token — which must not dial either, and must
// not be reported as a key problem (PORM-52 security requirement 3).
func TestDiscoverUnreadableCredentialMakesNoRequest(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "Blank", map[string]any{
		"url":         stub.srv.URL,
		"auth_type":   "bearer",
		"auth_config": map[string]string{},
	})
	d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil))
	if d["ok"] != false || d["error"] != "stored credential is not usable for this auth type" {
		t.Fatalf("discovery = %v", d)
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("stub saw %d requests; an unusable credential must stop before any of them", n)
	}
	at, ok, _ := upstreamTest(t, h, id)
	if ok != false {
		t.Fatalf("last_test_ok = %v, want false", ok)
	}
	wantRecentTest(t, at)
}

func TestDiscoverNeverReturnsCredential(t *testing.T) {
	const token = "sk-live-DO-NOT-LEAK"
	stub := newMCPStub(t)
	s, h, _ := testAPI(t)
	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{
		"url":         stub.srv.URL,
		"auth_type":   "bearer",
		"auth_config": map[string]string{"token": token},
	})

	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	if d := discovery(t, rr); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}
	// The credential really was presented — otherwise the rest proves nothing.
	if got := stub.requests()[0].Header.Get("Authorization"); got != "Bearer "+token {
		t.Fatalf("upstream saw Authorization %q", got)
	}
	if strings.Contains(rr.Body.String(), token) {
		t.Fatalf("the response repeats the credential: %s", rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["auth_config"]; ok {
		t.Fatalf("auth_config is not a field a discovery has: %v", out)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatalf("the credential reached the log: %s", logs.String())
	}
}

func TestDiscoverURLUserinfoRedacted(t *testing.T) {
	_, h, _ := testAPI(t)
	// A URL carrying a secret in three places, two of which Go's own redaction
	// keeps. Port 1 refuses on this machine; a host that drops rather than
	// refuses produces the timeout sentence instead, so BOTH are accepted —
	// what this test is about is which bytes come back, not which failure.
	id, _ := mustUpstream(t, h, "Leaky", map[string]any{
		"url": "https://user:secret@127.0.0.1:1/mcp?tok=QUERYSECRET",
	})

	d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil))
	if d["ok"] != false {
		t.Fatalf("discovery = %v", d)
	}
	msg, _ := d["error"].(string)
	allowed := []string{
		"cannot connect to 127.0.0.1:1",
		"cannot reach 127.0.0.1:1",
		"upstream did not answer within 10s",
	}
	if !slices.Contains(allowed, msg) {
		t.Fatalf("error %q is not one of the allowlist's sentences %q", msg, allowed)
	}
	for _, secret := range []string{"secret", "QUERYSECRET", "user", "/mcp"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error %q repeats %q", msg, secret)
		}
	}
}

func TestDiscoverDisabledUpstream(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	// An operator disables an upstream to stop serving it and then wants to
	// know why it broke.
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL, "enabled": false})

	d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil))
	if d["ok"] != true || d["tool_count"] != float64(2) {
		t.Fatalf("discovery = %v", d)
	}
}

func TestDiscoverAuthTypeNoneSendsNoHeader(t *testing.T) {
	stub := newMCPStub(t)
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}
	for _, rq := range stub.requests() {
		// The admin key is the caller's, never the upstream's, and an upstream
		// with no credential is sent none of anybody's.
		if rq.Header.Get("Authorization") != "" || rq.Header.Get("X-API-Key") != "" {
			t.Fatalf("%s %s carried a credential: %v", rq.Method, rq.RPC, rq.Header)
		}
	}
}

// TestDiscoverReturnsNoUpstreamHeaders pins that discovery does not inherit
// the proxy's 1:1 header pass-through (PORM-98): its only write is a
// Discovery, so an upstream cannot set a cookie or a challenge in the
// operator's browser.
func TestDiscoverReturnsNoUpstreamHeaders(t *testing.T) {
	stub := newMCPStub(t, func(s *mcpStub) {
		s.extra = http.Header{
			"Set-Cookie":       []string{"session=upstream-owned"},
			"Www-Authenticate": []string{`Basic realm="upstream"`},
			"X-Weird":          []string{"upstream-header"},
		}
	})
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	if d := discovery(t, rr); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}
	for _, name := range []string{"Set-Cookie", "WWW-Authenticate", "X-Weird"} {
		if got := rr.Header().Get(name); got != "" {
			t.Fatalf("%s = %q; no upstream header may reach the caller", name, got)
		}
	}
	if strings.Contains(rr.Body.String(), "upstream-header") {
		t.Fatalf("an upstream header value reached the body: %s", rr.Body.String())
	}
}

func TestDiscoverZeroToolsIsArray(t *testing.T) {
	stub := newMCPStub(t, func(s *mcpStub) { s.tools = nil })
	_, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "Empty", map[string]any{"url": stub.srv.URL})

	rr := doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)
	d := discovery(t, rr)
	if d["ok"] != true || d["tool_count"] != float64(0) {
		t.Fatalf("discovery = %v", d)
	}
	// Never null: the same rule as endpoints[], so a client can iterate what
	// it is given without a nil check.
	if !strings.Contains(rr.Body.String(), `"tools":[]`) {
		t.Fatalf("body %s: tools must be an empty array", rr.Body.String())
	}
}

// TestDiscoverPathIsPostOnly pins how chi resolves the static "discover" child
// against {id}. Every other verb backtracks into the upstream handlers and
// produces the ordinary unknown-upstream 404 — measured, not assumed, and
// pinned here so a chi upgrade that changed it is caught.
func TestDiscoverPathIsPostOnly(t *testing.T) {
	_, h, _ := testAPI(t)
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		rr := doJSON(t, h, method, "/upstreams/discover", "test-admin", nil)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s /upstreams/discover: %d, want 404", method, rr.Code)
		}
		if got := strings.TrimSpace(rr.Body.String()); got != `{"error":"not found"}` {
			t.Fatalf("%s /upstreams/discover body %q", method, got)
		}
	}
	// POST still reaches the unsaved handler, which is the only reason the
	// rows above are acceptable.
	rr := doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", map[string]any{"url": ""})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("POST /upstreams/discover: %d, want 400", rr.Code)
	}
	wantsBody(t, rr, "url is required")
}

// TestDiscoverLogsNothing holds the handlers to silence. The access log line
// in cmd/server carries the id and the status and is the trace; everything
// this package could add — the URL, the host, the upstream's own words — is
// text a third party chose, on the one management path that pulls bytes in
// from one.
//
// The one exception is a result that could not be recorded: one DEBUG (row
// changed or gone) or one WARN (store error), each naming the upstream id and
// nothing else — see TestDiscoverRecordWarnsWithIdOnly. Neither happens on the
// happy paths below, which is why this test stays at zero.
func TestDiscoverLogsNothing(t *testing.T) {
	stub := newMCPStub(t)
	s, h, _ := testAPI(t)
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{"url": stub.srv.URL})

	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/"+id+"/discover", "test-admin", nil)); d["ok"] != true {
		t.Fatalf("discovery = %v", d)
	}
	if d := discovery(t, doJSON(t, h, http.MethodPost, "/upstreams/discover", "test-admin", map[string]any{"url": stub.srv.URL})); d["ok"] != true {
		t.Fatalf("unsaved discovery = %v", d)
	}
	if logs.Len() != 0 {
		t.Fatalf("the discovery handlers wrote %s", logs.String())
	}
}
