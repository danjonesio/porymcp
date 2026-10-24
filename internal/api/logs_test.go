package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// TestListLogsPagesWithCursor is PORM-20 criterion 5: the next_cursor of one
// page, passed back as cursor, returns the following rows, the loop the Logs
// page runs. Five rows share one timestamp so page edges fall inside the tie,
// and a page of exactly the remaining rows ends with an empty next_cursor.
func TestListLogsPagesWithCursor(t *testing.T) {
	_, h, st := testAPI(t)
	ctx := context.Background()
	T := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	ids := []string{"c3", "c1", "c5", "c2", "c4"}
	for _, id := range ids {
		if err := st.InsertAuditLog(ctx, &models.AuditLog{
			ID: id, Timestamp: T, VirtualKeyID: "k1", VirtualKeyName: "bot",
			Method: "tools/list", Status: models.StatusSuccess, RequestID: "req-" + id,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.InsertAuditLog(ctx, &models.AuditLog{
		ID: "b0", Timestamp: T.Add(-time.Second), VirtualKeyID: "k1", VirtualKeyName: "bot",
		Method: "tools/list", Status: models.StatusSuccess, RequestID: "req-b0",
	}); err != nil {
		t.Fatal(err)
	}
	page := func(query string) ([]string, string) {
		t.Helper()
		rr := doJSON(t, h, http.MethodGet, "/logs"+query, "test-admin", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Logs []struct {
				ID string `json:"id"`
			} `json:"logs"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, l := range body.Logs {
			got = append(got, l.ID)
		}
		return got, body.NextCursor
	}

	var seen []string
	pages := 0
	cursor := ""
	for {
		q := "?limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		got, next := page(q)
		seen = append(seen, got...)
		pages++
		if next == "" || pages > 5 {
			break
		}
		cursor = next
	}
	if want := []string{"c5", "c4", "c3", "c2", "c1", "b0"}; !slices.Equal(seen, want) || pages != 3 {
		t.Errorf("walk at limit 2 = %v in %d pages, want %v in 3", seen, pages, want)
	}
	if got, next := page("?limit=6"); len(got) != 6 || next != "" {
		t.Errorf("limit 6 over 6 rows: %d rows, next_cursor %q; want 6 rows and an empty cursor", len(got), next)
	}
}

// TestListLogsRefusesMalformedCursor is PORM-154 criterion 1 and security
// requirement S9: GET /logs answers a malformed cursor, including one whose
// timestamp half is empty, with the exact 400 body /admin-events gives and no
// logs key, so a 200 with an empty page always means the walk ended. The
// admin gate runs before the cursor is read.
func TestListLogsRefusesMalformedCursor(t *testing.T) {
	_, h, _ := testAPI(t)
	for name, cur := range map[string]string{
		"empty timestamp half": "fHg", // base64url of "|x"
		"both halves empty":    "fA",  // base64url of "|"
		"not base64":           "%2A%2A",
	} {
		rr := doJSON(t, h, http.MethodGet, "/logs?cursor="+cur, "test-admin", nil)
		if rr.Code != http.StatusBadRequest || rr.Body.String() != "{\"error\":\"invalid cursor\"}\n" {
			t.Errorf("%s: %d %q, want 400 {\"error\":\"invalid cursor\"}", name, rr.Code, rr.Body.String())
		}
	}
	if rr := doJSON(t, h, http.MethodGet, "/logs?cursor=fHg", "", nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("no admin key: %d, want 401", rr.Code)
	}
}

// slowLogs holds ListAuditLogs until its context ends, as a walk of a long
// period would. entered and ended, when set, report the call starting and the
// context error it ended with.
type slowLogs struct {
	store.Store
	entered chan<- struct{}
	ended   chan<- error
}

func (s slowLogs) ListAuditLogs(ctx context.Context, _ models.LogFilter) ([]models.AuditLog, string, error) {
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	<-ctx.Done()
	if s.ended != nil {
		s.ended <- ctx.Err()
	}
	return nil, "", ctx.Err()
}

// failingLogs fails ListAuditLogs at once with an error that is not a
// deadline, as a broken disk would.
type failingLogs struct{ store.Store }

func (failingLogs) ListAuditLogs(context.Context, models.LogFilter) ([]models.AuditLog, string, error) {
	return nil, "", errors.New("disk")
}

// shortReadTimeout pins the shipped deadline, then shortens it to 50 ms for
// one test.
func shortReadTimeout(t *testing.T) {
	t.Helper()
	if logReadTimeout != 2*time.Second {
		t.Fatalf("logReadTimeout = %v, want the shipped 2s", logReadTimeout)
	}
	logReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { logReadTimeout = 2 * time.Second })
}

// answerWithin serves one admin GET and fails the test when no answer comes
// within d. The request's context ends with the test, so a handler that never
// stops on its own is released then.
func answerWithin(t *testing.T, h http.Handler, path string, d time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- doJSONCtx(t, h, ctx, http.MethodGet, path, "test-admin", nil) }()
	select {
	case rr := <-done:
		return rr
	case <-time.After(d):
		t.Fatalf("GET %s: no answer within %v", path, d)
		return nil
	}
}

// TestListLogsStopsAtTheDeadline is PORM-224 criterion 1: a read that
// outlives logReadTimeout answers the exact 503 body, decided on the context.
func TestListLogsStopsAtTheDeadline(t *testing.T) {
	shortReadTimeout(t)
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return slowLogs{Store: st} })
	rr := answerWithin(t, h, "/logs?method=nothing", time.Second)
	if rr.Code != http.StatusServiceUnavailable || rr.Body.String() != "{\"error\":\"log query took too long\"}\n" {
		t.Errorf("%d %q, want 503 {\"error\":\"log query took too long\"}", rr.Code, rr.Body.String())
	}
}

// TestListLogsStoreErrorIsNotADeadline is PORM-224 criterion 2: a store error
// before the deadline maps through storeError as before. The invalid cursor
// 400 is TestListLogsRefusesMalformedCursor's.
func TestListLogsStoreErrorIsNotADeadline(t *testing.T) {
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return failingLogs{st} })
	rr := doJSON(t, h, http.MethodGet, "/logs", "test-admin", nil)
	if rr.Code != http.StatusInternalServerError || rr.Body.String() != "{\"error\":\"internal error\"}\n" {
		t.Errorf("%d %q, want 500 {\"error\":\"internal error\"}", rr.Code, rr.Body.String())
	}
}

// TestListLogsClientGoneWritesNothing is S5: a request whose caller has gone
// gets no answer at all, never storeError's 500, which would log a store
// failure for an ordinary filter change in the dashboard.
func TestListLogsClientGoneWritesNothing(t *testing.T) {
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return slowLogs{Store: st} })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rr := doJSONCtx(t, h, ctx, http.MethodGet, "/logs", "test-admin", nil)
	if rr.Code == http.StatusInternalServerError || rr.Body.Len() != 0 {
		t.Errorf("%d %q, want nothing written", rr.Code, rr.Body.String())
	}
}

// TestListLogsStopsWhenTheClientGoesAway is the server half of the dashboard's
// abort (PORM-224): over a real connection, a client that hangs up ends the
// store call's context with context.Canceled. The deadline is 10 s here, so
// only the hang-up can end it within the second the test waits.
func TestListLogsStopsWhenTheClientGoesAway(t *testing.T) {
	if logReadTimeout != 2*time.Second {
		t.Fatalf("logReadTimeout = %v, want the shipped 2s", logReadTimeout)
	}
	logReadTimeout = 10 * time.Second
	t.Cleanup(func() { logReadTimeout = 2 * time.Second })
	entered, ended := make(chan struct{}, 1), make(chan error, 1)
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store {
		return slowLogs{Store: st, entered: entered, ended: ended}
	})
	srv := httptest.NewServer(h)
	// Registered after the restore, so it runs first: no handler is still
	// reading logReadTimeout when it is put back.
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/logs", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-admin")
	go func() {
		if resp, err := srv.Client().Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the store call never started")
	}
	cancel()
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("store context ended with %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the store call was still running 1 s after the client went away")
	}
}

// TestLogReadTimeoutMatchesTheDashboard is S18: the dashboard shows its own
// sentence only for a 503 whose text is exactly errLogReadTimeout, so the two
// constants must not drift apart.
func TestLogReadTimeoutMatchesTheDashboard(t *testing.T) {
	src, err := os.ReadFile("../../web/src/lib/logs-view.ts")
	if err != nil {
		t.Fatal(err)
	}
	if want := "LOG_READ_TIMEOUT = '" + errLogReadTimeout + "'"; !strings.Contains(string(src), want) {
		t.Errorf("web/src/lib/logs-view.ts has no %s", want)
	}
}
