package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func (s slowLogs) ListAuditFacets(ctx context.Context, _ models.LogFilter) (models.LogFacets, error) {
	<-ctx.Done()
	return models.LogFacets{}, ctx.Err()
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

// foldCapped answers ListAuditFacets as a window past facetFoldCap does.
type foldCapped struct{ store.Store }

func (foldCapped) ListAuditFacets(context.Context, models.LogFilter) (models.LogFacets, error) {
	return models.LogFacets{}, store.ErrTooManyFacetValues
}

// facetRows inserts one audit row per spec at ts, ids prefixed by tag.
func facetRows(t *testing.T, st *store.SQLStore, tag string, ts time.Time, specs ...[3]string) {
	t.Helper()
	for i, sp := range specs {
		if err := st.InsertAuditLog(context.Background(), &models.AuditLog{
			ID: fmt.Sprintf("%s%03d", tag, i), Timestamp: ts, VirtualKeyID: "k1", VirtualKeyName: "bot",
			Method: sp[0], ToolName: sp[1], Status: sp[2], RequestID: fmt.Sprintf("req-%s%03d", tag, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// getFacets reads GET /logs/facets with q and decodes it.
func getFacets(t *testing.T, h http.Handler, q url.Values) models.LogFacets {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/logs/facets?"+q.Encode(), "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("facets %s: %d %s", q.Encode(), rr.Code, rr.Body.String())
	}
	var f models.LogFacets
	if err := json.Unmarshal(rr.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// pagedLogs pages through GET /logs with q and returns every row's tool name,
// the count a facet list must sum to.
func pagedLogs(t *testing.T, h http.Handler, q url.Values) []string {
	t.Helper()
	q = maps.Clone(q)
	q.Set("limit", "200")
	var tools []string
	for range 20 {
		rr := doJSON(t, h, http.MethodGet, "/logs?"+q.Encode(), "test-admin", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("logs %s: %d %s", q.Encode(), rr.Code, rr.Body.String())
		}
		var body struct {
			Logs []struct {
				ToolName string `json:"tool_name"`
			} `json:"logs"`
			NextCursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		for _, l := range body.Logs {
			tools = append(tools, l.ToolName)
		}
		if body.NextCursor == "" {
			return tools
		}
		q.Set("cursor", body.NextCursor)
	}
	t.Fatal("the walk did not end within 20 pages")
	return nil
}

func entrySum(es []models.FacetEntry) int {
	n := 0
	for _, e := range es {
		n += e.Count
	}
	return n
}

func entryCount(es []models.FacetEntry, v string) int {
	for _, e := range es {
		if e.Value == v {
			return e.Count
		}
	}
	return 0
}

// TestListLogsHasTool is PORM-149 criterion 2 and S11: has_tool=false lists
// only rows with no tool and true only rows with one; beside tool, or with
// any value but exactly "true" or "false", it is a 400; empty is no filter.
func TestListLogsHasTool(t *testing.T) {
	_, h, st := testAPI(t)
	now := time.Now().UTC().Add(-time.Minute)
	facetRows(t, st, "h", now,
		[3]string{"tools/list", "", models.StatusSuccess},
		[3]string{"tools/call", "echo", models.StatusSuccess},
		[3]string{"initialize", "", models.StatusSuccess})
	tools := func(query string) []string {
		t.Helper()
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		got := pagedLogs(t, h, q)
		slices.Sort(got)
		return got
	}
	if got := tools("has_tool=false"); !slices.Equal(got, []string{"", ""}) {
		t.Errorf("has_tool=false: tools %q, want two empty", got)
	}
	if got := tools("has_tool=true"); !slices.Equal(got, []string{"echo"}) {
		t.Errorf("has_tool=true: tools %q, want [echo]", got)
	}
	if got := tools("has_tool="); len(got) != 3 {
		t.Errorf("has_tool= empty: %d rows, want all 3", len(got))
	}
	for query, msg := range map[string]string{
		"has_tool=false&tool=x": "has_tool cannot be set with tool",
		"has_tool=true&tool=x":  "has_tool cannot be set with tool",
		"has_tool=maybe":        "invalid has_tool",
		"has_tool=1":            "invalid has_tool",
		"has_tool=TRUE":         "invalid has_tool",
	} {
		rr := doJSON(t, h, http.MethodGet, "/logs?"+query, "test-admin", nil)
		if want := "{\"error\":\"" + msg + "\"}\n"; rr.Code != http.StatusBadRequest || rr.Body.String() != want {
			t.Errorf("%s: %d %q, want 400 %q", query, rr.Code, rr.Body.String(), want)
		}
	}
}

// TestListLogFacets is PORM-149 criterion 1: each list sums to the rows GET
// /logs pages through for the same window, tools[""] to the rows with no
// tool, and status narrows methods and tools but not statuses.
func TestListLogFacets(t *testing.T) {
	_, h, st := testAPI(t)
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	facetRows(t, st, "a", now,
		[3]string{"initialize", "", models.StatusSuccess},
		[3]string{"tools/list", "", models.StatusSuccess},
		[3]string{"tools/call", "echo", models.StatusSuccess},
		[3]string{"tools/call", "echo", models.StatusError},
		[3]string{"tools/call", "fetch", models.StatusBlocked})
	window := url.Values{
		"since": {now.Add(-time.Hour).Format(time.RFC3339)},
		"until": {now.Add(time.Hour).Format(time.RFC3339)},
	}
	got := getFacets(t, h, window)
	rows := pagedLogs(t, h, window)
	if entrySum(got.Methods) != len(rows) || entrySum(got.Tools) != len(rows) || entrySum(got.Statuses) != len(rows) {
		t.Errorf("sums %d, %d, %d; GET /logs lists %d", entrySum(got.Methods), entrySum(got.Tools), entrySum(got.Statuses), len(rows))
	}
	noTool := maps.Clone(window)
	noTool.Set("has_tool", "false")
	if a, b := entryCount(got.Tools, ""), len(pagedLogs(t, h, noTool)); a != b || a != 2 {
		t.Errorf("tools[\"\"] = %d, has_tool=false lists %d; want 2 both", a, b)
	}

	errs := maps.Clone(window)
	errs.Set("status", models.StatusError)
	ge := getFacets(t, h, errs)
	if want := []models.FacetEntry{{Value: "tools/call", Count: 1}}; !slices.Equal(ge.Methods, want) {
		t.Errorf("status=error methods %v, want %v", ge.Methods, want)
	}
	if want := []models.FacetEntry{{Value: "echo", Count: 1}}; !slices.Equal(ge.Tools, want) {
		t.Errorf("status=error tools %v, want %v", ge.Tools, want)
	}
	if !slices.Equal(ge.Statuses, got.Statuses) {
		t.Errorf("status=error statuses %v, want the unfiltered %v", ge.Statuses, got.Statuses)
	}
}

// TestListLogFacetsRefusesItsOwnFilters is PORM-149 criterion 3 and S12,
// S13, S19: the route's own filters are fixed 400s after the admin check, an
// empty one is no filter, cursor and limit are not read, and the route is the
// facet handler, never getLog with "facets" as an id.
func TestListLogFacetsRefusesItsOwnFilters(t *testing.T) {
	_, h, st := testAPI(t)
	rr := doJSON(t, h, http.MethodGet, "/logs/facets", "test-admin", nil)
	if want := "{\"methods\":[],\"tools\":[],\"statuses\":[],\"truncated\":false}\n"; rr.Code != http.StatusOK || rr.Body.String() != want {
		t.Errorf("empty store: %d %q, want 200 %q", rr.Code, rr.Body.String(), want)
	}
	logs := doJSON(t, h, http.MethodGet, "/logs", "test-admin", nil)
	if a, b := slices.Sorted(maps.Keys(rr.Header())), slices.Sorted(maps.Keys(logs.Header())); !slices.Equal(a, b) {
		t.Errorf("facet headers %v, GET /logs headers %v; want the same set", a, b)
	}

	for query, msg := range map[string]string{
		"method=tools/call": "method cannot be set on facets",
		"tool=x":            "tool cannot be set on facets",
		"has_tool=false":    "has_tool cannot be set on facets",
		"status=ok":         "invalid status",
		"since=yesterday":   "invalid since",
		"until=tomorrow":    "invalid until",
	} {
		rr := doJSON(t, h, http.MethodGet, "/logs/facets?"+query, "test-admin", nil)
		if want := "{\"error\":\"" + msg + "\"}\n"; rr.Code != http.StatusBadRequest || rr.Body.String() != want {
			t.Errorf("%s: %d %q, want 400 %q", query, rr.Code, rr.Body.String(), want)
		}
	}
	for _, admin := range []string{"", "wrong-key"} {
		if rr := doJSON(t, h, http.MethodGet, "/logs/facets?method=tools/call", admin, nil); rr.Code != http.StatusUnauthorized {
			t.Errorf("admin key %q: %d, want 401 before any 400", admin, rr.Code)
		}
	}

	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	facetRows(t, st, "r", now, [3]string{"tools/list", "", models.StatusSuccess})
	facetRows(t, st, "s", now.Add(-2*time.Hour), [3]string{"initialize", "", models.StatusSuccess})
	until := now.Add(-time.Hour).Format(time.RFC3339)
	for _, query := range []string{"method=&tool=&has_tool=&cursor=garbage&limit=0&until=" + until, "until=" + until} {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		got := getFacets(t, h, q)
		if want := []models.FacetEntry{{Value: "initialize", Count: 1}}; !slices.Equal(got.Methods, want) {
			t.Errorf("%s: methods %v, want %v (until bounds; the empty filters, cursor and limit are not read)", query, got.Methods, want)
		}
	}
}

// TestListLogFacetsCutsAt200 is PORM-149 criterion 4 through the API.
func TestListLogFacetsCutsAt200(t *testing.T) {
	_, h, st := testAPI(t)
	now := time.Now().UTC().Add(-time.Minute)
	specs := make([][3]string, 201)
	for i := range specs {
		specs[i] = [3]string{"tools/call", fmt.Sprintf("tool%03d", i), models.StatusSuccess}
	}
	facetRows(t, st, "c", now, specs...)
	got := getFacets(t, h, url.Values{})
	if len(got.Tools) != 200 || !got.Truncated {
		t.Errorf("201 tools: %d listed, truncated %v; want 200 and true", len(got.Tools), got.Truncated)
	}
}

// TestListLogFacetsStopsAtTheDeadline is the facet route under the same
// deadline and the same 503 as GET /logs.
func TestListLogFacetsStopsAtTheDeadline(t *testing.T) {
	shortReadTimeout(t)
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return slowLogs{Store: st} })
	rr := answerWithin(t, h, "/logs/facets", time.Second)
	if rr.Code != http.StatusServiceUnavailable || rr.Body.String() != "{\"error\":\"log query took too long\"}\n" {
		t.Errorf("%d %q, want 503 {\"error\":\"log query took too long\"}", rr.Code, rr.Body.String())
	}
}

// TestListLogFacetsFoldCapIsA503 is S22: a window past the fold cap answers
// as a read that took too long.
func TestListLogFacetsFoldCapIsA503(t *testing.T) {
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return foldCapped{st} })
	rr := doJSON(t, h, http.MethodGet, "/logs/facets", "test-admin", nil)
	if rr.Code != http.StatusServiceUnavailable || rr.Body.String() != "{\"error\":\"log query took too long\"}\n" {
		t.Errorf("%d %q, want 503 {\"error\":\"log query took too long\"}", rr.Code, rr.Body.String())
	}
}
