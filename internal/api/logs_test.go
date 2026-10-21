package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
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
