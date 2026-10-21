package api

import (
	"net/http"
	"testing"
)

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
