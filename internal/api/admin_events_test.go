package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// adminEvents reads every admin_events row the test's own calls have written,
// newest first, straight from the store rather than through the endpoint, so
// a bug in the read path cannot make a write test pass.
func adminEvents(t *testing.T, st *store.SQLStore) []models.AdminEvent {
	t.Helper()
	out, _, err := st.ListAdminEvents(context.Background(), models.AdminEventFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// eventsFor keeps the events with one action. Fixture rows a case creates on
// the way to its own call write their own events, so assertions count the
// case's action rather than the table.
func eventsFor(events []models.AdminEvent, action string) []models.AdminEvent {
	var out []models.AdminEvent
	for _, e := range events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// detailKeys returns the sorted keys of an event's details object.
func detailKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("details %s is not an object: %v", raw, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// mutationCase is one row of the table TestAdminEventPerMutation walks: one
// mutating route, what it answers, and the one event it must leave behind.
type mutationCase struct {
	name       string
	method     string
	action     string
	wantStatus int
	// wantName is the resource_name the event must carry; wantKeys the sorted
	// details keys. wantID is the resource_id, or "" for a create, whose id the
	// server mints (then the assertion is only that it is non-empty).
	wantName string
	wantKeys []string
	// prepare creates whatever rows the call needs on a fresh server and
	// returns the request path, its body and the resource id the event must
	// name.
	prepare func(t *testing.T, h http.Handler) (path string, body any, wantID string)
}

// mutationCases is every mutating route, one case each. The three slices are
// filled in as the handlers are wired (plan steps 6 to 8), and
// TestAdminEventEveryMutatingRouteIsCovered pins that none is missing.
func mutationCases() []mutationCase {
	return slices.Concat(upstreamMutationCases(), groupMutationCases(), virtualKeyMutationCases())
}

func upstreamMutationCases() []mutationCase {
	return []mutationCase{
		{
			name: "upstream.create", method: http.MethodPost, action: models.ActionUpstreamCreate,
			wantStatus: http.StatusCreated, wantName: "GitHub",
			wantKeys: []string{"auth_changed", "auth_type", "slug"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				return "/upstreams", upstreamBody("GitHub", map[string]any{
					"auth_type": "bearer", "auth_config": map[string]any{"token": "secret-token-value"},
				}), ""
			},
		},
		{
			name: "upstream.update", method: http.MethodPatch, action: models.ActionUpstreamUpdate,
			wantStatus: http.StatusOK, wantName: "GitHub", wantKeys: []string{"fields"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id, _ := mustUpstream(t, h, "GitHub", nil)
				return "/upstreams/" + id, map[string]any{"enabled": false, "description": "billing"}, id
			},
		},
		{
			name: "upstream.delete", method: http.MethodDelete, action: models.ActionUpstreamDelete,
			wantStatus: http.StatusNoContent, wantName: "GitHub", wantKeys: nil,
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id, _ := mustUpstream(t, h, "GitHub", nil)
				return "/upstreams/" + id, nil, id
			},
		},
	}
}

func groupMutationCases() []mutationCase {
	return []mutationCase{
		{
			name: "group.create", method: http.MethodPost, action: models.ActionGroupCreate,
			wantStatus: http.StatusCreated, wantName: "Research", wantKeys: []string{"upstream_count"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id, _ := mustUpstream(t, h, "GitHub", nil)
				return "/groups", map[string]any{"name": "Research", "upstream_ids": []string{id}}, ""
			},
		},
		{
			name: "group.update", method: http.MethodPatch, action: models.ActionGroupUpdate,
			wantStatus: http.StatusOK, wantName: "Research", wantKeys: []string{"fields"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := mustGroup(t, h, "Research", nil)
				return "/groups/" + id, map[string]any{"description": "the research team"}, id
			},
		},
		{
			name: "group.delete", method: http.MethodDelete, action: models.ActionGroupDelete,
			wantStatus: http.StatusNoContent, wantName: "Research", wantKeys: nil,
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := mustGroup(t, h, "Research", nil)
				return "/groups/" + id, nil, id
			},
		},
	}
}

// virtualKeyMutationCases is filled in by step 8.
func virtualKeyMutationCases() []mutationCase { return nil }

// TestAdminEventPerMutation is acceptance criterion 1: each mutating route
// writes exactly one admin_events row with the right action, resource_type,
// resource_id, resource_name and details keys. Each case runs on a fresh
// store.
func TestAdminEventPerMutation(t *testing.T) {
	for _, c := range mutationCases() {
		t.Run(c.name, func(t *testing.T) {
			_, h, st := testAPI(t)
			path, body, wantID := c.prepare(t, h)
			rr := doJSON(t, h, c.method, path, "test-admin", body)
			if rr.Code != c.wantStatus {
				t.Fatalf("%s %s: %d %s, want %d", c.method, path, rr.Code, rr.Body.String(), c.wantStatus)
			}
			got := eventsFor(adminEvents(t, st), c.action)
			if len(got) != 1 {
				t.Fatalf("%d events for %s, want exactly 1: %+v", len(got), c.action, got)
			}
			e := got[0]
			resourceType, _, _ := strings.Cut(c.action, ".")
			if e.ResourceType != resourceType {
				t.Errorf("resource_type = %q, want %q", e.ResourceType, resourceType)
			}
			if e.Actor != models.ActorAdmin {
				t.Errorf("actor = %q, want %q", e.Actor, models.ActorAdmin)
			}
			if e.ResourceID == "" || (wantID != "" && e.ResourceID != wantID) {
				t.Errorf("resource_id = %q, want %q", e.ResourceID, wantID)
			}
			if e.ResourceName != c.wantName {
				t.Errorf("resource_name = %q, want %q", e.ResourceName, c.wantName)
			}
			if keys := detailKeys(t, e.Details); !slices.Equal(keys, c.wantKeys) {
				t.Errorf("details keys = %v, want %v (details %s)", keys, c.wantKeys, e.Details)
			}
			if e.Timestamp.IsZero() || e.ID == "" {
				t.Errorf("id %q or timestamp %v not set server-side", e.ID, e.Timestamp)
			}
		})
	}
}

// TestAdminActionsWellFormed covers security requirement 13: every action is
// "{resource_type}.{verb}" with exactly one dot and a known prefix, which is
// what makes recordAdmin's strings.Cut derivation of resource_type safe, and
// the list carries all eleven constants.
func TestAdminActionsWellFormed(t *testing.T) {
	if len(models.AdminActions) != 11 {
		t.Fatalf("AdminActions has %d entries, want 11", len(models.AdminActions))
	}
	seen := map[string]bool{}
	for _, a := range models.AdminActions {
		if strings.Count(a, ".") != 1 {
			t.Errorf("%q must have exactly one dot", a)
		}
		prefix, verb, _ := strings.Cut(a, ".")
		if !validResourceType(prefix) {
			t.Errorf("%q has an unknown resource_type prefix", a)
		}
		if verb == "" {
			t.Errorf("%q has no verb", a)
		}
		if seen[a] {
			t.Errorf("%q listed twice", a)
		}
		seen[a] = true
	}
	for _, want := range []string{
		models.ActionUpstreamCreate, models.ActionUpstreamUpdate, models.ActionUpstreamDelete,
		models.ActionGroupCreate, models.ActionGroupUpdate, models.ActionGroupDelete,
		models.ActionVirtualKeyCreate, models.ActionVirtualKeyUpdate, models.ActionVirtualKeyRotate,
		models.ActionVirtualKeyRevoke, models.ActionVirtualKeyDelete,
	} {
		if !seen[want] {
			t.Errorf("%q missing from AdminActions", want)
		}
	}
}

// detailsOf returns the one event for action as its details text, failing the
// test when there is not exactly one.
func detailsOf(t *testing.T, st *store.SQLStore, action string) string {
	t.Helper()
	got := eventsFor(adminEvents(t, st), action)
	if len(got) != 1 {
		t.Fatalf("%d events for %s, want exactly 1", len(got), action)
	}
	return string(got[0].Details)
}

// TestAdminEventDeleteCapturesName covers security requirement 5 on the
// delete path: the event names the resource that was removed, an unknown id
// records nothing, and a delete the store refuses as in use records nothing.
func TestAdminEventDeleteCapturesName(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "Doomed", nil)
		if rr := doJSON(t, h, http.MethodDelete, "/upstreams/"+id, "test-admin", nil); rr.Code != http.StatusNoContent {
			t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
		}
		got := eventsFor(adminEvents(t, st), models.ActionUpstreamDelete)
		if len(got) != 1 || got[0].ResourceName != "Doomed" || got[0].ResourceID != id {
			t.Fatalf("delete event = %+v, want one naming Doomed/%s", got, id)
		}
	})
	t.Run("upstream unknown id", func(t *testing.T) {
		_, h, st := testAPI(t)
		if rr := doJSON(t, h, http.MethodDelete, "/upstreams/nope", "test-admin", nil); rr.Code != http.StatusNotFound {
			t.Fatalf("delete unknown: %d, want 404", rr.Code)
		}
		if got := eventsFor(adminEvents(t, st), models.ActionUpstreamDelete); len(got) != 0 {
			t.Fatalf("unknown id recorded %+v", got)
		}
	})
	t.Run("upstream in use", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "Held", nil)
		mustGroup(t, h, "Holder", []string{id})
		if rr := doJSON(t, h, http.MethodDelete, "/upstreams/"+id, "test-admin", nil); rr.Code != http.StatusConflict {
			t.Fatalf("delete in use: %d, want 409", rr.Code)
		}
		if got := eventsFor(adminEvents(t, st), models.ActionUpstreamDelete); len(got) != 0 {
			t.Fatalf("in-use delete recorded %+v", got)
		}
	})
	t.Run("group", func(t *testing.T) {
		_, h, st := testAPI(t)
		id := mustGroup(t, h, "Doomed", nil)
		if rr := doJSON(t, h, http.MethodDelete, "/groups/"+id, "test-admin", nil); rr.Code != http.StatusNoContent {
			t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
		}
		got := eventsFor(adminEvents(t, st), models.ActionGroupDelete)
		if len(got) != 1 || got[0].ResourceName != "Doomed" || got[0].ResourceID != id {
			t.Fatalf("delete event = %+v, want one naming Doomed/%s", got, id)
		}
	})
	t.Run("group unknown id", func(t *testing.T) {
		_, h, st := testAPI(t)
		if rr := doJSON(t, h, http.MethodDelete, "/groups/nope", "test-admin", nil); rr.Code != http.StatusNotFound {
			t.Fatalf("delete unknown: %d, want 404", rr.Code)
		}
		if got := eventsFor(adminEvents(t, st), models.ActionGroupDelete); len(got) != 0 {
			t.Fatalf("unknown id recorded %+v", got)
		}
	})
	t.Run("group in use", func(t *testing.T) {
		_, h, st := testAPI(t)
		id := mustGroup(t, h, "Held", nil)
		mustVirtualKey(t, h, "holder", "group", id)
		if rr := doJSON(t, h, http.MethodDelete, "/groups/"+id, "test-admin", nil); rr.Code != http.StatusConflict {
			t.Fatalf("delete in use: %d, want 409", rr.Code)
		}
		if got := eventsFor(adminEvents(t, st), models.ActionGroupDelete); len(got) != 0 {
			t.Fatalf("in-use delete recorded %+v", got)
		}
	})
}

// TestAdminEventFieldsAreADiff pins that details.fields names the fields whose
// stored value differs after the request, never the keys the body carried: a
// round-trip of the current values records nothing, a single changed field
// records that field, a credential is reported by auth_changed and never by a
// field, and the current slug sent back is not a change.
func TestAdminEventFieldsAreADiff(t *testing.T) {
	t.Run("upstream round-trip records nothing", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "GitHub", nil)
		cur := getJSON(t, h, "/upstreams/"+id)
		body := map[string]any{}
		for _, k := range []string{"name", "slug", "description", "url", "transport", "auth_type", "enabled"} {
			body[k] = cur[k]
		}
		patchUpstreamJSON(t, h, id, body)
		if d := detailsOf(t, st, models.ActionUpstreamUpdate); d != "{}" {
			t.Fatalf("round-trip details = %s, want {}", d)
		}
	})
	t.Run("upstream url only", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "GitHub", nil)
		patchUpstreamJSON(t, h, id, map[string]any{"url": "https://example.org/mcp"})
		if d := detailsOf(t, st, models.ActionUpstreamUpdate); d != `{"fields":["url"]}` {
			t.Fatalf("url-only details = %s", d)
		}
	})
	t.Run("upstream credential with auth_type", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "GitHub", nil)
		patchUpstreamJSON(t, h, id, map[string]any{"auth_type": "bearer", "auth_config": map[string]any{"token": "t"}})
		if d := detailsOf(t, st, models.ActionUpstreamUpdate); d != `{"fields":["auth_type"],"auth_type":"bearer","auth_changed":true}` {
			t.Fatalf("credential details = %s", d)
		}
	})
	t.Run("upstream credential re-sent", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "GitHub", map[string]any{"auth_type": "bearer", "auth_config": map[string]any{"token": "t"}})
		patchUpstreamJSON(t, h, id, map[string]any{"auth_config": map[string]any{"token": "t"}})
		if d := detailsOf(t, st, models.ActionUpstreamUpdate); d != `{"auth_type":"bearer","auth_changed":true}` {
			t.Fatalf("re-sent credential details = %s", d)
		}
	})
	t.Run("group members changed carries the count", func(t *testing.T) {
		_, h, st := testAPI(t)
		ghID, _ := mustUpstream(t, h, "GitHub", nil)
		id := mustGroup(t, h, "Research", nil)
		patchGroupJSON(t, h, id, map[string]any{"upstream_ids": []string{ghID}})
		if d := detailsOf(t, st, models.ActionGroupUpdate); d != `{"fields":["upstream_ids"],"upstream_count":1}` {
			t.Fatalf("members details = %s", d)
		}
	})
	t.Run("group filter set then nulled is both a field and a clear", func(t *testing.T) {
		_, h, st := testAPI(t)
		ghID, ghSlug := mustUpstream(t, h, "GitHub", nil)
		id := mustGroup(t, h, "Research", []string{ghID})
		good := `{"mode":"deny","tools":["` + ghSlug + `__delete_repo"]}`
		patchGroupJSON(t, h, id, map[string]any{"tool_filter": json.RawMessage(good)})
		if d := detailsOf(t, st, models.ActionGroupUpdate); d != `{"fields":["tool_filter"]}` {
			t.Fatalf("filter set details = %s", d)
		}
		patchGroupJSON(t, h, id, map[string]any{"tool_filter": nil})
		got := eventsFor(adminEvents(t, st), models.ActionGroupUpdate)
		if len(got) != 2 || string(got[0].Details) != `{"fields":["tool_filter"],"cleared":["tool_filter"]}` {
			t.Fatalf("filter nulled details = %+v", got)
		}
	})
	t.Run("group already-empty filter nulled is a clear with no field", func(t *testing.T) {
		_, h, st := testAPI(t)
		id := mustGroup(t, h, "Research", nil)
		patchGroupJSON(t, h, id, map[string]any{"tool_filter": nil})
		if d := detailsOf(t, st, models.ActionGroupUpdate); d != `{"cleared":["tool_filter"]}` {
			t.Fatalf("already-empty clear details = %s", d)
		}
	})
}

// TestAdminEventNoOpPatchStillRecords pins the decision that PATCH {} answers
// 200 and writes one event with empty details, for every resource.
func TestAdminEventNoOpPatchStillRecords(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		_, h, st := testAPI(t)
		id, _ := mustUpstream(t, h, "GitHub", nil)
		if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{}); rr.Code != http.StatusOK {
			t.Fatalf("PATCH {}: %d %s", rr.Code, rr.Body.String())
		}
		if d := detailsOf(t, st, models.ActionUpstreamUpdate); d != "{}" {
			t.Fatalf("no-op details = %s, want {}", d)
		}
	})
	t.Run("group", func(t *testing.T) {
		_, h, st := testAPI(t)
		id := mustGroup(t, h, "Research", nil)
		if rr := doJSON(t, h, http.MethodPatch, "/groups/"+id, "test-admin", map[string]any{}); rr.Code != http.StatusOK {
			t.Fatalf("PATCH {}: %d %s", rr.Code, rr.Body.String())
		}
		if d := detailsOf(t, st, models.ActionGroupUpdate); d != "{}" {
			t.Fatalf("no-op details = %s, want {}", d)
		}
	})
}
