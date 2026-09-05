package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	name   string
	method string
	// route is the chi pattern the case exercises, as chi.Walk reports it, so
	// TestAdminEventEveryMutatingRouteIsCovered can tie the table to the
	// router.
	route      string
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
			name: "upstream.create", method: http.MethodPost, route: "/upstreams", action: models.ActionUpstreamCreate,
			wantStatus: http.StatusCreated, wantName: "GitHub",
			wantKeys: []string{"auth_changed", "auth_type", "slug"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				return "/upstreams", upstreamBody("GitHub", map[string]any{
					"auth_type": "bearer", "auth_config": map[string]any{"token": "secret-token-value"},
				}), ""
			},
		},
		{
			name: "upstream.update", method: http.MethodPatch, route: "/upstreams/{id}", action: models.ActionUpstreamUpdate,
			wantStatus: http.StatusOK, wantName: "GitHub", wantKeys: []string{"fields"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id, _ := mustUpstream(t, h, "GitHub", nil)
				return "/upstreams/" + id, map[string]any{"enabled": false, "description": "billing"}, id
			},
		},
		{
			name: "upstream.delete", method: http.MethodDelete, route: "/upstreams/{id}", action: models.ActionUpstreamDelete,
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
			name: "group.create", method: http.MethodPost, route: "/groups", action: models.ActionGroupCreate,
			wantStatus: http.StatusCreated, wantName: "Research", wantKeys: []string{"upstream_count"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id, _ := mustUpstream(t, h, "GitHub", nil)
				return "/groups", map[string]any{"name": "Research", "upstream_ids": []string{id}}, ""
			},
		},
		{
			name: "group.update", method: http.MethodPatch, route: "/groups/{id}", action: models.ActionGroupUpdate,
			wantStatus: http.StatusOK, wantName: "Research", wantKeys: []string{"fields"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := mustGroup(t, h, "Research", nil)
				return "/groups/" + id, map[string]any{"description": "the research team"}, id
			},
		},
		{
			name: "group.delete", method: http.MethodDelete, route: "/groups/{id}", action: models.ActionGroupDelete,
			wantStatus: http.StatusNoContent, wantName: "Research", wantKeys: nil,
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := mustGroup(t, h, "Research", nil)
				return "/groups/" + id, nil, id
			},
		},
	}
}

func virtualKeyMutationCases() []mutationCase {
	withKey := func(t *testing.T, h http.Handler) string {
		t.Helper()
		upID, _ := mustUpstream(t, h, "GitHub", nil)
		return mustVirtualKey(t, h, "demo-vk", "upstream", upID)["id"].(string)
	}
	return []mutationCase{
		{
			name: "virtual_key.create", method: http.MethodPost, route: "/virtual-keys", action: models.ActionVirtualKeyCreate,
			wantStatus: http.StatusCreated, wantName: "demo-vk",
			wantKeys: []string{"key_prefix", "target_id", "target_type"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				upID, _ := mustUpstream(t, h, "GitHub", nil)
				return "/virtual-keys", map[string]any{"name": "demo-vk", "target_type": "upstream", "target_id": upID}, ""
			},
		},
		{
			name: "virtual_key.update", method: http.MethodPatch, route: "/virtual-keys/{id}", action: models.ActionVirtualKeyUpdate,
			wantStatus: http.StatusOK, wantName: "renamed", wantKeys: []string{"fields"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := withKey(t, h)
				return "/virtual-keys/" + id, map[string]any{"name": "renamed"}, id
			},
		},
		{
			name: "virtual_key.rotate", method: http.MethodPost, route: "/virtual-keys/{id}/rotate", action: models.ActionVirtualKeyRotate,
			wantStatus: http.StatusOK, wantName: "demo-vk", wantKeys: []string{"key_prefix"},
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := withKey(t, h)
				return "/virtual-keys/" + id + "/rotate", nil, id
			},
		},
		{
			name: "virtual_key.revoke", method: http.MethodPost, route: "/virtual-keys/{id}/revoke", action: models.ActionVirtualKeyRevoke,
			wantStatus: http.StatusOK, wantName: "demo-vk", wantKeys: nil,
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := withKey(t, h)
				return "/virtual-keys/" + id + "/revoke", nil, id
			},
		},
		{
			name: "virtual_key.delete", method: http.MethodDelete, route: "/virtual-keys/{id}", action: models.ActionVirtualKeyDelete,
			wantStatus: http.StatusNoContent, wantName: "demo-vk", wantKeys: nil,
			prepare: func(t *testing.T, h http.Handler) (string, any, string) {
				id := withKey(t, h)
				return "/virtual-keys/" + id, nil, id
			},
		},
	}
}

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
	t.Run("virtual key", func(t *testing.T) {
		_, h, st := testAPI(t)
		upID, _ := mustUpstream(t, h, "GitHub", nil)
		id := mustVirtualKey(t, h, "doomed-vk", "upstream", upID)["id"].(string)
		if rr := doJSON(t, h, http.MethodDelete, "/virtual-keys/"+id, "test-admin", nil); rr.Code != http.StatusNoContent {
			t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
		}
		got := eventsFor(adminEvents(t, st), models.ActionVirtualKeyDelete)
		if len(got) != 1 || got[0].ResourceName != "doomed-vk" || got[0].ResourceID != id {
			t.Fatalf("delete event = %+v, want one naming doomed-vk/%s", got, id)
		}
	})
	t.Run("virtual key unknown id", func(t *testing.T) {
		_, h, st := testAPI(t)
		if rr := doJSON(t, h, http.MethodDelete, "/virtual-keys/nope", "test-admin", nil); rr.Code != http.StatusNotFound {
			t.Fatalf("delete unknown: %d, want 404", rr.Code)
		}
		if got := eventsFor(adminEvents(t, st), models.ActionVirtualKeyDelete); len(got) != 0 {
			t.Fatalf("unknown id recorded %+v", got)
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
	t.Run("group created with an empty filter records no filter", func(t *testing.T) {
		_, h, st := testAPI(t)
		if rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", map[string]any{"name": "Research", "tool_filter": map[string]any{}}); rr.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
		}
		if d := detailsOf(t, st, models.ActionGroupCreate); d != `{"upstream_count":0}` {
			t.Fatalf("create with {} filter details = %s, want upstream_count only", d)
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
	t.Run("virtual key retarget names both target fields", func(t *testing.T) {
		_, h, st := testAPI(t)
		upID, _ := mustUpstream(t, h, "GitHub", nil)
		gid := mustGroup(t, h, "Research", []string{upID})
		id := mustVirtualKey(t, h, "demo-vk", "upstream", upID)["id"].(string)
		patchVirtualKeyJSON(t, h, id, map[string]any{"target_type": "group", "target_id": gid})
		if d := detailsOf(t, st, models.ActionVirtualKeyUpdate); d != `{"fields":["target_type","target_id"]}` {
			t.Fatalf("retarget details = %s", d)
		}
	})
	t.Run("virtual key expiry resent with another offset is not a change", func(t *testing.T) {
		_, h, st := testAPI(t)
		upID, _ := mustUpstream(t, h, "GitHub", nil)
		id := newVirtualKey(t, h, "upstream", upID, map[string]any{"expires_at": "2030-01-01T10:00:00Z"})["id"].(string)
		patchVirtualKeyJSON(t, h, id, map[string]any{"expires_at": "2030-01-01T11:00:00+01:00"})
		if d := detailsOf(t, st, models.ActionVirtualKeyUpdate); d != "{}" {
			t.Fatalf("same-instant expiry details = %s, want {}", d)
		}
	})
	for _, c := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"virtual key allowlist", map[string]any{"tool_allowlist": []string{"read_issue"}}, `{"fields":["tool_allowlist"]}`},
		{"virtual key denylist", map[string]any{"tool_denylist": []string{"delete_repo"}}, `{"fields":["tool_denylist"]}`},
		{"virtual key metadata name only", map[string]any{"metadata": map[string]any{"team": "billing"}}, `{"fields":["metadata"]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, h, st := testAPI(t)
			upID, _ := mustUpstream(t, h, "GitHub", nil)
			id := mustVirtualKey(t, h, "demo-vk", "upstream", upID)["id"].(string)
			patchVirtualKeyJSON(t, h, id, c.body)
			if d := detailsOf(t, st, models.ActionVirtualKeyUpdate); d != c.want {
				t.Fatalf("details = %s, want %s", d, c.want)
			}
		})
	}
	t.Run("virtual key rate limit nulled is a field and a clear", func(t *testing.T) {
		_, h, st := testAPI(t)
		upID, _ := mustUpstream(t, h, "GitHub", nil)
		id := newVirtualKey(t, h, "upstream", upID, map[string]any{"rate_limit": 10})["id"].(string)
		patchVirtualKeyJSON(t, h, id, map[string]any{"rate_limit": nil})
		if d := detailsOf(t, st, models.ActionVirtualKeyUpdate); d != `{"fields":["rate_limit"],"cleared":["rate_limit"]}` {
			t.Fatalf("rate limit nulled details = %s", d)
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
	t.Run("virtual key", func(t *testing.T) {
		_, h, st := testAPI(t)
		upID, _ := mustUpstream(t, h, "GitHub", nil)
		id := mustVirtualKey(t, h, "demo-vk", "upstream", upID)["id"].(string)
		if rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", map[string]any{}); rr.Code != http.StatusOK {
			t.Fatalf("PATCH {}: %d %s", rr.Code, rr.Body.String())
		}
		if d := detailsOf(t, st, models.ActionVirtualKeyUpdate); d != "{}" {
			t.Fatalf("no-op details = %s, want {}", d)
		}
	})
}

// skipRoutes names the mutating routes that deliberately write no admin event,
// each with the reason. The reason must be non-empty: adding a line here is a
// written decision, not a way to quiet the test.
var skipRoutes = map[string]string{
	"POST /upstreams/discover":      "changes no state: the unsaved probe persists nothing (discover.go)",
	"POST /upstreams/{id}/discover": "stamps last_test_at and last_test_ok, an observation of an upstream rather than a change an operator made to the configuration; it can be pressed repeatedly from one dialog and skips its own write when the caller goes away, so a row would sometimes claim a test that was never stored (plan open question 1; PORM-132 records it)",
}

// TestAdminEventEveryMutatingRouteIsCovered is security requirement 12: a
// mutating route added later cannot be silently unaudited. It walks the real
// router and requires every POST, PATCH, PUT or DELETE to be in the
// per-mutation table or in skipRoutes with a reason, and every action in
// models.AdminActions to have a case.
func TestAdminEventEveryMutatingRouteIsCovered(t *testing.T) {
	_, h, _ := testAPI(t)
	routes, ok := h.(chi.Routes)
	if !ok {
		t.Fatalf("Routes() returned %T, not a chi router", h)
	}
	covered := map[string]bool{}
	actions := map[string]bool{}
	for _, c := range mutationCases() {
		covered[c.method+" "+c.route] = true
		actions[c.action] = true
	}
	for route, reason := range skipRoutes {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("skipRoutes[%q] has no reason", route)
		}
		if covered[route] {
			t.Errorf("%q is both covered and skipped", route)
		}
	}
	seen := map[string]bool{}
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		switch method {
		case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		default:
			return nil
		}
		key := method + " " + route
		seen[key] = true
		if covered[key] {
			return nil
		}
		if _, skipped := skipRoutes[key]; skipped {
			return nil
		}
		t.Errorf("mutating route %s writes no admin event and is not in skipRoutes", key)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key := range covered {
		if !seen[key] {
			t.Errorf("table names %s, which the router does not serve", key)
		}
	}
	for key := range skipRoutes {
		if !seen[key] {
			t.Errorf("skipRoutes names %s, which the router does not serve", key)
		}
	}
	for _, a := range models.AdminActions {
		if !actions[a] {
			t.Errorf("action %s has no case in the per-mutation table", a)
		}
	}
}

// serialiseEvents renders every column of every event as one string, so a
// secrets assertion covers the whole row and not just details.
func serialiseEvents(t *testing.T, events []models.AdminEvent) string {
	t.Helper()
	var b bytes.Buffer
	for _, e := range events {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte(10)
	}
	return b.String()
}

// TestAdminEventNeverStoresSecrets is acceptance criterion 2 and security
// requirements 1 and 2: a credential change records auth_type and
// auth_changed and never the token, the ciphertext or the string auth_config;
// a rotate records key_prefix and never the plaintext, the hash or the lookup.
// Every column of every row is scanned.
func TestAdminEventNeverStoresSecrets(t *testing.T) {
	_, h, st, path := testAPIStoreFile(t, "http://localhost:8080")
	id, _ := mustUpstream(t, h, "GitHub", map[string]any{
		"auth_type": "bearer", "auth_config": map[string]any{"token": "secret-token-value"},
	})
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/"+id, "test-admin", map[string]any{
		"auth_config": map[string]any{"token": "rotated-secret-value"},
	}); rr.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
	ciphertext := rawAuth(t, path, id)
	if ciphertext == "" {
		t.Fatal("no stored ciphertext to assert against")
	}

	vk := mustVirtualKey(t, h, "demo-vk", "upstream", id)
	vkID := vk["id"].(string)
	rr := doJSON(t, h, http.MethodPost, "/virtual-keys/"+vkID+"/rotate", "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	var rotated map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	plain, _ := rotated["api_key"].(string)
	if plain == "" {
		t.Fatal("rotate returned no api_key")
	}
	stored, err := st.GetVirtualKey(context.Background(), vkID)
	if err != nil {
		t.Fatal(err)
	}

	events := adminEvents(t, st)
	upd := eventsFor(events, models.ActionUpstreamUpdate)
	if len(upd) != 1 {
		t.Fatalf("%d update events, want 1", len(upd))
	}
	if d := string(upd[0].Details); !strings.Contains(d, `"auth_type":"bearer"`) || !strings.Contains(d, `"auth_changed":true`) {
		t.Errorf("credential change details = %s, want auth_type and auth_changed:true", d)
	}
	rot := eventsFor(events, models.ActionVirtualKeyRotate)
	if len(rot) != 1 || !strings.Contains(string(rot[0].Details), `"key_prefix":"`) {
		t.Errorf("rotate details = %+v, want key_prefix", rot)
	}
	all := serialiseEvents(t, events)
	for name, secret := range map[string]string{
		"plaintext token":   "secret-token-value",
		"rotated token":     "rotated-secret-value",
		"stored ciphertext": ciphertext,
		"auth_config key":   "auth_config",
		"plaintext key":     plain,
		"key hash":          stored.KeyHash,
		"key lookup":        stored.KeyLookup,
		"first api_key":     vk["api_key"].(string),
	} {
		if secret == "" {
			t.Fatalf("%s fixture is empty", name)
		}
		if strings.Contains(all, secret) {
			t.Errorf("%s reached an admin_events row: %s", name, all)
		}
	}
}

// TestAdminEventRejectedRequestRecordsNothing covers security requirement 5
// on the rejected paths: a 400, a 401, a 404 and a 409 leave no row.
func TestAdminEventRejectedRequestRecordsNothing(t *testing.T) {
	_, h, st := testAPI(t)
	if rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin", upstreamBody("Bad", map[string]any{"url": "not a url"})); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid url: %d, want 400", rr.Code)
	}
	if rr := doJSON(t, h, http.MethodPost, "/upstreams", "", upstreamBody("NoKey", nil)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d, want 401", rr.Code)
	}
	if rr := doJSON(t, h, http.MethodPatch, "/upstreams/nope", "test-admin", map[string]any{"name": "x"}); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d, want 404", rr.Code)
	}
	if got := adminEvents(t, st); len(got) != 0 {
		t.Fatalf("rejected requests recorded %+v", got)
	}
	mustUpstream(t, h, "Taken", map[string]any{"slug": "taken"})
	if rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin", upstreamBody("Taken again", map[string]any{"slug": "taken"})); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate slug: %d, want 409", rr.Code)
	}
	if got := adminEvents(t, st); len(got) != 1 {
		t.Fatalf("after one create and one 409 the table holds %d rows, want 1: %+v", len(got), got)
	}
}

// flakyStore wraps the real store to fail, panic or cancel at one call: the
// seam the recorder tests need, through testAPIWrappedStore.
type flakyStore struct {
	store.Store
	insertErr   error
	insertPanic bool
	// cancel, when set, is called after a successful CreateUpstream, standing
	// in for a client that disconnected once its change had committed.
	cancel context.CancelFunc
	// armed is set after UpdateVirtualKey; the reads the presenter makes then
	// fail, so a PATCH answers 500 after its write landed.
	armed atomic.Bool
}

func (f *flakyStore) InsertAdminEvent(ctx context.Context, e *models.AdminEvent) error {
	if f.insertPanic {
		panic("recorder test panic")
	}
	if f.insertErr != nil {
		return f.insertErr
	}
	return f.Store.InsertAdminEvent(ctx, e)
}

func (f *flakyStore) CreateUpstream(ctx context.Context, u *models.Upstream) error {
	err := f.Store.CreateUpstream(ctx, u)
	if f.cancel != nil {
		f.cancel()
	}
	return err
}

func (f *flakyStore) UpdateVirtualKey(ctx context.Context, a *models.VirtualKey) error {
	err := f.Store.UpdateVirtualKey(ctx, a)
	f.armed.Store(true)
	return err
}

func (f *flakyStore) ListUpstreams(ctx context.Context) ([]models.Upstream, error) {
	if f.armed.Load() {
		return nil, errors.New("presenter read refused by the test")
	}
	return f.Store.ListUpstreams(ctx)
}

func (f *flakyStore) GetUpstream(ctx context.Context, id string) (*models.Upstream, error) {
	if f.armed.Load() {
		return nil, errors.New("presenter read refused by the test")
	}
	return f.Store.GetUpstream(ctx, id)
}

func withFlakyStore(t *testing.T, f *flakyStore) (http.Handler, *store.SQLStore) {
	t.Helper()
	_, h, st, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store {
		f.Store = st
		return f
	})
	return h, st
}

// TestAdminEventRecordedBeforeResponse covers security requirement 5 on the
// other side: a row follows the store write, not the response status, so a
// presenter 500 after a committed PATCH still leaves exactly one row.
func TestAdminEventRecordedBeforeResponse(t *testing.T) {
	f := &flakyStore{}
	h, st := withFlakyStore(t, f)
	upID, _ := mustUpstream(t, h, "GitHub", nil)
	id := mustVirtualKey(t, h, "demo-vk", "upstream", upID)["id"].(string)
	rr := doJSON(t, h, http.MethodPatch, "/virtual-keys/"+id, "test-admin", map[string]any{"name": "renamed"})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("patch with a failing presenter: %d %s, want 500", rr.Code, rr.Body.String())
	}
	got := eventsFor(adminEvents(t, st), models.ActionVirtualKeyUpdate)
	if len(got) != 1 || got[0].ResourceName != "renamed" {
		t.Fatalf("update events after a presenter 500 = %+v, want exactly one naming renamed", got)
	}
}

// TestAdminEventWriteFailureDoesNotFailMutation covers security requirement
// 6: a failed audit write never fails or hides the change. The create still
// answers 201 and the upstream is readable; the rotate still answers 200 with
// its one-time api_key.
func TestAdminEventWriteFailureDoesNotFailMutation(t *testing.T) {
	f := &flakyStore{insertErr: errors.New("audit table unavailable")}
	h, st := withFlakyStore(t, f)
	rr := doJSON(t, h, http.MethodPost, "/upstreams", "test-admin", upstreamBody("GitHub", nil))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create with a failing recorder: %d %s", rr.Code, rr.Body.String())
	}
	id := idOf(t, rr)
	if rr := doJSON(t, h, http.MethodGet, "/upstreams/"+id, "test-admin", nil); rr.Code != http.StatusOK {
		t.Fatalf("upstream not readable after create: %d", rr.Code)
	}
	vkID := mustVirtualKey(t, h, "demo-vk", "upstream", id)["id"].(string)
	rr = doJSON(t, h, http.MethodPost, "/virtual-keys/"+vkID+"/rotate", "test-admin", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"api_key":"`) {
		t.Fatalf("rotate with a failing recorder: %d %s, want 200 with api_key", rr.Code, rr.Body.String())
	}
	if got := adminEvents(t, st); len(got) != 0 {
		t.Fatalf("a failing recorder still wrote %+v", got)
	}
}

// TestAdminEventRecorderPanicDoesNotFailMutation covers security requirement
// 7: a panic inside the recorder is recovered, so a rotate whose write landed
// still answers 200 with its one-time api_key instead of a 500 that would
// lose the plaintext forever.
func TestAdminEventRecorderPanicDoesNotFailMutation(t *testing.T) {
	f := &flakyStore{insertPanic: true}
	h, _ := withFlakyStore(t, f)
	upID, _ := mustUpstream(t, h, "GitHub", nil)
	vkID := mustVirtualKey(t, h, "demo-vk", "upstream", upID)["id"].(string)
	rr := doJSON(t, h, http.MethodPost, "/virtual-keys/"+vkID+"/rotate", "test-admin", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"api_key":"`) {
		t.Fatalf("rotate with a panicking recorder: %d %s, want 200 with api_key", rr.Code, rr.Body.String())
	}
}

// TestAdminEventWrittenAfterClientCancel covers security requirement 8: the
// write is detached from the request context, so a client that disconnects
// after its mutation committed does not cost the event.
func TestAdminEventWrittenAfterClientCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &flakyStore{cancel: cancel}
	h, st := withFlakyStore(t, f)
	rr := doJSONCtx(t, h, ctx, http.MethodPost, "/upstreams", "test-admin", upstreamBody("GitHub", nil))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if ctx.Err() == nil {
		t.Fatal("the test's context was not cancelled inside the store call")
	}
	if got := eventsFor(adminEvents(t, st), models.ActionUpstreamCreate); len(got) != 1 {
		t.Fatalf("create events after a client cancel = %+v, want exactly one", got)
	}
}

// serve runs one hand-built request through the handler.
func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func createReq(body any) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/upstreams", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-admin")
	return req
}

// TestAdminEventRemoteAddrAndRequestID covers security requirement 4:
// remote_addr honours the trusted-proxy rule (a forwarding header is ignored
// from an untrusted socket and honoured from a trusted one) and request_id is
// the RequestID middleware's value when the router carries it.
func TestAdminEventRemoteAddrAndRequestID(t *testing.T) {
	t.Run("untrusted socket ignores X-Forwarded-For", func(t *testing.T) {
		_, h, st := testAPI(t)
		req := createReq(upstreamBody("GitHub", nil))
		req.RemoteAddr = "203.0.113.10:4444"
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		if rr := serve(h, req); rr.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
		}
		got := eventsFor(adminEvents(t, st), models.ActionUpstreamCreate)
		if len(got) != 1 || got[0].RemoteAddr != "203.0.113.10" {
			t.Fatalf("remote_addr = %+v, want the socket 203.0.113.10", got)
		}
		if got[0].RequestID != "" {
			t.Errorf("request_id = %q without the RequestID middleware, want empty", got[0].RequestID)
		}
	})
	t.Run("trusted socket takes the forwarded client", func(t *testing.T) {
		s, h, st := testAPI(t)
		s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
		req := createReq(upstreamBody("GitHub", nil))
		req.RemoteAddr = "203.0.113.10:4444"
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		if rr := serve(h, req); rr.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
		}
		got := eventsFor(adminEvents(t, st), models.ActionUpstreamCreate)
		if len(got) != 1 || got[0].RemoteAddr != "198.51.100.7" {
			t.Fatalf("remote_addr = %+v, want the forwarded client 198.51.100.7", got)
		}
	})
	t.Run("request_id from the middleware", func(t *testing.T) {
		_, h, st := testAPI(t)
		wrapped := middleware.RequestID(h)
		if rr := serve(wrapped, createReq(upstreamBody("GitHub", nil))); rr.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
		}
		got := eventsFor(adminEvents(t, st), models.ActionUpstreamCreate)
		if len(got) != 1 || got[0].RequestID == "" {
			t.Fatalf("request_id empty with the RequestID middleware: %+v", got)
		}
	})
}

// TestAdminEventBoundsStoredText covers security requirement 11: a near-
// unbounded name or X-Request-Id is cleaned and cut to 256 bytes of valid
// UTF-8 on the row, with a newline as a space and no escape byte, while the
// resource keeps its full name.
func TestAdminEventBoundsStoredText(t *testing.T) {
	_, h, st := testAPI(t)
	name := "prod\nread\x1b[31monly " + strings.Repeat("a", 10*1024)
	wrapped := middleware.RequestID(h)
	req := createReq(upstreamBody(name, nil))
	req.Header.Set("X-Request-Id", strings.Repeat("r", 10*1024))
	if rr := serve(wrapped, req); rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	got := eventsFor(adminEvents(t, st), models.ActionUpstreamCreate)
	if len(got) != 1 {
		t.Fatalf("%d create events", len(got))
	}
	e := got[0]
	if len(e.ResourceName) > 256 || !utf8.ValidString(e.ResourceName) {
		t.Errorf("resource_name is %d bytes, valid utf8 %v", len(e.ResourceName), utf8.ValidString(e.ResourceName))
	}
	if !strings.HasPrefix(e.ResourceName, "prod read") || strings.ContainsRune(e.ResourceName, 0x1b) {
		t.Errorf("resource_name = %q: want the newline as a space and no escape byte", e.ResourceName)
	}
	if len(e.RequestID) > 256 || len(e.RequestID) == 0 {
		t.Errorf("request_id is %d bytes, want 1..256", len(e.RequestID))
	}
	cur := getJSON(t, h, "/upstreams/"+e.ResourceID)
	if cur["name"] != name {
		t.Errorf("the resource's own name was changed: %q", cur["name"])
	}
}

// TestListAdminEvents is acceptance criteria 3 and 4 and security
// requirements 3 and 9: the envelope, newest-first order, the resource_type
// and since filters, the fixed 400 strings, keyset paging, [] on an empty
// page, and 401 without the admin key.
func TestListAdminEvents(t *testing.T) {
	_, h, _ := testAPI(t)
	upID, _ := mustUpstream(t, h, "GitHub", nil)
	gid := mustGroup(t, h, "Research", []string{upID})
	mustVirtualKey(t, h, "demo-vk", "group", gid)

	list := func(query string) (map[string]any, int) {
		t.Helper()
		rr := doJSON(t, h, http.MethodGet, "/admin-events"+query, "test-admin", nil)
		var body map[string]any
		if rr.Code == http.StatusOK {
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
		}
		return body, rr.Code
	}
	events := func(body map[string]any) []map[string]any {
		t.Helper()
		raw, ok := body["admin_events"].([]any)
		if !ok {
			t.Fatalf("admin_events is %T, want an array: %v", body["admin_events"], body)
		}
		out := make([]map[string]any, 0, len(raw))
		for _, e := range raw {
			out = append(out, e.(map[string]any))
		}
		return out
	}

	body, code := list("?limit=5")
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if _, ok := body["next_cursor"]; !ok {
		t.Fatal("envelope has no next_cursor")
	}
	all := events(body)
	if len(all) != 3 {
		t.Fatalf("%d events, want 3 (upstream, group, key creates)", len(all))
	}
	for _, k := range []string{"id", "timestamp", "actor", "action", "resource_type", "resource_id", "resource_name", "details", "request_id", "remote_addr"} {
		if _, ok := all[0][k]; !ok {
			t.Errorf("first event lacks %q: %v", k, all[0])
		}
	}
	// The three rows land inside one second, where the stored text order is
	// not guaranteed to be time order (see TestAdminEventsRoundTrip, which
	// pins newest-first with whole-second fixtures), so the set is asserted
	// here and the order is asserted there.
	actionsOf := func(events []map[string]any) []string {
		out := make([]string, 0, len(events))
		for _, e := range events {
			out = append(out, e["action"].(string))
		}
		slices.Sort(out)
		return out
	}
	allThree := []string{models.ActionGroupCreate, models.ActionUpstreamCreate, models.ActionVirtualKeyCreate}
	if got := actionsOf(all); !slices.Equal(got, allThree) {
		t.Errorf("actions = %v, want %v", got, allThree)
	}

	body, _ = list("?resource_type=virtual_key")
	if got := events(body); len(got) != 1 || got[0]["resource_type"] != "virtual_key" {
		t.Errorf("resource_type filter = %v", got)
	}
	// since on the whole second the oldest row fell in must include that row,
	// which almost always carries a fraction: the handler-to-store path of
	// sinceBound. A plain fmtTime bound would drop it.
	oldest := all[len(all)-1]["timestamp"].(string)
	for _, e := range all {
		if ts := e["timestamp"].(string); ts < oldest {
			oldest = ts
		}
	}
	oldestAt, err := time.Parse(time.RFC3339Nano, oldest)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = list("?since=" + oldestAt.Truncate(time.Second).Format(time.RFC3339))
	if got := events(body); len(got) != 3 {
		t.Errorf("since on the rows' whole second = %d events, want 3", len(got))
	}
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	body, _ = list("?since=" + future)
	if got := events(body); len(got) != 0 || body["admin_events"] == nil {
		t.Errorf("since in the future = %v, want an empty array", body["admin_events"])
	}

	for query, want := range map[string]string{
		"?resource_type=nope": "invalid resource_type",
		"?limit=abc":          "invalid limit",
		"?limit=0":            "invalid limit",
		"?since=yesterday":    "invalid since",
		"?cursor=%2A%2A":      "invalid cursor",
		"?cursor=fHg":         "invalid cursor", // base64url of "|x": decodes to an empty timestamp
	} {
		rr := doJSON(t, h, http.MethodGet, "/admin-events"+query, "test-admin", nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), want) {
			t.Errorf("%s: %d %s, want 400 %q", query, rr.Code, rr.Body.String(), want)
		}
	}

	var seen []string
	cursor := ""
	for i := 0; i < 5; i++ {
		q := "?limit=1"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		body, code := list(q)
		if code != http.StatusOK {
			t.Fatalf("page %d: %d", i, code)
		}
		for _, e := range events(body) {
			seen = append(seen, e["action"].(string))
		}
		cursor, _ = body["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	slices.Sort(seen)
	if !slices.Equal(seen, allThree) {
		t.Errorf("paged actions = %v, want %v (three pages of one)", seen, allThree)
	}

	if rr := doJSON(t, h, http.MethodGet, "/admin-events", "", nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("no admin key: %d, want 401", rr.Code)
	}
}
