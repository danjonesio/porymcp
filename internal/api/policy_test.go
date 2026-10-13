package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/google/uuid"
)

// The tests below are PORM-209's acceptance criteria and its security
// requirements (S1 to S9 in the plan). Audit rows are written with
// InsertAuditLog directly: the proxy writes them through an asynchronous
// queue, which a test here would race.

// policyOf fetches the policy view and decodes it twice: into a map, so a
// test can tell an absent field from a zero one, and into the response type.
func policyOf(t *testing.T, h http.Handler, id, query string) (map[string]any, policyView) {
	t.Helper()
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+id+"/policy"+query, "test-admin", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("policy %s%s: %d %s", id, query, rr.Code, rr.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	var v policyView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return raw, v
}

// putRow writes one audit row for key at ts.
func putRow(t *testing.T, st *store.SQLStore, key, status, msg string, ts time.Time) {
	t.Helper()
	if err := st.InsertAuditLog(context.Background(), &models.AuditLog{
		ID: uuid.NewString(), Timestamp: ts, VirtualKeyID: key, VirtualKeyName: "k",
		Method: "tools/call", Status: status, ErrorMessage: msg, RequestID: "req",
	}); err != nil {
		t.Fatal(err)
	}
}

func groupWithFilter(t *testing.T, h http.Handler, name string, ids []string, filter any) string {
	t.Helper()
	rr := doJSON(t, h, http.MethodPost, "/groups", "test-admin", map[string]any{
		"name": name, "upstream_ids": ids, "tool_filter": filter,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", rr.Code, rr.Body.String())
	}
	var g map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &g)
	return g["id"].(string)
}

// TestPolicyView is criterion 1, amended by A1: by_rule replaces by_reason.
func TestPolicyView(t *testing.T) {
	_, h, st := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	linID, _ := mustUpstream(t, h, "Linear", nil)
	gid := groupWithFilter(t, h, "ops", []string{ghID, linID},
		map[string]any{"mode": "deny", "prefixes": []string{"delete_"}})
	vk := newVirtualKey(t, h, "group", gid, map[string]any{
		"tool_denylist":  []string{"github__delete_repo", "linear__delete_issue"},
		"tool_allowlist": []string{"github__search_code"},
	})
	id := vk["id"].(string)
	other := newVirtualKey(t, h, "group", gid, nil)["id"].(string)

	now := time.Now().UTC().Add(-time.Hour)
	putRow(t, st, id, models.StatusBlocked, "blocked by virtual key denylist", now)
	putRow(t, st, id, models.StatusBlocked, "blocked by virtual key denylist", now.Add(time.Second))
	putRow(t, st, id, models.StatusBlocked, "blocked by group tool_filter", now)
	putRow(t, st, id, models.StatusBlocked, "unknown endpoint: anything", now)
	putRow(t, st, other, models.StatusBlocked, "blocked by virtual key denylist", now)

	raw, v := policyOf(t, h, id, "")
	if want := []string{"key_denylist", "key_allowlist", "group_tool_filter", "http_methods"}; !reflect.DeepEqual(v.Order, want) {
		t.Errorf("order = %v, want %v", v.Order, want)
	}
	if want := []string{"github__delete_repo", "linear__delete_issue"}; !reflect.DeepEqual(v.KeyDenylist, want) {
		t.Errorf("key_denylist = %v", v.KeyDenylist)
	}
	if want := []string{"github__search_code"}; !reflect.DeepEqual(v.KeyAllowlist, want) {
		t.Errorf("key_allowlist = %v", v.KeyAllowlist)
	}
	if v.GroupToolFilter == nil || v.GroupToolFilter.GroupID != gid || v.GroupToolFilter.GroupName != "ops" || v.GroupToolFilter.Malformed {
		t.Fatalf("group_tool_filter = %+v", v.GroupToolFilter)
	}
	var tf models.ToolFilter
	if err := json.Unmarshal(v.GroupToolFilter.ToolFilter, &tf); err != nil || tf.Mode != "deny" || !reflect.DeepEqual(tf.Prefixes, []string{"delete_"}) {
		t.Errorf("tool_filter = %s", v.GroupToolFilter.ToolFilter)
	}
	want := map[string]int{
		"key_denylist": 2, "key_allowlist": 0, "key_lists_unreadable": 0,
		"group_tool_filter": 1, "group_tool_filter_unreadable": 0,
		"http_methods": 0, "http_methods_unreadable": 0,
	}
	if !reflect.DeepEqual(v.Blocked.ByRule, want) {
		t.Errorf("by_rule = %v, want %v", v.Blocked.ByRule, want)
	}
	if _, ok := raw["blocked"].(map[string]any)["by_reason"]; ok {
		t.Error("by_reason is present; A1 replaced it with by_rule")
	}
	if !reflect.DeepEqual(v.TargetKinds, []string{"mcp"}) || v.TargetType != "group" || v.TargetSlug != "" || v.Status != "active" {
		t.Errorf("target = %s %q %v status %s", v.TargetType, v.TargetSlug, v.TargetKinds, v.Status)
	}
}

// TestPolicyViewSingleUpstream is criterion 2, plus the member-kind rule: a
// disabled HTTP member still makes http_methods apply, as the Edit dialog
// shows it.
func TestPolicyViewSingleUpstream(t *testing.T) {
	_, h, _ := testAPI(t)
	ghID, ghSlug := mustUpstream(t, h, "GitHub", nil)
	id := newVirtualKey(t, h, "upstream", ghID, nil)["id"].(string)
	raw, v := policyOf(t, h, id, "")
	if g, ok := raw["group_tool_filter"]; !ok || g != nil {
		t.Errorf("group_tool_filter = %v (present %v), want null", g, ok)
	}
	if m, ok := raw["http_methods"]; !ok || m != nil {
		t.Errorf("http_methods = %v (present %v), want null for a key with no HTTP member", m, ok)
	}
	if v.TargetSlug != ghSlug || !reflect.DeepEqual(v.TargetKinds, []string{"mcp"}) {
		t.Errorf("target_slug %q kinds %v", v.TargetSlug, v.TargetKinds)
	}

	apiID, _ := mustUpstream(t, h, "Billing", map[string]any{
		"kind": "http", "url": "https://example.com/api", "test_path": "/health", "enabled": false,
	})
	gid := mustGroup(t, h, "mixed", []string{ghID, apiID})
	gkey := newVirtualKey(t, h, "group", gid, map[string]any{"http_methods": []string{"GET"}})["id"].(string)
	_, gv := policyOf(t, h, gkey, "")
	if !reflect.DeepEqual(gv.HTTPMethods, []string{"GET"}) {
		t.Errorf("http_methods = %v, want [GET] (a disabled HTTP member still counts)", gv.HTTPMethods)
	}
	if !reflect.DeepEqual(gv.TargetKinds, []string{"mcp", "http"}) {
		t.Errorf("target_kinds = %v", gv.TargetKinds)
	}
}

// TestPolicyViewMalformed is criterion 3: an undecodable list answers
// lists_malformed and no list, and the copied fields equal GET's.
func TestPolicyViewMalformed(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	id := newVirtualKey(t, h, "upstream", ghID, map[string]any{"tool_allowlist": []string{"search"}})["id"].(string)
	healthy := newVirtualKey(t, h, "upstream", ghID, map[string]any{"tool_denylist": []string{"x"}})["id"].(string)
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE virtual_keys SET tool_denylist = ? WHERE id = ?`, `["unterminated`, id); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{id, healthy} {
		raw, _ := policyOf(t, h, k, "")
		get := getJSON(t, h, "/virtual-keys/"+k)
		// Absent and false are the same flag: GET omits it when false, the
		// view always sends it.
		flag := func(m map[string]any, name string) bool { b, _ := m[name].(bool); return b }
		for _, f := range []string{"lists_malformed", "http_methods_malformed"} {
			if flag(raw, f) != flag(get, f) {
				t.Errorf("%s: %s view=%v get=%v", k, f, raw[f], get[f])
			}
			if _, ok := raw[f]; !ok {
				t.Errorf("%s: %s absent from the view; it is always present", k, f)
			}
		}
		for view, getName := range map[string]string{"key_denylist": "tool_denylist", "key_allowlist": "tool_allowlist"} {
			if !reflect.DeepEqual(raw[view], get[getName]) {
				t.Errorf("%s: %s = %v, GET %s = %v", k, view, raw[view], getName, get[getName])
			}
		}
	}
	raw, _ := policyOf(t, h, id, "")
	if raw["lists_malformed"] != true {
		t.Errorf("lists_malformed = %v, want true", raw["lists_malformed"])
	}
	// The list that failed to decode is absent. The other one is whatever GET
	// says (checked above); the dashboard shows neither once the flag is set.
	if _, ok := raw["key_denylist"]; ok {
		t.Error("key_denylist present on a key whose denylist cannot be read")
	}
}

// TestPolicyViewMalformedGroupFilter is S5: a filter the gate refuses
// everything on reads as malformed, whether it is valid JSON of the wrong
// shape or not JSON at all, and the answer still encodes.
func TestPolicyViewMalformedGroupFilter(t *testing.T) {
	_, h, _, path := testAPIStoreFile(t, "http://localhost:8080")
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	gid := mustGroup(t, h, "ops", []string{ghID})
	id := newVirtualKey(t, h, "group", gid, nil)["id"].(string)
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		stored  string
		present bool
	}{
		{`{"mode":"Deny"}`, true},
		{`{"mode":"deny"`, false},
		// Valid JSON that is not an object: malformed, and never echoed under
		// a field the schema types as an object.
		{`["deny"]`, false},
	} {
		if _, err := db.Exec(`UPDATE groups SET tool_filter = ? WHERE id = ?`, tc.stored, gid); err != nil {
			t.Fatal(err)
		}
		raw, v := policyOf(t, h, id, "")
		if v.GroupToolFilter == nil || !v.GroupToolFilter.Malformed {
			t.Errorf("%s: group_tool_filter = %+v, want malformed", tc.stored, v.GroupToolFilter)
			continue
		}
		_, has := raw["group_tool_filter"].(map[string]any)["tool_filter"]
		if has != tc.present {
			t.Errorf("%s: tool_filter present = %v, want %v", tc.stored, has, tc.present)
		}
	}
}

// TestPolicyViewTargetGone: a key whose group or upstream row is gone answers
// a null group and no kinds. DeleteGroup refuses while a key references the
// group, so the dangling target is seeded at the database level, as
// TestListVirtualKeysIncludesEndpoints does.
func TestPolicyViewTargetGone(t *testing.T) {
	_, h, st := testAPI(t)
	for _, tc := range []struct{ id, typ, target string }{
		{"gone-group-key", models.TargetGroup, "no-such-group"},
		{"gone-upstream-key", models.TargetUpstream, "no-such-upstream"},
	} {
		if err := st.CreateVirtualKey(context.Background(), &models.VirtualKey{
			ID: tc.id, Name: "orphan", KeyHash: "not-a-real-hash", KeyLookup: tc.id + "-lookup",
			KeyPrefix: "pory_gone", TargetType: tc.typ, TargetID: tc.target, CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		raw, v := policyOf(t, h, tc.id, "")
		if g, ok := raw["group_tool_filter"]; !ok || g != nil {
			t.Errorf("%s: group_tool_filter = %v (present %v), want null", tc.id, g, ok)
		}
		if len(v.TargetKinds) != 0 || raw["target_kinds"] == nil {
			t.Errorf("%s: target_kinds %v, want []", tc.id, raw["target_kinds"])
		}
		if v.TargetType != tc.typ {
			t.Errorf("%s: target_type %q", tc.id, v.TargetType)
		}
	}
}

// TestPolicyViewEmptyGroup: a group that exists with no members answers its
// filter (not null, which means gone) and no kinds. The dialog tells the two
// apart by group_tool_filter, so this is the server half of that rule.
func TestPolicyViewEmptyGroup(t *testing.T) {
	_, h, _ := testAPI(t)
	gid := groupWithFilter(t, h, "empty", []string{}, map[string]any{"mode": "deny", "tools": []string{"x__y"}})
	id := newVirtualKey(t, h, "group", gid, nil)["id"].(string)
	raw, v := policyOf(t, h, id, "")
	if v.GroupToolFilter == nil || v.GroupToolFilter.GroupName != "empty" {
		t.Fatalf("group_tool_filter = %v, want the empty group", raw["group_tool_filter"])
	}
	if len(v.TargetKinds) != 0 {
		t.Errorf("target_kinds = %v, want []", v.TargetKinds)
	}
}

// TestPolicyViewPeriod is criterion 4 and S7.
func TestPolicyViewPeriod(t *testing.T) {
	_, h, st := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	id := newVirtualKey(t, h, "upstream", ghID, nil)["id"].(string)
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	putRow(t, st, id, models.StatusBlocked, "blocked by virtual key denylist", base)
	putRow(t, st, id, models.StatusBlocked, "blocked by virtual key denylist", base.Add(48*time.Hour))

	q := func(since, until time.Time) string {
		return "?since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)
	}
	_, both := policyOf(t, h, id, q(base.Add(-time.Hour), base.Add(72*time.Hour)))
	_, first := policyOf(t, h, id, q(base.Add(-time.Hour), base.Add(time.Hour)))
	if both.Blocked.ByRule["key_denylist"] != 2 || first.Blocked.ByRule["key_denylist"] != 1 {
		t.Errorf("counts both=%d first=%d, want 2 and 1", both.Blocked.ByRule["key_denylist"], first.Blocked.ByRule["key_denylist"])
	}
	if first.Blocked.Since != base.Add(-time.Hour).Format(time.RFC3339Nano) || first.Blocked.Until != base.Add(time.Hour).Format(time.RFC3339Nano) {
		t.Errorf("echoed period %s to %s", first.Blocked.Since, first.Blocked.Until)
	}
	// A bound with a fraction and an offset is echoed as the instant used, in
	// UTC and to the nanosecond, and the fraction still bounds the count: the
	// row at base is 1 ns inside this until.
	frac := "?since=" + url.QueryEscape("2026-09-01T13:00:00.0000000015+02:00") + "&until=" + url.QueryEscape("2026-09-01T14:00:00.0000000015+02:00")
	_, fv := policyOf(t, h, id, frac)
	// Go truncates a fraction past nine digits, so 1.5 ns reads as 1 ns.
	if fv.Blocked.Since != "2026-09-01T11:00:00.000000001Z" {
		t.Errorf("since echoed as %q", fv.Blocked.Since)
	}
	if fv.Blocked.Until != "2026-09-01T12:00:00.000000001Z" || fv.Blocked.ByRule["key_denylist"] != 1 {
		t.Errorf("until echoed as %q, count %d; want 12:00:00.000000001Z and 1", fv.Blocked.Until, fv.Blocked.ByRule["key_denylist"])
	}
	// since after until is an empty period, as GET /logs answers it.
	_, empty := policyOf(t, h, id, q(base.Add(72*time.Hour), base.Add(-time.Hour)))
	if empty.Blocked.ByRule["key_denylist"] != 0 {
		t.Errorf("since after until counted %d", empty.Blocked.ByRule["key_denylist"])
	}
	// The default period ends now, so these September rows are outside it.
	_, def := policyOf(t, h, id, "")
	if def.Blocked.ByRule["key_denylist"] != 0 {
		t.Errorf("default period counted %d", def.Blocked.ByRule["key_denylist"])
	}

	for _, tc := range []struct{ query, msg string }{
		{"?since=nope", "invalid since"},
		{"?until=nope", "invalid until"},
		{q(base, base.Add(91*24*time.Hour)), "period longer than 90 days"},
	} {
		rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+id+"/policy"+tc.query, "test-admin", nil)
		wantError(t, rr, http.StatusBadRequest, tc.msg)
	}
}

// TestPolicyViewEgress is criterion 5, with the count split by class (A3).
// testAPI turns loopback on for its stubs, so both values are set here.
func TestPolicyViewEgress(t *testing.T) {
	s, h, st := testAPI(t)
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	id := newVirtualKey(t, h, "upstream", ghID, nil)["id"].(string)

	s.cfg.UpstreamGuard = netguard.Options{}
	_, off := policyOf(t, h, id, "")
	if off.Egress.AllowLoopback || off.Egress.DenyPrivate {
		t.Errorf("egress = %+v, want both false", off.Egress)
	}
	s.cfg.UpstreamGuard = netguard.Options{AllowLoopback: true, DenyPrivate: true}
	putRow(t, st, id, models.StatusError, "upstream address denied: loopback", time.Now().UTC().Add(-time.Minute))
	putRow(t, st, id, models.StatusError, "upstream address denied: loopback and more", time.Now().UTC().Add(-time.Minute))
	raw, on := policyOf(t, h, id, "")
	if !on.Egress.AllowLoopback || !on.Egress.DenyPrivate {
		t.Errorf("egress = %+v, want both true", on.Egress)
	}
	if on.Blocked.UpstreamAddressDenied != 1 || on.Blocked.UpstreamAddressDeniedByClass["loopback"] != 1 {
		t.Errorf("upstream_address_denied = %d, by class %v", on.Blocked.UpstreamAddressDenied, on.Blocked.UpstreamAddressDeniedByClass)
	}
	if len(on.Blocked.UpstreamAddressDeniedByClass) != 6 {
		t.Errorf("by class has %d keys, want all six", len(on.Blocked.UpstreamAddressDeniedByClass))
	}
	if eg := raw["egress"].(map[string]any); len(eg) != 2 {
		t.Errorf("egress carries %v; only the two switches belong there", eg)
	}
}

// TestPolicyViewNoSecrets is S2: nothing that authenticates anything is in
// the answer, neither the key's own plaintext nor an upstream credential.
func TestPolicyViewNoSecrets(t *testing.T) {
	_, h, _ := testAPI(t)
	apiID, _ := mustUpstream(t, h, "Billing", map[string]any{
		"kind": "http", "url": "https://billing.example.com/api", "test_path": "/health",
		"auth_type": "bearer", "auth_config": map[string]any{"token": "stored-token-1"},
	})
	created := newVirtualKey(t, h, "upstream", apiID, nil)
	plaintext, _ := created["api_key"].(string)
	if plaintext == "" {
		t.Fatal("create answered no api_key")
	}
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+created["id"].(string)+"/policy", "test-admin", nil)
	body := rr.Body.String()
	for _, bad := range []string{plaintext, "pory_", "api_key", "key_hash", "key_lookup", "auth_config", "stored-token-1", "billing.example.com"} {
		if strings.Contains(body, bad) {
			t.Errorf("policy body contains %q: %s", bad, body)
		}
	}
}

// countForbidden fails the test if the handler ever counts.
type countForbidden struct {
	store.Store
	t *testing.T
}

func (s countForbidden) CountBlockedByReason(context.Context, string, time.Time, time.Time, []string, []string) (models.RefusalCounts, error) {
	s.t.Error("CountBlockedByReason ran for a key that does not exist")
	return models.RefusalCounts{}, nil
}

// TestPolicyViewUnknownKey is S8: an unknown key answers 404 before any count.
func TestPolicyViewUnknownKey(t *testing.T) {
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return countForbidden{st, t} })
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/no-such-key/policy", "test-admin", nil)
	wantError(t, rr, http.StatusNotFound, "not found")
}

// slowCounts holds CountBlockedByReason until its context ends, as a count
// over a very busy key would.
type slowCounts struct{ store.Store }

func (s slowCounts) CountBlockedByReason(ctx context.Context, _ string, _, _ time.Time, _, _ []string) (models.RefusalCounts, error) {
	<-ctx.Done()
	return models.RefusalCounts{}, ctx.Err()
}

// TestPolicyViewCountTimeout is S7: a count that outlives its deadline
// answers 503, decided on the context rather than the driver's error.
func TestPolicyViewCountTimeout(t *testing.T) {
	_, h, _, _ := testAPIWrappedStore(t, "http://localhost:8080", func(st store.Store) store.Store { return slowCounts{st} })
	ghID, _ := mustUpstream(t, h, "GitHub", nil)
	id := newVirtualKey(t, h, "upstream", ghID, nil)["id"].(string)
	rr := doJSON(t, h, http.MethodGet, "/virtual-keys/"+id+"/policy", "test-admin", nil)
	wantError(t, rr, http.StatusServiceUnavailable, "policy counts took too long")
}
