package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// TestReportToolPolicyProblemsNamesOnlyBrokenGroups pins the one thing an
// operator upgrading to PORM-19 relies on: a group whose tool_filter the proxy
// cannot enforce is named in the log before the server starts serving, because
// every tool call on that group is now blocked and nothing in the request path
// would say so. Groups the proxy can enforce must stay silent, or the report
// is noise the operator learns to skip.
//
// The groups are written straight through the store, which does not validate,
// that is exactly how a filter written before PORM-19 (or by hand in the
// database) arrives at startup.
func TestReportToolPolicyProblemsNamesOnlyBrokenGroups(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	for _, g := range []models.Group{
		{ID: "g-none", Name: "no filter", UpstreamIDs: []string{}},
		// An unscoped deny entry, which is a filter with nothing wrong with it:
		// it is matched against each member's own tool name on every endpoint
		// the key is served through, it names no member so it cannot name one
		// the group has not got, and deny entries are never skipped. So it
		// draws neither the invalid-filter error nor either warning, which is
		// what this test is about, the report staying quiet when the
		// configuration works.
		{ID: "g-good", Name: "enforceable", UpstreamIDs: []string{},
			ToolFilter: json.RawMessage(`{"mode":"deny","tools":["delete_repo"]}`)},
		// Decodes without error into a filter that matches nothing: mode is
		// compared byte-exactly, so "Deny" is not "deny".
		{ID: "g-bad", Name: "typo group", UpstreamIDs: []string{},
			ToolFilter: json.RawMessage(`{"mode":"Deny","tools":["x"]}`)},
	} {
		g.CreatedAt, g.UpdatedAt = now, now
		if err := st.CreateGroup(ctx, &g); err != nil {
			t.Fatalf("seed %s: %v", g.ID, err)
		}
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reportToolPolicyProblems(ctx, st, log)

	records := decodeLogRecords(t, &buf)
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1 (only the broken group):\n%s", len(records), buf.String())
	}

	rec := records[0]
	if rec["level"] != "ERROR" {
		t.Errorf("level=%v, want ERROR", rec["level"])
	}
	if want := "group tool_filter is invalid; every tool call on this group is blocked until it is fixed"; rec["msg"] != want {
		t.Errorf("msg=%v, want %q", rec["msg"], want)
	}
	if rec["group_id"] != "g-bad" {
		t.Errorf("group_id=%v, want g-bad", rec["group_id"])
	}
	if rec["group_name"] != "typo group" {
		t.Errorf("group_name=%v, want %q", rec["group_name"], "typo group")
	}
	// The operator has to be able to act on the record without a debugger, so
	// the reason has to reach the log, not just the fact that something failed.
	if errText, _ := rec["err"].(string); !strings.Contains(errText, "mode") {
		t.Errorf("err=%v, want it to name the offending field", rec["err"])
	}
}

// decodeLogRecords reads the JSON handler's output back one record per line.
// Asserting on decoded records rather than on substrings of the buffer is what
// keeps "the group id reached the log" from passing because the id happened to
// appear somewhere inside another field.
func decodeLogRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

// The two upstreams every case of TestReportToolPolicyProblems is seeded with.
// docs is disabled on purpose: disabling an upstream is reversible, so a rule
// naming it is dormant rather than wrong, and an entry scoped to docs must not
// be counted as naming a member that is not there.
const (
	upGH   = "u-gh"
	upDocs = "u-docs"
)

// toolEntryTexts is every entry string the fixtures below write into a filter
// or a key list. No case may repeat one in the log: entries are
// operator-written text about someone's private deployment, and ids, names and
// counts are the whole report.
var toolEntryTexts = []string{
	"gh__delete_repo", "docs__", "delete_repo", "github_search", "docs_search",
	"gh__gh_read", "nope__delete_repo", "docs__search", "search", "safe_tool",
	"mcp__fetch", "gh__mcp__fetch", "docs__mcp__fetch", "zzz__delete_repo",
}

// seedPolicyStore builds one deployment: the two upstreams above, plus the
// groups and keys a case is about. Each case gets its own store, so "drew
// nothing" means the log is empty rather than merely unchanged. The path comes
// back for the one case that has to reach past the store to corrupt a column.
func seedPolicyStore(t *testing.T, groups []models.Group, keys []models.VirtualKey) (store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, u := range []models.Upstream{
		{ID: upGH, Name: "one", Slug: "gh", Enabled: true},
		{ID: upDocs, Name: "two", Slug: "docs", Enabled: false},
	} {
		u.URL, u.Transport, u.AuthType = "http://127.0.0.1:1/mcp", models.TransportStreamableHTTP, models.AuthNone
		u.CreatedAt, u.UpdatedAt = now, now
		if err := st.CreateUpstream(ctx, &u); err != nil {
			t.Fatalf("seed upstream %s: %v", u.ID, err)
		}
	}
	for _, g := range groups {
		g.CreatedAt, g.UpdatedAt = now, now
		if err := st.CreateGroup(ctx, &g); err != nil {
			t.Fatalf("seed group %s: %v", g.ID, err)
		}
	}
	for _, k := range keys {
		// The report never looks at a key's secret, but key_lookup is unique,
		// so each row needs its own.
		k.KeyHash, k.KeyLookup, k.KeyPrefix = k.ID, k.ID, "pk_"
		k.CreatedAt = now
		if err := st.CreateVirtualKey(ctx, &k); err != nil {
			t.Fatalf("seed key %s: %v", k.ID, err)
		}
	}
	return st, path
}

// corruptDenylist writes a value into one key's tool_denylist column that no
// exported call could produce, through a second connection to the same file.
// The flag under test is set by the scan that fails to decode it, so the
// corruption has to be real: going through the store would only ever store
// valid JSON.
func corruptDenylist(t *testing.T, path, keyID string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE virtual_keys SET tool_denylist = ? WHERE id = ?`, `["unterminated`, keyID); err != nil {
		t.Fatalf("corrupt tool_denylist: %v", err)
	}
}

// TestReportToolPolicyProblems is the whole report read as the operator reads
// it: which configurations draw a line, which draw nothing, and what the line
// says. Every case is written straight through the store, bypassing the
// management API's validation, which is exactly how the rules this report
// exists for got into a database in the first place.
//
// The cases that draw nothing carry as much weight as the ones that do. A rule
// that works must be silent, or the report becomes a wall the operator scrolls
// past and the two lines that matter go with it.
func TestReportToolPolicyProblems(t *testing.T) {
	type wantRec struct {
		level  string
		msgHas string
		// id is the group_id or virtual_key_id the record names, one record
		// per entity, so it identifies the record as well.
		id string
		// counts says the record carries the two entry counts. The
		// invalid-filter error and the unreadable-lists warning do not: there
		// is nothing countable behind either.
		counts                   bool
		unmatched, unscopedAllow float64
		hint                     bool
	}
	for _, tc := range []struct {
		name    string
		groups  []models.Group
		keys    []models.VirtualKey
		corrupt string // the virtual key whose tool_denylist is made unreadable
		want    []wantRec
	}{
		{
			name: "rules that work draw nothing",
			groups: []models.Group{
				// Scoped to members the group actually has, in both lists.
				{ID: "g-scoped", Name: "one", UpstreamIDs: []string{upGH, upDocs},
					ToolFilter: json.RawMessage(`{"mode":"deny","tools":["gh__delete_repo"],"prefixes":["docs__"]}`)},
				// Unscoped deny entries, and every one of them is enforced.
				// "delete_repo" is a plain tool name; "github_search" and
				// "docs_search" are the shape the store's migration
				// deliberately keeps, where a bare name looks as if it might
				// be a slug and a tool joined by one underscore. Reading them
				// as scoped would be a guess, so the proxy matches them
				// against each member's own tool name and this report says
				// nothing about them.
				{ID: "g-bare-deny", Name: "two", UpstreamIDs: []string{upGH, upDocs},
					ToolFilter: json.RawMessage(`{"mode":"deny","tools":["delete_repo","github_search","docs_search"]}`)},
				{ID: "g-scoped-allow", Name: "three", UpstreamIDs: []string{upGH},
					ToolFilter: json.RawMessage(`{"mode":"allow","tools":["gh__gh_read"]}`)},
			},
			keys: []models.VirtualKey{
				{ID: "k-group", Name: "one", TargetType: models.TargetGroup, TargetID: "g-scoped",
					ToolAllowlist: []string{"gh__gh_read"}, ToolDenylist: []string{"delete_repo", "docs__search"}},
			},
		},
		{
			name: "a group filter scoped to a member the group has not got",
			groups: []models.Group{
				{ID: "g-stranger", Name: "one", UpstreamIDs: []string{upGH},
					ToolFilter: json.RawMessage(`{"mode":"deny","tools":["nope__delete_repo"]}`)},
			},
			want: []wantRec{{level: "WARN", msgHas: "group tool_filter has entries that can match no tool",
				id: "g-stranger", counts: true, unmatched: 1}},
		},
		{
			name: "a key list scoped to a member the target has not got",
			groups: []models.Group{
				{ID: "g-plain", Name: "one", UpstreamIDs: []string{upGH}},
			},
			keys: []models.VirtualKey{
				{ID: "k-stranger", Name: "one", TargetType: models.TargetGroup, TargetID: "g-plain",
					ToolDenylist: []string{"nope__delete_repo"}},
				// The same mistake against a single-upstream key, where the
				// one member is the target itself: an entry scoped to docs on
				// a key bound to gh admits nothing at all.
				{ID: "k-foreign", Name: "two", TargetType: models.TargetUpstream, TargetID: upGH,
					ToolAllowlist: []string{"docs__search"}},
			},
			want: []wantRec{
				{level: "WARN", msgHas: "virtual key tool list has entries that can match no tool",
					id: "k-stranger", counts: true, unmatched: 1},
				{level: "WARN", msgHas: "virtual key tool list has entries that can match no tool",
					id: "k-foreign", counts: true, unmatched: 1},
			},
		},
		{
			name: "an unscoped entry in an allow rule on a group",
			groups: []models.Group{
				{ID: "g-plain", Name: "one", UpstreamIDs: []string{upGH}},
				{ID: "g-allow-bare", Name: "two", UpstreamIDs: []string{upGH},
					ToolFilter: json.RawMessage(`{"mode":"allow","tools":["search"]}`)},
			},
			keys: []models.VirtualKey{
				{ID: "k-group-allow", Name: "one", TargetType: models.TargetGroup, TargetID: "g-plain",
					ToolAllowlist: []string{"search"}},
				// The contrast, and the reason the rule is about groups rather
				// than about allowlists: a key bound to one upstream has
				// exactly one member, so a bare allow entry names the only
				// tool it could name. The proxy admits it and this report must
				// not call it a problem.
				{ID: "k-upstream-allow", Name: "two", TargetType: models.TargetUpstream, TargetID: upGH,
					ToolAllowlist: []string{"search"}},
				// A bare entry on the deny side of a group key, for the same
				// reason: "block this name wherever it appears" is exactly
				// what it means.
				{ID: "k-group-deny", Name: "three", TargetType: models.TargetGroup, TargetID: "g-plain",
					ToolDenylist: []string{"search"}},
			},
			want: []wantRec{
				{level: "WARN", msgHas: "group tool_filter has entries that can match no tool",
					id: "g-allow-bare", counts: true, unscopedAllow: 1, hint: true},
				{level: "WARN", msgHas: "virtual key tool list has entries that can match no tool",
					id: "k-group-allow", counts: true, unscopedAllow: 1, hint: true},
			},
		},
		{
			// The exact output of the store's schema-3 rewrite for a pre-v0.1
			// deny entry "mcp__fetch": the scoped form for every member is added
			// and the original is kept, because dropping an entry from a deny
			// rule widens it. mcp is a reserved word no upstream can hold, so
			// the kept entry looks scoped to a stranger for ever, and a report
			// that fires on its own migration's output, on every restart, is a
			// report the operator learns to filter out.
			name: "the entries the migration itself writes",
			groups: []models.Group{
				{ID: "g-migrated", Name: "one", UpstreamIDs: []string{upGH, upDocs},
					ToolFilter: json.RawMessage(`{"mode":"deny","tools":["mcp__fetch","gh__mcp__fetch","docs__mcp__fetch"]}`)},
			},
			keys: []models.VirtualKey{
				// The same rewrite on a single-upstream key, where the one
				// member is the target itself.
				{ID: "k-migrated-solo", Name: "one", TargetType: models.TargetUpstream, TargetID: upGH,
					ToolDenylist: []string{"mcp__fetch", "gh__mcp__fetch"}},
				// And on a key bound to the two-member group.
				{ID: "k-migrated-group", Name: "two", TargetType: models.TargetGroup, TargetID: "g-migrated",
					ToolDenylist: []string{"mcp__fetch", "gh__mcp__fetch", "docs__mcp__fetch"}},
			},
		},
		{
			name: "a deny entry the migration did not write is still counted",
			groups: []models.Group{
				{ID: "g-two", Name: "two members", UpstreamIDs: []string{upGH, upDocs}},
			},
			keys: []models.VirtualKey{
				// An operator's typo: a scope no member holds, and nothing in
				// the list stands in for it.
				{ID: "k-typo", Name: "one", TargetType: models.TargetUpstream, TargetID: upGH,
					ToolDenylist: []string{"zzz__delete_repo"}},
				// Half the migration's output, which is what it becomes when
				// the group gains a member afterwards: nothing here denies
				// "fetch" on docs, and that gap is the operator's to close.
				{ID: "k-partial", Name: "two", TargetType: models.TargetGroup, TargetID: "g-two",
					ToolDenylist: []string{"mcp__fetch", "gh__mcp__fetch"}},
			},
			want: []wantRec{
				{level: "WARN", msgHas: "virtual key tool list has entries that can match no tool",
					id: "k-typo", counts: true, unmatched: 1},
				{level: "WARN", msgHas: "virtual key tool list has entries that can match no tool",
					id: "k-partial", counts: true, unmatched: 1},
			},
		},
		{
			// The carve-out is the deny side's alone. No migration has ever
			// written an allow rule (widening one is not a migration's decision
			// to make) so a scope no member holds is exactly the silently dead
			// allowlist this report exists to name.
			name: "the same entries in an allow rule are still counted",
			groups: []models.Group{
				{ID: "g-allow", Name: "one", UpstreamIDs: []string{upGH, upDocs},
					ToolFilter: json.RawMessage(`{"mode":"allow","tools":["mcp__fetch","gh__mcp__fetch","docs__mcp__fetch"]}`)},
			},
			keys: []models.VirtualKey{
				{ID: "k-allow", Name: "one", TargetType: models.TargetGroup, TargetID: "g-allow",
					ToolAllowlist: []string{"mcp__fetch", "gh__mcp__fetch", "docs__mcp__fetch"}},
			},
			want: []wantRec{
				{level: "WARN", msgHas: "group tool_filter has entries that can match no tool",
					id: "g-allow", counts: true, unmatched: 1},
				{level: "WARN", msgHas: "virtual key tool list has entries that can match no tool",
					id: "k-allow", counts: true, unmatched: 1},
			},
		},
		{
			name: "a key whose lists could not be decoded",
			keys: []models.VirtualKey{
				{ID: "k-corrupt", Name: "one", TargetType: models.TargetUpstream, TargetID: upGH,
					ToolDenylist: []string{"delete_repo"}},
			},
			corrupt: "k-corrupt",
			want: []wantRec{{level: "WARN", msgHas: "virtual key tool lists could not be decoded",
				id: "k-corrupt"}},
		},
		{
			name: "an invalid filter is the whole report for its group",
			groups: []models.Group{
				// The entries would draw a warning of their own (nope__delete_repo
				// names no member, "search" is unscoped in an allow rule) and they
				// draw nothing, because the proxy blocks every tool on this group
				// until the mode is fixed and which member an entry would have
				// named is not the question yet.
				{ID: "g-invalid", Name: "one", UpstreamIDs: []string{upGH},
					ToolFilter: json.RawMessage(`{"mode":"Allow","tools":["nope__delete_repo","search"]}`)},
			},
			want: []wantRec{{level: "ERROR", msgHas: "group tool_filter is invalid", id: "g-invalid"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, path := seedPolicyStore(t, tc.groups, tc.keys)
			if tc.corrupt != "" {
				corruptDenylist(t, path, tc.corrupt)
			}

			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			reportToolPolicyProblems(context.Background(), st, log)

			records := decodeLogRecords(t, &buf)
			byID := make(map[string]map[string]any, len(records))
			for _, rec := range records {
				id, _ := rec["group_id"].(string)
				if id == "" {
					id, _ = rec["virtual_key_id"].(string)
				}
				if _, dup := byID[id]; dup {
					t.Fatalf("%s was reported twice; one line per group or key, or the operator has to reconcile them:\n%s", id, buf.String())
				}
				byID[id] = rec
			}
			if len(records) != len(tc.want) {
				t.Fatalf("got %d records, want %d:\n%s", len(records), len(tc.want), buf.String())
			}

			for _, w := range tc.want {
				rec, ok := byID[w.id]
				if !ok {
					t.Fatalf("no record for %s; the operator gets no notice at all:\n%s", w.id, buf.String())
				}
				if rec["level"] != w.level {
					t.Errorf("%s level=%v, want %s", w.id, rec["level"], w.level)
				}
				if msg, _ := rec["msg"].(string); !strings.Contains(msg, w.msgHas) {
					t.Errorf("%s msg=%q, want it to contain %q", w.id, msg, w.msgHas)
				}
				if !w.counts {
					if _, has := rec["unmatched_entries"]; has {
						t.Errorf("%s carries entry counts; there is nothing countable behind this record: %v", w.id, rec)
					}
					continue
				}
				if rec["unmatched_entries"] != w.unmatched {
					t.Errorf("%s unmatched_entries=%v, want %v", w.id, rec["unmatched_entries"], w.unmatched)
				}
				if rec["unscoped_allow_entries"] != w.unscopedAllow {
					t.Errorf("%s unscoped_allow_entries=%v, want %v", w.id, rec["unscoped_allow_entries"], w.unscopedAllow)
				}
				// The counts say how many; the hint says how to spell the rule so
				// it means something. It is attached only to the mistake it
				// explains, a hint about an allow rule on a filter that has no
				// allow rule is how a report becomes noise.
				hint, hasHint := rec["hint"].(string)
				if hasHint != w.hint {
					t.Errorf("%s hint present=%v, want %v (hint=%q)", w.id, hasHint, w.hint, hint)
				}
				if w.hint && !strings.Contains(hint, "must name a member") {
					t.Errorf("%s hint=%q does not say what to write instead", w.id, hint)
				}
			}

			// The entries themselves never reach the log, ids, names and counts
			// are the whole report. A tool name is operator-written text about
			// someone's private deployment.
			for _, entry := range toolEntryTexts {
				if strings.Contains(buf.String(), entry) {
					t.Errorf("the log repeats rule contents (%q):\n%s", entry, buf.String())
				}
			}
		})
	}
}

// TestReportToolPolicyProblemsSurvivesStoreFailure: a closed store stands in
// for any database trouble at startup. The report must log and return, never
// panic or take the server down with it, the proxy and the dashboard do not
// depend on this check having run.
//
// All three reads are named, because the report needs all three tables and one
// message would hide the other two failures: an operator who fixed whatever
// broke ListGroups would never learn that the key and upstream halves of the
// check had not run either.
func TestReportToolPolicyProblemsSurvivesStoreFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reportToolPolicyProblems(context.Background(), st, log)

	for _, want := range []string{
		"could not check group tool_filters at startup",
		"could not check upstream slugs at startup",
		"could not check virtual key tool lists at startup",
	} {
		if got := buf.String(); !strings.Contains(got, want) {
			t.Errorf("store failure was not reported (%q): %q", want, got)
		}
	}
}

// TestReportToolPolicyProblemsNamesAnInvalidStoredSlug covers the one way a
// deployment can reach a state the proxy calls impossible.
//
// The store validates every stored slug once, at the migration step that
// introduced the {slug}__{tool} identity, and never again. A slug edited by hand
// in the database afterwards is composed into a group's catalogue unconditionally
// (the aggregate advertises "Bad Slug__search") while the proxy parses the name
// it is called with and refuses anything whose head is not a slug. So every tool
// this upstream advertises there is listed under a name no call can use, and
// nothing in the request path says why: the catalogue is served, the call comes
// back "unknown tool", and the two answers disagree.
//
// The slug itself must not reach the log. It is operator-written text about
// someone's private deployment, exactly like a rule entry, and the id is enough
// to find the row.
func TestReportToolPolicyProblemsNamesAnInvalidStoredSlug(t *testing.T) {
	const badSlug = "Bad Slug"
	st, path := seedPolicyStore(t, nil, nil)
	db, err := sql.Open("sqlite", "file://"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Through a second connection, because nothing exported would store this:
	// the API derives and validates a slug on every write.
	if _, err := db.Exec(`UPDATE upstreams SET slug = ? WHERE id = ?`, badSlug, upGH); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reportToolPolicyProblems(context.Background(), st, log)

	records := decodeLogRecords(t, &buf)
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1 (the one bad slug):\n%s", len(records), buf.String())
	}
	rec := records[0]
	if rec["level"] != "ERROR" {
		t.Errorf("level=%v, want ERROR: a tool that is advertised and cannot be called is broken, not merely suspect", rec["level"])
	}
	if msg, _ := rec["msg"].(string); !strings.Contains(msg, "slug") {
		t.Errorf("msg=%q does not say what is wrong", msg)
	}
	if rec["upstream_id"] != upGH {
		t.Errorf("upstream_id=%v, want %s; the operator has to be able to find the row", rec["upstream_id"], upGH)
	}
	if rec["upstream_name"] != "one" {
		t.Errorf("upstream_name=%v, want %q", rec["upstream_name"], "one")
	}
	if strings.Contains(buf.String(), badSlug) {
		t.Errorf("the log repeats the stored slug:\n%s", buf.String())
	}
	// docs, whose slug is untouched, draws nothing: this report stays silent
	// about what works.
	if strings.Contains(buf.String(), upDocs) {
		t.Errorf("the valid upstream was reported too:\n%s", buf.String())
	}
}
