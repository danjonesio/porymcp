package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

func TestFileDSNRelativeHasNoAuthority(t *testing.T) {
	dsn := fileDSN("./data/porymcp.db")
	if want := "file:./data/porymcp.db?"; dsn[:len(want)] != want {
		t.Fatalf("relative DSN %q should start with %q", dsn, want)
	}
}

func TestParseDBURLDefaultLocalPath(t *testing.T) {
	driver, dsn, err := parseDBURL("sqlite://./pory-rel-test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove("pory-rel-test.db") })
	if driver != "sqlite" {
		t.Fatalf("driver=%s", driver)
	}
	if dsn[:len("file:./")] != "file:./" {
		t.Fatalf("sqlite://./… should become file:./…, got %s", dsn)
	}
}

func TestOpenDefaultRelativeSQLite(t *testing.T) {
	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	s, err := Open("sqlite://./data/porymcp.db")
	if err != nil {
		t.Fatalf("Open default-style URL: %v", err)
	}
	defer s.Close()
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}

	s2, err := Open("./data/other.db")
	if err != nil {
		t.Fatalf("Open bare relative path: %v", err)
	}
	defer s2.Close()
}

func testStore(t *testing.T) *SQLStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pory.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestUpstreamCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &models.Upstream{
		ID: "u1", Name: "GitHub", Slug: "github", URL: "https://example.com/mcp",
		Transport: models.TransportStreamableHTTP, AuthType: models.AuthBearer,
		AuthConfig: []byte("cipher"), Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpstream(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "GitHub" || got.Slug != "github" || string(got.AuthConfig) != "cipher" {
		t.Fatalf("%+v", got)
	}
	// A row nobody has tested yet reads back with both test columns unset:
	// NULL is "never tested", and CreateUpstream wrote the struct's own nils.
	if got.LastTestAt != nil || got.LastTestOK != nil {
		t.Fatalf("a created upstream reads back tested: at=%v ok=%v", got.LastTestAt, got.LastTestOK)
	}
	list, err := s.ListUpstreams(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	if err := s.DeleteUpstream(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUpstream(ctx, "u1"); err != ErrNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestVirtualKeyLookupAndAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	a := &models.VirtualKey{
		ID: "a1", Name: "cursor", KeyHash: "hash", KeyLookup: "lookup",
		KeyPrefix: "pory_abc", TargetType: models.TargetUpstream, TargetID: "u1",
		CreatedAt: now,
	}
	if err := s.CreateVirtualKey(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVirtualKeyByLookup(ctx, "lookup")
	if err != nil || got.Name != "cursor" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	e := &models.AuditLog{
		ID: "l1", Timestamp: now, VirtualKeyID: "a1", VirtualKeyName: "cursor",
		Method: "tools/call", ToolName: "search", Status: models.StatusSuccess, RequestID: "r1",
	}
	if err := s.InsertAuditLog(ctx, e); err != nil {
		t.Fatal(err)
	}
	logs, next, err := s.ListAuditLogs(ctx, models.LogFilter{Limit: 10})
	if err != nil || len(logs) != 1 || next != "" {
		t.Fatalf("logs=%v next=%s err=%v", logs, next, err)
	}
}

func TestDeleteUpstreamInUse(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	newUpstream := func(t *testing.T, s *SQLStore) {
		t.Helper()
		u := &models.Upstream{ID: "u1", Name: "A", Slug: "a", URL: "http://x", Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
		if err := s.CreateUpstream(ctx, u); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("referenced by a group", func(t *testing.T) {
		s := testStore(t)
		newUpstream(t, s)
		g := &models.Group{ID: "g1", Name: "bundle", UpstreamIDs: []string{"u1"}, CreatedAt: now, UpdatedAt: now}
		if err := s.CreateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteUpstream(ctx, "u1"); err != ErrInUse {
			t.Fatalf("want in use, got %v", err)
		}
	})

	t.Run("referenced by a virtual key, no group", func(t *testing.T) {
		s := testStore(t)
		newUpstream(t, s)
		k := &models.VirtualKey{ID: "k1", Name: "cursor", KeyHash: "h", KeyLookup: "l1", KeyPrefix: "pory_k1",
			TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: now}
		if err := s.CreateVirtualKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteUpstream(ctx, "u1"); err != ErrInUse {
			t.Fatalf("want in use, got %v", err)
		}
		if err := s.DeleteVirtualKey(ctx, "k1"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteUpstream(ctx, "u1"); err != nil {
			t.Fatalf("delete after the key is gone: %v", err)
		}
	})
}

// TestDeleteGroupInUse covers the second ListVirtualKeys walk: a group a
// virtual key points at cannot be deleted from under it.
func TestDeleteGroupInUse(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	u := &models.Upstream{ID: "u1", Name: "A", Slug: "a", URL: "http://x", Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	g := &models.Group{ID: "g1", Name: "bundle", UpstreamIDs: []string{"u1"}, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	k := &models.VirtualKey{ID: "k1", Name: "claude", KeyHash: "h", KeyLookup: "l1", KeyPrefix: "pory_k1",
		TargetType: models.TargetGroup, TargetID: "g1", CreatedAt: now}
	if err := s.CreateVirtualKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "g1"); err != ErrInUse {
		t.Fatalf("want in use, got %v", err)
	}
	if err := s.DeleteVirtualKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "g1"); err != nil {
		t.Fatalf("delete after the key is gone: %v", err)
	}
}

// TestSchemaVersionIsCurrent pins that a freshly opened database is at the
// version this binary expects, for every migration step this project ever adds.
func TestSchemaVersionIsCurrent(t *testing.T) {
	s := testStore(t)
	got, err := s.currentSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if got != schemaVersion {
		t.Fatalf("fresh database is at schema version %d, want %d", got, schemaVersion)
	}
}

// oldUpstreamsDDL is a FROZEN copy of the upstreams table as it stood on main
// before this branch (10 columns, no slug). Do not update it when the live
// schema changes: its whole job is to reproduce a pre-change database so the
// migration can be exercised for real.
const oldUpstreamsDDL = `CREATE TABLE upstreams (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	url TEXT NOT NULL,
	transport TEXT NOT NULL,
	auth_type TEXT NOT NULL,
	auth_config TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`

// preChangeDB builds a database by hand at the given path by executing stmts
// in order: DDL first, then inserts, then any schema_meta stamp the fixture
// needs. It is the time machine for migration tests, so it never goes through
// Open or migrate.
func preChangeDB(t *testing.T, path string, stmts []string) {
	t.Helper()
	raw, err := sql.Open("sqlite", fileDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, stmt := range stmts {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func oldRow(id, name, createdAt string) string {
	return fmt.Sprintf(
		`INSERT INTO upstreams (id, name, description, url, transport, auth_type, auth_config, enabled, created_at, updated_at)
		 VALUES ('%s', '%s', '', 'https://example.com/mcp', 'streamable-http', 'none', '', 1, '%s', '%s')`,
		id, name, createdAt, createdAt)
}

func slugOf(t *testing.T, s *SQLStore, id string) string {
	t.Helper()
	u, err := s.GetUpstream(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return u.Slug
}

func indexCount(t *testing.T, s *SQLStore, name string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrateBackfillsSlugs(t *testing.T) {
	long := strings.Repeat("a", 60)

	t.Run("old schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pre.db")
		preChangeDB(t, path, []string{
			oldUpstreamsDDL,
			oldRow("u1", "GitHub", "2026-01-01T10:00:00Z"),
			// Same created_at as u1 on purpose: the backfill's id ASC tiebreaker
			// is what makes "the oldest keeps the bare slug" deterministic.
			oldRow("u2", "github", "2026-01-01T10:00:00Z"),
			oldRow("u3", "", "2026-01-02T10:00:00Z"),
			oldRow("u4", "日本語", "2026-01-03T10:00:00Z"),
			oldRow("u5", long, "2026-01-04T10:00:00Z"),
			oldRow("u6", long, "2026-01-05T10:00:00Z"),
			oldRow("u7", "MCP", "2026-01-06T10:00:00Z"),
			oldRow("u8", "GitHub Enterprise", "2026-01-07T10:00:00Z"),
		})

		s, err := Open(path)
		if err != nil {
			t.Fatalf("migrate a pre-change database: %v", err)
		}

		want := map[string]string{
			"u1": "github",
			"u2": "github-2",
			"u3": "up",
			"u4": "up-2",
			"u5": strings.Repeat("a", 40),
			"u6": strings.Repeat("a", 38) + "-2",
			"u7": "mcp-2",
			"u8": "github_enterprise",
		}
		seen := map[string]string{}
		for id, wantSlug := range want {
			got := slugOf(t, s, id)
			if got != wantSlug {
				t.Errorf("upstream %s slug = %q, want %q", id, got, wantSlug)
			}
			if !models.ValidSlug(got) {
				t.Errorf("upstream %s slug %q is not ValidSlug", id, got)
			}
			if models.ReservedSlug(got) {
				t.Errorf("upstream %s slug %q is reserved", id, got)
			}
			if len(got) > models.MaxSlugLen {
				t.Errorf("upstream %s slug %q is %d bytes", id, got, len(got))
			}
			if prev, dup := seen[got]; dup {
				t.Errorf("upstreams %s and %s share slug %q", prev, id, got)
			}
			seen[got] = id
		}

		if n := indexCount(t, s, "upstreams_slug"); n != 1 {
			t.Errorf("upstreams_slug index count = %d, want 1", n)
		}
		if v, err := s.currentSchemaVersion(); err != nil || v != 5 {
			t.Errorf("schema version = %d err=%v, want 5", v, err)
		}
		// Step 3 finds no groups and no virtual keys here, so every tool count
		// stays zero: this fixture is about slugs.
		wantSummary := MigrationSummary{Applied: true, Version: 5, SlugsDerived: 8, SlugsDeduplicated: 4}
		if got := s.LastMigration(); got != wantSummary {
			t.Errorf("LastMigration() = %+v, want %+v", got, wantSummary)
		}

		// Re-running must be a no-op: same slugs, same version, no second index,
		// and nothing reported as applied.
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s2, err := Open(path)
		if err != nil {
			t.Fatalf("re-open a migrated database: %v", err)
		}
		defer s2.Close()
		for id, wantSlug := range want {
			if got := slugOf(t, s2, id); got != wantSlug {
				t.Errorf("after re-open, upstream %s slug = %q, want %q", id, got, wantSlug)
			}
		}
		if n := indexCount(t, s2, "upstreams_slug"); n != 1 {
			t.Errorf("after re-open, index count = %d, want 1", n)
		}
		if v, _ := s2.currentSchemaVersion(); v != 5 {
			t.Errorf("after re-open, schema version = %d, want 5", v)
		}
		if s2.LastMigration().Applied {
			t.Errorf("re-open reported a migration: %+v", s2.LastMigration())
		}
	})

	t.Run("slug column already present, one row already slugged", func(t *testing.T) {
		// The shape of a database written by a pre-merge build of this branch:
		// the column exists, so the ALTER is skipped and `taken` is seeded.
		ddl := strings.Replace(oldUpstreamsDDL,
			"name TEXT NOT NULL,",
			"name TEXT NOT NULL,\n\tslug TEXT NOT NULL DEFAULT '',", 1)
		path := filepath.Join(t.TempDir(), "half.db")
		preChangeDB(t, path, []string{
			ddl,
			oldRow("u1", "GitHub", "2026-01-01T10:00:00Z"),
			oldRow("u2", "GitHub", "2026-01-02T10:00:00Z"),
			oldRow("u3", "Other", "2026-01-03T10:00:00Z"),
			// The pre-set value is deliberately what u1's own name derives to, so
			// u2 (also "GitHub") can only avoid it via the seeded `taken` map.
			// With 'kept' here the sub-test passes even if the seeding is deleted.
			`UPDATE upstreams SET slug = 'github' WHERE id = 'u1'`,
		})

		s, err := Open(path)
		if err != nil {
			t.Fatalf("migrate a half-migrated database: %v", err)
		}
		defer s.Close()
		if got := slugOf(t, s, "u1"); got != "github" {
			t.Errorf("pre-set slug was rewritten to %q", got)
		}
		if got := slugOf(t, s, "u2"); got != "github-2" {
			t.Errorf("u2 slug = %q, want github-2 (taken must be seeded from existing slugs)", got)
		}
		for _, id := range []string{"u2", "u3"} {
			got := slugOf(t, s, id)
			if got == "" {
				t.Errorf("upstream %s was not backfilled", id)
			}
			if got == "github" {
				t.Errorf("upstream %s collided with the pre-set slug", id)
			}
		}
		if v, _ := s.currentSchemaVersion(); v != 5 {
			t.Errorf("schema version = %d, want 5", v)
		}
	})

	t.Run("fail-closed: duplicate pre-existing slugs", func(t *testing.T) {
		ddl := strings.Replace(oldUpstreamsDDL,
			"name TEXT NOT NULL,",
			"name TEXT NOT NULL,\n\tslug TEXT NOT NULL DEFAULT '',", 1)
		path := filepath.Join(t.TempDir(), "dupe.db")
		preChangeDB(t, path, []string{
			ddl,
			oldRow("u1", "One", "2026-01-01T10:00:00Z"),
			oldRow("u2", "Two", "2026-01-02T10:00:00Z"),
			`UPDATE upstreams SET slug = 'dupe'`,
		})
		s, err := Open(path)
		if err == nil {
			_ = s.Close()
			t.Fatal("Open must fail when two upstreams already share a slug")
		}
	})

	t.Run("fail-closed: invalid pre-existing slug", func(t *testing.T) {
		ddl := strings.Replace(oldUpstreamsDDL,
			"name TEXT NOT NULL,",
			"name TEXT NOT NULL,\n\tslug TEXT NOT NULL DEFAULT '',", 1)
		path := filepath.Join(t.TempDir(), "invalid.db")
		preChangeDB(t, path, []string{
			ddl,
			`INSERT INTO upstreams (id, name, slug, description, url, transport, auth_type, auth_config, enabled, created_at, updated_at)
			 VALUES ('u1', 'Payroll Vendor', 'Bad Slug!', '', 'https://vendor.example.com/mcp?key=hunter2',
			         'streamable-http', 'none', '', 1, '2026-01-01T10:00:00Z', '2026-01-01T10:00:00Z')`,
		})
		s, err := Open(path)
		if err == nil {
			_ = s.Close()
			t.Fatal("Open must fail on a stored slug that is not ValidSlug")
		}
		msg := err.Error()
		if !strings.Contains(msg, "u1") {
			t.Errorf("error should name the row id, got %q", msg)
		}
		if strings.Contains(msg, "Payroll Vendor") || strings.Contains(msg, "vendor.example.com") || strings.Contains(msg, "hunter2") {
			t.Errorf("error leaked the upstream name or url: %q", msg)
		}
	})
}

func TestMigrateFreshDatabase(t *testing.T) {
	// The base CREATE TABLE already carries slug, so step 1's ALTER is skipped
	// and only the index creation does any work; step 2 finds no agents table
	// and passes straight through.
	s := testStore(t)
	if v, err := s.currentSchemaVersion(); err != nil || v != 5 {
		t.Fatalf("schema version = %d err=%v, want 5", v, err)
	}
	if n := indexCount(t, s, "upstreams_slug"); n != 1 {
		t.Fatalf("upstreams_slug index count = %d, want 1", n)
	}
	now := time.Now().UTC()
	u := &models.Upstream{ID: "u1", Name: "X", Slug: "x", URL: "http://x", Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUpstream(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

// tableColumns describes a table's columns from pragma_table_info, sorted by
// name so fresh and migrated databases compare equal regardless of ordinal.
func tableColumns(t *testing.T, s *SQLStore, table string) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT name, type, "notnull", ifnull(dflt_value,''), pk
		FROM pragma_table_info(?) ORDER BY name`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, typ, dflt string
		var notnull, pk int
		if err := rows.Scan(&name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s|%s|%d|%s|%d", name, typ, notnull, dflt, pk))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// indexColumns lists an index's key columns in order, each as name or "name
// DESC", from pragma_index_xinfo (which, unlike pragma_index_info, carries the
// sort direction). The trailing rowid entry (cid = -1) is skipped. A missing
// index yields nil, not an error, callers assert on presence too.
func indexColumns(t *testing.T, s *SQLStore, name string) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT name, "desc" FROM pragma_index_xinfo(?) WHERE key = 1 ORDER BY seqno`, name)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var col string
		var desc int
		if err := rows.Scan(&col, &desc); err != nil {
			t.Fatal(err)
		}
		if desc == 1 {
			col += " DESC"
		}
		out = append(out, col)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFreshAndMigratedSchemasMatch pins that migrateBase's CREATE TABLE and
// the migration steps describe the same tables and indexes. It compares
// pragma_table_info sorted by NAME, not sqlite_master.sql text: a fresh
// upstreams puts slug at ordinal 2 and a migrated one puts it last, and SQLite
// rewrites a renamed table's DDL as CREATE TABLE "virtual_keys" (quoted), so
// the DDL text genuinely differs for ever.
func TestFreshAndMigratedSchemasMatch(t *testing.T) {
	fresh := testStore(t)

	path := filepath.Join(t.TempDir(), "migrated.db")
	preChangeDB(t, path, v1Fixture())
	migrated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()

	// Opening the v1 fixture runs every step, step 3 included, over rows written
	// long before the tool identity existed. Step 3 adds no DDL, so it cannot
	// move the comparison below, but it does run here, and "it tolerates the
	// oldest fixture in the file" is worth pinning where that fixture lives.
	// Nothing is rewritten: key a2 points at a group row v1Fixture never
	// creates, so its two entries are left alone and counted.
	if got := migrated.LastMigration().ToolEntriesLeft; got != 2 {
		t.Errorf("ToolEntriesLeft = %d, want 2 (a2's allowlist and denylist, whose target group is gone)", got)
	}

	for _, table := range []string{"upstreams", "virtual_keys", "audit_logs"} {
		a, b := tableColumns(t, fresh, table), tableColumns(t, migrated, table)
		if len(a) == 0 {
			t.Errorf("%s: no columns on the fresh database", table)
		}
		if strings.Join(a, "\n") != strings.Join(b, "\n") {
			t.Errorf("%s columns differ:\nfresh:    %v\nmigrated: %v", table, a, b)
		}
	}
	a, b := indexNames(t, fresh), indexNames(t, migrated)
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Errorf("index names differ:\nfresh:    %v\nmigrated: %v", a, b)
	}
	// PORM-68: neither path carries a second index over key_lookup. Removed
	// from migrateBase and from step 2's rename together with step 4's drop,
	// leave one CREATE behind and the next boot puts it back on one side only,
	// which is exactly what this comparison would then report.
	if slices.Contains(a, "virtual_keys_lookup") || slices.Contains(b, "virtual_keys_lookup") {
		t.Errorf("virtual_keys_lookup is back: fresh %v, migrated %v", a, b)
	}
	for _, idx := range a {
		x, y := indexColumns(t, fresh, idx), indexColumns(t, migrated, idx)
		if strings.Join(x, ",") != strings.Join(y, ",") {
			t.Errorf("index %s differs: fresh %v, migrated %v", idx, x, y)
		}
	}
}

// assertLookupUsesUniqueIndex pins that GetVirtualKeyByLookup's query is served
// by the index the UNIQUE constraint on key_lookup creates, on whatever
// database it is handed. It is the reason the explicit virtual_keys_lookup
// index could be dropped (PORM-68), and the guard that keeps the drop honest.
func assertLookupUsesUniqueIndex(t *testing.T, s *SQLStore) {
	t.Helper()
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN SELECT `+virtualKeyCols+` FROM virtual_keys WHERE key_lookup = ?`, "lookup-a1")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// Measured on modernc SQLite, identical on a fresh and on a migrated
	// database: the UNIQUE constraint's index is the second one SQLite creates
	// on this table, after the one for the TEXT PRIMARY KEY.
	const want = "SEARCH virtual_keys USING INDEX sqlite_autoindex_virtual_keys_2 (key_lookup=?)"
	if got := strings.Join(plan, " | "); got != want {
		t.Errorf("query plan for the lookup = %q, want %q", got, want)
	}
}

// indexNames lists the explicitly created indexes, sorted.
func indexNames(t *testing.T, s *SQLStore) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func tableCount(t *testing.T, s *SQLStore, name string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// rowTuples runs query and renders every row as its columns joined by "|",
// with NULL spelled out, so a migrated table can be compared byte for byte
// against what the fixture inserted.
func rowTuples(t *testing.T, s *SQLStore, query string) []string {
	t.Helper()
	rows, err := s.db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(cols))
		for i, v := range vals {
			switch x := v.(type) {
			case nil:
				parts[i] = "NULL"
			case []byte:
				parts[i] = string(x)
			default:
				parts[i] = fmt.Sprint(x)
			}
		}
		out = append(out, strings.Join(parts, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// v1AgentsDDL, v1AuditLogsDDL and v1IndexDDL are FROZEN copies of the agents
// and audit_logs tables and their indexes as migrateBase created them at
// schema version 1 (main@3b2abd0), before the rename to virtual_keys. Do not
// update them when the live schema changes: their whole job is to reproduce a
// pre-rename database so migration step 2 can be exercised for real.
const v1AgentsDDL = `CREATE TABLE agents (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL,
	key_lookup TEXT NOT NULL UNIQUE,
	key_prefix TEXT NOT NULL,
	target_type TEXT NOT NULL,
	target_id TEXT NOT NULL,
	rate_limit INTEGER,
	expires_at TEXT,
	tool_allowlist TEXT NOT NULL DEFAULT '[]',
	tool_denylist TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL,
	last_used_at TEXT,
	revoked_at TEXT,
	metadata TEXT NOT NULL DEFAULT ''
)`

const v1AuditLogsDDL = `CREATE TABLE audit_logs (
	id TEXT PRIMARY KEY,
	timestamp TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	agent_name TEXT NOT NULL,
	method TEXT NOT NULL,
	tool_name TEXT NOT NULL DEFAULT '',
	params TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	latency_ms INTEGER NOT NULL DEFAULT 0,
	response_size_bytes INTEGER NOT NULL DEFAULT 0,
	upstream_id TEXT NOT NULL DEFAULT '',
	error_message TEXT NOT NULL DEFAULT '',
	request_id TEXT NOT NULL DEFAULT ''
)`

var v1IndexDDL = []string{
	`CREATE INDEX audit_logs_ts ON audit_logs (timestamp DESC)`,
	`CREATE INDEX audit_logs_agent ON audit_logs (agent_id, timestamp DESC)`,
	`CREATE INDEX agents_lookup ON agents (key_lookup)`,
}

// Two keys and two audit rows, written with every column spelled out so the
// migrated table can be compared byte for byte. a1 leaves every nullable
// column NULL; a2 fills them all.
var v1DataRows = []string{
	`INSERT INTO agents (id, name, key_hash, key_lookup, key_prefix, target_type, target_id, rate_limit, expires_at, tool_allowlist, tool_denylist, created_at, last_used_at, revoked_at, metadata)
	 VALUES ('a1', 'cursor', '$argon2id$hash-a1', 'lookup-a1', 'pory_a1a1a1a', 'upstream', 'u1', NULL, NULL, '[]', '[]', '2026-01-05T10:00:00Z', NULL, NULL, '')`,
	`INSERT INTO agents (id, name, key_hash, key_lookup, key_prefix, target_type, target_id, rate_limit, expires_at, tool_allowlist, tool_denylist, created_at, last_used_at, revoked_at, metadata)
	 VALUES ('a2', 'claude', '$argon2id$hash-a2', 'lookup-a2', 'pory_a2a2a2a', 'group', 'g1', 60, '2027-01-01T00:00:00Z', '["safe_tool"]', '["rm"]', '2026-01-06T10:00:00Z', '2026-01-07T10:00:00Z', '2026-01-08T10:00:00Z', '{"team":"x"}')`,
	`INSERT INTO audit_logs (id, timestamp, agent_id, agent_name, method, tool_name, params, status, latency_ms, response_size_bytes, upstream_id, error_message, request_id)
	 VALUES ('l1', '2026-01-09T10:00:00Z', 'a1', 'cursor', 'tools/list', '', '', 'success', 12, 340, 'u1', '', 'r1')`,
	`INSERT INTO audit_logs (id, timestamp, agent_id, agent_name, method, tool_name, params, status, latency_ms, response_size_bytes, upstream_id, error_message, request_id)
	 VALUES ('l2', '2026-01-09T11:00:00Z', 'a2', 'claude', 'tools/call', 'rm', '{}', 'blocked', 1, 0, '', 'tool blocked by agent policy', 'r2')`,
}

var (
	wantVirtualKeyRows = []string{
		"a1|cursor|$argon2id$hash-a1|lookup-a1|pory_a1a1a1a|upstream|u1|NULL|NULL|[]|[]|2026-01-05T10:00:00Z|NULL|NULL|",
		`a2|claude|$argon2id$hash-a2|lookup-a2|pory_a2a2a2a|group|g1|60|2027-01-01T00:00:00Z|["safe_tool"]|["rm"]|2026-01-06T10:00:00Z|2026-01-07T10:00:00Z|2026-01-08T10:00:00Z|{"team":"x"}`,
	}
	wantAuditRows = []string{
		"l1|a1|cursor|",
		"l2|a2|claude|tool blocked by agent policy",
	}
)

// v1Fixture rebuilds a database exactly as a version-1 server left it: step 1
// already applied to upstreams (slug column last, unique index present),
// agents and audit_logs under their old names, and the version stamped.
func v1Fixture() []string {
	stmts := []string{
		`CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		oldUpstreamsDDL,
		`ALTER TABLE upstreams ADD COLUMN slug TEXT NOT NULL DEFAULT ''`,
		`CREATE UNIQUE INDEX upstreams_slug ON upstreams (slug)`,
		v1AgentsDDL,
		v1AuditLogsDDL,
	}
	stmts = append(stmts, v1IndexDDL...)
	stmts = append(stmts,
		oldRow("u1", "GitHub", "2026-01-01T10:00:00Z"),
		`UPDATE upstreams SET slug = 'github' WHERE id = 'u1'`,
	)
	stmts = append(stmts, v1DataRows...)
	return append(stmts, `INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')`)
}

// v0Fixture is a database from before PORM-48: no schema_meta, no slug, and
// the same agents and audit rows, so one Open has to run step 1 and step 2.
func v0Fixture() []string {
	stmts := []string{oldUpstreamsDDL, v1AgentsDDL, v1AuditLogsDDL}
	stmts = append(stmts, v1IndexDDL...)
	stmts = append(stmts,
		oldRow("u1", "GitHub", "2026-01-01T10:00:00Z"),
		oldRow("u2", "GitHub", "2026-01-02T10:00:00Z"),
	)
	return append(stmts, v1DataRows...)
}

// assertRenamed checks everything step 2 promises about a migrated database.
func assertRenamed(t *testing.T, s *SQLStore) {
	t.Helper()
	if got := rowTuples(t, s, `SELECT `+virtualKeyCols+` FROM virtual_keys ORDER BY id`); strings.Join(got, "\n") != strings.Join(wantVirtualKeyRows, "\n") {
		t.Errorf("virtual_keys rows:\n got %q\nwant %q", got, wantVirtualKeyRows)
	}
	if got := rowTuples(t, s, `SELECT id, virtual_key_id, virtual_key_name, error_message FROM audit_logs ORDER BY id`); strings.Join(got, "\n") != strings.Join(wantAuditRows, "\n") {
		t.Errorf("audit_logs rows:\n got %q\nwant %q", got, wantAuditRows)
	}
	if n := tableCount(t, s, "agents"); n != 0 {
		t.Errorf("agents table still exists")
	}
	// The named index is gone and does not come back (PORM-68): key_lookup is
	// NOT NULL UNIQUE, so the constraint's own index is the one that serves the
	// proxy's authentication lookup, pinned here, because a future schema
	// change that dropped the UNIQUE would turn that lookup into a table scan
	// and nothing else in this file would notice.
	if n := indexCount(t, s, "virtual_keys_lookup"); n != 0 {
		t.Errorf("virtual_keys_lookup still exists after the rename")
	}
	assertLookupUsesUniqueIndex(t, s)
	if got := indexColumns(t, s, "audit_logs_virtual_key"); strings.Join(got, ",") != "virtual_key_id,timestamp DESC" {
		t.Errorf("audit_logs_virtual_key columns = %v, want [virtual_key_id timestamp DESC]", got)
	}
	for _, old := range []string{"agents_lookup", "audit_logs_agent"} {
		if n := indexCount(t, s, old); n != 0 {
			t.Errorf("old index %s still exists", old)
		}
	}
	if v, err := s.currentSchemaVersion(); err != nil || v != 5 {
		t.Errorf("schema version = %d err=%v, want 5", v, err)
	}
	// The Go layer reads the renamed table, nullable columns included.
	a, err := s.GetVirtualKeyByLookup(context.Background(), "lookup-a2")
	if err != nil {
		t.Fatalf("lookup through the store after migration: %v", err)
	}
	if a.Name != "claude" || a.RateLimit == nil || *a.RateLimit != 60 || a.RevokedAt == nil {
		t.Errorf("migrated key read back wrong: %+v", a)
	}
	if _, err := s.GetVirtualKey(context.Background(), "a1"); err != nil {
		t.Errorf("get a1 after migration: %v", err)
	}
}

func TestMigrateRenamesAgentsToVirtualKeys(t *testing.T) {
	t.Run("version 1", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "v1.db")
		preChangeDB(t, path, v1Fixture())
		s, err := Open(path)
		if err != nil {
			t.Fatalf("migrate a version-1 database: %v", err)
		}
		assertRenamed(t, s)
		// ToolEntriesLeft is 2 because of the fixture, not by accident: key a2
		// points at group g1, which v1Fixture never creates, so step 3 cannot
		// know that key's members and leaves both of its entries alone. See
		// TestMigrateRewritesToolIdentities for the rows it does rewrite.
		if got, want := s.LastMigration(), (MigrationSummary{Applied: true, Version: 5, ToolEntriesLeft: 2}); got != want {
			t.Errorf("LastMigration() = %+v, want %+v", got, want)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}

		s2, err := Open(path)
		if err != nil {
			t.Fatalf("re-open a migrated database: %v", err)
		}
		defer s2.Close()
		assertRenamed(t, s2)
		if s2.LastMigration().Applied {
			t.Errorf("re-open reported a migration: %+v", s2.LastMigration())
		}
	})

	t.Run("version 0 runs step 1 and step 2 in one Open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "v0.db")
		preChangeDB(t, path, v0Fixture())
		s, err := Open(path)
		if err != nil {
			t.Fatalf("migrate a version-0 database: %v", err)
		}
		defer s.Close()
		assertRenamed(t, s)
		if got, want := s.LastMigration(), (MigrationSummary{Applied: true, Version: 5, SlugsDerived: 2, SlugsDeduplicated: 1, ToolEntriesLeft: 2}); got != want {
			t.Errorf("LastMigration() = %+v, want %+v", got, want)
		}
		if a, b := slugOf(t, s, "u1"), slugOf(t, s, "u2"); a != "github" || b != "github-2" {
			t.Errorf("slugs = %q, %q; want github, github-2", a, b)
		}
	})

	t.Run("renamed but stamped 1 (crash between prelude and stamp)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "half.db")
		preChangeDB(t, path, v1Fixture())
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE schema_meta SET value = '1' WHERE key = ?`, schemaVersionKey); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s2, err := Open(path)
		if err != nil {
			t.Fatalf("re-open a renamed database stamped 1: %v", err)
		}
		defer s2.Close()
		assertRenamed(t, s2)
		if got, want := s2.LastMigration(), (MigrationSummary{Applied: true, Version: 5, ToolEntriesLeft: 2}); got != want {
			t.Errorf("LastMigration() = %+v, want %+v", got, want)
		}
	})

	t.Run("pre-merge build: new names, no stamp", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "premerge.db")
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DELETE FROM schema_meta`); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s2, err := Open(path)
		if err != nil {
			t.Fatalf("re-open an unstamped database with the new names: %v", err)
		}
		defer s2.Close()
		if v, _ := s2.currentSchemaVersion(); v != 5 {
			t.Errorf("schema version = %d, want 5", v)
		}
		if n := tableCount(t, s2, "virtual_keys"); n != 1 {
			t.Errorf("virtual_keys table count = %d", n)
		}
	})

	t.Run("both tables, virtual_keys empty: discard it and rename", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "both-empty.db")
		stmts := append(v1Fixture(), strings.Replace(v1AgentsDDL, "CREATE TABLE agents", "CREATE TABLE virtual_keys", 1))
		preChangeDB(t, path, stmts)
		s, err := Open(path)
		if err != nil {
			t.Fatalf("migrate with an empty virtual_keys beside agents: %v", err)
		}
		defer s.Close()
		assertRenamed(t, s)
	})

	t.Run("fail-closed: both tables hold rows", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "both-full.db")
		stmts := append(v1Fixture(),
			strings.Replace(v1AgentsDDL, "CREATE TABLE agents", "CREATE TABLE virtual_keys", 1),
			strings.Replace(v1DataRows[0], "INSERT INTO agents", "INSERT INTO virtual_keys", 1),
		)
		preChangeDB(t, path, stmts)
		s, err := Open(path)
		if err == nil {
			_ = s.Close()
			t.Fatal("Open must refuse a database where both agents and virtual_keys hold rows")
		}
		msg := err.Error()
		if !strings.Contains(msg, "agents") || !strings.Contains(msg, "virtual_keys") {
			t.Errorf("error should name both tables, got %q", msg)
		}
		for _, leak := range []string{"cursor", "claude", "pory_a1a1a1a", "hash-a1", "lookup-a1"} {
			if strings.Contains(msg, leak) {
				t.Errorf("error leaked row data %q: %q", leak, msg)
			}
		}
	})
}

func TestUpstreamSlugUnique(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, slug string) *models.Upstream {
		return &models.Upstream{ID: id, Name: id, Slug: slug, URL: "http://x",
			Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
	}
	if err := s.CreateUpstream(ctx, mk("u1", "github")); err != nil {
		t.Fatal(err)
	}
	// Proves the driver-level unique violation maps onto ErrConflict end to end.
	if err := s.CreateUpstream(ctx, mk("u2", "github")); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create with the same slug: got %v, want ErrConflict", err)
	}
}

// TestUpdateUpstreamIgnoresSlug is the store half of "a slug is immutable after
// create": slug is deliberately absent from UpdateUpstream's SET list, so even a
// caller that hands it a changed value cannot rewrite one.
func TestUpdateUpstreamIgnoresSlug(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	u := &models.Upstream{ID: "u1", Name: "GitHub", Slug: "github", URL: "http://x",
		Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	u.Name = "Renamed"
	u.Slug = "something_else"
	if err := s.UpdateUpstream(ctx, u, KeepTest, WriteAuth); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpstream(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Slug != "github" {
		t.Fatalf("stored slug = %q, want github (UpdateUpstream must not write slug)", got.Slug)
	}
	if got.Name != "Renamed" {
		t.Fatalf("name = %q, want Renamed", got.Name)
	}
}

// TestRecordUpstreamTest covers the writer that stamps one row with the outcome
// of one deliberate connection test, and the compare that keeps it from
// vouching for a configuration it never tested.
func TestRecordUpstreamTest(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	rawUpdatedAt := func(id string) string {
		t.Helper()
		var v string
		if err := s.db.QueryRow(`SELECT updated_at FROM upstreams WHERE id = ?`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	mk := func(id, slug string, when time.Time) *models.Upstream {
		return &models.Upstream{ID: id, Name: "GitHub", Slug: slug, URL: "http://x",
			Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: when, UpdatedAt: when}
	}

	// The invariant the WHERE clause rests on, asserted before anything relies
	// on it: fmtTime reproduces the bytes the column already holds, so a
	// reformat of a value read out through the store matches it exactly. Three
	// shapes, because RFC3339Nano strips trailing zeros, a whole second, a
	// half second, and an untruncated wall-clock reading.
	for i, when := range []time.Time{
		time.Date(2026, 8, 29, 14, 3, 11, 0, time.UTC),
		time.Date(2026, 8, 29, 14, 3, 11, 500_000_000, time.UTC),
		time.Now().UTC(),
	} {
		id := fmt.Sprintf("inv%d", i)
		if err := s.CreateUpstream(ctx, mk(id, id, when)); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetUpstream(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if fmtTime(got.UpdatedAt) != rawUpdatedAt(id) {
			t.Fatalf("fmtTime(read updated_at) = %q, stored %q; the compare in RecordUpstreamTest can never match",
				fmtTime(got.UpdatedAt), rawUpdatedAt(id))
		}
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.CreateUpstream(ctx, mk("u1", "github", now)); err != nil {
		t.Fatal(err)
	}

	// One run, recorded. updated_at does not move: a test is not an edit.
	at := now.Add(time.Minute)
	if err := s.RecordUpstreamTest(ctx, "u1", at, false, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpstream(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastTestAt == nil || !got.LastTestAt.Equal(at) || got.LastTestOK == nil || *got.LastTestOK {
		t.Fatalf("after one failed test: at=%v ok=%v, want %v/false", got.LastTestAt, got.LastTestOK, at)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Fatalf("updated_at moved to %v; RecordUpstreamTest must not bump it", got.UpdatedAt)
	}

	// A second run over the first: the later write wins, deliberately.
	at2 := at.Add(time.Minute)
	if err := s.RecordUpstreamTest(ctx, "u1", at2, true, got.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if got, err = s.GetUpstream(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if got.LastTestAt == nil || !got.LastTestAt.Equal(at2) || got.LastTestOK == nil || !*got.LastTestOK {
		t.Fatalf("after a passing test: at=%v ok=%v, want %v/true", got.LastTestAt, got.LastTestOK, at2)
	}

	// A seen value from before the row's current updated_at matches nothing and
	// records nothing: the configuration under test is no longer the one stored.
	if err := s.RecordUpstreamTest(ctx, "u1", at2.Add(time.Minute), false, now.Add(-time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale seen: got %v, want ErrNotFound", err)
	}
	if after, err := s.GetUpstream(ctx, "u1"); err != nil {
		t.Fatal(err)
	} else if after.LastTestOK == nil || !*after.LastTestOK || !after.LastTestAt.Equal(at2) {
		t.Fatalf("a dropped result changed the row: at=%v ok=%v", after.LastTestAt, after.LastTestOK)
	}
	if err := s.RecordUpstreamTest(ctx, "nope", at2, true, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: got %v, want ErrNotFound", err)
	}

	// An ordinary edit leaves the result alone, and cannot write one from the
	// struct, however wrong the struct's own copy has become.
	edited := *got
	edited.Name = "Renamed"
	edited.UpdatedAt = time.Now().UTC().Truncate(time.Millisecond).Add(time.Hour)
	wrongAt := now.Add(-24 * time.Hour)
	wrongOK := false
	edited.LastTestAt, edited.LastTestOK = &wrongAt, &wrongOK
	if err := s.UpdateUpstream(ctx, &edited, KeepTest, WriteAuth); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetUpstream(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if after.Name != "Renamed" {
		t.Fatalf("name = %q, want the edit to have landed", after.Name)
	}
	if after.LastTestAt == nil || !after.LastTestAt.Equal(at2) || after.LastTestOK == nil || !*after.LastTestOK {
		t.Fatalf("UpdateUpstream wrote the test columns from the struct: at=%v ok=%v", after.LastTestAt, after.LastTestOK)
	}
	// And the row a caller has just read can be stamped again.
	if err := s.RecordUpstreamTest(ctx, "u1", after.UpdatedAt.Add(time.Minute), false, after.UpdatedAt); err != nil {
		t.Fatalf("record against a freshly read updated_at: %v", err)
	}

	// A connection edit clears both columns in the statement that makes it.
	after.UpdatedAt = after.UpdatedAt.Add(time.Hour)
	after.URL = "http://y"
	if err := s.UpdateUpstream(ctx, after, ResetTest, WriteAuth); err != nil {
		t.Fatal(err)
	}
	reset, err := s.GetUpstream(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if reset.LastTestAt != nil || reset.LastTestOK != nil {
		t.Fatalf("resetTest left at=%v ok=%v, want both nil", reset.LastTestAt, reset.LastTestOK)
	}
	if reset.URL != "http://y" {
		t.Fatalf("url = %q, want the edit to have landed in the same statement", reset.URL)
	}
}

func TestGetUpstreamBySlug(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	u := &models.Upstream{ID: "u1", Name: "GitHub", Slug: "github", URL: "http://x",
		Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpstreamBySlug(ctx, "github")
	if err != nil || got.ID != "u1" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := s.GetUpstreamBySlug(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown slug: got %v, want ErrNotFound", err)
	}
}

// TestCreateUpstreamRequiresSlug pins the guard that turns "one slug-less row is
// possible per database" into a loud failure on the first insert. It is not a
// conflict and not a not-found: reaching it is a programming error, so it maps
// to a 500.
func TestCreateUpstreamRequiresSlug(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	u := &models.Upstream{ID: "u1", Name: "No Slug", URL: "http://x",
		Transport: "streamable-http", AuthType: "none", Enabled: true, CreatedAt: now, UpdatedAt: now}
	err := s.CreateUpstream(context.Background(), u)
	if err == nil {
		t.Fatal("CreateUpstream must reject an empty slug")
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want a plain error", err)
	}
}

// TestRefusesNewerSchema pins the downgrade guard: a binary must not serve
// traffic against a database written by a newer build. Without the guard
// migrate()'s step loop does not run and Open succeeds silently.
func TestRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE schema_meta SET value = ? WHERE key = ?`,
		strconv.Itoa(schemaVersion+1), schemaVersionKey); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err == nil {
		_ = s2.Close()
		t.Fatalf("Open must refuse a database at schema version %d", schemaVersion+1)
	}
	if !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("error should name the schema version, got %q", err)
	}
}

// --- Step 3: the {slug}__{tool} identity ---

// v2GroupsDDL is a FROZEN copy of the groups table as migrateBase created it at
// schema version 2. Do not update it when the live schema changes: its whole job
// is to reproduce a pre-change database so step 3 can be exercised for real.
const v2GroupsDDL = `CREATE TABLE groups (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	upstream_ids TEXT NOT NULL DEFAULT '[]',
	tool_filter TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`

// virtual_keys at version 2 is the version-1 agents table under its new name,
// which is exactly what step 2's ALTER TABLE … RENAME TO leaves behind, so the
// frozen v1 DDL is the frozen v2 DDL, and there is only one copy to keep.
var v2VirtualKeysDDL = strings.Replace(v1AgentsDDL, "CREATE TABLE agents", "CREATE TABLE virtual_keys", 1)

// The filters v2Fixture stores, named so that an assertion about a row that must
// not change can compare against the same bytes the fixture wrote.
const (
	// g1 is the deny half of the rewrite table over members github and docs:
	// the old one-underscore aggregate spelling ("github_search"), a tool whose
	// own name carries the separator ("mcp__fetch"), an entry already scoped at
	// a member ("docs__purge"), a bare name matching no member ("delete_repo"),
	// and one beginning with the separator ("__search"), which models.SplitEntry
	// classifies as unscoped and which must therefore not be read as a scoped
	// entry on a member called "". The prefixes list runs the same table.
	v2G1Filter = `{"mode":"deny","tools":["github_search","mcp__fetch","docs__purge","delete_repo","__search"],"prefixes":["github_","mcp__","delete_","docs__"]}`
	// g2 is the allow half, and every entry in it must survive untouched. The
	// dangerous one is the prefixes entry: expanding "github_" to "github__"
	// would turn an allow rule naming one tool into a member-wide wildcard.
	v2G2Filter = `{"mode":"allow","tools":["search","github__search","evil__x"],"prefixes":["github_"]}`
	// g3 has a misspelt key, so it does not validate and blocks every tool on
	// its group. Re-marshalling it would silently drop "toolz" and leave behind
	// a filter that denies two entries and permits everything else.
	v2G3Filter = `{"mode":"deny","tools":["github_search"],"toolz":["x"]}`
)

func v2Upstream(id, slug string, enabled int) string {
	return fmt.Sprintf(
		`INSERT INTO upstreams (id, name, slug, description, url, transport, auth_type, auth_config, enabled, created_at, updated_at)
		 VALUES ('%s', '%s', '%s', '', 'https://example.com/mcp', 'streamable-http', 'none', '', %d, '2026-02-01T10:00:00Z', '2026-02-01T10:00:00Z')`,
		id, slug, slug, enabled)
}

func v2Group(id, upstreamIDs, filter string) string {
	return fmt.Sprintf(
		`INSERT INTO groups (id, name, description, upstream_ids, tool_filter, created_at, updated_at)
		 VALUES ('%s', '%s', '', '%s', '%s', '2026-02-01T10:00:00Z', '2026-02-01T10:00:00Z')`,
		id, id, upstreamIDs, filter)
}

func v2Key(id, targetType, targetID, allow, deny string) string {
	return fmt.Sprintf(
		`INSERT INTO virtual_keys (id, name, key_hash, key_lookup, key_prefix, target_type, target_id,
			rate_limit, expires_at, tool_allowlist, tool_denylist, created_at, last_used_at, revoked_at, metadata)
		 VALUES ('%s', '%s', '$argon2id$hash-%s', 'lookup-%s', 'pory_%s', '%s', '%s',
			NULL, NULL, '%s', '%s', '2026-02-01T10:00:00Z', NULL, NULL, '')`,
		id, id, id, id, id, targetType, targetID, allow, deny)
}

// v2Fixture rebuilds a database as a version-2 server left it, with rows
// covering every cell of step 3's rewrite table. audit_logs and the indexes are
// left to migrateBase: step 3 reads upstreams, groups and virtual_keys and
// nothing else, and a fixture that repeats the whole schema would have to be
// kept in step with it for no gain.
func v2Fixture() []string {
	return []string{
		`CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		oldUpstreamsDDL,
		`ALTER TABLE upstreams ADD COLUMN slug TEXT NOT NULL DEFAULT ''`,
		`CREATE UNIQUE INDEX upstreams_slug ON upstreams (slug)`,
		v2GroupsDDL,
		v2VirtualKeysDDL,
		v2Upstream("u1", "github", 1),
		// Disabled deliberately: disabling an upstream is reversible, so a
		// disabled member is still a member as far as a rule is concerned.
		v2Upstream("u2", "docs", 0),
		// u1 twice, because a group may store a duplicate, plus an id with no
		// row at all. Both have to collapse out of the member set.
		v2Group("g1", `["u1","u2","u1","u404"]`, v2G1Filter),
		v2Group("g2", `["u1"]`, v2G2Filter),
		v2Group("g3", `["u1"]`, v2G3Filter),
		v2Group("g4", `["u1"]`, ``),
		v2Group("g5", `["u1"]`, `null`),
		// One entry, both lists, one upstream target: rewritten on the deny
		// side and left on the allow side.
		v2Key("k1", "upstream", "u1", `["mcp__fetch"]`, `["mcp__fetch"]`),
		// A trailing space, which only SQL can write: a key's lists have never
		// been validated by the API.
		v2Key("k2", "group", "g1", `[]`, `["delete_repo "]`),
		v2Key("k3", "group", "g1", `["github__search"]`, `["github_search","docs__purge"]`),
		// The group this key points at is gone, so its members are unknowable.
		v2Key("k4", "group", "g404", `["safe_tool"]`, `["rm"]`),
		// A denylist that is not JSON at all.
		v2Key("k5", "upstream", "u1", `[]`, `["unterminated`),
		// The allow column on a single upstream, both ways round: a bare entry
		// names a tool on the one upstream this key points at and still admits
		// it, while a scoped entry naming somebody else admits nothing.
		v2Key("k6", "upstream", "u1", `["search"]`, `[]`),
		v2Key("k7", "upstream", "u1", `["other__search"]`, `[]`),
		`INSERT INTO schema_meta (key, value) VALUES ('schema_version', '2')`,
	}
}

// v2Store builds the fixture, migrates it, and returns the open store and its
// path. extra is appended to the fixture, for tests that need one more row.
func v2Store(t *testing.T, extra ...string) (*SQLStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v2.db")
	preChangeDB(t, path, append(v2Fixture(), extra...))
	s, err := Open(path)
	if err != nil {
		t.Fatalf("migrate a version-2 database: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// filterOf and listsOf read a row back as it is stored, so an assertion compares
// the bytes on disk rather than a struct that has been through a decoder.
func filterOf(t *testing.T, s *SQLStore, id string) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(`SELECT tool_filter FROM groups WHERE id = ?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func listsOf(t *testing.T, s *SQLStore, id string) (allow, deny string) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT tool_allowlist, tool_denylist FROM virtual_keys WHERE id = ?`, id).Scan(&allow, &deny); err != nil {
		t.Fatal(err)
	}
	return allow, deny
}

func TestMigrateRewritesToolIdentities(t *testing.T) {
	s, _ := v2Store(t)

	t.Run("deny tools", func(t *testing.T) {
		// Entry by entry: "github_search" is the old spelling and gains
		// "github__search"; "mcp__fetch" is scoped at nobody, so it may be a
		// tool whose own name carries the separator and gains one form per
		// member; "docs__purge" is already an identity; "delete_repo" and
		// "__search" are bare names that still mean the same tool on every
		// member. Every original entry stays: a deny that stopped matching
		// would be a fail-open, and a key's lists still match prompts whole.
		want := `["github_search","mcp__fetch","docs__purge","delete_repo","__search","github__search","github__mcp__fetch","docs__mcp__fetch"]`
		if got := entriesOf(t, filterOf(t, s, "g1")).tools; got != want {
			t.Errorf("g1 tools =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("deny prefixes follow the same table", func(t *testing.T) {
		// "github_" is the old spelling with nothing after it, which is
		// meaningless in tools and exactly right here: "github__" is every tool
		// on github, which is what the entry blocked before. "mcp__" is the
		// same argument as "mcp__fetch". "delete_" matches no member and stays
		// a shape matched against every tool's own name; "docs__" is already
		// scoped at a member.
		want := `["github_","mcp__","delete_","docs__","github__","github__mcp__","docs__mcp__"]`
		if got := entriesOf(t, filterOf(t, s, "g1")).prefixes; got != want {
			t.Errorf("g1 prefixes =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("a filter with no entries to rewrite is not touched", func(t *testing.T) {
		for id, want := range map[string]string{"g4": ``, "g5": `null`} {
			if got := filterOf(t, s, id); got != want {
				t.Errorf("%s tool_filter = %q, want %q", id, got, want)
			}
		}
	})

	t.Run("a key on a single upstream", func(t *testing.T) {
		// The same entry in both lists: rewritten on the deny side, left on the
		// allow side, where "mcp" names no member so the entry admits nothing
		// and only an operator can say what was meant.
		allow, deny := listsOf(t, s, "k1")
		if want := `["mcp__fetch"]`; allow != want {
			t.Errorf("k1 tool_allowlist = %s, want %s", allow, want)
		}
		if want := `["mcp__fetch","github__mcp__fetch"]`; deny != want {
			t.Errorf("k1 tool_denylist = %s, want %s", deny, want)
		}
	})

	t.Run("a key on a group", func(t *testing.T) {
		allow, deny := listsOf(t, s, "k3")
		if want := `["github__search"]`; allow != want {
			t.Errorf("k3 tool_allowlist = %s, want %s", allow, want)
		}
		if want := `["github_search","docs__purge","github__search"]`; deny != want {
			t.Errorf("k3 tool_denylist = %s, want %s", deny, want)
		}
	})

	t.Run("an entry no tool name can equal is left alone", func(t *testing.T) {
		// A trailing space. It matches nothing today and would match nothing
		// scoped, so composing it would only write an entry the management API
		// now rejects.
		if _, deny := listsOf(t, s, "k2"); deny != `["delete_repo "]` {
			t.Errorf("k2 tool_denylist = %s, want the stored entry untouched", deny)
		}
	})

	t.Run("a key whose target has gone keeps both lists", func(t *testing.T) {
		allow, deny := listsOf(t, s, "k4")
		if allow != `["safe_tool"]` || deny != `["rm"]` {
			t.Errorf("k4 lists = %s / %s, want them untouched: a deleted group must not delete a rule", allow, deny)
		}
	})

	t.Run("a list that is not JSON is left byte for byte", func(t *testing.T) {
		// decodeStrings answers nil for this and for "[]" alike. Writing that
		// nil back would replace an unreadable denylist with no denylist.
		if _, deny := listsOf(t, s, "k5"); deny != `["unterminated` {
			t.Errorf("k5 tool_denylist = %q, want it exactly as stored", deny)
		}
	})

	t.Run("a bare allow entry on a single upstream is not a leftover", func(t *testing.T) {
		// Both keys are left alone (the allow side is never expanded) but only
		// one of them is worth an operator's attention. k6's "search" still
		// admits search on github, exactly as it did before the upgrade; k7's
		// "other__search" names a member this key does not have, so it admits
		// nothing and the count is how anyone finds out.
		for _, tc := range []struct{ id, want string }{
			{"k6", `["search"]`},
			{"k7", `["other__search"]`},
		} {
			if allow, _ := listsOf(t, s, tc.id); allow != tc.want {
				t.Errorf("%s tool_allowlist = %s, want %s", tc.id, allow, tc.want)
			}
		}
		// Counting k6 would report a rule that is working perfectly as one the
		// migration could not handle, and the startup report walks the same
		// rule: an operator who is told to fix a correct entry learns to ignore
		// both. The arithmetic is pinned by the counters sub-test below, which
		// includes k7 and not k6.
	})

	t.Run("counters", func(t *testing.T) {
		// Rewritten: g1's github_search, mcp__fetch, github_ and mcp__, plus
		// k1's and k3's deny entries. Left: g2's three allow-side entries that
		// admit nothing, k1's and k7's allow entries, k2's unclean entry, k4's
		// two entries with no target, and k5's unreadable column. Not k6's,
		// which admits what it always did.
		want := MigrationSummary{
			Applied: true, Version: 5,
			ToolEntriesRewritten: 6, ToolEntriesLeft: 9,
			ToolFiltersLeftInvalid: 1, GroupsRewritten: 1, VirtualKeysRewritten: 2,
		}
		if got := s.LastMigration(); got != want {
			t.Errorf("LastMigration() = %+v, want %+v", got, want)
		}
	})
}

// entriesOf renders a stored filter's two lists as the JSON arrays they were
// written as, so a test can assert on one list at a time and still be comparing
// stored bytes rather than a set.
func entriesOf(t *testing.T, filter string) struct{ tools, prefixes string } {
	t.Helper()
	var tf models.ToolFilter
	if err := json.Unmarshal([]byte(filter), &tf); err != nil {
		t.Fatalf("stored filter %s: %v", filter, err)
	}
	tools, err := json.Marshal(tf.Tools)
	if err != nil {
		t.Fatal(err)
	}
	prefixes, err := json.Marshal(tf.Prefixes)
	if err != nil {
		t.Fatal(err)
	}
	return struct{ tools, prefixes string }{string(tools), string(prefixes)}
}

// TestMigrateLeavesInvalidFilterUntouched is the fail-closed half of step 3. A
// filter the proxy refuses to read blocks every tool on its group; decoding it
// into a models.ToolFilter drops whatever made it invalid, so re-marshalling one
// would hand the group back permissive.
func TestMigrateLeavesInvalidFilterUntouched(t *testing.T) {
	s, _ := v2Store(t)

	got := filterOf(t, s, "g3")
	if got != v2G3Filter {
		t.Errorf("g3 tool_filter = %s, want it byte for byte as stored: %s", got, v2G3Filter)
	}
	if err := models.ValidateToolFilter(json.RawMessage(got)); err == nil {
		t.Error("the stored filter still has to fail validation: that is what keeps the group failing closed")
	}
	if n := s.LastMigration().ToolFiltersLeftInvalid; n != 1 {
		t.Errorf("ToolFiltersLeftInvalid = %d, want 1", n)
	}
}

// TestMigrateNeverWidensAnAllowlist pins the one thing a migration must never do
// unattended: hand an agent access it did not have before the upgrade.
func TestMigrateNeverWidensAnAllowlist(t *testing.T) {
	s, _ := v2Store(t)

	if got := filterOf(t, s, "g2"); got != v2G2Filter {
		t.Errorf("g2 tool_filter = %s, want it byte for byte as stored: %s", got, v2G2Filter)
	}
	// Named separately because it is the worst of the widenings: "github_" is
	// the old spelling of "everything from github", and its scoped form is the
	// empty rest, which admits every tool on that member.
	if strings.Contains(filterOf(t, s, "g2"), `"github__"`) {
		t.Error(`the migration synthesised a "github__" prefixes entry: an allow rule became a member-wide wildcard`)
	}
	for _, tc := range []struct{ id, want string }{
		{"k1", `["mcp__fetch"]`},
		{"k3", `["github__search"]`},
		{"k4", `["safe_tool"]`},
	} {
		if allow, _ := listsOf(t, s, tc.id); allow != tc.want {
			t.Errorf("%s tool_allowlist = %s, want %s", tc.id, allow, tc.want)
		}
	}
}

// TestMigrateIsAFixedPoint runs step 3 over its own output. migrateStep's
// advisory-lock comment promises every step is idempotent because a Postgres
// replica that loses the lock race re-runs the step after the winner committed;
// this is that re-run, in one process.
func TestMigrateIsAFixedPoint(t *testing.T) {
	s, path := v2Store(t)

	const groupRows = `SELECT id, tool_filter FROM groups ORDER BY id`
	const keyRows = `SELECT id, tool_allowlist, tool_denylist FROM virtual_keys ORDER BY id`
	wantGroups := rowTuples(t, s, groupRows)
	wantKeys := rowTuples(t, s, keyRows)
	first := s.LastMigration()

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.migrateToolIdentities(tx); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	second := s.LastMigration()
	if n := second.ToolEntriesRewritten - first.ToolEntriesRewritten; n != 0 {
		t.Errorf("the second run rewrote %d entries; every form it adds must already be there", n)
	}
	if n := second.GroupsRewritten - first.GroupsRewritten; n != 0 {
		t.Errorf("the second run wrote %d group rows, want 0", n)
	}
	if n := second.VirtualKeysRewritten - first.VirtualKeysRewritten; n != 0 {
		t.Errorf("the second run wrote %d virtual key rows, want 0", n)
	}
	if got := rowTuples(t, s, groupRows); strings.Join(got, "\n") != strings.Join(wantGroups, "\n") {
		t.Errorf("groups changed on the second run:\n got %q\nwant %q", got, wantGroups)
	}
	if got := rowTuples(t, s, keyRows); strings.Join(got, "\n") != strings.Join(wantKeys, "\n") {
		t.Errorf("virtual_keys changed on the second run:\n got %q\nwant %q", got, wantKeys)
	}

	// And the ordinary path: a re-open runs no step at all, because the version
	// stamp says 3.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open a migrated database: %v", err)
	}
	defer s2.Close()
	if s2.LastMigration().Applied {
		t.Errorf("re-open reported a migration: %+v", s2.LastMigration())
	}
	if got := rowTuples(t, s2, keyRows); strings.Join(got, "\n") != strings.Join(wantKeys, "\n") {
		t.Errorf("virtual_keys changed on re-open:\n got %q\nwant %q", got, wantKeys)
	}
}

// TestMigrateRefusesInvalidStoredSlug mirrors step 1's refusal one level up. At
// step 3 a slug is half of an authorization identity, so composing a rule
// against a hand-edited one would write rules naming a member that cannot exist.
// The error names the row and nothing else: it is going to a log.
func TestMigrateRefusesInvalidStoredSlug(t *testing.T) {
	path := filepath.Join(t.TempDir(), "badslug.db")
	preChangeDB(t, path, append(v2Fixture(),
		`INSERT INTO upstreams (id, name, slug, description, url, transport, auth_type, auth_config, enabled, created_at, updated_at)
		 VALUES ('u9', 'Payroll Vendor', 'Bad Slug!', '', 'https://vendor.example.com/mcp?key=hunter2',
		         'streamable-http', 'none', '', 1, '2026-02-01T10:00:00Z', '2026-02-01T10:00:00Z')`))

	s, err := Open(path)
	if err == nil {
		_ = s.Close()
		t.Fatal("Open must fail when a stored slug is not ValidSlug")
	}
	msg := err.Error()
	if !strings.Contains(msg, "u9") {
		t.Errorf("error should name the row id, got %q", msg)
	}
	for _, leak := range []string{"Payroll Vendor", "vendor.example.com", "hunter2", "Bad Slug", "github_search", "mcp__fetch"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error leaked %q: %q", leak, msg)
		}
	}
}

// TestCorruptKeyListFailsClosed is the read side of the same argument the
// migration makes: a list column that does not decode is not an empty list. The
// scan still succeeds (the proxy needs the row to authenticate the request and
// to record refusing it) but the key is marked, and the proxy blocks every call
// on a marked key. The three spellings that legitimately mean "no list" must
// never set the mark, or every key in the database would be dead.
func TestCorruptKeyListFailsClosed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	k := &models.VirtualKey{
		ID: "k1", Name: "bot", KeyHash: "h", KeyLookup: "l1", KeyPrefix: "pory_k1",
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: time.Now().UTC(),
	}
	if err := s.CreateVirtualKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	set := func(t *testing.T, column, value string) *models.VirtualKey {
		t.Helper()
		if _, err := s.db.Exec(`UPDATE virtual_keys SET `+column+` = ? WHERE id = 'k1'`, value); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetVirtualKey(ctx, "k1")
		if err != nil {
			t.Fatalf("a key with %s = %q must still read back: %v", column, value, err)
		}
		return got
	}

	for _, column := range []string{"tool_allowlist", "tool_denylist"} {
		t.Run(column+" holding no list", func(t *testing.T) {
			for _, value := range []string{``, `null`, `[]`} {
				if got := set(t, column, value); got.ListsMalformed {
					t.Errorf("%s = %q marked the key malformed; that is what an unset list looks like", column, value)
				}
			}
		})
		t.Run(column+" corrupted", func(t *testing.T) {
			got := set(t, column, `["unterminated`)
			if !got.ListsMalformed {
				t.Errorf("%s = %q did not mark the key: an unreadable list would read as no list at all", column, `["unterminated`)
			}
			set(t, column, `[]`) // leave the other sub-test's column clean
		})
	}
}

// TestCorruptKeyListSurvivesAnUpdate is the write side of the same argument.
// The scan answers nil for both lists on a key it has marked, so an update that
// wrote them back would store "null" in both columns, which decodes cleanly,
// clears the mark on the next read, and leaves the key with no policy at all.
// Every mutating handler in the management API reads a key and writes it
// straight back, so that would make a rename, a rotation or a revocation the
// way to turn a key the proxy blocks on every call into a fully permissive one:
// the operator handed the startup warning would destroy the rule by following
// it. The columns are left exactly as they are found instead.
func TestCorruptKeyListSurvivesAnUpdate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	const corrupt = `["unterminated`
	k := &models.VirtualKey{
		ID: "k1", Name: "bot", KeyHash: "h", KeyLookup: "l1", KeyPrefix: "pory_k1",
		TargetType: models.TargetUpstream, TargetID: "u1", CreatedAt: time.Now().UTC(),
		ToolAllowlist: []string{"read_issue"},
	}
	if err := s.CreateVirtualKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE virtual_keys SET tool_denylist = ? WHERE id = 'k1'`, corrupt); err != nil {
		t.Fatal(err)
	}
	column := func(t *testing.T, name string) string {
		t.Helper()
		var v string
		if err := s.db.QueryRow(`SELECT ` + name + ` FROM virtual_keys WHERE id = 'k1'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	got, err := s.GetVirtualKey(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ListsMalformed {
		t.Fatalf("the seeded key did not read back marked; the rest of this test proves nothing")
	}

	// The ordinary rename, which is also what rotate and revoke do to the rest
	// of the row: read the key, change one field, write it back.
	got.Name = "renamed"
	if err := s.UpdateVirtualKey(ctx, got); err != nil {
		t.Fatalf("a corrupt key must still be renamable: %v", err)
	}

	if v := column(t, "tool_denylist"); v != corrupt {
		t.Errorf("tool_denylist = %q after the update, want %q unchanged", v, corrupt)
	}
	// The readable column is preserved too. Its list is nil on a marked key for
	// the same reason the unreadable one is, so writing it back would delete a
	// rule that was never in question.
	if want, v := `["read_issue"]`, column(t, "tool_allowlist"); v != want {
		t.Errorf("tool_allowlist = %q after the update, want %q unchanged", v, want)
	}

	after, err := s.GetVirtualKey(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !after.ListsMalformed {
		t.Error("the key read back unmarked after an update; every call on it is permitted again")
	}
	if after.Name != "renamed" {
		t.Errorf("name = %q, want the update to have landed on every other column", after.Name)
	}

	// And the way out: a caller with new text for both columns clears the flag,
	// which is what internal/api's patch handler does when a request supplies
	// both lists.
	after.ToolAllowlist = []string{"read_issue"}
	after.ToolDenylist = []string{"delete_repo"}
	after.ListsMalformed = false
	if err := s.UpdateVirtualKey(ctx, after); err != nil {
		t.Fatal(err)
	}
	fixed, err := s.GetVirtualKey(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if fixed.ListsMalformed {
		t.Error("the key is still marked after both columns were replaced with readable lists")
	}
	if len(fixed.ToolDenylist) != 1 || fixed.ToolDenylist[0] != "delete_repo" {
		t.Errorf("tool_denylist = %v, want the replacement to have been stored", fixed.ToolDenylist)
	}
}

// --- Step 4: the last-test columns ---

// TestMigrateAddsUpstreamTestColumns exercises step 4 against the oldest
// database in this file. The second, direct call of migrateUpstreamTestColumns
// is the only test of its columnExists gate: once the stamp reads 4 a re-open
// never enters the switch again, so the idempotence migrateStep's advisory-lock
// comment promises can only be proved by calling the step by name, the shape
// TestMigrateIsAFixedPoint uses for step 3.
func TestMigrateAddsUpstreamTestColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	preChangeDB(t, path, v1Fixture())
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	assertTestColumns := func(when string) {
		t.Helper()
		for _, want := range []string{"last_test_at|TEXT|0||0", "last_test_ok|INTEGER|0||0"} {
			if n := countColumns(t, s, "upstreams", want); n != 1 {
				t.Errorf("%s: upstreams has %d columns matching %q, want exactly 1", when, n, want)
			}
		}
		// NULL is "never tested", and that is what every migrated row is:
		// nothing is backfilled and no upstream is dialled by a migration.
		if got := rowTuples(t, s, `SELECT last_test_at, last_test_ok FROM upstreams ORDER BY id`); strings.Join(got, "\n") != "NULL|NULL" {
			t.Errorf("%s: rows = %q, want one row of NULL|NULL", when, got)
		}
	}
	assertTestColumns("after Open")

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.migrateUpstreamTestColumns(tx); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertTestColumns("after a second direct run")

	// And the Go layer reads the new columns as the three-state value they are.
	u, err := s.GetUpstream(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if u.LastTestAt != nil || u.LastTestOK != nil {
		t.Errorf("migrated upstream reads back tested: at=%v ok=%v", u.LastTestAt, u.LastTestOK)
	}
}

// TestMigrateDropsVirtualKeysLookupIndex is the only test that watches step
// 4's drop do anything (PORM-68). Every other fixture in this file either
// predates the index or loses it in step 2's rename, so by the time step 4 runs
// there is nothing there to drop and dropVirtualKeysLookupIndex could be a bare
// `return nil` without a single test noticing. Here the index is written onto a
// version-2 database before Open, which is exactly what a server that ran the
// pre-PORM-68 migrateBase left behind on every real deployment.
func TestMigrateDropsVirtualKeysLookupIndex(t *testing.T) {
	s, path := v2Store(t, `CREATE INDEX virtual_keys_lookup ON virtual_keys (key_lookup)`)
	if n := indexCount(t, s, "virtual_keys_lookup"); n != 0 {
		t.Errorf("virtual_keys_lookup survived step 4 (count %d)", n)
	}
	// And the lookup the proxy authenticates with is still served by an index:
	// the UNIQUE constraint's own, which is the whole reason the drop is safe.
	assertLookupUsesUniqueIndex(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopened, because migrateBase runs on every start while step 4 never runs
	// again once the stamp reads 4: a CREATE INDEX left behind in migrateBase
	// or in the rename would put the index back here and keep it back for good.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if n := indexCount(t, s2, "virtual_keys_lookup"); n != 0 {
		t.Errorf("virtual_keys_lookup came back on the second Open (count %d)", n)
	}
	if v, err := s2.currentSchemaVersion(); err != nil || v != 5 {
		t.Errorf("schema version = %d, %v; want 5", v, err)
	}
}

// countColumns counts the columns of table whose tableColumns description is
// exactly want, so a test can assert "this column exists once, spelled this
// way" without depending on ordinal.
func countColumns(t *testing.T, s *SQLStore, table, want string) int {
	t.Helper()
	n := 0
	for _, c := range tableColumns(t, s, table) {
		if c == want {
			n++
		}
	}
	return n
}

// TestParseDBURLFileFormKeepsTxlock pins the PORM-25 fix for the parked
// PORM-52 residual: a file: DATABASE_URL used to reach the driver verbatim and
// so missed _txlock=immediate, the one connection setting Open's imperative
// PRAGMAs cannot supply, and what lets `porymcp rekey` run against a live
// server. Operator-supplied parameters are kept; an explicit _txlock is never
// overridden.
func TestParseDBURLFileFormKeepsTxlock(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string // substring the resulting DSN must contain
		full string // when set, the DSN must equal this exactly
	}{
		{name: "bare file DSN gains the full setting set", raw: "file:./x.db",
			want: "_txlock=immediate"},
		{name: "operator params kept, txlock added", raw: "file:./x.db?_pragma=busy_timeout(1)",
			full: "file:./x.db?_pragma=busy_timeout(1)&_txlock=immediate"},
		{name: "explicit txlock untouched", raw: "file:./x.db?_txlock=deferred",
			full: "file:./x.db?_txlock=deferred"},
		{name: "trailing ? gains no stray separator", raw: "file:./x.db?",
			full: "file:./x.db?_txlock=immediate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			driver, dsn, err := parseDBURL(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if driver != "sqlite" {
				t.Fatalf("driver=%s", driver)
			}
			if tc.full != "" && dsn != tc.full {
				t.Fatalf("dsn=%q want %q", dsn, tc.full)
			}
			if tc.want != "" && !strings.Contains(dsn, tc.want) {
				t.Fatalf("dsn=%q missing %q", dsn, tc.want)
			}
		})
	}
	// The bare form is re-derived through fileDSN, so it carries the PRAGMA
	// set too, the same DSN a sqlite:// URL would get.
	_, bare, err := parseDBURL("file:./x.db")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"_pragma=foreign_keys(1)", "_pragma=busy_timeout(5000)", "_pragma=journal_mode(WAL)"} {
		if !strings.Contains(bare, p) {
			t.Fatalf("bare file: DSN %q missing %q", bare, p)
		}
	}
}
