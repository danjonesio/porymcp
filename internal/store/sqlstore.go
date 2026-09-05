package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	sqlite "modernc.org/sqlite"

	"github.com/danjonesio/porymcp/internal/models"
)

type SQLStore struct {
	db            *sql.DB
	driver        string
	lastMigration MigrationSummary
}

// MigrationSummary reports what the last migrate() run changed, so the caller
// can log it. Counts only, never names or URLs: `url` is stored in plaintext
// and MCP endpoints commonly carry a key in the query string.
//
// SlugsDeduplicated counts rows whose assigned slug differs from the plain
// derivation of their name, which includes a reserved-word skip (an upstream
// named "MCP" becomes "mcp-2"), not only genuine duplicates.
//
// The tool-entry counts describe step 3, migrateToolIdentities. A rule entry is
// operator-written text about somebody's tools, so it is held to the same rule
// as a name or a url and never appears here: only how many there were.
//
//   - ToolEntriesRewritten: entries that gained at least one scoped
//     {slug}__{tool} form. The entry they were written as is kept beside it, so
//     this counts additions, never replacements.
//   - ToolEntriesLeft: entries the step deliberately did not touch and an
//     operator may want to look at: an entry no advertised tool name can ever
//     equal, an allow-side entry that admits nothing as it stands, every entry
//     on a key whose target row has gone, and one per virtual-key list column
//     whose JSON does not decode (there are no entries to count in that one).
//   - ToolFiltersLeftInvalid: group filters left exactly as stored because
//     validation refused them, on the way in or on the way out.
//
// Every field is an int, so MigrationSummary stays comparable: the tests assert
// on whole summaries with ==, which is what makes a new count hard to forget.
type MigrationSummary struct {
	Applied           bool
	Version           int
	SlugsDerived      int
	SlugsDeduplicated int

	ToolEntriesRewritten   int
	ToolEntriesLeft        int
	ToolFiltersLeftInvalid int
	GroupsRewritten        int
	VirtualKeysRewritten   int
}

// LastMigration reports what migrate() did during Open. Zero value means the
// schema was already current.
func (s *SQLStore) LastMigration() MigrationSummary { return s.lastMigration }

func Open(databaseURL string) (*SQLStore, error) {
	driver, dsn, err := parseDBURL(databaseURL)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		if err := os.MkdirAll(filepath.Dir(stripSQLitePath(dsn)), 0o755); err != nil && !errors.Is(err, os.ErrNotExist) {
			// stripSQLitePath may return a relative file; still try
			_ = os.MkdirAll(filepath.Dir(fileFromDSN(dsn)), 0o755)
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;`); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	s := &SQLStore{db: db, driver: driver}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func parseDBURL(raw string) (driver, dsn string, err error) {
	if raw == "" {
		return "", "", fmt.Errorf("DATABASE_URL is empty")
	}
	switch {
	case strings.HasPrefix(raw, "postgres://"), strings.HasPrefix(raw, "postgresql://"):
		return "pgx", raw, nil
	case strings.HasPrefix(raw, "sqlite://"):
		// sqlite:///abs/path is /abs/path
		// sqlite://./rel/path or sqlite://rel/path is relative
		path := strings.TrimPrefix(raw, "sqlite://")
		return sqliteFile(path)
	case strings.HasPrefix(raw, "file:"):
		// A file: DSN used to reach the driver verbatim, so it missed the one
		// setting Open's own PRAGMAs cannot supply: _txlock=immediate, which
		// is what lets `porymcp rekey` run against a live server (PORM-52
		// residual, parked with PORM-25). A DSN with no query is re-derived
		// through fileDSN so one function owns the connection settings; one
		// that carries the operator's own parameters keeps them and gains only
		// what is missing, rewriting it wholesale would turn
		// file::memory:?cache=shared into an on-disk file called ":memory:".
		if !strings.Contains(raw, "?") {
			return sqliteFile(fileFromDSN(raw))
		}
		if !strings.Contains(raw, "_txlock=") {
			if strings.HasSuffix(raw, "?") {
				raw += "_txlock=immediate"
			} else {
				raw += "&_txlock=immediate"
			}
		}
		return "sqlite", raw, nil
	default:
		return sqliteFile(raw)
	}
}

func sqliteFile(path string) (string, string, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", "", err
		}
	}
	return "sqlite", fileDSN(path), nil
}

// fileDSN builds a modernc.org/sqlite URI. Relative paths must be
// file:./data/x.db, file://./data/x.db is invalid because SQLite treats
// "." as the URI authority.
func fileDSN(path string) string {
	path = filepath.ToSlash(path)
	var dsn string
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") {
		dsn = "file://" + path
	} else {
		dsn = "file:" + path
	}
	// _txlock=immediate: every explicit transaction takes the write lock at
	// BEGIN. All three transaction users here (migrateStep, the step-2 rename,
	// RekeyUpstreams) write, and a deferred BEGIN in WAL mode takes a read
	// snapshot instead, any other connection's commit (an audit row from one
	// proxied call, say) then fails the first write with SQLITE_BUSY_SNAPSHOT,
	// which busy_timeout deliberately does not retry. Immediate makes an
	// unrelated writer queue behind busy_timeout instead, which is what lets
	// `porymcp rekey` run against a live server (PORM-52).
	return dsn + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
}

func fileFromDSN(dsn string) string {
	if strings.HasPrefix(dsn, "file://") {
		p := strings.TrimPrefix(dsn, "file://")
		if i := strings.Index(p, "?"); i >= 0 {
			p = p[:i]
		}
		return p
	}
	if strings.HasPrefix(dsn, "file:") {
		p := strings.TrimPrefix(dsn, "file:")
		if i := strings.Index(p, "?"); i >= 0 {
			p = p[:i]
		}
		return p
	}
	return dsn
}

func stripSQLitePath(dsn string) string {
	return fileFromDSN(dsn)
}

func (s *SQLStore) q(query string) string {
	if s.driver != "pgx" {
		return query
	}
	n := 0
	var b strings.Builder
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(fmt.Sprintf("%d", n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

const (
	// schemaVersion is the migration level this binary expects. Bump it in the
	// SAME commit as the migrateStep case it enables, or the tree is unbuildable
	// at that commit and future bisects land on a broken store.Open.
	schemaVersion    = 5
	schemaVersionKey = "schema_version"

	// EncryptionKeyFPKey is the schema_meta row holding the fingerprint of the
	// ENCRYPTION_KEY that the stored credentials open under (PORM-52). It is
	// data, not schema: written by the boot check once every row has been
	// proved to open under the current key, and by RekeyUpstreams, never by a
	// migration step, which runs with no key. The issue's draft called it
	// enc_key_fp; this is the name used.
	EncryptionKeyFPKey = "encryption_key_fp"

	// migrationLockID is an arbitrary constant for pg_advisory_xact_lock; any
	// future migration path must use this same value. int64 is deliberate: an
	// untyped constant passed as `any` defaults to int and overflows a 32-bit
	// build (verified: GOARCH=386 go vet reports "overflows"), and int64 is the
	// type pg_advisory_xact_lock takes.
	migrationLockID int64 = 4815162342
)

// migrate brings the database to schemaVersion: it makes sure the version
// table exists, runs the step-2 rename ahead of the base DDL when the recorded
// version needs it, creates the base tables, then runs every numbered step
// above the recorded version.
func (s *SQLStore) migrate() error {
	if err := s.ensureSchemaMeta(); err != nil {
		return err
	}
	current, err := s.currentSchemaVersion()
	if err != nil {
		return fmt.Errorf("migrate: read schema version: %w", err)
	}
	// Refuse a database written by a newer build. Without this the step loop
	// does not run and an old binary serves traffic against a schema it
	// does not understand, the same hazard migrateUpstreamSlugs already fails
	// closed on. A rolled-back deploy is an ordinary ops event.
	if current > schemaVersion {
		return fmt.Errorf("migrate: database is at schema version %d but this binary only knows %d; "+
			"run the newer build or restore a backup", current, schemaVersion)
	}
	if current < 2 {
		// Step 2 renames the very tables and columns migrateBase's DDL names,
		// so it cannot wait for the step loop: against a version-1 database
		// migrateBase would first create an empty virtual_keys beside agents
		// and then fail on the audit_logs index over a column that does not
		// exist yet. Run the rename ahead of the base DDL, gated so a fresh
		// database passes straight through, and let case 2 below re-run it as
		// a no-op before stamping the version. Once the stamp reads 2 this
		// branch never runs again.
		if err := s.renameAgentsToVirtualKeys(); err != nil {
			return fmt.Errorf("migrate: rename agents to virtual_keys: %w", err)
		}
	}
	if err := s.migrateBase(); err != nil {
		return err
	}
	for v := current + 1; v <= schemaVersion; v++ {
		if err := s.migrateStep(v); err != nil {
			return fmt.Errorf("migrate: step %d: %w", v, err)
		}
		s.lastMigration.Applied = true
		s.lastMigration.Version = v
	}
	return nil
}

// ensureSchemaMeta creates the version table on its own, ahead of everything
// else, so migrate can read the recorded version before deciding what to run.
// Shared with PORM-52's encryption-key fingerprint: whichever lands first
// creates it.
func (s *SQLStore) ensureSchemaMeta() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// migrateBase creates the tables every version shares.
//
// Not covered by migrateStep's advisory lock: two replicas starting against a
// virgin Postgres can still race here on CREATE TABLE IF NOT EXISTS. The loser
// exits and a restart succeeds, because the tables then exist.
func (s *SQLStore) migrateBase() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS upstreams (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL,
			transport TEXT NOT NULL,
			auth_type TEXT NOT NULL,
			auth_config TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_test_at TEXT,
			last_test_ok INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			upstream_ids TEXT NOT NULL DEFAULT '[]',
			tool_filter TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS virtual_keys (
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
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			virtual_key_id TEXT NOT NULL,
			virtual_key_name TEXT NOT NULL,
			method TEXT NOT NULL,
			tool_name TEXT NOT NULL DEFAULT '',
			params TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			latency_ms INTEGER NOT NULL DEFAULT 0,
			response_size_bytes INTEGER NOT NULL DEFAULT 0,
			upstream_id TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			request_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS audit_logs_ts ON audit_logs (timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS audit_logs_virtual_key ON audit_logs (virtual_key_id, timestamp DESC)`,
		// admin_events is additive and lives here rather than in a numbered
		// step: migrateBase runs on every open ahead of the step loop, so an
		// existing database gains the table on its next start, and
		// schemaVersion stays 5 so a rolled-back binary can still open a
		// database that has it. Every insert names the details column, so its
		// default is documentation. One index: the shipped reads order by
		// timestamp with an optional resource_type equality (PORM-54).
		`CREATE TABLE IF NOT EXISTS admin_events (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			resource_name TEXT NOT NULL DEFAULT '',
			details TEXT NOT NULL DEFAULT '{}',
			request_id TEXT NOT NULL DEFAULT '',
			remote_addr TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS admin_events_ts ON admin_events (timestamp DESC)`,
		// No index on virtual_keys.key_lookup: the column is NOT NULL UNIQUE
		// above, and the constraint's own index is the one the planner uses for
		// GetVirtualKeyByLookup. A second index over the same single column
		// served no read and cost every write (PORM-68); step 4 drops it from
		// databases that already have it.
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) currentSchemaVersion() (int, error) {
	var v string
	err := s.db.QueryRow(s.q(`SELECT value FROM schema_meta WHERE key = ?`), schemaVersionKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("schema_meta %s = %q: %w", schemaVersionKey, v, err)
	}
	return n, nil
}

// migrateStep runs one schema migration and stamps the new version in the same
// transaction, so a crash mid-step leaves the database untouched.
//
// Every statement below must go through tx, never s.db: SQLite runs with
// SetMaxOpenConns(1) and an s.db call here would deadlock on the connection the
// transaction is holding.
func (s *SQLStore) migrateStep(v int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	if s.driver == "pgx" {
		// Serialise concurrent first-starts across replicas. Without it the loser
		// fails inside a poisoned transaction and Postgres then answers 25P02 to
		// every following statement, hiding the real error. The waiter re-runs
		// this step as a no-op, which is safe only because every step is written
		// to be idempotent (keep it that way) and because READ COMMITTED (the
		// default) means its statements after the lock see the winner's commit.
		// Released at COMMIT/ROLLBACK.
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
			return err
		}
	}

	switch v {
	case 1:
		if err := s.migrateUpstreamSlugs(tx); err != nil {
			return err
		}
	case 2:
		// The rename itself already ran ahead of migrateBase (see migrate).
		// This re-run is a gated no-op that exists so the step and its version
		// stamp share one transaction, and so a replica that lost the
		// advisory-lock race finds nothing left to do.
		if err := s.renameAgentsToVirtualKeysTx(tx); err != nil {
			return err
		}
	case 3:
		if err := s.migrateToolIdentities(tx); err != nil {
			return err
		}
	case 4:
		if err := s.migrateUpstreamTestColumns(tx); err != nil {
			return err
		}
		if err := s.dropVirtualKeysLookupIndex(tx); err != nil {
			return err
		}
	case 5:
		// Format stamp, no DDL, no data change (PORM-52): from this version
		// upstreams.auth_config may hold "v1:"-prefixed ciphertexts, which a
		// version-4 binary base64-decodes as garbage and then (because its
		// decryptAuth returns nil for any failure) forwards as a request with
		// no credential. The stamp makes that binary refuse the database at
		// Open instead. It lands on the FIRST boot of this build, before any
		// v1 value exists: upgrading is one-way from that boot.
	default:
		return fmt.Errorf("no migration defined for version %d", v)
	}

	if err := s.setMetaTx(tx, schemaVersionKey, strconv.Itoa(v)); err != nil {
		return err
	}
	return tx.Commit()
}

// Meta reads one schema_meta value. A missing key is ("", nil), the way
// currentSchemaVersion treats sql.ErrNoRows. The value is operator-writable
// text; callers validate it before comparing or logging it.
func (s *SQLStore) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT value FROM schema_meta WHERE key = ?`), key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// SetMeta upserts one schema_meta row outside any transaction. Inside a
// transaction use setMetaTx: an s.db call while a tx holds SQLite's single
// connection hangs, it does not error.
func (s *SQLStore) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, s.q(schemaMetaUpsert), key, value)
	return err
}

// schemaMetaUpsert is the one upsert every schema_meta write uses; ON CONFLICT
// works on both drivers because key is the primary key.
const schemaMetaUpsert = `
		INSERT INTO schema_meta (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`

// setMetaTx is SetMeta through an open transaction.
func (s *SQLStore) setMetaTx(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec(s.q(schemaMetaUpsert), key, value)
	return err
}

// RekeyRow is one stored credential handed to RekeyUpstreams' callback: the
// row's id and name (for the operator's report, never a value) and the
// ciphertext as stored.
type RekeyRow struct{ ID, Name, Stored string }

// RekeySummary is what RekeyUpstreams did, as counts. PreviousFingerprint is
// the encryption_key_fp row as it stood before the write ("" when absent), so
// the stamp moving is visible in the command's output.
type RekeySummary struct {
	Rewritten, AlreadyCurrent, NoCredential int
	PreviousFingerprint                     string
}

// RekeyUpstreams re-wraps every stored credential and stamps the fingerprint in
// ONE transaction. The crypto does not belong in the store, which holds no key:
// rewrite receives every row that needs a credential and holds a blob, in id
// order, and returns one replacement per row, "" for a row already sealed under
// the current key. Any error from rewrite returns before anything is written,
// so the deferred Rollback undoes nothing; the callback is expected to classify
// every row and name all the failures in one error, and no UPDATE and no
// schema_meta write happens on a run that saw one.
//
// Cross-driver constraints, the ones every migration step works under: every
// statement goes through tx, never s.db (SQLite runs with SetMaxOpenConns(1)
// and an s.db call inside the transaction would deadlock on the connection it
// holds); every row is collected before the first UPDATE, because SQLite
// cannot interleave an Exec with open Rows; placeholders go through s.q(); on
// pgx the migration advisory lock serialises this against a migration or a
// second rekey. No DDL.
//
// Each write is a compare-and-swap on the ciphertext that was read: `UPDATE …
// WHERE id = ? AND auth_config = ?`. On SQLite the transaction takes the
// database write lock at BEGIN (fileDSN sets _txlock=immediate), so every
// other writer (a credential edit and an unrelated audit insert alike) queues
// behind busy_timeout and then applies AFTER the commit; the operator's
// concurrent edit lands on top of the re-wrapped value, under the current key,
// and nothing is lost. On Postgres (READ COMMITTED) writers do not queue: a
// credential edited between the read and the write makes the CAS match zero
// rows, which aborts the whole run with the one operator-facing sentence. That
// zero-rows branch is Postgres's mechanism and is unreachable on SQLite by
// construction. Keep it. There is deliberately no retry inside the
// transaction: re-running the command is the retry; a retry here would write
// the re-wrapped OLD plaintext over a credential the operator had just
// replaced, which is the lost update the CAS exists to prevent. The rewrite
// callback runs while this transaction holds SQLite's only connection, so it
// must never call back into the store.
//
// updated_at, last_test_at and last_test_ok are untouched: re-wrapping a
// credential is not an edit to the connection, and RecordUpstreamTest's
// compare-and-swap on updated_at must keep matching. NOTE: only SQLite is
// exercised by this package's tests.
func (s *SQLStore) RekeyUpstreams(ctx context.Context, fingerprint string, rewrite func([]RekeyRow) ([]string, error)) (RekeySummary, error) {
	var sum RekeySummary
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RekeySummary{}, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	if s.driver == "pgx" {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
			return RekeySummary{}, err
		}
	}

	var prev string
	if err := tx.QueryRowContext(ctx, s.q(`SELECT value FROM schema_meta WHERE key = ?`), EncryptionKeyFPKey).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return RekeySummary{}, err
	}
	sum.PreviousFingerprint = prev

	var needing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstreams WHERE auth_type NOT IN ('none', '')`).Scan(&needing); err != nil {
		return RekeySummary{}, err
	}

	// Collect fully before updating: SQLite runs on one connection and cannot
	// interleave an Exec with open Rows. COALESCE because a hand-edited
	// database may hold NULL where the DDL says TEXT NOT NULL DEFAULT ''.
	rs, err := tx.QueryContext(ctx, `SELECT id, name, COALESCE(auth_config, '') FROM upstreams
		WHERE auth_type NOT IN ('none', '') AND COALESCE(auth_config, '') <> '' ORDER BY id`)
	if err != nil {
		return RekeySummary{}, err
	}
	var rows []RekeyRow
	for rs.Next() {
		var r RekeyRow
		if err := rs.Scan(&r.ID, &r.Name, &r.Stored); err != nil {
			rs.Close()
			return RekeySummary{}, err
		}
		rows = append(rows, r)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return RekeySummary{}, err
	}
	sum.NoCredential = needing - len(rows)

	next, err := rewrite(rows)
	if err != nil {
		return RekeySummary{}, err
	}
	if len(next) != len(rows) {
		return RekeySummary{}, fmt.Errorf("rekey: rewrite returned %d values for %d rows", len(next), len(rows))
	}

	for i, r := range rows {
		if next[i] == "" {
			sum.AlreadyCurrent++
			continue
		}
		res, err := tx.ExecContext(ctx, s.q(`UPDATE upstreams SET auth_config = ? WHERE id = ? AND auth_config = ?`), next[i], r.ID, r.Stored)
		if err != nil {
			return RekeySummary{}, fmt.Errorf("upstream %s changed during rekey; re-run: %w", r.ID, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return RekeySummary{}, fmt.Errorf("upstream %s changed during rekey; re-run", r.ID)
		}
		sum.Rewritten++
	}

	if err := s.setMetaTx(tx, EncryptionKeyFPKey, fingerprint); err != nil {
		return RekeySummary{}, err
	}
	if err := tx.Commit(); err != nil {
		return RekeySummary{}, err
	}
	return sum, nil
}

// migrateUpstreamSlugs adds upstreams.slug, derives a unique slug for every row
// that lacks one, then makes the column unique. The backfill has to run before
// the index: two or more pre-change rows share the empty-string default and
// would fail it.
//
// The derivation itself cannot fail: SlugCandidatesN's walk is total (see
// models.SlugCandidatesN). The only data-dependent errors below come from a
// database corrupted outside PoryMCP: an existing slug that is not ValidSlug, or
// existing duplicate slugs, which surface from CREATE UNIQUE INDEX. Both must
// fail closed.
func (s *SQLStore) migrateUpstreamSlugs(tx *sql.Tx) error {
	has, err := s.columnExists(tx, "upstreams", "slug")
	if err != nil {
		return err
	}
	if !has {
		if _, err := tx.Exec(`ALTER TABLE upstreams ADD COLUMN slug TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}

	// Seed from rows that already carry a slug so a re-run cannot collide, and
	// validate them: a hand-edited database must not carry an invalid slug into
	// a public URL after PORM-14. Name the row id only, never name or url.
	taken := map[string]bool{}
	rows, err := tx.Query(`SELECT id, slug FROM upstreams WHERE slug IS NOT NULL AND slug <> ''`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, sl string
		if err := rows.Scan(&id, &sl); err != nil {
			rows.Close()
			return err
		}
		if !models.ValidSlug(sl) {
			rows.Close()
			return fmt.Errorf("upstream %s has an invalid stored slug; fix it in the database and restart", id)
		}
		taken[sl] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Oldest first, so the upstream clients already know keeps the bare slug.
	// NOTE: the opposite order to ListUpstreams, do not copy that one.
	// Collect fully before updating: SQLite runs on one connection and cannot
	// interleave an Exec with open Rows.
	type pending struct{ id, name string }
	var todo []pending
	rows, err = tx.Query(`SELECT id, name FROM upstreams WHERE slug IS NULL OR slug = '' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.name); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range todo {
		// The cheap walk covers every realistic database; widening only when all
		// MaxSlugAttempts are taken keeps a large backfill at ~50 allocations per
		// row instead of one per existing upstream. The widened walk is total.
		sl := firstFreeSlug(models.SlugCandidates(p.name), taken)
		if sl == "" {
			sl = firstFreeSlug(models.SlugCandidatesN(p.name, len(taken)+2), taken)
		}
		if sl == "" {
			// Assertion, not a data-dependent failure: models.SlugCandidatesN is
			// total, so this is unreachable unless its precondition was broken
			// (see TestReservedSlug). Fail loudly at the row rather than writing
			// slug='' and surfacing later as a confusing unique-index error.
			return fmt.Errorf("could not derive a unique slug for upstream %s", p.id)
		}
		if _, err := tx.Exec(s.q(`UPDATE upstreams SET slug = ? WHERE id = ?`), sl, p.id); err != nil {
			return err
		}
		taken[sl] = true
		s.lastMigration.SlugsDerived++
		if sl != models.DeriveSlug(p.name) {
			s.lastMigration.SlugsDeduplicated++
		}
	}

	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS upstreams_slug ON upstreams (slug)`)
	return err
}

func firstFreeSlug(candidates []string, taken map[string]bool) string {
	for _, c := range candidates {
		if !taken[c] {
			return c
		}
	}
	return ""
}

// uniqueViolation reports whether err is a UNIQUE-constraint failure from either
// supported driver. Primary-key collisions are deliberately excluded on SQLite
// (SQLITE_CONSTRAINT_PRIMARYKEY, 1555): every id is a fresh uuid.NewString(), so
// a PK collision is a programming error and 500 is the honest answer, not a
// "slug is already taken" 409. Postgres reports both as 23505 and cannot be
// separated without inspecting ConstraintName, accepted imprecision, in favour
// of cross-driver parity in the common (slug) case.
//
// Extended result codes, not the primary 19 masked with 0xff: masking would
// sweep NOT NULL, CHECK and FOREIGN KEY failures into a 409.
func uniqueViolation(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() == 2067 // SQLITE_CONSTRAINT_UNIQUE
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == "23505" // unique_violation
	}
	return false
}

// conflictErr maps a driver-level unique violation onto ErrConflict so handlers
// can answer 409 without knowing which driver is underneath.
func conflictErr(err error) error {
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// columnExists probes for a column on either driver, because SQLite has no
// ALTER TABLE … ADD COLUMN IF NOT EXISTS and one probe keeps the migration to a
// single ALTER statement instead of two dialect variants.
func (s *SQLStore) columnExists(tx *sql.Tx, table, column string) (bool, error) {
	q := `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`
	if s.driver == "pgx" {
		q = `SELECT COUNT(*) FROM information_schema.columns
		     WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`
	}
	var n int
	if err := tx.QueryRow(q, table, column).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// tableExists probes for a table on either driver. pragma/catalog probes on a
// missing object return zero rows, not an error, so gates can ask freely.
func (s *SQLStore) tableExists(tx *sql.Tx, table string) (bool, error) {
	q := `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`
	if s.driver == "pgx" {
		q = `SELECT COUNT(*) FROM information_schema.tables
		     WHERE table_schema = current_schema() AND table_name = $1`
	}
	var n int
	if err := tx.QueryRow(q, table).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// rowCount is for migration gates only; table is always a literal here.
func (s *SQLStore) rowCount(tx *sql.Tx, table string) (int, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
	return n, err
}

// renameAgentsToVirtualKeys runs migration step 2 in its own transaction,
// under the same advisory lock migrateStep takes, because it has to run
// before migrateBase (see migrate). On a version-1 database this commits the
// rename before the version stamp; a crash in between is safe, the next Open
// reads version 1, re-runs the gated rename as a no-op, and case 2 stamps 2.
func (s *SQLStore) renameAgentsToVirtualKeys() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	if s.driver == "pgx" {
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
			return err
		}
	}
	if err := s.renameAgentsToVirtualKeysTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// renameAgentsToVirtualKeysTx is migration step 2: the agents table becomes
// virtual_keys, audit_logs.agent_id and agent_name become virtual_key_id and
// virtual_key_name, and the two indexes over them are recreated under their
// new names. Every statement is gated on the catalog so the function is
// idempotent (it runs once ahead of migrateBase and again as case 2) and a
// fresh database, where none of the old objects exist, passes straight
// through. Data is untouched: both renames are metadata-only on SQLite and
// PostgreSQL.
func (s *SQLStore) renameAgentsToVirtualKeysTx(tx *sql.Tx) error {
	hasOld, err := s.tableExists(tx, "agents")
	if err != nil {
		return err
	}
	hasNew, err := s.tableExists(tx, "virtual_keys")
	if err != nil {
		return err
	}
	if hasOld && hasNew {
		// Both exist only when a build carrying the new base DDL ran against
		// an unmigrated database and left an empty table behind, or when an
		// operator has already moved the rows by hand. An empty side is
		// discarded; two populated tables are a state this code refuses to
		// guess at. The error names the tables and nothing in them.
		oldRows, err := s.rowCount(tx, "agents")
		if err != nil {
			return err
		}
		newRows, err := s.rowCount(tx, "virtual_keys")
		if err != nil {
			return err
		}
		switch {
		case newRows == 0:
			if _, err := tx.Exec(`DROP TABLE virtual_keys`); err != nil {
				return err
			}
			hasNew = false
		case oldRows == 0:
			if _, err := tx.Exec(`DROP TABLE agents`); err != nil {
				return err
			}
			hasOld = false
		default:
			return fmt.Errorf("both agents (%d rows) and virtual_keys (%d rows) exist; "+
				"restore a backup or drop the table you do not want", oldRows, newRows)
		}
	}
	if hasOld && !hasNew {
		if _, err := tx.Exec(`ALTER TABLE agents RENAME TO virtual_keys`); err != nil {
			return err
		}
	}
	for _, c := range [][2]string{{"agent_id", "virtual_key_id"}, {"agent_name", "virtual_key_name"}} {
		has, err := s.columnExists(tx, "audit_logs", c[0])
		if err != nil {
			return err
		}
		if has {
			if _, err := tx.Exec(`ALTER TABLE audit_logs RENAME COLUMN ` + c[0] + ` TO ` + c[1]); err != nil {
				return err
			}
		}
	}
	// Both drivers keep an index's NAME across RENAME TO and RENAME COLUMN and
	// only rewrite its definition, so the old names would otherwise live on
	// over the new objects. Drop them and create the new names. Ahead of
	// migrateBase on a fresh database the tables do not exist yet, in which
	// case migrateBase creates the indexes instead.
	for _, stmt := range []string{
		`DROP INDEX IF EXISTS agents_lookup`,
		`DROP INDEX IF EXISTS audit_logs_agent`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	// agents_lookup is dropped and NOT recreated under the new name: key_lookup
	// is NOT NULL UNIQUE, so the constraint index already serves the lookup
	// (PORM-68). Recreating it here would put it back on every upgrade and
	// step 4's drop would never stick.
	hasAudit, err := s.tableExists(tx, "audit_logs")
	if err != nil {
		return err
	}
	if hasAudit {
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS audit_logs_virtual_key ON audit_logs (virtual_key_id, timestamp DESC)`); err != nil {
			return err
		}
	}
	return nil
}

// migrateToolIdentities is migration step 3: it rewrites the tool rules written
// before the {slug}__{tool} identity existed, so that a rule an operator wrote
// against the old aggregate spelling still means what they meant.
//
// Only DENY rules are rewritten, and they are rewritten by ADDING the scoped
// forms beside the entry that is already there, never by replacing it. Three
// reasons, which are all one reason:
//
//   - A deny entry that stops matching is a fail-open: the rule written to keep
//     a tool out of an agent's hands quietly permits it. Adding every reading of
//     an ambiguous entry can only over-block, which is a support ticket rather
//     than a breach.
//   - An allow entry that gains a form widens an authorization list during an
//     upgrade with nobody present. A prefixes entry "github_" would become
//     "github__", every tool on that member. So allow-side entries are left
//     exactly as they are and counted: the group's tools go dark, the startup
//     report names it, and an operator rewrites the entry knowingly.
//   - Keeping the original entry keeps a key's lists matching prompts and
//     resources, which are compared whole against each entry and know nothing
//     about slugs (keyListsOnly, internal/proxy/policy.go).
//
// The rewrite is a FIXED POINT: every form it adds is deduped against the list
// it is added to, and a scoped entry whose head is already a member is left
// alone, so a second run over its own output changes nothing. That is not a
// nicety. migrateStep's advisory-lock comment promises that every step is
// idempotent, because a Postgres replica that loses the lock race re-runs the
// step after the winner has committed and sees the winner's rows under READ
// COMMITTED. Without the fixed point that replica would append a second copy of
// every added form, on every start.
//
// Cross-driver constraints, the same ones steps 1 and 2 work under: every
// statement goes through tx, never s.db (SQLite runs with SetMaxOpenConns(1)
// and an s.db call inside the transaction would deadlock on the connection it
// holds); every row is collected before the first UPDATE, because SQLite cannot
// interleave an Exec with open Rows; placeholders go through s.q(). Nothing
// else here is dialect-specific, plain SELECT and UPDATE over columns both
// drivers already have, and no DDL at all, so the fresh-versus-migrated schema
// comparison is untouched by it. NOTE: only SQLite is exercised by this
// package's tests; there is no Postgres server in the build environment.
//
// updated_at is deliberately not bumped. The row's meaning did not change, only
// its spelling, and updated_at answers "when did a person last edit this?".
func (s *SQLStore) migrateToolIdentities(tx *sql.Tx) error {
	// A stored slug stopped being only a URL segment at this step: it is now
	// half of an authorization identity. Composing one from a hand-edited row
	// would write rules naming a member that can never exist, so refuse the way
	// step 1 does, naming the row id and nothing else, because the name and the
	// url are operator data and this error is going to a log.
	slugByID := map[string]string{}
	rows, err := tx.Query(`SELECT id, slug FROM upstreams`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, sl string
		if err := rows.Scan(&id, &sl); err != nil {
			rows.Close()
			return err
		}
		if !models.ValidSlug(sl) {
			rows.Close()
			return fmt.Errorf("upstream %s has an invalid stored slug and it cannot be part of a tool identity; fix it in the database and restart", id)
		}
		slugByID[id] = sl
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	type groupRow struct{ id, upstreamIDs, filter string }
	var groups []groupRow
	rows, err = tx.Query(`SELECT id, upstream_ids, tool_filter FROM groups`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var g groupRow
		if err := rows.Scan(&g.id, &g.upstreamIDs, &g.filter); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	type keyRow struct{ id, targetType, targetID, allow, deny string }
	var keys []keyRow
	rows, err = tx.Query(`SELECT id, target_type, target_id, tool_allowlist, tool_denylist FROM virtual_keys`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k keyRow
		if err := rows.Scan(&k.id, &k.targetType, &k.targetID, &k.allow, &k.deny); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Every read is done; from here on it is UPDATEs only.
	byGroup := make(map[string]membership, len(groups))
	for _, g := range groups {
		ids, ok := decodeJSONStrings(g.upstreamIDs)
		if !ok {
			// The membership is unreadable, so no entry on this group or on a
			// key pointing at it can be judged. membership's zero value says so.
			continue
		}
		byGroup[g.id] = newMembership(ids, slugByID)
	}

	for _, g := range groups {
		raw := strings.TrimSpace(g.filter)
		if raw == "" || raw == "null" {
			continue // no filter
		}
		// Validate the STORED bytes before deciding to rewrite anything, and
		// never marshal a filter the validator refused. A filter the proxy
		// cannot read blocks every tool on its group, and re-emitting it
		// through models.ToolFilter would silently drop the misspelt key that
		// made it invalid, turning a group that fails closed into one that
		// permits everything, in a migration, with nobody watching.
		if err := models.ValidateToolFilter(json.RawMessage(raw)); err != nil {
			s.lastMigration.ToolFiltersLeftInvalid++
			continue
		}
		var tf models.ToolFilter
		if err := json.Unmarshal([]byte(raw), &tf); err != nil {
			// Unreachable: ValidateToolFilter has already decoded these same
			// bytes more strictly. Counted rather than ignored so that a change
			// to either side cannot turn this into a silent skip.
			s.lastMigration.ToolFiltersLeftInvalid++
			continue
		}
		before := s.lastMigration
		deny := tf.Mode == "deny"
		m := byGroup[g.id]
		tools, toolsChanged := s.rewriteRule(tf.Tools, m, deny, false)
		prefixes, prefixesChanged := s.rewriteRule(tf.Prefixes, m, deny, true)
		if !toolsChanged && !prefixesChanged {
			continue
		}
		tf.Tools, tf.Prefixes = tools, prefixes
		out, err := json.Marshal(tf)
		if err != nil {
			return err // unreachable: a ToolFilter is strings all the way down
		}
		// The self-check on the way out, on top of the pre-check on the way in:
		// a bug in the rules above must not be able to write a filter the proxy
		// then refuses to read, because that would block every tool on the
		// group. The counters rewind with the row, so the summary describes
		// what was actually written.
		if err := models.ValidateToolFilter(out); err != nil {
			s.lastMigration = before
			s.lastMigration.ToolFiltersLeftInvalid++
			continue
		}
		if _, err := tx.Exec(s.q(`UPDATE groups SET tool_filter = ? WHERE id = ?`), string(out), g.id); err != nil {
			return err
		}
		s.lastMigration.GroupsRewritten++
	}

	for _, k := range keys {
		var m membership
		switch k.targetType {
		case models.TargetUpstream:
			if sl, ok := slugByID[k.targetID]; ok {
				// group stays false: a bare entry in this key's allowlist names
				// a tool on the one upstream it points at and keeps working.
				m = membership{slugs: []string{sl}, index: map[string]bool{sl: true}, resolved: true}
			}
		case models.TargetGroup:
			m = byGroup[k.targetID] // the zero value when the group row has gone
		}
		// The last argument is the side the list is on: a denylist takes the
		// deny column of the rewrite table, an allowlist the allow column.
		allow, allowChanged := s.rewriteColumn(k.allow, m, false)
		deny, denyChanged := s.rewriteColumn(k.deny, m, true)
		if !allowChanged && !denyChanged {
			continue
		}
		if _, err := tx.Exec(s.q(`UPDATE virtual_keys SET tool_allowlist = ?, tool_denylist = ? WHERE id = ?`),
			allow, deny, k.id); err != nil {
			return err
		}
		s.lastMigration.VirtualKeysRewritten++
	}
	return nil
}

// membership is the set of upstream slugs a rule on one target may name: a
// group's members, or the single upstream a virtual key points at.
//
// Disabled members are included. Disabling an upstream is reversible and a rule
// has to survive the round trip, a filter that quietly lost its entries while a
// member was switched off would come back permissive when the member came back.
// Duplicate ids collapse, because a group may list the same upstream twice, and
// an id with no row is skipped, so the slugs are a set in stored order.
//
// resolved is false when the target row itself is missing, its type is not one
// this build knows, or its membership could not be decoded. That is a different
// thing from a group with no members: there is nothing to compose against in
// either case, but an unresolvable target means the step cannot judge any of the
// entries, so it leaves them all and counts them.
//
// group says the target is a group rather than a single upstream, which the
// allow side needs. An unscoped allow entry admits nothing on a group (the
// proxy skips it rather than read it as "this name on every member") but on a
// single upstream every tool belongs to that upstream and a bare tool name is
// exactly right, so there is nothing to report about it.
type membership struct {
	slugs    []string
	index    map[string]bool
	resolved bool
	group    bool
}

func newMembership(upstreamIDs []string, slugByID map[string]string) membership {
	m := membership{index: map[string]bool{}, resolved: true, group: true}
	for _, id := range upstreamIDs {
		sl, ok := slugByID[id]
		if !ok || m.index[sl] {
			continue
		}
		m.index[sl] = true
		m.slugs = append(m.slugs, sl)
	}
	return m
}

func (m membership) has(slug string) bool { return m.index[slug] }

// rewriteColumn rewrites one of a virtual key's two list columns and returns the
// text to store. A column whose JSON does not decode comes back exactly as it
// was found: replacing an operator's unreadable denylist with no denylist at all
// is precisely the fail-open this step exists to close, so the bytes stay and
// the summary counts one entry left.
func (s *SQLStore) rewriteColumn(stored string, m membership, deny bool) (string, bool) {
	entries, ok := decodeJSONStrings(stored)
	if !ok {
		s.lastMigration.ToolEntriesLeft++
		return stored, false
	}
	out, changed := s.rewriteRule(entries, m, deny, false)
	if !changed {
		return stored, false
	}
	return jsonBytes(out), true
}

// rewriteRule maps one stored rule list onto the identity grammar and reports
// whether anything was added. prefixes says the list is a tool_filter's
// prefixes, the one list where an entry ending at the separator means something
// ("docs__" is every tool on docs) rather than naming a tool with no name.
//
// The table, entry by entry. head and scoped come from models.SplitEntry, the
// one definition of the split, so an entry beginning with the separator is an
// unscoped bare name and not a scoped entry on a member called "":
//
//	unclean (whitespace, control, U+FFFD)      leave and count: it equals no tool
//	                                           name today and would equal none
//	                                           scoped either. A group's filter
//	                                           has been validated since PORM-19,
//	                                           so this row is live only for a
//	                                           key's lists, which nothing has
//	                                           ever validated.
//	scoped, head is a member                   leave: already an identity.
//	scoped, head is not a member               deny: keep it and add {s}__{e} for
//	                                           every member s, because the entry
//	                                           may be a tool whose own
//	                                           name carries the separator, an
//	                                           upstream that is itself a proxy
//	                                           advertises "mcp__fetch".
//	unscoped, equal to s+"_"+rest for member s deny: keep it and add {s}__{rest}
//	                                           for each such s. That is the old
//	                                           aggregate spelling, where one
//	                                           underscore joined slug and name.
//	                                           Both readings are added when both
//	                                           fit, since which one was meant is
//	                                           exactly what the one-underscore
//	                                           scheme could not record.
//	unscoped otherwise                         leave: a bare tool name still
//	                                           names that tool on every member.
//
// The allow side takes none of the deny column: every entry is left exactly as
// it stands, because expanding one would widen an authorization list during an
// upgrade. An entry is COUNTED only when it admits nothing as it stands, which
// is not the same question on the two kinds of target. A scoped entry whose head
// is not a member admits nothing anywhere, so it is counted on both. An unscoped
// entry is counted only on a group, where the proxy skips it; on a single
// upstream a bare tool name names a tool on that upstream, keeps working exactly
// as it always did, and there is nothing for an operator to fix.
func (s *SQLStore) rewriteRule(entries []string, m membership, deny, prefixes bool) ([]string, bool) {
	out, changed := entries, false
	// add is the fixed point: a form already in the list is not added again, so
	// a second run over this function's own output writes nothing.
	add := func(e string) bool {
		for _, x := range out {
			if x == e {
				return false
			}
		}
		if !changed {
			out = append([]string(nil), out...) // entries belongs to the caller
			changed = true
		}
		out = append(out, e)
		return true
	}
	for _, e := range entries {
		if !m.resolved {
			// No member set to compose against: the target row has gone, or its
			// type is not one this build knows. Leaving the entry keeps a deny
			// denying; dropping it would delete a rule because a row somewhere
			// else was deleted.
			s.lastMigration.ToolEntriesLeft++
			continue
		}
		if !models.CleanToolEntry(e) {
			// The text rule only, not models.ValidateToolList: that validator
			// judges an entry an operator is writing, and its errors name a
			// field and an index there is neither of here. It also judges the
			// shape, which this step must not, a prefixes entry ending at the
			// separator is legal and has to be rewritten like any other.
			s.lastMigration.ToolEntriesLeft++
			continue
		}
		head, _, scoped := models.SplitEntry(e)
		if !deny {
			if scoped && !m.has(head) || !scoped && m.group {
				s.lastMigration.ToolEntriesLeft++
			}
			continue
		}
		if scoped && m.has(head) {
			continue
		}
		added := false
		for _, sl := range m.slugs {
			if scoped {
				added = add(sl+models.ToolSeparator+e) || added
				continue
			}
			rest, ok := strings.CutPrefix(e, sl+"_")
			if !ok {
				continue
			}
			if rest == "" && !prefixes {
				// Nothing after the separator names no tool in a list matched
				// for equality, and models.ValidateToolFilterWrite refuses one,
				// so this step must not write one either.
				continue
			}
			added = add(sl+models.ToolSeparator+rest) || added
		}
		if added {
			s.lastMigration.ToolEntriesRewritten++
		}
	}
	return out, changed
}

// migrateUpstreamTestColumns is migration step 4: two columns holding the
// outcome of the last deliberate connection test, when it ran and whether it
// passed. Nullable with no default, because NULL means "never tested" and that
// is what every existing row is. Nothing is backfilled and nothing is
// contacted: a migration must not invent a result by dialling an upstream with
// a stored credential while nobody is watching (PORM-114 owns background
// probing). No index: nothing filters or sorts on either column.
//
// Idempotent, as migrateStep's advisory-lock comment requires: SQLite has no
// ADD COLUMN IF NOT EXISTS, so each column is gated on the columnExists probe
// step 1 uses; a fresh database already has both from migrateBase. The two
// type strings must match migrateBase byte for byte (no NULL, no DEFAULT) or
// TestFreshAndMigratedSchemasMatch fails, which is the test that exists to
// catch exactly this.
//
// NOTE: only SQLite is exercised by this package's tests; there is no Postgres
// server in the build environment. On Postgres the same DDL is a catalog-only
// ADD COLUMN, and columnExists reads information_schema.
func (s *SQLStore) migrateUpstreamTestColumns(tx *sql.Tx) error {
	for _, col := range []struct{ name, ddl string }{
		{"last_test_at", `ALTER TABLE upstreams ADD COLUMN last_test_at TEXT`},
		{"last_test_ok", `ALTER TABLE upstreams ADD COLUMN last_test_ok INTEGER`},
	} {
		has, err := s.columnExists(tx, "upstreams", col.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := tx.Exec(col.ddl); err != nil {
			return err
		}
	}
	return nil
}

// dropVirtualKeysLookupIndex rides along in step 4 (PORM-68). It is a separate
// call rather than a line inside migrateUpstreamTestColumns because it has
// nothing to do with the test columns: a step is a version, not a subject, and
// the two are dropped or kept independently at review.
//
// virtual_keys.key_lookup is declared NOT NULL UNIQUE, so the constraint's own
// index already answers GetVirtualKeyByLookup, measured on modernc SQLite:
// SEARCH virtual_keys USING INDEX sqlite_autoindex_virtual_keys_2
// (key_lookup=?), before and after this drop. The explicit index was a second
// index over the same single column: no read used it and every write to
// virtual_keys maintained it. The matching CREATE INDEX is gone from
// migrateBase and from step 2's rename, or the next boot would put it straight
// back.
//
// IF EXISTS, so the step is idempotent for the replica that re-runs it and for
// a fresh database that never had it. Never CONCURRENTLY: that is forbidden
// inside a transaction, and every statement in a step runs on tx.
func (s *SQLStore) dropVirtualKeysLookupIndex(tx *sql.Tx) error {
	_, err := tx.Exec(`DROP INDEX IF EXISTS virtual_keys_lookup`)
	return err
}

func (s *SQLStore) Close() error { return s.db.Close() }

func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

func parseTimePtr(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil
	}
	return &t
}

// boolPtr is nullBool's read direction: a NULL column is "no answer yet", and
// any other value is the flag that was recorded.
func boolPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 != 0
	return &b
}

func nullInt(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

// nullBool writes a tri-state flag the way the schema holds it: NULL for no
// answer yet, 1 or 0 for one that was recorded, an INTEGER on both drivers,
// see enabled.
func nullBool(p *bool) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(boolToInt(*p)), Valid: true}
}

func nullTime(p *time.Time) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: fmtTime(*p), Valid: true}
}

func jsonBytes(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case json.RawMessage:
		if len(t) == 0 {
			return ""
		}
		return string(t)
	case []string:
		b, _ := json.Marshal(t)
		return string(b)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func decodeStrings(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// decodeJSONStrings decodes a stored JSON array of strings and reports whether
// it could be read at all. It sits beside decodeStrings because that one
// answers nil for "", for "null" and for "this is not a list" alike, and a
// caller that has to fail closed (step 3, which must never drop a rule it
// could not read) needs the third case separated from the first two.
func decodeJSONStrings(raw string) ([]string, bool) {
	if raw == "" {
		return nil, true
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, false
	}
	return out, true
}

func rawOrNil(s string) json.RawMessage {
	if s == "" {
		return nil
	}
	return json.RawMessage(s)
}

// --- Upstreams ---

// upstreamCols is the one place the column list lives. A fresh CREATE TABLE puts
// slug at ordinal 2 and an ALTER-migrated table puts it last, so the two schemas
// differ in column ORDER: never introduce SELECT * against upstreams.
const upstreamCols = `id, name, slug, description, url, transport, auth_type, auth_config, enabled, created_at, updated_at, last_test_at, last_test_ok`

func (s *SQLStore) CreateUpstream(ctx context.Context, u *models.Upstream) error {
	// The unique index permits exactly one slug-less row; this takes it to zero,
	// so a slug-less upstream fails on the FIRST insert rather than the second.
	// Unreachable over HTTP (the API always supplies or derives one) so it maps
	// to a 500 via storeError's default: reaching it is a programming error.
	if u.Slug == "" {
		return errors.New("upstream slug is required")
	}
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO upstreams (`+upstreamCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		u.ID, u.Name, u.Slug, u.Description, u.URL, u.Transport, u.AuthType, string(u.AuthConfig),
		boolToInt(u.Enabled), fmtTime(u.CreatedAt), fmtTime(u.UpdatedAt),
		nullTime(u.LastTestAt), nullBool(u.LastTestOK),
	)
	return conflictErr(err)
}

func (s *SQLStore) GetUpstream(ctx context.Context, id string) (*models.Upstream, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+upstreamCols+` FROM upstreams WHERE id = ?`), id)
	u, err := scanUpstream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUpstreamBySlug resolves an upstream by its stable slug. It serves the
// management API's derived-slug availability walk (createUpstreamDerivedSlug in
// internal/api/upstreams.go); the proxy deliberately does not use it.
//
// The /{virtual_key_id}/{slug}/mcp route resolves the slug among the virtual
// key's own already-loaded enabled members instead, so a slug that exists
// elsewhere in the deployment costs exactly as much as one that exists nowhere,
// and an unknown slug, a slug outside this key's target, a disabled upstream and
// a member removed from the group all fall out of one walk with one answer. The
// requirement that route carries (an identical response in every one of those
// cases, so that one valid virtual key cannot enumerate every slug in the
// deployment) is therefore met structurally rather than by care at the call
// site, and a lookup through here would reintroduce it. Slugs are meaningful
// strings and disclose what an organisation connects to.
//
// No lookup may ever fall back between id and slug: ValidSlug rejects
// UUID-shaped slugs precisely so the two domains stay disjoint.
func (s *SQLStore) GetUpstreamBySlug(ctx context.Context, slug string) (*models.Upstream, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+upstreamCols+` FROM upstreams WHERE slug = ?`), slug)
	u, err := scanUpstream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *SQLStore) ListUpstreams(ctx context.Context) ([]models.Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+upstreamCols+` FROM upstreams ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Upstream
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	if out == nil {
		out = []models.Upstream{}
	}
	return out, rows.Err()
}

// Named arguments for UpdateUpstream's two flags, so a call site reads as
// what it does rather than as `false, true` (the savedUpstream/unsavedPayload
// convention in internal/api/discover.go).
const (
	ResetTest = true
	KeepTest  = false
	WriteAuth = true
	KeepAuth  = false
)

// UpdateUpstream writes every mutable field except slug (immutable after
// create; deliberately absent from SET, so the store can never rewrite one
// even if a caller hands it a changed value) and, unless writeAuth, except
// auth_config.
//
// The two flags are independent and both shape the one statement, there is no
// second statement for a crash to land between (there is no transaction here).
// resetTest appends `last_test_at=NULL, last_test_ok=NULL`: literal NULLs and
// no argument, passed when url, transport, auth_type or auth_config changed,
// so a dot never vouches for a configuration nobody tested. The test columns
// are never written FROM the struct, which is what keeps a row read before a
// concurrent RecordUpstreamTest from writing a stale result back. writeAuth
// adds `auth_config=?` AND its argument, passed only when the request carried
// a credential (PORM-52): a PATCH that did not is otherwise a writer of the
// ciphertext it happened to read, and one that read before `porymcp rekey`
// committed would put an old-key value back. The SET fragments and the
// argument list are built together in one pass so a column and its value
// cannot slip out of position; resetTest can be true while writeAuth is false
// (only url, transport or auth_type changed).
func (s *SQLStore) UpdateUpstream(ctx context.Context, u *models.Upstream, resetTest, writeAuth bool) error {
	set := []string{"name=?", "description=?", "url=?", "transport=?", "auth_type=?", "enabled=?", "updated_at=?"}
	args := []any{u.Name, u.Description, u.URL, u.Transport, u.AuthType, boolToInt(u.Enabled), fmtTime(u.UpdatedAt)}
	if writeAuth {
		set = append(set, "auth_config=?")
		args = append(args, string(u.AuthConfig))
	}
	if resetTest {
		set = append(set, "last_test_at=NULL", "last_test_ok=NULL")
	}
	args = append(args, u.ID)
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE upstreams SET `+strings.Join(set, ", ")+` WHERE id=?`), args...)
	if err != nil {
		// unreachable while slug is the only unique column and is not in SET;
		// kept so a future unique column maps to 409 without a code change
		return conflictErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordUpstreamTest stamps one row with the outcome of one deliberate
// connection test. One statement, its own method rather than two more fields on
// UpdateUpstream: the two writers race (an operator can save an edit while a
// ten-second handshake is in flight), and a full-row UPDATE built from a row
// read before the handshake would resurrect the pre-edit url and credential.
//
// seen is the row's updated_at as read before the handshake; the UPDATE is
// conditioned on it, so a result for a configuration edited in the meantime is
// dropped rather than vouching for settings it never tested. The compare is on
// the canonical string fmtTime(seen): every writer of updated_at is fmtTime and
// the column is TEXT on both drivers, so the reformat reproduces the stored
// bytes exactly. A row whose updated_at came from outside PoryMCP (a +00:00
// offset, trailing zeros in the fraction) can never match and records nothing,
// fail closed, the same way steps 1 and 3 treat hand-edited rows.
//
// updated_at is deliberately not bumped: a test is not an edit, and updated_at
// answers "when did a person last edit this?", the rule migrateToolIdentities
// states. Returns ErrNotFound when no row matched, deleted, or edited since
// seen. Between two overlapping tests of one unchanged row the later write
// wins, deliberately.
func (s *SQLStore) RecordUpstreamTest(ctx context.Context, id string, at time.Time, ok bool, seen time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE upstreams SET last_test_at=?, last_test_ok=?
		WHERE id=? AND updated_at=?`),
		fmtTime(at), boolToInt(ok), id, fmtTime(seen),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) DeleteUpstream(ctx context.Context, id string) error {
	groups, err := s.ListGroups(ctx)
	if err != nil {
		return err
	}
	for _, g := range groups {
		for _, uid := range g.UpstreamIDs {
			if uid == id {
				return ErrInUse
			}
		}
	}
	keys, err := s.ListVirtualKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.TargetType == models.TargetUpstream && k.TargetID == id {
			return ErrInUse
		}
	}
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM upstreams WHERE id=?`), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUpstream(row rowScanner) (*models.Upstream, error) {
	var u models.Upstream
	var auth string
	var enabled int
	var created, updated string
	var lastTestAt sql.NullString
	var lastTestOK sql.NullInt64
	if err := row.Scan(&u.ID, &u.Name, &u.Slug, &u.Description, &u.URL, &u.Transport, &u.AuthType, &auth, &enabled, &created, &updated, &lastTestAt, &lastTestOK); err != nil {
		return nil, err
	}
	u.AuthConfig = rawOrNil(auth)
	u.Enabled = enabled != 0
	u.LastTestAt = parseTimePtr(lastTestAt)
	u.LastTestOK = boolPtr(lastTestOK)
	var err error
	u.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	u.UpdatedAt, err = parseTime(updated)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// --- Groups ---

func (s *SQLStore) CreateGroup(ctx context.Context, g *models.Group) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO groups (id, name, description, upstream_ids, tool_filter, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		g.ID, g.Name, g.Description, jsonBytes(g.UpstreamIDs), string(g.ToolFilter),
		fmtTime(g.CreatedAt), fmtTime(g.UpdatedAt),
	)
	return err
}

func (s *SQLStore) GetGroup(ctx context.Context, id string) (*models.Group, error) {
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, name, description, upstream_ids, tool_filter, created_at, updated_at
		FROM groups WHERE id=?`), id)
	g, err := scanGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

func (s *SQLStore) ListGroups(ctx context.Context) ([]models.Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, upstream_ids, tool_filter, created_at, updated_at
		FROM groups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	if out == nil {
		out = []models.Group{}
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateGroup(ctx context.Context, g *models.Group) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE groups SET name=?, description=?, upstream_ids=?, tool_filter=?, updated_at=?
		WHERE id=?`),
		g.Name, g.Description, jsonBytes(g.UpstreamIDs), string(g.ToolFilter), fmtTime(g.UpdatedAt), g.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) DeleteGroup(ctx context.Context, id string) error {
	keys, err := s.ListVirtualKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.TargetType == models.TargetGroup && k.TargetID == id {
			return ErrInUse
		}
	}
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM groups WHERE id=?`), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanGroup(row rowScanner) (*models.Group, error) {
	var g models.Group
	var ids, filter, created, updated string
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &ids, &filter, &created, &updated); err != nil {
		return nil, err
	}
	g.UpstreamIDs = decodeStrings(ids)
	if g.UpstreamIDs == nil {
		g.UpstreamIDs = []string{}
	}
	g.ToolFilter = rawOrNil(filter)
	var err error
	g.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	g.UpdatedAt, err = parseTime(updated)
	return &g, err
}

// --- Virtual keys ---

func (s *SQLStore) CreateVirtualKey(ctx context.Context, a *models.VirtualKey) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO virtual_keys (
			id, name, key_hash, key_lookup, key_prefix, target_type, target_id,
			rate_limit, expires_at, tool_allowlist, tool_denylist, created_at,
			last_used_at, revoked_at, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.ID, a.Name, a.KeyHash, a.KeyLookup, a.KeyPrefix, a.TargetType, a.TargetID,
		nullInt(a.RateLimit), nullTime(a.ExpiresAt), jsonBytes(a.ToolAllowlist), jsonBytes(a.ToolDenylist),
		fmtTime(a.CreatedAt), nullTime(a.LastUsedAt), nullTime(a.RevokedAt), string(a.Metadata),
	)
	return err
}

func (s *SQLStore) GetVirtualKey(ctx context.Context, id string) (*models.VirtualKey, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+virtualKeyCols+` FROM virtual_keys WHERE id=?`), id)
	a, err := scanVirtualKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) GetVirtualKeyByLookup(ctx context.Context, lookup string) (*models.VirtualKey, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+virtualKeyCols+` FROM virtual_keys WHERE key_lookup=?`), lookup)
	a, err := scanVirtualKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) ListVirtualKeys(ctx context.Context) ([]models.VirtualKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+virtualKeyCols+` FROM virtual_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.VirtualKey
	for rows.Next() {
		a, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	if out == nil {
		out = []models.VirtualKey{}
	}
	return out, rows.Err()
}

// UpdateVirtualKey writes a back to its row. Every column is written except the
// two entry lists of a key whose lists did not decode, which are left exactly as
// they are found.
//
// The reason is that scanVirtualKey answers nil for both lists alongside
// ListsMalformed, because there is no list to answer: an unreadable column is
// not a rule anyone can enforce. Writing those nils back would store "null" in
// both columns (no allowlist and no denylist) and "null" decodes cleanly, so the
// flag would be gone on the next read and the key would be fully permissive.
// That would hand a rename, a rotation or a revocation the power to turn a key
// the proxy blocks on every call into one with no policy at all, which is the
// exact opposite of what an operator reaching for any of the three means. The
// corruption stays in place, the key stays blocked, and the evidence survives
// for whoever has to work out what the rule was meant to say.
//
// Replacing the two columns is therefore something only a caller that has new
// text for BOTH of them can do, by clearing the flag first; internal/api's
// patch handler is the one place that happens.
func (s *SQLStore) UpdateVirtualKey(ctx context.Context, a *models.VirtualKey) error {
	set := `name=?, key_hash=?, key_lookup=?, key_prefix=?, target_type=?, target_id=?,
			rate_limit=?, expires_at=?, last_used_at=?, revoked_at=?, metadata=?`
	args := []any{
		a.Name, a.KeyHash, a.KeyLookup, a.KeyPrefix, a.TargetType, a.TargetID,
		nullInt(a.RateLimit), nullTime(a.ExpiresAt),
		nullTime(a.LastUsedAt), nullTime(a.RevokedAt), string(a.Metadata),
	}
	if !a.ListsMalformed {
		set += `, tool_allowlist=?, tool_denylist=?`
		args = append(args, jsonBytes(a.ToolAllowlist), jsonBytes(a.ToolDenylist))
	}
	args = append(args, a.ID)
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE virtual_keys SET `+set+` WHERE id=?`), args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) DeleteVirtualKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM virtual_keys WHERE id=?`), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) TouchVirtualKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE virtual_keys SET last_used_at=? WHERE id=?`), fmtTime(time.Now()), id)
	return err
}

const virtualKeyCols = `id, name, key_hash, key_lookup, key_prefix, target_type, target_id, rate_limit, expires_at, tool_allowlist, tool_denylist, created_at, last_used_at, revoked_at, metadata`

func scanVirtualKey(row rowScanner) (*models.VirtualKey, error) {
	var a models.VirtualKey
	var rate sql.NullInt64
	var expires, last, revoked sql.NullString
	var allow, deny, created, meta string
	if err := row.Scan(
		&a.ID, &a.Name, &a.KeyHash, &a.KeyLookup, &a.KeyPrefix, &a.TargetType, &a.TargetID,
		&rate, &expires, &allow, &deny, &created, &last, &revoked, &meta,
	); err != nil {
		return nil, err
	}
	if rate.Valid {
		v := int(rate.Int64)
		a.RateLimit = &v
	}
	a.ExpiresAt = parseTimePtr(expires)
	a.LastUsedAt = parseTimePtr(last)
	a.RevokedAt = parseTimePtr(revoked)
	allowList, allowOK := decodeJSONStrings(allow)
	denyList, denyOK := decodeJSONStrings(deny)
	a.ToolAllowlist, a.ToolDenylist = allowList, denyList
	// A column that does not decode is not "no list". The scan still succeeds,
	// because the proxy needs the row to authenticate the request and to write
	// an audit line about refusing it, but the key carries a flag that blocks
	// every call on it. decodeStrings answers nil for "", for "null" and for
	// "this is not a list" alike, which is what let an unreadable denylist read
	// as no denylist and leave the key permissive.
	a.ListsMalformed = !allowOK || !denyOK
	a.Metadata = rawOrNil(meta)
	var err error
	a.CreatedAt, err = parseTime(created)
	return &a, err
}

// --- Audit ---

func (s *SQLStore) InsertAuditLog(ctx context.Context, e *models.AuditLog) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO audit_logs (
			id, timestamp, virtual_key_id, virtual_key_name, method, tool_name, params, status,
			latency_ms, response_size_bytes, upstream_id, error_message, request_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, fmtTime(e.Timestamp), e.VirtualKeyID, e.VirtualKeyName, e.Method, e.ToolName, string(e.Params),
		e.Status, e.LatencyMS, e.ResponseSizeBytes, e.UpstreamID, e.ErrorMessage, e.RequestID,
	)
	return err
}

func (s *SQLStore) GetAuditLog(ctx context.Context, id string) (*models.AuditLog, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+logCols+` FROM audit_logs WHERE id=?`), id)
	e, err := scanLog(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *SQLStore) ListAuditLogs(ctx context.Context, f models.LogFilter) ([]models.AuditLog, string, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	var conds []string
	var args []any
	if f.VirtualKeyID != "" {
		conds = append(conds, "virtual_key_id = ?")
		args = append(args, f.VirtualKeyID)
	}
	if f.Method != "" {
		conds = append(conds, "method = ?")
		args = append(args, f.Method)
	}
	if f.Tool != "" {
		conds = append(conds, "tool_name = ?")
		args = append(args, f.Tool)
	}
	if f.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, f.Status)
	}
	if f.Since != nil {
		conds = append(conds, "timestamp >= ?")
		args = append(args, fmtTime(*f.Since))
	}
	if f.Until != nil {
		conds = append(conds, "timestamp <= ?")
		args = append(args, fmtTime(*f.Until))
	}
	if f.Cursor != "" {
		ts, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", ErrInvalidCursor
		}
		conds = append(conds, "(timestamp < ? OR (timestamp = ? AND id < ?))")
		args = append(args, fmtTime(ts), fmtTime(ts), id)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit+1)
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+logCols+` FROM audit_logs `+where+` ORDER BY timestamp DESC, id DESC LIMIT ?`), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []models.AuditLog
	for rows.Next() {
		e, err := scanLog(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var next string
	if len(out) > f.Limit {
		last := out[f.Limit-1]
		next = encodeCursor(last.Timestamp, last.ID)
		out = out[:f.Limit]
	}
	if out == nil {
		out = []models.AuditLog{}
	}
	return out, next, nil
}

const logCols = `id, timestamp, virtual_key_id, virtual_key_name, method, tool_name, params, status, latency_ms, response_size_bytes, upstream_id, error_message, request_id`

func scanLog(row rowScanner) (*models.AuditLog, error) {
	var e models.AuditLog
	var ts, params string
	if err := row.Scan(
		&e.ID, &ts, &e.VirtualKeyID, &e.VirtualKeyName, &e.Method, &e.ToolName, &params, &e.Status,
		&e.LatencyMS, &e.ResponseSizeBytes, &e.UpstreamID, &e.ErrorMessage, &e.RequestID,
	); err != nil {
		return nil, err
	}
	var err error
	e.Timestamp, err = parseTime(ts)
	e.Params = rawOrNil(params)
	return &e, err
}

func encodeCursor(ts time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmtTime(ts) + "|" + id))
}

func decodeCursor(cur string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(cur)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", ErrInvalidCursor
	}
	ts, err := parseTime(parts[0])
	return ts, parts[1], err
}

// --- Admin events ---

const adminEventCols = `id, timestamp, actor, action, resource_type, resource_id, resource_name, details, request_id, remote_addr`

// sinceBound formats a lower bound for a TEXT timestamp column, compared in
// byte order. fmtTime writes RFC3339Nano, which strips trailing zeros, so
// "...00Z" sorts after "...00.5Z" and a bound written the same way would drop
// rows inside its own second. A fixed-width bound is exact for a whole-second
// since and never worse than fmtTime; a since that itself carries a fraction
// can still include a stored whole-second row from the same second, because
// that row has no separator to compare against. Only the bound is formatted
// this way; stored values and cursors keep fmtTime.
func sinceBound(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}

// InsertAdminEvent writes one management-plane event. Details is stored as
// JSON text, {} when empty, so a row never reads back as null.
func (s *SQLStore) InsertAdminEvent(ctx context.Context, e *models.AdminEvent) error {
	details := string(e.Details)
	if details == "" {
		details = "{}"
	}
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO admin_events (
			id, timestamp, actor, action, resource_type, resource_id, resource_name, details, request_id, remote_addr
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, fmtTime(e.Timestamp), e.Actor, e.Action, e.ResourceType, e.ResourceID, e.ResourceName,
		details, e.RequestID, e.RemoteAddr,
	)
	return err
}

// ListAdminEvents returns the newest page first, with the cursor for the next
// page or "" on the last one. It is ListAuditLogs with two filters.
func (s *SQLStore) ListAdminEvents(ctx context.Context, f models.AdminEventFilter) ([]models.AdminEvent, string, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	var conds []string
	var args []any
	if f.ResourceType != "" {
		conds = append(conds, "resource_type = ?")
		args = append(args, f.ResourceType)
	}
	if f.Since != nil {
		conds = append(conds, "timestamp >= ?")
		args = append(args, sinceBound(*f.Since))
	}
	if f.Cursor != "" {
		ts, id, err := decodeCursor(f.Cursor)
		// A cursor whose timestamp half is empty decodes to the zero time
		// without an error (parseTime accepts ""), and a zero bound would
		// answer an empty page. On an audit endpoint an empty answer reads as
		// "nothing happened", so it is refused like any other malformed cursor.
		if err != nil || ts.IsZero() {
			return nil, "", ErrInvalidCursor
		}
		conds = append(conds, "(timestamp < ? OR (timestamp = ? AND id < ?))")
		args = append(args, fmtTime(ts), fmtTime(ts), id)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit+1)
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+adminEventCols+` FROM admin_events `+where+` ORDER BY timestamp DESC, id DESC LIMIT ?`), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []models.AdminEvent
	for rows.Next() {
		e, err := scanAdminEvent(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var next string
	if len(out) > f.Limit {
		last := out[f.Limit-1]
		next = encodeCursor(last.Timestamp, last.ID)
		out = out[:f.Limit]
	}
	if out == nil {
		out = []models.AdminEvent{}
	}
	return out, next, nil
}

func scanAdminEvent(row rowScanner) (*models.AdminEvent, error) {
	var e models.AdminEvent
	var ts, details string
	if err := row.Scan(
		&e.ID, &ts, &e.Actor, &e.Action, &e.ResourceType, &e.ResourceID, &e.ResourceName,
		&details, &e.RequestID, &e.RemoteAddr,
	); err != nil {
		return nil, err
	}
	var err error
	e.Timestamp, err = parseTime(ts)
	e.Details = rawOrNil(details)
	if e.Details == nil {
		// A row written outside the API (an export, a hand edit) may hold ''.
		// The API promises details is always an object, never null.
		e.Details = json.RawMessage("{}")
	}
	return &e, err
}

func (s *SQLStore) Stats(ctx context.Context) (*models.Stats, error) {
	st := &models.Stats{}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM virtual_keys`).Scan(&st.TotalVirtualKeys)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM virtual_keys WHERE revoked_at IS NULL`).Scan(&st.ActiveVirtualKeys)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstreams`).Scan(&st.Upstreams)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups`).Scan(&st.Groups)

	dayAgo := fmtTime(time.Now().Add(-24 * time.Hour))
	weekAgo := fmtTime(time.Now().Add(-7 * 24 * time.Hour))
	_ = s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?`), dayAgo).Scan(&st.CallsToday)
	_ = s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ? AND status = 'error'`), dayAgo).Scan(&st.ErrorsToday)
	_ = s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ? AND status = 'blocked'`), dayAgo).Scan(&st.BlockedToday)
	_ = s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?`), weekAgo).Scan(&st.CallsLast7Days)
	if st.CallsToday > 0 {
		st.ErrorRate = float64(st.ErrorsToday) / float64(st.CallsToday)
	}
	return st, nil
}
