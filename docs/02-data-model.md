# Core data model

## Upstream
Represents a real MCP server.

- `id` (uuid)
- `name` (string)
- `slug` (string): stable, unique, URL- and tool-name-safe identifier
  (`[a-z0-9]`, `_` and `-` inside, 1 to 40 chars, no repeated separator, not
  UUID-shaped; and, on create, not `mcp`/`api`/`health`/`metrics`). Derived from
  the name on create when omitted and de-duplicated as `github`, `github-2`, …;
  renaming an upstream never changes it, and it is **immutable after create**.
  Half of every tool identity (`{slug}__{tool}`, see `tool_filter` below), and
  the path segment of a group member's own proxy endpoint
  (`/{virtual_key_id}/{slug}/mcp`).
- `description` (optional; cleared with `""` or `null` on `PATCH`)
- `url` (string): the real MCP endpoint, and it must be the **final** one: the
  proxy presents this upstream's credential to this URL and never to a host the
  upstream names in a redirect, so a `3xx` answer is a failed call (`502` to the
  client, and an `error` audit row reading `upstream redirected to <host>`)
  rather than a hop to follow. Prefer `https://` and the exact path the server
  serves, trailing slash included. It must be an absolute `http` or `https` URL
  with a host and no fragment (`mcpclient.CheckTarget`, the same check
  discovery applies before it opens a socket), so a stored value is one PoryMCP
  can dial; anything else is `400`. Whether that host *should* be
  dialled (loopback, link-local, cloud metadata) is not checked yet (PORM-79)
- `transport`: `"streamable-http"` | `"sse"`
- `auth_type`: `"none"` | `"bearer"` | `"header"` | `"api_key"` | `"custom"`
- `auth_config` (JSON): e.g. `{"header": "Authorization", "value": "Bearer sk-..."}`
- `enabled` (bool)
- `last_test_at` (nullable): when the last deliberate connection test ran. A
  press of **Tools** or **Refresh** in the dashboard is that test
  (`POST /upstreams/{id}/discover`), and the field is `null` until the first one.
  `PATCH` cannot set it, and a `PATCH` that changes `url`, `transport` or
  `auth_type`, or carries any `auth_config` other than an explicit `null`,
  resets it to `null`, so a recorded result never vouches for a connection
  nobody has tried. A test is not an edit: `updated_at` does not move when one
  is recorded.
- `last_test_ok` (nullable): whether that run completed the handshake **and**
  the catalogue. Written in the same statement as `last_test_at`, reset with it,
  and `null` on the same terms. A refused transport, and a stored credential
  that cannot be decrypted after a rotated `ENCRYPTION_KEY`, both record
  `false`: PoryMCP could not use the upstream, which is what the field answers
  (the cause of the second is `auth_status` on the same row, see `docs/03-api.md`).
  Nothing the upstream said is kept beside it: no catalogue (PORM-113), no tool
  count, no error sentence.
- `created_at`, `updated_at`

Real credentials are stored encrypted at rest, in `auth_config`, as
`v1:<fingerprint>:<base64>`, AES-256-GCM under `ENCRYPTION_KEY` with the
sealing key's fingerprint as additional authenticated data. Values written by
builds before PORM-52 are bare base64 with no AAD and are read for ever;
`porymcp rekey` rewrites them. The column is written by `POST /upstreams`, by a
`PATCH` that carries `auth_config` (a `PATCH` that does not leaves the column
out of its statement, so an edit that raced a rekey cannot put an old-key value
back), and by `rekey`, and by nothing else. `auth_type: none` rows may hold a blob too
(the dashboard sends `{}` on create); nothing reads it.

## Group
A named collection of Upstreams (for multi-MCP agents).  
One Group = one “shape” that PoryMCP can take.

- `id` (uuid)
- `name` (string)
- `description` (optional; cleared with `""` or `null` on `PATCH`)
- `upstream_ids` ([]uuid)
- `tool_filter` (optional): `{"mode":"allow"|"deny","tools":[…],"prefixes":[…]}`.
  `deny` rejects a tool named in `tools` or whose name starts with one of
  `prefixes`; `allow` admits only those and rejects everything else. Omitted or
  `null` means the group has no filter.

  Every entry is written against one **tool identity**: the member's slug and
  the tool's own name, joined by two underscores as `{upstream_slug}__{tool}`.
  That identity is the same on every path a key over this group reaches (the
  aggregate endpoint and each per-member endpoint), so one entry is enforced
  everywhere, and a member joining, leaving or failing to answer cannot change
  what it means. It is the same identity a virtual key's own allow/deny lists
  name, on a single-upstream target too.

  An entry carrying `__` with something before it is **scoped**: it names one
  member, and the rest of the entry is matched against that member's own tool
  names. An entry with no `__`, or one that begins with it, is **unscoped** and
  is matched against the tool's own name on every member. `__search` is
  unscoped rather than scoped to a member called `""`, because an upstream is
  free to advertise a tool really called `__search`.

  The two directions are deliberately not symmetric. **A deny is a rule on the
  zone**: left unscoped it follows membership, so a deny of `delete_repo` covers
  a server added to the group tomorrow. **An allow is a rule on a host, and must
  name it**: an unscoped entry under `"mode":"allow"` is rejected with `400` on
  write, skipped on read (it admits nothing) and named in a warning at
  startup. Reading it as "this name on every member" would widen the rule to the
  whole group, the opposite of what an operator narrowing access to one member's
  tool meant. A one-member group is a group, so bare allow entries are rejected
  there too.

  A `tools` entry is matched for **equality**; a `prefixes` entry with a
  string-prefix test, and both against the tool's **own** name, never against
  the composed one. So write `delete_`, or `github__delete_` to scope it to one
  member, never the advertised aggregate string. A scoped `prefixes` entry may
  end at the separator: `github__` is every tool on `github`. `github_`, with
  one underscore, is not a scope at all; it is a name shape, and matches any
  tool whose own name starts `github_` on any member.

  Read-side validation, applied every time the proxy loads the filter: `mode`
  must be exactly `allow` or `deny` and is required whenever `tools` or
  `prefixes` has an entry, no entry may be empty or hold whitespace, a control
  character or U+FFFD, `allow` needs at least one entry, and unknown keys are
  rejected. A stored filter that fails those rules blocks every call on the
  group until it is fixed (`docs/07-security.md`). Write-side validation adds
  the identity rules, and only there: a scoped entry's head must be a
  syntactically valid slug, a scoped `tools` entry must name a tool after the
  separator, and every entry of an `allow` filter must be scoped. They are
  write-only on purpose: enforcing them on read would take a group written
  before the grammar existed offline instead of correcting the operator who is
  standing there. Membership is not checked at all, since a group's members
  change. Applied after the virtual key's own lists, so it can only narrow them,
  and enforced on `tools/list` **and** `tools/call`, on the group's aggregate
  endpoint and on each of its per-member endpoints alike.
- `created_at`, `updated_at`

## Virtual Key
Formerly called an Agent.

The PoryMCP entity an AI agent authenticates with. A **virtual key** is this
record: key prefix, target, rate limit, expiry, allow/deny lists, audit trail.
An **agent** or **client** is the consumer that holds one (Claude Code, Cursor,
a bot); PoryMCP does not store agents.

- `id` (uuid)
- `name` / label (e.g. "cursor-dev", "research-agent")
- `key_hash` (hashed: never store plaintext after creation)
- `key_prefix` (for display, e.g. "pory_7f3a...")
- `target_type`: `"upstream"` | `"group"`
- `target_id` (uuid)
- `endpoints` (read-only): not stored. Computed on every response from the
  target: one entry `{upstream_id, slug, name, url}` per **enabled** group
  member, in `upstream_ids` order, whose `url` is
  `{PUBLIC_URL}/{virtual_key_id}/{slug}/mcp`; or, for a single-upstream target,
  exactly one entry whose `url` is `proxy_url` itself. Every entry is a URL that
  speaks exactly one upstream, 1:1. A member that is disabled or removed from
  the group has no entry and its URL answers `404`; `endpoints` is `[]` when
  nothing is reachable, and is unchanged by revocation or expiry. See
  `docs/03-api.md`.
- `rate_limit` (optional: requests per minute; `null`, omitted or `0` means
  unlimited; removed with `null` on `PATCH`)
- `expires_at` (optional; removed with `null` on `PATCH`, after which the key is
  active again)
- `tool_allowlist` / `tool_denylist` (optional): per-key overrides applied to
  every target. Precedence is **key denylist, then key allowlist, then group
  `tool_filter`**: a name in the denylist is rejected outright, a non-empty
  allowlist rejects everything not in it, and whatever survives must still pass
  the group filter. Each list narrows, never widens. Both match byte-exactly and
  are enforced on `tools/list` and `tools/call`, on the aggregate, per-member and
  single-upstream paths alike.
  Both use the same identity and the same scoped/unscoped grammar as a group's
  `tool_filter.tools` (above), matched for equality: an entry names
  `{upstream_slug}__{tool}` on **every** path. On the aggregate endpoint that is
  also the name the client sees; on a per-member endpoint and under a
  single-upstream key the client sees the upstream's bare name and the proxy
  composes the slug before matching.
  The allow-side rule follows the key's target. On a **group** target an unscoped
  `tool_allowlist` entry is refused with `400` on write and admits nothing on
  read; on a **single-upstream** target every tool belongs to that one upstream,
  so a bare name is exactly right and is accepted. Moving a key across that line
  is checked in both directions, on the allow side only: retargeting onto a group
  while the allowlist holds unscoped entries, or onto an upstream while it holds
  entries scoped to a different slug, answers `400` naming the stranded entries
  until the list is rewritten or a new one is sent with the same request. The
  denylist is never refused for a move: an operator who writes "never
  `delete_repo`, anywhere" wants precisely the unscoped entry that survives one.
  On the other methods that carry a `params.name` (`prompts/get`,
  `resources/read`) both lists match the name **whole**: no splitting, no slug,
  no scoping, and nothing skipped for being unscoped. An entry `docs__search`
  blocks a prompt named `docs__search`, a bare entry blocks the prompt
  of that name on every path, and a group key's `tool_allowlist` still admits the
  prompts it names. One entry can therefore mean two different things depending
  on the method; PORM-6 owns fixing that.
- `created_at`, `last_used_at`, `revoked_at` (nullable)
- `metadata` (JSON: free-form tags)

On creation/rotation the plaintext key is returned **once**.

## AuditLog
- `id`
- `timestamp`
- `virtual_key_id`
- `virtual_key_name` (denormalized)
- `method` (tools/list, tools/call, resources/list, initialize, etc.): a
  request refused before its body could be parsed (a batch, an unparseable
  body) records the HTTP verb here instead, because no method was read
- `tool_name` (if applicable)
- `params` (JSON, redacted; above 4 KiB it is replaced by
  `{"truncated":true,"bytes":N}`)
- `status`: success | error | blocked (`blocked` = refused by tool policy;
  no upstream was contacted. `error` covers both an upstream that answered badly
  and one the proxy refused to keep talking to: a `3xx` answer, which is never
  followed)
- `latency_ms`
- `response_size_bytes` (optional)
- `upstream_id` (which real server handled it): empty when none was
  contacted. A blocked call on the **aggregate** group endpoint records no
  upstream, since the block happens before a member is chosen; a blocked call
  on a single-upstream virtual key or on a per-member endpoint records the
  upstream it targeted, which is known from the target or the URL without
  contacting anything
- `error_message` (if any): the operator-facing detail. On a `blocked` row it
  names the rule that rejected the call; on an `error` row from a forwarded
  call it is the failure the proxy saw, while the client was told only
  `upstream request failed`. An upstream that answered a redirect reads
  `upstream redirected to <host>` (the redirect target's host alone, never
  the full `Location`, which can carry a query string), and that redirect
  message is bounded at 256 bytes. The field can hold upstream-controlled
  text, and is rendered as text, never HTML (`docs/06-ui.md`)
- `request_id` (for correlation)

## AdminEvent
One row per successful state-changing management API call (PORM-54): the
management-plane half of the audit trail, beside `AuditLog`, the proxy half.
- `id`
- `timestamp`
- `actor`: the literal `admin` until dashboard users land (PORM-127)
- `action`: `{resource_type}.{verb}`, one of `upstream.create|update|delete`,
  `group.create|update|delete`,
  `virtual_key.create|update|rotate|revoke|delete`
- `resource_type`: `upstream` | `group` | `virtual_key`
- `resource_id`
- `resource_name`: the name as it stood when the change landed, read before a
  delete; cleaned of control characters and cut at 256 bytes on the row
- `details` (JSON, always an object, `{}` when empty): a closed set of keys
  the server composes, `fields`, `cleared`, `slug`, `auth_type`,
  `auth_changed`, `upstream_count`, `tool_filter_set`, `target_type`,
  `target_id`, `key_prefix`; never the request body, a credential, a
  ciphertext, a plaintext key, metadata, a tool filter, a tool list or a
  member id list (`docs/03-api.md`, Admin events)
- `request_id` (for correlation with the server log; cut at 256 bytes)
- `remote_addr`: the client address after the trusted-proxy rule, or the
  literal `unknown`

Indexed on `timestamp DESC`. Written from the API handlers after the store
write returns, as a separate statement (no transaction spans the two, so a
crash between them loses the event and keeps the change), and listed newest
first through `GET /admin-events`. Nothing purges it yet; PORM-13 owns
retention for both audit tables, with a longer window for this one.

## Schema versioning

`schema_meta(key, value)` records the applied schema version under
`schema_version`; this binary expects version 5. It also holds
`encryption_key_fp`, the fingerprint of the `ENCRYPTION_KEY` the stored
credentials open under (the PORM-52 issue text called it `enc_key_fp`). That row
is data, not schema: it is written by the boot check once every stored
credential has been proved to open under the current key, and by
`porymcp rekey` in the same transaction as the rows it rewrites, never by a
migration step, which runs with no key. A boot that finds a mismatch leaves it
alone. `store.migrate()` first makes
sure `schema_meta` exists, then creates the base tables, then runs each numbered
step above the stored version inside a single transaction and stamps the new
version in that same transaction, so a crash never leaves a half-applied
schema. Step 1 adds `upstreams.slug`, backfills every existing row from its name
(oldest first, so the oldest upstream keeps the bare slug, and later ones are
de-duplicated), then creates the `upstreams_slug` unique index. Step 2 renames
`agents` to `virtual_keys`, `audit_logs.agent_id`/`agent_name` to
`virtual_key_id`/`virtual_key_name`, and the index `audit_logs_agent` to
`audit_logs_virtual_key`. `agents_lookup` is dropped and not recreated:
`key_lookup` is `NOT NULL UNIQUE`, so the constraint's own index already serves
the lookup.

`admin_events` (PORM-54) is created by the base `CREATE TABLE IF NOT EXISTS`
set rather than by a numbered step: an existing database gains it on its next
start, and the version stays 5, so a rolled-back binary can still open a
database that has it.

Step 3 rewrites tool rules onto the `{upstream_slug}__{tool}` identity, so that
a rule written before the identity existed still means what its author meant. It
works from stored data alone (no upstream is contacted) and it refuses to
start if a stored slug does not validate, since a slug is now half of an
authorization identity. For each group's `tool_filter` and each virtual key's
`tool_allowlist`/`tool_denylist` it takes the target's member slugs (a group's
`upstream_ids`, disabled members included, because disabling is reversible; or
the one upstream a key targets) and applies these rules to each entry:

- **Deny rules only are rewritten, and only by adding.** An unscoped entry that
  reads as `{member_slug}_{rest}` (the pre-v0.1 aggregate spelling, one
  underscore) gains `{member_slug}__{rest}`. A scoped entry whose head is not a
  member gains `{member_slug}__{entry}` for every member, because it may
  be a tool whose own name carries the separator (an upstream that is itself a
  proxy advertises `mcp__fetch`). The entry that was already there is **kept**
  beside the new one: dropping it would stop a key's lists matching a prompt or
  resource of that name, which are compared whole.
- **Allow-side entries are never rewritten.** Widening an authorization list
  during an upgrade with nobody present is not a migration's decision to make:
  a `prefixes` entry `github_` would become `github__`, every tool on that
  member. An allow entry that admits nothing as it stands is counted and
  reported instead, and the operator rewrites it knowingly. It fails closed
  meanwhile.
- **A group filter that does not validate is left byte-for-byte** and counted;
  the migration never marshals a filter the validator rejects. The same is true
  of a key list column whose JSON does not decode.
- Every form it adds is de-duplicated against the list it is added to, so the
  step is a fixed point: running it twice changes nothing. `updated_at` is not
  bumped: the row's meaning did not change, only its spelling.

The step reports five counts on the `schema migrated` startup line, and never
the entries themselves: `tool_entries_rewritten` (entries that gained at least
one scoped form), `tool_entries_left` (entries deliberately untouched that an
operator may want to look at), `tool_filters_left_invalid`, `groups_rewritten`
and `virtual_keys_rewritten`.

Step 4 adds `upstreams.last_test_at` and `upstreams.last_test_ok`, the outcome
of the last deliberate connection test. Both are nullable with no default,
because `NULL` means "never tested" and that is what every existing row is:
nothing is backfilled and nothing is contacted, since a migration must not
invent a result by dialling an upstream with a stored credential while nobody is
watching (PORM-114 owns background probing). Neither column is indexed, as
nothing filters or sorts on either. The step also drops the redundant
`virtual_keys_lookup` index: `virtual_keys.key_lookup` is `NOT NULL UNIQUE`, so
authentication keeps a unique index to look a presented key up by, and the
second index only cost every write. On Postgres the `DROP INDEX` takes an
`ACCESS EXCLUSIVE` lock on `virtual_keys` for the length of the step's
transaction, so a rolling deploy's first new instance briefly queues behind live
key lookups; `CONCURRENTLY` is not an option inside a transaction. Each
`ADD COLUMN` is gated on a column-existence probe, as step 1's is, so re-running
the step changes nothing. Only SQLite is exercised by the store package's tests
(there is no Postgres server in the build environment), and on Postgres the
same DDL is a catalog-only `ADD COLUMN` while the probe reads
`information_schema`.

Step 5 is a format stamp and nothing else: no DDL, no data change. From this
version `upstreams.auth_config` may hold `v1:`-prefixed ciphertexts, which a
version-4 binary base64-decodes as garbage and, because its decrypt path
returned nothing for any failure, forwards as a request with no credential.
The stamp makes that binary refuse the database at `Open` instead. It lands on
the **first boot** of this build, before any `v1:` value exists and even if that
boot then refuses to start for another reason, so upgrading is one-way from
that boot.

Step 2 is the one exception to base-then-steps: it renames the very objects the
base `CREATE TABLE IF NOT EXISTS` statements name, so while the recorded version
is below 2 the rename runs first, as an existence-gated prelude in its own
transaction (under the Postgres advisory lock), before the base DDL; `case 2` of
the step runner is then an idempotent no-op that stamps the version.

- A fresh database: the prelude finds nothing to rename and is a no-op, and step
  3 finds no rules to rewrite.
- A database that somehow holds both `agents` and a non-empty `virtual_keys`
  refuses to start, naming the two tables and nothing else.
- A database at a version this binary does not know refuses to start, naming
  both versions. The rollback for a schema change is therefore
  **restore from backup**, not redeploy: the old binary will not run against the
  new schema, and step 3 has already added entries the old binary never wrote.
  Starting a build at or after PORM-52 migrates the database to version 5
  immediately, even if startup then refuses for another reason, so take the
  backup **before** the upgrade. A backup is restorable only together with the
  `ENCRYPTION_KEY` that was current when it was taken: one taken before a
  rotation holds credentials sealed under the old key.

Separately from the migration, every start reports the tool rules it can see are
broken, with ids, names and counts only, never entry text. One `ERROR` row per
group whose `tool_filter` does not validate (that group blocks every call until
it is fixed), and a `WARN` row for each of: a group or key holding scoped
entries whose head is not one of that target's members; a group filter in mode
`allow`, or a group key's `tool_allowlist`, holding unscoped entries, which
admit nothing; and a key whose stored lists could not be decoded, which blocks
everything on that key. An entry the migration deliberately kept (a bare deny
entry beside the scoped form it added) draws nothing.

Concurrent starts never leave a half-applied schema, though the protection
differs by driver. On Postgres, `pg_advisory_xact_lock` covers the versioned
steps: replicas queue, and the waiter re-runs the step as a no-op. The base
`CREATE TABLE IF NOT EXISTS` statements run before that lock is taken, so two
replicas starting against a virgin Postgres, or first booting a build that adds
a base table (as PORM-54's `admin_events` did), can still race there; the loser
exits, and a restart succeeds because the tables then exist. On SQLite there is
no such lock: a second process starting against the same file while a migration
is pending blocks on the 5 s `busy_timeout`, then either proceeds normally
(re-running the step as a no-op) or, if the migration outran the timeout, fails
with a busy/locked error, rolls back cleanly and exits. Either way nothing is
corrupted, and restarting once the first process has finished succeeds.
