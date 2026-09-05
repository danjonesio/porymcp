# Changelog

Behaviour changes that affect a running deployment. Newest first.

## Unreleased

### Clearing an upstream's credential (PORM-120)

- **Choosing None now removes the stored credential, and the removal cannot
  be undone.** `PATCH /api/v1/upstreams/{id}` with `{"auth_type":"none"}`
  empties the `auth_config` column, resets the last test result and records
  `cleared: ["credential"]` on the admin event. Before this change the
  credential stayed in the row and the edit dialog said so; switching back
  later now means entering it again. The dialog says this under the Auth type
  select before the save.
- `auth_config: {}` now stores nothing, on create and on patch, instead of
  sealing an empty credential. A blank credential box in the Add dialog no
  longer leaves a row reading `auth_configured: true`. Rows this build writes
  that way no longer count as stored credentials, so an install whose only
  stored values are empty objects written after the upgrade starts under an
  ephemeral key where it previously refused; rows an earlier build sealed as
  `{}` keep their bytes and keep counting until the upstream is saved again.
- `auth_type: "none"` with a credential in the same request answers
  `400 auth_config cannot be set when auth_type is none`, on create (an
  omitted `auth_type` defaults to `none`) and on patch.
- A None row that holds a stored value (written by an earlier build, or sent
  alone by a client to a None row, which stays legal) keeps it until a request
  names `auth_type: "none"`. The edit dialog shows a "Remove the stored value"
  checkbox on every None row that holds one, including the empty objects the
  Add dialog used to write, so on most rows it removes nothing of value; the
  same over-reporting applies to `GET /api/v1/upstreams` filtered on
  `auth_type == "none"` and `auth_configured == true`. Rolling back to
  `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the binary, not a
  cleared credential.

### Published image path (PORM-10)

- Images are published at `ghcr.io/danjonesio/porymcp` for linux/amd64 and
  linux/arm64: `edge` and `sha-<short sha>` from every push to `main`, the
  git tag and `latest` from a release tag. Nothing was ever published under
  the path an earlier README named, so no running deployment changes; a
  `docker run` line copied from that README never pulled, and needs the new
  owner now.

### Both keys are now required (PORM-122)

- **Compose now requires `ADMIN_API_KEY` as well as `ENCRYPTION_KEY`.** A
  deployment that relied on the built-in fallback refuses every subcommand
  (`up`, `down`, `logs`) until `.env` sets one. Generate a value
  (`openssl rand -hex 32`), put it in `.env`, and sign in to the dashboard
  with it. For `down` and `logs` a throwaway value works
  (`ADMIN_API_KEY=unused docker compose logs porymcp`), never for `up` against
  an existing data volume. A new `ADMIN_API_KEY` is read at start-up, so
  recreate the container (`docker compose up -d --force-recreate`); any client
  still holding the old key then fails immediately, and nothing stored is
  affected.
- There is one mode. The development-key detection that unreleased builds
  carried in the boot log, on `/health` and as a dashboard banner is gone,
  along with the `/health` field it set. A correctly configured deployment's
  `/health` body is unchanged. Update any alerting that keyed on that field.
- A deployment that ever ran an encryption key copied from a pre-release
  checkout of this repository must treat its stored credentials as
  compromised: put a new key in `ENCRYPTION_KEY`, the old one in
  `ENCRYPTION_KEY_PREVIOUS`, restart, and run `porymcp rekey`
  (`docs/11-deployment.md` section 12).

### The dashboard components are PoryMCP's own MIT code (PORM-61)

- The third-party-derived component set under `web/src/components/` was
  replaced; `NOTICE` now carries dependency attributions only. No behaviour
  change for a running deployment; redistributors no longer have a licence
  exception to honour.

### Compose requires ENCRYPTION_KEY (PORM-25)

- **Compose now requires `ENCRYPTION_KEY`.** `docker compose` refuses every
  subcommand (`up`, `down`, `logs`) until `.env` holds one
  (`cp .env.example .env`, then `openssl rand -hex 32` into it).
- `/health`'s `error` field is now the fixed string `database unavailable`;
  the real store error moved to the server log (Error level, throttled to once
  per minute). Update any alerting that parsed the old text.
- The Postgres profile is wired: `DATABASE_URL` is overridable,
  `porymcp` waits for a healthy database, and the service no longer publishes
  `5432` to the host. It is a separate, empty datastore: there is no
  SQLite to Postgres migration. Needs a recent Compose (`depends_on.required`,
  `healthcheck.start_interval`; verified on v5.5).
- Variables set only in `.env` (`TRUSTED_PROXIES`, the host-allowlist and TLS
  settings) now reach the container via explicit pass-throughs; before, they
  were silently ignored under compose.
- Both compose services now run with `restart: unless-stopped`: they come back
  after a crash, a daemon restart, or a host reboot, and a *permanent*
  misconfiguration (now reachable from `.env` via the new pass-throughs)
  restarts in a loop instead of exiting once; `docker compose logs porymcp`
  names the cause.
- Rollback is a compose/docs revert (no schema change), but reverting also
  reverts the datastore if the Postgres profile was enabled: rows written
  there stay in the `porymcp-pg` volume.

### A changed ENCRYPTION_KEY is detected, and rotation is supported (PORM-52)

- **Upgrading is one-way from the first boot, and needs a backup first.** This
  build stamps schema version 5 the moment it opens the database (before any
  credential is written, before `rekey`, even if startup then refuses for
  another reason), and earlier builds refuse a version-5 database. New
  credentials are written as `v1:`-prefixed ciphertexts earlier builds cannot
  read either. Take a database backup before upgrading, and keep it with the
  `ENCRYPTION_KEY` that was current when it was taken.
- The proxy fails closed on a stored credential it cannot use. An upstream
  whose credential no configured key opens (`ENCRYPTION_KEY` changed), or whose
  credential is empty or holds nothing its auth type can send (a blank token
  stored as `{}`, a `bearer` row switched to `custom`), now answers the usual
  `502 -32000 "upstream request failed"` with **no request sent**; before, the
  request went out with no credential and the upstream's `401` looked like a
  bad token. The audit row reads `credential undecryptable` or
  `credential unreadable`. Discovery refuses the same rows, and a draft whose
  auth type has no credential is refused instead of dialled. On a group's
  aggregate endpoint such a member is skipped like any unlistable member.
- Every upstream response carries `auth_status` (`none`, `ok`, `undecryptable`,
  `unreadable`); `GET /api/v1/stats` gains `undecryptable_upstreams`,
  `unreadable_upstreams` and `upstreams_under_previous_key`; the dashboard
  shows an `Unreadable` / `Incomplete` badge in the Auth cell and a notice on
  Overview.
- `GET /health` gains `encryption: ok | mismatch` (always present) and a third
  `status`, `degraded` (`503`), when the boot check found a credential no
  configured key opens. `porymcp healthcheck` exits `0` on `degraded` (the
  container stays healthy so the dashboard stays reachable) and still `1` on
  `unhealthy`. Monitors on `GET /health` still see the `503`.
- Boot logs one `encryption key verified` line (with the key's fingerprint) on
  every start with `ENCRYPTION_KEY` set whose stored credentials all open (a
  mismatch boot logs the Error naming the affected upstreams instead, and an
  ephemeral-key boot logs nothing), and refuses to start when `ENCRYPTION_KEY`
  is unset against a database that holds stored credentials.
- New: `ENCRYPTION_KEY_PREVIOUS` (comma-separated previous keys, decrypt only,
  at most five, hex or base64) and the `porymcp rekey` subcommand, which
  re-encrypts every stored credential under the current key in one transaction.
  Runbook: `docs/11-deployment.md` §12.
- An unknown first argument (`porymcp rekeyy`) prints usage and exits `2`
  instead of starting a server.
- A `PATCH /api/v1/upstreams/{id}` that does not carry `auth_config` no longer
  rewrites the stored ciphertext it read.

### PATCH keeps the fields you did not send

- `PATCH /api/v1/upstreams/{id}`, `/groups/{id}` and `/virtual-keys/{id}` leave
  every field the body does not carry as it was. Renaming an upstream no longer
  wipes its description.
- `null` now clears `description` (upstreams, groups), `rate_limit`,
  `expires_at`, `tool_allowlist`, `tool_denylist`, `metadata` and
  `upstream_ids`, all of which were ignored before. `tool_filter: null` already
  cleared the filter in effect; it now stores `''` and the response omits the
  key instead of carrying `"tool_filter": null`.
- `""` now clears a group `description` (ignored before).
- A required field sent with a value it cannot hold answers `400` instead of
  being ignored: `name` (empty, whitespace or null; whitespace used to store an
  empty name), `url`, `transport`, `auth_type`, `enabled: null`, `slug: null`,
  `target_type` and `target_id`.
- `POST` keeps its defaults: `transport`, `auth_type` and `target_type` sent as
  `""` or `null` take the default, and `enabled: null` means enabled. The same
  keys are `400` on `PATCH`, which has no default to fall back to.
- On `POST`, a literal `null` for `auth_config` no longer stores ciphertext of
  the four bytes `null` (the upstream reports `auth_configured: false`, which
  is the truth), and `tool_filter` or `metadata` sent as `null` store `''`.
- A client that serialises absent optionals as an explicit `null` now clears
  those fields. Nothing in this repo does. See `docs/03-api.md`, Partial
  updates.

### Breaking: aggregate tool names now always carry the upstream slug

The aggregate group endpoint `/{virtual_key_id}/mcp` advertises every tool as
`{upstream_slug}__{tool}`: `github__create_issue`, not `create_issue`. It did
this before only when two members exported the same name, and with a single
underscore; now it is unconditional, two underscores, and a one-member group is
prefixed too. Per-upstream endpoints `/{virtual_key_id}/{upstream_slug}/mcp` and
single-upstream virtual keys are **unchanged** and still advertise the upstream's
own names.

One underscore was a real defect. Two members `s` and `s_x` each exporting a
tool whose name collides across the join (`s` + `_` + `x_search` and `s_x` + `_`
+ `search` are the same string) produced one name in the merged catalogue, and
the loser of that overwrite resolved to the winner's upstream: a call executed
against the wrong credential. Two underscores make the split back to (slug, tool)
exact, because a slug may not contain a repeated separator and must end
alphanumeric.

**If you connect a client to an aggregate URL, reconnect it.** Cached catalogues
hold the old names, and a call using one now answers
`-32602 unknown tool: <name>` instead of guessing which member meant it. Saved
prompts, scripts and `--allowedTools` lines that name an aggregate tool need the
prefix added.

**If you have written group `tool_filter` entries or virtual-key allow/deny
lists, read the startup log after upgrading.** `{slug}__{tool}` is now the one
identity a rule names on every path, so a rule written once is enforced on the
aggregate endpoint and on every member endpoint alike, which is the point of the
change, and which also means entries written against the old aggregate names no
longer match as written. A schema migration (version 3) rewrites them in place,
offline, at first start: it contacts no upstream, it is idempotent, and it reports
counts, never the entries themselves, in the startup log.

- **Deny entries are rewritten to the strictest reading that preserves intent**,
  by *adding* the scoped forms beside the entry that is already there, never by
  replacing it. The original is kept because a key's lists also match prompt and
  resource names, which are compared whole.
- **Allow entries are never rewritten.** Widening an authorization list during an
  upgrade with nobody present is not a migration's decision to make. An allow
  entry it cannot read unambiguously is left alone and counted: an unmatched
  allow entry fails closed, so nothing opens up silently, but the tool it meant
  to permit is refused until you fix the entry.
- In particular, **an unscoped allow entry on a group admits nothing until it is
  rewritten**. An allow rule on a group must name a member: `github__search`, not
  `search`. The management API refuses to write an unscoped one, the proxy skips
  it, and every start names the group or key still holding one. A deny entry may
  be either form: an unscoped deny is "block this name wherever it appears", and
  it follows the group's membership.
- Watch the deny side for one over-block. A `prefixes` entry `github_` on a group
  with a `github` member gains `github__`, which is **every** tool on that
  member, because a `prefixes` entry ending at the separator means exactly that.
  It is the intended direction (a migration may over-block, never under-block),
  but it is worth checking before it surprises an agent.

Tool names on the aggregate are longer as a result, and clients prepend their own
prefix: Claude Code shows an aggregate tool as `mcp__{server}__{slug}__{tool}`.
A name of 87 characters was accepted and callable in Claude Code 2.1.250, but a
long slug combined with long upstream tool names can still reach a client's
tool-name limit. Slugs are immutable after create, so choose short ones.

### The proxy no longer follows an upstream redirect

An upstream that answers a proxied request with `3xx` is now a failed call. The
proxy makes no second request, sends the client `502` with
`-32000 "upstream request failed"`, and writes an audit row with
`status = error` whose `error_message` reads `upstream redirected to <host>`,
the host alone, never the full `Location`, and bounded at 256 bytes. A `3xx`
that carries no `Location` (typically a `304`, which the proxy never provokes:
it sends no conditional requests) records `upstream redirected` with no host.
Nothing from the redirect response, `Location` included, is copied back to the
client.

Following a `Location` re-sent the upstream's real credential to whatever host
it named. Go drops `Authorization`, `Cookie`, `Cookie2` and `Www-Authenticate`
only when the hostname changes (not on a subdomain, not on a same-host scheme
downgrade) and copies every other header verbatim; on a `307` or `308` the
client's request body is re-sent too. Three of the four auth types PoryMCP
supports put the secret in an ordinary header (`api_key` to `X-API-Key` by
default, `header`, `custom`), so a vendor moving a hostname behind a `301`, or a
typo in a registered URL, was enough to hand the credential to a third party,
and a hostile upstream could point the proxy at an internal address. A
credential now goes to that upstream's own URL, and never to a host the upstream
names in a redirect. `docs/07-security.md` has the full statement.

**If any upstream's registered URL relies on a redirect, fix it before
upgrading.** The usual three are an `http://` URL that `301`s to `https://`, a
path missing its trailing slash, and a hostname the vendor has moved. Each of
them worked silently before and fails completely now. `PATCH
/api/v1/upstreams/{id}` with the final URL from the server's own documentation.
The host on the audit row is a diagnostic, not an instruction; nothing else
about the upstream, and nothing in any client, needs to change. Slugs, keys,
endpoints and tool rules are untouched.

**To find them after the fact, filter the logs.**
`GET /api/v1/logs?status=error` (or the Logs page) shows the row, and the
message names the host the upstream tried to send the proxy to. Note the one
blind spot: on the **aggregate** group endpoint a member that redirects its
catalogue request is skipped, so its tools are missing from the merged
list and no audit row names it: the row belongs to the client's call, which
succeeded on the members that did answer. That skip is written to the server log
as `group member skipped`, naming the member's slug and its upstream id. Call
that member's own `/{virtual_key_id}/{upstream_slug}/mcp` endpoint to get the
`502` and the row.

Correctly configured upstreams are unaffected: a `2xx`, a `4xx` and a `5xx` all
behave exactly as before.

### Also in this release

- A `tools/call` on an aggregate endpoint for a name that is not a
  `{slug}__{tool}` identity (no `__`, an empty half, or a head that is not a
  valid slug) answers `-32602 "unknown tool: <name>"` without contacting any
  upstream. A well-formed name whose slug is not a member of that key's group,
  or whose tool no member advertises, gets the same answer after the members'
  catalogues have been listed and before anything is forwarded. Both are audited
  as `error` rather than `blocked`, since no rule fired. The echoed name is
  bounded at 256 bytes.
- A virtual key whose stored `tool_allowlist`/`tool_denylist` cannot be decoded
  now blocks every call on that key instead of behaving as if it had no lists.
  Both columns are left as they are by every write, so a rename, a rotate and a
  revoke keep the key blocked rather than replacing an unreadable rule with no
  rule at all; a `PATCH` sending both lists replaces them and clears the block,
  and one list alone answers `400`.
- Every start reports tool rules that are invalid or inert (an unparseable group
  filter, an upstream whose stored slug is no longer valid, entries scoped to a
  slug that is not a member, unscoped entries in an allow rule on a group,
  undecodable key lists), with ids, names and counts, and never the entry text.
  A deny entry the migration above kept beside its scoped forms is not reported:
  it is this release's own output, not a mistake.
- The dashboard can ask an upstream what tools it offers, from the Add upstream
  dialog before one is saved, and from the Upstreams table afterwards. It runs a
  real MCP handshake with that upstream's own credential and shows the server's
  name, version, response time and every tool it advertises, with the
  `{upstream_slug}__{tool}` identity a rule would name beside each one. Nothing
  is stored: the list is what the server said just now, and the response carries
  neither the credential nor the upstream's own response body.
  `POST /api/v1/upstreams/{id}/discover` and `POST /api/v1/upstreams/discover`
  answer the same call from the API, admin key only, budgeted at thirty a minute
  and four at once. Both routes are new. This is an outbound
  request PoryMCP now makes on an *operator's* say-so rather than a virtual
  key's, and where the URL points is not yet checked. `docs/07-security.md` says
  what that does and does not grant, and `docs/03-api.md` has the response
  contract.
- An upstream `url` must now be an absolute `http` or `https` URL with a host
  and no fragment. `POST /upstreams` and `PATCH /upstreams/{id}` answer
  `400 {"error":"url must be an absolute http or https URL"}` for anything else.
  A bare `localhost:3001/mcp` parses as the scheme `localhost` and was stored
  happily before this, then failed at the first proxy call. Stored rows are
  untouched; only writes are refused.
