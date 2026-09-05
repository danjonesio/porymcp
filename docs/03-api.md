# Management API (REST, `/api/v1`)

Auth: `Authorization: Bearer <ADMIN_API_KEY>` (simple for MVP)

Errors: every error body is `{"error": "..."}`. An unknown path or an unknown
resource id answers `404 {"error":"not found"}` (unknown paths are answered
before auth is checked); a known path without the admin key answers
`401 {"error":"unauthorized"}`. Ten failed admin-auth attempts from one
client IP within a minute make the next one `429 {"error":"too many requests"}`
with a `Retry-After` header; a request that presents the correct key never
consumes that budget. The two discovery routes below carry a second budget of
their own, which a *correct* key does spend, and the two are counted apart so
that a burst of discoveries cannot lock an operator out of the API.

## Partial updates

`PATCH /upstreams/{id}`, `PATCH /groups/{id}` and `PATCH /virtual-keys/{id}`
share one rule. **A key that is absent from the body leaves the field
unchanged.** A value sets the field and is validated exactly as on create.
`null` clears a field that has a cleared state; on a field that has none it is
a `400` with that field's usual message; on `auth_config` alone it means
unchanged (see the table). `""` clears a string whose empty value is
meaningful, and `[]` clears a list. A cleared field is absent from the
response, the same as one that was never set.

| Field | value | `null` | `""` / `[]` / `{}` |
|---|---|---|---|
| `name` (all three) | trimmed and set | `400 name cannot be empty` | `400 name cannot be empty` (whitespace-only too) |
| upstream `slug` | equal to the stored slug: no-op; anything else: `400 slug cannot be changed after create` | same `400` | same `400` |
| upstream / group `description` | set | **cleared** | **cleared** |
| upstream `url` | set; `400 url must be an absolute http or https URL` if not; resets the last test when it differs | that `400` | that `400` |
| upstream `transport`, `auth_type` | set; `400 invalid transport` / `400 invalid auth_type` if not an allowed value; resets the last test when it differs | that `400` | that `400` |
| upstream `auth_config` | replaces the stored credential; resets the last test | **kept**: the value is write-only, so an object read back and sent again cannot carry it; `null` therefore means unchanged | `{}` replaces with `{}` |
| upstream `enabled` | set | `400 enabled must be true or false` | n/a |
| group `upstream_ids` | validated and replaced | **cleared** to `[]`: the group has no members, and every key targeting it loses its endpoints | `[]` clears |
| group `tool_filter` | validated and replaced | **cleared** | `{}` is a valid filter that filters nothing; stored as sent |
| key `target_type`, `target_id` | validated together as the target the key will have | `400 target_type must be upstream or group` / `400 unknown upstream target` or `unknown group target`, per the key's target type | same `400`s |
| key `rate_limit` | set; `0` (like `null`) means unlimited | **cleared**: unlimited | n/a |
| key `expires_at` | set | **cleared**: a key that had expired is active again | `400` |
| key `tool_allowlist`, `tool_denylist` | validated and replaced | **cleared** to `[]`; counts as *sent* for the both-lists rule under Tool lists | `[]` clears |
| key `metadata` | replaced | **cleared** | `{}` stored as sent |

**Responses.** A cleared field is absent from the response, the same as a field
that was never set: `description`, `rate_limit`, `expires_at`, `tool_filter`,
`tool_allowlist`, `tool_denylist` and `metadata` are omitted when empty.
`upstream_ids` is always an array. A group or key written before PORM-21 with
an explicit `null` may still echo `"tool_filter": null` or `"metadata": null`
until that field is next sent.

**Create.** On `POST` the same keys keep their defaults: `transport`,
`auth_type` and `target_type` sent as `""` or `null` take the default, and
`enabled: null` means enabled. There is a default to fall back to on create and
none on `PATCH`, which is why the same key answers differently.

**Consequences.** Clearing `expires_at` makes a key that had expired active
again: its plaintext authenticates from the next request. Clearing
`upstream_ids` empties the group, and every key that targets it loses its
endpoints. Clearing `tool_allowlist`, `tool_denylist` or a group's
`tool_filter` widens what a key may call. The management API writes one line
to the server log for each (`group policy fields cleared` and `virtual key
policy fields cleared`), naming the resource, its id and the fields, never a
value. The same field names also land on the request's admin event, under
`details.cleared` (see Admin events).

**Round-trips.** An edit form must omit `auth_config`, `tool_filter`,
`tool_allowlist` and `tool_denylist` when the operator did not touch them. The
stored credential cannot be resent, and only a filter or list the request sends
is judged: one that predates today's validation rules keeps working until
someone rewrites it, but sent back unchanged it is judged by the current rules
and may be refused (see Tool lists).

**Concurrency.** Two overlapping `PATCH`es are not merged: last write wins;
each request rewrites the row from the copy it read when it arrived. Every
`PATCH` of an upstream or a group, `{}` included, moves its `updated_at`
(virtual keys carry none), so a discovery that began before an upstream edit
does not record its result (see The last test).

**Compatibility.** Before PORM-21 a field sent with a value it could not hold
was ignored (or, for a whitespace-only `name`, stored as an empty name); it is
now a `400`. A client that serialises absent optionals as an explicit `null`
now clears those fields where it previously left them alone.

## Upstreams
- `POST   /upstreams`
- `GET    /upstreams`
- `GET    /upstreams/{id}`
- `PATCH  /upstreams/{id}`
- `DELETE /upstreams/{id}`
- `POST   /upstreams/discover`
- `POST   /upstreams/{id}/discover`

### Upstream URLs
`url` must be an absolute `http` or `https` URL with a host and no fragment.
`POST /upstreams` and `PATCH /upstreams/{id}` answer
`400 {"error":"url must be an absolute http or https URL"}` for anything else
(a bare `localhost:3001/mcp`, a `file:` or `ftp:` scheme, a scheme-relative
`//host/mcp`), so a URL PoryMCP could never connect to is refused where it is
typed rather than where it is used. It is the same check discovery applies
before it opens a socket (`mcpclient.CheckTarget`), and it is syntax only:
whether the host should be dialled at all is PORM-79, see `docs/07-security.md`.

### Upstream slugs
`slug` is optional on `POST /upstreams`: an omitted, empty or whitespace-only
value is derived from the name and de-duplicated (`github_enterprise`, then
`github_enterprise-2`). Supplied, it is lowercased and trimmed, and must match
`^[a-z0-9]([a-z0-9_-]{0,38}[a-z0-9])?$` with no repeated separator (`__`, `--`,
`-_`, `_-`), must not be UUID-shaped, and must not be `mcp`, `api`, `health` or
`metrics`. Otherwise `400`. A slug already in use returns `409`. If every
derived candidate is taken (50 upstreams sharing one name), `POST` returns `409`
asking for an explicit slug.

`slug` is fixed at create. `PATCH /upstreams/{id}` rejects a different `slug`
with `400`; sending the current value (lowercased and trimmed first, as on
create) is a no-op and omitting the field keeps it (see Partial updates), so
renaming an upstream never moves its slug; `null`, like any other value, is a
`400`. To change a slug, delete and recreate the upstream. This is
deliberate: group tool filters and virtual-key allow/deny lists are written
against the tool identity the slug composes (`{slug}__{tool}`, the same on
every path), and a stale deny entry would fail open; the same is true of the
per-member endpoint URLs clients configure, which carry the slug in the path.

### Discovering an upstream's tools

`POST /upstreams/{id}/discover` connects to a saved upstream with its stored
credential and returns what that server advertises.
`POST /upstreams/discover` does the same for a payload that has not been saved:
it takes the body `POST /upstreams` accepts (`name`, `url`, `transport`,
`auth_type`, `auth_config`), of which only `url` is required, so the Add
upstream dialog can check a URL and a token before writing a row that does not
work.

Nothing is cached on either route (the list is what the server said just now),
and `POST /upstreams/discover` persists nothing at all.
`POST /upstreams/{id}/discover` writes exactly two fields on the upstream's own
row, `last_test_at` and `last_test_ok`, on every run that completes, pass or
fail, including a refused transport and an undecryptable stored credential. A
`429`, a cancelled request, and a run whose upstream was edited or deleted while
it ran record nothing. The catalogue itself is not stored (PORM-113).

Both are admin-only, and both answer `200` whether or not the upstream answered:
the HTTP status describes the request PoryMCP received, `ok` describes the
upstream. They are `POST` rather than `GET` because the call has an effect
outside PoryMCP (a real MCP handshake against a host an operator named, using a
real credential), and a `GET` is the kind of thing browsers, proxies and link
checkers fetch on their own. `GET /upstreams/discover` is not a route at all: it
falls through to `GET /upstreams/{id}` with `discover` as the id and answers the
ordinary `404 {"error":"not found"}`.

Each call is the handshake a client would make: `initialize`,
`notifications/initialized`, `tools/list` followed to the end of its cursors,
then a `DELETE` of the session so none is left open on the upstream. The whole
sequence is bounded at 10 seconds and the teardown at a further 2, so a hung
upstream cannot hold an admin request open; the proxy's own 60 s budget is for
relaying a client's call, not for answering the dashboard.

```json
{
  "ok": true,
  "latency_ms": 140,
  "protocol_version": "2025-06-18",
  "server_info": { "name": "mcp-servers/everything", "version": "2.0.0" },
  "slug": "everything",
  "tool_count": 13,
  "truncated": false,
  "unnameable_tools": 0,
  "tools": [
    {
      "name": "echo",
      "title": "Echo",
      "description": "Echoes back the input string",
      "scoped_name": "everything__echo",
      "annotations": { "readOnlyHint": true }
    }
  ]
}
```

Every field is either PoryMCP's own or a clamped copy of something the upstream
said, and there is nothing else in the body. `error`, present only when `ok` is
`false`, is one of a closed set of sentences composed from a status code, a
host name and the step that failed. `upstream_message` carries the upstream's
own JSON-RPC `error.message`, single line, visible characters, at most 200
bytes, and it is a separate field precisely so that `error` stays a string
PoryMCP wrote: "token lacks the `repo` scope" is the answer an operator came
for, but it is the upstream talking. `latency_ms` is the whole handshake,
rounded to 10 ms: enough to tell a slow server from a fast one, blunt enough
not to be a stopwatch on the network PoryMCP sits in. `protocol_version` and
`server_info` are what came back from `initialize`, clamped to 32, 128 and 64
bytes. Every upstream-controlled string PoryMCP carries (`description`,
`title`, `server_info.name`, `server_info.version`, `protocol_version` and
`upstream_message`) has its control characters scrubbed before it is clamped: a
newline or a tab becomes a space, and any other C0 character, `DEL` or U+FFFD is
dropped, so a `curl … | jq -r` cannot be handed an escape sequence by an
upstream. Invisible and bidirectional marks are not stripped yet: that is
PORM-83.

`tools` is always an array, never `null` and never omitted, and `tool_count` is
its length *after* drops: how many tools are shown, not how many the server
has. `description` is clamped to 4096 bytes on a rune boundary and carries
`description_truncated: true` when it was cut; `title` is clamped to 256.
`annotations` is a fixed object (`title`, `readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`), never an arbitrary blob whose shape the
upstream chooses. There is no `inputSchema`: a schema is unbounded upstream JSON,
and an opt-in `?include=schema` can be added later without breaking anything.
`unnameable_tools` counts the tools left out because the proxy could not hold a
caller to their names (empty, over 256 bytes, or carrying a control character
or U+FFFD: the same rule that governs a tool identity everywhere else, plus a
256-byte cap on what discovery will show), and it counts them without repeating
them. `truncated` is `true` when the catalogue was cut short: at 500 tools, at
50 pages, or when a server returned a cursor it had already returned. Duplicate
names are kept exactly as the upstream sent them, because an ambiguity in a
server's own catalogue is one of the things an operator is reading this list to
find.

`slug`, and each tool's `scoped_name`, are the tool identity `{slug}__{tool}`,
what a group `tool_filter` entry and a virtual-key allow/deny entry name, on
every path. **Both are absent on `POST /upstreams/discover`**, and that is
deliberate rather than an omission. An unsaved payload has no slug, and deriving
a provisional one would be worse than showing none: create de-duplicates, so the
`github` computed before saving can be stored as `github-2`, and an operator who
copied `github__search` out of the panel into a **deny** rule would have written
an entry that matches nothing and fails open, the failure the immutable slug
above exists to prevent. The dashboard shows a preview and labels it as one.

The response never carries `auth_config`, the credential in any form, an
upstream response header, or any byte of an upstream response body outside the
fields listed here and `upstream_message`. The MCP session id is used to
complete the handshake and never returned. An error names a host and never a
URL: a `user:password@` and a query string are never written into one. That
matters, because Go's own transport errors mask the password and keep the
username, the path and the whole query string.

A failure is `ok: false` with `error`, worded so an operator can tell which half
is broken. `cannot resolve <host>`, `cannot connect to <host>` and
`tls handshake with <host> failed` are the network. `upstream did not answer
within 10s` is the budget above. `upstream redirected to <host>` is the same
refusal the proxy makes: discovery goes out over the same client, so a `3xx`
ends the call rather than moving the credential to a host the upstream named.
`upstream rejected the credential (401) at initialize` and
`upstream answered 404 at initialize; check the url points at the mcp endpoint`
are the two an operator meets most often, and each names the step it failed at,
so "the credential works but the catalogue does not" is a thing the answer can
say. `upstream's answer to <step> is larger than discovery will read` is the
read cap: a whole handshake is allowed 2 MiB, and an answer over it is refused
rather than decoded from a document that stops mid-object, which would otherwise
report a working server as one that does not speak JSON-RPC. A `transport` of
`sse` answers `ok: false` naming the transport instead of hanging (that
transport is accepted on `POST /upstreams` but not implemented,
PORM-28), and a URL that is not an absolute `http` or `https` URL is refused
before any request is made. A stored credential that exists but cannot be
decrypted, after a rotated `ENCRYPTION_KEY`, answers
`stored credential cannot be decrypted` and makes **no** outbound request at
all: sending an unauthenticated one instead would come back as a `401` that
looks exactly like a bad token; `auth_status` on the row says which it is. A
stored credential that decrypts but holds nothing its auth type can send (a
blank token stored as `{}`, a `bearer` row switched to `custom`) answers
`stored credential is not usable for this auth type`, likewise with no request.
On the unsaved route a draft whose auth type needs a credential it does not
have answers `this auth type needs a credential; add one or choose None`. An
`auth_type: none` draft or row is never judged by a credential.

Thirty discovery calls a minute across the deployment, and four in flight at
once. The thirty-first is `429 {"error":"too many discovery requests"}` with the
limiter's `Retry-After`; a fifth concurrent call is
`429 {"error":"too many concurrent discoveries"}` with `Retry-After: 5`. The
budget is spent before the store is read, so a flood of unknown ids costs a
caller exactly what real ones do. Otherwise: `400` for a malformed body, a
missing `url` or an invalid `transport`/`auth_type`; `404` for an unknown `{id}`,
byte-identical to `GET /upstreams/{id}`; `500` only when the store fails.
Everything the *upstream* does is `200` with `ok: false`.

A disabled upstream is still discovered (an operator who has turned one off is
usually the operator diagnosing it), and the saved route ignores its request
body, as `rotate` and `revoke` do.

Discovery contacts the upstream on the **operator's** behalf rather than a
virtual key's, so it writes no `audit_logs` row: `GET /logs` is the record of
what agents did, and this is not one of them. It writes no `admin_events` row
either (see Admin events): a test result is an observation of the upstream,
not a change to the configuration. The discover handlers and the upstream
client add no log line of their own either, with one exception: when the saved
route cannot record its result it writes a single line (`DEBUG` when the row
was edited or deleted while the handshake ran, `WARN` when the store itself
failed) naming the upstream id, and the store's error on the `WARN`. The access
log's `POST /api/v1/upstreams/<id>/discover 200` is the trace, and nothing
logged on this path carries the URL, a header value or a byte of a body. See
`docs/07-security.md` for what this route does and does not grant.

### The last test

Every upstream response (list, get, create and patch) carries `last_test_at`
and `last_test_ok`, the record of the last press of Tools or Refresh, which is
`POST /upstreams/{id}/discover`. Both keys are always present, and both are
`null` until the first press. `last_test_at` is an RFC 3339 UTC timestamp taken
from the server's clock when the run finished; `last_test_ok` is that run's own
`ok` (the whole handshake **and** the catalogue), so a refused `sse` transport
and a stored credential that cannot be decrypted both read `false`. Neither
field is writable: `POST /upstreams` and `PATCH /upstreams/{id}` ignore them in
a body, and the saved discovery route is the only thing that sets them.

`PATCH /upstreams/{id}` resets both to `null` when it changes what a test tested:
a different `url`, `transport` or `auth_type`, or any `auth_config` in the
body other than an explicit `null`, since a credential is encrypted under a
fresh nonce and two ciphertexts of one secret never compare equal. `name`,
`description` and `enabled` never reset it. The reset is in the body of the
`200` the `PATCH` itself returns, not only in the next `GET`. Recording a test
does not move `updated_at`: a test is not an edit. Every `PATCH` is one and does
move it, `{}` included (see Partial updates).

### auth_status

Every upstream response also carries `auth_status`, PoryMCP's verdict on the
stored credential (PORM-52): `none`: `auth_type` is `none`, the upstream sends
no credential and nothing stored beside it is consulted; `ok`; `undecryptable`:
no configured `ENCRYPTION_KEY` (current or `ENCRYPTION_KEY_PREVIOUS`) opens
the stored value: the key changed, and the fix is a key; `unreadable`: nothing
is stored, or the value opens but holds nothing the auth type can send (a blank
token stored as `{}`): the fix is the credential, never the key. The proxy
refuses to call an `undecryptable` or `unreadable` upstream (see Upstream
failures). Invariants: `auth_status` is `"none"` iff `auth_type` is `"none"`,
whatever the dashboard stored; `auth_hint` is present only when `ok`;
`auth_configured` keeps its meaning (a blob is stored) and is independent: a
`bearer` upstream with no credential yet reads `auth_configured: false,
auth_status: "unreadable"`. It is computed live on every read, so it clears the
moment a credential is re-entered or `porymcp rekey` finishes; `GET /health`'s
`encryption` is the boot verdict and clears at the next restart.

## Groups
- `POST   /groups`
- `GET    /groups`
- `GET    /groups/{id}`
- `PATCH  /groups/{id}`
- `DELETE /groups/{id}`

`PATCH /groups/{id}` is a partial update (see Partial updates): `description`
clears on `""` or `null`; `upstream_ids` and `tool_filter` clear on `null`.

## Virtual keys
- `POST   /virtual-keys`  
  returns `{ id, name, api_key (plaintext once), proxy_url, endpoints, ... }`
- `GET    /virtual-keys`
- `GET    /virtual-keys/{id}`
- `PATCH  /virtual-keys/{id}`
- `POST   /virtual-keys/{id}/rotate`: new key returned once
- `POST   /virtual-keys/{id}/revoke`
- `DELETE /virtual-keys/{id}`

`PATCH /virtual-keys/{id}` is a partial update (see Partial updates):
`rate_limit` and `expires_at` are removed with `null`; `tool_allowlist`,
`tool_denylist` and `metadata` clear on `null`.

### Endpoints

Every virtual-key response carries `endpoints`: a read-only array computed per
response from the target and never stored.

Every entry is a URL that speaks **exactly one upstream, 1:1**: that upstream's
own tool names, `initialize`, capabilities, instructions, prompts, resources and
sessions. For a group target that is `{PUBLIC_URL}/{virtual_key_id}/{slug}/mcp`,
one entry per **enabled** member, in the group's `upstream_ids` order. For a
single-upstream target there is exactly one entry and its `url` **is**
`proxy_url` itself, because that endpoint is already 1:1. The `/{slug}/mcp`
form is a group-only route and answers `404` there.

A group key:

```json
{
  "id": "77232bc0-dd4a-44d5-8ae7-ef2f679879ec",
  "name": "research-agent",
  "proxy_url": "https://porymcp.example.com/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp",
  "endpoints": [
    {
      "upstream_id": "8e2a1f7c-6b0d-4a3e-9d21-0f4c5b8e7a10",
      "slug": "github",
      "name": "GitHub",
      "url": "https://porymcp.example.com/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp"
    },
    {
      "upstream_id": "c14b93de-2f55-4c8a-b0e6-71a2d9f43c88",
      "slug": "linear",
      "name": "Linear",
      "url": "https://porymcp.example.com/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp"
    }
  ]
}
```

A single-upstream key, one entry mirroring `proxy_url`:

```json
{
  "id": "3f9c0a52-77bd-4f1e-9a35-2c6e8b1d40aa",
  "name": "cursor-dev",
  "proxy_url": "https://porymcp.example.com/3f9c0a52-77bd-4f1e-9a35-2c6e8b1d40aa/mcp",
  "endpoints": [
    {
      "upstream_id": "8e2a1f7c-6b0d-4a3e-9d21-0f4c5b8e7a10",
      "slug": "github",
      "name": "GitHub",
      "url": "https://porymcp.example.com/3f9c0a52-77bd-4f1e-9a35-2c6e8b1d40aa/mcp"
    }
  ]
}
```

- `proxy_url` on a group key is the *aggregate* endpoint and is never an entry.
- A member that is disabled, or removed from the group, has no entry, and its
  URL answers `404` on the next request.
- `endpoints` is always an array, never `null` and never omitted: `[]` when
  nothing is reachable (a group with no enabled members, a deleted group, a
  disabled single upstream).
- It is present on list, get, create, rotate, patch and revoke, and revoking or
  expiring a key does not change it: endpoints are a property of the target, not
  of the key's status, exactly as `proxy_url` is. The key stops authenticating;
  the URLs stay the same.
- `PUBLIC_URL` mints `proxy_url` and every entry's `url`.

### Tool lists

`tool_allowlist` and `tool_denylist` are validated on `POST /virtual-keys` and
on `PATCH`, and a rejected entry is quoted back with its list name and index.
An entry may not be empty or carry whitespace, a control character or U+FFFD;
a *scoped* entry (one holding `__` with something before it) must have a
syntactically valid slug before the separator and a tool name after it. The
slug is not checked against any membership, because a group's members change.

The allow side takes one more rule, and it follows the key's **target**:

| target | `tool_allowlist` entry | result |
| --- | --- | --- |
| group | `github__create_issue` | accepted |
| group | `create_issue` | `400`: an allow rule on a group must name a member |
| upstream | `create_issue` | accepted: every tool belongs to that upstream |
| upstream | `github__create_issue` | accepted on create; on a retarget, `400` if `github` is not this upstream's slug |

`tool_denylist` takes both forms on both targets: "block this name wherever it
appears" is exactly what an unscoped deny entry means.

`PATCH` validates only a list the request sends, and against the target
the key will have **after** the patch, so a body that moves a key onto a group
and sends a new allowlist in the same request is judged as the group key it is
about to become. A list the request does not send is left alone and not
re-checked, so a key written before these rules existed stays renamable,
expirable and revocable.

A key whose **stored** lists cannot be decoded is the one place where leaving an
unsent list alone is not enough. Both lists read back as absent on such a key,
so the proxy blocks every call on it, and every write leaves the two columns
exactly as they are: a rename, a `rotate` and a `revoke` all succeed and the key
stays blocked, rather than replacing an unreadable rule with no rule at all. A
`PATCH` carrying **both** `tool_allowlist` and `tool_denylist` (including as
`null` or `[]`, see Partial updates) replaces them and clears the block. One
list alone answers `400` naming both fields, because the store would not have
written it and the `200` would have been a no-op.

Retargeting is the one exception, because a move changes what an untouched list
means. When `target_type`/`target_id` change, the resulting
`tool_allowlist` (whatever this request sent, or the stored list when it sent
none) is re-read against the new target, in both directions:

- onto a **group**, unscoped entries would admit nothing, and
- onto an **upstream**, entries scoped to any other slug can never match.

Either answers `400` naming the stranded entries, and the stored key is left
untouched; send a rewritten `tool_allowlist` with the same request to move and
fix in one call. The denylist is never refused for a move: an operator who
writes "never `delete_repo`, anywhere" wants precisely the entry that survives
one, and forcing a rewrite on every retarget would only teach them to empty it.

## Logs
- `GET /logs?virtual_key_id=&since=&until=&method=&tool=&status=&limit=&cursor=`
- `GET /logs/{id}`

`tool` is an exact match on the recorded `tool_name`, not a prefix or a
substring. That name is the one the client sent, so on the aggregate endpoint of
a group it is the canonical `{upstream_slug}__{tool}` and on a per-member
endpoint or a single-upstream key it is the upstream's own bare name. Filtering
one group's calls for a tool therefore takes the spelling the path uses.

`limit` below 1 or not an integer is a `400`; above 200 it is treated as 50.

## Admin events
- `GET /admin-events?since=&resource_type=&limit=&cursor=`

Every successful state-changing management call writes one row to
`admin_events` before it answers: create, update and delete of an upstream or
a group, and create, update, rotate, revoke and delete of a virtual key
(PORM-54). A row carries `id`, `timestamp`, `actor` (the literal `admin` until
dashboard users land), `action`, `resource_type`, `resource_id`,
`resource_name`, `details`, `request_id` and `remote_addr`: the client address
after the trusted-proxy rule, so a deployment behind a reverse proxy records
the client rather than the proxy, or the literal `unknown` when there is no
socket address. The response is
`{"admin_events": [...], "next_cursor": "..."}`, newest first; `next_cursor`
is empty on the last page and `admin_events` is `[]`, never null.

`resource_type` is one of `upstream`, `group`, `virtual_key`; any other value
is a `400`, because on an audit endpoint an empty answer would read as
"nothing happened". `since` is inclusive and takes RFC 3339; on a whole second
it is exact, and a value carrying a fraction can include a row from earlier in
that same second. `limit` below 1 or not an integer is a `400`; above 200 it
is treated as 50, as on `/logs`. `cursor` is opaque; a malformed one is a
`400`.

| action | details keys |
|---|---|
| `upstream.create` | `slug`, `auth_type`, `auth_changed` (when a credential was supplied) |
| `upstream.update` | `fields`, `auth_changed` (when a credential was sent), `auth_type` (when the credential or the type changed) |
| `upstream.delete` | none |
| `group.create` | `upstream_count`, `tool_filter_set` (when a filter was supplied) |
| `group.update` | `fields`, `upstream_count` (when the membership changed), `cleared` |
| `group.delete` | none |
| `virtual_key.create` | `target_type`, `target_id`, `key_prefix` |
| `virtual_key.update` | `fields`, `cleared` |
| `virtual_key.rotate` | `key_prefix` |
| `virtual_key.revoke` | none |
| `virtual_key.delete` | none |

`details` is a closed object composed by the server, never the request body.
It is always an object, `{}` when there is nothing to add. `fields` names the
fields whose stored value differs after the request, not the keys the body
carried: a client that round-trips the current values records no field, and
sending the current `slug` (which cannot change) records nothing. `cleared`
records that the request nulled or emptied a field (the same names the server
log line carries) and can appear without a matching `fields` entry when the
field was already empty. A credential is reported by `auth_changed`, never by
a field: ciphertexts cannot be compared, so an identical credential sent again
shows the flag and no field. A `PATCH` with an empty body answers `200` and
records `details: {}`. A value is recorded only when it is a bounded
identifier, enum or count the API already returns in the clear (`slug`,
`auth_type`, `key_prefix`, `target_type`, `target_id`, `upstream_count`); a
name, description, URL, credential, ciphertext, plaintext key, metadata, tool
filter, tool list or member id list never appears as a value, and the string
`auth_config` never appears at all.

A row follows the store write, not the response: a request the store refused
(`400`, `401`, `404`, `409`) records nothing, and a rare `500` raised after a
committed write (a presenter failure) still has its row. Only completed
changes are recorded; a refused or unauthorised request is visible only as a
status line in the server log. The two discovery routes
(`POST /upstreams/discover` and `POST /upstreams/{id}/discover`) are not
recorded: the unsaved probe changes no state, and the saved one stamps a test
result, an observation of the upstream rather than a change to the
configuration; recording them is PORM-132. `resource_name` and `request_id`
are cleaned (a newline or tab
becomes a space, other control characters are dropped) and cut at 256 bytes on
the row; the resource keeps its own name.

## Meta
- `GET /health`: also served unauthenticated at `/health` (root). The
  management-API copy is `/api/v1/health` (likewise unauthenticated).

  | Field | When present | Meaning |
  | --- | --- | --- |
  | `status` | always | `ok`; `degraded`: stored credentials cannot be read with the current `ENCRYPTION_KEY` (`503`); `unhealthy`: store ping failed (`503`) |
  | `service` | ok, degraded | `porymcp` |
  | `time` | ok, degraded | RFC 3339 UTC |
  | `scheme_enforced` | always | `true` when `PUBLIC_URL` is https and `ALLOW_INSECURE_HTTP` is unset |
  | `trusted_proxies` | always | count of configured trusted-proxy CIDRs; never the CIDR list |
  | `encryption` | always | `ok`, or `mismatch` when the boot check found a stored credential no configured key opens. A verdict only, never a fingerprint, a count or a name on this unauthenticated route |
  | `error` | unhealthy | the fixed string `database unavailable`; the real store error is in the server log at Error level |

  A failed store ping outranks the encryption verdict: the body is `unhealthy`
  and `encryption` is still reported. A `503` body of either kind still
  includes `scheme_enforced`, `trusted_proxies` and `encryption`. `encryption`
  is the **boot** check's verdict, not recomputed per request (the route
  issues no store read beyond its ping), so a `rekey` or a re-entered
  credential clears `auth_status` and `/stats` at once but clears `/health` at
  the next restart, which the rotation runbook ends with anyway
  (`docs/11-deployment.md` §12). The container check, `porymcp healthcheck`,
  exits `0` on `degraded`.
- `GET /stats`: dashboard counters (active virtual keys, calls today, error
  rate, …) plus three credential counts computed live from one pass over the
  upstreams, the same pass the boot check makes: `undecryptable_upstreams` (no
  configured key opens the stored credential, which drives the Overview notice),
  `unreadable_upstreams` (nothing stored, or nothing the auth type can send)
  and `upstreams_under_previous_key` (still sealed under an
  `ENCRYPTION_KEY_PREVIOUS` key, so a rotation `porymcp rekey` has not finished;
  the runbook waits for `0`). `auth_type: none` upstreams are never counted.
- `GET /metrics` (optional Prometheus)

---

# Proxy endpoints (what agents use)

All three take `Authorization: Bearer <api_key>`: the virtual key, never the
admin key.

- Per member: `POST /{virtual_key_id}/{upstream_slug}/mcp`: **the primary
  endpoint for a group key**. A pure 1:1 proxy to that one member: its original
  tool names, its own `initialize`, capabilities, instructions, prompts,
  resources and sessions. A group key has one of these per enabled member, and
  they are listed as `endpoints` on every virtual-key response.
- Aggregate: `POST /{virtual_key_id}/mcp`: the single-connection view of the
  same key: one merged catalogue, a synthesised `initialize`, no upstream
  session. On a single-upstream key this *is* the 1:1 endpoint.
- Shared: `POST /mcp`: the same door without the id in the path; the key
  identifies the virtual key. `POST //{upstream_slug}/mcp` (the same door with
  the id left empty) is its per-member analogue, resolved against the caller's
  own key. An empty *slug* (`POST /{virtual_key_id}//mcp`) is not an endpoint
  and answers the `404` below.

A key used on another key's path is rejected `403`, **before the request body is
read**.

A slug that is not an enabled member of this key's group is rejected `404`,
identically for every reason it can miss: a slug no upstream carries, a slug
belonging to an upstream outside this key's group, a disabled member, a member
removed from the group, any slug at all under a single-upstream key, and a group
with no enabled members. The body is the JSON-RPC error below, carrying the
request's own id, and one `blocked` audit row is written:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown endpoint"}}
```

The URL segment is validated with the same rule that governs a stored slug
before any lookup, and the proxy resolves it only among this key's own enabled
members (it never looks a slug up across the deployment), so one valid key
cannot enumerate another group's upstreams.

A group `tool_filter.tools` entry and a key allow/deny entry name one tool on
one member as `{upstream_slug}__{tool}`, and that identity is the same on every
path: the per-member endpoint, the aggregate endpoint, and a single-upstream
key. One entry is enforced everywhere that key reaches. An entry written without
a slug is *unscoped* and matches that tool name on every member: allowed in a
deny rule, refused in an allow rule on a group. `tool_filter.prefixes` entries
take both forms too, but are matched against the upstream's **own** tool name
rather than the composed one: write `delete_`, or `github__delete_` to scope it.
See `docs/07-security.md`.

Primary transport: **Streamable HTTP**.  
SSE support as fallback if needed. A `GET` for an SSE stream is forwarded and
**buffered**, not streamed, on all three paths: a stream the upstream holds
open fails at the proxy's 60 s upstream timeout with `502` (PORM-30 owns the
`405`, PORM-5 real streaming).

The proxy:
1. Validates the virtual key
2. Resolves the target (Upstream or Group)
3. On `/{virtual_key_id}/{upstream_slug}/mcp`, resolves the member named by the
   slug among the target group's **enabled** members, or answers `404`
4. Applies tool policy: the group `tool_filter` plus the key's
   `tool_allowlist`/`tool_denylist`
5. Injects real upstream credentials
6. Forwards the JSON-RPC request to the upstream's own URL, and never to a host
   the upstream names in a redirect (a `3xx` answer ends the call)
7. Filters a `tools/list` response down to what the key may call
8. Writes an AuditLog entry
9. Returns the response

Policy is applied **before** credentials are injected, so a blocked call
contacts no upstream and never presents the real secret. A call that *is*
forwarded presents it to the upstream's own URL, and never to a host the
upstream names in a redirect: a `3xx` answer is a failed call, not a hop.

Those nine steps are the whole of what a *virtual key* can make PoryMCP do. The
only other requests that leave the process carrying a real credential are the
two discovery routes above (`POST /api/v1/upstreams/{id}/discover` with a
stored credential and `POST /api/v1/upstreams/discover` with one from the body),
which an operator makes with the admin key: the same client construction, the
same injection and the same refusal to follow a redirect, but no virtual key, no
policy gate and no audit row. `docs/07-security.md` says what that means.

## Blocked tools

A `tools/call` for a tool the virtual key may not invoke is a failed tool call,
not a failed transport. It answers `200` with a JSON-RPC error carrying the
request's own id:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"tool blocked"}}
```

The shape is the same on a group target, on a per-member endpoint and on a
single-upstream virtual key.
(Before v0.1 the single-upstream path answered `403` with
`-32000 "tool is not allowed for this virtual key"` and `"id": null`, which
most MCP clients report as a broken connection rather than one refused call.)
A blocked **notification** (a `tools/call` sent without an `id`, so there is
no reply to correlate) answers `202` with an empty body. `tools/list` is
filtered through the same policy, so a blocked tool is normally not advertised
in the first place.

Requests the proxy cannot evaluate are refused with HTTP `400` before any
upstream is contacted:

| Request body | JSON-RPC error |
| --- | --- |
| A batch (`[{…},{…}]`) | `-32600 "batch requests are not supported"` |
| Not valid JSON (trailing garbage, a BOM, …) | `-32700 "parse error"` |
| `id` present but not a string, number or null | `-32600 "invalid request"` |
| A spelling variant of `tools/call`/`tools/list` (`Tools/Call`, `tools/call `) | `-32600 "invalid request"` |
| An envelope or `params` object with two spellings of one member name (`"method"` and `"Method"`) | `-32600 "invalid request"` |

The last of those is refused because Go binds a member name
case-insensitively and keeps the last match, while a JavaScript or Python MCP
server looks the name up exactly. `{"method":"tools/call","Method":"ping",…}`
would therefore be judged as `ping` by the proxy and executed as `tools/call`
by the upstream. Only the envelope and `params` are checked; `arguments` are
forwarded verbatim and never read here.

A `tools/call` whose `params.name` is missing, is not a non-empty string, or
contains U+FFFD or a control character answers `200` with
`-32602 "invalid params: tools/call requires a tool name"`. Go's decoder
substitutes U+FFFD for a lone surrogate or an invalid byte that a JavaScript or
Python client keeps, so such a name is not one the proxy can hold the caller
to: it would authorise a different string from the one the upstream runs.

Every policy rejection writes an audit row with `status = "blocked"`, so
`GET /api/v1/logs?status=blocked` is the list of them. The row carries
`method`, `tool_name`, `virtual_key_id` and the rule that rejected the call in
`error_message`. `upstream_id` is the targeted upstream on a single-upstream key
**and on a per-member endpoint** (both know the upstream from the target or the
URL without contacting it), and empty on the aggregate group endpoint, where the
block happens before a member is chosen. The `404` from an unresolvable member
URL is recorded the same way, with an empty `upstream_id` and an
`error_message` naming the endpoint as unknown.

## Unknown tools on the aggregate endpoint

Every tool the aggregate endpoint advertises is named `{upstream_slug}__{tool}`.
A `tools/call` there for a name that is not in that form (no `__`, an empty
half, or a head that is not a valid slug) is a name the proxy never advertised.
It is refused without guessing a member and without contacting any upstream:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unknown tool: search"}}
```

The same answer covers a well-formed name whose slug is not a member of this
key's group, and one whose slug is a member but whose tool no catalogue holds,
so the reply tells a caller nothing about which upstreams the deployment has.
The shape check reads no group, no member and no store: a member's slug and a
stranger's cost the same.

The name is echoed back so a client can see what it sent, truncated to 256 bytes
on a rune boundary, the same bound this row's `tool_name` and `error_message`
take, since nothing is contacted on this path and the reply and the row are its
only cost. The row's `status` is **`error`**, not `blocked`: no rule fired, so
an operator filtering `GET /logs?status=blocked` for policy decisions is not
shown a probe for a name that never existed. The row still carries the name, so
the probing is visible to anyone looking for it. A notification (no `id`)
gets the same envelope with `"id":null`.

Per-member endpoints are unaffected: they forward the upstream's own names
verbatim, and the upstream answers for a name it does not know.

## Upstream failures

When a forwarded call cannot be completed, the client gets `502` with a
JSON-RPC error carrying the request's own id, and the reply is the same
whatever went wrong:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream request failed"}}
```

An audit row with `status = "error"` records which of these it was, in
`error_message`. The row is the only place the detail appears; the client is
told nothing about the upstream's host, address or response. The two transport
rows quote the upstream's own registered URL, query string and all: the URL an
operator chose, not one an upstream named, but one more reason this field is
read by operators and never returned to a key holder (PORM-72).

| Condition | `error_message` on the row |
| --- | --- |
| No configured `ENCRYPTION_KEY` opens the stored credential (the key changed) | `credential undecryptable`: no request was built; the fix is the key, and `auth_status` on the upstream reads `undecryptable` |
| The stored credential is empty or holds nothing its auth type can send | `credential unreadable`: no request was built; the fix is the credential, and `auth_status` reads `unreadable` |
| The upstream answered `3xx` | `upstream redirected to <host>`: the host from `Location`, never the full URL |
| The upstream did not answer within 60 s | `Post "<the upstream's url>": context deadline exceeded (Client.Timeout exceeded while awaiting headers)` |
| The connection was refused, or DNS failed | the same shape, ending `connect: connection refused` or `no such host` |

**A redirect is a failure, not a route.** The proxy never follows an upstream
`Location`: it makes no second request, copies no header from the `3xx` back to
the client, and presents the real credential to the upstream's own URL and never
to a host the upstream names in a redirect. An upstream that works only because
it redirects (an `http://` URL that `301`s to `https://`, a path missing its
trailing slash, a hostname the vendor has moved) stops working, and the row
says so. Fix it with `PATCH /api/v1/upstreams/{id}`. See `docs/07-security.md`
for why.

A `3xx` records `upstream redirected` with no host whenever the proxy cannot
name one safely: no `Location` at all (typically a `304`, which the proxy never
provokes, since it sends no conditional requests), a relative one, one that does not
parse, or one whose host is not plain ASCII. Whichever it is, the message on
this row is bounded at 256 bytes.

On the **aggregate** endpoint the same redirect on a member's catalogue request
writes no audit row: the member is skipped, its tools are absent from the
merged catalogue, and the client's own call succeeds on the members that
answered. The skip is written to the server log as `group member skipped`,
naming the member's slug and its upstream id. Call the member's own
`/{virtual_key_id}/{upstream_slug}/mcp` endpoint to get the `502` and the row.
A `tools/call` the aggregate does route to a redirecting member is not blind:
that one answers `502` and writes a row naming the member's `upstream_id`. A
`tools/call` for one of the *skipped* member's tools answers
`-32602 "unknown tool"` instead, because the name is no longer in the merged
catalogue. The log line is what says why. A member whose stored credential
cannot be used (`credential undecryptable` / `credential unreadable`) is
skipped the same way: zero requests reach it, its tools are absent, the group's
own `tools/list` succeeds, and the `group member skipped` line carries the
cause. The member's own endpoint answers the `502` and writes the row; the
operator's signals are `auth_status`, the counts on `/stats` and the boot line.
