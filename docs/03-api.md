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
response, the same as one that was never set. Validated exactly as on create
means a stored value that create no longer accepts cannot be sent back either:
an upstream stored with `transport: "sse"` (saved before PORM-28) is edited by
omitting `transport` or by sending `streamable-http`, and a body that echoes
`sse` is `400 invalid transport`.

| Field | value | `null` | `""` / `[]` / `{}` |
|---|---|---|---|
| `name` (all three) | trimmed and set | `400 name cannot be empty` | `400 name cannot be empty` (whitespace-only too) |
| upstream `slug` | equal to the stored slug: no-op; anything else: `400 slug cannot be changed after create` | same `400` | same `400` |
| upstream / group `description` | set | **cleared** | **cleared** |
| upstream `url` | set, stored normalised (see Upstream URLs); `400 url must be an absolute http or https URL`, `400 url must not carry a fragment` or `400 url must not embed credentials` if not; resets the last test when it differs after normalisation | that `400` | that `400` |
| upstream `transport`, `auth_type` | set; `400 invalid transport` / `400 invalid auth_type` if not an allowed value (`sse` is not one: `streamable-http` is the only transport accepted on write); resets the last test when it differs. `auth_type: "none"` also removes the stored credential (the column is emptied and `auth_configured` reads `false`) and resets the last test when one was stored; a credential sent beside it is `400 auth_config cannot be set when auth_type is none` | that `400` | that `400` |
| upstream `auth_config` | replaces the stored credential; resets the last test; `400 auth_config cannot be set when auth_type is none` when the same request names `auth_type: "none"` | **kept**: the value is write-only, so an object read back and sent again cannot carry it; `null` therefore means unchanged, unless the same request names `auth_type: "none"`, which removes the stored credential (see Removing a credential) | `{}` stores nothing: an object with no members is no credential, on create and on patch alike, so the column is emptied, the row reads `auth_configured: false` and, on a type other than `none`, `unreadable`, and the proxy stops authenticating; a client that did not change the credential omits the key (the dashboard's edit dialog does) |
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
`details.cleared` (see Admin events), beside one entry that is not a field
name: `credential`, recorded when a request removed an upstream's stored
credential.

**Round-trips.** An edit form must omit `auth_config`, `tool_filter`,
`tool_allowlist` and `tool_denylist` when the operator did not touch them. The
stored credential cannot be resent, and only a filter or list the request sends
is judged: one that predates today's validation rules keeps working until
someone rewrites it, but sent back unchanged it is judged by the current rules
and may be refused (see Tool lists). The dashboard follows this rule by
comparing meaning, not bytes: a filter or list whose entries are the same set
is not sent, and "No filter" is sent as `null`, never `{}`, so what is stored
and what is served agree.

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
- `POST   /upstreams/{id}/oauth/start`
- `POST   /upstreams/{id}/oauth/revoke`
- `GET    /oauth/callback` (no admin key; answers HTML)
- `GET    /oauth/client-metadata` (no admin key)

### Connecting an OAuth upstream
An upstream with `auth_type: "oauth"` (PORM-139) holds no credential an
operator can paste. `POST /upstreams` with that type and no `auth_config`
answers `201` with `auth_status: "unreadable"`, `auth_configured: false` and
an `oauth` object (`expires_at: null`, `has_refresh_token: false`,
`client_source: null`): the row is not connected. `auth_config` for this type
accepts `client_id` and optionally `client_secret`, the client identity a
vendor issued in its own settings, and nothing else:
`400 {"error":"auth_config for oauth accepts client_id and client_secret only"}`.
Writing a new client drops any stored token set, recorded as
`cleared: ["credential"]`.

`POST /upstreams/{id}/oauth/start` learns the authorization server from the
upstream (the `WWW-Authenticate` challenge's `resource_metadata`, then the
RFC 9728 well-known path, then the origin root; then the RFC 8414 document),
chooses the client identity, holds the sign-in in memory for ten minutes and
answers `200 {"authorization_url", "expires_in": 600, "issuer": "<host>",
"client": "document"|"registered"|"supplied"}` with `Cache-Control:
no-store`. The body is optional: `{"client": "registered"}` forces RFC 7591
dynamic registration where the vendor cannot fetch this PoryMCP's client
metadata document (an allowlisted or private deployment); `document` forces
the document. The client identity is chosen in this order: a supplied
client; a registration stored from an earlier connect whose issuer and
redirect URI still match; the client metadata document when the vendor
advertises support, `PUBLIC_URL` is https and its host is not loopback;
dynamic registration; else
`400 {"error":"the authorization server offers no way to register PoryMCP; enter a client ID"}`.
`{"client": "document"}` on an http or loopback `PUBLIC_URL` is refused
before anything is dialled:
`400 {"error":"a client metadata document needs an https PUBLIC_URL the vendor can fetch; use registered or enter a client ID"}`.
A supplied client is bound to the issuer that first accepted it; a different
issuer later answers
`400 {"error":"the stored client ID belongs to another authorization server; enter it again"}`.
`PUBLIC_URL` is the redirect URI's origin: it must be https, or http on a
loopback host, or http with `ALLOW_INSECURE_HTTP`, else
`400 {"error":"PUBLIC_URL must be an https address to connect an OAuth upstream"}`;
a `PUBLIC_URL` that does not parse as an http or https address is
`400 {"error":"PUBLIC_URL is not a valid URL; set it to the address the browser uses"}`;
a loopback `PUBLIC_URL` reached from another address is refused with both
values. A metadata, host-rule, redirect or registration failure is `502`
with one fixed sentence from the OAuth client's closed set, never a byte the
vendor sent, and one Warn line with the stage, the status and the host. A
metadata or registration address that resolves to a refused range, the
upstream's own host included, is
`502 {"error":"authorization server address denied: <class>"}`, the class
only (see Upstream failures). The token endpoint is dialled later: a refusal
at the callback shows the callback's generic failure page and logs
`exchange`; on a refresh the audit row reads `credential refresh failed`. The
metadata walk and a registration share one ten-second budget. The route
spends the discovery budgets and records nothing; the connect is recorded
by the callback. Sixty-four sign-ins may be pending at once, one per
upstream (a new start replaces that upstream's earlier one); past that the
route answers `429 {"error":"too many pending sign-ins; wait for one to expire"}`
with `Retry-After: 60`. The authorization URL carries `code_challenge`
(S256), `state`, `redirect_uri={PUBLIC_URL}/api/v1/oauth/callback` and
`resource=<upstream url>` (RFC 8707). Anyone holding a live authorization
URL can connect the upstream to their own vendor account within ten
minutes; the admin event shows the connect.

`GET /oauth/callback?code&state[&iss]` is the one route that needs no admin
key and the one that answers `text/html`: the vendor sends the operator's
browser here. Every answer is a fixed page with `Cache-Control: no-store`
and a link to the Upstreams page, and nothing from the query enters a page.
In order: a per-address budget of ten callbacks a minute answers `429` with
`Retry-After` before the state is touched, so a reload keeps its state; the
state is taken and deleted (single use, ten minutes); `error=` from the
vendor is `400` (the page names the code only when it is one of the seven
RFC 6749 values); `iss` is compared with the issuer pinned at start before
any exchange (RFC 9207), and is required when the server advertised it:
`502` on a mismatch; the row must still read the `updated_at` the flow
started with and still be `oauth`, else `409` (or `404` when it is gone);
the code is exchanged at the pinned token endpoint on the server's own
context, so a browser that goes away cannot abandon a redeemed code (`502`
on a failure); the token set is sealed and written under the per-upstream
lock, waited for up to twelve seconds so a refresh in flight on the same
row finishes first (`503` with a page that says the upstream was busy and
nothing was stored, when it does not); `upstream.oauth_connect` is recorded
and the page reads `200`. On a
`200` the row reads `auth_status: "ok"`, `auth_configured: true` and an
`oauth` object with `expires_at`, `has_refresh_token` and `client_source`.
The same state a second time is `400` and records nothing.

From then on the proxy and `POST /upstreams/{id}/discover` present the
access token and renew it: when `expires_at` is within sixty seconds the
refresh grant is posted to the stored token endpoint under a process-wide
per-upstream lock, so ten concurrent calls cost one refresh, and the new set
replaces the old by a compare-and-swap that leaves `updated_at` alone. One
`upstream.oauth_refresh` event is recorded per refresh (actor `proxy` on a
proxied call, `admin` from the discover route), about one per token lifetime
per upstream. Inside that window the stored token is still presented when
the vendor cannot be reached, and the vendor is not asked again for thirty
seconds. A refresh the vendor refuses (`invalid_grant`, `invalid_client`)
drops the refresh token: the row reads `auth_status: "expired"` once the
access token lapses, and the fix is Connect again. A vendor that issued no
refresh token gives the same outcome at `expires_at`. `expired` is derived
from the stored set on every read, never stored.

### Disconnecting an OAuth upstream
`POST /upstreams/{id}/oauth/revoke` takes the per-upstream lock, asks the
vendor's revocation endpoint (RFC 7009) to revoke the refresh token (or the
access token when there is none) when the stored set names one, then empties
the column, the client identity included, and records
`upstream.oauth_revoke` with `cleared: ["credential"]` and
`vendor_revocation`. It answers
`200 {"upstream": <the row>, "vendor_revocation": "revoked"|"failed"|"not_offered"|"no_token"}`:
the local clear always happens once the vendor was asked, and `failed` says
the vendor did not confirm it. `no_token` is a row that held only a client
identity (cleared) or nothing (no write, no event). A grant that landed on
the row after the vendor call is never cleared:
`409 {"error":"upstream changed; try Disconnect again"}`. The lock is waited
for on the request's own context; when it cannot be taken the answer is
`503 {"error":"upstream is busy; try again"}`, as it is for a `PATCH` that
writes an `oauth` row. `PATCH {"auth_type": "none"}` on an `oauth` row
removes the token set without asking the vendor (see Removing a
credential). Disconnect also forgets a dynamic registration; the next
Connect registers again or uses the document.

### OAuth client metadata
`GET /oauth/client-metadata` serves the Client ID Metadata Document, without
a key and with `Cache-Control: public, max-age=300`: PoryMCP's client id is
this document's own URL, and a vendor's authorization server fetches it when
PoryMCP identifies itself that way. It carries `client_id`, `client_name`,
`redirect_uris` (`{PUBLIC_URL}/api/v1/oauth/callback`), `grant_types`,
`response_types`, `token_endpoint_auth_method: none` and `application_type:
web`, built from `PUBLIC_URL` alone and never from the request's `Host`. It
is the one OAuth document PoryMCP publishes: PoryMCP is a client of an
upstream's authorization server, never an authorization server itself.

### Removing a credential
`PATCH /upstreams/{id}` with `{"auth_type": "none"}` stops the upstream
sending a credential and removes the stored one: the `auth_config` column is
emptied, the `200` reads `auth_configured: false, auth_status: "none"` with
`last_test_at` and `last_test_ok` reset to `null`, and the admin event records
`cleared: ["credential"]`. The same request on a row that is already `none`
and still holds a value (a credential switched to None by an earlier build, or
the empty object earlier builds sealed for a blank box) removes it too; on a
row with nothing stored it changes nothing and keeps the recorded test. A
credential sent beside `auth_type: "none"`, on create (an omitted `auth_type`
defaults to `none`) or on patch, answers
`400 {"error":"auth_config cannot be set when auth_type is none"}` and nothing
is written. A credential sent alone to a row stored as `none` is stored, as
before, and is not sent until the type changes. The removal is a row update,
not an erasure of the database file, its write-ahead log or backups (see
`docs/07-security.md`).

### Upstream URLs
`url` must be an absolute `http` or `https` URL with a host, no fragment and
no embedded credentials. `POST /upstreams`, `PATCH /upstreams/{id}` and the
unsaved discover route (`POST /upstreams/discover`) answer `400` with one of
three sentences:
`url must be an absolute http or https URL` (a bare `localhost:3001/mcp`, a
`file:` or `ftp:` scheme, a scheme-relative `//host/mcp`, a scheme with no
host), `url must not carry a fragment` (`https://host/mcp#frag`) and
`url must not embed credentials` (`https://user:pw@host/mcp`, on every kind
since PORM-79; rows saved before it are PORM-27's), so a URL PoryMCP could
never connect to is refused where it is typed rather than where it is used.
The syntax check is the one discovery applies before it opens a socket
(`mcpclient.CheckTarget`). The stored value is the URL as `url.Parse`
re-serialises it: the scheme lower-cased, unescaped path characters
percent-encoded (`/a b` becomes `/a%20b`) and an empty fragment dropped;
the host keeps its case, the port stays and a trailing slash is kept. A `PATCH` that sends
the same URL in either spelling is not a URL change: it keeps the recorded
test and, on an `oauth` upstream, the token set.

Where the host resolves is checked when PoryMCP connects, not when the URL is
saved: the transport refuses an address in a loopback, link-local, metadata,
multicast or unspecified range (and a private one under
`UPSTREAM_DENY_PRIVATE`), see `docs/07-security.md` and Upstream failures.

On an `http` upstream (see Upstream kinds) the URL is the API's base URL and
one more rule applies, on create, on `PATCH` and on the unsaved probe: it must
carry no query string (`400 {"error":"url must not carry a query string"}`),
because a caller's query is appended and the two must not merge
(`mcpclient.CheckHTTPBase`). The userinfo rule above was this kind's alone
before PORM-79, because Go's transport would send it as
`Authorization: Basic`; it now applies to every kind.
A path is fine, trailing slash or not: `https://api.example.com/v1` and
`https://api.example.com/v1/` both put a caller's `users` at `/v1/users`.

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

### Upstream kinds

`kind` says what the URL is: `mcp` (the default when omitted, `null` or
`""`; an MCP server, relayed as JSON-RPC) or `http` (a plain HTTP API,
relayed request for request through `/{virtual_key_id}/api/*`, see HTTP API
relay under Proxy endpoints; PORM-146). Anything else is
`400 {"error":"invalid kind"}`. Every upstream response carries it, never
empty. Like `slug` it is fixed at create: `PATCH /upstreams/{id}` with a
different value answers `400 {"error":"kind cannot be changed"}`, the same
value is a no-op that is not listed in the admin event's `fields`, and
omitting it keeps it. Delete and recreate to change it. The four rules that
follow `kind`, checked on create, on `PATCH` against the merged row, and on
`POST /upstreams/discover`:

| rule | on `http` | on `mcp` |
| --- | --- | --- |
| `test_path` (optional, `""` clears on `PATCH`) | a path the connection test requests, joined under `url`: must begin with `/`, be at most 256 bytes, hold no `?`, `#` or control character and no `.` or `..` segment in any encoding, else `400` with the reason (`test_path must begin with /`, `test_path is longer than 256 bytes`, `test_path must not contain a query or fragment`, `test_path must not contain a control character`, `test_path must not contain a .. segment`). A change resets `last_test_at` and `last_test_ok` and lists `test_path` in `fields` | anything but empty is `400 {"error":"test_path applies to an HTTP API upstream"}` |
| `url` | no query string, no userinfo (see Upstream URLs) | as before |
| `auth_type: oauth` | `400 {"error":"oauth is not available on an HTTP API upstream"}`, on create, on `PATCH` and on `POST /upstreams/{id}/oauth/start` | as before |
| `transport` | validated as before and stored at its default; it means nothing on this kind | as before |

`POST /upstreams` for an HTTP API:

```json
{"name":"GitHub","kind":"http","url":"https://api.github.com","test_path":"/user","auth_type":"bearer","auth_config":{"token":"ghp_…"}}
```

answers `201` with `"kind":"http"`, `"test_path":"/user"` and the other
fields as on any upstream. The stored credential is presented to the base URL
exactly as an MCP credential is: `bearer` as `Authorization: Bearer`,
`api_key` as `X-API-Key`, `header` and `custom` in the named header.

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
An `oauth` upstream is discovered by the saved route only, after it is
connected: the unsaved route answers
`400 {"error":"oauth upstreams are discovered after they are connected: create the upstream, connect it, then call POST /upstreams/{id}/discover"}`.
On the saved route the stored token is presented and renewed as the proxy
renews it (see Connecting an OAuth upstream); a set whose access token has
lapsed with no refresh token, or whose refresh the vendor refused, answers
`200` with `ok: false` and `error: "stored credential has expired; connect again"`,
and a vendor that could not be reached after the token lapsed answers
`ok: false` with `error: "the token could not be refreshed; try again"`.
`POST /upstreams/{id}/discover` writes exactly two fields on the upstream's own
row, `last_test_at` and `last_test_ok`, on every run that completes, pass or
fail, including a refused transport and an undecryptable stored credential. A
`429`, a cancelled request, and a run whose upstream was edited or deleted while
it ran record nothing. The catalogue itself is not stored (PORM-113).

On an `http` upstream both routes run a **probe** instead of a handshake
(PORM-146): one `GET` of `url` joined with `test_path` (`test_path` and
`kind` are read from the body on the unsaved route), with the credential,
`Accept: */*`, a 10 s budget and no redirect followed. The answer is

```json
{"ok":true,"kind":"http","http_status":200,"latency_ms":140,"tools":[],"tool_count":0,"unnameable_tools":0,"truncated":false}
```

`ok` is a 2xx status. `kind` is on every discovery response, `mcp` or `http`,
on the failure paths too, so a client can branch on it; `http_status` is
present when the upstream answered at all. `error` on a failed probe is one
of `upstream rejected the credential (401)` (or `403`),
`upstream answered 404; check the test path`, `upstream answered N`,
`upstream redirected to <host>`, the transport sentences discovery uses
(`cannot resolve <host>`, `cannot connect to <host>`,
`tls handshake with <host> failed`, `upstream address denied: <class>` with
the loopback remedy clause discovery adds), `upstream did not answer within
10s`, and the credential sentences shared with discovery. The response body is drained
(at most 2 MiB) and never returned; `tools` is `[]` and no server, era or
version field is present. The saved route records `last_test_at` and
`last_test_ok` on the same terms as a handshake; `ok: false` from a `401` is
a failed test.

Both are admin-only, and both answer `200` whether or not the upstream answered:
the HTTP status describes the request PoryMCP received, `ok` describes the
upstream. They are `POST` rather than `GET` because the call has an effect
outside PoryMCP (a real MCP handshake against a host an operator named, using a
real credential), and a `GET` is the kind of thing browsers, proxies and link
checkers fetch on their own. `GET /upstreams/discover` is not a route at all: it
falls through to `GET /upstreams/{id}` with `discover` as the id and answers the
ordinary `404 {"error":"not found"}`.

Each call first asks the upstream which MCP era it speaks, then talks to it that
way. Step 0 is `server/discover` on the 2026-07-28 revision: the request carries
`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: server/discover` and the
`params._meta` every request of that revision carries (the protocol version,
`clientInfo` and empty `clientCapabilities`). It has five seconds of the budget
below and reads at most 2 MiB. What comes back decides the rest:

- **Modern.** A `200` whose result, in the document that answers the probe's own
  JSON-RPC id, carries a `supportedVersions` array that lists `2026-07-28`.
  `tools/list` is then followed to the end of its cursors, each request carrying
  the same two headers (with `Mcp-Method: tools/list`) and the same `_meta`.
  There is no `initialize`, no `notifications/initialized`, no session and no
  `DELETE`: that era has none of them.
- **Modern, and not one PoryMCP can speak to.** A `400` whose JSON-RPC error is
  `-32020`, `-32021` or `-32022`, or a `200` whose `supportedVersions` is empty
  or lists nothing PoryMCP speaks. Discovery fails with one of three sentences
  (below) and there is no fallback: a server of that era has no handshake to
  fall back to.
- **Legacy.** Everything else: any other status, `-32601`, the reference
  server's `-32000` "not initialized", a `404` page, a body that is not
  JSON-RPC, a `200` with no `supportedVersions`, or no answer at all. So is a
  server that answers `server/discover` (or `-32022`'s `data.supported`) with
  only handshake revisions (`2025-11-25`, `2025-06-18`, `2025-03-26`,
  `2024-11-05`): it has said how to talk to it. The handshake a client would make
  follows, exactly as before this probe existed: `initialize` asking for
  `2025-11-25`, `notifications/initialized`, `tools/list` followed to the end of
  its cursors, then a `DELETE` of the session so none is left open on the
  upstream. What the server answers `initialize` with is the version recorded
  and declared from then on.

Only those three codes, on a `400`, count as a modern server refusing. `-32601`
does not, although the revision lists it as a modern server's answer to a method
it does not know: a modern server must implement `server/discover`, and a
handshake server answering `-32601` is the common case.

The whole sequence, probe included, is bounded at 10 seconds and the teardown at
a further 2, so a hung upstream cannot hold an admin request open; the proxy's
own relay budget (five minutes for a buffered answer) is for a client's call,
not for answering the dashboard. A server slower than five seconds to answer `server/discover` is
treated as legacy and gets what is left of the ten for its handshake.

```json
{
  "ok": true,
  "latency_ms": 140,
  "era": "legacy",
  "protocol_version": "2025-11-25",
  "capabilities": ["tools", "resources", "prompts", "completions"],
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

A 2026-07-28 server's answer differs in four fields:

```json
{
  "ok": true,
  "era": "modern",
  "protocol_version": "2026-07-28",
  "supported_versions": ["2026-07-28"],
  "capabilities": ["tools", "io.example/search"],
  "server_info": { "name": "stateless-server", "version": "2.0.0" }
}
```

`era` is `modern` or `legacy`. It is evidence and never a default: `modern` when
the probe was answered as a modern server (a usable one or not), `legacy` when
the probe got an HTTP response that was not modern or when `initialize`
completed, and absent when nothing came back or a request was refused before
any I/O. `protocol_version` is the version discovery ended up speaking:
PoryMCP's own `2026-07-28` on a modern server, the negotiated one on a legacy
server, absent when none was agreed. `supported_versions` is what the server
said it supports, from its `server/discover` answer or a `-32022`'s
`data.supported`: at most 8 entries, each at most 32 bytes of visible ASCII. An
entry that is anything else is dropped, never repaired, because a version is a
token and scrubbing one would show an operator a version the server never sent.
A legacy server normally has none, because `protocol_version` already holds the
one version it negotiated. `capabilities` is the names of what the server
advertised and never the settings under them: `tools`, `resources`, `prompts`
and `completions` in that order when present, then the keys of its `extensions`
object, sorted, at most 16 in all, each at most 128 bytes of visible ASCII.
Those names and nothing else, so it is not the server's whole advertisement: a
legacy server's come from its `initialize` result, where `logging` and the
`experimental` bucket are never listed, and their absence here says nothing
about the server. A modern server that answered
with a full result and no version PoryMCP speaks keeps its `server_info` and
`capabilities` on the failure; the three error codes carry neither.
`server_info` on a modern server is `_meta["io.modelcontextprotocol/serverInfo"]`
of its answer, and may be absent. Neither list touches `truncated`. The server's
`instructions` are never carried: they are prompt content (PORM-83).

These fields are what the upstream answered just now. The proxy keeps its own
memory of each group member's era (see `docs/04-architecture.md`), for up to ten
minutes, so the panel and the proxy can disagree for that long after a server
changes. Saving the upstream makes the proxy ask again; a passing discovery on
its own does not.

Every field is either PoryMCP's own or a clamped copy of something the upstream
said, and there is nothing else in the body. `error`, present only when `ok` is
`false`, is one of a closed set of sentences composed from a status code, a
host name and the step that failed. The era probe adds three to that set, each a
fixed string: `upstream supports no protocol version PoryMCP speaks` (`-32022`,
an empty `supportedVersions`, or a list with nothing PoryMCP speaks; what the
server does support is in `supported_versions`), `upstream refused the routing
headers PoryMCP sent (-32020)`, and `upstream requires a client capability
PoryMCP does not offer (-32021)`. Every other outcome of the probe has no
sentence of its own: it falls through to the handshake, which reports in the
words it always used. `upstream_message` carries the upstream's
own JSON-RPC `error.message`, single line, visible characters, at most 200
bytes, and it is a separate field precisely so that `error` stays a string
PoryMCP wrote: "token lacks the `repo` scope" is the answer an operator came
for, but it is the upstream talking. `latency_ms` is the whole handshake,
rounded to 10 ms, the era probe included: enough to tell a slow server from a
fast one, blunt enough not to be a stopwatch on the network PoryMCP sits in. On
a legacy server `protocol_version` and `server_info` are what came back from
`initialize`, clamped to 32, 128 and 64 bytes. Every upstream-controlled string PoryMCP carries (`description`,
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
`tls handshake with <host> failed` are the network. `upstream address denied:
<class>` is the egress guard: the host resolved to a `loopback`, `link-local`, `metadata`, `private`, `multicast` or `unspecified`
address, and the sentence names the class, never the address. For the
loopback class discovery and the probe append the remedy
`; on a bare binary set UPSTREAM_ALLOW_LOOPBACK=true, in a container use host.docker.internal`; the audit rows keep the bare sentence. `upstream did not answer
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
report a working server as one that does not speak JSON-RPC. On the unsaved
route a `transport` of `sse` is `400 invalid transport`, the same refusal
`POST /upstreams` gives it. On the saved route a row stored as `sse` before
PORM-28 answers `200` with `ok: false` and the fixed sentence
`the sse transport is not implemented yet; use streamable-http` instead of
hanging, and a URL that is not an absolute `http` or `https` URL is refused
before any request is made. A stored credential that exists but cannot be
decrypted, after a rotated `ENCRYPTION_KEY`, answers
`stored credential cannot be decrypted` and makes **no** outbound request at
all: sending an unauthenticated one instead would come back as a `401` that
looks exactly like a bad token; `auth_status` on the row says which it is. A
row with nothing stored, or a stored credential that decrypts but holds nothing
its auth type can send (a `bearer` row switched to `custom`), answers
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
a different `url`, `transport` or `auth_type`, `auth_type: "none"` over a
stored credential (the request that removes it, see Removing a credential), or
any `auth_config` in the body other than an explicit `null`, since a credential
is encrypted under a fresh nonce and two ciphertexts of one secret never
compare equal. `name`, `description` and `enabled` never reset it, and neither
does `auth_type: "none"` on a row with nothing stored. The reset is in the body of the
`200` the `PATCH` itself returns, not only in the next `GET`. Recording a test
does not move `updated_at`: a test is not an edit. Every `PATCH` is one and does
move it, `{}` included (see Partial updates).

### auth_status

Every upstream response also carries `auth_status`, PoryMCP's verdict on the
stored credential (PORM-52): `none`: `auth_type` is `none`, the upstream sends
no credential and nothing stored beside it is consulted; `ok`; `undecryptable`:
no configured `ENCRYPTION_KEY` (current or `ENCRYPTION_KEY_PREVIOUS`) opens
the stored value: the key changed, and the fix is a key; `unreadable`: nothing
is stored (a blank credential box stores nothing), or the value opens but holds
nothing the auth type can send: the fix is the credential, never the key. The proxy
refuses to call an `undecryptable` or `unreadable` upstream (see Upstream
failures). A fifth value, `expired`, belongs to `oauth` rows (PORM-139): the access
token has lapsed and there is no refresh token to renew it, because the
vendor issued none or refused the last refresh; the fix is Connect again.
The proxy refuses to call an `expired` upstream (`credential expired` on the
audit row). A lapsed token that still has a refresh token reads `ok`: the
next call renews it. An `oauth` row that is not yet connected reads
`unreadable`, with `auth_configured: true` when a client identity is stored
and `false` otherwise; the `oauth` object's `expires_at: null` is what says
"not connected". Invariants: `auth_status` is `"none"` iff `auth_type` is `"none"`,
whatever the dashboard stored; `auth_hint` is present only when `ok` and
never on an `oauth` row; `oauth` is present only on an `oauth` row whose
stored value is absent or opens;
`auth_configured` keeps its meaning (a blob is stored) and is independent: a
`bearer` upstream with no credential yet reads `auth_configured: false,
auth_status: "unreadable"`, and `auth_configured: true` with
`auth_type: "none"` means a value is still stored and not sent, whether an
earlier build wrote it or a client sent `auth_config` alone to a `none` row,
which a `PATCH` naming `auth_type: "none"` removes (see Removing a
credential). It is computed live on every read, so it clears the
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
`tool_denylist`, `http_methods` and `metadata` clear on `null`.

`http_methods` (PORM-146) is the list of verbs the key may send through an
`/api/` endpoint: a subset of `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and
`DELETE`, accepted in any case and any order and stored upper-cased,
de-duplicated and in that order (`["get","HEAD"]` reads back as
`["GET","HEAD"]`). A value outside the six is
`400 {"error":"invalid http_methods: FETCH"}` and a repeat, judged after
upper-casing, `400 {"error":"duplicate http_methods entry: GET"}`. Empty,
which every key has until it is set, means every one of the six. Every
response carries it as an array, never `null`. On `PATCH` an omitted field
keeps the stored list, and `[]` or `null` clears it, recorded as
`cleared: ["http_methods"]` even when it was already empty. It is judged on
the relay door only (`403` with `{"error":"method not allowed by virtual
key"}` and a `blocked` row); the MCP endpoints never read it, a key whose
target has no HTTP API can still hold one, and tool lists on a key whose
target is only an HTTP API are accepted and never consulted. Edits are
last-write-wins, as `rate_limit` is (PORM-119 owns a stale check).

Every virtual-key response carries `lists_malformed: true` when the key's
stored tool lists could not be decoded, and leaves the member out otherwise.
A list that did not decode reads back as absent, which is what a key with no
such list looks like, while the proxy refuses every call on the key; this is how
a client tells the two apart. A list that did decode is served as stored. It is response only: a request that sends it changes
nothing. Sending both lists in one `PATCH` replaces them and clears it (see
Tool lists).

`http_methods_malformed: true` is its sibling for `http_methods`: present when
the stored value is not a normalised array (a hand-edited row; this build
never writes one). `http_methods` then reads back as `[]`, every request on
the key's `/api/` endpoint is refused with `403` and a `blocked` row reading
`blocked: virtual key http_methods could not be decoded`, the MCP endpoints
are unaffected, a rename, rotate or revoke leaves the column alone, and a
`PATCH` that sends `http_methods` (a list or `[]`) replaces it and clears the
flag. The start log names such a key once, never its stored text.

### Endpoints

Every virtual-key response carries `endpoints`: a read-only array computed per
response from the target and never stored.

Every entry is a URL that speaks **exactly one upstream, 1:1**: for an MCP
server, that upstream's own tool names, `initialize`, capabilities,
instructions, prompts, resources and sessions; for an HTTP API, that API's
base URL. Each entry carries the upstream's `kind`. For a group target that
is `{PUBLIC_URL}/{virtual_key_id}/{slug}/mcp` for an `mcp` member and
`{PUBLIC_URL}/{virtual_key_id}/{slug}/api/` for an `http` member, one entry
per **enabled** member, in the group's `upstream_ids` order. For a
single-upstream target there is exactly one entry and its `url` **is**
`proxy_url` itself, because that endpoint is already 1:1: `…/mcp` on an
`mcp` upstream and `…/api/` on an `http` one. The `/{slug}/mcp` and
`/{slug}/api/` forms are group-only routes and answer `404` there.

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
      "kind": "mcp",
      "url": "https://porymcp.example.com/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp"
    },
    {
      "upstream_id": "c14b93de-2f55-4c8a-b0e6-71a2d9f43c88",
      "slug": "linear",
      "name": "Linear",
      "kind": "mcp",
      "url": "https://porymcp.example.com/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp"
    },
    {
      "upstream_id": "5b7d2e90-1c4f-4a6b-8e3d-9f0a1b2c3d4e",
      "slug": "github-api",
      "name": "GitHub API",
      "kind": "http",
      "url": "https://porymcp.example.com/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github-api/api/"
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
      "kind": "mcp",
      "url": "https://porymcp.example.com/3f9c0a52-77bd-4f1e-9a35-2c6e8b1d40aa/mcp"
    }
  ]
}
```

A key on a single HTTP API upstream: `proxy_url` ends in `/api/` and the one
entry mirrors it.

```json
{
  "id": "9a1e4c2b-3d5f-4a7b-8c9d-0e1f2a3b4c5d",
  "name": "gh-readonly",
  "proxy_url": "https://porymcp.example.com/9a1e4c2b-3d5f-4a7b-8c9d-0e1f2a3b4c5d/api/",
  "http_methods": ["GET", "HEAD"],
  "endpoints": [
    {
      "upstream_id": "5b7d2e90-1c4f-4a6b-8e3d-9f0a1b2c3d4e",
      "slug": "github-api",
      "name": "GitHub API",
      "kind": "http",
      "url": "https://porymcp.example.com/9a1e4c2b-3d5f-4a7b-8c9d-0e1f2a3b4c5d/api/"
    }
  ]
}
```

- `proxy_url` on a group key is the *aggregate* endpoint and is never an entry.
  It is the `/mcp` URL whatever the members' kinds, even when every member is
  an HTTP API (that aggregate then answers `400 group has no MCP members`);
  an HTTP API member is reached by its own entry only.
- `proxy_url` on a single-upstream key follows the upstream's `kind` whether
  or not the upstream is enabled: a disabled HTTP API target still reports the
  `/api/` URL, with `endpoints` `[]`.
- A member whose stored `kind` is neither `mcp` nor `http` has no entry.
- A member that is disabled, or removed from the group, has no entry, and its
  URL answers `404` on the next request.
- An enabled member whose stored `transport` is `sse` keeps its entry. The
  proxy refuses every request to it with the `502` and a log row, and the
  entry is how an operator reading the key sees which URL that is.
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

On an upstream target both spellings are correct and both are enforced. The
dashboard's picker writes the scoped one on every target, so one identity is
taught and an allow entry fails loudly on a retarget instead of changing what
it means. The cost is on the deny side: a scoped deny entry belongs to that
upstream and stops applying if the key is moved to another, and it does not
govern a prompt or resource of the same bare name. An unscoped deny entry,
added by hand, survives the move.

`PATCH` validates only a list the request sends, and against the target
the key will have **after** the patch, so a body that moves a key onto a group
and sends a new allowlist in the same request is judged as the group key it is
about to become. A list the request does not send is left alone and not
re-checked, so a key written before these rules existed stays renamable,
expirable and revocable.

A key whose **stored** lists cannot be decoded is the one place where leaving an
unsent list alone is not enough. The list that did not decode reads back as
absent on such a key, which would otherwise read as no rule at all, so the proxy
blocks every call on it, and every write leaves the two columns
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
one group's calls for a tool therefore takes the spelling the path uses. On a
relayed HTTP API request (PORM-146) `tool_name` is the request path after
`/api`, beginning with `/` and bounded at 256 bytes, so `?tool=/user` finds
the calls to one path exactly and a path carrying an id is its own value;
`?method=GET` finds every relayed `GET`. A facet or path grouping is
PORM-149's.

`limit` below 1 or not an integer is a `400`; above 200 it is treated as 50.

`since` and `until` take RFC 3339 and are inclusive and exact, at any
fraction of a second. `next_cursor` is opaque; a cursor issued by a build before
schema version 6 still works after the upgrade.

## Admin events
- `GET /admin-events?since=&resource_type=&limit=&cursor=`

Every successful state-changing management call writes one row to
`admin_events` before it answers: create, update and delete of an upstream or
a group, create, update, rotate, revoke and delete of a virtual key
(PORM-54), and the OAuth connect, refresh and disconnect of an upstream
(PORM-139). A row carries `id`, `timestamp`, `actor` (the literal `admin`
until dashboard users land, or `proxy` for a token refresh PoryMCP made on
its own while presenting a credential; a connect is `admin`, because the
admin started the flow, with the browser's address on an unauthenticated
route), `action`, `resource_type`, `resource_id`,
`resource_name`, `details`, `request_id` and `remote_addr`: the client address
after the trusted-proxy rule, so a deployment behind a reverse proxy records
the client rather than the proxy, or the literal `unknown` when there is no
socket address. The response is
`{"admin_events": [...], "next_cursor": "..."}`, newest first; `next_cursor`
is empty on the last page and `admin_events` is `[]`, never null.

`resource_type` is one of `upstream`, `group`, `virtual_key`; any other value
is a `400`, because on an audit endpoint an empty answer would read as
"nothing happened". `since` is inclusive and exact and takes RFC 3339, at any
fraction of a second. `limit` below 1 or not an integer is a `400`; above 200 it
is treated as 50, as on `/logs`. `cursor` is opaque; a malformed one is a
`400`.

| action | details keys |
|---|---|
| `upstream.create` | `slug`, `kind`, `auth_type`, `auth_changed` (when a credential was stored) |
| `upstream.update` | `fields` (`test_path` among the names it can hold), `auth_changed` (when a credential was stored), `cleared` (`credential`, when the stored credential was removed), `auth_type` (when the credential or the type changed) |
| `upstream.delete` | none |
| `group.create` | `upstream_count`, `tool_filter_set` (when a filter that filters something was supplied; `{}` does not count, as on update) |
| `group.update` | `fields`, `upstream_count` (when the membership changed), `cleared` |
| `group.delete` | none |
| `virtual_key.create` | `target_type`, `target_id`, `key_prefix` |
| `virtual_key.update` | `fields`, `cleared` (`http_methods` among the names either can hold) |
| `virtual_key.rotate` | `key_prefix` |
| `virtual_key.revoke` | none |
| `virtual_key.delete` | none |
| `upstream.oauth_connect` | `auth_type`, `client` (`document`, `registered` or `supplied`), `refresh_token` (whether the vendor issued one), `issuer` (the authorization server's host) |
| `upstream.oauth_refresh` | none; `request_id` is the proxied call's, so the row joins its audit row. One per token lifetime per upstream, about a day's worth on the Logs page per hourly token |
| `upstream.oauth_revoke` | `cleared` (`credential`), `vendor_revocation` (`revoked`, `failed`, `not_offered` or `no_token`) |

`details` is a closed object composed by the server, never the request body.
It is always an object, `{}` when there is nothing to add. `fields` names the
fields whose stored value differs after the request, not the keys the body
carried: a client that round-trips the current values records no field, and
sending the current `slug` (which cannot change) records nothing. `cleared`
records that the request nulled or emptied a field (the same names the server
log line carries), or removed the stored credential, and can appear without a
matching `fields` entry when the field was already empty. A stored credential
is reported by `auth_changed`, never by a field: ciphertexts cannot be
compared, so an identical credential sent again shows the flag and no field,
and an object with no members stores nothing and sets no flag. A removed
credential is the word `credential` in `cleared`, the one `cleared` entry that
is not a field name. A `PATCH` with an empty body answers `200` and
records `details: {}`. A value is recorded only when it is a bounded
identifier, enum or count the API already returns in the clear (`slug`,
`kind`, `auth_type`, `key_prefix`, `target_type`, `target_id`, `upstream_count`,
`client`, `refresh_token`, `vendor_revocation`, and `issuer` as a host and
never a path); a
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
  management-API copy is `/api/v1/health` (likewise unauthenticated). The
  only other routes served without the admin key are `GET /oauth/callback`
  and `GET /oauth/client-metadata` (see Connecting an OAuth upstream).

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
  An `oauth` upstream that is not yet connected counts as unreadable, as its
  row reads; an `expired` one counts as fine, because the sweep judges what
  is stored and not when it lapses.

---

# Proxy endpoints (what agents use)

Every proxy endpoint takes `Authorization: Bearer <api_key>`: the virtual key,
never the admin key. The three MCP endpoints come first; the HTTP API relay
(`/{virtual_key_id}/api/*`, PORM-146) has its own section below them.

- Per member: `POST /{virtual_key_id}/{upstream_slug}/mcp`: **the primary
  endpoint for a group key**. A pure 1:1 proxy to that one member: its original
  tool names, its own `initialize`, capabilities, instructions, prompts,
  resources and sessions. A group key has one of these per enabled member, and
  they are listed as `endpoints` on every virtual-key response.
- Aggregate: `POST /{virtual_key_id}/mcp`: the single-connection view of the
  same key: one merged catalogue, a synthesised `initialize`, no upstream
  session. A member's answer to a routed `tools/call` is reduced to the one
  JSON-RPC document that answers the call and sent on as `application/json`,
  whichever framing the member used, with the member's own HTTP status. A
  member's JSON-RPC error therefore reaches the caller with its code, id and
  data unchanged and the credential the proxy injected, and credential-shaped
  text, in its message replaced by `[redacted]`, a protocol error such as
  `-32022` included, and describes the
  member and not the group.
  An answer with no such document in it is passed on as it came when it is
  `application/json` or `text/event-stream`, under that media type; a body in
  any other media type keeps the member's status with no body when that status
  is `400` or above, and gets the caller a `502` and an `error` row otherwise.
  On a single-upstream key this *is* the 1:1 endpoint, and the upstream's
  answer is relayed as it came, with two exceptions. The message of a JSON-RPC
  error is redacted as described under the audit row's `error_message`, on
  every MCP endpoint. A body with a status of `400` or above that is not a
  JSON-RPC error envelope, such as a gateway's plain-text, HTML or JSON `401`,
  keeps its status and `Content-Type` and has the credential the proxy
  injected, and credential-shaped text, replaced by `[redacted]` on a
  single-upstream key and a member endpoint, whatever its
  media type apart from an event stream; on the aggregate endpoint only a JSON
  one crosses, as the sentence above says, and it is redacted the same way.
  JSON up to 64 KiB is decoded and scanned, and comes back compact with its
  members in sorted order when a decoded string held the match; a body the
  rules would leave unparseable, or a body that opens as JSON, gets no walk
  (over 64 KiB, or not parsing) and holds a `\u` or `\/` escape, answers `502`
  with `upstream request failed`; any other body, a longer JSON one included,
  is cut at 64 KiB at a value boundary, so a cut JSON body no longer parses;
  one with nothing credential-shaped, and none of the injected credential,
  under that bound crosses byte for byte.
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

Transport to upstreams: **Streamable HTTP**, and nothing else. The legacy
HTTP+SSE transport is not implemented; `sse` is refused on write since
PORM-28, and a row stored with it before then is refused on every request (see
Upstream failures below). `POST` carries every call. A `GET`, which a client
opens after `initialize` to listen for server-initiated messages, is answered
`405` on all three paths with `Allow: POST, DELETE, OPTIONS` and the body
below, before the virtual key is read and without contacting any upstream. A
client that treats the stream as optional carries on, which is what the
transport prescribes. `DELETE` is a session teardown and is forwarded to the
upstream with the client's `Mcp-Session-Id`; the upstream decides whether the
session ends. `OPTIONS` answers `204` with the same `Allow`. Any other method
the router recognises, `HEAD`, `PUT` and `PATCH` included, gets the same
`405`; a method token the router does not know is refused by the router itself
with a bare `405` and no `Allow`. A refused verb contacts no upstream and
presents no credential, so it appears in the server log and not in
`audit_logs`. A `GET` stays refused: in the 2026-07-28 revision a server's
messages arrive on the response to a `POST`.

```json
{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"method not allowed"}}
```

An upstream that answers a `POST` with `text/event-stream` and a 2xx status is
relayed as it arrives on a member or single-upstream endpoint: the headers and
`X-Accel-Buffering: no` go out first, then a comment line, a field line
(`event:`, `id:`, `retry:` or any field name) and a blank line outside an
event reach the client as they arrive, keep-alive lines included. An event
that carries data is sent once its ending line arrives, so an error inside it
can be redacted first. A result over 1 MiB whose first megabyte does not show
it is a result or a notification reaches the client when it ends, and a stream
ends when an event that may be an error passes 16 MiB. A bare JSON document
under the `text/event-stream` label, which has no ending line, is sent when
the upstream closes the stream. The stream stays open until the upstream or the
client closes it, the upstream sends nothing for five minutes, the key stops
being valid or the upstream stops being reachable through it or is edited
(checked once a minute; a store error during that check leaves the stream
open), or the proxy
stops; a client that closes it, or that stops reading it until a write to it
has waited five minutes, cancels the upstream request. A `tools/list` answer, an answer with status 400 or above,
an answer not labelled `text/event-stream`, and every answer on the group
endpoint are read whole, then sent as one body, as a JSON answer is. A stream
that breaks after it started cannot change its status: if the upstream fails,
goes silent, or is removed or edited, or the key stops being valid, or an
event that may be an error passes 16 MiB, the proxy drops the connection so
the client sees the stream cut short, and the audit row says why (the last
reads `stream event too large to check`). A
`subscriptions/listen` ends when the client, the upstream or the proxy closes
it, or when the upstream goes quiet, and that is its normal end: its row is
`success` unless the stream carried a JSON-RPC error for it, the key stopped
being valid, the upstream was removed or edited, the read failed, or an event
was too large to check.

For a `POST` or a `DELETE`, the proxy:
1. Validates the virtual key
2. Compares the 2026-07-28 revision's routing headers with the body, when the
   request sends them (the table below)
3. Resolves the target (Upstream or Group)
4. On `/{virtual_key_id}/{upstream_slug}/mcp`, resolves the member named by the
   slug among the target group's **enabled** members, or answers `404`
5. Applies tool policy: the group `tool_filter` plus the key's
   `tool_allowlist`/`tool_denylist`
6. Injects real upstream credentials
7. Forwards the JSON-RPC request to the upstream's own URL, and never to a host
   the upstream names in a redirect (a `3xx` answer ends the call)
8. Filters a `tools/list` response down to what the key may call, and marks
   any `cacheScope` the upstream sent as `private` when it can read the list; the aggregate endpoint's
   merged list is PoryMCP's own document (see "The group endpoint as a server")
9. Writes an AuditLog entry
10. Returns the response: relayed as it arrives when the answer is a streamed
    event stream (the row is then written when the stream ends), or sent whole
    otherwise

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

## HTTP API relay

An upstream of kind `http` (see Upstream kinds) is served by a second door
beside `/mcp`. Four routes, all taking the six verbs `GET`, `HEAD`, `POST`,
`PUT`, `PATCH` and `DELETE` plus `OPTIONS` for the preflight:

- `/{virtual_key_id}/api/*` and `/{virtual_key_id}/api`: a key bound to one
  `http` upstream.
- `/{virtual_key_id}/{upstream_slug}/api/*` and
  `/{virtual_key_id}/{upstream_slug}/api`: one `http` member of the key's
  group, resolved among that group's enabled members as the `/mcp` member
  route is.

There is no shared `/api/*` door without the key id: `//api/x` answers `401`
with no key and `404` with one. The management API's `/api/v1` prefix is a
different path and is never reached through a key.

What comes after `/api` is joined under the upstream's base URL as the client
escaped it: `/{id}/api/repos/o/r?per_page=2` on the base
`https://api.github.com` reaches `https://api.github.com/repos/o/r?per_page=2`
with the same verb, the same query and the same body. `/api` and `/api/` with
nothing after them reach the base URL exactly as stored. A `%2F` inside a
segment crosses still encoded; `a//b` collapses to `a/b`. A segment that is
`.` or `..` in any encoding (`..`, `%2e%2e`, `%252e%252e`, `..%5c`, `..;`),
or a decoded segment that still holds `%2e`, `%2f` or `%5c`, is refused
before any dial with `400 {"error":"path escapes the upstream base"}`, and so
is a joined path that does not stay under the base (`../v1beta/x` under
`/v1`). The scheme, host and port always come from the upstream row.

The key goes in `Authorization: Bearer` or, absent that, `X-Api-Key`, the two
placements `/mcp` reads. A request whose path or query also carries the
key, in either form, is refused with
`400 {"error":"request carries the virtual key"}` before any dial, so an SDK
that puts its key in a query parameter never hands PoryMCP's credential to
the vendor. A request header whose value contains the key is dropped for the
same reason.

**Refusals are plain JSON**, not a JSON-RPC envelope:

```json
{"error":"method not allowed by virtual key","request_id":"1b1c…"}
```

`request_id` is the client's `X-Request-Id` (bounded at 256 bytes on this
door) or one PoryMCP minted. It is absent on the two refusals written before
an id exists on either door: the `405` for a verb outside the six
(`{"error":"method not allowed"}` with `Allow: GET, HEAD, POST, PUT, PATCH,
DELETE, OPTIONS`, for a method the router knows, such as `CONNECT` or
`TRACE`; a token it does not know, such as `PROPFIND`, gets the router's own
bare `405` with no body and no `Allow`, as on the MCP door) and the host
refusal. The management API's error shape is unchanged.

| status | body `error` | when | audit row |
| --- | --- | --- | --- |
| `401` | `invalid virtual key`, `virtual key revoked` or `virtual key expired`, as on `/mcp` | no key, an unknown, revoked or expired key | `blocked`, as on `/mcp` |
| `403` | `virtual key does not match this endpoint` | the key belongs to another id | `blocked` |
| `403` | `method not allowed by virtual key` | the verb is not in the key's `http_methods`, or the stored list could not be decoded | `blocked`, reading `blocked by virtual key http_methods` or `blocked: virtual key http_methods could not be decoded` |
| `404` | `unknown endpoint` | the key's upstream is an MCP server, the key targets a group (single door), the slug is not an enabled `http` member (member door), or the row's `kind` is unknown | `blocked` |
| `400` | `path escapes the upstream base` | a dot segment or a join that leaves the base | `error`, no dial |
| `400` | `request carries the virtual key` | the key in the path or the query | `error`, no dial |
| `400` | `invalid body` | the body could not be read | none, as on `/mcp` |
| `400` | `upstream is disabled` | the key's one HTTP API upstream is disabled | `error`, no dial, as on `/mcp` |
| `413` | `request body too large` | more than 8 MiB | `error`, no dial |
| `429` | `rate limit exceeded`, with `Retry-After` in whole seconds | the key's `rate_limit` | `blocked` |
| the upstream's, `400` or above | `upstream error body withheld` | the upstream's error body could not be redacted safely: JSON the rules would break, a JSON-opening body over 64 KiB or unparseable with a `\u` or `\/` escape in its first 64 KiB, JSON nested more than 32 levels, a body under a `Content-Encoding` the proxy did not decode, or UTF-16 or UTF-32 text. The upstream answered; this body is the proxy's, not the API's, and it does not mean the virtual key is wrong. The upstream's other headers cross, redacted; `Content-Type` becomes `application/json`, `Content-Length` is the sentence's length, and `ETag`, `Content-MD5`, `Digest`, `Content-Digest` and `Repr-Digest` are dropped | `error`, `upstream answered N, body withheld` |
| `502` | `upstream request failed` | the credential could not be used, a `3xx` other than `304`, a transport failure, the 5 minute budget, an answer over 16 MiB, or a `1xx` status | `error`, with the cause on the row as on `/mcp` (`docs/03-api.md`, Upstream failures) |

The MCP door's `429` does not carry `Retry-After`; its bytes are unchanged.

**What crosses, inbound.** Every request header except: the hop-by-hop set
and every name listed in `Connection`; `Host`, `Content-Length`, `Expect`;
`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`; the forwarding
and client-address names (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`,
`X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Cluster-Client-IP`,
`Client-IP`); the method- and URL-override names (`X-HTTP-Method-Override`,
`X-HTTP-Method`, `X-Method-Override`, `X-Original-URL`, `X-Rewrite-URL`);
`Accept-Encoding` (the transport negotiates its own and hands back decoded
bytes); any name containing `_`; and any header whose value contains the
presented key. The stored credential is written last, so a client header of
the same name as a `custom` auth header arrives with the stored value.
`X-GitHub-Api-Version`, `Notion-Version`, `If-None-Match`, `If-Match`,
`Idempotency-Key`, `Prefer`, `Accept` and the rest cross as sent, which is
what lets an unmodified SDK work.

**What crosses, outbound.** The upstream's status, every value of every
response header, and the body, except: the hop-by-hop set and `Connection`'s
names; `Content-Length` (set from the relayed body, except on `HEAD`, where
the upstream's is copied) and `Content-Encoding` (the gzip the transport
negotiated is decoded; an error body under any other coding is withheld,
see the refusal table above);
`Set-Cookie`, `Set-Cookie2`, `WWW-Authenticate`, `Proxy-Authenticate`;
`Location`, `Refresh`; every `Access-Control-*` name, the security-policy,
cross-origin, reporting and client-hint names (`Content-Security-Policy`,
`Strict-Transport-Security`, `X-Frame-Options`, `Cross-Origin-*`, `Report-To`,
`Clear-Site-Data`, `Accept-CH` and the rest); `Server`, `Via`, `Alt-Svc`,
`Cache-Control`, `Vary`; and any name PoryMCP had already written on the
response, so nothing an upstream sends replaces a header the middleware,
the CORS block or the door set. A body with no upstream `Content-Type` is
labelled `application/octet-stream`, never sniffed. A `304` is relayed with
its headers and no body; every other `3xx` is a failed call (`502`) and
nothing from it reaches the client. `Cache-Control: no-store` is on every
answer.

**An error body is redacted.** A body with a status of `400` or above has
the credential the proxy injected, and credential-shaped text, replaced by
`[redacted]`, whatever its media type (PORM-204): `{"message":"invalid token
<token>"}` reaches the client as `{"message":"invalid token [redacted]"}`.
JSON of 64 KiB or less stays valid JSON with every member kept; when a
decoded string held the match it comes back compact with its members in
sorted order. Any other body, and JSON over 64 KiB, is cut at 64 KiB at a
value boundary before the rules run, with no marker, so a cut JSON body no
longer parses. A body with nothing credential-shaped and none of the
injected credential, of 64 KiB or less, is relayed byte for byte, and so is
every `2xx` body. When the body changed, `ETag`, `Content-MD5`, `Digest`,
`Content-Digest` and `Repr-Digest` are dropped. A body that cannot be
redacted safely is withheld: the refusal table above has the row. On `HEAD`
the upstream's `Content-Length` crosses as sent and is that of its
unredacted body. Every response header value has the credential the proxy
injected replaced by `[redacted]`, on every status, a header whose name
carries it is dropped, and `Authorization` and `Proxy-Authorization` do not
cross.

**CORS** on this door is its own: `Access-Control-Allow-Methods` names the
six verbs and `OPTIONS`, `Access-Control-Allow-Headers` is the fixed list
`Authorization, X-Api-Key, X-Request-Id, Content-Type, Accept,
Accept-Language, If-None-Match, If-Match, If-Modified-Since, Idempotency-Key,
Prefer` (nothing is reflected from the preflight), `Access-Control-Expose-Headers`
is `ETag, Link, Last-Modified, Retry-After, X-Request-Id`, and there is no
`Access-Control-Allow-Credentials` and no `Mcp-Param-*` reflection. The MCP
door's preflight is unchanged.

**The audit row** for a relayed request records the verb in `method`, the
escaped path after `/api` in `tool_name` (beginning with `/`, bounded at 256
bytes; `/` for the base), and in `params`
`{"query":{…},"content_type":"…","request_bytes":N}`, where the query is
one string per name with secret-looking names (`token`, `key`, `api-key`,
`access_token`, `sig`, `X-Amz-Signature` and the rest) and any value
containing the key replaced by `[redacted]`. The request body is never
recorded and neither is the response body. `status` is `success` below 400
and `error` at 400 and above (`error_message` `upstream answered N`),
`response_size_bytes` is the length of the body the client received (after
redaction and any cut on a status of `400` or above, the fixed sentence's
length when that body was withheld, and `0` on `HEAD` and `304`),
`upstream_id` the upstream reached, and `last_used_at` moves as on `/mcp`. A group's
`tool_filter` and a key's tool lists do not govern this door: `http_methods`
judges the verb and nothing judges the path (PORM-147). The relay is
buffered: a response is read whole (16 MiB, five minutes) and then written;
streaming is not offered on this door.

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

The 2026-07-28 revision mirrors three routing values into headers, and
PoryMCP compares them with the body before it forwards anything. These
refusals contact no upstream and write an `error` row whose `error_message`
names the header (PORM-150):

| Request | HTTP | JSON-RPC error |
| --- | --- | --- |
| `MCP-Protocol-Version` disagrees with `params._meta["io.modelcontextprotocol/protocolVersion"]`, or the body declares `2026-07-28` and the header is absent, or `params._meta` is an object the proxy cannot read (member names that collide under case folding, or a version member that is not a JSON string, a null included) | `400` | `-32020 "header mismatch: MCP-Protocol-Version"` |
| `Mcp-Method` absent on a request declaring `2026-07-28` or later, or present and not equal to `method` | `400` | `-32020 "header mismatch: Mcp-Method"` |
| `Mcp-Name` absent on a `tools/call`, `resources/read` or `prompts/get` that declares `2026-07-28` or later and whose body carries the value it would name, or present and not equal to `params.name` or `params.uri` | `400` | `-32020 "header mismatch: Mcp-Name"` |
| An `Mcp-Param-` value outside printable ASCII | `400` | `-32020 "header mismatch: Mcp-Param"` |
| More than 32 `Mcp-Param-` values, or one name or value over 4096 bytes | `431` | `-32000 "too many or too large Mcp-Param headers"` |

`-32020` is the revision's own `HeaderMismatch` code, the one place PoryMCP
uses a code it did not choose; its own errors stay at `-32000` and `-32602`.
The message names the header and never its value. Each of
`MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` may appear on one line
only; two lines of one of them are refused with that header's message rather
than folded into a single value, because an intermediary in front of the
proxy may fold them differently from the upstream behind it. `Mcp-Name` on
any other method is forwarded and not compared, and one over 4096 bytes, raw
or decoded, is a mismatch. A value in the revision's `=?base64?...?=` form is
decoded before the comparison. A request declaring an earlier version, or
none, is refused only when a header it did send disagrees or its `_meta`
cannot be read; a client that sends none of these headers with a readable
body is forwarded as it was before this. A version the proxy cannot read as
a revision date counts as none. A `DELETE`, or a `POST` with an empty body,
carries no JSON-RPC request, so `Mcp-Method` and the declared version are
not compared on it; an `Mcp-Name` sent on it has nothing to mirror and is
refused, and the `Mcp-Param-` character check and the `431` bound apply to
it as they do to every request. A notification (no `id`) gets the same body
with `"id":null`. On a request declaring
`2026-07-28` or later these checks run before the body's own shape is judged,
so a `tools/call` that sends `Mcp-Name` and omits `params.name` answers
`-32020`; one that sends neither still answers the `-32602` above. The bound
is checked before the request body is read, so its answer carries no id even
when the request had one:

```json
{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"too many or too large Mcp-Param headers"}}
```

The audit row for it records the HTTP verb in `method`, as every refusal
decided before the body does.

Every policy rejection writes an audit row with `status = "blocked"`, so
`GET /api/v1/logs?status=blocked` is the list of them. The row carries
`method`, `tool_name`, `virtual_key_id` and the rule that rejected the call in
`error_message`. `upstream_id` is the targeted upstream on a single-upstream key
**and on a per-member endpoint** (both know the upstream from the target or the
URL without contacting it), and empty on the aggregate group endpoint, where the
block happens before a member is chosen. The `404` from an unresolvable member
URL is recorded the same way, with an empty `upstream_id` and an
`error_message` naming the endpoint as unknown.

## The group endpoint as a server

On `POST /{virtual_key_id}/mcp` for a group key, PoryMCP is an MCP server in its
own right, in both protocol eras. A request that declares `2026-07-28` in the
`MCP-Protocol-Version` header is served statelessly; a request that declares
an earlier version, or none, is served as a handshake-era one. The header is the only way to declare it:
`params._meta` must carry the same version or none, and a body that declares
`2026-07-28` with no header is refused with `-32020`, as on every endpoint. A
single-upstream key on the same path is a 1:1 door and none of this applies to
it: every method, `server/discover` and `initialize` included, reaches the
upstream.

Answered by PoryMCP, with no member contacted and an audit row that names no
upstream:

- `server/discover`: `supportedVersions` is `["2026-07-28"]`, `capabilities` is
  `{"tools":{"listChanged":false}}`, `_meta` carries PoryMCP's `serverInfo`,
  `ttlMs` is `3600000`, `cacheScope` is `private`, and there are no
  `instructions`. It is built from constants and reads no member, so it
  describes the group and never the software behind it. A client on an earlier
  revision uses `initialize` instead.
- `initialize`: answers the protocol version the client asked for when it is
  `2024-11-05`, `2025-03-26`, `2025-06-18` or `2025-11-25`, and `2025-11-25`
  otherwise. The answer is taken from that list and never from the request.
  Capabilities are the same as `server/discover` reports.
- `notifications/initialized`: `202` with no body.
- `ping`: an empty result for a handshake-era request, and
  `{"resultType":"complete"}` for a `2026-07-28` one. That revision removed
  `ping` and requires `resultType` on every result. It is answered and not
  refused on purpose: a client that still sends it gets an answer it can use,
  where a `404` might mark the whole server as failed. The refusals below are
  for methods the endpoint cannot serve.
- `tools/list`: the merged catalogue. Members come in the order the group
  stores them, and each member's tools in the order that member listed them.
  The result also carries `resultType: "complete"`, `cacheScope: "private"`
  (the list is composed per key and trimmed by that key's tool rules),
  PoryMCP's `serverInfo` in `_meta`, and `ttlMs`. `ttlMs` is the smallest
  value any listed member reported, a member that reports none counting as
  `60000`, held between `10000` and `3600000`. Only a non-negative whole number
  counts as a report. There is never a `nextCursor`. Every tool carries an
  `inputSchema` that is a JSON object of type `object`, which the revision
  requires. A member's conforming schema crosses unchanged. One that is an
  object without that `type` has `type` set to `object` and keeps everything
  else it declared. A value that is not an object becomes `{"type":"object"}`.
  `resultType` says nothing about a member skipped at catalogue time.

Refused by PoryMCP, with no member contacted and an `error` row that names no
upstream:

- `subscriptions/listen`, `tasks/get` and `tasks/update`: HTTP `404` with
  JSON-RPC `-32601` and the message `method not found`. A subscription is a
  stream held open to one member, which the group endpoint does not merge; open
  it on that member's endpoint, where it is relayed as it arrives. A task
  handle belongs to the one member that issued it. A member endpoint relays all
  three to its member.
- A request that declares a stateless revision other than `2026-07-28`: HTTP
  `400` with `-32022`, the message `unsupported protocol version`, and
  `data: {"supported":["2026-07-28"],"requested":"<the version>"}`.

The order of these refusals is fixed, because a client can observe it: the
routing headers are checked first (`400`, `-32020`), then the version (`400`,
`-32022`), then the method. The checks that already existed sit around them: a
group with an enabled `sse` member answers `502` before the version is looked
at, and the tool gate (`-32602`, a blocked call) runs after the version and
before the method. So a blocked tool called with a revision the endpoint does
not speak is recorded as a version error and not as a block; nothing is
forwarded either way. A request with no method at all (a `DELETE`) is held to
the version rule too.

`tools/call` is routed to the member that owns the tool, and the request is
composed for the era that member speaks, whichever era the client spoke. The
member's era is what PoryMCP learned when it listed the member for this same
request. If that is not known, the client's request is sent as it came, with
the tool name rewritten.

- A handshake-era client calling a `2026-07-28` member: PoryMCP adds
  `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and the three
  `io.modelcontextprotocol/` members of `params._meta`, from its own values.
  Anything else the client put in `_meta` stays.
- A `2026-07-28` client calling a handshake-era member: the client's
  `MCP-Protocol-Version` header and those three `_meta` members are not sent,
  and no version is sent in their place. `Mcp-Method`, the rewritten `Mcp-Name`,
  the `Mcp-Param-` headers and the rest of `_meta` still cross. The member's
  result is given `resultType: "complete"` when it has none, because the
  revision requires one on every result a `2026-07-28` server sends.
- The same era on both sides: the client's request, with the tool name
  rewritten, and the member's answer, as before.

The three reserved `_meta` members are matched without regard to case, as the
version check reads them, so another spelling of one neither survives the
removal nor sits beside the one PoryMCP writes.

The headers PoryMCP composes are written after the stored credential, so an
upstream's stored `auth_config` cannot replace them.

Every other method is relayed to the group's first member and audited against
it. A handshake-era client's `MCP-Protocol-Version` is not sent with it: that
version was agreed by the group endpoint's `initialize`, for itself, and a
member on an older revision would refuse it. A `2026-07-28` client's relayed
request has the first member's era looked up first: the cached verdict, else
one `server/discover` probe, cached for ten minutes, or thirty seconds while
the member does not answer (the bounds in `docs/07-security.md`); to a
member held as handshake-era the request loses its `MCP-Protocol-Version`
header and the three reserved `_meta` members, and every other value crosses
as sent. The member's answer is read as a routed call's is: reduced to the
one document that answers the request, sent as `application/json` with no
member header but `Retry-After`, and given `resultType: "complete"` for a
`2026-07-28` client when the member sent none. A member body that is neither
JSON nor an event stream keeps its status with no body when that status is
`400` or above, and is a `502` otherwise, so a member's own `401` or `403`
reaches the client bare.

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
told nothing about the upstream's host, address or response. Every sentence in
the table below is PoryMCP's own. A transport failure names the upstream's host
at most, with its port when the registered URL names one, and never the URL,
its query string or the address the host resolved to. The HTTP relay door
writes the same sentence for the same failure. The host is written only when
it holds ASCII letters, digits, `.`, `_`, `-`, `:`, `[` and `]` alone; any
other host reads as `the upstream`. The field is read by operators and never
returned to a key holder. An upstream's own JSON-RPC error message is returned
to the key holder cut at 64 KiB and recorded cut to 256 bytes, in both places
with the credential the proxy injected, whatever its shape, and
credential-shaped text replaced by `[redacted]` (PORM-72, PORM-195,
PORM-208). A
body with a status of `400` or above that is not a JSON-RPC error envelope
leaves the row's `error_message` empty unless it carries an `error` object
with a `message`, which the row reads as it does for a JSON-RPC error; the key
holder receives the body with the same replacement (PORM-205).

Whether a row is `success` or `error` is judged from the document that
answers the request, in either framing: an upstream's JSON-RPC error inside
an event stream is an `error` row carrying that error's message, as a JSON
one is. When the framing cannot be read, the row is judged by the HTTP status
and the raw body, as every row was before PORM-172.

| Condition | `error_message` on the row |
| --- | --- |
| No configured `ENCRYPTION_KEY` opens the stored credential (the key changed) | `credential undecryptable`: no request was built; the fix is the key, and `auth_status` on the upstream reads `undecryptable` |
| The stored credential is empty or holds nothing its auth type can send | `credential unreadable`: no request was built; the fix is the credential, and `auth_status` reads `unreadable` |
| An OAuth access token lapsed and the vendor refused to renew it, or issued no refresh token | `credential expired`: no request was built; the fix is Connect again, and `auth_status` reads `expired` |
| An OAuth access token lapsed and the vendor's token endpoint could not be reached or answered something unusable | `credential refresh failed`: no request was built; the next call retries after thirty seconds, and `auth_status` still reads `ok` |
| The stored `transport` is `sse` or an unknown value | `the sse transport is not implemented yet; use streamable-http`, or `unsupported transport` for a value that is not `sse` (the value itself is never written): no request was built; the fix is a `PATCH` sending `transport: "streamable-http"`, and the row shows an Unsupported badge in the dashboard and one WARN line at startup |
| The stored URL does not parse | `upstream url is not usable`: no request was built, and the fix is a `PATCH` sending a URL that parses |
| The upstream answered `3xx` | `upstream redirected to <host>`: the host from `Location`, never the full URL |
| The address the upstream's host resolved to is in a refused range (PORM-79) | `upstream address denied: <class>`: one of `loopback`, `link-local`, `metadata`, `private`, `multicast` or `unspecified`; the class only, never the address or the URL. `private` appears only under `UPSTREAM_DENY_PRIVATE`; `UPSTREAM_ALLOW_LOOPBACK` reopens `loopback` and nothing else. The same sentence is written on the HTTP relay door, and the server log carries one Warn line, `upstream address denied`, with the upstream id, the class and the request id |
| The upstream did not answer within the relay budget | `upstream did not answer within 5m0s`: five minutes for a buffered answer, or for a stream's headers |
| The connection or the TLS handshake did not complete within the connect budget | `upstream did not connect within 10s` |
| The upstream's host did not resolve | `cannot resolve <host>` |
| The connection was refused or reset before the upstream answered | `cannot connect to <host>` |
| The TLS handshake failed | `tls handshake with <host> failed` |
| Any other failure to get an answer | `cannot reach <host>` |
| The client hung up before the upstream answered | `client went away before the answer`: the upstream is not at fault |
| The answer was larger than 16 MiB | `upstream body exceeds 16777216 bytes`: the body is not relayed |
| The client closed a stream before the answer, or stopped reading it until a write to it had waited five minutes | `client closed the stream before the answer` |
| The upstream closed a stream before the answer | `upstream closed the stream before the answer` |
| The upstream sent nothing on a stream for five minutes | `upstream sent nothing for 5m0s` |
| The proxy stopped while a stream was open | `proxy stopped before the answer` |
| The key was revoked, expired, rotated or retargeted while a stream was open | `virtual key no longer valid during the stream` |
| The upstream was removed from the key's route while a stream was open | `upstream no longer reachable through the key during the stream` |
| The upstream's URL, transport or credential changed while a stream was open (a new name or description leaves the stream alone) | `upstream changed during the stream` |
| The upstream connection failed while the answer was being read, buffered or streamed | `upstream connection failed`, or `unexpected EOF` for a body that ended without its terminator; the read error's own text is never recorded |

A streamed row's `timestamp` is when the stream ended, its `latency_ms` the
stream's whole life and its `response_size_bytes` the bytes relayed to the
client. The row is judged from the last complete event, then from the first 64
KiB of the stream; an answer event larger than 1 MiB is not judged and reads as
`success` when the upstream ended the stream. A `subscriptions/listen` ended by
the client, the upstream, the idle bound or the proxy is a `success` row. An
upstream that accepts the connection and never answers is caught by the
five-minute budget, not the connect budget.

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
naming the member's slug and its upstream id. The `err` field carries the same
sentence the member's own row would. Call the member's own
`/{virtual_key_id}/{upstream_slug}/mcp` endpoint to get the `502` and the row.
A `tools/call` the aggregate does route to a redirecting member is not blind:
that one answers `502` and writes a row naming the member's `upstream_id`. A
`tools/call` for one of the *skipped* member's tools answers
`-32602 "unknown tool"` instead, because the name is no longer in the merged
catalogue. The log line is what says why. A member whose host resolves to a
refused range (`upstream address denied: <class>`) is skipped the same way:
the line carries the class sentence, a `tools/call` for one of its tools
answers `-32602 "unknown tool"` because the name is not in the merged
catalogue, and the member's own endpoint answers the `502` and writes the
`upstream address denied: <class>` row. A member whose stored credential
cannot be used (`credential undecryptable` / `credential unreadable`) is
skipped the same way: zero requests reach it, its tools are absent, the group's
own `tools/list` succeeds, and the `group member skipped` line carries the
cause. The member's own endpoint answers the `502` and writes the row; the
operator's signals are `auth_status`, the counts on `/stats` and the boot line.

A member whose stored `transport` is `sse` is not skipped. While it is enabled,
every method on the group's aggregate endpoint, `initialize` included, answers
the `502` and writes a row naming that member, so a client sees the group as
failed rather than a catalogue that is quietly missing one server. The other
members' own endpoints keep working. The group serves again once the member is
disabled or its `transport` is set to `streamable-http`.
