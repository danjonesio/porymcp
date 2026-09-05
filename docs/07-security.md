# Security model

- Real upstream credentials: encrypted at rest (AES-256-GCM) under
  `ENCRYPTION_KEY`, in the `v1:<fingerprint>:<base64>` form since PORM-52: the
  fingerprint names the key that sealed the value and is the AES-GCM additional
  authenticated data, so a value is never even attempted under a key that does
  not match its label. Values written by earlier builds (bare base64, no AAD)
  are read for ever; `porymcp rekey` rewrites them. The AAD is format hygiene
  and the hook for a later KMS key id, not tamper protection: anyone with write
  access to the database can redirect a credential by editing `upstreams.url`,
  which is stored in the clear, without touching `auth_config` at all:
  database write access is credential-exfiltration capability whatever the
  ciphertext format.
- **The encryption key is as important as the database.** Back it up
  separately from the database and keep the two together: a backup is
  restorable only with the key that was current when it was taken. Losing the
  key makes every stored credential unrecoverable; PoryMCP cannot get them
  back. Recovery when the key is gone: `PATCH /api/v1/upstreams/{id}` with a
  fresh `auth_config` for every upstream the boot line named (or delete the
  upstream), then **restart**: the boot check records the current fingerprint
  once every credential opens under it and `/health` returns to `ok`;
  `porymcp rekey` is not needed on that path.
- The key must be 32 random bytes (`openssl rand -hex 32`). The parser also
  accepts any 32-character string as a key, so a passphrase works. Do not use
  one: the stored fingerprint (below) is an offline oracle for a weak key, at
  one hash per guess, and it travels into logs. A raw-form key can be listed in
  `ENCRYPTION_KEY_PREVIOUS` only re-expressed as hex
  (`printf %s "$KEY" | xxd -p`). PoryMCP ships no encryption key: compose
  refuses every subcommand without `ENCRYPTION_KEY`, and `/health` never
  exposes the key's fingerprint. The boot log and
  `schema_meta.encryption_key_fp` do, and both are operator-only.
- `schema_meta.encryption_key_fp` holds
  `hex(sha256("porymcp-key-fp" || key))[:16]`, one-way and domain-separated,
  no key material. It is written only by a boot that proved every stored
  credential opens under the current key, and by `porymcp rekey`; a boot that
  finds a mismatch never moves it, and a value that is not sixteen hex
  characters is ignored as absent and never echoed. Every boot reads every
  stored credential once to classify it: the plaintext is dropped as each row
  is classified, none is retained and none is written anywhere. The boot line
  carries fingerprints, counts, upstream ids and names, never a value, never
  a URL.
- Rotation is supported, in this order: set `ENCRYPTION_KEY` to the new key
  and `ENCRYPTION_KEY_PREVIOUS` to the old one; restart (the boot Warn reads
  "rotation pending" and the proxy keeps working on the previous key); run
  `porymcp rekey` (one transaction, safe against a live server, re-running is
  the retry); verify `GET /api/v1/stats` reports
  `upstreams_under_previous_key: 0` and that a restart with both keys still set
  logs no "rotation pending"; only then remove `ENCRYPTION_KEY_PREVIOUS` and
  restart; only then delete the old key from the secret store. The commands,
  against the shipped compose file, are in `docs/11-deployment.md` §12.
  `ENCRYPTION_KEY_PREVIOUS` is a rotation window measured in minutes (decrypt
  only, at most five keys, 64-hex or base64), and not a way to keep a
  compromised key alive.
- When a stored credential cannot be used the proxy fails closed: no request
  is built, the client gets the same `502 -32000 "upstream request failed"` as
  for any upstream failure (a key holder is not told that the operator's
  encryption key is wrong), and the audit row's `error_message` reads
  `credential undecryptable` (no configured key opens it: the key changed) or
  `credential unreadable` (nothing stored, or nothing the auth type can send,
  such as a blank token stored as `{}`; the fix is the credential, never the
  key). Discovery refuses the same rows with `stored credential cannot be
  decrypted` / `stored credential is not usable for this auth type`, and a
  draft form whose auth type has no credential with `this auth type needs a
  credential; add one or choose None`. An upstream with `auth_type: none`
  sends nothing and is never judged by whatever sits in its column. On a
  group's aggregate endpoint an undecryptable member is skipped exactly like
  any unlistable member: its tools vanish from the merged catalogue, the
  group's `tools/list` succeeds, a call for one of its tools answers
  `-32602 unknown tool`, and the `group member skipped` Warn names the cause.
  The operator's signals are the boot line, `auth_status` on the row, the
  counts on `GET /api/v1/stats` and the Overview notice.
- `GET /health` reports `encryption: ok | mismatch` and, on a mismatch,
  `status: degraded` with `503`. That is a verdict only, never a fingerprint, a count
  or a name: the route is unauthenticated, and a fingerprint would let anyone
  test whether a particular key is in use. It
  is the boot check's verdict, not recomputed per request (the route issues no
  store read beyond its ping); `auth_status`, `/stats` and the dashboard are
  live, so the restart that ends a rotation or a recovery is what clears a
  monitor. `porymcp healthcheck` (the container check) exits `0` on a degraded
  body on purpose: a restart cannot change an environment variable.
- `ADMIN_API_KEY` is required under compose but not validated by the server:
  use at least 32 random characters (`openssl rand -hex 32`). Outside compose,
  if it is unset the server generates one for that process and prints it in
  the boot log at WARN.
- `/health`'s `error` field is the fixed string `database unavailable`, never
  the store error itself, which can quote DSN detail (an SQLite path; pgx's
  `user=`/`database=` plus host). The real error is in the server log at Error
  level, throttled to once per minute so the unauthenticated route cannot be
  driven as a log amplifier.
- `ENCRYPTION_KEY` unset against a database that holds stored credentials
  refuses to start (the schema migration has already run by then). An
  ephemeral key is for an empty database, or one whose upstreams all use
  `auth_type: none`. A key generated at boot is unguessable, and the
  generated-key warning already covers it.
- Virtual keys: high-entropy, shown only once on create/rotate. Store only hash (argon2id preferred).
- Proxy never logs or returns real upstream secrets.
- Optional redaction of sensitive fields in AuditLog params.
- Management changes are recorded in `admin_events` (PORM-54): one row per
  successful create, update, delete, rotate or revoke, with actor, action,
  resource, request id and client address, written after the store write
  returns and before the response. `details` is a closed object of field
  names, an auth type, a changed flag, a key prefix, a target and a member
  count. No credential, ciphertext, plaintext key, key hash or key lookup can
  reach a row, and `TestAdminEventNeverStoresSecrets` serialises every column
  of every row to prove it. A failed audit write is logged at `ERROR` and never
  fails or hides the change; a crash between the mutation and the insert loses
  the event, never the change. Stored names and request ids are cleaned and cut
  at 256 bytes on the row only; the `X-Request-Id` header itself stays
  unbounded in `audit_logs` and the access log. The table records completed
  changes, so a refused or unauthorised attempt is visible only as a status
  line in the server log. It is operational recall and attribution, not tamper
  evidence or non-repudiation: the admin key holder is also the principal with
  database access, and every row says `admin` until PORM-127 adds named users.
- Upstream slugs are public, non-secret identifiers: they appear in per-member
  proxy URLs (`/{virtual_key_id}/{upstream_slug}/mcp`) and in every tool name
  the aggregate endpoint advertises, are never an authorization token (virtual
  keys are), and are immutable after create so tool filters, allow/deny lists
  and client endpoints written against them cannot silently stop matching. The
  per-member endpoint validates the URL segment with the same rule that governs
  a stored slug **before any lookup**, so `..`, `%2F`, a NUL byte, an empty
  segment, an over-long string and a non-ASCII lookalike are refused with the
  endpoint's ordinary `404` and never reach the store or an `error_message`. (Do
  not rely on that `404` end to end for a dot-segment: an intermediary that
  normalises `..` may resolve the path before PoryMCP ever sees it.)
- The per-member endpoint answers **identically** (same status, same JSON-RPC
  error `-32000 "unknown endpoint"`, same `blocked` audit row) for an unknown
  slug, a slug belonging to an upstream outside this key's group, a disabled
  member, a member removed from the group, any slug at all under a
  single-upstream key, and a group with no enabled members. The proxy resolves
  the slug only among the members it already loaded for this key and performs no
  lookup outside them, so a valid key cannot use wording, status or timing to
  discover another group's upstreams. A key presented on another key's path is
  `403` before the body is read, so it is told nothing about that key's slugs
  either. What that uniform `404` buys is narrower than it was: since every tool
  the aggregate endpoint advertises carries its member's slug, any holder of a
  group key can read that group's own member slugs straight out of `tools/list`.
  That is the point of the aggregate view, not a leak. The half worth keeping is
  the other one: slugs **outside** the key's group stay hidden, and the
  aggregate endpoint keeps them hidden too: a `tools/call` there for a
  well-formed identity whose slug is not a member of this key's group answers
  the same `-32602 "unknown tool"` as one whose slug belongs to nothing at all,
  and the shape check that produces it reads no group, no member and no store,
  so a member's slug and a stranger's cost the same.
- Tool policy is one gate. A group's `tool_filter` and a virtual key's
  `tool_allowlist`/`tool_denylist` are evaluated by a single predicate that
  both `tools/call` and `tools/list` consult, on the aggregate endpoint of a
  group target, on each of that group's per-member endpoints, and on a
  single-upstream target alike: a tool hidden from the catalogue cannot be
  called, and a callable tool is listed. Precedence is key denylist, then key
  allowlist, then group `tool_filter`; the first rule that rejects wins, so each
  step only narrows what the one before it permitted. An allowlist entry never
  re-admits a tool the group filter denies, and a filter never widens a key.
  Methods other than `tools/call` that carry a `params.name` (`prompts/get`,
  for one) keep today's narrower check: the key's own lists, not the group
  filter, and the name matched whole rather than as a tool identity, on every
  path. Policy for prompts and resources is PORM-6.
- A per-member endpoint is a full 1:1 pass-through, so a group's `tool_filter`
  reaches `tools/call` and that member's `tools/list` and nothing else. A group
  is **not** a containment boundary for `prompts/get`, `resources/read`,
  `completion/complete` or a vendor method on the member path until PORM-6: a
  key that targets a group can reach every enabled member with those, subject
  only to its own allow/deny lists. Before this route existed a group key could
  reach only the first member for them; the mechanism is unchanged and the
  scope is not.
- A blocked `tools/call` never reaches the upstream and never presents the
  real credential. It answers `200` with the JSON-RPC error
  `-32602 "tool blocked"` against the request's own id. A blocked
  *notification* (a `tools/call` sent with no id, so there is nothing to
  correlate) answers `202` with an empty body. Both write an audit row with
  `status = "blocked"`, `error_message` naming which rule rejected it. Before
  v0.1 a `tool_filter` only hid tools from the aggregate `tools/list`, so a
  client that already knew a name could still call it; a filter written then
  is enforced now.
- **A real credential is presented to exactly one host: the host in
  `upstreams.url` (or the egress proxy named by `HTTPS_PROXY`/`HTTP_PROXY`, if
  the deployment sets one); the proxy never follows a redirect.** Any `3xx`
  answer ends the call: on a per-member endpoint, on the aggregate endpoint,
  on the `tools/list` the proxy composes itself, and on the discovery call an
  operator makes from the dashboard: no second request is made, the
  `Location` is not fetched, and nothing from the redirect response reaches the
  client. This is not a convenience. Three of the four auth types write the real
  credential into an ordinary header (`api_key` to `X-API-Key` by default,
  `header`, `custom`), and Go drops `Authorization`, `Cookie`, `Cookie2` and
  `Www-Authenticate` only when the hostname changes (not on a subdomain, not on
  a same-host scheme downgrade) and copies every other header, the one holding
  the secret included, to the redirect target; on a `307` or `308` the client's
  request body is re-sent too. Following a `Location` would also let an upstream
  steer the proxy at an address the operator never configured. So a redirecting
  upstream is a misconfiguration to fix, not a route to follow.
- **Two things about how a credential leaves PoryMCP are worth stating
  plainly.** A plain `http://` upstream URL is allowed and will stay allowed
  (`http://mcp-server:3000` on a Docker network is the documented deployment), so
  a credential registered against one travels unencrypted, on the proxy path and
  on a discovery call alike. The dashboard says so where an operator will see
  it; nothing refuses it. And a credential written into the URL itself,
  `https://user:pass@host/mcp`, is still sent: `net/http` re-derives
  `Authorization: Basic …` from the URL's userinfo at send time, *after* PoryMCP
  has deleted any `Authorization` header of its own, so for every `auth_type`
  except `bearer` a URL-embedded credential reaches the upstream. It is not a
  secret PoryMCP is keeping, either: what sits in `upstreams.url` is stored and
  shown like any other part of that URL, and is not encrypted at rest the way
  `auth_config` is. PORM-27 owns deciding whether userinfo should be refused,
  stripped, or promoted into a real `auth_config`. Until it does, the places it
  can be read back are worth knowing: `GET /api/v1/upstreams` and the dashboard
  show the URL as stored, and the audit row for a timeout or a refused
  connection quotes it, query string and all, a field operators read and key
  holders never see (PORM-72). A discovery `error` names a host and never a URL.
- What the *client* is told about an upstream failure is deliberately flat. A
  redirect, a timeout, a refused connection and an unreadable body all answer
  `502` with the same `-32000 "upstream request failed"`, and no upstream
  response header (`Location` included) is copied back. The redirect host is
  recorded once, in the audit row, where an operator can see it and a key holder
  cannot: `error_message` reads `upstream redirected to <host>`, the host alone,
  never the path or the query string a `Location` can also carry, and never
  a `Location` Go itself could not read. That message is bounded at 256 bytes.
  An answer too large to read is one of those failures rather than a half-read
  document: the client reads one byte past its cap and stops, so discovery
  answers `upstream's answer to <step> is larger than discovery will read`
  instead of reporting a working server as one that speaks no JSON-RPC, and a
  relayed call whose response exceeds 16 MiB fails as a call rather than
  reaching the agent (and the audit row) cut off mid-object.
- One thing follows the credential once a call *is* forwarded, on every path,
  and the per-member endpoint makes 1:1 forwarding the primary one. Every
  response header the upstream sets except `Content-Length` is copied back to
  the client: `Set-Cookie` (a session minted with the real credential),
  `WWW-Authenticate` (the upstream's identity and authorization-server URL) and
  a second `Access-Control-Allow-Origin` included. Narrowing that to an
  allowlist that keeps `Mcp-Session-Id` is PORM-98, and is not fixed today.
- **Discovery is the one outbound call PoryMCP makes on an operator's behalf.**
  `POST /api/v1/upstreams/{id}/discover` and `POST /api/v1/upstreams/discover`
  run a real MCP handshake (`initialize`, `notifications/initialized`, a
  paginated `tools/list`, then a `DELETE` of the session so none is left open on
  the upstream) over the same client, with the same credential injection and
  the same refusal to follow a redirect as everything above: a `3xx` ends the
  call here too, and the credential still reaches exactly the host in
  `upstreams.url`. It is admin-key only, and the admin key is already the
  authority that chooses which host a credential is sent to, so the route grants
  no capability that key did not have. What it removes is the cost. Pointing
  PoryMCP at a host used to mean a `POST /upstreams`, a proxy call and a
  `DELETE`, and left a row every other admin-key holder could see; it is now one
  request that stores no catalogue: the saved route records only when it last
  ran and whether it passed, a timestamp and a flag, never anything the upstream
  said. That record is the route's only write: no `audit_logs` row, since the
  call is made on an operator's behalf rather than a virtual key's, no
  `admin_events` row, since a test result is an observation of the upstream
  rather than a change to the configuration (recording it is a filed
  follow-up), and no log line
  either, except when the record itself does not land (one `DEBUG` when the row
  was edited or deleted while the handshake ran, one `WARN` when the store
  failed, each naming the upstream id) and, on the `WARN`, the store's own
  error; never a name, a URL or a credential. That is why it carries budgets of
  its own: thirty calls a minute and four in flight. The per-minute token is
  spent before the store is read, so a flood of unknown ids costs what real ones
  do; the in-flight slot is taken later, once there is an outbound call to make,
  so a `404` or an undecryptable credential never holds a slot a real discovery
  could use. Both are counted apart from the failed-admin-auth budget, so a
  burst of discoveries cannot lock an operator out of the API. The handshake is
  bounded at ten seconds and the teardown at a further two, so a hung upstream
  cannot hold an admin request open, and that is the bound that matters,
  because one discovery is at most 53 authenticated requests (`initialize`, the
  notification, up to fifty pages, the teardown), so the per-minute budget
  bounds discoveries, not requests.
- **A discovery response is a fixed set of fields, not a window onto the
  upstream.** `ok`, a latency rounded to 10 ms, the protocol version, the
  server's name and version, and a list of tool names, titles, descriptions and
  typed annotations, each clamped to a byte budget and forced back to valid
  UTF-8. No upstream response header reaches it: the copy-back described above
  is a property of the relay path and is not inherited here, so a `Set-Cookie`
  or a `WWW-Authenticate` collected during a discovery attempt goes nowhere.
  Nor does any byte of an upstream body outside those fields, and never
  `auth_config` or the credential in any form. None of it is persisted either:
  what the saved route records is a timestamp and a flag (`last_test_at` and
  `last_test_ok`), never a catalogue, a tool count or a sentence the upstream
  wrote. The one deliberate exception is
  `upstream_message` (the upstream's own JSON-RPC `error.message`, single line,
  visible characters, at most 200 bytes, in a field of its own), because "token
  lacks the `repo` scope" is the answer the feature exists to give, and keeping
  it out of `error` is what lets `error` stay a closed set of sentences PoryMCP
  wrote, whose only variables are a status code, a step name and a host. An
  upstream URL is never stringified into one: Go's own `*url.Error` masks the
  password and keeps the username, the path and the whole query string, so a
  redaction built on it would still publish a token written into a query. Tool
  names and descriptions are upstream-controlled text that now renders in an
  *operator's* browser rather than an agent's context, which is why the
  dashboard renders them as text and never as markup (see `docs/06-ui.md`).
- **Where a discovery URL points is not checked yet, and this is the route that
  makes that matter.** PoryMCP will connect to any absolute `http` or `https`
  URL an admin-key holder names: `127.0.0.1`, a private-range address, a Docker
  service name and the cloud-metadata address `169.254.169.254` included. That
  has always been true of `POST /upstreams` followed by a proxy call; what
  changes is that it is now a single request, and on the unsaved-payload route a
  single request that writes nothing down. The answer is structured but it is
  not opaque: `cannot connect to <host>` at 0 ms, `upstream did not answer
  within 10s` at 10 000, and `upstream answered 401 at initialize` are three
  different facts about a port. **The admin key is therefore a
  network-reachability capability** wherever the container sits. That, and not
  only what it can read out of the database, is what to weigh when deciding who
  holds one and what the container is allowed to route to. Refusing loopback,
  link-local and metadata destinations is PORM-79, and it belongs on the
  transport's dialer rather than in a pre-flight check on the URL, because a
  hostname that resolved safely once is resolved again when the connection is
  made. The check discovery does make (an absolute `http` or `https` URL, a
  non-empty host, no fragment, refused before anything leaves the process) is
  `mcpclient.CheckTarget`, and it is the single seam PORM-79 will build on:
  `POST /upstreams` and `PATCH /upstreams/{id}` call it before storing a URL,
  discovery calls it before opening a socket, and the proxy's client is the
  one the dialer guard will sit inside. It is syntax only. Deciding whether a
  host may be dialled is not done anywhere yet.
- A `tool_filter` that does not validate blocks **every** call on that group
  until it is fixed. `{"mode":"Deny"}`, `{"tool":[…]}` and `{"mode":"allow"}`
  with no entries all decode into a *permissive* filter, so failing open on
  them would turn a typo into a silent bypass. A virtual key whose stored
  `tool_allowlist`/`tool_denylist` cannot be decoded fails closed the same way
  and for the same reason: once a decoder has swallowed the error, "the list is
  unreadable" looks exactly like "there is no list", and the second one permits
  everything the first was written to refuse. It fails closed on
  `prompts/get` too, since the key's lists are the whole of that policy. Both
  are reported at startup, naming the group or the key and never the entries, so
  an operator sees them in the server log instead of discovering them from
  inside a client. The same report warns about rules that are merely inert: a
  scoped entry whose head is not one of the target's members, and an unscoped
  entry in an allow rule on a group.
- Filtering `tools/list` is presentation; the call gate is the control. The
  proxy rewrites JSON and SSE-framed list responses on the way back through
  the same policy, and passes through, with a warning log, any body it
  cannot parse. A pass-through can advertise a tool the proxy will still
  refuse to call; it can never make a blocked tool callable.
- Tool policy matches a name byte-exactly: no trimming, no case folding, no
  wildcards, no regular expressions, no Unicode normalisation. There is one
  identity, and it is the same on every path.
  - **The identity of a tool is `{upstream_slug}__{tool}`**: two underscores,
    the member's slug and then the upstream's own name for it. It is what a
    group's `tool_filter.tools` and a key's `tool_allowlist`/`tool_denylist` are
    matched against on the aggregate endpoint, on each per-member endpoint and
    under a single-upstream key alike. On the aggregate endpoint it is also the
    name the client is shown; on the other two the client sees the upstream's
    bare name and the policy composes the slug before matching. A rule written
    once therefore holds on every endpoint the key serves, and a member joining,
    leaving, being disabled or merely failing to answer its catalogue cannot
    change it. The composition is reversible because a slug holds no `__` of its
    own and ends alphanumeric, so the first `__` in a composed name sits exactly
    at the join, which is why one underscore was not enough: `gh` + `_` +
    `enterprise_create_issue` and `gh_enterprise` + `_` + `create_issue` are the
    same string, and the loser of that collision resolved to the winner's
    upstream, a call executed against the wrong credential.
  - An entry carrying `__` with something before it is **scoped** and names one
    member; anything else is **unscoped** and is matched against the tool's own
    name on every member the rule covers. An entry beginning with the separator
    (`__search`) is unscoped, not scoped to a member called `""`, because an
    upstream may advertise a tool really called `__search`.
  - **A deny is a rule on the zone; an allow is a rule on a host.** The
    asymmetry is the design, not an omission. An unscoped deny follows
    membership: `delete_repo` covers a server added to the group tomorrow, which
    is what "blanket deny at the zone edge" means and what an operator writing
    one wants. An allow entry is a permit for one named thing, and on a group
    there is no one named thing: reading `search` as "search on every member"
    would widen the permit to the whole group, so an unscoped entry in an allow
    rule on a group is refused with `400` when written, **skipped** when read
    (it admits nothing) and named in a `WARN` row at startup. A one-member group
    is still a group, so it is rejected there too. A key bound to a **single
    upstream** takes bare allow entries happily: every tool it can reach belongs
    to that upstream, so a bare name already names one thing.
  - Scoping is read off the text, so it can be surprising in two directions, and
    both are deliberate. An entry containing `__` is **always** read as scoped in
    a tool rule: a tool whose own name carries the separator has to be written
    `{slug}__{name}`, because `mcp__fetch` alone means "the member `mcp`", a
    member that can never exist, since `mcp` is a reserved slug. And the
    converse: `docs__purge` denies the `docs` member's tool `purge`, not some
    other member's tool literally named `docs__purge`.
  - **`prefixes` entries take the same two forms**, and what they are matched
    against is the tool's **own** name, never the composed `{slug}__{tool}`
    string the aggregate advertises. Write `delete_`, or `github__delete_` to
    scope it to `github`. A scoped `prefixes` entry may end at the separator:
    `github__` is **every** tool on `github`, which is worth reading twice
    before writing it into an allow rule. `github_`, with one underscore, is not
    a scope at all: it is a name shape, and matches any tool whose own name
    starts `github_` on any member the rule covers. Matching the composed name
    instead would be a fail-open at every upgrade: `delete_`, the spelling this
    document has always told operators to use, would stop matching
    `github__delete_repo` on every path with no error and no audit row.
  - **Prompts and resources are matched whole.** Key allow/deny entries on
    `prompts/get`, `resources/read` and the other `params.name` methods are
    compared against the name as it stands, with no splitting, no slug and
    nothing skipped for being unscoped: a `{slug}__{tool}` identity is a *tool*
    identity, and a prompt is not a tool. One entry can therefore mean two
    things depending on the method: the deny `docs__search` blocks `docs`'s tool
    `search` **and** a prompt named `docs__search`, and a group key's
    `tool_allowlist` entry `read_docs` still admits the prompt `read_docs` while
    admitting no tool at all. PORM-6 owns fixing that; until then it is written
    down here.

  To stop `create_issue` on the `github` member of a group, an operator writes
  `github__create_issue`, once. It is enforced on `/{virtual_key_id}/mcp` and
  on `/{virtual_key_id}/github/mcp`, and nothing about the group's membership
  changes what it means. This is why slugs are immutable (above): the slug is
  the half of the identity PoryMCP owns, and moving it would silently stop a
  deny entry matching.

  Two consequences of membership follow from the asymmetry. A member added to a
  group is covered by every unscoped deny entry and by no scoped allow entry,
  which is the correct default in both cases. A member removed leaves any allow
  entry scoped to it admitting nothing, and the startup report names it. Moving
  a key across the group/upstream line is the one edit that changes what an
  untouched list means, so it is checked on the allow side in both directions
  and answers `400` naming the stranded entries; the deny side is never refused
  for a move, because an entry written to survive one is exactly the point of
  it.

  Rules written before v0.1's identity existed are rewritten in place by the
  schema-v3 migration (`docs/02-data-model.md`), and it only ever adds. A deny
  entry gains the scoped readings of the old aggregate spelling and **keeps** the
  bare one, which goes on denying a tool literally named that on any member, a
  deliberate residue, since it is the only spelling a prompt of that name is
  matched by. An allow entry is never rewritten at all: widening an
  authorization list during an upgrade with nobody present is not a migration's
  decision to make, so an entry that admits nothing is counted, reported at
  startup, and fails closed until an operator rewrites it knowingly.
- Requests the gate cannot read are refused with `400` before any upstream is
  contacted: a JSON-RPC batch (`[…]`), a body that does not parse, an `id`
  that is not a string, number or null, any spelling variant of
  `tools/call`/`tools/list` (`Tools/Call`, a trailing space, a leading BOM),
  and an envelope or `params` object carrying two spellings of one member name
  (`{"method":"tools/call","Method":"ping"}` reads as `ping` here, because Go
  binds a name case-insensitively and keeps the last match, and runs as
  `tools/call` at an upstream that looks the name up exactly). Each of those
  previously slipped past the gate and was forwarded verbatim with the real
  credential.
- Two gaps remain, tracked with the aggregate re-listing work in PORM-23: a
  group member the proxy cannot read when it re-lists it is skipped,
  so it contributes nothing to the aggregate catalogue: that is a member
  requiring an MCP session, one answering `tools/list` over
  `text/event-stream`, which the reference SDK does by default and which the
  aggregate path does not parse, and one that answers the catalogue request
  with a redirect, which is refused rather than followed. That skip is
  written to the server log as `group member skipped`, naming the member's slug
  and its upstream id (once per aggregate request, so a member that stays
  broken stays loud), but **no audit row names it**: the row belongs to the
  client's call, which succeeded on the members that did answer, and a
  `tools/call` for one of the missing tools answers `-32602 unknown tool`
  because the name is no longer in the merged catalogue. An operator whose
  member has vanished from the aggregate should call that member's own
  `/{virtual_key_id}/{upstream_slug}/mcp` endpoint, which answers `502` and
  writes the row. And a `tools/list` answer whose SSE event spreads `data:` over
  several lines is passed through unfiltered (and logged).
  The call gate still refuses those tools. A member dropping out is now neutral
  for the ones that remain: every advertised name carries its own member's slug,
  so a missing member removes its own tools from the catalogue and changes
  nothing about any other member's names, or about the rules written against
  them. What a client loses is that member's tools, not the meaning of its
  filters. What is not yet stable is **routability**: a `tools/call` on the
  aggregate endpoint is still routed through the merged catalogue, so a
  well-formed name on a member that could not be listed answers
  `-32602 "unknown tool"` until that member can be listed again. PORM-32 owns
  routing a call by the slug the name already carries, which takes the catalogue
  out of the call path; refusing the whole group while one member is unreadable
  is PORM-71. The proxy re-lists members with its own request rather than
  replaying the client's headers, so a client cannot steer which members answer;
  a member that is down or session-gated still drops out of the catalogue, and
  PoryMCP does not refuse the whole group when one member fails. Discovery reads
  both of the shapes the aggregate path does not (a `text/event-stream` answer
  and a catalogue spread over cursors), so
  `POST /api/v1/upstreams/{id}/discover` is how an operator sees what a member
  that has dropped out of the merged catalogue offers. That is a
  diagnostic, not a fix: what the aggregate serves is unchanged, and making the
  proxy's own `tools/list` follow cursors is PORM-73.
- Management API protected by separate admin key. Unknown API paths answer
  `404` before the admin key is checked, so the existence of an API path is
  observable without it; nothing else is. Failed admin-auth attempts are
  limited to 10 per client IP per minute; the eleventh returns
  `429 {"error":"too many requests"}` with `Retry-After`. Successful requests
  never consume that budget. Failures are logged at warn with the resolved IP,
  never the presented key. The counter is not exposed on `/health`.
- Client IP for that limiter comes from the socket address unless
  `TRUSTED_PROXIES` lists CIDRs that cover the socket. Only then are
  `Forwarded` (RFC 7239, preferred) and `X-Forwarded-For` honoured, taking
  the rightmost hop that is not itself trusted. The default is empty: a
  client cannot spoof its address. Host validation and scheme enforcement
  use the same resolver: `Forwarded` `host=` / `proto=` first, then
  `X-Forwarded-Host` / `X-Forwarded-Proto` (rightmost token), honoured
  only from a trusted socket.
- Every HTTP response (dashboard, `/api/v1`, `/health`, and the proxy)
  carries `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and
  `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.
  The CSP is `default-src 'self'` with hashed inline scripts (no
  `'unsafe-inline'` in `script-src`), `frame-ancestors 'none'`,
  `base-uri 'none'`, and `form-action 'self'`. `style-src` and `font-src`
  still allow `https://rsms.me` until PORM-43 vendors Inter locally.
  `style-src-attr 'unsafe-inline'` is required by Headless UI
  (visually-hidden spans and dialog positioning); injected `<style>`
  elements remain blocked. Hashes are computed at process start from the
  dashboard files that will be served. Embedding the dashboard
  in an iframe is intentionally broken.
- The dashboard admin key still lives in `sessionStorage` and is readable by
  any script that runs in the page. CSP is the current mitigation; moving
  the session to an httpOnly cookie is PORM-49.
- Run container as non-root, prefer read-only root filesystem.
- Rate limiting enforced at the proxy layer (per virtual key), on failed admin
  authentication (per IP), and on discovery (thirty a minute and four in flight,
  per deployment). The three are separate budgets on purpose: spending one never
  spends another. A virtual key's `rate_limit` is optional; `null` and `0` both
  mean **unlimited**: a key created without one is never throttled, and a
  `PATCH` with `null` removes one.
  The per-key limiter runs during authentication, ahead of the tool-policy
  gate, so a blocked call has already spent its budget.
- **One virtual key, N endpoints.** A key that targets a group is reachable at
  one aggregate URL and one URL per enabled member. The rate limit, revocation,
  expiry, `last_used_at` and host validation are all properties of the *key*, so
  they cover every one of those at once: one rotate or revoke closes all N, and
  the N endpoints share a single budget. N endpoints do not mean N budgets. The
  slug in the path is operator-chosen and public, and discloses nothing the
  group's own aggregate catalogue did not already: every tool name there carries
  its member's slug.
- Host validation on the proxy endpoints only (`/mcp`,
  `/{virtual_key_id}/mcp` and `/{virtual_key_id}/{upstream_slug}/mcp`): the
  resolved host is compared with the host of `PUBLIC_URL` and any
  `EXTRA_ALLOWED_HOSTS`. Forwarded host is honoured only when the socket is in
  `TRUSTED_PROXIES`. This is not a dashboard or `/api/v1` rebinding guard. CORS
  is applied on all three proxy endpoints.
- When `PUBLIC_URL` is https and `ALLOW_INSECURE_HTTP` is unset, a
  non-loopback request whose resolved scheme is http is refused with
  `426 {"error":"insecure scheme","scheme":"http"}`. Loopback is exempt so
  `porymcp healthcheck` (`http://127.0.0.1`) still works behind an edge.
  HSTS is the TLS edge's job, not PoryMCP's (see `docs/11-deployment.md`).