# Changelog

Behaviour changes that affect a running deployment. Newest first.

## Unreleased

### The credential the proxy injected is redacted whatever its shape (PORM-208)

- **An upstream that echoes the credential it was sent, in a form the
  pattern rules cannot see, no longer hands it to the agent or the audit
  row.** The proxy knows the value it injected and replaces it with
  `[redacted]` before the pattern rules run, on the row's `error_message`,
  on a JSON-RPC error's message and on a refusal body that is not JSON-RPC,
  on a single-upstream key, a member endpoint and a group endpoint, buffered
  and on the stream door. The pattern rules still run after it, so a
  credential the proxy did not inject is caught as before.
- **The replacement covers every piece of the credential of 8 bytes or
  more.** A value under that is left to the pattern rules, so a short word
  stored as a credential cannot blank ordinary text. The scheme word is
  never replaced on its own: `Authorization: Bearer <token>` in an echo
  reads `Authorization: Bearer [redacted]`, and `Bearer%20<token>` reads
  `Bearer%20[redacted]`.
- **Every value a `custom` credential's headers hold counts.** A non-secret
  header stored beside the secret is replaced wherever an error names it.
- **A refusal body over 64 KiB is scanned whole before it is cut,** so the
  cut cannot leave a fragment of the credential at the edge.

### A refusal that is not JSON-RPC no longer returns the credential to the agent (PORM-205)

- **A gateway's plain-text, HTML or JSON 401 that quotes the credential reads
  `invalid token [redacted]` in the agent's answer.** The status and
  `Content-Type` are the upstream's. The same rules as the audit row's
  `error_message` apply to any body with a status of 400 or above that is not
  a JSON-RPC error envelope, whatever its media type apart from an event
  stream, on a single-upstream key and a member endpoint. A binary 4xx body is
  scanned and cut like any other.
- **A refusal with nothing credential-shaped in it and under 64 KiB is
  relayed byte for byte.** An agent that matches on a refusal's text now
  sees `[redacted]` where a trace id, a container id or another token-shaped
  run stood.
- **A refusal body is at most 64 KiB.** It is cut at a value boundary before
  the rules run, so a JSON refusal over that bound no longer parses. A JSON
  refusal under it is decoded and scanned, and comes back compact with its
  members sorted when a decoded string held the match; one the rules would
  leave unparseable, or one that opens as JSON, gets no walk (over the bound,
  or not parsing) and holds a `\u` or `\/` escape, answers `502` with
  `upstream request failed`.
- **On a group endpoint a plain-text or HTML refusal still reaches the agent as
  its status with no body.** A JSON body there that is not JSON-RPC is redacted
  as on the other endpoints.

### An upstream's error message no longer returns the credential to the agent (PORM-195)

- **A failed call at an upstream that echoes its credential reads
  `invalid token [redacted]` in the agent's answer too.** The JSON-RPC code,
  id and data are the upstream's. The same rules as the audit row's
  `error_message` apply, on a single-upstream key, a member endpoint and a
  group endpoint, in JSON, in an event stream and on a held-open stream.
- **An error whose message holds nothing credential-shaped and is under
  64 KiB is relayed byte for byte, as is every result and notification.** A
  trace id, a container id or a camelCase name of 20 or more letters with
  two digits inside an error message now reads `[redacted]` for the agent as
  well as in the row.
- **The message an agent receives is at most 64 KiB.** It is cut at a value
  boundary before the rules run; as in the row, a window with no boundary in
  it is kept whole, so a credential pressed against padding with no
  separator can keep a fragment.
- **A streamed event that carries data reaches the client at its ending
  line.** Keep-alive lines and other lines outside such an event still reach
  it as they arrive. An event over 1 MiB that is not shown to be a result or
  a notification is held to its end, and a stream ends when such an event
  passes 16 MiB, the bound a buffered answer already has.

### Credential-shaped text in error_message is redacted (PORM-72)

- **An upstream that echoes the credential it was sent no longer writes it
  to the audit log.** A row that used to read `invalid token ghp_…` reads
  `invalid token [redacted]`. The rules cover `Bearer` and `Basic` values,
  labelled values such as `X-API-Key: …`, vendor prefixes (`sk-`, `ghp_`,
  `github_pat_`, `glpat-`, `xoxb-`, `AKIA`, JWTs) and any run of base64
  characters holding letters and two digits that is 20 or more characters
  with no separator, or that mixes upper and lower case. Redaction is best
  effort: a short opaque value, a lowercase hyphenated value, an unlabelled
  UUID-shaped key or a mixed-case key with fewer than two digits (about one
  in seven at 20 characters) is not recognised, and a token the upstream
  has encoded or split with invisible characters can keep a fragment.
- **`error_message` is at most 256 bytes on every row.** The bound is
  applied after redaction, so a token cut at the boundary is never stored
  in part.
- **An id that looks like a token is redacted too.** A trace id, a
  container id, another vendor's request id, a host label or a camelCase
  tool name of 20 or more letters with two digits reads `[redacted]` inside
  the sentence. The row's `upstream_id`, `tool_name` and `request_id` are
  unchanged.
- **Rows written before the upgrade keep the upstream's text as sent.**
  Nothing purges them until retention ships (PORM-13). An operator whose
  upstream echoed a credential into an older row should rotate that
  credential at the vendor.

### Transport failures on the MCP door are recorded as fixed sentences (PORM-191)

- **A refused connection, a DNS failure, a TLS failure or a reset now reads a
  fixed sentence.** On `/{virtual_key_id}/mcp` and
  `/{virtual_key_id}/{upstream_slug}/mcp` the row reads
  `cannot connect to <host>`, `cannot resolve <host>`,
  `tls handshake with <host> failed` or `cannot reach <host>`, where it used
  to quote Go's text with the registered URL and the dialled address. The host
  is the registered URL's host, with its port when the URL names one, or
  `the upstream` when it holds a byte outside letters, digits and `._-:[]`.
- **A saved search for `dial tcp` or `connection refused` matches only rows
  written before the upgrade.** Search `error_message` for
  `cannot connect to` and `cannot resolve` instead.
- **A client that hung up before the answer reads
  `client went away before the answer`.** On the MCP door it used to read Go's
  cancellation text with the registered URL. On the HTTP relay door it used to
  read `cannot connect to <host>` or `cannot reach <host>`, which blamed the
  upstream.
- **A body that failed while it was being read reads
  `upstream connection failed`.** A body that ended without its terminator
  reads `unexpected EOF`. On the MCP door it used to quote the read error,
  which named the resolved address. On the HTTP relay door it used to read
  `cannot connect to <host>` or `cannot reach <host>`. Whether the answer was
  buffered or streamed, the read error is not recorded.
- **A stored URL that does not parse reads `upstream url is not usable`.**
  That is the relay door's sentence, in place of the parse error, which quoted
  the URL.
- **The `group member skipped` log line carries the same sentence as the
  member's own row.**
- No schema change. Stored rows are not rewritten. The client's
  `502 upstream request failed` is unchanged. Rollback is the previous image.

### Breaking: upstream addresses on loopback, link-local and metadata ranges are refused (PORM-79)

- **A `localhost` upstream on a bare binary stops working** until
  `UPSTREAM_ALLOW_LOOPBACK=true` is set; discover and test say so, and the
  startup line `upstream guard` shows the setting. Inside a container loopback
  is the container itself: reach the host as `host.docker.internal`.
- **Every outbound dial on the upstream client is checked against the address
  it resolved.** Loopback, link-local, multicast, unspecified and the cloud
  metadata addresses are refused; the proxy answers the usual `502`, the audit
  row reads `upstream address denied: <class>` (the class, never the address),
  and one Warn line, `upstream address denied`, reaches the server log.
  Private ranges stay open by default.
- **Two new variables.** `UPSTREAM_ALLOW_LOOPBACK` reopens loopback and nothing
  else; `UPSTREAM_DENY_PRIVATE` also refuses RFC 1918, ULA and CGNAT
  addresses, which breaks compose-network, cluster-IP and tailnet upstreams.
  The shipped `docker-compose.yml` passes both through; a copied compose file
  needs `UPSTREAM_ALLOW_LOOPBACK: ${UPSTREAM_ALLOW_LOOPBACK:-}` and
  `UPSTREAM_DENY_PRIVATE: ${UPSTREAM_DENY_PRIVATE:-}` added.
- **`POST` and `PATCH /api/v1/upstreams` answer per-rule `400`s.** A fragment
  is `url must not carry a fragment` and embedded credentials are
  `url must not embed credentials`, on every kind; the stored URL is the
  form `url.Parse` re-serialises (scheme lower-cased, unescaped path
  characters percent-encoded, an empty fragment dropped; host, port and
  trailing slash kept). A row is rewritten only by a `PATCH` that sends
  `url`. A client that compared the one old sentence, or read back the exact
  bytes it sent, sees a change.
- **Dual-stack upstreams are dialled one address at a time.** The guard
  resolves the host itself and tries the permitted addresses in resolver
  order, each on its share of a 30 s dial budget, instead of Go's 300 ms
  race between address families. An address the host cannot route to fails
  at once and the next is tried; one that drops packets keeps its share, so
  an upstream whose first address is black-holed fails until its DNS is
  fixed.
- **Behind an egress proxy the guard checks the proxy's address only**, so a
  proxy on loopback needs `UPSTREAM_ALLOW_LOOPBACK`; what the proxy fetches
  is the proxy's job. On OAuth Connect a refused metadata or registration
  address reads `authorization server address denied: <class>`; a refused
  token endpoint reads `credential refresh failed` on refresh, as before.
- No schema change. Rollback is the previous image, or the variable and a
  restart.

### Plain HTTP APIs behind a virtual key (PORM-146)

- **An upstream can now be an HTTP API.** `POST /api/v1/upstreams` takes
  `kind: "http"` with a base URL, a credential and an optional `test_path`;
  a virtual key on it is served at `/{virtual_key_id}/api/<path>` (and an
  HTTP API member of a group at `/{virtual_key_id}/{slug}/api/<path>`), where
  any `GET`, `HEAD`, `POST`, `PUT`, `PATCH` or `DELETE` is relayed to the base
  URL with the same path, query, headers and body, the virtual key swapped
  for the stored credential, and the upstream's status, headers and body
  relayed back. `kind` defaults to `mcp` and cannot be changed after create.
  Existing upstreams and keys are unchanged.
- **Schema version 7.** The first boot adds `upstreams.kind`,
  `upstreams.test_path` and `virtual_keys.http_methods`, with defaults, and
  stamps the version. The stamp is one-way: the previous build refuses the
  database at `Open`, so the rollback is restore from backup. Back up before
  the upgrade (`docs/11-deployment.md`, section 14). The step moves no data,
  so the start does not pause.
- **`http_methods` on a virtual key** limits the verbs it may send through an
  `/api/` endpoint (`["GET","HEAD"]` for a read-only key; empty means every
  one of the six). A refused verb is `403` with a `blocked` audit row. The
  MCP endpoints never read it.
- **Refusals on an `/api/` endpoint are plain JSON**
  (`{"error":"…","request_id":"…"}`), not a JSON-RPC envelope, and the
  relay's `429` carries `Retry-After`. The MCP endpoints' bytes are
  unchanged.
- **Audit rows for relayed requests** record the verb in `method`, the path
  in `tool_name` (beginning with `/`), and the query, content type and
  request size in `params`, with secret-looking query values redacted. The
  request body is not recorded.
- **`oauth` is refused on an HTTP API upstream** for now: the connect flow
  starts with an MCP `initialize`, which a REST API cannot answer. Bearer,
  header, API-key and custom credentials work.
- **The Test button** on an HTTP API upstream sends one `GET` to the base URL
  joined with `test_path` and reports the status; `POST /upstreams/{id}/discover`
  answers `kind: "http"`, `http_status` and an empty `tools`.
- **An upstream's `endpoints[]` entries carry `kind`**, and a single HTTP API
  key's `proxy_url` ends in `/api/`. A group's `proxy_url` stays its `/mcp`
  aggregate whatever its members are.

### Event-stream answers are relayed as they arrive (PORM-5)

- **A 2xx `text/event-stream` answer on a member or single-upstream endpoint
  reaches the client as the upstream writes it**, so `subscriptions/listen`
  and streamed `tools/call` progress work through the proxy; `tools/list`,
  non-2xx, unlabelled and group answers stay buffered.
- **The flat 60 s upstream timeout is gone.** A buffered answer has five
  minutes, a connection ten seconds, a stream five minutes between reads and
  per client write, and a group member's listing 60 s as before. The row text
  for a timeout changes from `Client.Timeout exceeded while awaiting headers`
  to `upstream did not answer within 5m0s`.
- **An upstream that accepts the connection and never answers now holds a
  buffered call for up to five minutes, not 60 s.** An edge with a shorter
  timeout, such as Cloudflare at 125 s, cuts it first.
- **A streamed row is written when the stream ends**, with the bytes relayed
  and the latency to the end. **A `subscriptions/listen` row is `success` when
  the client closes the stream**, because closing it is how a listen ends.
- **A key that is revoked, expired, rotated or retargeted, an upstream removed
  from it, or an upstream whose URL, transport or credential changed since
  the stream opened, ends its open streams within a minute.** A new name or
  description leaves a stream alone.
- **The proxy sets `X-Accel-Buffering: no` on streams.** nginx operators keep
  `proxy_buffering off` for the rest.
- **Shutdown ends open streams and the audit queue is drained before exit**; a
  row recorded after the drain is logged and dropped instead of panicking.
- **Rollback** is the previous `sha-<short sha>` image; no schema change.

### Virtual keys are verified with SHA-256 instead of argon2id (PORM-44)

- **A proxied call no longer spends about 60 ms and 64 MiB checking its
  key.** The proxy compares, in constant time, the SHA-256 digest it already
  stored for every key; sixteen calls in flight no longer hold about 1 GiB,
  and creating or rotating a key is as fast. Every existing key keeps
  working with no re-keying, and the schema version stays 6.
- **A key with no `rate_limit` is no longer slowed by hashing.** It calls as
  fast as the network allows, and every call still writes its audit row and
  `last_used_at`; set a limit where that matters.
- **The previous build refuses keys created or rotated on this one** with
  `401`, because it checks a hash they no longer have; keys made before this
  build and not rotated since keep working under it. Before a rollback, list
  the keys that will need rotating (`length(key_hash) = 0` and not revoked;
  the commands are in `docs/11-deployment.md`, section 15), and rotate them
  under the previous build afterwards, or roll forward. Stop every
  previous-build replica before starting this one.

### A relayed answer is read the way a routed call's is (PORM-172)

- **Rows that read `success` now read `error` when the upstream's error came
  in SSE framing.** On a single-upstream key and a member endpoint an
  upstream's JSON-RPC error inside an event stream was written as `success`
  with no message, because the row was judged from the raw bytes. It is now
  judged from the document that answers the request, in either framing, and
  carries the upstream's message, bounded. The bytes the client receives on
  those routes do not change. Dashboards and alerts built on the old counts
  move.
- **A group endpoint no longer sends a member's `Mcp-Session-Id` or media
  type on a relayed method** (`resources/read`, `prompts/get`,
  `logging/setLevel` and the rest). The member's answer is reduced to its one
  document and sent as `application/json`, as a routed `tools/call` answer has
  been since PORM-171, and a 2026-07-28 client gets `resultType: "complete"`
  when a handshake-era member sent none. The server log line for an answer
  that could not be reduced now reads `group answer relayed unreduced` and
  names the method.
- **A 2026-07-28 client's relayed request to a handshake-era first member no
  longer carries the version header that member would refuse,** nor the three
  reserved `_meta` members; every other value crosses as sent. The member's
  era is read from the cache and, on a miss, probed, under the era probe's
  existing bounds: one `server/discover` per member per ten minutes for
  callers in sequence, thirty seconds while the member does not answer.
- **A member body on a group endpoint that is neither JSON nor an event stream
  keeps its status with no body** when the status is `400` or above (a `429`
  keeps its `Retry-After`), and is a `502` on a success status. On a relayed
  method it used to be passed through with the member's label; on a routed
  call every such body used to be a `502`.
- **`Retry-After` now crosses on a routed `tools/call`**, as it already did on
  a relayed method.

### The group endpoint is a server in both protocol eras (PORM-153)

- **A 2026-07-28 client can use a group.** Claude Code showed a group as
  connected with "tools fetch failed, INVALID_RESULT": the merged tool list had
  no `ttlMs`, which that revision requires. The list now carries `ttlMs` (the
  smallest value a member reported, between 10000 and 3600000), PoryMCP's
  `serverInfo`, and a conforming `inputSchema` on every tool. A member that
  reports no `ttlMs`, as every handshake-era member does, counts as 60000. `server/discover` on a group
  is answered by PoryMCP, where it used to be relayed to the group's first
  member and describe that one upstream.
- **A call through a group works across eras.** The request is composed for the
  era the member speaks, so a 2026-07-28 client can call a handshake-era member
  and a handshake-era client can call a 2026-07-28 one. Both used to be refused
  by the member.
- **`initialize` on a group answers the version the client asked for** when it
  is `2024-11-05`, `2025-03-26`, `2025-06-18` or `2025-11-25`, and `2025-11-25`
  otherwise. It used to answer `2024-11-05` whatever was asked. Reconnect
  clients on a group URL.
- **A method a group relays to its first member no longer carries a
  handshake-era client's `MCP-Protocol-Version`.** That version is the one the
  group endpoint agreed to, for itself, and a member on an older revision would
  refuse it. `logging/setLevel`, `prompts/*`, `resources/*` and the rest reach
  the first member with no version header, which a handshake server reads as
  `2025-03-26`. A 2026-07-28 client's relayed request is unchanged.
- **`subscriptions/listen`, `tasks/get` and `tasks/update` are refused on a
  group** with `404` and `-32601`, and reach no member. `ping` is answered by
  PoryMCP. A group request that declares a stateless revision other than
  `2026-07-28` is answered `400` with `-32022`.
- A stored `auth_config` that names `Mcp-Name` no longer replaces the name
  PoryMCP rewrites on a group call. The API has refused to save such a config
  since PORM-150.
- **`initialize` and `notifications/initialized` rows on a group no longer name
  an upstream.** The group endpoint answers both itself and contacts nobody, but
  their audit rows carried the id of the group's first member. `upstream_id` is
  now empty on them, as it always was for a group's `tools/list`. Filtering the
  Logs page by that upstream no longer shows these rows. `notifications/initialized`
  is also answered `202` with no body, where it used to send `{}`.

### A group lists and calls members that answer as an event stream (PORM-171)

- **A group can serve more tools after this upgrade.** A member that answered
  `tools/list` as `text/event-stream`, which is what the reference SDKs and most
  hosted servers do, was dropped from the group's merged catalogue while it
  listed everywhere else. It is now listed like any other member. A key's allow
  and deny rules already apply to the recovered `{upstream_slug}__{tool}` names.
  Reconnect clients on a group URL so they fetch the longer catalogue.
- **A call through a group is answered as JSON.** A member's event-stream answer
  to a `tools/call` used to reach a group's client labelled `application/json`,
  and a failed call was logged as a success. The client now gets the one
  answering document, with the member's HTTP status, and the Logs row records
  its outcome. An answer with no such document in it is passed on as it came
  when it is JSON or an event stream; its row is judged by the HTTP status and
  what can be read of its bytes, and the server log says `group answer relayed
  unreduced` (PORM-172, above). A member that answers with a body in any other
  media type keeps its failure status with no body, or is a `502` on a success
  status (PORM-172).
- A member can still be missing from a group when it refuses a `tools/list` sent
  without a session, answers with a redirect, or answers something the proxy
  cannot read. The `group member skipped` log line says which.

### Upstreams on the 2026-07-28 revision can be discovered and grouped (PORM-151)

- **Discovery asks `server/discover` first.** An upstream that serves only the
  2026-07-28 revision used to fail its Tools check with a handshake error and a
  red dot, because `initialize` no longer exists there. It is now listed
  statelessly, and the panel's protocol line reads "2026-07-28, stateless". A
  handshake server sees one method it does not know and then exactly the
  sequence it always saw. The discovery response gains `era`,
  `supported_versions` and `capabilities`, and loses nothing.
- **A legacy upstream is asked for `2025-11-25`.** `initialize` requested
  `2025-06-18`. A server on an older revision still answers with its own, and
  that answer is what is recorded and declared afterwards.
- **A group lists each member in the era it speaks.** The aggregate endpoint
  sends the same probe to a member the first time it meets it, remembers the
  answer in memory for ten minutes (thirty seconds when the member did not
  list), and asks again when the upstream is saved. A legacy member receives
  the same catalogue request as before. Expect one extra request per member
  after a restart or redeploy.
- **A call to a modern-only member through a group is not bridged yet.** It is
  the client's own request relayed as sent, so that member refuses it with
  `-32020` unless the client is itself on 2026-07-28. PORM-153 has it.

### The 2026-07-28 routing headers cross the proxy, and are checked (PORM-150)

- **`Mcp-Method`, `Mcp-Name` and the `Mcp-Param-` headers now reach the
  upstream.** The proxy forwarded six client headers by name and dropped
  these. An upstream on the 2026-07-28 revision answers `400` with a header
  mismatch when they are missing, and that error tells a client the server is
  modern, so it does not fall back: the connection was a dead end with a
  relayed `400` in the log. On a group's aggregate endpoint `Mcp-Name` is
  rewritten to the member's own tool name, beside the `params.name` that was
  already rewritten.
- **A request whose routing headers disagree with its body is now refused by
  PoryMCP.** `400` with `-32020`, the revision's own code, a message naming
  the header and never its value, no upstream contacted and an `error` audit
  row. A client that sent a wrong `Mcp-Name` was relayed before this and
  failed at the upstream.
- **On a request declaring `2026-07-28` or later the headers are required.**
  The declared version is `MCP-Protocol-Version`, or the body's `_meta`
  version when the header is absent, and the two must agree. A request
  declaring an earlier version, or none, is refused only when a header it did
  send disagrees, so a client that sends none of them is unaffected, as long
  as its `params._meta` is an object the proxy can read.
- **At most 32 `Mcp-Param-` values cross, no name or value over 4096 bytes.**
  Over either bound the answer is `431` with `-32000 "too many or too large Mcp-Param
  headers"`, and a value outside printable ASCII is `400` with `-32020`. The
  bounds are PoryMCP's own; the revision caps neither.
- **A `tools/list` the proxy relays no longer claims `cacheScope: "public"`.**
  Any scope an upstream sends on a list the proxy can read leaves as
  `private`, whether or not a tool was removed, because one proxy URL answers
  for every key; a list
  that carried no scope is relayed byte for byte, so a client on an earlier
  revision whose upstream sends none sees no change. The aggregate endpoint's
  merged list carries `cacheScope: "private"` and `resultType: "complete"`;
  `ttlMs` on it is PORM-153.
- **The CORS preflight allows the new names.** `Mcp-Method` and `Mcp-Name` are
  always allowed, and up to 32 `Mcp-Param-` names the request asks for are
  echoed back; a request that asks for more, or that lists more than 64
  header names in all, is refused them all at the preflight.
- **There is no setting.** Rolling back to
  `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the previous binary;
  no schema or data is involved.

## v0.1.0 (2026-09-06)

### Breaking: the sse upstream transport is refused on write (PORM-28)

- **The README advertised SSE pass-through and it was never implemented.**
  The proxy has always POSTed Streamable HTTP to every upstream whatever its
  stored `transport` said; the legacy HTTP+SSE client is PORM-5.
- **`POST /api/v1/upstreams`, `PATCH /api/v1/upstreams/{id}` and
  `POST /api/v1/upstreams/discover` answer `400 {"error":"invalid transport"}`
  for `sse`.** `streamable-http` is the only value accepted on write. The
  create and unsaved-discover `400` that read `invalid transport or auth_type`
  is split into `invalid transport` and `invalid auth_type`, the strings PATCH
  already used.
- **Rows already stored as `sse` are kept.** Nothing rewrites or deletes them.
  They are listed with an Unsupported badge in the Transport column, the Edit
  dialog shows `sse (unsupported)` with Streamable HTTP as the repair, and the
  server logs one WARN line per such row at startup naming its id. Edit one by
  omitting `transport` or by sending `streamable-http`; a body that echoes
  `sse` is `400`. No recreate is needed.
- **A request routed to a stored `sse` row is not dialled.** The agent gets
  the usual `502 upstream request failed`; the audit row names the upstream
  and reads `the sse transport is not implemented yet; use streamable-http`.
  A row that worked because its URL already spoke Streamable HTTP now fails
  until `transport` is set to `streamable-http`; the URL does not change.
- **A group with an enabled `sse` member fails on its aggregate endpoint**,
  `initialize` included, until the member is disabled or repaired. The other
  members' own endpoints keep working. Rolling back to
  `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the previous binary,
  which accepts `sse` on write again; no schema or data is involved.

### Timestamps stored fixed-width (PORM-26)

- **Log order, `next_cursor`, `since`/`until` and the stats windows are now
  exact at any fraction of a second.** Every stored timestamp is written as
  `2006-01-02T15:04:05.000000000Z`, 30 bytes, UTC, so the byte order SQL
  applies to the TEXT columns is time order. Before this change trailing
  zeros were dropped, so two audit rows a microsecond apart could list in the
  wrong order and a page cursor could skip or repeat rows at a page edge.
- **Upgrading is one-way from the first boot, and needs a backup first.** This
  build stamps schema version 6 the moment it opens the database, even if
  startup then refuses for another reason, and earlier builds refuse a
  version-6 database. Take a database backup before upgrading, and keep it
  with the `ENCRYPTION_KEY` that was current when it was taken
  (`docs/11-deployment.md` §13).
- **Stop every old process before starting the new one.** A process already
  running the old build keeps writing the short spelling to rows the
  migration will not revisit. With more than one replica, stop them all, start
  one, wait for `schema migrated` with `version=6`, then start the rest.
- **The first start pauses while stored timestamps are rewritten**, roughly
  65 to 70 s per million audit rows on SQLite as measured on a four-core
  virtual machine, and the container reports `unhealthy` until it finishes.
  Under the shipped compose file it recovers on its own; Swarm and Kubernetes
  operators time the start on a copy of the database and size `start_period`
  or a startup probe from that.
- `GET /admin-events?since=` with a fractional `since` no longer includes a
  row from earlier in the same second. `GET /logs` `since` and `until` are
  inclusive and exact. A `next_cursor` issued by the previous build still
  works.
- No settings and no API shape change. The JSON timestamps the API returns
  are unchanged.

### GET on a proxy endpoint is answered 405 (PORM-30)

- **A `GET` on `/mcp`, `/{virtual_key_id}/mcp` or
  `/{virtual_key_id}/{upstream_slug}/mcp` returns `405` with
  `Allow: POST, DELETE, OPTIONS` and contacts no upstream.** Streamable HTTP
  clients open that `GET` after `initialize` to listen for server-initiated
  messages. Before this change it was forwarded and the client waited for the
  proxy's 60 s upstream timeout, so a server took about a minute to become
  usable, or saw one failed stream per connect against an upstream that
  answered the `GET` quickly.
- **The refusal is written before the virtual key is read.** A probe costs no
  key lookup and no upstream request, no audit row is written for it, and a
  `GET` no longer tells a caller whether a key is live. The server log still
  carries one line per refused request.
- **Every other verb the router recognises gets the same `405`, `HEAD`, `PUT`
  and `PATCH` included.** Before this change any verb with a valid key was
  replayed to the upstream with the stored credential attached.
- **`OPTIONS` now carries `Allow`.** The `204` names the methods the endpoint
  supports, with or without an `Origin`.
- **`DELETE` still reaches the upstream unchanged.**
- **A request whose body named no JSON-RPC method records the HTTP verb in
  `audit_logs.method`.** A session teardown records `DELETE` and a bodyless
  `POST` records `POST`; those rows recorded nothing, and the Logs page's
  method filter could never match them.
- **`Access-Control-Allow-Methods` no longer names `GET`.** The same constant
  feeds `Allow`, so the two cannot disagree. A browser's `GET` is unaffected
  either way: `GET` is a CORS-safelisted method, which a preflight never
  refuses on that header.
- **A valid key's refused `GET`s no longer count against its rate limit.** The
  refusal costs no store read and no upstream call.
- **There is no setting.** Rolling back to
  `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the previous binary
  and with it the stall; no schema or data is involved.

### Upstream response headers are an allowlist (PORM-98)

- **A 1:1 forward returns three upstream response headers and drops the
  rest.** `Content-Type`, `Mcp-Session-Id` and `Retry-After` reach the client
  on `/{virtual_key_id}/mcp` and `/{virtual_key_id}/{upstream_slug}/mcp`.
  Before this change every header except `Content-Length` did.
- **`Set-Cookie` and `WWW-Authenticate` no longer reach the client.** A client
  that read an OAuth challenge out of an upstream 401 now sees a 401 with no
  challenge, which is what PoryMCP's own 401 has always been. The client's
  `Cookie` was never forwarded upstream, so no cookie round trip is lost.
- **An upstream's `Access-Control-Allow-Origin`, `Vary`,
  `Content-Security-Policy` and `X-Frame-Options` no longer duplicate the ones
  PoryMCP sets.** A browser client that failed CORS against a permissive
  upstream now connects.
- **`X-Request-Id`, `X-RateLimit-*`, `Server`, `ETag` and `Connection` from
  the upstream no longer reach the client, and PoryMCP records none of
  them.** An agent that read remaining quota out of a header loses it.
- **`Date` is PoryMCP's own rather than the upstream's.** PoryMCP records the
  `X-Request-Id` a client sends as the `request_id` on the audit row, which is
  how a call is correlated now.
- **An upstream that answers in an encoding PoryMCP did not ask for has its
  `Content-Encoding` dropped while the compressed body is relayed.** That is
  `br` or `zstd`, never gzip, which Go decompresses; a client then sees bytes
  it cannot decode. Refusing such a response at the proxy is PORM-142.
- **Every response the proxy endpoints write carries
  `Cache-Control: no-store`, and an upstream's `Cache-Control` is not
  relayed.**
- **`Access-Control-Expose-Headers` names `Retry-After`, so a browser client
  can read it.**
- **There is no setting.** Extending the list is a code change with a review.
  Rolling back to `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the
  previous binary and with it the leak; no schema or data is involved.

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
  `{}` keep their bytes and keep counting until a request sends
  `auth_config: {}` to the row or switches it to `auth_type: "none"`, since an
  ordinary save sends nothing about the credential.
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
