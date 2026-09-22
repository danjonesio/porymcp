# Architecture

## High-level components
- Management API (REST + OpenAPI)
- MCP Proxy core (JSON-RPC forwarding over Streamable HTTP `POST`, plus the
  `DELETE` that ends a session; a client's `GET` for a server-initiated stream
  is refused `405` until PORM-5)
- Auth middleware (virtual key validation)
- Credential injector (holds real secrets, never exposes them, and presents each
  to the upstream's own URL, never to a host the upstream names in a redirect)
- Upstream client (`internal/mcpclient`): the one place a real credential is
  written onto an outgoing request, and the one construction every client that
  carries one comes from: one refusal to follow a redirect, one wrapped default
  transport, and a timeout and read cap each caller sizes for its own job (the
  proxy relays a client's call in 60 s and 16 MiB; discovery has 10 s and 2 MiB
  for a whole handshake; the era probe, `server/discover`, has 5 s and 2 MiB
  for its one round trip, on both planes). The proxy's relay, the proxy's own
  catalogue request and era probe, and the dashboard's discovery call all go
  through it, so a rule added here holds on all of them rather than on the path
  someone remembered
- Tool discovery (management plane): a real MCP handshake against one upstream,
  run for an **operator** rather than a virtual key, returning a fixed set of
  structured fields and persisting nothing
- Member router (for Groups: resolves `/{virtual_key_id}/{upstream_slug}/mcp` to one enabled member and forwards 1:1; the primary path)
- Aggregator (for Groups: the secondary single-connection view: merges the members' catalogues and names every tool for the member that owns it, `{upstream_slug}__{tool}`, always (e.g. `github__create_issue`), not only when two members collide)
- Tool-policy gate (one predicate over the group `tool_filter` and the key's
  allow/deny lists, consulted by both `tools/call` and `tools/list`)
- Audit logger (async writes)
- Optional dashboard (React, Tailwind CSS and Headless UI)

## Data flow

### Per member (primary, group keys)

```text
Agent → /{virtual_key_id}/{upstream_slug}/mcp with its virtual key
→ Validate key and path (a key on another key's path is 403 before the body is read)
→ Compare the routing headers with the body: a disagreement stops here with
  400 and JSON-RPC -32020, contacting no upstream
→ Resolve target (a Group, or 404)
→ Resolve the enabled member the slug names (404 if there is none)
→ Apply tool policy with that member's {slug}__ identity: a blocked
  tools/call stops here with JSON-RPC -32602 "tool blocked" and a blocked
  audit row carrying the member's upstream_id, contacting no upstream
→ Inject real credentials
→ Forward verbatim to that one member, at its configured URL and never to a
  host it names in a redirect: a 3xx answer is a failed call (502, and an
  error row naming the redirect host), not a second request
→ Filter its tools/list response through the same policy, leaving the original
  names
→ Copy back only the allowed response headers: Content-Type, Mcp-Session-Id,
  Retry-After
→ Log (async)
→ Return response
```

### Aggregate (secondary) and single-upstream keys

```text
Agent → /{virtual_key_id}/mcp (or shared /mcp) with its virtual key
→ Validate key (and path, when present)
→ Compare the routing headers with the body: a disagreement stops here with
  400 and JSON-RPC -32020, contacting no upstream
→ Resolve target (Upstream or Group)
→ On a group tools/call, split the tool name at its first __ into an
  upstream slug and that upstream's own tool name: a name with no __, an
  empty half, or a head that is not a valid slug is one the aggregate never
  advertised, and stops here with JSON-RPC -32602 "unknown tool: <name>" and
  an error audit row, contacting no upstream
→ Apply tool policy: a blocked tools/call stops here with JSON-RPC
  -32602 "tool blocked" and a blocked audit row, contacting no upstream
→ Inject real credentials
→ Forward to real MCP server(s) at their configured URLs, rewriting a group
  tools/call back to the upstream's own tool name: a well-formed name no
  member's catalogue holds answers the same -32602 "unknown tool: <name>"
  after the catalogue requests and before anything is forwarded, and a member
  that answered its catalogue request with a redirect is one of the members
  whose tools are not in that catalogue
→ Filter a tools/list response through the same policy, prefixing every
  member's tools with that member's slug
→ Log (async)
→ Return response
```

On a group target the aggregator is an MCP server in both protocol eras. It
answers `server/discover`, `initialize`, `notifications/initialized`, `ping` and
`tools/list` itself, refuses `subscriptions/listen`, `tasks/get` and
`tasks/update` with `404` and `-32601`, and routes `tools/call` to the member
that owns the tool, composing the request for the era that member speaks (the
era comes from the era cache, read and never probed on this path). Everything
else goes to the first member, composed for that member's era when a
`2026-07-28` client sent it (the era cache, probed on a miss, at most once per
member per ten minutes), and no upstream session reaches the client. A member is
listed whether it answers `tools/list` as JSON or as an event stream, and every
answer on a group endpoint, to a routed `tools/call` or a relayed method, is
reduced to its one JSON document before the client sees it, so the audit row
is judged from the bytes the client is sent. An answer with no such document
in it is passed on as it came when it is JSON or an event stream; any other
media type keeps its failure status with no body, or is a `502` on a success
status. On a single-upstream key and a member endpoint the answer is relayed
as the upstream sent it, and only the row is judged from the answering
document.

### Sessions and response headers
The proxy is stateless: it holds no session table. Each member URL carries its
own MCP session, minted by that member and returned to the client in
`Mcp-Session-Id`. A session id minted by member A is forwarded verbatim if a
client sends it to member B, which rejects it: that is the member's decision,
not PoryMCP's. On the 1:1 path the proxy copies back three response headers
and no others: `Content-Type`, `Mcp-Session-Id` and `Retry-After`
(`copyResponseHeaders`, PORM-98). Everything else the upstream sets is dropped,
`Set-Cookie`, `WWW-Authenticate`, `Server` and the upstream's own
`Access-Control-Allow-Origin` included. An upstream cannot mint a session a
browser stores against PoryMCP's origin, cannot name its authorization server
to a key holder in a response header, and cannot duplicate the CORS and
security headers PoryMCP sets. The response body is relayed as it always has
been. Every response the proxy endpoints write carries
`Cache-Control: no-store`. That copying happens only on a response the proxy
relays, and a `3xx` is never relayed (the call has already failed by then), so
`Location` never reaches the client on any path, and neither does anything else
the redirect response set.

Inbound, the proxy forwards eight named client headers and every `Mcp-Param-`
header within its bound, and compares `Mcp-Method`, `Mcp-Name` and
`MCP-Protocol-Version` with the body before anything is sent
(`copyHopHeaders`, PORM-150). The names and the bound are in
`docs/07-security.md`.

Server-initiated messages are not proxied. A `GET` on a proxy endpoint is
answered `405` with `Allow: POST, DELETE, OPTIONS` in the shared serve body,
after the CORS block and the host check and before the key is read, so a
refused probe costs no key lookup, no upstream request and no audit row; the
request log records it. The proxy's own `Access-Control-Allow-Methods` names
the same three verbs, from the same constant. Real streaming over `GET` is
PORM-5.

### Discovery (management plane, not a proxy path)

```text
Operator → POST /api/v1/upstreams/{id}/discover, or /upstreams/discover with
an unsaved body, carrying the admin key
→ Spend one token from the discovery budget (30/min), before the store is read
→ Load the upstream, or read the payload; stop before any outbound request if a
  stored credential is present and cannot be decrypted (the saved route still
  stamps that row as a failure)
→ Take one of four in-flight slots, so a request that makes no outbound call
  never holds one
→ Check the URL is an absolute http or https URL
→ Inject the real credential and ask server/discover on the 2026-07-28
  revision, against that URL and never a host it names in a redirect
→ A modern server: tools/list followed to the end of its cursors, each request
  declaring its version and method and carrying _meta, capped at 500 tools and
  50 pages; no session, so nothing to end
→ Anything else: initialize, notifications/initialized, then tools/list the
  same way, and DELETE the session, so none is left open on the upstream
→ On the saved route, stamp last_test_at and last_test_ok on that upstream's
  own row (a timestamp and a flag, never anything the upstream said) unless
  the caller has gone away or the row was edited or deleted while the handshake
  ran
→ Return a fixed set of structured fields (no upstream header, no upstream body
  outside them) with ok describing the upstream and 200 describing the
  request
→ Write no audit row, and no log line of its own beyond one DEBUG or WARN
  naming the upstream id when that stamp could not be written
```

The whole sequence, the probe included, is bounded at 10 s and the teardown at
a further 2 s. The catalogue is not stored: it is read again on the next call.
`docs/03-api.md` has the rule that decides which era an answer means.

### The era cache (data plane, group endpoints only)

A group's aggregate endpoint lists every member to build its catalogue and to
route a call, and it lists each member in the era that member speaks. The first
time it meets an upstream it sends the same `server/discover` probe, through the
same client, with the real credential and PoryMCP's own constants (nothing of
the inbound request reaches it), and remembers the verdict in memory. A modern
member is then listed with `MCP-Protocol-Version`, `Mcp-Method: tools/list` and
`params._meta`; a legacy member gets the bare `tools/list` it always got; a
modern member that cannot be spoken to is skipped with the usual
`group member skipped` warning and no request. Nothing is persisted: a restart
or a redeploy means one cold walk.

One rule sets how long a verdict lasts. A verdict that listed lives ten
minutes. Anything that did not list lives thirty seconds: an unusable verdict,
a probe nothing answered, and any failure to list. That second figure is a
floor and not an eviction, because the member walk runs on every `tools/call`
as well as every `tools/list`: a member that is broken for good costs at most
one probe per thirty seconds from callers arriving one after another. The
lifetime is chosen when the probe returns and nothing lengthens it afterwards,
so the thirty seconds also applies to a member that never answers
`server/discover` and then lists perfectly well the legacy way: it is asked
again every thirty seconds, and the group call that asks pays up to the 5 s
probe budget each time. A verdict is remembered whether or not the caller
waited for it; the one thing not remembered is a probe nothing answered
because the caller had already gone. The cache holds one
entry per upstream id (at most 1024, dropping the one that expires soonest),
and an entry is a miss as soon as the upstream's `updated_at` differs from the
one the probe saw, so saving the upstream makes the proxy ask again. Pressing
Tools does not: a test is not an edit.

What this does not bound, stated so nobody has to find out. Misses are not
deduplicated, so K group calls arriving together on a cold or expired entry
cost K probes, and every entry made at boot expires together. The member walk
is sequential with no deadline of its own, a group's size is uncapped, and each
member costs up to 5 s for the probe and 60 s for the listing; the member that
costs the most is one that accepts the connection and never answers. A
`server/discover` slower than 5 s reads as legacy; the `member era probed`
DEBUG line (slug, upstream id, era, `reached`, latency) shows it as
`reached=false`. A key bound to one upstream, and the
`/{virtual_key_id}/{upstream_slug}/mcp` route, relay the client's own request
and never list, so they are never probed.

## Tech stack (recommended)

The language is Go (preferred: a single static binary with low resource use).
TypeScript (Fastify/Hono) is the alternative if you want faster UI iteration.
The database is SQLite by default, with no configuration, plus optional
Postgres. The HTTP router is chi or gin in Go, Hono or Fastify in TypeScript.
The UI is React with Tailwind CSS and Headless UI, using PoryMCP's own component
set in `web/src/components/`. Auth uses high-entropy API keys hashed with
argon2id or bcrypt. Secrets are encrypted at rest with AES-256-GCM.
Observability is structured JSON logs plus optional Prometheus.

Go 1.26 is the supported minimum; `go.mod` pins the exact toolchain
(`toolchain go1.26.8`) so local builds, the Docker stage and the `go` job in
`.github/workflows/ci.yml` compile with the same release.

## Project structure (Go example)
/
├── .github/workflows/ci.yml   # go, web and docker checks on every pull request; publish to GHCR
├── cmd/server/main.go
├── internal/
│   ├── api/          # Management REST handlers
│   ├── proxy/        # MCP proxy + aggregator
│   ├── auth/
│   ├── crypto/       # AES-256-GCM for auth_config at rest; Keyring, fingerprints, the v1 form
│   ├── credential/   # one answer to "can PoryMCP use this stored credential?" (proxy, API, boot)
│   ├── mcpclient/    # the one client that carries an upstream credential
│   ├── models/
│   ├── store/        # SQLite / Postgres
│   ├── audit/
│   ├── config/
│   └── webutil/      # trusted-proxy host/scheme/IP, health payload, security headers
├── web/              # React and Tailwind CSS dashboard
├── deploy/           # optional edge configs (Caddy overlay)
├── docs/11-deployment.md
├── Dockerfile
├── docker-compose.yml
├── docker-compose.tls.yml
├── openapi.yaml
├── CONTRIBUTING.md   # what CI runs and how to run it locally
└── README.md
