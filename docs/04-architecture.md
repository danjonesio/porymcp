# Architecture

## High-level components
- Management API (REST + OpenAPI)
- MCP Proxy core (JSON-RPC forwarding, Streamable HTTP + SSE)
- Auth middleware (virtual key validation)
- Credential injector (holds real secrets, never exposes them, and presents each
  to the upstream's own URL, never to a host the upstream names in a redirect)
- Upstream client (`internal/mcpclient`): the one place a real credential is
  written onto an outgoing request, and the one construction every client that
  carries one comes from: one refusal to follow a redirect, one wrapped default
  transport, and a timeout and read cap each caller sizes for its own job (the
  proxy relays a client's call in 60 s and 16 MiB; discovery has 10 s and 2 MiB
  for a whole handshake). The proxy's relay, the proxy's own catalogue request
  and the dashboard's discovery call all go through it, so a rule added here
  holds on all three rather than on the path someone remembered
- Tool discovery (management plane): a real MCP handshake against one upstream,
  run for an **operator** rather than a virtual key, returning a fixed set of
  structured fields and persisting nothing
- Member router (for Groups: resolves `/{virtual_key_id}/{upstream_slug}/mcp` to one enabled member and forwards 1:1; the primary path)
- Aggregator (for Groups: the secondary single-connection view: merges the members' catalogues and names every tool for the member that owns it, `{upstream_slug}__{tool}`, always (e.g. `github__create_issue`), not only when two members collide)
- Tool-policy gate (one predicate over the group `tool_filter` and the key's
  allow/deny lists, consulted by both `tools/call` and `tools/list`)
- Audit logger (async writes)
- Optional dashboard (React + Tailwind UI Kit)

## Data flow

### Per member (primary, group keys)

```text
Agent → /{virtual_key_id}/{upstream_slug}/mcp with its virtual key
→ Validate key and path (a key on another key's path is 403 before the body is read)
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
→ Copy the response headers back, Mcp-Session-Id included
→ Log (async)
→ Return response
```

### Aggregate (secondary) and single-upstream keys

```text
Agent → /{virtual_key_id}/mcp (or shared /mcp) with its virtual key
→ Validate key (and path, when present)
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

On a group target, `initialize`, `tools/list`, `tools/call` and
`notifications/initialized` are answered by the aggregator; everything else goes
to the first member, and no upstream session reaches the client.

### Sessions and response headers
The proxy is stateless: it holds no session table. Each member URL carries its
own MCP session, minted by that member and returned to the client in
`Mcp-Session-Id`. A session id minted by member A is forwarded verbatim if a
client sends it to member B, which rejects it: that is the member's decision,
not PoryMCP's. On the 1:1 path every response header the upstream sets other
than `Content-Length` currently reaches the client, `Set-Cookie` and
`WWW-Authenticate` included; narrowing that to an allowlist that keeps
`Mcp-Session-Id` is PORM-98. That copying happens only on a response the proxy
relays, and a `3xx` is never relayed (the call has already failed by then), so
`Location` never reaches the client on any path, and neither does anything else
the redirect response set.

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
→ Inject the real credential and initialize against that URL, never a host it
  names in a redirect
→ notifications/initialized, then tools/list followed to the end of its
  cursors, capped at 500 tools and 50 pages
→ DELETE the session, so none is left open on the upstream
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

The whole sequence is bounded at 10 s and the teardown at a further 2 s. The
catalogue is not stored: it is read again on the next call.

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
(`toolchain go1.26.7`) so local builds, the Docker stage and any future CI
compile with the same release.

## Project structure (Go example)
/
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
├── web/              # React + Tailwind UI Kit dashboard
├── deploy/           # optional edge configs (Caddy overlay)
├── docs/11-deployment.md
├── Dockerfile
├── docker-compose.yml
├── docker-compose.tls.yml
├── openapi.yaml
└── README.md
