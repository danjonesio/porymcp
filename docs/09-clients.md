# Connecting clients

A virtual key bound to a **single upstream** gets one URL:

```
{PUBLIC_URL}/{virtual_key_id}/mcp
```

A virtual key bound to a **group** gets one URL per enabled member:

```
{PUBLIC_URL}/{virtual_key_id}/{upstream_slug}/mcp
```

plus the aggregate URL above. Configure the member URLs. Each one is a pure 1:1
proxy to that upstream (its original tool names, its own `initialize`,
capabilities, prompts, resources and session), and every client here already
knows how to show several servers at once. `GET /api/v1/virtual-keys/{id}`
returns them as `endpoints[]`, and the create/rotate dialog lists them.

A virtual key bound to an **HTTP API** upstream (`kind: http`, PORM-146) gets
a URL ending in `/api/` instead, and an HTTP API member of a group gets
`{PUBLIC_URL}/{virtual_key_id}/{upstream_slug}/api/`. Those are not MCP
servers: see [HTTP APIs](#http-apis) below, and never give one to an MCP
client.

Example, a key over a group of `github` and `linear`:

```
http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp
http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp
http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp      ← aggregate
```

`tools/list` on a member URL returns that upstream's **original** tool names:
`create_issue`, not `github__create_issue`. The aggregate URL is the one that
merges the catalogues, and every tool it advertises carries its upstream's slug:
`github__create_issue`, `linear__create_issue`. Two underscores, always: a
one-member group is prefixed too, so moving an upstream into a bigger group
never renames its tools a second time.

The shared door `POST /mcp` still works: the bearer key identifies the virtual key. Prefer the per-key URLs so clients, logs, and access rules can tell agents apart. A key used on the wrong `/{id}/mcp` path is rejected. A member URL whose slug is not an enabled member of this key's group answers `404`, as does any slug under a single-upstream key, where `/{id}/mcp` is already the 1:1 endpoint.

Clients send the **virtual** key, not the admin key, and the same key works on every one of its endpoints:

```
Authorization: Bearer pory_…
```

Keep PoryMCP running while the client is connected. Copy the plaintext key when it is shown: it is not displayed again.

Clients cache the tool catalogue they fetch on connect. After an operator changes a group's tool filter or a key's allow/deny lists, reconnect the client so it picks up the new catalogue; until then it may still offer tools the proxy now refuses. Reconnect after upgrading PoryMCP itself, too, if the client is on an aggregate URL: v0.1 renamed every tool there to `{upstream_slug}__{tool}`, and a cached old name now answers `-32602 unknown tool` (see [CHANGELOG.md](../CHANGELOG.md)). An aggregate URL also now answers `server/discover` itself and answers `initialize` with the version the client asked for, so a client that connected before that change holds the old handshake: `/mcp` in Claude Code, reload MCP servers in Cursor. A refused tool call comes back as a failed tool call (a JSON-RPC error against that one request), not as a transport or connection error. Removing a member from a group, or disabling it, makes that member's URL answer `404` on the next request: the client shows that one server as failed and the others as healthy.

A client on the 2026-07-28 revision needs no setting (PORM-150). PoryMCP forwards `Mcp-Method`, `Mcp-Name` and the `Mcp-Param-` headers a tool's schema asks for, and compares the first two with the body before forwarding, so a request whose headers and body disagree is answered `400` with `{"code":-32020,"message":"header mismatch: Mcp-Name"}` and reaches no upstream. On an aggregate URL, send the composed name you were shown, `github__create_issue`, in `params.name` and in `Mcp-Name` alike: PoryMCP rewrites both to the member's own name on the way to that member. At most 32 `Mcp-Param-` headers cross and none over 4096 bytes; a request over either bound is answered `431` and reaches no upstream, and a browser whose preflight asks for more than 32, or lists more than 64 header names in all, is refused them at the preflight. A client on an earlier revision that sends none of these headers is unaffected.

The create/rotate dialog can copy a snippet for Claude Code, Cursor, Codex, OpenCode, Gemini CLI, or curl, and for a group key it emits one entry per member, with a “One combined server” option that emits the aggregate URL instead.

---

## Claude Code

One `claude mcp add` per member:

```bash
claude mcp add --transport http github http://localhost:8080/{virtual_key_id}/github/mcp \
  --header "Authorization: Bearer pory_YOUR_VIRTUAL_KEY"
claude mcp add --transport http linear http://localhost:8080/{virtual_key_id}/linear/mcp \
  --header "Authorization: Bearer pory_YOUR_VIRTUAL_KEY"
```

Add `-s user` for every project. Then `claude mcp list` and `/mcp` inside Claude.

`.mcp.json` (do not commit a real key):

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "http://localhost:8080/{virtual_key_id}/github/mcp",
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    },
    "linear": {
      "type": "http",
      "url": "http://localhost:8080/{virtual_key_id}/linear/mcp",
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    }
  }
}
```

For one combined server instead (one server, the merged catalogue):

```bash
claude mcp add --transport http my-agent http://localhost:8080/{virtual_key_id}/mcp \
  --header "Authorization: Bearer pory_YOUR_VIRTUAL_KEY"
```

---

## Cursor

`.cursor/mcp.json` (project) or the Cursor user MCP config:

```json
{
  "mcpServers": {
    "github": {
      "url": "http://localhost:8080/{virtual_key_id}/github/mcp",
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    },
    "linear": {
      "url": "http://localhost:8080/{virtual_key_id}/linear/mcp",
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    }
  }
}
```

Reload MCP servers.

For one combined server instead, use one `mcpServers` entry pointing at
`http://localhost:8080/{virtual_key_id}/mcp`.

---

## Codex

Export the key where Codex will see it:

```bash
# In the shell that launches Codex:
export PORYMCP_KEY='pory_YOUR_VIRTUAL_KEY'
```

Then one table per member:

```toml
# ~/.codex/config.toml
[mcp_servers.github]
url = "http://localhost:8080/{virtual_key_id}/github/mcp"
bearer_token_env_var = "PORYMCP_KEY"

[mcp_servers.linear]
url = "http://localhost:8080/{virtual_key_id}/linear/mcp"
bearer_token_env_var = "PORYMCP_KEY"
```

(or project `.codex/config.toml`). `bearer_token_env_var` is the **name** of the
variable, not the key itself: keep the key out of the file. Table names take
`_`, not `-`, so a slug like `github-mcp` becomes `[mcp_servers.github_mcp]`.

For one combined server instead, use one `[mcp_servers.my_agent]` table pointing at
`http://localhost:8080/{virtual_key_id}/mcp`.

---

## OpenCode

`opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "github": {
      "type": "remote",
      "url": "http://localhost:8080/{virtual_key_id}/github/mcp",
      "oauth": false,
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    },
    "linear": {
      "type": "remote",
      "url": "http://localhost:8080/{virtual_key_id}/linear/mcp",
      "oauth": false,
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    }
  }
}
```

`oauth` must be `false` on every entry so OpenCode does not treat 401 as an OAuth challenge. An upstream that itself needs OAuth (PORM-139) needs nothing on the client side: the operator connects it once from the dashboard, PoryMCP renews the token, and the client keeps its virtual key.

For one combined server instead, use one `mcp` entry pointing at
`http://localhost:8080/{virtual_key_id}/mcp`.

---

## Gemini CLI

Merge into Gemini CLI `settings.json`:

```json
{
  "mcpServers": {
    "github": {
      "httpUrl": "http://localhost:8080/{virtual_key_id}/github/mcp",
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    },
    "linear": {
      "httpUrl": "http://localhost:8080/{virtual_key_id}/linear/mcp",
      "headers": {
        "Authorization": "Bearer pory_YOUR_VIRTUAL_KEY"
      }
    }
  }
}
```

`httpUrl` (not `url`) is Gemini CLI's Streamable HTTP key.

For one combined server instead, use one `mcpServers` entry whose `httpUrl` is
`http://localhost:8080/{virtual_key_id}/mcp`.

---

## curl

```bash
# github
curl -sS -X POST http://localhost:8080/{virtual_key_id}/github/mcp \
  -H "Authorization: Bearer pory_YOUR_VIRTUAL_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# linear
curl -sS -X POST http://localhost:8080/{virtual_key_id}/linear/mcp \
  -H "Authorization: Bearer pory_YOUR_VIRTUAL_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Each of those lists that upstream's own tool names, unprefixed. The same request
against `http://localhost:8080/{virtual_key_id}/mcp` returns the merged
catalogue, where every name carries its member's slug: `github__search` and
`linear__search`, and `github__create_issue` even when no other member
advertises `create_issue`. Call one there by the name you were shown; a bare or
unknown name answers

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unknown tool: search"}}
```

A name that is not a `{slug}__{tool}` identity at all (no `__`, an empty half,
or a head that is not a valid slug) is refused without contacting any upstream.
A well-formed name whose slug is not a member, or whose tool no member
advertises, gets the same reply after the members' catalogues have been listed,
and still before anything is forwarded.

An unknown or non-member slug answers `404` with
`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown endpoint"}}`.
(Do not count on a `..` in the path reaching PoryMCP to get that `404`: an
intermediary that normalises dot-segments may resolve the path first.)

A `tools/call` on the 2026-07-28 revision carries the routing headers beside
the body:

```bash
# a tools/call on the 2026-07-28 revision
curl -sS -X POST http://localhost:8080/{virtual_key_id}/github/mcp \
  -H "Authorization: Bearer pory_YOUR_VIRTUAL_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: create_issue" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"curl","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
```

The three headers must agree with the body. `MCP-Protocol-Version` must match
the `_meta` version, and it must be sent: a body that declares the revision
with no header is refused the same way. The same call with `Mcp-Name: other`
answers `400` with

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"header mismatch: Mcp-Name"}}
```

On the aggregate URL send `github__create_issue` in both `params.name` and
`Mcp-Name`.

A `subscriptions/listen` is a `POST` whose answer stays open; on a member or
single-upstream endpoint the proxy relays it as it arrives:

```bash
curl -N -sS -X POST http://localhost:8080/{virtual_key_id}/mcp \
  -H "Authorization: Bearer pory_YOUR_VIRTUAL_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: subscriptions/listen" \
  -d '{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"curl","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
```

`-N` stops curl buffering its output, so each event prints as it arrives. The
stream stays open until you press Ctrl-C.

---

## HTTP APIs

An upstream of kind `http` is a plain REST API, registered with its base URL
(`https://api.github.com`, `https://api.example.com/v1`) and its credential.
A virtual key on it is served at

```
{PUBLIC_URL}/{virtual_key_id}/api/<path>
```

and an HTTP API member of a group at
`{PUBLIC_URL}/{virtual_key_id}/{upstream_slug}/api/<path>`. Whatever comes
after `/api/` is joined under the base URL: with the base
`https://api.example.com/v1`, a request to `…/api/users?page=2` reaches
`https://api.example.com/v1/users?page=2` with the same verb, headers and
body, and the virtual key swapped for the stored credential. The virtual key
goes in `Authorization: Bearer` or, absent that, `X-Api-Key`; the two
placements PoryMCP reads. `…/api` and `…/api/` with nothing after them reach
the base URL as stored.

```bash
# one request
curl -sS 'http://localhost:8080/{virtual_key_id}/api/user' \
  -H "Authorization: Bearer pory_YOUR_VIRTUAL_KEY" \
  -H "X-GitHub-Api-Version: 2022-11-28"

# a write
curl -sS -X POST 'http://localhost:8080/{virtual_key_id}/api/repos/o/r/issues' \
  -H "Authorization: Bearer pory_YOUR_VIRTUAL_KEY" \
  -H "Content-Type: application/json" \
  -d '{"title":"x"}'
```

An SDK works unchanged: set its base URL to
`http://localhost:8080/{virtual_key_id}/api/` and its API key to the virtual
key. Vendor headers such as `X-GitHub-Api-Version`, `Notion-Version`,
`If-None-Match` and `Idempotency-Key` cross as sent; the SDK's own
`Authorization`, `X-Api-Key` and `Cookie` are replaced or dropped. The
upstream's status, body, `Content-Type`, `ETag`, `Link`, `Last-Modified`,
`Retry-After` and `X-RateLimit-*` come back; its cookies, auth challenges and
redirects do not (a `3xx` other than `304` fails the call with `502`).

A refusal on this endpoint is plain JSON, not a JSON-RPC envelope:

```json
{"error":"method not allowed by virtual key","request_id":"…"}
```

`403` with that body is a verb outside the key's `http_methods`; `404
{"error":"unknown endpoint"}` is an MCP upstream, a group on the single door,
or a slug that is not an enabled HTTP API member; `400
{"error":"path escapes the upstream base"}` is a `..` segment in any
encoding; `400 {"error":"request carries the virtual key"}` is the key sent in
the path or the query as well as the header; `413` is a body over 8 MiB; `429`
carries `Retry-After`. Only `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and `DELETE`
are relayed; anything else is `405` with `Allow`. (To see the `400` for a
dot segment from curl, pass `--path-as-is`: curl decodes `%2e%2e` and drops
the segment before the request leaves, as any normalising intermediary may.)

Every call writes one audit row with the verb in Method and the path in Tool
(`GET` and `/user`), so the Logs page shows what the key did. The request
body is not recorded.

---

## Testing against a local server

To exercise the whole path (upstream, virtual key, client) without a vendor
account, run the MCP project's reference server:

```bash
npx -y @modelcontextprotocol/server-everything@2026.8.18 streamableHttp
# MCP Streamable HTTP Server listening on port 3001
# endpoint: http://localhost:3001/mcp
```

`streamableHttp` is a positional argument, not a flag: this server has no
`--transport` option. Register `http://localhost:3001/mcp` as an upstream with
`auth_type: none` and press **Discover tools**: it answers with the server's
name and version, the protocol line "2025-11-25, handshake", and **13** tools.
(That server answers the `server/discover` PoryMCP sends first with `400` and
`-32000` "Server not initialized", which is how a handshake server is
recognised; checked against `2026.8.18`.)

An upstream that serves only the 2026-07-28 revision has no `initialize` at
all. PoryMCP asks every upstream `server/discover` first, so such a server
discovers with a protocol line reading "2026-07-28, stateless", and a group
lists its tools beside everyone else's. A call through the group's aggregate
URL is composed for the era the member speaks, so a handshake-era client can
call a 2026-07-28 member and a 2026-07-28 client can call a handshake-era one.

What remains on an aggregate URL:

- A handshake-era member that needs a real session still refuses a call, or is
  missing from the catalogue (PORM-23).
- A call to a handshake-era member is sent without a protocol version, so that
  member may serve it under 2025-03-26 and leave out `structuredContent`.
- A 2026-07-28 member may answer with `resultType: "input_required"`, from
  `tools/call` or from a relayed `resources/read` or `prompts/get`. It reaches a
  handshake-era client unchanged, and that client cannot act on it.
- A task handle a member hands out cannot be redeemed there, because
  `tasks/get` is refused. Use the member's own URL.
- `subscriptions/listen` is refused with `404` and `-32601`.
- PoryMCP composes no `Mcp-Param-` headers for a handshake-era client's call to
  a 2026-07-28 member. A member whose tool declares `x-mcp-header` parameters
  may refuse the call or ignore the parameter.
- The merged catalogue carries each tool's name, title, description and input
  schema. A member's `annotations` (`readOnlyHint` and `destructiveHint`
  included), `outputSchema`, `icons` and tool `_meta` do not cross (PORM-73).
  The member's own URL lists them.

Thirteen, not sixteen. That server registers three further tools
(`get-roots-list`, `trigger-sampling-request` and `trigger-elicitation-request`)
only for clients that declare the `roots`, `sampling` or `elicitation`
capabilities in their `initialize`, and discovery declares none of them: it asks
what the server offers a plain catalogue reader. A client that does declare
them, connected straight to the server, sees all sixteen. That is the server
being accommodating, not PoryMCP hiding anything.

It is also a good way to see the aggregate gap `docs/07-security.md` describes
from both sides at once. The gap is the session and not the framing: a member
that answers as an event stream, as this server does, is listed in a group like
any other. This server also refuses a `tools/list` that arrives without
an initialized session, so a group whose member it is serves that member's tools
on the member's own `/{virtual_key_id}/{upstream_slug}/mcp` URL and omits them
from the merged catalogue at `/{virtual_key_id}/mcp`, while **Discover tools**,
which performs the full handshake, lists them either way.

---

## Other clients

Anything that speaks Streamable HTTP can use the same pair: **endpoint URL + `Authorization: Bearer`**, the same key on every member URL. Windsurf, Cline, and similar editors typically use a Cursor-like `mcpServers` JSON block. Claude Desktop (stdio-only) can bridge with `npx mcp-remote`.

N members means N connections. Some clients cap the number of MCP servers or the total tool count; if you hit one, use the aggregate URL instead. Two keys over the *same* group installed in one client also collide on server names, since both default to the upstream slugs. Rename one.

Aggregate tool names are longer than per-member ones, because each carries its member's slug, and most clients prepend a name of their own: Claude Code shows an aggregate tool as `mcp__{server}__{slug}__{tool}`, where `{server}` is the name you gave the server in `claude mcp add`. That is four parts, and a client with a tool-name limit counts all of them. Keep slugs short (they are fixed once the upstream is created) and give the server a short name too. For reference, a full name of **87 characters** was accepted and callable in Claude Code 2.1.250; a long slug on an upstream with long tool names can still reach a limit, and the per-member URLs are the way out when it does.

A client opens a `GET` on the endpoint after `initialize` to listen for server-initiated messages. PoryMCP answers `405` at once and forwards nothing. The Streamable HTTP transport tells a client to read that as a server that does not offer the stream, and to carry on over `POST` without reporting an error. Claude Code and OpenCode bundle a transport that does exactly that (checked in the bundled code, not against a running PoryMCP); Cursor, Codex and Gemini CLI follow the same transport rule and were not checked. No client should need a setting for this. Before this change the `GET` was forwarded and the client waited for the proxy's 60 s upstream timeout before seeing a `502`, so a server took about a minute to become usable; against an upstream that answered the `GET` quickly, the client saw one failed stream per connect instead. `POST` carries every call today.

A `502` with `{"code":-32000,"message":"upstream request failed"}` means the real MCP server did not answer usably (it timed out, refused the connection, or answered with a redirect, which PoryMCP does not follow), or that PoryMCP could not use its own stored credential for that upstream and built no request at all; the operator's log row then reads `credential undecryptable` or `credential unreadable`, and the fix is the operator's encryption key or the credential, not the URL. An upstream stored with the `sse` transport is refused the same way, with a log row naming the transport, and the fix is the operator setting it to `streamable-http`. Expect it to present as a failed **server** rather than a failed tool call whenever the upstream's URL is at fault, because the `initialize` a client sends on connect is the call that gets the `502`: Claude Code lists the server as `✘ Failed to connect` with the `502` body quoted, and other clients mark it unavailable in their own way. A `502` that only starts later (a timeout on one slow call, say) surfaces as that one call failing instead. The reply is identical for a timeout, a refused connection and a redirect on purpose (a key holder is not told the upstream's host), so ask the operator to check `GET /api/v1/logs?status=error` or the Logs page, where the row for that call says which it was. If it reads `upstream redirected to <host>`, the upstream's registered URL is wrong; the host on the row is a diagnostic, not an instruction, so take the correct endpoint from the server's own documentation, usually `https://` where `http://` was registered, or the path with its trailing slash. Nothing in the client needs changing.

A `401` on a proxy URL has two causes and looks the same either way: the virtual key is wrong, expired or revoked, or the upstream rejected the credential PoryMCP holds for it. PoryMCP sends no `WWW-Authenticate` in either case, and it does not copy the upstream's, so a client that would otherwise read that header and start an OAuth flow against the upstream's own authorization server does not. An operator can tell the two causes apart on the Logs page: a `blocked` row means the virtual key, an `error` row carrying an upstream id means the upstream.

PoryMCP publishes no protected-resource or authorization-server metadata. It publishes one OAuth client metadata document, at `/api/v1/oauth/client-metadata`, which names PoryMCP as a client of an upstream's authorization server (PORM-139) and says nothing to an MCP client. A probe for protected-resource metadata is an unmatched path, so it returns the dashboard page rather than a `404`, and a client that discovers by probing fails on the HTML instead of falling through cleanly. Set `oauth` to `false` where a client offers it, as the OpenCode block above does.

A `429` carries `Retry-After` when the upstream sent one. PoryMCP's own rate limiter answers `429` without it, so treat a missing `Retry-After` as an ordinary backoff rather than an immediate retry.

A proxy response carries no request id of its own, and an upstream's `X-Request-Id` is not copied back. PoryMCP records the `X-Request-Id` a client sends as the `request_id` on the audit row for the call.

The three response headers PoryMCP returns from an upstream, and everything it drops, are listed in `docs/07-security.md`.

If a client cannot set headers, it cannot use PoryMCP yet (no secrets in the URL). A later installer (`npx porymcp connect`) should write the right file per client, consuming `endpoints[]` (PORM-11), so users do not have to remember paths.
