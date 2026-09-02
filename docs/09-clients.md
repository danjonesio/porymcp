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

Clients cache the tool catalogue they fetch on connect. After an operator changes a group's tool filter or a key's allow/deny lists, reconnect the client so it picks up the new catalogue; until then it may still offer tools the proxy now refuses. Reconnect after upgrading PoryMCP itself, too, if the client is on an aggregate URL: v0.1 renamed every tool there to `{upstream_slug}__{tool}`, and a cached old name now answers `-32602 unknown tool` (see [CHANGELOG.md](../CHANGELOG.md)). A refused tool call comes back as a failed tool call (a JSON-RPC error against that one request), not as a transport or connection error. Removing a member from a group, or disabling it, makes that member's URL answer `404` on the next request: the client shows that one server as failed and the others as healthy.

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

`oauth` must be `false` on every entry so OpenCode does not treat 401 as an OAuth challenge.

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
name and version and **13** tools.

Thirteen, not sixteen. That server registers three further tools
(`get-roots-list`, `trigger-sampling-request` and `trigger-elicitation-request`)
only for clients that declare the `roots`, `sampling` or `elicitation`
capabilities in their `initialize`, and discovery declares none of them: it asks
what the server offers a plain catalogue reader. A client that does declare
them, connected straight to the server, sees all sixteen. That is the server
being accommodating, not PoryMCP hiding anything.

It is also a good way to see the aggregate gap `docs/07-security.md` describes
from both sides at once. This server refuses a `tools/list` that arrives without
an initialized session, so a group whose member it is serves that member's tools
on the member's own `/{virtual_key_id}/{upstream_slug}/mcp` URL and omits them
from the merged catalogue at `/{virtual_key_id}/mcp`, while **Discover tools**,
which performs the full handshake, lists them either way.

---

## Other clients

Anything that speaks Streamable HTTP can use the same pair: **endpoint URL + `Authorization: Bearer`**, the same key on every member URL. Windsurf, Cline, and similar editors typically use a Cursor-like `mcpServers` JSON block. Claude Desktop (stdio-only) can bridge with `npx mcp-remote`.

N members means N connections. Some clients cap the number of MCP servers or the total tool count; if you hit one, use the aggregate URL instead. Two keys over the *same* group installed in one client also collide on server names, since both default to the upstream slugs. Rename one.

Aggregate tool names are longer than per-member ones, because each carries its member's slug, and most clients prepend a name of their own: Claude Code shows an aggregate tool as `mcp__{server}__{slug}__{tool}`, where `{server}` is the name you gave the server in `claude mcp add`. That is four parts, and a client with a tool-name limit counts all of them. Keep slugs short (they are fixed once the upstream is created) and give the server a short name too. For reference, a full name of **87 characters** was accepted and callable in Claude Code 2.1.250; a long slug on an upstream with long tool names can still reach a limit, and the per-member URLs are the way out when it does.

A `GET` for an SSE stream is forwarded and **buffered**, not streamed, on all three paths: a stream the upstream holds open fails at the proxy's 60 s upstream timeout with `502` (PORM-30 owns the `405`, PORM-5 real streaming); `POST` carries everything today.

A `502` with `{"code":-32000,"message":"upstream request failed"}` means the real MCP server did not answer usably (it timed out, refused the connection, or answered with a redirect, which PoryMCP does not follow), or that PoryMCP could not use its own stored credential for that upstream and built no request at all; the operator's log row then reads `credential undecryptable` or `credential unreadable`, and the fix is the operator's encryption key or the credential, not the URL. Expect it to present as a failed **server** rather than a failed tool call whenever the upstream's URL is at fault, because the `initialize` a client sends on connect is the call that gets the `502`: Claude Code lists the server as `✘ Failed to connect` with the `502` body quoted, and other clients mark it unavailable in their own way. A `502` that only starts later (a timeout on one slow call, say) surfaces as that one call failing instead. The reply is identical for a timeout, a refused connection and a redirect on purpose (a key holder is not told the upstream's host), so ask the operator to check `GET /api/v1/logs?status=error` or the Logs page, where the row for that call says which it was. If it reads `upstream redirected to <host>`, the upstream's registered URL is wrong; the host on the row is a diagnostic, not an instruction, so take the correct endpoint from the server's own documentation, usually `https://` where `http://` was registered, or the path with its trailing slash. Nothing in the client needs changing.

If a client cannot set headers, it cannot use PoryMCP yet (no secrets in the URL). A later installer (`npx porymcp connect`) should write the right file per client, consuming `endpoints[]` (PORM-11), so users do not have to remember paths.
