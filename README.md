# PoryMCP

**One key. Many shapes.**

PoryMCP is a simple, Docker-first open-source MCP credential proxy.
Register real MCP servers once, then mint unlimited per-agent virtual keys and endpoints. Agents never see the real credentials.

Inspired by Pokémon’s Porygon — digital, polymorphic, and able to take many forms.

**Website:** [porymcp.com](https://porymcp.com)

---

## Why PoryMCP?

- **Credential isolation** — Real upstream URLs and API keys stay hidden from agents, and each credential goes to the upstream you registered, never to a host it names in a redirect
- **Per-agent virtual keys** — Easy rotation, revocation, and rate limits
- **Multi-MCP groups** — One virtual key can unlock multiple upstreams at once, each on its own endpoint
- **Tool discovery** — Ask a registered server what it offers, from the dashboard or the API, and read back the exact `{slug}__{tool}` name a rule has to be written in; the tool list is not stored, only whether the last test passed
- **Full audit trail** — Structured logs of every tool call (who, when, what, which upstream)
- **Super simple** — Single Docker container, clean REST API, modern dashboard
- **API-first** — Everything is controllable via API

---

## Quick start

```bash
[ -f .env ] || cp .env.example .env
grep -q '^ADMIN_API_KEY=' .env || printf 'ADMIN_API_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
grep -q '^ENCRYPTION_KEY=' .env || printf 'ENCRYPTION_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
docker compose up --build
```

Compose refuses to start unless `.env` holds both `ADMIN_API_KEY` and `ENCRYPTION_KEY` — the guarded lines above create each one only when it is missing, so re-running the block never overwrites an existing value (losing `ENCRYPTION_KEY` makes every stored credential unrecoverable; back it up separately from the data volume). Open the dashboard at [http://localhost:8080](http://localhost:8080) and sign in with the admin key from `.env`:

```bash
grep '^ADMIN_API_KEY=' .env | cut -d= -f2-
```

Put the process behind TLS for anything other than localhost. See [TLS and reverse-proxy deployment](docs/11-deployment.md).

Once images are published (PORM-10), the same deployment runs from the image:

```bash
# Generate each key once and keep it (0600): a second inline $(openssl …) would
# mint a different encryption key and lock the stored credentials away.
[ -f ~/porymcp.admin ] || (umask 077; openssl rand -hex 32 > ~/porymcp.admin)
[ -f ~/porymcp.key ] || (umask 077; openssl rand -hex 32 > ~/porymcp.key)
docker run -d \
  -p 8080:8080 \
  -e ADMIN_API_KEY="$(cat ~/porymcp.admin)" \
  -e ENCRYPTION_KEY="$(cat ~/porymcp.key)" \
  -v porymcp-data:/data \
  ghcr.io/netcasklabs/porymcp:latest
```

Back `ENCRYPTION_KEY` up separately from the data volume: without it, the
stored upstream credentials are unrecoverable — and restarting the same
volume under a different key puts the server into its degraded, fail-closed
state until you rotate or restore.

## Local development

Go 1.26+ (`go.mod` pins `toolchain go1.26.7`; Go downloads it automatically — set `GOTOOLCHAIN=local` to insist on your installed release). The dashboard is compiled into the server binary. After `go run ./cmd/server`, open http://localhost:8080.

```bash
[ -f ~/porymcp.admin ] || (umask 077; openssl rand -hex 32 > ~/porymcp.admin)
export ADMIN_API_KEY=$(cat ~/porymcp.admin)    # the same key every shell — this is your dashboard sign-in
[ -f ~/porymcp.key ] || (umask 077; openssl rand -hex 32 > ~/porymcp.key)
export ENCRYPTION_KEY=$(cat ~/porymcp.key)     # the same key every shell — ./data/porymcp.db persists
go run ./cmd/server
```

Keep the same `ENCRYPTION_KEY` across restarts once an upstream has a stored
credential: the server refuses to start with none set against a database that
holds one.

To change the UI:

```bash
cd web && npm install && npm run build
# then restart the Go server (or `npm run dev` on :3000 while the API stays on :8080)
```

`go test ./...` (or `make test`) covers auth, key hashing, store CRUD, management API, and proxy credential injection. `make web-test` (`cd web && npm test`) covers the dashboard's client-snippet generation.

## Core concepts

| Concept | Description |
| --- | --- |
| Upstream | A real MCP server (its final URL + credentials) |
| Group | A collection of Upstreams that can be exposed together |
| Virtual key | A key plus its endpoints — one per Upstream, or one per Group member plus an aggregate |
| Audit log | Every MCP request made through a Virtual key is recorded |

## How it works

1. Register one or more real MCP servers as Upstreams
2. (Optional) Bundle several Upstreams into a Group
3. Create a Virtual Key — you receive the plaintext key and its endpoints
4. Point your AI agent at those endpoints with `Authorization: Bearer <api_key>`: one per group member (`/{virtual_key_id}/{upstream_slug}/mcp`), or the single `proxy_url` for an Upstream target
5. PoryMCP injects the real credentials, forwards the request to that upstream's own URL — never to a host it names in a redirect — and logs everything

Each virtual key has its own endpoint — and a group key has one per member, so your client sees the servers separately, with their original tool names. `/{virtual_key_id}/mcp` still serves the merged single-connection view, where every tool is named `{upstream_slug}__{tool}` so you can always see which server a tool came from, and `/mcp` still works as a shared door. Install snippets for Claude Code, Cursor, Codex, OpenCode, and Gemini CLI: [Connecting clients](docs/09-clients.md).

## Features

- Streamable HTTP (primary) + SSE pass-through
- Encrypted storage of upstream secrets (AES-256-GCM)
- Virtual keys hashed with argon2id; plaintext shown only on create or rotate
- Virtual key rotation and revocation
- Optional per-key rate limiting
- Filterable audit logs
- Dashboard with an application shell (React + Tailwind CSS + Headless UI); every component is PoryMCP's own
- REST management API + OpenAPI (`openapi.yaml`)
- SQLite by default; Postgres via `DATABASE_URL=postgres://...` **and** `docker compose --profile postgres up` together (schema creation verified; behaviour beyond that is unverified — PORM-18)

## Documentation

- [Vision & product goals](docs/01-vision.md)
- [Data model](docs/02-data-model.md)
- [API reference](docs/03-api.md)
- [Architecture](docs/04-architecture.md)
- [MVP scope](docs/05-mvp.md)
- [UI guidelines](docs/06-ui.md)
- [Security model](docs/07-security.md)
- [Docker & deployment](docs/08-docker.md)
- [Connecting clients](docs/09-clients.md)
- [TLS and reverse-proxy deployment](docs/11-deployment.md)

## Tech stack

- Backend: Go
- Database: SQLite (default) / Postgres
- Dashboard: React + Tailwind CSS + Headless UI
- Container: Single multi-stage Docker image

## Status

Early development. The management API, proxy, audit log, Docker image, and dashboard skeleton are in place. Behaviour changes that affect a running deployment are recorded in [CHANGELOG.md](CHANGELOG.md).

## License

MIT (see [LICENSE](LICENSE)). Third-party notices for the bundled dashboard
dependencies are in [NOTICE](NOTICE).
