# MVP scope

## Must have
- [x] Register / list / update / delete Upstreams
- [x] Create / list / update / delete Groups of Upstreams
- [x] Create Virtual Key, which returns the plaintext key + proxy_url once
- [x] Rotate / revoke virtual keys
- [x] Proxy traffic over Streamable HTTP with credential injection
- [x] Support single Upstream or Group targets
- [x] Structured AuditLog for every MCP method
- [x] Queryable logs API
- [x] Basic rate limiting per virtual key (optional but nice)
- [x] Health endpoint
- [x] Single Docker image + docker-compose
- [ ] Management API with OpenAPI
- [x] Dashboard (React, Tailwind CSS and Headless UI, with PoryMCP's own components):
  - Application shell (sidebar)
  - Upstreams table + create form/modal
  - Groups management
  - Virtual keys table (name, key prefix + copy, status, last used, target)
  - Create Virtual Key form
  - Logs table with filters
  - Simple stats overview

## Known gaps
- `openapi.yaml` describes the management API, no route serves it, and several
  of its responses carry a description and no schema (PORM-22).
- The legacy HTTP+SSE upstream transport is not implemented (PORM-5). `sse` is
  refused on write since PORM-28; a row stored with it before then is refused on
  every request until its transport is set to `streamable-http`.
- A group key's aggregate endpoint `/{virtual_key_id}/mcp` answers `initialize`
  itself and opens no session with the members, and a member whose `tools/list`
  fails is left out of the merged catalogue while the client's request succeeds.
  Each member's own endpoint `/{virtual_key_id}/{upstream_slug}/mcp` passes the
  handshake through (PORM-23).
- The Logs page shows the newest 50 rows and has no control for older ones.
  `GET /api/v1/logs` returns a `next_cursor` for them (PORM-20).

## Nice-to-have (post-MVP)
- Tool-level filtering UI (PORM-4). The proxy and the management API enforce
  group and virtual key tool filters today; the dashboard has no form for them
- Log export as JSONL (PORM-7)
- Prometheus metrics (PORM-8)
- Key expiry enforcement ships: a key past its `expires_at` reports `expired`
  and the proxy refuses the call
- Light and dark mode: the dashboard renders both and follows the operating
  system setting. A toggle is PORM-9
- Skills catalog + sync, see `01-vision.md`, Post-MVP directions (PORM-126)
