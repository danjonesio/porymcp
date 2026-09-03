# MVP Scope

## Must have
- [x] Register / list / update / delete Upstreams
- [x] Create / list / delete Groups of Upstreams
- [x] Create Virtual Key, which returns the plaintext key + proxy_url once
- [x] Rotate / revoke virtual keys
- [x] Proxy traffic (Streamable HTTP primary) with credential injection
- [x] Support single Upstream or Group targets
- [x] Structured AuditLog for every MCP method
- [x] Queryable logs API
- [x] Basic rate limiting per virtual key (optional but nice)
- [x] Health endpoint
- [x] Single Docker image + docker-compose
- [x] Management API with OpenAPI
- [x] Dashboard using Tailwind UI Kit:
  - Application shell (sidebar)
  - Upstreams table + create form/modal
  - Groups management
  - Virtual keys table (name, key prefix + copy, status, last used, target)
  - Create Virtual Key form
  - Logs table with filters
  - Simple stats overview

## Nice-to-have (post-MVP)
- Tool-level filtering UI
- Log export (JSONL)
- Prometheus metrics
- Key expiry enforcement
- Basic light/dark mode
- Skills catalog + sync (see `01-vision.md`, Post-MVP directions)
