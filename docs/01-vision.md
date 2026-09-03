# PoryMCP

**Domain:** porymcp.com  
**Branding:** Named after Porygon, the Pokémon made of data. Use soft blues, cyans, and a digital, polygon look.

## One-liner
An open-source MCP credential proxy that runs as one Docker container.  
Register real MCP servers once, then mint per-agent virtual keys and endpoints. Agents never see the real credentials.  
Full structured audit logs. Support grouping multiple upstreams under one virtual key: each member gets its own endpoint under that key, and a single aggregated endpoint remains for clients that want one connection.

## Vision
Let AI agents use MCP tools without leaking real API keys or URLs, with as little setup as one container and two keys.

PoryMCP presents one endpoint per agent and shapes it to whatever set of tools that agent needs.

- Opinionated defaults
- Fully API-driven
- Audit trail (who, when, what tool, which upstream)
- Per-agent isolation
- Multi-MCP grouping under one key
- Dashboard (React, Tailwind CSS, Headless UI)
- Single Docker container

## Differentiators
- One container, minimal config
- Per-agent virtual keys and endpoints
- Queryable audit logs from the first request
- Grouping of multiple MCPs behind one key
- API-first, with a dashboard for the same actions

## Non-goals for MVP
- Full OAuth client flows for agents
- Complex multi-tenant orgs / RBAC beyond virtual keys
- LLM gateway features
- Heavy policy engines
- Enterprise SSO (can come later)

## Post-MVP directions

Ideas that fit the product but are out of scope until the MVP in `05-mvp.md` ships.

### Skills catalog (assessed 2026-08-27)

Agents increasingly need both MCP servers and skills (`SKILL.md` bundles that live on the client's disk). PoryMCP could be the one place that says which skills a Virtual Key or Group should have. Skills do not flow through the proxy at runtime and carry no secret, so this is a distribution and governance feature. It does not touch the proxy.

**In scope if built (in this order):**
- Catalog: register a skill source (GitHub `owner/repo/path` using the `npx skills` convention, or a hand-written skill), pin it to a commit or content hash, attach it to a Virtual Key or Group.
- Update check: periodically fetch the source, compare hashes, show "update available" with a diff in the dashboard. Third-party skills are prompt content; a silent upstream change is a supply-chain risk, so *reviewed and pinned centrally* is the value.
- Sync: the planned `npx porymcp connect` installer (see `09-clients.md`) also pulls the virtual key's pinned skills into the client's skills directory. Wrap `npx skills`; do not rebuild it.
- Dashboard skill editor: last, and the lowest value over "point at a repo you control".

**Out of scope:** a general-purpose skill package manager; any of this before MVP ships.

**Open decision (Dan):** positioning. "MCP credential proxy" is a precise one-liner; adding skills makes PoryMCP an "agent capability control plane". Decide before building.

**Alternative noted:** expose a virtual key's skills as MCP `prompts` through the existing proxy (Claude Code shows MCP prompts as slash commands). No new transport, but it loses progressive disclosure, bundled scripts and auto-triggering, so it would serve as a demo of the feature.
