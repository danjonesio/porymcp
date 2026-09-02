# PoryMCP

**Domain:** porymcp.com  
**Branding:** Inspired by Pokémon’s Porygon — digital, polymorphic, can take multiple shapes. Use soft blues, cyans, and digital/polygon aesthetics.

## One-liner
A dead-simple, Docker-first open-source MCP credential proxy.  
Register real MCP servers once → mint unlimited per-agent virtual keys + endpoints → agents never see the real credentials.  
Full structured audit logs. Support grouping multiple upstreams under one virtual key: each member gets its own endpoint under that key, and a single aggregated endpoint remains for clients that want one connection.

## Vision
Make it trivial and safe to give AI agents access to MCP tools without leaking real API keys or URLs.

PoryMCP acts like Porygon: one clean form that can morph into whatever set of tools the agent needs.

- Super clean and opinionated
- Fully API-driven
- Strong audit trail (who, when, what tool, which upstream)
- First-class per-agent isolation
- Easy multi-MCP grouping under one key
- Beautiful modern dashboard using Tailwind UI Kit
- Single Docker container

## Differentiators
- Extreme simplicity (one container, minimal config)
- First-class per-agent virtual keys + endpoints
- Strong, queryable audit logs out of the box
- Easy grouping of multiple MCPs behind one key
- Fully API-first + polished Tailwind dashboard
- Designed as a product, not just infrastructure

## Non-goals for MVP
- Full OAuth client flows for agents
- Complex multi-tenant orgs / RBAC beyond virtual keys
- LLM gateway features
- Heavy policy engines
- Enterprise SSO (can come later)

## Post-MVP directions

Ideas that fit the product but are out of scope until the MVP in `05-mvp.md` ships.

### Skills catalog (assessed 2026-08-27)

Agents increasingly need both MCP servers and skills (`SKILL.md` bundles that live on the client's disk). PoryMCP could be the one place that says which skills a Virtual Key or Group should have. Skills do not flow through the proxy at runtime and carry no secret, so this is a distribution and governance feature, not a proxy feature.

**In scope if built (in this order):**
- **Catalog** — register a skill source (GitHub `owner/repo/path` using the `npx skills` convention, or a hand-written skill), pin it to a commit / content hash, attach it to a Virtual Key or Group.
- **Update check** — periodically fetch the source, compare hashes, show "update available" with a diff in the dashboard. Third-party skills are prompt content; a silent upstream change is a supply-chain risk, so *reviewed and pinned centrally* is the value.
- **Sync** — the planned `npx porymcp connect` installer (see `09-clients.md`) also pulls the virtual key's pinned skills into the client's skills directory. Wrap `npx skills`; do not rebuild it.
- **Dashboard skill editor** — last; lowest value over "point at a repo you control".

**Out of scope:** a general-purpose skill package manager; any of this before MVP ships.

**Open decision (Dan):** positioning. "MCP credential proxy" is a crisp one-liner; adding skills makes PoryMCP an "agent capability control plane". Decide before building.

**Alternative noted:** expose a virtual key's skills as MCP `prompts` through the existing proxy (Claude Code shows MCP prompts as slash commands). Zero new transport, but loses progressive disclosure, bundled scripts, and auto-triggering — a demo, not the feature.
