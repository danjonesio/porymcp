# Stop accepting the sse transport until it is implemented

Linear [PORM-28](https://linear.app/team-refresh/issue/PORM-28). Blocks PORM-131 (cut v0.1.0). Branch per CONTRIBUTING.md: `dan/porm-28-stop-accepting-the-sse-transport-until-it-is-implemented`. Dan merges.

## Context

An operator picks "SSE" in the Add upstream dialog, saves without error, wires a virtual key to it, and if the URL does not speak Streamable HTTP every request through that key answers `502` with `"upstream request failed"`. Nothing in the dashboard, the audit log or the README says why. The proxy has one outbound path: POST the JSON-RPC body to `up.URL`. `forward` (`internal/proxy/proxy.go:564-588`) and `listTools` (`:614-629`) never read `up.Transport`. Legacy HTTP+SSE needs a GET to open a stream, an `endpoint` event, a POST to that endpoint and correlation of responses by JSON-RPC `id`; none of that exists. `README.md:111` still lists "Streamable HTTP (primary) + SSE pass-through".

One consequence of `forward` ignoring the field: a row stored as `sse` whose URL already speaks Streamable HTTP works today. After this change the proxy refuses it until the operator sets `transport` to `streamable-http`; the URL does not change. The plan says so wherever an operator will read it (changelog, startup log, edit dialog).

After this ships: the API refuses `transport: "sse"` on every write with `400 {"error":"invalid transport"}`; the Add dialog offers Streamable HTTP only; a request routed to an upstream still stored as `sse` is not dialled, the agent gets the same generic `502` as every other upstream failure, and the audit row's `error_message` names the transport; rows already stored as `sse` are listed with an Unsupported badge and logged once at startup; README, docs and `openapi.yaml` stop claiming SSE; `models.TransportSSE` stays so stored rows keep deserialising. Nothing is migrated.

The Linear issue's line numbers date from 2026-08-26 and are wrong for this tree. Every line number below was re-read on `main` at `26635d3`.

## Findings from exploration

- `validTransport` (`internal/api/upstreams.go:458-459`) is `v == TransportStreamableHTTP || v == TransportSSE`, exact match, no trim, no case folding. Create copies `in.Transport.Value` into a local `transport`, defaults empty and `null` to `streamable-http`, does the same for `authType`, then validates both locals in one `if` with the combined `400` string `"invalid transport or auth_type"` (`:147-157`). PATCH validates only when the key is present (`in.Transport.Set`, `:344-349`) and already answers `"invalid transport"` (`:346`) and `"invalid auth_type"` (`:352-353`) separately. Unsaved discover (`internal/api/discover.go:93-104`) has the same local-then-validate shape and the combined string (`:101-103`). Saved discover (`:32-72`) does not call `validTransport`.
- `mcpclient.Discover` already refuses a stored `sse` row before any I/O with `"the sse transport is not implemented yet; use streamable-http"` and refuses any other value with `"unsupported transport"` without echoing it (`internal/mcpclient/discover.go:232-241`, through `Discovery.fail` at `:176-185`; pinned by `TestDiscoverSSETransport` at `internal/mcpclient/discover_test.go:661-671` and `internal/mcpclient/leak_test.go:212-215`). `mcpclient` imports only `models` and the standard library (`client.go:12`); `internal/api` (`upstreams.go:14`, `discover.go:12`), `internal/proxy` and `cmd/server/main.go:23` already import it.
- Proxy error shapes. `resolveTargets` failures reach the agent as HTTP `400` with `err.Error()` on the JSON-RPC body (`internal/proxy/proxy.go:228-236`), and `resolveMember` collapses them into `404 unknown endpoint` for every member URL of that group (`:501-514`, `:533-536`). Failures inside `forward` or `listTools` are audited as `truncate(err.Error(), auditFieldBytes)` and answered `502`, code `-32000`, `"upstream request failed"` (`:368-378`, `finish` at `:844-860`, `auditFieldBytes` 256 at `internal/proxy/request.go:25-28`; `writeRPCError(w, status, id, code, msg)` at `:878`). Credential failures use the second shape on purpose (`:544-550`, `:906-914`); `assert502Generic` in `internal/proxy/credential_test.go:46-61` rejects any client body naming the cause. `docs/07-security.md` states that every upstream failure answers the same `502`.
- In `serve`, after resolve and before the tool-policy gate (`:238-240`) the locals in scope are `upstreams`, `member`, `group`, `vk`, `requestID`, `req`, `method`, `tool` and `start`. `usedID` is declared later at `:331-336`, after tool policy. The tool-policy block names the refused row with `upstreams[0].ID` (`blockedUpstream`, `:276-281`).
- `resolveTargets` skips `!Enabled` group members (`:471-472`) and returns `errNoUpstreams` when none remain (`:476-478`). Group `initialize` and `notifications/initialized` return a local body from `ups[0]` without dialling (`:706-714`). `memberCatalogues` (`:638-688`) returns `([]*models.Upstream, [][]mcpTool)`, skips any member whose `listTools` fails through a local `skip` closure (`:663-669`, `:675-678`), logs `group member skipped` (`:667`), and returns `200` with the survivors; its comment at `:641-646` is about SSE-framed responses from a Streamable HTTP server, not `models.TransportSSE`. `tools/call` on a group re-lists through that walk and only then `forward`s (`:728-737`).
- `endpointsFor` (`internal/api/virtual_keys.go:98-104`, `:158-170`) skips missing and disabled members only, and its comment says the API must never advertise a URL the proxy would refuse. After this change an enabled `sse` member is still listed and its URL is shown in the key dialog (`web/src/app/(app)/virtual-keys/page.tsx:164`).
- The dashboard edit form seeds `transport` from the row (`formFromUpstream`, `web/src/lib/upstream-form.ts:85-91`) and sends `transport` on PATCH only when it differs from the stored value (`upstreamPatchBody`, `:157-164`). Create always sends it (`upstreamCreateBody`, `:135`). `openAdd` (`web/src/app/(app)/upstreams/page.tsx:245-259`) clears name, slug, url and credentials but keeps `transport`, auth type, header name and enabled (comment at `:249-251`), so Add after editing an `sse` row would POST `sse`. The transport `<Select>` is at `web/src/app/upstream-form.tsx:131-136`; `Select` is Headless UI's native `<select>` (`web/src/components/select.tsx:6-16`), so a controlled value with no matching `<option>` renders blank or snaps to the remaining option depending on the browser; a snap would make the next save PATCH `transport: "streamable-http"`, a silent rewrite. `AUTH_TYPE_LABELS` (`upstream-form.ts:41-47`) is how the auth select's options are driven (`upstream-form.tsx:140-145`).
- The table renders raw `u.transport` (`page.tsx:421`). `AuthCell` (`:54-65`) puts a pink `Badge` beside the auth type when the row cannot work; Status uses lime Enabled / zinc Disabled (`:434`). Badge tones are at `web/src/components/badge.tsx:8-13`. Group member checkboxes carry a `Description` for disabled members only (`web/src/app/group-form.tsx:71`); `group-form.tsx` does not import `upstream-form.ts`.
- Store: `upstreams.transport` is `TEXT NOT NULL`, no default, no CHECK, same DDL on sqlite and Postgres (`internal/store/sqlstore.go:302-316`), so the column is not a closed enum; `schemaVersion = 5` (`:211-214`); `CreateUpstream` requires a slug (`:1490-1492`) and writes `u.Transport`, `LastTestAt` and `LastTestOK` unvalidated from the struct (`:1485-1500`); `UpdateUpstream` writes `transport` from the in-memory struct (`:1588-1589`); `scanUpstream` copies it back (`:1683-1706`). `DeleteUpstream` returns `ErrInUse` while a row is in any group's `upstream_ids` or is a key's `target_id` (`:1648-1666`), so "recreate the row" is not an available workaround.
- Startup: `reportToolPolicyProblems` (`cmd/server/main.go:74`, body `:181-211`) already walks `ListUpstreams` once and logs one JSON line per problem with `upstream_id` and `upstream_name`, never the URL or slug because they are operator-written text (`:196-203`; the "never urls" contract is at `:52-55` and `cmd/server/encryption.go:44-46`). `LOG_LEVEL` defaults to info (`:593-594`). `TestReportToolPolicyProblems` indexes records by `group_id` then `virtual_key_id` and counts them exactly (`cmd/server/startup_test.go:397-416`); `decodeLogRecords` is at `:88-106`; `seedPolicyStore` (`:131-167`) seeds `TransportStreamableHTTP` (`:146`) and is the store-seed field set to copy.
- `TestPatchUpstreamURLResetsTestResult` (`internal/api/api_test.go:942-969`) runs every case as `mustUpstream` (always `streamable-http`) then `recordTestOn` (`:828-839`, which POSTs discover and fatals unless `ok == true`) then a PATCH; the `"transport"` case PATCHes `{"transport":"sse"}` at `:948`. `testAPI` returns `(*Server, http.Handler, *store.SQLStore)` (`:28-31`) and the handler is `Routes()` without the `/api/v1` prefix (`internal/api/api.go:102-114`; the prefix is applied in `cmd/server/main.go:443`), so tests post to `/upstreams`. `TestDiscoverRejectsInvalidPayload` expects the combined string (`internal/api/discover_test.go:782-783`).
- Proxy test fixtures: `newFixture` sorts slugs and assigns ids in that order, and the group stores that id order (`internal/proxy/fixture_test.go:218-222`, `:267-272`), so `upstreams[0]` is the alphabetically first slug. `upstreamSpec` (`:231-237`) has no `Transport` field. `totalReqs(slug)` (`:409`) and `upstreamsIdle()` (`:416-426`) are the idle assertions; `waitAudit` is at `:428-437`; `disable` (`internal/proxy/member_test.go:315-328`) flips a seeded member off through the store.
- Web tests are `node --test 'src/lib/*.test.ts'` (`web/package.json:10`); `upstream-form.test.ts` pins the create default and the PATCH omit rule (`:94-97`, `:147`, `:172`); no component renders under test (`web/src/lib/upstream-form.ts:7-8`).
- Docs that claim the upstream transport: `README.md:111`, `docs/04-architecture.md:5`, `docs/02-data-model.md:27` (enum), `docs/03-api.md:265-267` and `:315` (sse accepted on write), `:661-665` ("SSE support as fallback"), `:795-801` (upstream failures table), `docs/06-ui.md:160-163` ("until PORM-28 lands"), `openapi.yaml:642-645` (read enum), `:735-737` (write enum, "accepted on write but not implemented"), `:124` (discover 400 text). Docs about client-side GET streaming and edge buffering, which stay: `docs/09-clients.md:306`, `docs/11-deployment.md:67,90,163`, `docs/07-security.md:373-374,492-493`. `docs/05-mvp.md:8` already says Streamable HTTP is primary. `docs/03-api.md:287` (a combined catalogue line for `invalid transport` / `auth_type`) stays true after the split.
- The word `sse` also appears in `internal/mcpclient/fixture_test.go:38,83` and `internal/mcpclient/discover_test.go:66` as Streamable HTTP response framing; those are not `models.TransportSSE` and are not touched.
- `CHANGELOG.md:5` opens `## Unreleased`; entries are newest-first `### Title (PORM-N)` with bold lead bullets and a closing rollback sentence of the form "Rolling back to `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the previous binary ...; no schema or data is involved." (`:7-38`); a scope drop has used `### Breaking:` before (`:202`).
- `make dev` is `go run ./cmd/server` and `config.Load` reads the process environment only; nothing loads `.env` (`internal/config/config.go:57-80`). Compose is what requires `ADMIN_API_KEY` and `ENCRYPTION_KEY` in `.env` (`docker-compose.yml:13-17`). The README has the two flows: `.env` plus `docker compose up --build` (`README.md:28-32`) and `export` plus `go run` (`:70-74`).
- `TestProseStyle` (`cmd/server/prose_test.go`) scans every tracked `.md`, `.yaml`, `.go`, `.ts`, `.tsx`: no em or en dash, no arrow in prose, no emoji, no banned word. This plan file is scanned too.

## Design

### Caller's usage first

Admin API, after the change:

```
POST /api/v1/upstreams {"name":"x","url":"https://example.com/mcp","transport":"sse"}
  400 {"error":"invalid transport"}
POST /api/v1/upstreams {"name":"x","url":"https://example.com/mcp","auth_type":"nope"}
  400 {"error":"invalid auth_type"}
POST /api/v1/upstreams {"name":"x","url":"https://example.com/mcp"}
  201, transport streamable-http                (omitted, "" and null still default)
PATCH /api/v1/upstreams/{id} {"transport":"sse"}
  400 {"error":"invalid transport"}             (also when the stored value is sse)
PATCH /api/v1/upstreams/{id} {"name":"renamed"}
  200, transport unchanged (a stored sse stays sse)
PATCH /api/v1/upstreams/{id} {"transport":"streamable-http"}
  200, the repair; last_test_* reset as for any transport change
GET  /api/v1/upstreams/{id}
  200 {"transport":"sse", ...}                  (stored rows still round-trip)
POST /api/v1/upstreams/discover {"url":"...","transport":"sse"}
  400 {"error":"invalid transport"}             (was 200 ok:false)
POST /api/v1/upstreams/{id}/discover           (stored sse row)
  200 {"ok":false,"error":"the sse transport is not implemented yet; use streamable-http"}  (unchanged)
GET  /api/v1/virtual-keys/{id}
  endpoints still list an enabled sse member    (surface it; the proxy then refuses it)
```

Agent-facing proxy, for a key or member URL whose resolved upstream is stored as `sse`:

```
HTTP 502
{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream request failed"}}
```

No request reaches the upstream. The audit row for that call has `status` error, `upstream_id` set to the row, and `error_message` `the sse transport is not implemented yet; use streamable-http`. The Logs page detail dialog already shows `error_message` (`web/src/app/(app)/logs/page.tsx:142-145`).

Group key whose enabled members include one `sse` row: every method on the aggregate URL, including `initialize` (which today never dials), answers that same `502` with that audit row, until the operator disables the row or PATCHes it to `streamable-http`. Claude Code shows the group as failed to connect. Member URLs of the other members keep working; the `sse` member's own URL answers the same `502`, not `404`.

Startup, one line per stored row the proxy will refuse:

```
{"level":"WARN","msg":"upstream transport is not implemented; the proxy refuses every request to this upstream while it is enabled; set transport to streamable-http to restore it","upstream_id":"...","upstream_name":"...","enabled":true,"transport":"sse"}
```

The `transport` attribute is present only when the stored value is exactly `sse`; any other refused value is not written to the log.

Dashboard: the Add dialog's Transport select has one option, Streamable HTTP. Editing a stored `sse` row shows a select with `sse (unsupported)` selected and Streamable HTTP as the other option, plus a description line; saving without touching it omits `transport`; picking Streamable HTTP sends `{"transport":"streamable-http"}`. The Upstreams table shows `sse` in the Transport cell with a pink `Unsupported` badge beside it. The group dialog's member checkbox for an enabled `sse` row carries a description line; a disabled one keeps only the existing Disabled line.

### Data shapes

No schema change, no migration, `schemaVersion` stays 5. `models.TransportSSE` stays (`internal/models/models.go:10`). `validTransport` becomes `v == models.TransportStreamableHTTP`.

New in `internal/mcpclient` (owner of the sentences today), beside `errNeedsCredential` (`discover.go:190`):

```go
var (
	errSSENotImplemented   = errors.New("the sse transport is not implemented yet; use streamable-http")
	errUnsupportedTransport = errors.New("unsupported transport")
)

// TransportError reports whether the proxy can dial a stored transport.
// It is nil for TransportStreamableHTTP and for "" (Discover treats an
// empty value as streamable-http today). The stored value is never part
// of the message: the column is free text an operator wrote.
func TransportError(transport string) error
```

The two values stay unexported: no production caller needs `errors.Is`; callers compare `up.Transport == models.TransportSSE` when they need to know which case fired, and tests compare `err.Error()` against `mcpclient.TransportError(models.TransportSSE).Error()`.

Dashboard: `TRANSPORT_LABELS: Record<string,string>` (`{'streamable-http': 'Streamable HTTP'}`) in `web/src/lib/upstream-form.ts` beside `AUTH_TYPE_LABELS`; `transportUnsupported(t: string): boolean` (true unless `t === 'streamable-http' || t === ''`) in a new `web/src/lib/upstream-transport.ts`, the `authState` analogue, because `group-form.tsx` and the table need it and do not import `upstream-form.ts`.

### Module map

- `internal/api/upstreams.go` (change): `validTransport`; split create `400`s.
- `internal/api/discover.go` (change): split unsaved-discover `400`s.
- `internal/api/virtual_keys.go` (change): comment on `endpointsFor` only.
- `internal/mcpclient/discover.go` (change): extract `TransportError` and the two sentences; `Discover` calls it.
- `internal/proxy/proxy.go` (change): transport gate in `serve` after resolve; the same check beside `credential()` in `forward` and `listTools`.
- `cmd/server/main.go` (change): WARN per refused row inside the existing `ListUpstreams` loop of `reportToolPolicyProblems`.
- `web/src/lib/upstream-transport.ts` (new) and `web/src/lib/upstream-transport.test.ts` (new).
- `web/src/lib/upstream-form.ts`, `web/src/app/upstream-form.tsx`, `web/src/app/(app)/upstreams/page.tsx`, `web/src/app/group-form.tsx` (change).
- `web/out/**` (regenerated by `make web`, committed).
- `README.md`, `docs/02-data-model.md`, `docs/03-api.md`, `docs/04-architecture.md`, `docs/05-mvp.md`, `docs/06-ui.md`, `docs/09-clients.md`, `openapi.yaml`, `CHANGELOG.md` (change).
- Tests: `internal/api/api_test.go`, `internal/api/discover_test.go` (change); `internal/mcpclient/discover_test.go`, `internal/mcpclient/leak_test.go`, `internal/mcpclient/fixture_test.go` (unchanged, must still pass); `internal/proxy/transport_test.go` (new); `internal/proxy/fixture_test.go` (change); `cmd/server/startup_test.go` (change); `web/src/lib/upstream-form.test.ts` (change).

### Interfaces

- Write gate: `validTransport(v string) bool` in `internal/api/upstreams.go`, unchanged signature, one caller each in create, patch and unsaved discover.
- Dial gate: `mcpclient.TransportError(transport string) error`, called from `Discover`, from `proxy.serve` over the resolved targets, from `forward` and `listTools` before `credential()`, and from the startup walk.
- Proxy error mapping: a `TransportError` result is handled on the existing `502` arm (`finish` with `err.Error()` and the offending `up.ID`, then `writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed")`). It never returns from `resolveTargets`, and `memberCatalogues` keeps its signature and its skip.
- Startup: no new function signature; the WARN is a branch inside the loop at `cmd/server/main.go:196-211`.
- Dashboard: `transportUnsupported(u.transport)` drives the table badge, the edit-form option and the group-form description; `TRANSPORT_LABELS` drives the select options.

### Rejected alternative

Treat a stored `sse` row like a disabled one inside `resolveTargets`. That is the smallest edit, and it is wrong three ways: the agent would receive HTTP `400` with the sentinel text on the JSON-RPC body (`proxy.go:228-236`), which breaks the flat-failure contract in `docs/07-security.md`; `resolveMember` would turn the failure into `404 unknown endpoint` for every member URL of that group (`:511-512`), taking healthy Streamable HTTP members offline; and a group whose enabled members are all `sse` would report `"group has no enabled upstreams"`, which is false and is the silent-empty-list failure the issue forbids.

Also rejected: a gate only in `forward` and `listTools` without the `serve` pre-scan. Group `initialize` never calls either (`:706-714`), and `memberCatalogues` would skip the `sse` member and return a `200` partial catalogue, so the aggregate would never write the named audit row the acceptance criteria require. Also rejected: a third fail-loud branch inside `memberCatalogues`; with the `serve` gate in front of dispatch it is unreachable for stored rows, cannot be pinned by a test, and needs a signature change at two call sites (`:716`, `:728`).

Also rejected: implementing the legacy HTTP+SSE client now (PORM-5), and leaving the option in place with a tooltip (the API would still accept the value and the docs would still be wrong).

## Reuse

- `internal/mcpclient/discover.go:232-241` and `Discovery.fail` (`:176-185`): the two refusal sentences and the no-echo rule for unknown values. Step 2 extracts them; the proxy audit text cannot drift from discover's.
- `internal/proxy/proxy.go` `credential()` at the top of `forward` and `listTools` (`:565-570`, `:615-618`), the `502` arm at `:368-378`, and `blockedUpstream` naming `upstreams[0].ID` at `:276-281`: the "cannot use this upstream, nothing dialled" shape and how a pre-dispatch refusal names its row. Step 3 copies these.
- `internal/proxy/credential_test.go` `assert502Generic` (`:46-61`), `setStoredAuth` (`:20-30`), `TestUndecryptableCredentialFailsClosed`, `TestAggregateSkipsUndecryptableMember`; `internal/proxy/fixture_test.go` `newFixture`, `upstreamSpec`, `waitAudit`, `totalReqs(slug)`, `upstreamsIdle()`; `internal/proxy/member_test.go` `disable`: step 3 tests.
- `internal/api/helpers.go:14-28` `writeError` / `errorBody`: every `400` body.
- `internal/api/api_test.go` `testAPI` (third return is the store), `doJSON`, `newUpstream`, `upstreamBody`, `mustUpstream`, `upstreamTest`, and the exact-body assertion in `TestPatchRejectsBlankRequiredFields` (`:2362-2368`). `patchUpstreamJSON` fatals on non-200 (`:844-848`) and is not for rejection cases; `recordTestOn` fatals on `ok != true` and is not for `sse` rows.
- `internal/store` `CreateUpstream` (`sqlstore.go:1485`) with the field set from `cmd/server/startup_test.go:142-150` (id, name, slug, url, transport, auth_type, enabled, timestamps): the only way tests seed a stored `sse` row once the API refuses it; `api_test.go:1382-1391` already seeds through `testAPI`'s store for a dangling key.
- `cmd/server/main.go:196-211` loop plus `decodeLogRecords` and the JSON handler setup at `startup_test.go:398-399`: step 4.
- `web/src/lib/upstream-auth.ts` `authState` and `AuthCell` (`upstreams/page.tsx:54-65`) with pink `Badge` (`badge.tsx:17-21`): pattern for `upstream-transport.ts` and the Transport cell.
- `AUTH_TYPE_LABELS` (`upstream-form.ts:41-47`) and its `<option>` map (`upstream-form.tsx:140-145`): pattern for `TRANSPORT_LABELS`.
- `web/src/lib/upstream-form.ts` `formFromUpstream` and `upstreamPatchBody`: keep seeding the stored value and omitting unchanged keys; that is what lets an `sse` row be edited without a PATCH exemption.
- `web/src/app/group-form.tsx:71` `Description` on disabled members: same slot and same register for enabled unsupported members.
- `web/src/lib/edit-error.ts:41` `editErrorMessage`: shows a `400` `"invalid transport"` verbatim in the dialog; no change.
- `CHANGELOG.md:7-38` (PORM-98) as the Unreleased entry shape, rollback sentence included. `README.md:28-32` and `:70-74` as the two ways to get keys for manual checks.

## Security requirements

1. The agent-facing JSON-RPC body for an unsupported transport is the generic `"upstream request failed"` `502`; it never contains the transport value, the upstream id, name or URL. Satisfied by step 3; pinned with `assert502Generic`.
2. The transport check never runs inside `resolveTargets`, so no new `400` text and no `404` on healthy member URLs. Satisfied by step 3.
3. The audit `error_message` and the startup WARN are fixed sentences plus `upstream_id`, `upstream_name` and `enabled`; the stored `transport` column is free text and is written to the log only when it equals the constant `sse`; the URL (which may carry a query-string token, `docs/07-security.md`) is never logged. Satisfied by steps 2, 3 and 4; pinned by the `websocket` seed in step 4's test.
4. `validTransport` stays exact match: no `EqualFold`, no trim. `400` bodies never repeat the submitted value (the `errURLRule` contract, `internal/api/upstreams.go:36-37`). Satisfied by step 1.
5. The saved discover route (`POST /upstreams/{id}/discover`) does not gain a `validTransport` call; it keeps returning `200 ok:false` through `mcpclient.Discover`. Satisfied by steps 1 and 2 (test in step 1).
6. Admin routes stay behind `requireAdmin` (`internal/api/api.go:98-131`); no new route, no new env var, no new dependency. Satisfied by every step touching none of those.
7. An unknown stored transport (hand-edited column) is refused with `"unsupported transport"` and is never interpolated into the audit row or the startup log. Satisfied by step 2's `TransportError` and step 4.

## Changes

### 1. API write gate and split `400`s

Files: `internal/api/upstreams.go`, `internal/api/discover.go`, `internal/api/api_test.go`, `internal/api/discover_test.go`.

- `upstreams.go:458-459`: `func validTransport(v string) bool { return v == models.TransportStreamableHTTP }`. Doc comment: only `streamable-http` is accepted on write; `models.TransportSSE` remains a stored value until PORM-5 implements it.
- `upstreams.go:155-157`: keep the two locals and their defaults at `:147-154` exactly as they are; replace the combined `if` with two, on the post-default locals and in this order: `if !validTransport(transport) { writeError(w, http.StatusBadRequest, "invalid transport"); return }` then `if !validAuthType(authType) { writeError(w, http.StatusBadRequest, "invalid auth_type"); return }`. Same strings as PATCH at `:346` and `:352-353`. Do not validate `in.Transport.Value` before the default: omitted, `""` and `null` must still create as `streamable-http`.
- `discover.go:101-103`: the same split on the post-default locals in `discoverUnsaved`. Do not touch `discoverUpstream` (`:32-72`).
- `api_test.go`, new `TestRejectsSSETransport` using `_, h, st := testAPI(t)`, paths without the `/api/v1` prefix, `doJSON`, and the exact-body pattern from `TestPatchRejectsBlankRequiredFields`:
  - (a) `POST /upstreams` with `upstreamBody` plus `"transport":"sse"` is `400` and the body is exactly `{"error":"invalid transport"}`.
  - (b) `mustUpstream` a default row; `PATCH /upstreams/{id}` `{"transport":"sse"}` is `400` with the same body; GET still says `streamable-http`.
  - (c) seed a second row with `st.CreateUpstream` using the `seedPolicyStore` field set (id, name, slug, url, `Transport: models.TransportSSE`, `AuthType: models.AuthNone`, `Enabled: true`, timestamps); `GET /upstreams/{id}` returns `"transport":"sse"`.
  - (d) `PATCH /upstreams/{id}` `{"transport":"sse"}` on that seeded row is `400 {"error":"invalid transport"}` and GET still returns `sse` (the round-trip client case).
  - (e) `PATCH /upstreams/{id}` `{"name":"renamed"}` on that row is `200` and GET still returns `sse`.
  - (f) `PATCH /upstreams/{id}` `{"transport":"streamable-http"}` on that row is `200` and GET returns `streamable-http`.
  - (g) seed a third `sse` row; `POST /upstreams/{id}/discover` is `200` with `ok` false and `error` equal to the mcpclient sentence (no HTTP server needed; Discover refuses before I/O).
- `api_test.go:942-969` `TestPatchUpstreamURLResetsTestResult`: remove the `"transport"` case from the table (the table's `mustUpstream` then `recordTestOn` cannot produce an `sse` row, and PATCHing `streamable-http` onto a `streamable-http` row does not reset, `upstreams.go:306`). Add a separate `TestPatchTransportResetsTestResult`: `_, h, st := testAPI(t)`; `st.CreateUpstream` with `Transport: models.TransportSSE`, `LastTestAt` and `LastTestOK` set to non-nil pointers (the store writes them, `sqlstore.go:1497-1498`); `PATCH {"transport":"streamable-http"}` is `200`; `upstreamTest` shows both columns reset. Do not call `recordTestOn`.
- `api_test.go`, a create case: `POST /upstreams` with `"auth_type":"nope"` and no transport is `400 {"error":"invalid auth_type"}` (pins the split and the default).
- `discover_test.go:782-783`: expect `"invalid transport"` and `"invalid auth_type"` on their respective rows; add a row with `"transport":"sse"` expecting `400 {"error":"invalid transport"}`.
- **Verify**: `go test ./internal/api/ -count=1 -run 'TestRejectsSSETransport|TestPatchTransportResetsTestResult|TestPatchUpstreamURLResetsTestResult|TestDiscoverRejectsInvalidPayload|TestCreate'` passes, then `go test ./internal/api/ -count=1`.

### 2. Shared transport predicate in `mcpclient`

Files: `internal/mcpclient/discover.go`.

- Add `errSSENotImplemented`, `errUnsupportedTransport` and `TransportError` as in Data shapes, next to `errNeedsCredential` (`discover.go:190`).
- `discover.go:232-241`: replace the switch with `if err := TransportError(up.Transport); err != nil { return out.fail(err.Error()) }`, keeping the two existing comments (why saying so is the correct outcome; why the value is never repeated). Strings are byte-identical to today's (`the sse transport is not implemented yet; use streamable-http` and `unsupported transport`, checked against `:236` and `:240`), so `TestDiscoverSSETransport` (`discover_test.go:661-671`) and `leak_test.go:212-215` pass unchanged. Leave `internal/mcpclient/fixture_test.go:38,83` and `discover_test.go:66` alone: their `sse` is response framing.
- **Verify**: `go test ./internal/mcpclient/ -count=1` passes with no test edits.

### 3. Proxy: refuse before dispatch, audit names the transport, client stays generic

Files: `internal/proxy/proxy.go`, `internal/api/virtual_keys.go`, `internal/proxy/fixture_test.go`, new `internal/proxy/transport_test.go`.

- `proxy.go` `serve`, at `:240`, after the resolve block has filled `upstreams` and before the tool-policy comment: `for _, up := range upstreams { if err := mcpclient.TransportError(up.Transport); err != nil { h.finish(vk, requestID, truncate(method, auditFieldBytes), truncate(tool, auditFieldBytes), up.ID, models.StatusError, truncate(err.Error(), auditFieldBytes), start, 0, boundedParams(req.Params)); writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed"); return } }`. `upstreams` holds the single member, the single target, or the group's enabled members (`:226`, `:228`), so this covers member URLs, single keys, and every aggregate method including `initialize`. Use the locals in scope at that point; `usedID` does not exist until `:331`. Do not add anything to `resolveTargets` (`:452-478`), `resolveMember` (`:501-514`) or `memberCatalogues` (`:638-688`).
- Doc comment on that loop, in the style of `:544-550`: the client body stays generic because operator configuration is not the key holder's to learn and `docs/07-security.md` promises one `502` shape; the check is not in `resolveTargets` because that path answers `400` with the error text and `404`s member URLs; it runs before dispatch because group `initialize` never dials and a skipped member would be a silent partial catalogue; a row that worked because its URL already spoke Streamable HTTP now fails until `transport` is set to `streamable-http`.
- `forward` (`:565`) and `listTools` (`:615`): first statement `if err := mcpclient.TransportError(up.Transport); err != nil { return nil, 0, nil, err }` (or the two-value form for `listTools`), before `credential()`. This is the defence for any future caller that reaches a dial without passing `serve`; it is the same shape as `credential()` and not a second policy.
- `internal/api/virtual_keys.go:98-104`: `endpointsFor` keeps advertising an enabled `sse` member (surface it, then the proxy refuses it; hiding it is the silent path the issue forbids). Rewrite the comment so it no longer claims the API never advertises a URL the proxy would refuse: it skips what `resolveTargets` skips (missing and disabled), and a member the proxy refuses for its transport is listed so the operator can see it. No code change.
- `fixture_test.go` `upstreamSpec` (`:231-237`): add `Transport string`; `newFixture` writes it when non-empty, else `models.TransportStreamableHTTP`.
- `transport_test.go` (same package as `credential_test.go`; reuse its helpers, do not fold into it). Seed the Streamable HTTP member with a slug that sorts before the `sse` member (for example `alpha` and `zeta`) so a gate that only looked at `upstreams[0]` would fail the group tests:
  - `TestProxyRefusesSSETransport`: single-upstream key on an `sse` row with slug `solo`; `tools/list` answers `502`; `assert502Generic`; `waitAudit` row has `error_message` equal to `mcpclient.TransportError(models.TransportSSE).Error()` and `upstream_id` equal to the row; `totalReqs("solo") == 0`.
  - `TestProxyMemberEndpointRefusesSSETransport`: group of `alpha` (Streamable HTTP) and `zeta` (`sse`); `zeta`'s member URL answers the generic `502` with the named audit row (not `404`); `alpha`'s member URL answers `200`.
  - `TestProxyGroupFailsWhenEnabledMemberIsSSE`: the same group's aggregate URL: `initialize`, `tools/list` and `tools/call` each answer `502`; each audit row names `zeta`; `upstreamsIdle()` is true.
  - `TestProxyGroupServesWhenSSEMemberDisabled`: same group after `disable(t, f, zetaID)`; aggregate `tools/list` is `200` and lists `alpha`'s tools (the operator's escape hatch).
  - `TestProxyRefusesUnknownTransport`: single key on a row seeded with `Transport: "websocket"`; `502`; audit `error_message` is exactly `unsupported transport` and the string `websocket` appears nowhere in the audit row or the response body.
- **Verify**: `go test ./internal/proxy/ -count=1 -run 'TestProxy.*Transport|TestProxyGroup|TestUndecryptable|TestAggregateSkips'` passes, then `go test ./internal/proxy/ -count=1 && go vet ./internal/api/`.

### 4. Startup WARN inside the existing upstream walk

Files: `cmd/server/main.go`, `cmd/server/startup_test.go`.

- `main.go:196-211`, inside the per-upstream loop of `reportToolPolicyProblems`, after the slug check: `if err := mcpclient.TransportError(u.Transport); err != nil { attrs := []any{"upstream_id", u.ID, "upstream_name", u.Name, "enabled", u.Enabled}; if u.Transport == models.TransportSSE { attrs = append(attrs, "transport", models.TransportSSE) }; log.Warn("upstream transport is not implemented; the proxy refuses every request to this upstream while it is enabled; set transport to streamable-http to restore it", attrs...) }`. Disabled rows are included, and the sentence is true for them (the refusal applies while enabled). Level WARN, never abort. Extend the comment at `:198-203`: the stored transport is operator-written text like the slug, so only the constant `sse` is ever logged. If the function's doc comment enumerates its findings, add this one.
- `startup_test.go`: new `TestReportsUnsupportedTransportAtStartup`: seed three rows through `st.CreateUpstream` with the `seedPolicyStore` field set: `sse` enabled, `websocket` disabled, `streamable-http` enabled. JSON handler as at `:398-399`; run `reportToolPolicyProblems`; `decodeLogRecords` shows exactly two records; assert on `rec["upstream_id"]`, `rec["transport"]` and `rec["enabled"]` directly (not through a `group_id`/`virtual_key_id` index): the `sse` record has `transport` `sse` and `enabled` true; the `websocket` record has no `transport` key and `enabled` false; neither has a `url` key; `buf.String()` does not contain `websocket`. Do not change `seedPolicyStore`'s default transport; `TestReportToolPolicyProblems` counts records exactly.
- **Verify**: `go test ./cmd/server/ -count=1 -run 'TestReport'` passes, then `go test ./cmd/server/ -count=1` (includes `TestProseStyle` over every file edited so far).

### 5. Dashboard

Files: `web/src/lib/upstream-transport.ts` (new), `web/src/lib/upstream-transport.test.ts` (new), `web/src/lib/upstream-form.ts`, `web/src/app/upstream-form.tsx`, `web/src/app/(app)/upstreams/page.tsx`, `web/src/app/group-form.tsx`, `web/src/lib/upstream-form.test.ts`, `web/out/**`.

- `upstream-form.ts`: add `TRANSPORT_LABELS` beside `AUTH_TYPE_LABELS` (`:41-47`). No other logic change; `blankUpstreamForm` (`:65`) already defaults to `streamable-http`.
- `upstream-transport.ts`: `transportUnsupported` as in Data shapes. `upstream-transport.test.ts` (`node --test`): `streamable-http` and `''` are supported; `sse` and `websocket` are not.
- `upstream-form.tsx:131-136`: render options from `TRANSPORT_LABELS` the way `:140-145` renders auth types; when `transportUnsupported(form.transport)`, also render `<option value={form.transport}>{form.transport} (unsupported)</option>` so the native select shows the stored value (`sse (unsupported)`) and cannot snap. Below the select, when unsupported: `<Description>Not implemented. Requests through this upstream fail until the transport is Streamable HTTP. The URL stays as it is.</Description>`. In Add mode `form.transport` is always `streamable-http` after the `openAdd` change, so the Add dialog shows one option.
- `page.tsx:245-259` `openAdd`: add `transport: 'streamable-http'` to the existing reset object at `:257` so auth type, header name and enabled still carry across Add dialogs. Edit the comment at `:249-251`: auth type, header name and enabled persist for the operator adding three upstreams behind the same scheme; transport is reset because `streamable-http` is the only write value.
- `page.tsx:421`: Transport cell becomes `<span className="inline-flex items-center gap-2">{u.transport}{transportUnsupported(u.transport) ? <Badge color="pink">Unsupported</Badge> : null}</span>`, the `AuthCell` layout. Status column unchanged; the badge shows on disabled rows too.
- `group-form.tsx:71`: keep the disabled `Description` as is. Add, only when `u.enabled && transportUnsupported(u.transport)`: `<Description>Not implemented. This member's endpoint fails, and so does the group endpoint, until the transport is Streamable HTTP or the member is disabled.</Description>`. A disabled `sse` member shows the Disabled line only.
- `upstream-form.test.ts`: add (a) `formFromUpstream` of an `sse` row keeps `transport: 'sse'`; (b) `upstreamPatchBody` with only `name` changed on that form omits `transport`; (c) `upstreamPatchBody` after setting `transport: 'streamable-http'` emits `{ transport: 'streamable-http' }`; (d) `TRANSPORT_LABELS` has exactly one key, `streamable-http`.
- UI copy follows `docs/12-writing.md` (label, consequence, stop; no dashes).
- **Verify**: `cd web && nvm use && npm ci --no-audit --no-fund && cd .. && make web && make web-typecheck && make web-lint && make web-test` (build first: typecheck needs the `web/next-env.d.ts` the build writes); `git status --short web/out | head` shows the regenerated export, which is committed with this step. Manual: `export ADMIN_API_KEY=... ENCRYPTION_KEY=...` as in `README.md:70-74`, `make dev`, open `http://localhost:8080/upstreams`, Add upstream: the Transport select lists one option.

### 6. Docs, OpenAPI, README, changelog

Files: `README.md`, `docs/02-data-model.md`, `docs/03-api.md`, `docs/04-architecture.md`, `docs/05-mvp.md`, `docs/06-ui.md`, `docs/09-clients.md`, `openapi.yaml`, `CHANGELOG.md`.

- `README.md:111`: replace the feature line with `Streamable HTTP to upstreams. Legacy HTTP+SSE is not implemented (PORM-5).`
- `docs/04-architecture.md:5`: drop `+ SSE` from the proxy bullet.
- `docs/02-data-model.md:27`: `transport` accepts `streamable-http` on write; `sse` may still be present on rows saved before PORM-28 and is refused by the proxy and by discovery. `:34` and `:41` (reset and refusal wording) checked against the new behaviour.
- `docs/03-api.md`: `:32` add `sse` to the refused write values; Partial updates (`:16-19`) add one sentence: a stored `sse` row is edited by omitting `transport` or by sending `streamable-http`; a body that echoes `sse` is `400`. `:265-267` rewrite: unsaved discover with `sse` is `400 invalid transport`; saved discover of a stored `sse` row is `200 ok:false` with the fixed sentence. `:287` unchanged. `:315` keep for saved discover. `:661-665` rewrite so SSE is not called a fallback transport PoryMCP speaks to upstreams; keep the client-facing GET buffering fact. `:795-801` Upstream failures table: add a row `stored transport is sse or unknown: 502, audit error_message names it, no request is made`. Where the group section (`:828-833`) describes undecryptable members being skipped, add that an enabled `sse` member fails every aggregate method, `initialize` included, until it is disabled or repaired, and that the other members' own endpoints keep working. Virtual keys section: an enabled `sse` member is still listed in `endpoints`.
- `docs/05-mvp.md`: add a known-gap line: legacy HTTP+SSE upstream transport is not implemented (PORM-5); `sse` is refused on write since PORM-28.
- `docs/06-ui.md:160-163`: a stored `sse` row shows `sse` with an Unsupported badge in the Transport cell; Tools still records Failed; Edit shows `sse (unsupported)` and offers Streamable HTTP as the repair. Remove "until PORM-28 lands".
- `docs/09-clients.md:307` (the `502` paragraph after `:306`): one sentence that a stored `sse` upstream now writes a log row naming the transport. Leave `:306`.
- `openapi.yaml:642-645` `Upstream.transport`: keep enum `[streamable-http, sse]`; description: `sse` may appear on rows saved before PORM-28 and is not implemented. `:735-737` `UpstreamWrite.transport`: enum `[streamable-http]`; drop "accepted on write but not implemented (PORM-28)". `:124` discover `400` description: `invalid transport` or `invalid auth_type`. Confirm `:697-699` still says omitted, empty and `null` default on create.
- `CHANGELOG.md`: insert at the top of `## Unreleased`, above PORM-98, in the PORM-98 shape (bold lead bullets, closing rollback sentence): `### Breaking: the sse upstream transport is refused on write (PORM-28)`. Bullets: **The README advertised SSE pass-through and it was never implemented**; the proxy has always POSTed Streamable HTTP to every upstream. **`POST /api/v1/upstreams`, `PATCH /api/v1/upstreams/{id}` and `POST /api/v1/upstreams/discover` answer `400 {"error":"invalid transport"}` for `sse`**; the create `400` is split into `invalid transport` and `invalid auth_type`. **Rows already stored as `sse` are kept**, listed with an Unsupported badge, and logged once at startup; edit them by omitting `transport` or sending `streamable-http`; no recreate. **A request routed to a stored `sse` row is not dialled**; the agent gets the usual `502` and the audit row names the transport. A row that worked because its URL already spoke Streamable HTTP now fails until `transport` is set to `streamable-http`; the URL does not change. **A group with an enabled `sse` member fails on its aggregate endpoint**, `initialize` included, until the member is disabled or repaired; other members' endpoints keep working. Closing sentence: Rolling back to `ghcr.io/danjonesio/porymcp:sha-<short sha>` restores the previous binary, which accepts `sse` on write again; no schema or data is involved.
- **Verify**: `grep -n 'SSE' README.md` shows no pass-through claim; `rg -n 'sse' docs/02-data-model.md docs/03-api.md openapi.yaml CHANGELOG.md` shows only the stored-row and refusal wording; `go test ./cmd/server/ -count=1 -run TestProseStyle` passes.

### 7. Full gate and commits

- **Verify**: the `CONTRIBUTING.md:9-20` block, in that order and in full: `make vet`, `make test`, `make vuln`, `cd web && npm ci --no-audit --no-fund && cd ..`, `make web`, `make web-typecheck`, `make web-lint`, `make web-test`, `make web-audit`, `docker build .`. Do not run `go test ./...` after `npm ci` (`CONTRIBUTING.md:24`).
- One commit per step above, subject naming PORM-28, body with the step's `Verify:` command (`CONTRIBUTING.md:37`).

## Verification

- Automated: the step 7 block.
- API, against Compose: `[ -f .env ] || cp .env.example .env`, then the two `grep -q ... >> .env` lines from `README.md:29-31`, then `docker compose up --build`; `ADMIN_API_KEY=$(sed -n 's/^ADMIN_API_KEY=//p' .env)`; `curl -i -X POST -H "Authorization: Bearer $ADMIN_API_KEY" -H 'Content-Type: application/json' -d '{"name":"x","url":"https://example.com/mcp","transport":"sse"}' http://localhost:8080/api/v1/upstreams` answers `400` with `{"error":"invalid transport"}`. Against `make dev`: `export ADMIN_API_KEY` and `export ENCRYPTION_KEY` as in `README.md:70-74` (a `.env` file does nothing for `go run`), then the same curl.
- Dashboard: `http://localhost:8080/upstreams`, Add upstream: the Transport select has one option, Streamable HTTP.
- Proxy: with a row seeded as `sse` (through a test, or `sqlite3 data/porymcp.db "UPDATE upstreams SET transport='sse' WHERE id='...'"` on a scratch database and a restart), a `tools/list` through its key answers `502 upstream request failed`; `GET /api/v1/logs` shows the row with `error_message` `the sse transport is not implemented yet; use streamable-http`; the server's startup log has one WARN naming the row with `"transport":"sse"`.
- Done: all six acceptance criteria in the issue hold, with the `400` body reading `invalid transport` (the issue's `invalid transport or auth_type` predates the PATCH split and is superseded by the issue's own note asking for the split) and `make test` in place of `go test ./...` (`CONTRIBUTING.md:24`).

## Tests to add

- `TestRejectsSSETransport` (`internal/api/api_test.go`): cases (a) to (g) in step 1. Security requirements 4 and 5.
- `TestPatchTransportResetsTestResult` (`api_test.go`): store-seeded `sse` row with `last_test_*` set, PATCH `streamable-http` resets them; replaces the `"transport"` case of `TestPatchUpstreamURLResetsTestResult` at `:948`.
- Create with a bad `auth_type` is `400 invalid auth_type` (`api_test.go`). The split.
- `TestDiscoverRejectsInvalidPayload` rows for the split strings and for `sse` (`internal/api/discover_test.go:782-783`).
- `TestProxyRefusesSSETransport`, `TestProxyMemberEndpointRefusesSSETransport`, `TestProxyGroupFailsWhenEnabledMemberIsSSE`, `TestProxyGroupServesWhenSSEMemberDisabled`, `TestProxyRefusesUnknownTransport` (`internal/proxy/transport_test.go`). Security requirements 1, 2, 3, 7 and the group decision.
- `TestReportsUnsupportedTransportAtStartup` (`cmd/server/startup_test.go`). Security requirements 3 and 7.
- `web/src/lib/upstream-transport.test.ts` and four cases in `web/src/lib/upstream-form.test.ts`: stored `sse` is kept by `formFromUpstream`, omitted by `upstreamPatchBody` when unchanged, sent as `streamable-http` when changed; `TRANSPORT_LABELS` has one key.
- Unchanged and must still pass: `TestDiscoverSSETransport`, `leak_test.go` transport cases, the `mcpclient` framing fixtures, `TestUndecryptableCredentialFailsClosed`, `TestAggregateSkipsUndecryptableMember`, `TestReportToolPolicyProblems`, `TestProseStyle`.

## Risks and open questions

- Stored `sse` rows whose URL already speaks Streamable HTTP work today and will answer `502` after this ships until `transport` is PATCHed to `streamable-http`. Accepted as the issue's explicit step 5 ("reject a request to an upstream whose transport is not streamable-http"); the changelog, startup WARN and edit dialog all name the one-field repair. Open question for Dan: confirm that cut, mixed groups included. Default: ship the gate as planned.
- A group with an enabled stored `sse` member goes offline on its aggregate URL, `initialize` included, until the operator disables or repairs the row. Accepted: the issue asks for loud failure over a silent partial catalogue; the startup WARN, the table badge and the group dialog point at the row; member URLs of the healthy members keep working. The security analyst noted the fingerprint this gives a key holder who also has member URLs: aggregate `502` plus a healthy member `200` says "this group has a pre-dial refusal", which an undecryptable or down member does not (those keep the aggregate at `200`). It reveals no URL, slug, transport value or other group. Recorded, not mitigated. If Dan prefers skip-on-aggregate, the change is confined to the `serve` loop in step 3 (skip when `group != nil && member == nil`, still fail single and member routes), `TestProxyGroupFailsWhenEnabledMemberIsSSE`, and the changelog and `docs/03-api.md` group sentences; default is fail.
- The agent-facing body is generic, so an agent cannot tell an unsupported transport from a timeout. Accepted: `docs/07-security.md` promises one `502` shape for every upstream failure, and the audit row and Logs page carry the cause for the operator.
- API clients that GET an `sse` row and PATCH the whole object back now get `400`. Accepted and documented in `docs/03-api.md` and the changelog; the dashboard never echoes an unchanged transport.
- `endpointsFor` keeps listing an enabled `sse` member's URL, which the proxy then refuses. Accepted: hiding it is the silent path; the comment is corrected in step 3.
- `make web` output is not byte-reproducible and no CI step diffs `web/out`; a stale export would ship the old dropdown in `go run` and `make build`. Mitigation: step 5 rebuilds with Node 22 and commits the export.
- Rollback: an older image opens the same store (`schemaVersion` unchanged) and accepts `sse` on write again. No data step either way.
- Open question for Dan: the Linear acceptance checkboxes still say `"invalid transport or auth_type"` and `go test ./...`. The plan follows the PATCH split the issue itself asks for and `CONTRIBUTING.md:24`; the checkboxes want editing so the PR does not look like it missed them. Default: build to the plan's strings.

## Out of scope

- Implementing the legacy HTTP+SSE upstream client (PORM-5).
- Client-facing streaming on `GET /mcp` and the GET-stall buffering (PORM-5, PORM-30); the SSE sentences in `docs/09-clients.md:306`, `docs/11-deployment.md` and `docs/07-security.md` describe that and stay.
- Migrating, rewriting or deleting stored `sse` rows.
- A `/health`, `/stats` or Overview count of unsupported rows.
- Hiding an enabled `sse` member from a virtual key's `endpoints`.
- A CHECK constraint or default on `upstreams.transport`.

## Panel record

Panel model: `cursor-grok-4.6-high` (the ask named Grok 4.6 without an effort level; high was chosen and is recorded here). Orchestrator on the session model.

| member | model | wave | findings | accepted | rejected (reason) |
|---|---|---|---|---|---|
| architect | cursor-grok-4.6-high | 1 | draft v0 + 6 (5 warning, 1 nit) | design, steps, tests, PATCH decision, group fail-loud, `TransportError` extraction | client body carries Discover's sentence (security, ops, ux and reuse: `docs/07-security.md` flat `502`, `assert502Generic`); separate startup function (ops, reuse, data: extend the existing walk); exported sentinels and the `memberCatalogues` branch (dropped in wave 2, see reuse-scout and code-reviewer) |
| reuse-scout | cursor-grok-4.6-high | 1 | 8 (3 critical, 4 warning, 1 nit) | all | none |
| security-analyst | cursor-grok-4.6-high | 1 | 6 (1 critical, 4 warning, 1 nit) | 1, 2, 4, 5, 6 in full; 3 in part (generic envelope) | 3 skip-on-aggregate (issue prefers loud failure; skip makes an all-`sse` group an empty `200`; recorded as a risk with a default) |
| data-analyst | cursor-grok-4.6-high | 1 | 7 (6 warning, 1 nit) | 1, 2, 4, 5, 6, 7; 3's `ErrInUse` fact and "no recreate" wording | 3 option (a) allow `sse` when it equals the stored value (AC requires PATCH `sse` to be `400`; the dashboard never echoes it; allowing it lets round-tripping clients keep writing `sse`) |
| ux-api-designer | cursor-grok-4.6-high | 1 | 12 (2 critical, 9 warning, 1 nit) | all | none |
| ops-analyst | cursor-grok-4.6-high | 1 | 8 (2 critical, 6 warning) | all; 2's fail-the-group caveat honoured by gating after resolve, not in `resolveTargets` | none |
| code-reviewer | cursor-grok-4.6-high | 2 (fresh) | 6 warning | all: `serve` gate uses `upstreams` and `up.ID` (no `usedID`); `memberCatalogues` untouched; group-form gated on `enabled`; slug ordering and `upstreamsIdle` / `totalReqs(slug)` / `disable` in tests; `/upstreams` paths and full seed field set; startup test asserts fields directly | none |
| skeptic | cursor-grok-4.6-high | 2 (fresh) | 6 (5 warning, 1 nit) | all: working `sse` rows named in Context, changelog, WARN and dialog, plus an open question; `initialize` symptom stated; single primary gate; `endpointsFor` decided (advertise, fix comment); WARN never writes the column; framing `sse` hits listed as leave-alone; Linear checkbox mismatch as an open question | none |
| security-analyst | cursor-grok-4.6-high | 2 (resumed) | 2 warning | both: aggregate `502` fingerprint recorded as a risk; startup WARN writes only the constant `sse`, pinned with a `websocket` seed | none |
| reuse-scout | cursor-grok-4.6-high | 2 (resumed) | 3 (2 warning, 1 nit) | all: `memberCatalogues` branch dropped; sentinels unexported; `TRANSPORT_LABELS` beside `AUTH_TYPE_LABELS`; `transport_test.go` stays a separate file | none |
| data-analyst | cursor-grok-4.6-high | 2 (resumed) | 3 (2 warning, 1 nit) | all: transport-reset case pulled out of the table and seeded with `last_test_*` set; echo-400 on a stored `sse` row added as (d); full seed field set | none |
| ux-api-designer | cursor-grok-4.6-high | 2 (resumed) | 4 (3 warning, 1 nit) | all: group-form line gated on `enabled` and reworded; `sse (unsupported)` label; create validates the post-default locals; `openAdd` comment keeps the carry-over sentence | none |
| ops-analyst | cursor-grok-4.6-high | 2 (resumed) | 4 warning | all: WARN gated and attribute fixed; changelog in the Unreleased shape with the image-tag rollback sentence; step 7 is the full CONTRIBUTING block; Compose and `make dev` key setup split | none |

Situational members included: data-analyst (stored rows, PATCH round-trip), ux-api-designer (dialog, table, OpenAPI, error contract), ops-analyst (startup log, changelog, release, CI). perf-analyst skipped: the new check is a string comparison on a struct already in memory. No wave-2 finding was critical, so no third loop was run.
