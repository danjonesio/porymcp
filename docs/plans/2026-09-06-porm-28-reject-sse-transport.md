# Stop accepting the sse transport until it is implemented

Linear [PORM-28](https://linear.app/team-refresh/issue/PORM-28). Blocks PORM-131 (cut v0.1.0). Branch per CONTRIBUTING.md: `dan/porm-28-stop-accepting-the-sse-transport-until-it-is-implemented`. Dan merges.

## Context

An operator picks "SSE" in the Add upstream dialog, saves without error, wires a virtual key to it, and every request through that key answers `502` with `"upstream request failed"`. Nothing in the dashboard, the audit log or the README says why. The proxy has one outbound path: POST the JSON-RPC body to `up.URL`. `forward` (`internal/proxy/proxy.go:564-588`) and `listTools` (`:614-629`) never read `up.Transport`. Legacy HTTP+SSE needs a GET to open a stream, an `endpoint` event, a POST to that endpoint and correlation of responses by JSON-RPC `id`; none of that exists. `README.md:111` still lists "Streamable HTTP (primary) + SSE pass-through".

After this ships: the API refuses `transport: "sse"` on every write with `400 {"error":"invalid transport"}`; the Add dialog offers Streamable HTTP only; a request routed to an upstream still stored as `sse` is not dialled, the agent gets the same generic `502` as every other upstream failure, and the audit row's `error_message` names the transport; rows already stored as `sse` are listed with an Unsupported badge and logged once at startup; README, docs and `openapi.yaml` stop claiming SSE; `models.TransportSSE` stays so stored rows keep deserialising. Nothing is migrated.

The Linear issue's line numbers date from 2026-08-26 and are wrong for this tree. Every line number below was re-read on `main` at `26635d3`.

## Findings from exploration

- `validTransport` (`internal/api/upstreams.go:458-459`) is `v == TransportStreamableHTTP || v == TransportSSE`, exact match, no trim, no case folding. Create defaults empty and `null` to `streamable-http` then validates (`:147-157`), and shares one `400` string `"invalid transport or auth_type"` (`:155-157`). PATCH validates only when the key is present (`in.Transport.Set`, `:344-349`) and already answers `"invalid transport"` (`:346`) and `"invalid auth_type"` (`:352-353`) separately. Unsaved discover (`internal/api/discover.go:93-104`) uses `validTransport` and the combined string (`:101-103`). Saved discover (`:32-72`) does not call `validTransport`.
- `mcpclient.Discover` already refuses a stored `sse` row before any I/O with `"the sse transport is not implemented yet; use streamable-http"` and refuses any other value with `"unsupported transport"` without echoing it (`internal/mcpclient/discover.go:232-241`; pinned by `TestDiscoverSSETransport` at `internal/mcpclient/discover_test.go:661-671` and `internal/mcpclient/leak_test.go:212-215`).
- Proxy error shapes. `resolveTargets` failures reach the agent as HTTP `400` with `err.Error()` on the JSON-RPC body (`internal/proxy/proxy.go:228-236`), and `resolveMember` collapses them into `404 unknown endpoint` for every member URL of that group (`:501-514`, `:533-536`). Failures inside `forward` or `listTools` are audited as `truncate(err.Error(), auditFieldBytes)` and answered `502`, code `-32000`, `"upstream request failed"` (`:368-378`, `finish` at `:844-860`, `auditFieldBytes` 256 at `internal/proxy/request.go:25-28`). Credential failures use the second shape on purpose (`:544-550`, `:906-914`); `assert502Generic` in `internal/proxy/credential_test.go:46-61` rejects any client body naming the cause. `docs/07-security.md` states that every upstream failure answers the same `502`.
- `resolveTargets` skips `!Enabled` group members (`:471-472`) and returns `errNoUpstreams` when none remain (`:476-478`). `memberCatalogues` (`:638-688`) skips any member whose `listTools` fails, logs `group member skipped` (`:667`), and returns `200` with the survivors; its comment at `:641-646` is about SSE-framed responses from a Streamable HTTP server, not `models.TransportSSE`. Group `initialize` uses `ups[0]` (`:707-714`). `tools/call` on a group re-lists through that walk and only then `forward`s.
- The dashboard edit form seeds `transport` from the row (`formFromUpstream`, `web/src/lib/upstream-form.ts:85-91`) and sends `transport` on PATCH only when it differs from the stored value (`upstreamPatchBody`, `:157-164`). Create always sends it (`upstreamCreateBody`, `:135`). `openAdd` (`web/src/app/(app)/upstreams/page.tsx:245-259`) clears name, slug, url and credentials but keeps `transport`, so Add after editing an `sse` row would POST `sse`. The transport `<Select>` is at `web/src/app/upstream-form.tsx:131-136`. A controlled `<select value="sse">` whose only option is `streamable-http` renders blank or snaps to the remaining option depending on the browser; a snap would make the next save PATCH `transport: "streamable-http"`, a silent rewrite.
- The table renders raw `u.transport` (`page.tsx:421`). `AuthCell` (`:54-65`) puts a pink `Badge` beside the auth type when the row cannot work; Status uses lime Enabled / zinc Disabled (`:434`). Badge tones are at `web/src/components/badge.tsx:8-13`. Group member checkboxes carry a `Description` for disabled members (`web/src/app/group-form.tsx:63-71`).
- Store: `upstreams.transport` is `TEXT NOT NULL`, no default, no CHECK, same DDL on sqlite and Postgres (`internal/store/sqlstore.go:302-316`); `schemaVersion = 5` (`:211-214`); `CreateUpstream` and `UpdateUpstream` write `u.Transport` unvalidated (`:1485-1500`, `:1588-1589`); `scanUpstream` copies it back (`:1683-1706`). `DeleteUpstream` returns `ErrInUse` while a row is in any group's `upstream_ids` or is a key's `target_id` (`:1648-1666`), so "recreate the row" is not an available workaround.
- Startup: `reportToolPolicyProblems` (`cmd/server/main.go:74`, body `:181-211`) already walks `ListUpstreams` once and logs one JSON line per problem with `upstream_id` and `upstream_name`, never the URL or slug (`:196-203`; the "never urls" contract is at `:52-55` and `cmd/server/encryption.go:44-46`). `LOG_LEVEL` defaults to info (`:593-594`). Tests decode records with `decodeLogRecords` (`cmd/server/startup_test.go:88-106`); `seedPolicyStore` seeds `TransportStreamableHTTP` (`:146`).
- `TestPatchUpstreamURLResetsTestResult` (`internal/api/api_test.go:942-969`) PATCHes `{"transport":"sse"}` at `:948` to prove a transport change resets `last_test_*`. `TestDiscoverRejectsInvalidPayload` expects the combined string (`internal/api/discover_test.go:782-783`).
- Web tests are `node --test 'src/lib/*.test.ts'` (`web/package.json:10`); `upstream-form.test.ts` pins the create default and the PATCH omit rule (`:94-97`, `:147`, `:172`); no component renders under test (`web/src/lib/upstream-form.ts:7-8`).
- Docs that claim the upstream transport: `README.md:111`, `docs/04-architecture.md:5`, `docs/02-data-model.md:27` (enum), `docs/03-api.md:265-267` and `:315` (sse accepted on write), `:661-665` ("SSE support as fallback"), `:795-801` (upstream failures table), `docs/06-ui.md:160-163` ("until PORM-28 lands"), `openapi.yaml:642-645` (read enum), `:735-737` (write enum, "accepted on write but not implemented"), `:124` (discover 400 text). Docs about client-side GET streaming and edge buffering, which stay: `docs/09-clients.md:306`, `docs/11-deployment.md:67,90,163`, `docs/07-security.md:373-374,492-493`. `docs/05-mvp.md:8` already says Streamable HTTP is primary.
- `CHANGELOG.md:5` opens `## Unreleased`; entries are newest-first `### Title (PORM-N)` with behaviour bullets and a rollback sentence; a scope drop has used `### Breaking:` before (`:202`).
- `TestProseStyle` (`cmd/server/prose_test.go`) scans every tracked `.md`, `.yaml`, `.go`, `.ts`, `.tsx`: no em or en dash, no arrow in prose, no emoji, no banned word. This plan file is scanned too.

## Design

### Caller's usage first

Admin API, after the change:

```
POST /api/v1/upstreams {"name":"x","url":"https://example.com/mcp","transport":"sse"}
  400 {"error":"invalid transport"}
POST /api/v1/upstreams {"name":"x","url":"https://example.com/mcp","auth_type":"nope"}
  400 {"error":"invalid auth_type"}
PATCH /api/v1/upstreams/{id} {"transport":"sse"}
  400 {"error":"invalid transport"}          (also when the stored value is sse)
PATCH /api/v1/upstreams/{id} {"name":"renamed"}
  200, transport unchanged (a stored sse stays sse)
PATCH /api/v1/upstreams/{id} {"transport":"streamable-http"}
  200, the repair; last_test_* reset as for any transport change
GET  /api/v1/upstreams/{id}
  200 {"transport":"sse", ...}               (stored rows still round-trip)
POST /api/v1/upstreams/discover {"url":"...","transport":"sse"}
  400 {"error":"invalid transport"}          (was 200 ok:false)
POST /api/v1/upstreams/{id}/discover        (stored sse row)
  200 {"ok":false,"error":"the sse transport is not implemented yet; use streamable-http"}  (unchanged)
```

Agent-facing proxy, for a key or member URL whose resolved upstream is stored as `sse`:

```
HTTP 502
{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream request failed"}}
```

No request reaches the upstream. The audit row for that call has `status` error, `upstream_id` set to the row, and `error_message` `the sse transport is not implemented yet; use streamable-http`. The Logs page detail dialog already shows `error_message` (`web/src/app/(app)/logs/page.tsx:142-145`).

Group key whose enabled members include one `sse` row: `initialize`, `tools/list` and `tools/call` on the aggregate URL answer that same `502` with that audit row, until the operator disables the row or PATCHes it to `streamable-http`. Member URLs of the other members keep working.

Startup, one line per stored `sse` row:

```
{"level":"WARN","msg":"upstream transport is not implemented; requests through it fail until it is changed to streamable-http","upstream_id":"...","upstream_name":"...","transport":"sse"}
```

Dashboard: the Add dialog's Transport select has one option, Streamable HTTP. Editing a stored `sse` row shows a select with `SSE (unsupported)` selected and Streamable HTTP as the other option, plus a description line; saving without touching it omits `transport`; picking Streamable HTTP sends `{"transport":"streamable-http"}`. The Upstreams table shows `sse` in the Transport cell with a pink `Unsupported` badge beside it. The group dialog's member checkbox for that row carries a description line.

### Data shapes

No schema change, no migration, `schemaVersion` stays 5. `models.TransportSSE` stays (`internal/models/models.go:10`). `validTransport` becomes `v == models.TransportStreamableHTTP`.

New in `internal/mcpclient` (owner of the sentences today):

```go
// ErrSSENotImplemented is returned for a stored transport of "sse".
var ErrSSENotImplemented = errors.New("the sse transport is not implemented yet; use streamable-http")

// ErrUnsupportedTransport is returned for any stored transport that is
// neither streamable-http nor empty. The value is not repeated.
var ErrUnsupportedTransport = errors.New("unsupported transport")

// TransportError reports whether a stored transport can be dialled.
// It is nil for TransportStreamableHTTP and for "" (Discover treats an
// empty value as streamable-http today).
func TransportError(transport string) error
```

Dashboard: `web/src/lib/upstream-transport.ts` exporting `TRANSPORT_LABELS: Record<string,string>` (`{'streamable-http': 'Streamable HTTP'}`) and `transportUnsupported(t: string): boolean` (true unless `t === 'streamable-http' || t === ''`), mirroring `web/src/lib/upstream-auth.ts`.

### Module map

- `internal/api/upstreams.go` (change): `validTransport`; split create `400`s.
- `internal/api/discover.go` (change): split unsaved-discover `400`s.
- `internal/mcpclient/discover.go` (change): extract `TransportError` and the two sentinels; `Discover` calls it.
- `internal/proxy/proxy.go` (change): transport gate in `serve` after resolve, and beside `credential()` in `forward` and `listTools`; `memberCatalogues` returns rather than skips the transport sentinels.
- `cmd/server/main.go` (change): WARN per `sse` row inside the existing `ListUpstreams` loop of `reportToolPolicyProblems`.
- `web/src/lib/upstream-transport.ts` (new) and `web/src/lib/upstream-transport.test.ts` (new).
- `web/src/app/upstream-form.tsx`, `web/src/lib/upstream-form.ts`, `web/src/app/(app)/upstreams/page.tsx`, `web/src/app/group-form.tsx` (change).
- `web/out/**` (regenerated by `make web`, committed).
- `README.md`, `docs/02-data-model.md`, `docs/03-api.md`, `docs/04-architecture.md`, `docs/05-mvp.md`, `docs/06-ui.md`, `docs/09-clients.md`, `openapi.yaml`, `CHANGELOG.md` (change).
- Tests: `internal/api/api_test.go`, `internal/api/discover_test.go`, `internal/mcpclient/discover_test.go` (unchanged, must still pass), `internal/proxy/transport_test.go` (new), `internal/proxy/fixture_test.go` (change), `cmd/server/startup_test.go` (change), `web/src/lib/upstream-form.test.ts` (change).

### Interfaces

- Write gate: `validTransport(v string) bool` in `internal/api/upstreams.go`, unchanged signature, one caller each in create, patch and unsaved discover.
- Dial gate: `mcpclient.TransportError(transport string) error`, called from `Discover`, from `proxy.serve` over the resolved targets, and from `forward` and `listTools` before `credential()`.
- Proxy error mapping: a `TransportError` result is handled on the existing `502` arm (`finish` with `err.Error()`, then `writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed")`). It never returns from `resolveTargets`.
- Startup: no new function signature; the WARN is a branch inside the loop at `cmd/server/main.go:196-211`.
- Dashboard: `transportUnsupported(u.transport)` drives the table badge, the edit-form option and the group-form description.

### Rejected alternative

Treat a stored `sse` row like a disabled one inside `resolveTargets`. That is the smallest edit, and it is wrong three ways: the agent would receive HTTP `400` with the sentinel text on the JSON-RPC body (`proxy.go:228-236`), which breaks the flat-failure contract in `docs/07-security.md`; `resolveMember` would turn the failure into `404 unknown endpoint` for every member URL of that group (`:511-512`), taking healthy Streamable HTTP members offline; and a group whose enabled members are all `sse` would report `"group has no enabled upstreams"`, which is false and is the silent-empty-list failure the issue forbids.

Also rejected: implementing the legacy HTTP+SSE client now (PORM-5), and leaving the option in place with a tooltip (the API would still accept the value and the docs would still be wrong).

## Reuse

- `internal/mcpclient/discover.go:232-241`: the two refusal sentences and the no-echo rule for unknown values. Step 2 extracts them; the proxy audit text cannot drift from discover's.
- `internal/proxy/proxy.go` `credential()` at the top of `forward` and `listTools`, and the `502` arm at `:368-378`: the "cannot use this upstream, nothing dialled" shape. Step 3 adds the transport check beside it.
- `internal/proxy/credential_test.go` `assert502Generic`, `setStoredAuth`, `TestUndecryptableCredentialFailsClosed`, `TestAggregateSkipsUndecryptableMember`; `internal/proxy/fixture_test.go` `newFixture`, `upstreamSpec`, `waitAudit` (`:428-437`), `totalReqs` (`:408`): step 3 tests.
- `internal/api/helpers.go:14-28` `writeError` / `errorBody`: every `400` body.
- `internal/api/api_test.go` `testAPI`, `doJSON`, `newUpstream`, `upstreamBody`, `mustUpstream`, and the exact-body assertion in `TestPatchRejectsBlankRequiredFields` (`:2362-2368`). `patchUpstreamJSON` fatals on non-200 (`:844-848`) and is not for the rejection test.
- `internal/store` `CreateUpstream` (`sqlstore.go:1485`): the only way tests seed a stored `sse` row once the API refuses it; `startup_test.go:26-27` and `proxy_test.go:46-51` already seed this way.
- `cmd/server/main.go:196-211` loop plus `decodeLogRecords` and `seedPolicyStore` in `startup_test.go`: step 4.
- `web/src/lib/upstream-auth.ts` and `AuthCell` (`upstreams/page.tsx:54-65`) with pink `Badge`: pattern for `upstream-transport.ts` and the Transport cell.
- `web/src/lib/upstream-form.ts` `formFromUpstream` and `upstreamPatchBody`: keep seeding the stored value and omitting unchanged keys; that is what lets an `sse` row be edited without a PATCH exemption.
- `web/src/app/group-form.tsx:70-71` `Description` on disabled members: same slot for unsupported members.
- `web/src/lib/edit-error.ts:41` `editErrorMessage`: shows a `400` `"invalid transport"` verbatim in the dialog; no change.
- `CHANGELOG.md` Unreleased `###` pattern with a rollback sentence.

## Security requirements

1. The agent-facing JSON-RPC body for an unsupported transport is the generic `"upstream request failed"` `502`; it never contains the transport value, the upstream id, name or URL. Satisfied by step 3; pinned with `assert502Generic`.
2. The transport check never runs inside `resolveTargets`, so no new `400` text and no `404` on healthy member URLs. Satisfied by step 3.
3. The audit `error_message` and the startup WARN are fixed sentences plus `upstream_id`, `upstream_name` and the closed-enum `transport` value; the URL (which may carry a query-string token, `docs/07-security.md`) is never logged. Satisfied by steps 2, 3 and 4.
4. `validTransport` stays exact match: no `EqualFold`, no trim. `400` bodies never repeat the submitted value (the `errURLRule` contract, `internal/api/upstreams.go:36-37`). Satisfied by step 1.
5. The saved discover route (`POST /upstreams/{id}/discover`) does not gain a `validTransport` call; it keeps returning `200 ok:false` through `mcpclient.Discover`. Satisfied by steps 1 and 2 (test in step 1).
6. Admin routes stay behind `requireAdmin` (`internal/api/api.go:98-131`); no new route, no new env var, no new dependency. Satisfied by every step touching none of those.
7. An unknown stored transport (hand-edited column) is refused with `"unsupported transport"` and is never interpolated into the audit row. Satisfied by step 2's `ErrUnsupportedTransport`.

## Changes

### 1. API write gate and split `400`s

Files: `internal/api/upstreams.go`, `internal/api/discover.go`, `internal/api/api_test.go`, `internal/api/discover_test.go`.

- `upstreams.go:458-459`: `func validTransport(v string) bool { return v == models.TransportStreamableHTTP }`. Doc comment: only `streamable-http` is accepted on write; `models.TransportSSE` remains a stored value until PORM-5 implements it.
- `upstreams.go:155-157`: replace the combined check with two, in this order: `if !validTransport(u.Transport) { writeError(w, 400, "invalid transport"); return }` then `if !validAuthType(...) { writeError(w, 400, "invalid auth_type"); return }` (use whatever the auth predicate at that site is called). Same strings as PATCH at `:346` and `:352-353`.
- `discover.go:101-103`: the same split for `discoverUnsaved`. Do not touch `discoverUpstream` (`:32-72`).
- `api_test.go`, new `TestRejectsSSETransport`: (a) POST `upstreamBody` with `"transport":"sse"` is `400` and body is exactly `{"error":"invalid transport"}`; (b) create a default row with `mustUpstream`, PATCH `{"transport":"sse"}` is `400` with the same body; (c) seed a row with `Transport: models.TransportSSE` through the store handle `testAPI` exposes, GET returns `"transport":"sse"`; (d) PATCH `{"name":"renamed"}` on that row is `200` and GET still returns `sse`; (e) PATCH `{"transport":"streamable-http"}` on that row is `200` and GET returns `streamable-http`; (f) POST `/api/v1/upstreams/{id}/discover` on a seeded `sse` row is `200` with `ok:false` and the mcpclient sentence (no HTTP server needed; Discover refuses before I/O). Use `doJSON` and the exact-body pattern from `TestPatchRejectsBlankRequiredFields`.
- `api_test.go:942-969` `TestPatchUpstreamURLResetsTestResult`, `"transport"` case: seed the row as `sse` through the store with `last_test_*` set, then PATCH `{"transport":"streamable-http"}` and keep the reset assertions. The other cases are unchanged.
- `api_test.go`, a create case: POST with `"auth_type":"nope"` and a valid transport is `400 {"error":"invalid auth_type"}` (pins the split).
- `discover_test.go:782-783`: expect `"invalid transport"` and `"invalid auth_type"` on their respective rows; add a row with `"transport":"sse"` expecting `400 {"error":"invalid transport"}`.
- **Verify**: `go test ./internal/api/ -count=1 -run 'TestRejectsSSETransport|TestPatchUpstreamURLResetsTestResult|TestDiscoverRejectsInvalidPayload|TestCreate'` passes, then `go test ./internal/api/ -count=1`.

### 2. Shared transport predicate in `mcpclient`

Files: `internal/mcpclient/discover.go`.

- Add `ErrSSENotImplemented`, `ErrUnsupportedTransport` and `TransportError` as in Data shapes, next to `errNeedsCredential` (`discover.go:190`).
- `discover.go:232-241`: replace the switch with `if err := TransportError(up.Transport); err != nil { return out.fail(err.Error()) }` (or the equivalent local failure constructor). Strings are byte-identical to today's, so `TestDiscoverSSETransport` (`discover_test.go:661-671`) and `leak_test.go:212-215` pass unchanged.
- **Verify**: `go test ./internal/mcpclient/ -count=1` passes with no test edits.

### 3. Proxy: refuse before dialling, audit names the transport, client stays generic

Files: `internal/proxy/proxy.go`, `internal/proxy/fixture_test.go`, new `internal/proxy/transport_test.go`.

- `proxy.go` `serve`, immediately after `resolveTargets` / `resolveMember` have succeeded and before the tool-policy gate (the block ending at `:238`, next statement at `:240`): for a member request check that one row; for a single or group request iterate the resolved targets (already enabled-only). On the first `mcpclient.TransportError(up.Transport) != nil`: set the audit `upstream_id` to that row (the `usedID` variable at `:346` or its equivalent for this point), call `finish` with `err.Error()`, and answer with the existing `502` arm: `writeRPCError(w, http.StatusBadGateway, req.ID, -32000, "upstream request failed")`. Do not add anything to `resolveTargets` (`:452-478`) or `resolveMember` (`:501-514`).
- `forward` (`:564`) and `listTools` (`:614`): first statement `if err := mcpclient.TransportError(up.Transport); err != nil { return ..., err }`, before `credential()`. This is the defence for future callers; `serve` is the primary gate.
- `memberCatalogues` (`:675-678`): if `errors.Is(err, mcpclient.ErrSSENotImplemented) || errors.Is(err, mcpclient.ErrUnsupportedTransport)`, return the error instead of `skip()`. With the `serve` gate in place this branch is unreachable for stored rows; it exists so a missed gate fails loud rather than dropping the member.
- Doc comment on the `serve` gate, in the style of `:544-550`: why the client body stays generic (operator configuration is not the key holder's to learn, and `docs/07-security.md` promises one `502` shape) and why the check is not in `resolveTargets` (member `404`, group `errNoUpstreams`).
- `fixture_test.go` `upstreamSpec` (`:231-237`): add `Transport string`; `newFixture` writes it when non-empty, else `models.TransportStreamableHTTP`.
- `transport_test.go`:
  - `TestProxyRefusesSSETransport`: single-upstream key on an `sse` row; `tools/list` answers `502`; `assert502Generic`; `waitAudit` row has `error_message` equal to `mcpclient.ErrSSENotImplemented.Error()` and `upstream_id` equal to the row; `totalReqs() == 0`.
  - `TestProxyMemberEndpointRefusesSSETransport`: group with one `sse` member and one Streamable HTTP member; the `sse` member URL answers the same generic `502` with the named audit row (not `404`); the Streamable HTTP member URL still answers `200`.
  - `TestProxyGroupFailsWhenEnabledMemberIsSSE`: the same group's aggregate URL: `initialize`, `tools/list` and `tools/call` answer `502`, audit names the `sse` row, `totalReqs() == 0`.
  - `TestProxyGroupServesWhenSSEMemberDisabled`: same group with the `sse` row `Enabled: false`; aggregate `tools/list` is `200` and lists the Streamable HTTP member's tools (the operator's escape hatch).
  - `TestProxyRefusesUnknownTransport`: single key on a row seeded with `Transport: "websocket"`; `502`; audit `error_message` is exactly `unsupported transport` (the value is not echoed).
- **Verify**: `go test ./internal/proxy/ -count=1 -run 'TestProxy.*Transport|TestProxyGroup.*SSE|TestUndecryptable|TestAggregateSkips'` passes, then `go test ./internal/proxy/ -count=1`.

### 4. Startup WARN inside the existing upstream walk

Files: `cmd/server/main.go`, `cmd/server/startup_test.go`.

- `main.go:196-211`, inside the per-upstream loop of `reportToolPolicyProblems`: `if err := mcpclient.TransportError(u.Transport); err != nil { log.Warn("upstream transport is not implemented; requests through it fail until it is changed to streamable-http", "upstream_id", u.ID, "upstream_name", u.Name, "transport", u.Transport) }`. Disabled rows are included (the brief does not exempt them). Level WARN, never abort. `transport` is a closed enum so logging it does not breach the never-slugs, never-urls rule at `:198-203`; add one sentence to that comment saying so. If the function's comment enumerates its findings, add this one.
- `startup_test.go`: new `TestReportsUnsupportedTransportAtStartup`: seed one `sse` row and one `streamable-http` row through `store.CreateUpstream`; run the report; `decodeLogRecords` shows exactly one record with `level` WARN, `upstream_id` of the `sse` row, `transport` `sse`, and no `url` attribute. Do not change `seedPolicyStore`'s default transport; `TestReportToolPolicyProblems` counts records exactly.
- **Verify**: `go test ./cmd/server/ -count=1 -run 'TestReport'` passes, then `go test ./cmd/server/ -count=1` (includes `TestProseStyle` over every file edited so far).

### 5. Dashboard

Files: `web/src/lib/upstream-transport.ts` (new), `web/src/lib/upstream-transport.test.ts` (new), `web/src/app/upstream-form.tsx`, `web/src/lib/upstream-form.ts`, `web/src/app/(app)/upstreams/page.tsx`, `web/src/app/group-form.tsx`, `web/src/lib/upstream-form.test.ts`, `web/out/**`.

- `upstream-transport.ts`: `TRANSPORT_LABELS` and `transportUnsupported` as in Data shapes. `upstream-transport.test.ts` (`node --test`): `streamable-http` and `''` are supported; `sse` and `websocket` are not.
- `upstream-form.tsx:131-136`: render options from `TRANSPORT_LABELS`; when `form.transport` is unsupported, also render `<option value={form.transport}>{form.transport} (unsupported)</option>` so the controlled select shows the stored value and cannot snap. Below the select, when unsupported: `<Description>Not implemented. Requests through this upstream fail until the transport is Streamable HTTP.</Description>`. In Add mode `form.transport` is always `streamable-http` after the `openAdd` change, so the Add dialog shows one option.
- `page.tsx:245-259` `openAdd`: set `transport: 'streamable-http'` along with the fields it already clears. Update the comment at `:249-251`: transport is no longer carried over because only one write value exists.
- `page.tsx:421`: Transport cell becomes `<span className="inline-flex items-center gap-2">{u.transport}{transportUnsupported(u.transport) ? <Badge color="pink">Unsupported</Badge> : null}</span>`, the `AuthCell` layout. Status column unchanged.
- `group-form.tsx:70-71`: beside the disabled `Description`, when `transportUnsupported(u.transport)`: `<Description>Transport not implemented. A virtual key on this group fails until this upstream is changed to Streamable HTTP or disabled.</Description>`.
- `upstream-form.ts`: no logic change. `blankUpstreamForm` (`:65`) already defaults to `streamable-http`.
- `upstream-form.test.ts`: add (a) `formFromUpstream` of an `sse` row keeps `transport: 'sse'`; (b) `upstreamPatchBody` with only `name` changed on that form omits `transport`; (c) `upstreamPatchBody` after setting `transport: 'streamable-http'` emits `{ transport: 'streamable-http' }`.
- Rebuild the embedded export with the Node major in `web/.nvmrc` (22): `cd web && nvm use && npm ci --no-audit --no-fund && cd .. && make web`; commit `web/out`.
- UI copy follows `docs/12-writing.md` (label, consequence, stop; no dashes).
- **Verify**: `make web-test && make web-typecheck && make web-lint` pass; `make web` completes and `git status --short web/out | head` shows the regenerated export; then `make build` and, with `.env` present, `make dev` and open `http://localhost:8080/upstreams`: the Add upstream dialog's transport select lists one option.

### 6. Docs, OpenAPI, README, changelog

Files: `README.md`, `docs/02-data-model.md`, `docs/03-api.md`, `docs/04-architecture.md`, `docs/05-mvp.md`, `docs/06-ui.md`, `docs/09-clients.md`, `openapi.yaml`, `CHANGELOG.md`.

- `README.md:111`: replace the feature line with `Streamable HTTP to upstreams. Legacy HTTP+SSE is not implemented (PORM-5).`
- `docs/04-architecture.md:5`: drop `+ SSE` from the proxy bullet.
- `docs/02-data-model.md:27`: `transport` accepts `streamable-http` on write; `sse` may still be present on rows saved before PORM-28 and is refused by the proxy and by discovery. `:34` and `:41` (reset and refusal wording) checked against the new behaviour.
- `docs/03-api.md`: `:32` add `sse` to the refused write values; Partial updates (`:16-19`) add one sentence: a stored `sse` row is edited by omitting `transport` or by sending `streamable-http`; a body that echoes `sse` is `400`. `:265-267` rewrite: unsaved discover with `sse` is `400 invalid transport`; saved discover of a stored `sse` row is `200 ok:false` with the fixed sentence. `:315` keep for saved discover. `:661-665` rewrite so SSE is not called a fallback transport PoryMCP speaks to upstreams; keep the client-facing GET buffering fact. `:795-801` Upstream failures table: add a row `stored transport is sse or unknown: 502, audit error_message names it, no request is made`. Where the group section (`:828-833`) describes undecryptable members being skipped, add that an enabled `sse` member fails the aggregate until it is disabled or repaired.
- `docs/05-mvp.md`: add a known-gap line: legacy HTTP+SSE upstream transport is not implemented (PORM-5); `sse` is refused on write since PORM-28.
- `docs/06-ui.md:160-163`: a stored `sse` row shows `sse` with an Unsupported badge in the Transport cell; Tools still records Failed; Edit offers Streamable HTTP as the repair. Remove "until PORM-28 lands".
- `docs/09-clients.md:307` (the `502` paragraph after `:306`): one sentence that a stored `sse` upstream now writes a log row naming the transport. Leave `:306`.
- `openapi.yaml:642-645` `Upstream.transport`: keep enum `[streamable-http, sse]`; description: `sse` may appear on rows saved before PORM-28 and is not implemented. `:735-737` `UpstreamWrite.transport`: enum `[streamable-http]`; drop "accepted on write but not implemented (PORM-28)". `:124` discover `400` description: `invalid transport` or `invalid auth_type`. Confirm `:697-699` still says omitted, empty and `null` default on create.
- `CHANGELOG.md` under `## Unreleased`, newest-first: `### Breaking: the sse upstream transport is refused on write (PORM-28)`. Bullets: the README advertised SSE pass-through and it was never implemented; `POST` and `PATCH /api/v1/upstreams` and `POST /api/v1/upstreams/discover` answer `400 invalid transport` for `sse`; the create `400` is split into `invalid transport` and `invalid auth_type`; rows already stored as `sse` are kept, listed with an Unsupported badge, and logged once at startup; a request routed to such a row is not dialled and its audit row names the transport; a group with an enabled `sse` member fails until the row is disabled or changed to `streamable-http`; edit by omitting `transport` or sending `streamable-http`, no recreate needed. Rollback: run the previous image tag; no schema or data step.
- **Verify**: `grep -n 'SSE' README.md` shows no pass-through claim; `rg -n '"sse"|sse' docs/02-data-model.md docs/03-api.md openapi.yaml` shows only the stored-row and refusal wording; `go test ./cmd/server/ -count=1 -run TestProseStyle` passes.

### 7. Full gate and commits

- **Verify**: `make vet && make test && make vuln && make web && make web-typecheck && make web-lint && make web-test && make web-audit && docker build .` (the CI list in `CONTRIBUTING.md:9-20`). Do not run `go test ./...` after `npm ci` (`CONTRIBUTING.md:24`).
- One commit per step above, subject naming PORM-28, body with the step's `Verify:` command (`CONTRIBUTING.md:37`).

## Verification

- Automated: the step 7 command line.
- API, with the server running from `.env` (`cp .env.example .env` and set `ADMIN_API_KEY` and `ENCRYPTION_KEY`; `docker-compose.yml:8-17` refuses to start without them): `curl -i -X POST -H "Authorization: Bearer $ADMIN_API_KEY" -H 'Content-Type: application/json' -d '{"name":"x","url":"https://example.com/mcp","transport":"sse"}' http://localhost:8080/api/v1/upstreams` answers `400` with `{"error":"invalid transport"}`.
- Dashboard: `http://localhost:8080/upstreams`, Add upstream: the Transport select has one option, Streamable HTTP.
- Proxy: with a row seeded as `sse` (through a test or a direct sqlite `UPDATE upstreams SET transport='sse' WHERE id=...` on a scratch database), a `tools/list` through its key answers `502 upstream request failed`; `GET /api/v1/logs` shows the row with `error_message` `the sse transport is not implemented yet; use streamable-http`; the server's startup log has one WARN naming the row.
- Done: all six acceptance criteria in the issue hold, with the `400` body reading `invalid transport` (the issue's `invalid transport or auth_type` predates the PATCH split and is superseded by the issue's own note asking for the split).

## Tests to add

- `TestRejectsSSETransport` (`internal/api/api_test.go`): POST `sse` is `400 invalid transport`; PATCH `sse` is `400` on a Streamable HTTP row and on a stored `sse` row; stored `sse` round-trips on GET; PATCH of `name` leaves it; PATCH `streamable-http` repairs it; saved discover of a stored `sse` row is `200 ok:false`. Security requirements 4 and 5.
- Create with a bad `auth_type` is `400 invalid auth_type` (`api_test.go`). The split.
- `TestPatchUpstreamURLResetsTestResult` `"transport"` case reseeded through the store (`api_test.go:948`).
- `TestDiscoverRejectsInvalidPayload` rows for the split strings and for `sse` (`internal/api/discover_test.go:782-783`).
- `TestProxyRefusesSSETransport`, `TestProxyMemberEndpointRefusesSSETransport`, `TestProxyGroupFailsWhenEnabledMemberIsSSE`, `TestProxyGroupServesWhenSSEMemberDisabled`, `TestProxyRefusesUnknownTransport` (`internal/proxy/transport_test.go`). Security requirements 1, 2, 3, 7 and the group decision.
- `TestReportsUnsupportedTransportAtStartup` (`cmd/server/startup_test.go`). Security requirement 3.
- `web/src/lib/upstream-transport.test.ts` and three cases in `web/src/lib/upstream-form.test.ts`: stored `sse` is kept by `formFromUpstream`, omitted by `upstreamPatchBody` when unchanged, sent as `streamable-http` when changed.
- Unchanged and must still pass: `TestDiscoverSSETransport`, `leak_test.go` transport cases, `TestUndecryptableCredentialFailsClosed`, `TestAggregateSkipsUndecryptableMember`, `TestReportToolPolicyProblems`, `TestProseStyle`.

## Risks and open questions

- A group with an enabled stored `sse` member goes offline on its aggregate URL until the operator disables or repairs the row. Accepted: the issue asks for loud failure over a silent partial catalogue, the startup WARN and the table badge point at the row, and member URLs of the healthy members keep working. The panel's security analyst preferred skipping the member as undecryptable credentials are skipped; that would make an all-`sse` group a `200` with an empty catalogue, which is the failure mode the issue names. If Dan prefers skip, the change is confined to the `serve` gate in step 3 (skip on aggregate, fail on single and member routes) and the `TestProxyGroupFailsWhenEnabledMemberIsSSE` test; default is fail.
- The agent-facing body is generic, so an agent cannot tell an unsupported transport from a timeout. Accepted: `docs/07-security.md` promises one `502` shape for every upstream failure, and the audit row and Logs page carry the cause for the operator.
- API clients that GET an `sse` row and PATCH the whole object back now get `400`. Accepted and documented in `docs/03-api.md` and the changelog; the dashboard never echoes an unchanged transport.
- `make web` output is not byte-reproducible and no CI step diffs `web/out`; a stale export would ship the old dropdown in `go run` and `make build`. Mitigation: step 5 rebuilds with Node 22 and commits the export.
- Rollback: an older image opens the same store (`schemaVersion` unchanged) and accepts `sse` on write again. No data step either way.
- Open question: none that blocks building. Defaults above stand.

## Out of scope

- Implementing the legacy HTTP+SSE upstream client (PORM-5).
- Client-facing streaming on `GET /mcp` and the GET-stall buffering (PORM-5, PORM-30); the SSE sentences in `docs/09-clients.md:306`, `docs/11-deployment.md` and `docs/07-security.md` describe that and stay.
- Migrating, rewriting or deleting stored `sse` rows.
- A `/health`, `/stats` or Overview count of unsupported rows.
- A CHECK constraint or default on `upstreams.transport`.

## Panel record

Panel model: `cursor-grok-4.6-high` (the ask named Grok 4.6 without an effort level; high was chosen and is recorded here). Orchestrator on the session model.

| member | model | wave | findings | accepted | rejected (reason) |
|---|---|---|---|---|---|
| architect | cursor-grok-4.6-high | 1 | draft v0 + 6 (5 warning, 1 nit) | design, steps, tests, PATCH decision, group fail-loud, `TransportError` extraction | client body carries Discover's sentence (security, ops, ux and reuse: `docs/07-security.md` flat `502`, `assert502Generic`); separate startup function (ops, reuse, data: extend the existing walk) |
| reuse-scout | cursor-grok-4.6-high | 1 | 8 (3 critical, 4 warning, 1 nit) | all | none |
| security-analyst | cursor-grok-4.6-high | 1 | 6 (1 critical, 4 warning, 1 nit) | 1, 2, 4, 5, 6 in full; 3 in part (generic envelope) | 3 skip-on-aggregate (issue prefers loud failure; skip makes an all-`sse` group an empty `200`; recorded as a risk with a default) |
| data-analyst | cursor-grok-4.6-high | 1 | 7 (6 warning, 1 nit) | 1, 2, 4, 5, 6, 7; 3's `ErrInUse` fact and "no recreate" wording | 3 option (a) allow `sse` when it equals the stored value (AC requires PATCH `sse` to be `400`; the dashboard never echoes it; allowing it lets round-tripping clients keep writing `sse`) |
| ux-api-designer | cursor-grok-4.6-high | 1 | 12 (2 critical, 9 warning, 1 nit) | all | none |
| ops-analyst | cursor-grok-4.6-high | 1 | 8 (2 critical, 6 warning) | all; 2's fail-the-group caveat honoured by gating after resolve, not in `resolveTargets` | none |

Situational members included: data-analyst (stored rows, PATCH round-trip), ux-api-designer (dialog, table, OpenAPI, error contract), ops-analyst (startup log, changelog, release, CI). perf-analyst skipped: the new check is a string comparison on a struct already in memory.
