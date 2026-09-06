# Build record: PORM-28, stop accepting the sse transport until it is implemented

Plan: `docs/plans/2026-09-06-porm-28-reject-sse-transport.md`. Branch `dsc/porm-28-stop-accepting-sse-transport-dd04` from base `ee56c29888392b4c3863f384a306dfbb083c8b2e`, head `c2138a7` after the review fix (`09e61be8024f6b9bdcebf3475fb69f5b38fc3cce` before it). Linear PORM-28; Dan merges.

## Questions resolved

| question | answer | source |
|---|---|---|
| Stored `sse` rows whose URL already speaks Streamable HTTP will answer `502` after this ships until PATCHed; confirm that cut, mixed groups included | ship the gate as planned | default |
| A group with an enabled `sse` member fails on its aggregate endpoint (fingerprint recorded, not mitigated); skip-on-aggregate instead? | fail loudly on the aggregate | default |
| Linear acceptance checkboxes still read `invalid transport or auth_type` and `go test ./...` | build to the plan's strings (`invalid transport`, `make test`); checkboxes want editing in Linear | default |
| Panel model for the review | `cursor-grok-4.6-high`, the model the ask named and the plan's panel used | user (the ask: "grok 4.6 sub agents") |

## Audit

`git status --porcelain` was empty at `ee56c29`. Every path in **Changes** and **Findings from exploration** exists in the tree: `internal/api/upstreams.go` (`validTransport` at `:458`, combined `400` at `:155`), `internal/api/discover.go` (`:101`), `internal/mcpclient/discover.go` (switch at `:232`, `errNeedsCredential` at `:190`), `internal/proxy/proxy.go` (resolve block ends `:238`, `forward` `:565`, `listTools` `:615`), `internal/api/virtual_keys.go` (`endpointsFor` `:98`), `cmd/server/main.go` (loop `:196`), the six `web/src` files, the nine doc files, `openapi.yaml` (`:124`, `:642`, `:735`). No path moved and no signature differed from the plan; no deviation from the audit. Toolchain: the VM's `PATH` had `/exec-daemon/node` (22.14) ahead of nvm's 22.22 and `/usr/bin/go` 1.22.2 ahead of the 1.26.7 toolchain; both were put first on `PATH` for the gates (see Verification), no file changed for it.

## Steps

| # | step | commit | verify | result |
|---|---|---|---|---|
| 1 | API write gate and split `400`s | `524c83f` | `go test ./internal/api/ -count=1 -run 'TestRejectsSSETransport\|TestPatchTransportResetsTestResult\|TestPatchUpstreamURLResetsTestResult\|TestDiscoverRejectsInvalidPayload\|TestCreate'` then `go test ./internal/api/ -count=1` | pass (ok 1.0s; ok 8.3s) |
| 2 | Shared transport predicate in `mcpclient` | `bc00f2b` | `go test ./internal/mcpclient/ -count=1` | pass (ok 0.4s, no test edits) |
| 3 | Proxy: refuse before dispatch, audit names the transport, client stays generic | `b8e53e9` | `go test ./internal/proxy/ -count=1 -run 'TestProxy.*Transport\|TestProxyGroup\|TestUndecryptable\|TestAggregateSkips'` then `go test ./internal/proxy/ -count=1 && go vet ./internal/api/` | pass (ok 1.1s; ok 22.0s; vet clean) |
| 4 | Startup WARN inside the existing upstream walk | `f0a5ab6` | `go test ./cmd/server/ -count=1 -run 'TestReport'` then `go test ./cmd/server/ -count=1` | pass (ok 0.4s; ok 3.5s, `TestProseStyle` included) |
| 5 | Dashboard | `8b823bc` | `cd web && nvm use && npm ci --no-audit --no-fund && cd .. && make web && make web-typecheck && make web-lint && make web-test`; `git status --short web/out \| head` | pass (build ok; tsc clean; eslint 0 errors, 1 pre-existing warning in `eslint.config.mjs`; 126 node tests pass; 56 files in the commit, `web/out` regenerated under Node 22.22.2) |
| 6 | Docs, OpenAPI, README, changelog | `09e61be` | `grep -n 'SSE' README.md`; `rg -n 'sse' docs/02-data-model.md docs/03-api.md openapi.yaml CHANGELOG.md`; `go test ./cmd/server/ -count=1 -run TestProseStyle` | pass (README: one line, `Legacy HTTP+SSE is not implemented (PORM-5)`; every `sse` hit is stored-row or refusal wording; prose ok) |
| 7 | Full gate and commits | none (gate only; steps 1 to 6 are the commits) | the `CONTRIBUTING.md:9-20` block in order | pass: `make vet` ok; `make test` ok (12 packages); `make vuln` `No vulnerabilities found` (0 affecting, 3 in required modules not called, matching CI run 34000422653); `npm ci` 396 packages; `make web` ok; `make web-typecheck` ok; `make web-lint` 0 errors; `make web-test` 126 pass; `make web-audit` `found 0 vulnerabilities`; `docker build .` exit 0 (BuildKit, image `sha256:f5ed7c02...`). The second `make web` rewrote `web/out` hashes; that churn was discarded (`git checkout -- web/out`), the step 5 export stands |

## Tests

| case | covers | file | commit |
|---|---|---|---|
| `TestRejectsSSETransport` (a) to (g) | security requirements 4 and 5 | `internal/api/api_test.go` | `524c83f` |
| `TestPatchTransportResetsTestResult` | replaces the `"transport"` case of `TestPatchUpstreamURLResetsTestResult`; reset on repair | `internal/api/api_test.go` | `524c83f` |
| `TestCreateUpstreamRejectsUnknownAuthType` | the split create `400` | `internal/api/api_test.go` | `524c83f` |
| `TestDiscoverRejectsInvalidPayload` rows `unknown transport`, `sse transport`, `unknown auth_type` | the split strings and `sse` on the unsaved route | `internal/api/discover_test.go` | `524c83f` |
| `TestProxyRefusesSSETransport` | security requirements 1 and 3 | `internal/proxy/transport_test.go` | `b8e53e9` |
| `TestProxyMemberEndpointRefusesSSETransport` | security requirement 2 | `internal/proxy/transport_test.go` | `b8e53e9` |
| `TestProxyGroupFailsWhenEnabledMemberIsSSE` | the group decision (fail loudly, `initialize` included) | `internal/proxy/transport_test.go` | `b8e53e9` |
| `TestProxyGroupServesWhenSSEMemberDisabled` | the operator's escape hatch | `internal/proxy/transport_test.go` | `b8e53e9` |
| `TestProxyRefusesUnknownTransport` | security requirement 7 | `internal/proxy/transport_test.go` | `b8e53e9` |
| `TestReportsUnsupportedTransportAtStartup` | security requirements 3 and 7 | `cmd/server/startup_test.go` | `f0a5ab6` |
| `upstream-transport.test.ts` (2 cases) | the predicate behind badge, select and group line | `web/src/lib/upstream-transport.test.ts` | `8b823bc` |
| `upstream-form.test.ts` (4 cases: stored `sse` kept, omitted when unchanged, `streamable-http` when repaired, `TRANSPORT_LABELS` one key) | edit without a PATCH exemption | `web/src/lib/upstream-form.test.ts` | `8b823bc` |
| Unchanged and still passing: `TestDiscoverSSETransport`, `leak_test.go`, `mcpclient` fixtures, `TestUndecryptableCredentialFailsClosed`, `TestAggregateSkipsUndecryptableMember`, `TestReportToolPolicyProblems`, `TestProseStyle` | regression | as named | `make test` in step 7 |

## Verification

| check | command or action | result |
|---|---|---|
| Automated | the step 7 block | pass (see Steps, row 7) |
| API against Compose | `[ -f .env ] \|\| cp .env.example .env`; the two `grep -q ... >> .env` lines; `docker compose up --build -d`; `curl -i -X POST -H "Authorization: Bearer $ADMIN_API_KEY" -H 'Content-Type: application/json' -d '{"name":"x","url":"https://example.com/mcp","transport":"sse"}' http://localhost:8080/api/v1/upstreams` | `HTTP/1.1 400 Bad Request` `{"error":"invalid transport"}`; then `docker compose down -v`, `.env` removed |
| API against the binary | `go build -o /tmp/porymcp ./cmd/server`; `ADMIN_API_KEY`, `ENCRYPTION_KEY`, `DATA_DIR=/tmp/porm-data` exported; the same curl; plus `POST /upstreams/discover` with `sse`; plus create with `auth_type: nope`; plus `PATCH {"transport":"sse"}` on a stored `streamable-http` row | `400 {"error":"invalid transport"}`; `400 {"error":"invalid transport"}`; `{"error":"invalid auth_type"}`; `400 {"error":"invalid transport"}` |
| Dashboard, Add upstream | browser at `http://localhost:8080/upstreams`, Add upstream, Transport select | one option, `Streamable HTTP`; no SSE option |
| Dashboard, stored `sse` row | table row `Legacy renamed`; Edit dialog | Transport cell `sse` with pink `Unsupported` badge; Edit select shows `sse (unsupported)` selected with `Streamable HTTP` as the other option; helper text `Not implemented. Requests through this upstream fail until the transport is Streamable HTTP. The URL stays as it is.` |
| Proxy, stored `sse` row | server stopped; `sqlite3 /tmp/porm-data/porymcp.db "UPDATE upstreams SET transport='sse' WHERE id='1d8d159b-...'"`; restart; `tools/list` through the key's `proxy_url`; `GET /api/v1/logs?status=error`; startup log | `502` `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream request failed"}}`; log row `method tools/list, status error, upstream_id 1d8d159b-..., error_message the sse transport is not implemented yet; use streamable-http`; startup line `level WARN, msg upstream transport is not implemented; the proxy refuses every request to this upstream while it is enabled; set transport to streamable-http to restore it, upstream_id, upstream_name Legacy, enabled true, transport sse` |
| Stored `sse` row, edit by omission | `PATCH {"name":"Legacy renamed"}` on the `sse` row; `GET` | `200`; `Legacy renamed sse` |
| Done | the six acceptance criteria | hold, with `invalid transport` for the `400` body and `make test` for `go test ./...`, as the plan's Verification section states |

## Deviations

| # | step | plan said | done instead | why |
|---|---|---|---|---|
| 1 | C (Isolate) | branch named by the plan's first line, `dan/porm-28-stop-accepting-the-sse-transport-until-it-is-implemented` | `dsc/porm-28-stop-accepting-sse-transport-dd04` | the cloud agent harness requires every branch it creates to match `dsc/<name>-dd04`; the plan file lives on the planning branch `dsc/porm-28-plan-sse-transport-dd04`, so the build branch was cut from it (base `ee56c29`, which is `main` plus the plan file) |
| 2 | 1 | "a create case: `POST /upstreams` with `auth_type: nope`" (no name given) | named `TestCreateUpstreamRejectsUnknownAuthType` | the plan named no function; the name follows the file's `TestCreateUpstream...` convention |
| 3 | 1 | seed `sse` rows "with `st.CreateUpstream` using the `seedPolicyStore` field set" inline | one helper `seedStoredUpstream(t, st, slug, transport, lastTestAt, lastTestOK)` in `api_test.go`, used by both new tests | three seeds in one test plus one in another; the field set is the plan's, written once |
| 4 | 3 | `upstreamSpec` gains `Transport string`; "`newFixture` writes it when non-empty, else `models.TransportStreamableHTTP`" | as stated, implemented as an override after the existing literal | same behaviour; the existing literal already wrote the default |
| 5 | 4 | "If the function's doc comment enumerates its findings, add this one" | the doc comment read "It reports five things"; now "six", with a paragraph for the transport WARN | the comment did enumerate |
| 6 | 5 | "Verify: `cd web && nvm use && ...`" | `nvm use` selected v22.22.2 but `/exec-daemon/node` (v22.14.0) stayed ahead on `PATH`, so nvm's bin directory was exported first by hand; under 22.14 all 11 node test files fail with `ERR_UNKNOWN_FILE_EXTENSION` (no type stripping before 22.18) | the VM's `PATH`, not the tree; `.nvmrc` says `22` and CI's `setup-node` resolves that to the current 22.x |
| 7 | 7 | `make vuln` | run with the go1.26.7 toolchain's `bin` first on `PATH` and `GOTOOLCHAIN=local` | with `/usr/bin/go` 1.22.2 and `GOTOOLCHAIN=auto`, govulncheck v1.1.4 fails with `internal error: package "golang.org/x/sync/semaphore" without types`, identically on the base commit; CI installs 1.26.7 directly and passes (run 34000422653); with the same toolchain first, it passes here |
| 8 | 7 | `docker build .` | Docker 29.1.3, buildx 0.30.1 and compose v2 installed on the VM for the check (`apt-get`); the build ran under BuildKit | the VM had no Docker; the Dockerfile's `--platform=$BUILDPLATFORM` needs BuildKit, which is what CI uses |
| 9 | 7 | "`make web` ... committed with this step" (step 5) and the full gate in step 7 | the step 7 `make web` regenerated `web/out` with new hashes; that second export was discarded and the step 5 export stands | `next build` is not byte-reproducible (`CONTRIBUTING.md`); committing a second build of the same source would be churn without a source change |

## Review

| member | model | critical | warning | nit | fixed (commits) | deferred (reason) |
|---|---|---|---|---|---|---|
| security-analyst | cursor-grok-4.6-high | 0 | 0 | 0 | none needed; requirements 1 to 7 all `met` | none |
| code-reviewer | cursor-grok-4.6-high | 0 | 1 | 0 | `c2138a7`: `TestDiscoverRejectsInvalidPayload` compared the split `400` strings with `strings.Contains`, and `invalid transport` is a substring of the old combined message, so a regression of the split would have stayed green; the rows now compare the whole body. Re-check: `resolved` | none |
| skeptic | cursor-grok-4.6-high | 0 | 0 | 0 | none needed; deviations 1 to 9 and the record's claims re-run and confirmed (committed `web/out` carries the new copy and no `value="sse"` option; the `make vuln` toolchain account matches CI run 34000422653) | none |
| data-analyst | cursor-grok-4.6-high | 0 | 0 | 0 | none needed; 8 requirements `met` | none |
| ux-api-designer | cursor-grok-4.6-high | 0 | 0 | 0 | none needed; 12 requirements `met` | none |
| ops-analyst | cursor-grok-4.6-high | 0 | 0 | 0 | none needed; 16 requirements `met`; deviations 6 to 9 checked against CI | none |

Panel as `panel.md` sizes it: the three fixed members plus the three situational analysts the plan's Panel record ran (perf-analyst was not on the plan's panel and is not here). Two departures from the skill's letter: each reviewer was pointed at the plan and this record on disk and told to read both in full first, instead of having both pasted into the prompt, to keep six copies of a 330-line plan out of the orchestrator's context; and the branch was pushed with a draft PR opened before the panel closed, because the cloud agent harness requires every branch it changes to be pushed and to carry a PR ([#15](https://github.com/danjonesio/porymcp/pull/15)). One re-check round; nothing remained after it.

Head after review: `c2138a7`. `go test ./internal/api/ -count=1` re-run after the fix: ok.

## Noticed, not done

- `web/eslint.config.mjs:5` carries a pre-existing `import/no-anonymous-default-export` warning; `make web-lint` passes with it.
- `docs/03-api.md:287` still lists `invalid transport/auth_type` as one item in the saved-discover error list; the plan said leave it, and it is still true as written.
- The Linear issue's acceptance checkboxes read `invalid transport or auth_type` and `go test ./...` (plan open question 3); they want editing in Linear so the PR does not read as having missed them.
- The three "vulnerabilities in modules you require, but your code doesn't appear to call" that govulncheck lists are in dependencies and predate this branch; the same three show in CI.

## PR body

```
PORM-28: stop accepting the sse transport until it is implemented

The API accepted transport "sse" and the README advertised SSE pass-through,
but the proxy has always POSTed Streamable HTTP to every upstream, so an sse
row saved without error then failed every request with a generic 502.
streamable-http is now the only transport accepted on write (400 invalid
transport for sse on create, PATCH and unsaved discover; the create 400 is
split into invalid transport and invalid auth_type). Rows already stored as
sse are kept, not rewritten: the proxy refuses them before dialling with the
usual 502 and an audit row naming the upstream and the transport, the server
logs one WARN per such row at startup, the dashboard shows an Unsupported
badge and offers Streamable HTTP as the one-field repair, and a group with an
enabled sse member fails on its aggregate endpoint until it is disabled or
repaired. README, docs, OpenAPI and the changelog say so.

Plan: docs/plans/2026-09-06-porm-28-reject-sse-transport.md
Steps: 6 commits, one per plan step (step 7 is the gate), plus 1 review fix
Verification: make vet, make test, make vuln, npm ci, make web, make web-typecheck, make web-lint, make web-test, make web-audit, docker build . all pass; API, proxy and dashboard checks done against a running server
Needs human: none
```
