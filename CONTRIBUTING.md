# Contributing

PoryMCP is developed on GitHub at `danjonesio/porymcp`. Every change reaches `main` through a pull request, and every pull request runs the checks below from `.github/workflows/ci.yml`. The workflow needs no repository secret: the `publish` job uses its own `GITHUB_TOKEN` with `packages: write`, and nothing else in the pipeline authenticates anywhere.

## Before you open a pull request

Run what CI runs, in the same order. The `make` targets are the ones the workflow calls, so the commands here and the commands in CI are the same strings.

```bash
make vet
make test
make vuln
cd web && npm ci --no-audit --no-fund && cd ..
make web
make web-typecheck
make web-lint
make web-test
docker build .
```

What each one needs:

- `make test` and `make vet` use the package list `./cmd/... ./internal/... ./web`. Once `npm ci` has run, `go test ./...` also reaches a Go file shipped inside `web/node_modules`, so use the targets rather than `./...`.
- `make vet` also runs `gofmt -l` over the tracked Go files and fails when any is unformatted.
- `make vuln` runs `govulncheck` at a pinned version against a vulnerability database that is fetched fresh, so it can fail on a commit that changed nothing. That is the point; the fix is a dependency bump.
- The Go toolchain that compiles is the `toolchain` line in `go.mod`, not whatever `go version` prints; the first `go` command downloads it when they differ. Offline builders can set `GOTOOLCHAIN=local` (see the README). In CI, `setup-go` installs that release directly and sets `GOTOOLCHAIN=local`, so nothing is downloaded there.
- `make web` (`next build`) rewrites about a hundred paths under `web/out`, the tracked export the Go binary embeds. Commit that churn only when the dashboard itself changed, and build it with the Node major in `web/.nvmrc` (`nvm use`). No CI step diffs `web/out`, because `next build` output is not byte-reproducible; a pull request that edits `web/src` without rebuilding the export passes CI, and `go run` and `make build` then embed the stale export until someone rebuilds it. The published image is unaffected: its own web stage rebuilds the export.
- `npm ci` reproduces the lockfile, which is what CI and the Dockerfile do. `npm install` is for changing dependencies.
- `make web-typecheck` runs after `make web` because the build writes `web/next-env.d.ts`, which is git-ignored and is what declares the CSS module imports.

## Branches and pull requests

- One branch per issue, named after it (`dan/porm-NN-...`), pushed to `origin`, with a pull request against `main`.
- The three checks `go`, `web` and `docker` must be green. `publish` runs after a merge and on tags, never on a pull request.
- Every action in the workflow is pinned to a commit SHA with the release in a comment. Bumps are made by hand until dependency automation lands (PORM-42).
- Commit messages name the issue in the subject and carry a `Verify:` line with the command that proved the change.

## Writing

Text in this repository follows `docs/12-writing.md`. The rules the test enforces (no em or en dashes, no arrows, no emoji, no words from the banned list) apply to Markdown, YAML, Go, TypeScript, the Dockerfile and the Makefile alike, and `make test` reports each violation by file and line.
