# Docker & deployment

## First run

Copy `.env.example` to `.env` and set both `ADMIN_API_KEY` and `ENCRYPTION_KEY` (`openssl rand -hex 32` for each). Compose refuses **every** subcommand without them, `down` and `logs` included, with an error naming the variable. Use the README Quick start's guarded block: it creates `.env` and each key only when they are missing, so re-running it never overwrites an existing key. Two traps: a shell variable set to empty (`export ENCRYPTION_KEY=`) overrides a good `.env`, so if compose reports a variable missing while `.env` sets it, `unset` it in that shell; and for `down` or `logs` on a machine with no keys yet, any non-empty throwaway satisfies the guards (`ADMIN_API_KEY=unused ENCRYPTION_KEY=unused docker compose logs porymcp`), but never use a throwaway with `up` against an existing data volume, and if you already have a data volume with stored credentials, go to `docs/11-deployment.md` §12 **before** generating anything. `ADMIN_API_KEY` is required the same way and refuses the same way; it is also the value you sign in to the dashboard with. Verified with Docker Compose v5.5 / Engine 29 only; older releases may lack `depends_on.required` (rejected by `docker compose config`) or `healthcheck.start_interval` (Engine-side: it surfaces at `up`, not at `config`). If either trips, upgrade.

## Build

`Dockerfile` is a three-stage build. `docker build .` (or, after the one-time `.env` step above, `docker compose up --build`) runs all of it; no local Node or Go toolchain is needed.

| Stage | Base image | What it does |
| --- | --- | --- |
| `web` | `node:22-alpine`, pinned by digest | `npm ci --no-audit --no-fund`, then `npm run build`: the Next.js static export lands in `/web/out`. Runs on the builder's own architecture. |
| `build` | `golang:1.26-alpine`, pinned by digest | Copies `cmd/`, `internal/`, `web/fs.go` and the export from the `web` stage, then `go build` with `GOOS` and `GOARCH` taken from the target platform. `web/fs.go` declares `//go:embed all:out`, so the export is compiled into the binary. |
| runtime | `gcr.io/distroless/static-debian12:nonroot`, pinned by digest | The `/porymcp` binary and `openapi.yaml`. No shell, no dashboard files on disk. |

The embed directive is a compile-time error when `web/out` is missing, so the `COPY --from=web` in the `build` stage has to come before `go build`. `.dockerignore` excludes the tracked `web/out`, so the image always embeds what the `web` stage just built, never what happens to be checked in. Both build stages carry `--platform=$BUILDPLATFORM`, so a multi-arch build (`--platform linux/amd64,linux/arm64`) runs the export once and cross-compiles the binary per target; nothing runs under emulation, and only the runtime stage resolves per platform.

All three base images are pinned by index digest (the Go image since PORM-40, the Node and runtime images since PORM-10), so rebuilds are reproducible and do not silently pick up base-image changes; bumping a digest is a deliberate edit (the build-reproducibility issue's Dependabot config is the counterweight). An index digest, which resolves per platform, comes from `docker buildx imagetools inspect <ref> --format '{{.Manifest.Digest}}'`; the digest `docker inspect` prints on one machine is that machine's platform manifest and must not be pinned. `go.mod` pins `toolchain go1.26.7`, which makes `go build`/`go test` download that exact toolchain when the local one differs. Offline or air-gapped builders can set `GOTOOLCHAIN=local` to insist on the installed Go (1.26.x or later required).

## Images and tags

The `publish` job in `.github/workflows/ci.yml` pushes to `ghcr.io/danjonesio/porymcp` after the `go`, `web` and `docker` checks pass on a push to `main`, on a `v*` tag, or on a manual run. It authenticates with the job's own `GITHUB_TOKEN` (`packages: write`); the repository holds no secret for it.

| Tag | Built from |
| --- | --- |
| `edge` | every push to `main` |
| `sha-<short sha>` | the same push, by commit |
| `vX.Y.Z` (the git tag) | a `v*` tag |
| `latest` | a `v*` tag with no `-` suffix; a release candidate such as `v0.2.0-rc1` leaves it alone |

Each tag is one index carrying `linux/amd64` and `linux/arm64`. `docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:edge` lists those two platforms and two `unknown/unknown` rows, which are the provenance attestation the build attaches, not a broken index. `edge` and `latest` move, so a production deployment pins the digest printed in the publish run's summary: `ghcr.io/danjonesio/porymcp@sha256:...`. A tag is never moved; a bad release is followed by the next patch tag. The package is public.

## Runtime

- Default: SQLite on a volume (`/data/porymcp.db`). The image ships `/data` owned by `nonroot` (uid 65532), so a fresh named volume mounted there is writable by the server. Docker only copies that ownership into a volume it creates; a volume left behind by an older image is still root-owned and the server exits with `unable to open database file (14)`. Remove it (`docker volume rm porymcp_porymcp-data`) or `chown 65532:65532` its root before starting.
- Optional Postgres for local development: see the Postgres section below. The profile flag and a `postgres://` `DATABASE_URL` are **both** required, or Postgres starts beside an app still on SQLite.
- Healthcheck: `GET /health` or `/porymcp healthcheck`. When `TLS_CERT_FILE` / `TLS_KEY_FILE` are set, the check uses `https://127.0.0.1` and skips certificate verification. A server whose stored credentials cannot be read with the current `ENCRYPTION_KEY` answers `GET /health` with `503 {"status":"degraded","encryption":"mismatch"}` for monitors, while `/porymcp healthcheck` exits `0` on that body on purpose: the container stays **healthy** so the dashboard the operator needs to fix it stays reachable, and a restart could not change an environment variable anyway. It still exits `1` on `unhealthy` (store ping failed). See `docs/11-deployment.md` §12 for what to point probes at.
- The compose service runs with `restart: unless-stopped` (crash, daemon restart, host reboot). The flip side: a *permanent* misconfiguration (a malformed `TRUSTED_PROXIES`, a `TLS_CERT_FILE` path that is not mounted, an unparseable `ENCRYPTION_KEY`) no longer exits once but restarts in a loop, with `docker compose ps` showing `Restarting`. `docker compose logs porymcp | tail` names the cause; fix `.env` and `docker compose up -d --force-recreate`.
- Subcommands: `/porymcp healthcheck` (above) and `/porymcp rekey`, which re-encrypts every stored credential under the current `ENCRYPTION_KEY` after a rotation (`docs/11-deployment.md` §12). Any other first argument prints a usage line and exits `2`, so a mistyped `rekey` never starts a second server on the live database.
- Simple `docker compose up --build` experience once `.env` holds `ADMIN_API_KEY` and `ENCRYPTION_KEY` (see First run)
- TLS / reverse proxy: `docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build` (Caddy in front; see `docs/11-deployment.md`; needs the same `.env`)

## Postgres (local development only)

```bash
DATABASE_URL=postgres://porymcp:porymcp@postgres:5432/porymcp \
  docker compose --profile postgres up -d --wait
```

Both halves are required: the `--profile postgres` flag starts the database, and the `postgres://` `DATABASE_URL` points PoryMCP at it. Either one alone leaves the app on SQLite (set `DATABASE_URL` in `.env` if you use the profile routinely). `porymcp` waits for the database via `depends_on: condition: service_healthy` with `required: false`, the flag that keeps plain `docker compose up` a valid project when the profile is off. The profile is a **separate, empty datastore**: there is no SQLite to Postgres migration, existing rows stay in the `porymcp-data` volume, and switching back restores them. A `postgres://` URL without the profile exits with a connection error and retries under `restart: unless-stopped` until the database appears. The service publishes no host port and keeps the `porymcp/porymcp` credentials, a local-development convenience and not a production topology; use `docker compose --profile postgres exec postgres psql -U porymcp -d porymcp` for host-side access. Schema creation is verified; behaviour beyond that is PORM-18.

## Environment variables

- `ADMIN_API_KEY`: management API and dashboard login. **Required under compose**: the `${ADMIN_API_KEY:?}` guard fails every compose subcommand when it is unset or empty (a bare binary or `docker run` without it generates a random key for that process and logs it at startup at WARN). It is the value you sign in to the dashboard with.
- `ENCRYPTION_KEY`: 32-byte AES key (64 hex chars, `openssl rand -hex 32`) for upstream secrets. **Required under compose**: the `${ENCRYPTION_KEY:?}` guard fails every compose subcommand when it is unset or empty (a bare binary or `docker run` without it still generates an ephemeral key). **Back it up separately from the data volume**: without it, every stored credential is unrecoverable. The first boot of a build at or after PORM-52 stamps schema version 5, which earlier builds refuse to open.
- `ENCRYPTION_KEY_PREVIOUS`: comma-separated previous keys, oldest last, 64 hex chars or base64 only, at most five, accepted for decryption only. Set it for the rotation window, run `/porymcp rekey`, then remove it and restart (`docs/11-deployment.md` §12). Empty means unset.
- `DATABASE_URL`: `sqlite:///data/porymcp.db` or `postgres://...`; overridable in compose. The Postgres profile needs it and `--profile postgres` together (see the Postgres section).
- `PUBLIC_URL`: used when minting `proxy_url` and every entry in a virtual key's `endpoints[]`, and as the expected host/scheme for proxy-endpoint checks. Default `http://localhost:8080` (no scheme enforcement by default).
- `LISTEN_ADDR`: default `:8080`
- `LOG_LEVEL`, `DATA_DIR`
- `WEB_ROOT`: serve the dashboard from a directory on disk instead of the embedded export. Not set in the image. The default is the relative path `web/out`, so the binary uses a disk copy only when that directory exists (locally after `cd web && npm run build`, or via a bind mount at `/web/out` in the container), and otherwise serves the embedded export. A development override, not a deployment setting; the startup log reports which is in use (`serving dashboard root=…`).
- `TRUSTED_PROXIES`: comma-separated CIDRs (or bare IPs) whose socket address may present `Forwarded` / `X-Forwarded-*` for client IP, host, and scheme. Empty (the default) means trust nobody; those headers are ignored and the admin-auth limiter keys on the real socket address. A malformed value refuses to start, and under compose restarts in a loop until it is fixed.
- `ALLOW_INSECURE_HTTP`: when truthy, skip scheme enforcement even if `PUBLIC_URL` is https. Default unset/false.
- `ALLOW_LOCALHOST`: when truthy, accept localhost Host values even when `PUBLIC_URL` is not localhost. Default unset/false.
- `EXTRA_ALLOWED_HOSTS`: extra Host values (comma-separated, no scheme) accepted on the proxy endpoints besides `PUBLIC_URL`. Default empty.
- `TLS_CERT_FILE`, `TLS_KEY_FILE`: built-in TLS. Both must be set, or both left empty.

Reverse-proxy and TLS deployment (Caddy, nginx, Traefik, Cloudflare, built-in certs) is in `docs/11-deployment.md`.

PoryMCP sets Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, X-Frame-Options and Permissions-Policy on every response. HSTS belongs at the TLS edge (Caddy, nginx, a PaaS router), not in this container. See `docs/07-security.md` and `docs/11-deployment.md`.
