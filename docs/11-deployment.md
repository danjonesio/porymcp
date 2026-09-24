# TLS and reverse-proxy deployment

PoryMCP listens on plain HTTP at `:8080` by default. `PUBLIC_URL` defaults to
`http://localhost:8080`, so a laptop checkout does not enforce TLS. That
default is for localhost only. `PUBLIC_URL` is also the address an OAuth
vendor sends the operator's browser back to (§16), so it must be the address
the browser uses.

## 1. TLS is required off localhost

Do not publish `:8080` on a public interface over HTTP.

The dashboard admin key and every virtual key travel as `Authorization: Bearer`
tokens. Tool arguments and upstream responses travel in the same bodies. A
clear-text hop on a shared network is a credential leak.

Put TLS in front (Caddy is the recommended edge) or terminate it on the
process with `TLS_CERT_FILE` / `TLS_KEY_FILE`. Then set `PUBLIC_URL` to the
`https://` URL clients actually use.

TLS on the *outbound* side is separate and is not configured here. An upstream's
`url` is used exactly as registered: PoryMCP forwards to that URL and never to
a host the upstream names in a redirect, so an `http://` upstream URL a vendor
`301`s to `https://` fails rather than upgrading. Register the `https://` URL.

## 2. What PoryMCP reads, and when

Forwarded headers are honoured only when `TRUSTED_PROXIES` covers the
**socket** that sent the request. The default is empty: trust nobody. An
untrusted socket's `Forwarded` / `X-Forwarded-*` values are ignored.

When the socket is trusted, resolution prefers RFC 7239 `Forwarded`, then
falls back **per attribute** to the matching `X-Forwarded-*` header. Each
attribute uses the rightmost hop or token.

| What | Trusted socket | Untrusted socket |
| --- | --- | --- |
| Scheme | `Forwarded` `proto=` (rightmost hop that has it), else `X-Forwarded-Proto` (rightmost token), else the local TLS state | Local TLS state only (`https` if the connection is TLS, otherwise `http`) |
| Host | `Forwarded` `host=` (rightmost hop that has it), else `X-Forwarded-Host` (rightmost token), else the `Host` header | `Host` header only |
| Client IP | `Forwarded` `for=` (preferred), else `X-Forwarded-For`; rightmost hop that is not itself trusted | Socket address only |

`TRUSTED_PROXIES` is a comma-separated list of CIDRs or bare IPs (a bare IPv4
becomes `/32`). A malformed value refuses to start, and under compose
restarts in a loop until it is fixed.

Host comparison against `PUBLIC_URL` / `EXTRA_ALLOWED_HOSTS` runs on the
**proxy endpoints only** (`/mcp`, `/{virtual_key_id}/mcp` and
`/{virtual_key_id}/{upstream_slug}/mcp`). It is not a dashboard or `/api/v1`
rebinding guard. Forwarded host is used in that comparison only when the socket
is trusted.

The per-member endpoint needs no edge change: every reverse-proxy config below
forwards `/` wholesale, so a third proxy route is already covered.

When `PUBLIC_URL` is `https://` and `ALLOW_INSECURE_HTTP` is unset, a
non-loopback request whose resolved scheme is `http` is refused:

```
HTTP/1.1 426 Upgrade Required
{"error":"insecure scheme","scheme":"http"}
```

Loopback is exempt so `porymcp healthcheck` (`http://127.0.0.1`) still works
behind an edge or when the process itself terminates TLS.

## 3. Recommended: Caddy in front

Caddy issues certificates, sets forwarded headers, and does not buffer by
default (SSE and long `tools/call` responses stay streamed).

```
porymcp.example.com {
	reverse_proxy porymcp:8080 {
		# Drop a client-supplied Forwarded; Caddy sets X-Forwarded-*.
		header_up -Forwarded
	}
}
```

Set `PUBLIC_URL=https://porymcp.example.com` and `TRUSTED_PROXIES` to the
**Caddy container IP `/32`** (or the CIDR of the hop that actually talks to
PoryMCP). Do not set `TRUSTED_PROXIES=0.0.0.0/0` when port 8080 is also
published: a direct hitter on the bridge gateway can then spoof
`X-Forwarded-Proto` / `X-Forwarded-For` and `Forwarded`.

The compose overlay in this repository pins Caddy at `172.28.0.4` and sets
`TRUSTED_PROXIES=172.28.0.4/32`. See [§8](#8-compose-overlay).

## 4. nginx

nginx does not set forwarded headers for you, and it buffers by default.
PoryMCP sends `X-Accel-Buffering: no` on a streamed answer, which turns
buffering off for that answer unless `proxy_ignore_headers` lists it. Keep
`proxy_buffering off` for the rest. `proxy_read_timeout` runs between reads, so
set it above the longest gap an upstream leaves between keep-alives; the block
below uses an hour. Cap the inbound body at 8 MiB so it matches the proxy's own
cap.

```nginx
server {
    listen 443 ssl;
    server_name porymcp.example.com;

    ssl_certificate     /etc/ssl/certs/porymcp.crt;
    ssl_certificate_key /etc/ssl/private/porymcp.key;

    client_max_body_size 8m;

    location / {
        proxy_pass http://porymcp:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        # PoryMCP prefers RFC 7239 Forwarded when present. Clear it so a
        # client cannot smuggle proto=/host= past the X-Forwarded-* values
        # this block sets.
        proxy_set_header Forwarded "";
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

Set `PUBLIC_URL=https://porymcp.example.com` and `TRUSTED_PROXIES` to the
nginx hop's address `/32`.

`proxy_pass_request_headers` is on by default, so inbound headers are
forwarded. The proxy copies eight named client headers and every `Mcp-Param-`
header to the upstream, and returns three upstream response headers; both
lists are in `docs/07-security.md`. Those names use hyphens; they usually
survive. nginx lowercases header names and may drop unknown headers that
contain underscores unless `underscores_in_headers on` is set. If a client or
an intermediate hop sends underscore forms (`Mcp_Session_Id`), either enable
that flag or set the hyphenated names explicitly with `proxy_set_header`. The
`Mcp-Param-` headers cannot be listed one by one in `proxy_set_header` and do
not need to be, since nothing in this block removes them; an edge that
filters request headers by name has to admit `Mcp-Method`, `Mcp-Name` and
that prefix, or a client on the 2026-07-28 revision is refused by PoryMCP for
headers the edge dropped (PORM-150). nginx reaches its own header limits before
PoryMCP's bound of 32 `Mcp-Param-` values at 4096 bytes each:
`large_client_header_buffers` (four buffers of 8k by default) caps a single
header line and the header block together, and nginx answers with its own
`400` when a request exceeds it.

## 5. Traefik

Traefik sets `X-Forwarded-*` by default. Point the load balancer at 8080 and
put the container IP (or the Traefik-to-app CIDR) in `TRUSTED_PROXIES`.
Traefik's defaults carry a stream: the entry point's read timeout covers the
request, not the response (Go clears the read deadline once the body is read),
and its write timeout is off.

```yaml
services:
  porymcp:
    labels:
      - traefik.enable=true
      - traefik.http.routers.porymcp.rule=Host(`porymcp.example.com`)
      - traefik.http.routers.porymcp.tls=true
      - traefik.http.services.porymcp.loadbalancer.server.port=8080
```

Set `PUBLIC_URL=https://porymcp.example.com`. Attach a cert resolver on the
router if Traefik is issuing certificates (`traefik.http.routers.porymcp.tls.certresolver=…`).

## 6. Cloudflare

Use **Full (strict)** so the hop from Cloudflare to the origin is TLS with a
valid certificate (Caddy or another origin cert). Flexible SSL terminates at
Cloudflare and forwards HTTP to the origin. If that hop is not in
`TRUSTED_PROXIES`, PoryMCP sees `http` and returns 426. If you do trust the
hop, forwarded `proto=https` would pass scheme enforcement while bearer
tokens still travel in clear text on the origin hop. Do not use Flexible.

Cloudflare's proxy read timeout is 125 seconds until the origin's response
starts (Enterprise plans can raise it). A JSON `tools/call` longer than that is
cut at the edge whatever PoryMCP's budget. A streamed answer sends its headers
at once, so it starts well inside that limit.

Cloudflare is a trusted hop only if `TRUSTED_PROXIES` covers the address that
actually connects to PoryMCP (usually your origin edge, not every Cloudflare
anycast range).

## 7. Built-in TLS

When there is no edge, terminate TLS on the process:

```
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
PUBLIC_URL=https://porymcp.example.com
```

Both paths must be set, or both left empty. A half-set pair (or a path not
mounted into the container) refuses to start, and under compose
restarts in a loop until it is fixed.
ACME is out of scope; use Caddy for automatic certificates.

The image is distroless `nonroot`. The healthcheck is `/porymcp healthcheck`.
When the cert env vars are set, that check uses `https://127.0.0.1` and
skips certificate verification so a hostname-bound cert still passes.

HSTS is still the edge's job; built-in TLS does not emit it.

## 8. Compose overlay

The overlay adds Caddy. It does **not** unpublish `8080:8080`: Compose
merges ports additively, and a direct hit on the container port is how you
confirm scheme enforcement.

```bash
# .env must hold ADMIN_API_KEY and ENCRYPTION_KEY: every compose command needs both
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

What the overlay pins:

| Setting | Value | Why |
| --- | --- | --- |
| Default network subnet | `172.28.0.0/16` | Stable addressing so the trusted CIDR does not drift |
| IPv6 on that network | off | Caddy to app must not arrive as an untrusted v6 address |
| Caddy IPv4 | `172.28.0.4` | The only socket PoryMCP should trust |
| `TRUSTED_PROXIES` | `172.28.0.4/32` | That Caddy address, nothing else |
| `PUBLIC_URL` | `https://localhost` | Scheme enforcement on; host matches the Caddyfile |
| Caddy ports | `80:80`, `443:443` | Edge listeners |
| Caddyfile | `deploy/caddy/Caddyfile` (read-only) | `localhost { tls internal; reverse_proxy … header_up -Forwarded }` |

Caddy waits for PoryMCP to be healthy (`/porymcp healthcheck`) before it
starts.

A request through Caddy (`https://localhost/health`) should return `200`. A
direct hit on `:8080` (`http://localhost:8080/…`) is expected to return `426`
once `PUBLIC_URL` is `https://`, except loopback from inside the container.

**Network egress.** PoryMCP checks where an upstream's host resolves as it
connects (PORM-79, `docs/07-security.md`): loopback, link-local, multicast,
unspecified and cloud-metadata addresses are refused, and no setting reopens
any of them but loopback. The compose network above (`172.28.0.0/16`, or
Docker's default bridge) is a private range, which stays open by default, so
an upstream reached by service name keeps working. A server on the Docker
host is `host.docker.internal`, a private address too; on Linux add
`extra_hosts: ["host.docker.internal:host-gateway"]` and have it listen on the
bridge address. A `localhost` upstream from inside the container reaches only
the container itself and is refused; `UPSTREAM_ALLOW_LOOPBACK` is for a bare
binary on a laptop. `UPSTREAM_DENY_PRIVATE` closes the private ranges as
well, at the cost of every compose-network, cluster-IP and tailnet upstream.
Behind an egress proxy (`HTTPS_PROXY`, `HTTP_PROXY`, either case) the guard
checks the proxy's own address, so a sidecar proxy on loopback needs
`UPSTREAM_ALLOW_LOOPBACK`, and what the proxy fetches is the proxy's job to
restrict. The guard is a check inside one process; restrict egress at the
Docker or network layer as well (an internal network, an egress firewall, a
metadata-service block on the host) where the deployment allows it.

## 9. HSTS

`Strict-Transport-Security` belongs at the TLS edge (Caddy, nginx, Traefik,
a PaaS router), not in PoryMCP. The process does not emit it.

## 10. Escape hatches

| Variable | Default | When to set it |
| --- | --- | --- |
| `ALLOW_INSECURE_HTTP` | unset / false | TLS terminates somewhere PoryMCP cannot observe (some kube HTTP probes, an outer mesh that strips TLS before the pod). Non-loopback HTTP is then allowed even when `PUBLIC_URL` is https, and an http `PUBLIC_URL` off loopback is accepted as an OAuth redirect URI (§16). |
| `ALLOW_LOCALHOST` | unset / false | Accept `localhost` / `127.0.0.1` / `::1` Host values when `PUBLIC_URL` is not itself localhost. Inbound only; it does not touch upstream dials. |
| `EXTRA_ALLOWED_HOSTS` | empty | Extra Host values (comma-separated, no scheme) accepted on the proxy endpoints besides `PUBLIC_URL`. |
| `UPSTREAM_ALLOW_LOOPBACK` | unset / false | A bare binary whose upstreams listen on `localhost`. Inside a container loopback is the container itself, so use `host.docker.internal` instead. Reopens loopback only. |
| `UPSTREAM_DENY_PRIVATE` | unset / false | Every upstream is a public host and RFC 1918, ULA and CGNAT addresses should be refused too. Breaks compose-network, cluster-IP and tailnet upstreams. |

Kubernetes-style HTTP probes from a **non-loopback** in-cluster IP will 426
when `PUBLIC_URL` is https, unless the probe uses HTTPS or
`ALLOW_INSECURE_HTTP` is set. A probe to `http://127.0.0.1` is loopback and
is already exempt.

Do not use `ALLOW_INSECURE_HTTP` to paper over a published `:8080` on a
public interface.

## 11. Confirming config

```bash
curl -sS http://127.0.0.1:8080/health
```

The egress guard's effective settings are on the startup line, not on
`/health` (which needs no key). The line is logged at `info`: with
`LOG_LEVEL` at `warn` or `error` it is absent, and its absence says nothing
about the image.

```bash
docker compose logs porymcp | grep '"msg":"upstream guard"'
```

Behind the overlay, prefer the edge:

```bash
curl -sk https://localhost/health
```

A healthy body looks like:

```json
{
  "status": "ok",
  "service": "porymcp",
  "time": "2026-08-27T19:00:00Z",
  "scheme_enforced": true,
  "trusted_proxies": 1,
  "encryption": "ok"
}
```

| Field | Meaning |
| --- | --- |
| `scheme_enforced` | `true` when `PUBLIC_URL` is https and `ALLOW_INSECURE_HTTP` is unset |
| `trusted_proxies` | Count of configured CIDRs. It is not the CIDR list; the prefixes never appear in the payload |
| `encryption` | `ok`, or `mismatch` when the boot check found a stored credential no configured key opens. A verdict only, never a fingerprint |

The same fields are on `GET /api/v1/health`. A `503` response, `unhealthy`
(store ping failed) or `degraded` (encryption mismatch, see §12), still
includes `scheme_enforced`, `trusted_proxies` and `encryption`. On `unhealthy` the
`error` field is the fixed string `database unavailable`. The cause is in the
server log. `/health` (root) is unauthenticated. A degraded body:

```json
{
  "status": "degraded",
  "service": "porymcp",
  "time": "2026-08-30T16:00:00Z",
  "scheme_enforced": false,
  "trusted_proxies": 0,
  "encryption": "mismatch"
}
```

With the default `PUBLIC_URL=http://localhost:8080` and empty
`TRUSTED_PROXIES`, expect `scheme_enforced: false` and `trusted_proxies: 0`.

## 12. Rotating the encryption key

`ENCRYPTION_KEY` seals every stored upstream credential; losing it makes them
unrecoverable, so back it up separately from the data volume and rotate it
deliberately. (Upgrading to the build that introduced this is itself one-way:
the first boot stamps schema version 5, and version 6 at the fixed-width
timestamp build, which earlier builds refuse, so take the pre-upgrade backup
before deploying it. See `CHANGELOG.md`, `docs/02-data-model.md` and §13
below.) The policy is in `docs/07-security.md`; these are the commands
against the shipped compose file. Only step 1 has downtime. The image has no
shell: `docker compose exec porymcp /porymcp rekey` execs the binary directly,
inherits the container's environment as created (so edit `.env` and recreate
before running it), and prints its result to **your terminal, not to
`docker compose logs`**: keep it.

Precondition: these commands assume `.env` exists and holds the deployment's
current `ADMIN_API_KEY` and `ENCRYPTION_KEY`: compose refuses every
subcommand without both. A throwaway value in the shell satisfies compose but
not step 4's `curl` checks, and it overrides `.env`, so never run `up` with a throwaway
set; step 4 reads the real key straight out of `.env`. If the encryption key has been
lost but the container that was created with it is still present, recover it
before doing anything else:
`docker inspect <container> --format '{{range .Config.Env}}{{println .}}{{end}}' | grep ENCRYPTION_KEY`.
Write it into `.env` to keep running, or into `ENCRYPTION_KEY_PREVIOUS`
beside a fresh `ENCRYPTION_KEY` and follow the steps below. If the key is gone
for good, the stored credentials cannot be recovered: re-enter each one, or
switch an upstream to `auth_type: none` (`PATCH /api/v1/upstreams/{id}` with
`{"auth_type":"none"}`), which removes the stored value without the old key.

```bash
# 0. a new key, on the host (the image has no openssl)
openssl rand -hex 32

# 1. consistent backup: the only step with downtime. The database and the
#    key it was taken under go together; label the archive with the key.
docker compose stop porymcp
docker run --rm -v porymcp_porymcp-data:/data -v "$PWD:/backup" \
  alpine tar czf /backup/porymcp-$(date +%F).tgz /data
docker compose start porymcp

# 2. .env: ENCRYPTION_KEY=<new>  ENCRYPTION_KEY_PREVIOUS=<old>
docker compose up -d porymcp
# the boot log reads "encryption key rotation pending"; GET /health is 200
# "encryption":"ok"; the proxy keeps working on the previous key throughout

# 3. rewrite every stored credential under the new key, once, by hand
docker compose exec porymcp /porymcp rekey
# {"level":"INFO","msg":"rekey complete","rewritten":…,"already_current":…,
#  "no_credential":…,"previous_fingerprint":"…","fingerprint":"…"}   exit 0

# 4. verify, before the old key is destroyed
curl -s -H "Authorization: Bearer $(grep '^ADMIN_API_KEY=' .env | cut -d= -f2-)" \
  http://127.0.0.1:8080/api/v1/stats | jq .upstreams_under_previous_key   # 0
curl -s -H "Authorization: Bearer $(grep '^ADMIN_API_KEY=' .env | cut -d= -f2-)" \
  http://127.0.0.1:8080/api/v1/upstreams | jq '.upstreams[].auth_status'  # ok | none (an OAuth upstream not yet connected reads unreadable, a lapsed one expired)
docker compose up -d --force-recreate porymcp      # both keys still set
# The two log checks assume the default LOG_LEVEL=info: Warn and Info records
# are invisible at LOG_LEVEL=error, and an empty log greps as a false pass.
# The /stats check above is the gate; these corroborate it.
docker compose logs porymcp | grep -c 'rotation pending'                  # 0
docker compose logs porymcp | grep 'encryption key verified'              # the new fingerprint
docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q porymcp)"

# 5. drop the previous key and restart; only now delete the old key from the
#    secret store (remove ENCRYPTION_KEY_PREVIOUS from .env)
docker compose up -d porymcp
```

Behind the TLS overlay, the curls in step 4 go through Caddy
(`curl -sk https://localhost/…`, since a direct `:8080` hit is `426` once
`PUBLIC_URL` is https), and every `up -d` keeps the same `-f` flags, or compose
treats `caddy` as an orphan.

**More than one replica** (Postgres): deploy the new binary everywhere first
with the key unchanged: `rekey` opens the database, which runs every schema
step the build carries (version 6 as of PORM-26), so a `rekey` ahead of the
rollout locks every replica still on the old binary out at `Open`. Then set
both keys on **all** replicas and wait for
the rollout to settle; then run `rekey` **once**, from one process; then remove
`ENCRYPTION_KEY_PREVIOUS` everywhere. Never wire `rekey` into an entrypoint, an
init container or a deploy hook: it is a deliberate, once-per-rotation step.

If `rekey` exits `1` naming rows no configured key opens, nothing was changed:
re-enter those credentials (`PATCH /api/v1/upstreams/{id}` with a fresh
`auth_config`), switch them to `auth_type: none` (the same route with
`{"auth_type":"none"}`, which removes the stored value without the old key), or
delete those upstreams; then re-run `rekey` and restart the server so
`GET /health` reports `encryption: ok`. If it reports a row
"changed during rekey", a concurrent credential edit raced it (a Postgres
deployment: on SQLite, writers queue behind the rotation's transaction
instead); re-run.

**What to point probes at.** A key mismatch is a `503 degraded` on
`GET /health`, and a restart cannot fix it, so:

| Probe | Use | Why |
| --- | --- | --- |
| Docker / compose healthcheck, Swarm, Kubernetes liveness **and** readiness | `exec: ["/porymcp", "healthcheck"]` | Exits `0` on `degraded` (alive, serving the dashboard the operator needs), `1` on `unhealthy` (store ping failed) |
| Uptime monitor, alerting | `GET /health` | Alert on `status != "ok"` or `encryption != "ok"` |
| Load-balancer target check | `GET /` | `/health` would pull the only instance out of rotation on a key mismatch and hide the dashboard |

A Kubernetes **HTTP** liveness probe on `/health` will CrashLoop the deployment
on a key mismatch, taking the working upstreams offline with it. Use the exec
form. On an upgrade that carries a schema step, give the pod a startup probe
long enough for the rewrite (§13); a liveness probe alone kills the process
mid-migration.

## 13. Upgrading to schema version 6

The build that stores timestamps fixed-width (PORM-26) stamps schema version 6
on its first boot. The stamp is one-way: a version-5 binary refuses the
database at `Open`, so the rollback is restore from backup, as in §12. Before
deploying it:

1. **Back up**, stored together with the `ENCRYPTION_KEY` it was taken under
   (§12 step 1 for SQLite). Postgres:

   ```bash
   docker compose --profile postgres stop porymcp
   docker compose --profile postgres exec -T postgres pg_dump -U porymcp porymcp > porymcp-$(date +%F).sql
   ```

   `-T` so the redirect captures the dump and not a TTY.

2. **Stop every old process first.** The version stamp keeps an old binary from
   starting, but it does not stop one that is already past `Open`, and such a
   process keeps writing the short spelling to rows the step will not revisit.
   With more than one replica (Postgres): stop every old replica, back up, start
   **one** new process, wait for its `schema migrated` line with `version=6`
   and `timestamps_rewritten=N`, then `porymcp listening`, then start the rest.
   A rolling deploy is not an upgrade path for this build.

3. **Expect the first start to pause.** `Open` blocks while every stored
   timestamp is rewritten. On SQLite the measured rate was about 15 000 rows
   per second on a four-core virtual machine, the same on RAM-backed and on
   disk-backed storage: roughly 65 to 70 s per million audit rows, with a WAL
   about the size of the database file meanwhile. Time the start on a copy of
   the database before sizing a probe from that figure. A crash mid-step rolls
   back and the next start retries from the beginning. Under the shipped
   compose file the container reports `unhealthy` for that time and recovers
   on its own, because `restart: unless-stopped` acts on exit, not on health,
   and `up -d --wait` may time out before the line appears: wait for the log
   instead (`docs/08-docker.md`). Swarm replaces an unhealthy task, so raise
   `healthcheck.start_period` in the stack file to cover that figure before
   upgrading. Kubernetes: a startup probe with `failureThreshold` times
   `periodSeconds` at least that long, or the liveness probe restarts the pod
   mid-migration and it never finishes.

4. **If the start refuses**, the log names a table, row id and column whose
   value neither layout reads (a hand-edited row; every value a released build
   wrote parses). Nothing was changed and the version is still 5. Under
   `restart: unless-stopped` the container is restart-looping on that refusal,
   so stop it first; then fix that one cell and start it again:

   ```bash
   # SQLite, against the volume (needs network for apk). The chown puts back
   # the ownership the server needs (uid 65532, docs/08-docker.md) on the
   # database and any -wal or -shm file the root shell created.
   docker compose stop porymcp
   docker run --rm -it -v porymcp_porymcp-data:/data alpine sh -c 'apk add -q sqlite && sqlite3 /data/porymcp.db; chown 65532:65532 /data/porymcp.db*'
   docker compose start porymcp
   # Postgres (the porymcp service is already stopped from step 1)
   docker compose --profile postgres exec postgres psql -U porymcp -d porymcp
   docker compose --profile postgres start porymcp
   ```

5. **Verify** after the `schema migrated` line: every stored value is 30 bytes.

   ```bash
   # SQLite
   docker run --rm -v porymcp_porymcp-data:/data alpine sh -c 'apk add -q sqlite && sqlite3 /data/porymcp.db "SELECT DISTINCT length(timestamp) FROM audit_logs;"'   # 30
   # Postgres
   docker compose --profile postgres exec postgres psql -U porymcp -d porymcp -c "SELECT DISTINCT length(timestamp) FROM audit_logs;"   # 30
   ```

   An empty result means no audit rows yet, which is also fine.

## 14. Upgrading to schema version 7

The build that adds HTTP API upstreams (PORM-146) stamps schema version 7 on
its first boot, after adding three columns with defaults: `upstreams.kind`
(`mcp`), `upstreams.test_path` (`""`) and `virtual_keys.http_methods`
(`[]`). No row is rewritten and nothing is contacted, so the start does not
pause as the version-6 upgrade did. The stamp is one-way: a version-6 binary
refuses the database at `Open`, so the rollback is restore from backup, as in
§12 and §13. Before deploying it:

1. **Back up**, stored together with the `ENCRYPTION_KEY` it was taken under
   (§12 step 1 for SQLite, §13 step 1 for Postgres).

2. **Stop every old process first**, as in §13 step 2: the stamp keeps an old
   binary from starting, not one already running. With more than one replica
   (Postgres) start **one** new process, wait for its `schema migrated` line
   with `version=7`, then `porymcp listening`, then start the rest.

3. **Verify** after the `schema migrated` line: every upstream reads `kind`
   `mcp` and every key `http_methods` `[]`, until an operator changes one.

   ```bash
   # SQLite
   docker run --rm -v porymcp_porymcp-data:/data alpine sh -c 'apk add -q sqlite && sqlite3 /data/porymcp.db "SELECT kind, count(*) FROM upstreams GROUP BY kind; SELECT http_methods, count(*) FROM virtual_keys GROUP BY http_methods;"; chown 65532:65532 /data/porymcp.db*'
   # Postgres
   docker compose --profile postgres exec postgres psql -U porymcp -d porymcp -c "SELECT kind, count(*) FROM upstreams GROUP BY kind;" -c "SELECT http_methods, count(*) FROM virtual_keys GROUP BY http_methods;"
   ```

4. **Rolling back** is a restore of the step-1 backup under the previous
   image. An upstream created as an HTTP API, and every key on it, exists
   only in the version-7 database and is lost with it; the previous build
   would not have served them anyway.

The start also reports, once per row and never with the stored text, a key
whose `http_methods` could not be decoded (every request on its `/api/`
endpoint is refused until a `PATCH` supplies the field) and an upstream whose
`kind` is neither `mcp` nor `http` (it serves on no endpoint). Neither can
come from this build's own writes.

## 15. Rolling back past the SHA-256 key check (PORM-44)

The build that verifies virtual keys by their SHA-256 digest has no schema
step, so the version stays 6 and the previous build still opens the
database. A key created or rotated on the newer build carries no hash the
previous build can check, so the previous build answers 401 to it until it
is rotated again there; keys made before the newer build keep working,
including ones the newer build renamed or revoked. Rotate is the only way to
bring a revoked key back, and a rotated key needs rotating again. Before a
rollback, list the keys that will need rotating (revoked keys need none):

```bash
# SQLite
docker run --rm -v porymcp_porymcp-data:/data alpine sh -c 'apk add -q sqlite && sqlite3 /data/porymcp.db "SELECT id, name FROM virtual_keys WHERE length(key_hash) = 0 AND revoked_at IS NULL;"; chown 65532:65532 /data/porymcp.db*'
# Postgres
docker compose --profile postgres exec postgres psql -U porymcp -d porymcp -c "SELECT id, name FROM virtual_keys WHERE length(key_hash) = 0 AND revoked_at IS NULL;"
```

Stop every replica of the previous build before starting the newer one: a
previous-build replica answers 401 to keys the newer one creates.

## 16. OAuth upstreams

An upstream with `auth_type: oauth` is connected by the operator signing in at
the vendor from the dashboard (PORM-139). Three deployment facts decide
whether that works.

`PUBLIC_URL` is the redirect URI's origin: the vendor sends the operator's
browser to `{PUBLIC_URL}/api/v1/oauth/callback`, so it must be the address the
browser uses. It must be https, or http on a loopback host (the laptop
default), or http with `ALLOW_INSECURE_HTTP`; the start route refuses anything
else with a `400` that says so, and a loopback `PUBLIC_URL` reached from
another address is refused with both values in the message.

The client metadata document, `{PUBLIC_URL}/api/v1/oauth/client-metadata`, is
fetched by the vendor's authorization server from its own network when
PoryMCP identifies itself by URL, which it does whenever the vendor supports
it and `PUBLIC_URL` is https off loopback. A deployment the vendor cannot
reach (an IP allowlist, a Cloudflare access rule or challenge, a tailnet, a
LAN name) fails at the vendor's own page, where PoryMCP logs nothing. Exempt
that one path from the rule (it carries no secret and needs no key), or tick
"Register PoryMCP with the vendor instead of publishing its client document"
in the upstream's Edit dialog, press Save, then press Connect on the row
(Cancel drops the tick; the API form is `POST /upstreams/{id}/oauth/start`
with `{"client":"registered"}`). A
registration, once stored, is used by later connects, so the choice sticks
until Disconnect, which forgets the registration with the token set.
Cloudflare does not cache the document or the callback by default; nothing
needs an edge rule.

The callback route has a budget of ten hits per client address per minute.
Behind an edge that is not listed in `TRUSTED_PROXIES` every caller shares
the edge's address and that one budget, so set `TRUSTED_PROXIES` for the
edge (section 2) before connecting an OAuth upstream through it; otherwise
a scan of the public route can hold a sign-in off for a minute.

Pending sign-ins and the refresh lock live in one process. Behind several
replicas the callback must land on the replica that started the flow (one
replica, or session affinity), and two replicas refreshing one upstream at
once can trip a vendor's refresh-token reuse detection and disconnect it. A
database-held flow and refresh lease are a follow-up.

A token refresh PoryMCP makes writes one `upstream.oauth_refresh` event and
one Info line; a refresh the vendor refuses writes a Warn line and the row
reads `expired` on the Upstreams page (never on the boot line, whose sweep
judges what is stored). Nothing about an OAuth upstream needs a restart.
