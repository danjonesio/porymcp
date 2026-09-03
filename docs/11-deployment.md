# TLS and reverse-proxy deployment

PoryMCP listens on plain HTTP at `:8080` by default. `PUBLIC_URL` defaults to
`http://localhost:8080`, so a laptop checkout does not enforce TLS. That
default is for localhost only.

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
Turn buffering off and raise the read timeout for SSE and long tool calls.
Cap the inbound body at 8 MiB so it matches the proxy's own cap.

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
forwarded. The proxy copies `Mcp-Session-Id`, `Mcp-Protocol-Version`, and
`Last-Event-ID` outbound. Those names use hyphens; they usually survive.
nginx lowercases header names and may drop unknown headers that contain
underscores unless `underscores_in_headers on` is set. If a client or an
intermediate hop sends underscore forms (`Mcp_Session_Id`), either enable
that flag or set the hyphenated names explicitly with `proxy_set_header`.

## 5. Traefik

Traefik sets `X-Forwarded-*` by default. Point the load balancer at 8080 and
put the container IP (or the Traefik-to-app CIDR) in `TRUSTED_PROXIES`.

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

Free-plan edge timeouts are about 100 seconds. Long `tools/call` responses
and SSE streams that run past that are cut. Raise the plan or keep those
calls shorter than the edge timeout.

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

## 9. HSTS

`Strict-Transport-Security` belongs at the TLS edge (Caddy, nginx, Traefik,
a PaaS router), not in PoryMCP. The process does not emit it.

## 10. Escape hatches

| Variable | Default | When to set it |
| --- | --- | --- |
| `ALLOW_INSECURE_HTTP` | unset / false | TLS terminates somewhere PoryMCP cannot observe (some kube HTTP probes, an outer mesh that strips TLS before the pod). Non-loopback HTTP is then allowed even when `PUBLIC_URL` is https. |
| `ALLOW_LOCALHOST` | unset / false | Accept `localhost` / `127.0.0.1` / `::1` Host values when `PUBLIC_URL` is not itself localhost. |
| `EXTRA_ALLOWED_HOSTS` | empty | Extra Host values (comma-separated, no scheme) accepted on the proxy endpoints besides `PUBLIC_URL`. |

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
the first boot stamps schema version 5, which earlier builds refuse, so take the
pre-upgrade backup before deploying it. See `CHANGELOG.md` and
`docs/02-data-model.md`.) The policy is in `docs/07-security.md`; these are the commands
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
for good, the stored credentials cannot be recovered: re-enter each one.

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
  http://127.0.0.1:8080/api/v1/upstreams | jq '.upstreams[].auth_status'  # ok | none
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
with the key unchanged: `rekey` opens the database, which runs the schema-5
migration, so a `rekey` ahead of the rollout locks every replica still on the
old binary out at `Open`. Then set both keys on **all** replicas and wait for
the rollout to settle; then run `rekey` **once**, from one process; then remove
`ENCRYPTION_KEY_PREVIOUS` everywhere. Never wire `rekey` into an entrypoint, an
init container or a deploy hook: it is a deliberate, once-per-rotation step.

If `rekey` exits `1` naming rows no configured key opens, nothing was changed:
re-enter those credentials (`PATCH /api/v1/upstreams/{id}` with a fresh
`auth_config`) or delete those upstreams, then re-run. If it reports a row
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
form.
