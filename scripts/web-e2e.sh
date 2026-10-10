#!/usr/bin/env bash
# web-e2e.sh runs the browser suite against a binary it starts itself: the echo
# stub and bin/porymcp on free loopback ports, a temp DATA_DIR, keys minted
# here as shell locals, LOG_LEVEL=warn. It mirrors the docker job's main step,
# so the suite always meets an instance that is already up. make web-e2e runs
# it after make build.
#
# Keys never appear on a command line, in this script's output or in a file
# that outlives the run; the trap stops both processes and removes the temp
# directory on every exit. Playwright's report in web/playwright-report is the
# diagnostic a failed run leaves behind.
set -u
case $- in *x*)
  echo 'FAIL input: xtrace is on; a trace prints keys' >&2
  exit 1
  ;;
esac
set +x
umask 077
cd "$(dirname "$0")/.."

stub_pid= srv_pid= tmp=
stop_all() {
  [ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null
  [ -n "$stub_pid" ] && wait "$stub_pid" 2>/dev/null
  [ -n "$srv_pid" ] && wait "$srv_pid" 2>/dev/null
  [ -n "$tmp" ] && rm -rf "$tmp"
  return 0
}
trap stop_all EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in go node npm npx curl openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL input: $tool is not installed" >&2; exit 1; }
done
[ -d web/node_modules ] || (cd web && npm ci --no-audit --no-fund) || exit 1
[ -x bin/porymcp ] || { echo 'FAIL input: bin/porymcp is missing; run make build' >&2; exit 1; }
# The headless shell Playwright 1.64 runs; a no-op once it is in the cache.
# Its Linux libraries are a one-time root install: npx playwright install-deps chromium.
(cd web && npx --no-install playwright install --only-shell chromium) || exit 1

tmp="$(mktemp -d "${TMPDIR:-/tmp}/porymcp-e2e.XXXXXX")"
go build -o "$tmp/echostub" ./scripts/echostub || exit 1

# Two free ports from one process, so the kernel cannot hand out one port twice.
read -r stub_port srv_port < <(python3 -c '
import socket
a = socket.socket(); a.bind(("127.0.0.1", 0))
b = socket.socket(); b.bind(("127.0.0.1", 0))
print(a.getsockname()[1], b.getsockname()[1])
a.close(); b.close()')
[ -n "${stub_port:-}" ] && [ -n "${srv_port:-}" ] || { echo 'FAIL input: no free port' >&2; exit 1; }

ADMIN_API_KEY="$(openssl rand -hex 32)"
ENCRYPTION_KEY="$(openssl rand -hex 32)"
[ -n "$ADMIN_API_KEY" ] && [ -n "$ENCRYPTION_KEY" ] || exit 1

"$tmp/echostub" -addr "127.0.0.1:$stub_port" > "$tmp/echostub.log" 2>&1 &
stub_pid=$!
# The stub is on loopback, which the upstream guard refuses unless told
# otherwise; PUBLIC_URL matches the port so the dialog's proxy URL is real.
ADMIN_API_KEY="$ADMIN_API_KEY" ENCRYPTION_KEY="$ENCRYPTION_KEY" DATA_DIR="$tmp/data" LOG_LEVEL=warn \
  LISTEN_ADDR="127.0.0.1:$srv_port" PUBLIC_URL="http://127.0.0.1:$srv_port" UPSTREAM_ALLOW_LOOPBACK=1 \
  bin/porymcp > "$tmp/porymcp.log" 2>&1 &
srv_pid=$!

ready=
for _ in $(seq 1 30); do
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$stub_port/v1/ok" &&
    curl -s --max-time 1 "http://127.0.0.1:$srv_port/health" | grep -q '"service":"porymcp"' &&
    kill -0 "$srv_pid" 2>/dev/null; then
    ready=yes
    break
  fi
  sleep 1
done
[ "$ready" = yes ] || { echo 'FAIL start: the stub or the server did not come up' >&2; exit 1; }

status=0
(cd web && PORYMCP_BASE_URL="http://127.0.0.1:$srv_port" STUB_URL="http://127.0.0.1:$stub_port" \
  ADMIN_API_KEY="$ADMIN_API_KEY" PLAYWRIGHT_NO_COPY_PROMPT=1 npm run e2e) || status=$?
[ "$status" -eq 0 ] || echo 'the report is in web/playwright-report'
exit "$status"
