#!/usr/bin/env bash
# image-check.sh proves a PoryMCP image on the host it runs on (PORM-156). The
# docker, docker-arm64 and verify jobs in .github/workflows/ci.yml each run it
# in one step; make image-check runs it by hand. It reads its inputs from the
# environment only:
#
#   IMAGE_CHECK_REF   the image to run: a local tag, or repo@sha256:<digest>
#   IMAGE_CHECK_ARCH  amd64 or arm64; the host, the image and its binary must match
#   IMAGE_CHECK_STUB  the echo stub binary (go build -o <path> ./scripts/echostub)
#   IMAGE_CHECK_E2E   1 to run the browser suite (web/e2e) after the smoke script
#
# It checks the architecture of the host, the image and the binary inside it,
# then starts the stub on the docker bridge gateway and the image as the
# container porymcp-ci on 127.0.0.1:8080, waits for /health, checks the guard
# line and the dashboard, runs scripts/smoke.sh and, when asked, the browser
# suite. The container is left running so a failure step can read its log;
# the caller removes it. Any container already named porymcp-ci is removed
# first.
#
# Both keys are minted here, live only in this process and are passed to the
# container by name. smoke.sh registers each key as a mask through file
# descriptor 3, which the caller points at its own stdout. Every output and
# log is grepped for key forms before it is printed. The script refuses to
# run under xtrace.
#
#   bash scripts/image-check.sh --logs
#
# prints the container log and the stub log through the filter that withholds
# every key form; it mints nothing and starts nothing.
set -euo pipefail
case $- in *x*)
  echo 'FAIL input: xtrace is on; a trace prints keys' >&2
  exit 1
  ;;
esac
set +x
umask 077
cd "$(dirname "$0")/.."

# One work directory both modes find: the runner's temp directory in CI, a
# fixed path under TMPDIR by hand. It is refused when another user owns it.
work="${RUNNER_TEMP:-${TMPDIR:-/tmp}/porymcp-image-check}"
mkdir -p "$work"
[ -O "$work" ] || { echo "FAIL input: $work is owned by another user" >&2; exit 1; }

# The withheld forms: virtual key shapes, the stored literals and any 64-hex
# value (the shape of both keys). This sed is one of the four lists that move
# together (scripts/e2e-scrub.sh names the others).
if [ "${1:-}" = --logs ]; then
  { docker logs porymcp-ci 2>&1; echo '--- echostub'; cat "$work/echostub.log" 2>/dev/null; } |
    grep -v admin_api_key |
    sed -E 's/pory_[0-9a-f]{16,}/pory_<withheld>/g; s/(smokeplain|e2eplain)(alpha|bravo)/<withheld>/g; s/[0-9a-f]{64}/<withheld>/g' || true
  exit 0
fi

fail() {
  echo "FAIL $*" >&2
  exit 1
}

ref="${IMAGE_CHECK_REF:-}"
arch="${IMAGE_CHECK_ARCH:-}"
stub_bin="${IMAGE_CHECK_STUB:-}"
e2e="${IMAGE_CHECK_E2E:-}"
[ -n "$ref" ] || fail 'input: IMAGE_CHECK_REF is not set'
case "$arch" in amd64 | arm64) ;; *) fail 'input: IMAGE_CHECK_ARCH must be amd64 or arm64' ;; esac
[ -x "$stub_bin" ] || fail 'input: IMAGE_CHECK_STUB is not an executable file'
case "$ref" in
*@*) [[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || fail 'input: a digest reference must end in @sha256 and 64 hex digits' ;;
esac

tools="docker curl openssl python3 file"
[ "$e2e" = 1 ] && tools="$tools npm"
for tool in $tools; do
  command -v "$tool" >/dev/null 2>&1 || fail "input: $tool is not installed"
done

stub_pid= extract_id=
# Every line tolerates failure: under errexit a failing command here would end
# the trap early and replace the script's exit status.
cleanup() {
  if [ -n "$stub_pid" ]; then kill "$stub_pid" 2>/dev/null || true; fi
  if [ -n "$extract_id" ]; then docker rm -f "$extract_id" >/dev/null 2>&1 || true; fi
  rm -f "$work/porymcp.bin" || true
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The architecture of the host, the image and the binary, before any key
# exists. The binary is copied out of a container created with no
# environment and removed at once.
host="$(uname -m)"
case "$host" in
x86_64) host_arch=amd64 ;;
aarch64 | arm64) host_arch=arm64 ;;
*) host_arch="$host" ;;
esac
echo "host $host"
[ "$host_arch" = "$arch" ] || fail "arch: the host is $host, not $arch"
image_arch="$(docker image inspect --format '{{.Architecture}}' "$ref")"
echo "image architecture $image_arch"
[ "$image_arch" = "$arch" ] || fail "arch: the image is $image_arch, not $arch"
extract_id="$(docker create --pull=never "$ref")"
docker cp "$extract_id:/porymcp" "$work/porymcp.bin"
docker rm -f "$extract_id" >/dev/null
extract_id=
binary="$(file -b "$work/porymcp.bin")"
echo "binary $binary"
case "$arch" in
amd64) [[ "$binary" == *x86-64* ]] || fail 'arch: the binary is not x86-64' ;;
arm64) [[ "$binary" == *"ARM aarch64"* ]] || fail 'arch: the binary is not ARM aarch64' ;;
esac
echo "binary sha256 $(sha256sum "$work/porymcp.bin" | cut -d' ' -f1)"
rm -f "$work/porymcp.bin"
echo "image $ref"

docker rm -f porymcp-ci >/dev/null 2>&1 || true

ADMIN_API_KEY="$(openssl rand -hex 32)"
ENCRYPTION_KEY="$(openssl rand -hex 32)"
[ -n "$ADMIN_API_KEY" ] && [ -n "$ENCRYPTION_KEY" ] || fail 'keys: openssl gave no key'
export ADMIN_API_KEY ENCRYPTION_KEY

# The container log and the stub log, captured once and grepped from the
# file: grep -q on a pipe exits at the first match, docker logs can then die
# of SIGPIPE, and under pipefail the if reads a match as no match.
leak_check() {
  docker logs porymcp-ci >"$work/porymcp.log" 2>&1
  if grep -q admin_api_key "$work/porymcp.log"; then
    fail 'leak: the container log carries an admin key field'
  fi
  if grep -qF -e "$ADMIN_API_KEY" -e "$ENCRYPTION_KEY" "$work/porymcp.log"; then
    fail 'leak: the container log carries a key value'
  fi
  if grep -qE '(smokeplain|e2eplain)(alpha|bravo)|pory_[0-9a-f]{16,}' "$work/porymcp.log"; then
    fail 'leak: the container log carries a stored credential or a virtual key'
  fi
  if grep -qE '(smokeplain|e2eplain)(alpha|bravo)|pory_[0-9a-f]{16,}' "$work/echostub.log"; then
    fail 'leak: the stub log carries a stored credential or a virtual key'
  fi
}

# The echo stub listens on the bridge gateway, which is what host-gateway
# resolves to inside the container, and nowhere else.
gw="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
[ -n "$gw" ] || fail 'start: no bridge gateway'
"$stub_bin" -addr "$gw:8098" >"$work/echostub.log" 2>&1 &
stub_pid=$!
stub=
for _ in $(seq 1 10); do
  if curl -s -o /dev/null --max-time 1 "http://$gw:8098/v1/ok"; then
    stub=yes
    break
  fi
  sleep 1
done
[ "$stub" = yes ] || fail 'start: the echo stub did not come up'

# The port is published on loopback only, so the URLs below name 127.0.0.1:
# localhost would try ::1 first and be refused.
base=http://127.0.0.1:8080
docker run -d --pull=never --name porymcp-ci -p 127.0.0.1:8080:8080 --add-host=host.docker.internal:host-gateway -e ADMIN_API_KEY -e ENCRYPTION_KEY "$ref" >/dev/null
ok=
for _ in $(seq 1 30); do
  if curl -fs "$base/health" 2>/dev/null | grep -q '"status":"ok"'; then
    ok=yes
    break
  fi
  sleep 1
done
[ "$ok" = yes ] || fail 'start: /health never reported ok'
echo 'PASS /health reports ok'

# The startup line and the image's guard defaults (PORM-79). Logged before
# the listener opens, so it is there once /health answers.
docker logs porymcp-ci >"$work/porymcp.log" 2>&1
grep -qF '"msg":"upstream guard","allow_loopback":false,"deny_private":false' "$work/porymcp.log" ||
  fail 'start: the upstream guard line is missing'
curl -fsS -o "$work/index.html" -w '%{http_code} %{content_type}\n' "$base/" | grep -q '^200 text/html' ||
  fail 'dashboard: / did not answer 200 text/html'
grep -q '<title>PoryMCP</title>' "$work/index.html" || fail 'dashboard: the title is missing'
echo 'PASS the dashboard answers 200 text/html with its title'

# The smoke script (PORM-213): two upstreams, a group, three keys, the four
# MCP doors, the relay, a revoke and the audit rows. Its output is checked
# before it is printed, so a leak never reaches the job log. The stored
# credentials are smokeplain followed by alpha or bravo; the regex is written
# so this file's own text never matches it.
smoke_status=0
STUB_URL=http://host.docker.internal:8098 SMOKE_BASE="$base" bash scripts/smoke.sh >"$work/smoke.out" 2>&1 || smoke_status=$?
if grep -qE 'smokeplain(alpha|bravo)|pory_[0-9a-f]{16,}' "$work/smoke.out" || grep -qF -e "$ADMIN_API_KEY" -e "$ENCRYPTION_KEY" "$work/smoke.out"; then
  fail 'leak: the smoke output carries a stored credential or a key'
fi
cat "$work/smoke.out"
leak_check
[ "$smoke_status" -eq 0 ] || exit "$smoke_status"

if [ "$e2e" != 1 ]; then
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "Ran \`$ref\` on $host" >>"$GITHUB_STEP_SUMMARY"
  exit 0
fi

# The browser suite's scrub self-test runs first, while the keys are
# exported, so the check that gates the upload is proven able to see a key at
# every layer of a report.
bash scripts/e2e-scrub.sh --self-test
e2e_status=0
(cd web && PORYMCP_BASE_URL="$base" STUB_URL=http://host.docker.internal:8098 PLAYWRIGHT_NO_COPY_PROMPT=1 npm run e2e) >"$work/e2e.raw" 2>&1 || e2e_status=$?
# A failing Settings assertion prints the first 12 characters of the admin
# key; they are withheld before the grep, which then sees what would be
# printed. The stored credential words are not grepped in this output: a
# failing fill on the bearer field prints them, and a hit would hide an
# ordinary failure. They are grepped in the logs.
sed "s/${ADMIN_API_KEY:0:12}/<withheld>/g" "$work/e2e.raw" >"$work/e2e.out"
if grep -qE 'pory_[0-9a-f]{16,}' "$work/e2e.out" || grep -qF -e "$ADMIN_API_KEY" -e "$ENCRYPTION_KEY" "$work/e2e.out"; then
  fail 'leak: the browser suite output carries a key'
fi
cat "$work/e2e.out"
leak_check
# On a red suite the report is scrubbed and moved to the upload path only
# when the scrub's check finds nothing; otherwise it stays where it is and
# nothing uploads.
if [ "$e2e_status" -ne 0 ] && [ -d web/playwright-report ]; then
  if bash scripts/e2e-scrub.sh web/playwright-report web/test-results; then
    rm -rf "$work/playwright-report"
    mv web/playwright-report "$work/playwright-report"
    echo 'the browser report is the playwright-report artefact on this run (npx playwright show-report <dir>); the test-results paths above stayed on the runner'
  else
    echo 'the browser report was not kept'
  fi
fi
[ "$e2e_status" -eq 0 ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "Ran \`$ref\` on $host" >>"$GITHUB_STEP_SUMMARY"
exit "$e2e_status"
