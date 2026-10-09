#!/usr/bin/env bash
# smoke.sh proves a running PoryMCP end to end (PORM-213). It reads its
# inputs from the environment only:
#
#   SMOKE_BASE         the instance root, default http://localhost:8080
#   SMOKE_EXPECT_EDGE  1 to require scheme_enforced and a trusted proxy on /health
#   SMOKE_VIRTUAL_KEY  a virtual key; runs one handshake and tools/list on /mcp
#   ADMIN_API_KEY      with STUB_URL, runs the full section against a loopback instance
#   STUB_URL           the echo stub (scripts/echostub) as the instance reaches it
#
# Every check prints one PASS or FAIL line and is counted; the exit status is
# 1 when any check failed. No key value is ever printed: every body and
# reason passes through one scrub, keys reach curl from files and never from
# its command line, and the script refuses to run under xtrace.
set -u
case $- in *x*)
  echo 'FAIL input: xtrace is on; a trace prints keys' >&2
  exit 1
  ;;
esac
set +x
umask 077

SMOKE_BASE="${SMOKE_BASE:-http://localhost:8080}"
SMOKE_BASE="${SMOKE_BASE%/}"
SMOKE_EXPECT_EDGE="${SMOKE_EXPECT_EDGE:-}"
SMOKE_VIRTUAL_KEY="${SMOKE_VIRTUAL_KEY:-}"
ADMIN_API_KEY="${ADMIN_API_KEY:-}"
STUB_URL="${STUB_URL:-}"
STUB_URL="${STUB_URL%/}"

# The two stored credentials the full section registers. Lowercase letters
# only, 15 bytes: above the literal pass's minimum, under the long-run rule,
# no digit and no mixed case, so no pattern rule can take credit for a
# [redacted]. They hold nothing and are not vendor-shaped.
BEARER=smokeplainalpha
QVALUE=smokeplainbravo

tmp="$(mktemp -d)"
PASSES=0
FAILS=0
section=""
section_start=0
req_n=0
run_start=$SECONDS
finished=""

# Every JSON step runs in python3 from this one file; curl makes every HTTP
# call, because the edge in front of a deployment refuses urllib's agent.
cat > "$tmp/smoke.py" <<'PY'
import base64
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlsplit, unquote

KEY_RE = re.compile(r'pory_[0-9a-f]{16,}')
LITERALS = ['smokeplainalpha', 'smokeplainbravo']


def docs(raw):
    """Every JSON document in raw: a plain body, or each SSE event's data."""
    text = raw.replace('\r', '')
    s = text.lstrip()
    if s.startswith('{') or s.startswith('['):
        try:
            return [json.loads(s)]
        except ValueError:
            return []
    out = []
    for ev in s.split('\n\n'):
        data = '\n'.join(l[5:].lstrip() for l in ev.split('\n') if l.startswith('data:'))
        if not data:
            continue
        try:
            out.append(json.loads(data))
        except ValueError:
            pass
    return out


def pick(raw, want):
    ds = docs(raw)
    if want is not None:
        for d in ds:
            if isinstance(d, dict) and str(d.get('id')) == want:
                return d
    return ds[-1] if ds else None


def walk(cur, expr):
    for part in [p for p in expr.split('.') if p != '']:
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def show(v):
    if v is None:
        return ''
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return str(v)


def read(path):
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', 'replace')


def secrets(tmp):
    out = list(LITERALS)
    try:
        with open(os.path.join(tmp, 'secrets')) as f:
            out += [l.rstrip('\n') for l in f if l.strip()]
    except FileNotFoundError:
        pass
    return out


def scrub(tmp, text):
    for s in secrets(tmp):
        forms = {s, s.upper(), base64.b64encode(s.encode()).decode()}
        for form in forms:
            text = text.replace(form, '<withheld>')
    text = KEY_RE.sub('<withheld>', text)
    text = text[:600]
    if not text.endswith('\n'):
        text += '\n'
    return text


def validate(name, val):
    if any(c.isspace() or ord(c) < 32 for c in val):
        return None
    u = urlsplit(val)
    if u.scheme not in ('http', 'https') or not u.hostname:
        return None
    if u.username is not None or u.password is not None or u.query or u.fragment:
        return None
    if u.path not in ('', '/'):
        return None
    return u.scheme, u.hostname


def main():
    cmd = sys.argv[1]
    if cmd == 'validate':
        r = validate(sys.argv[2], sys.argv[3])
        if r is None:
            sys.exit(1)
        print(r[0], r[1])
    elif cmd == 'jget':
        want = sys.argv[4] if len(sys.argv) > 4 else None
        print(show(walk(pick(read(sys.argv[2]), want), sys.argv[3])))
    elif cmd == 'proof':
        want = sys.argv[3] if len(sys.argv) > 3 else None
        text = walk(pick(read(sys.argv[2]), want), 'result.content.0.text')
        if not isinstance(text, str):
            print('')
            return
        try:
            print(json.dumps(json.loads(text).get('proof'), sort_keys=True))
        except ValueError:
            print('')
    elif cmd == 'has_tool':
        want = sys.argv[4] if len(sys.argv) > 4 else None
        tools = walk(pick(read(sys.argv[2]), want), 'result.tools') or []
        names = [t.get('name') for t in tools if isinstance(t, dict)]
        sys.exit(0 if sys.argv[3] in names else 1)
    elif cmd == 'tool_count':
        want = sys.argv[3] if len(sys.argv) > 3 else None
        tools = walk(pick(read(sys.argv[2]), want), 'result.tools') or []
        print(len(tools))
    elif cmd == 'sha':
        print(hashlib.sha256(sys.argv[2].encode()).hexdigest())
    elif cmd == 'scrub':
        sys.stdout.write(scrub(sys.argv[2], sys.stdin.buffer.read().decode('utf-8', 'replace')))
    elif cmd == 'body':
        # body k=v k=v ... builds a JSON object; a value starting with @ is
        # itself JSON (a list or an object), anything else is a string.
        obj = {}
        for kv in sys.argv[2:]:
            k, v = kv.split('=', 1)
            obj[k] = json.loads(v[1:]) if v.startswith('@') else v
        print(json.dumps(obj))
    elif cmd == 'suffix':
        import secrets as s
        print(s.token_hex(3))
    elif cmd == 'header_value':
        # header_value FILE NAME prints the first value of a response header.
        name = sys.argv[3].lower()
        for line in read(sys.argv[2]).replace('\r', '').split('\n'):
            if ':' in line and line.split(':', 1)[0].strip().lower() == name:
                print(line.split(':', 1)[1].strip())
                return
        print('')
    else:
        sys.exit(2)


main()
PY

py() { python3 "$tmp/smoke.py" "$@"; }

say() {
  section="$1"
  section_start=$SECONDS
  echo "== $1 =="
}

pass() {
  PASSES=$((PASSES + 1))
  echo "PASS $section: $1"
}

# fail CHECK REASON [FILE]: the reason and the file both pass through the
# scrub; under Actions an annotation names the check and nothing else.
fail() {
  FAILS=$((FAILS + 1))
  local reason
  reason="$(printf '%s' "$2" | py scrub "$tmp" | tr -d '\n')"
  echo "FAIL $section: $1: $reason"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::error title=smoke::$section: $1"
  fi
  if [ -n "${3:-}" ] && [ -s "$3" ]; then
    py scrub "$tmp" < "$3" | sed 's/^/| /'
  fi
}

mask() {
  if [ "${GITHUB_ACTIONS:-}" = true ] && [ -n "$1" ]; then
    echo "::add-mask::$1"
  fi
}

# req METHOD URL [HDRFILE] [JSON] [MAXTIME] [EXTRA...]: one curl, with the
# status in $tmp/code, the body in $tmp/body and the response headers in
# $tmp/hdr. A credential travels in HDRFILE, never on the command line.
req() {
  local method="$1" url="$2" hdrfile="${3:-}" json="${4:-}" maxtime="${5:-20}"
  shift 5 2>/dev/null || shift $#
  local -a args=(-sS --connect-timeout 5 --max-time "$maxtime" -o "$tmp/body" -D "$tmp/hdr" -w '%{http_code}' -X "$method")
  if [ -n "$hdrfile" ]; then
    args+=(--header @"$hdrfile")
  fi
  if [ -n "$json" ]; then
    printf '%s' "$json" > "$tmp/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$tmp/req")
  fi
  local code
  : > "$tmp/body"
  : > "$tmp/hdr"
  code="$(curl "${args[@]}" "$@" "$url" 2> "$tmp/curlerr")" || code=000
  echo "$code" > "$tmp/code"
}

code() { cat "$tmp/code"; }

api() { req "$1" "$SMOKE_BASE$2" "$tmp/hdr.admin" "${3:-}" "${4:-20}"; }

# rpc URL HDRFILE JSON IDFILE [SESSION] [VERSION]: one JSON-RPC POST with a
# request id the audit section matches rows on.
rpc() {
  local url="$1" hdrfile="$2" json="$3" idfile="$4" session="${5:-}" version="${6:-}"
  req_n=$((req_n + 1))
  local rid="smoke-$sfx-$req_n"
  echo "$rid" >> "$idfile"
  local -a extra=(-H 'Accept: application/json, text/event-stream' -H "X-Request-Id: $rid")
  if [ -n "$session" ]; then
    extra+=(-H "Mcp-Session-Id: $session")
  fi
  if [ -n "$version" ]; then
    extra+=(-H "MCP-Protocol-Version: $version")
  fi
  req POST "$url" "$hdrfile" "$json" 10 "${extra[@]}"
}

# del URL HDRFILE SESSION: the session teardown a client sends.
del() {
  req DELETE "$1" "$2" "" 10 -H "Mcp-Session-Id: $3"
}

# relay PATH HDRFILE IDFILE: one GET through the HTTP relay.
relay() {
  req_n=$((req_n + 1))
  local rid="smoke-$sfx-$req_n"
  echo "$rid" >> "$3"
  req GET "$SMOKE_BASE$1" "$2" "" 10 -H "X-Request-Id: $rid"
}

jget() { py jget "$@"; }
sha() { py sha "$1"; }

rpc_body() {
  # rpc_body ID METHOD [PARAMS-JSON]
  if [ -n "${3:-}" ]; then
    printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}' "$1" "$2" "$3"
  else
    printf '{"jsonrpc":"2.0","id":%s,"method":"%s"}' "$1" "$2"
  fi
}

INIT_PARAMS='{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}'
NOTIFY='{"jsonrpc":"2.0","method":"notifications/initialized"}'

# handshake URL HDRFILE IDFILE LABEL: initialize and the notification on one
# door. Leaves the session in $hs_session and the version in $hs_version.
# A door that answers no session (the group door) passes with both empty.
hs_session=""
hs_version=""
handshake() {
  local url="$1" hdrfile="$2" idfile="$3" label="$4" require_session="${5:-}"
  hs_session=""
  hs_version=""
  rpc "$url" "$hdrfile" "$(rpc_body 1 initialize "$INIT_PARAMS")" "$idfile"
  if [ "$(code)" != 200 ]; then
    fail "$label initialize" "status $(code)" "$tmp/body"
    return 1
  fi
  hs_version="$(jget "$tmp/body" result.protocolVersion 1)"
  hs_session="$(py header_value "$tmp/hdr" Mcp-Session-Id)"
  if [ -z "$hs_version" ]; then
    fail "$label initialize" "no protocolVersion in the answer" "$tmp/body"
    return 1
  fi
  if [ -n "$require_session" ] && [ -z "$hs_session" ]; then
    fail "$label initialize" "no Mcp-Session-Id in the answer"
    return 1
  fi
  rpc "$url" "$hdrfile" "$NOTIFY" "$idfile" "$hs_session" "$hs_version"
  case "$(code)" in
    200|202|204) ;;
    *) fail "$label notifications/initialized" "status $(code)" "$tmp/body"; return 1 ;;
  esac
  return 0
}

# teardown runs once, on every exit path. The full section's deletes are
# added by run_full's bookkeeping; here it prints the summary and removes
# the temp directory.
teardown() {
  local status=$?
  if [ -n "$finished" ]; then
    return
  fi
  finished=1
  trap - EXIT INT TERM
  full_teardown
  echo "smoke: $PASSES passed, $FAILS failed in $((SECONDS - run_start))s"
  rm -rf "$tmp"
  if [ "$FAILS" -gt 0 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}
full_teardown() { :; }
trap teardown EXIT
trap 'exit 130' INT TERM

# Input validation, before any request.
if ! base_parts="$(py validate SMOKE_BASE "$SMOKE_BASE")"; then
  section=input
  fail "SMOKE_BASE" "not an http or https origin with no userinfo, path, query or fragment"
  exit 1
fi
base_scheme="${base_parts%% *}"
base_host="${base_parts#* }"
if [ -n "$STUB_URL" ] && ! py validate STUB_URL "$STUB_URL" > /dev/null; then
  section=input
  fail "STUB_URL" "not an http or https origin with no userinfo, path, query or fragment"
  exit 1
fi
loopback=""
case "$base_host" in
  localhost|127.0.0.1|::1) loopback=1 ;;
esac
if [ "$base_scheme" = http ] && [ -z "$loopback" ] && { [ -n "$SMOKE_VIRTUAL_KEY" ] || [ -n "$ADMIN_API_KEY" ]; }; then
  section=input
  fail "scheme" "a key is never sent over plain http to a remote host"
  exit 1
fi

: > "$tmp/secrets"
if [ -n "$ADMIN_API_KEY" ]; then
  printf 'Authorization: Bearer %s\n' "$ADMIN_API_KEY" > "$tmp/hdr.admin"
  printf '%s\n' "$ADMIN_API_KEY" >> "$tmp/secrets"
  mask "$ADMIN_API_KEY"
fi
if [ -n "$SMOKE_VIRTUAL_KEY" ]; then
  printf 'Authorization: Bearer %s\n' "$SMOKE_VIRTUAL_KEY" > "$tmp/hdr.deploy"
  printf '%s\n' "$SMOKE_VIRTUAL_KEY" >> "$tmp/secrets"
  mask "$SMOKE_VIRTUAL_KEY"
fi
sfx="$(py suffix)"

# edge: what every instance answers with no key.
say edge
req GET "$SMOKE_BASE/health" "" "" 20
if [ "$(code)" = 200 ] && [ "$(jget "$tmp/body" status)" = ok ]; then
  pass "GET /health is 200 with status ok"
else
  loc="$(py header_value "$tmp/hdr" Location)"
  fail "GET /health is 200 with status ok" "status $(code)${loc:+, location $loc}" "$tmp/body"
fi
if [ "$SMOKE_EXPECT_EDGE" = 1 ]; then
  if [ "$(jget "$tmp/body" scheme_enforced)" = true ]; then
    pass "scheme_enforced is true"
  else
    fail "scheme_enforced is true" "got $(jget "$tmp/body" scheme_enforced)" "$tmp/body"
  fi
  tp="$(jget "$tmp/body" trusted_proxies)"
  if [ -n "$tp" ] && [ "$tp" -gt 0 ] 2>/dev/null; then
    pass "trusted_proxies is above zero"
  else
    fail "trusted_proxies is above zero" "got $tp" "$tmp/body"
  fi
fi
req GET "$SMOKE_BASE/" "" "" 20
ct="$(py header_value "$tmp/hdr" Content-Type)"
if [ "$(code)" = 200 ] && [ "${ct#text/html}" != "$ct" ] && grep -q '<title>PoryMCP</title>' "$tmp/body"; then
  pass "GET / is 200 text/html with the PoryMCP title"
else
  fail "GET / is 200 text/html with the PoryMCP title" "status $(code), content type $ct"
fi

# deploy key: the shared /mcp door with an operator's key. One handshake,
# one tools/list, one DELETE. The tool count is printed, never the body.
if [ -n "$SMOKE_VIRTUAL_KEY" ]; then
  say "deploy key"
  : > "$tmp/ids.deploy"
  if handshake "$SMOKE_BASE/mcp" "$tmp/hdr.deploy" "$tmp/ids.deploy" "deploy key"; then
    pass "initialize on /mcp answers protocolVersion $hs_version"
    rpc "$SMOKE_BASE/mcp" "$tmp/hdr.deploy" "$(rpc_body 2 tools/list)" "$tmp/ids.deploy" "$hs_session" "$hs_version"
    n="$(py tool_count "$tmp/body" 2)"
    if [ "$(code)" = 200 ] && [ "${n:-0}" -gt 0 ] 2>/dev/null; then
      pass "tools/list carries $n tool$([ "$n" = 1 ] || echo s)"
    else
      fail "tools/list carries at least one tool" "status $(code), count ${n:-0}" "$tmp/body"
    fi
    if [ -n "$hs_session" ]; then
      del "$SMOKE_BASE/mcp" "$tmp/hdr.deploy" "$hs_session"
      echo "deploy key: DELETE with the session answered $(code)"
    fi
  fi
fi

# full: the register-to-teardown run against a loopback instance with the
# echo stub. Defined by run_full below; absent, the skip line says why.
if [ -n "$ADMIN_API_KEY" ] && [ -n "$STUB_URL" ]; then
  if [ -z "$loopback" ]; then
    echo "skip: the full section runs against a loopback instance only"
  elif declare -F run_full > /dev/null; then
    run_full
  else
    echo "skip: the full section is not in this build"
  fi
else
  echo "skip: the full section needs ADMIN_API_KEY and STUB_URL"
fi
