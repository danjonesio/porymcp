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


def load_rows(tmp, name):
    try:
        raw = read(os.path.join(tmp, name))
    except FileNotFoundError:
        return [], ''
    d = pick(raw, None) or {}
    rows = d.get('logs') if isinstance(d, dict) else None
    return [r for r in (rows or []) if isinstance(r, dict)], raw


def parsed(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


def audit(tmp, revoked):
    """Every audit assertion over the rows the sections left behind."""
    rows, raws = [], []
    for name in ('rows.k1', 'rows.k2', 'rows.k3'):
        r, raw = load_rows(tmp, name)
        rows += r
        raws.append(raw)
    blocked, braw = load_rows(tmp, 'rows.blocked')
    raws.append(braw)
    try:
        raws.append(read(os.path.join(tmp, 'admin_events')))
    except FileNotFoundError:
        pass
    expect = []
    with open(os.path.join(tmp, 'expect')) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 4:
                expect.append(parts)
    by_id = {}
    for r in rows:
        by_id.setdefault(r.get('request_id'), []).append(r)
    out = []

    def check(name, ok, reason=''):
        out.append('PASS ' + name if ok else 'FAIL %s: %s' % (name, reason))

    missing = [rid for rid, _, _, _ in expect if len(by_id.get(rid, [])) != 1]
    check('one row per request id (%d of %d)' % (len(expect) - len(missing), len(expect)),
          not missing, '%d ids without exactly one row' % len(missing))
    bad = [rid for rid, st, _, _ in expect if st == 'success'
           and any(r.get('status') != 'success' for r in by_id.get(rid, []))]
    check('every 2xx call is a success row', not bad, '%d rows are not success' % len(bad))
    bad = [rid for rid, _, up, _ in expect if up == 'yes'
           and any(not r.get('upstream_id') for r in by_id.get(rid, []))]
    check('forwarded rows name an upstream', not bad, '%d forwarded rows name none' % len(bad))
    bad = [rid for rid, _, _, tool in expect if tool != '-'
           and any(r.get('tool_name') != tool for r in by_id.get(rid, []))]
    check('tool names on the call and relay rows', not bad, '%d rows carry another tool_name' % len(bad))
    err = [r for rid, st, _, _ in expect if st == 'error' for r in by_id.get(rid, [])]
    check('the json401 row is an error row',
          bool(err) and all(r.get('status') == 'error' and r.get('error_message') == 'upstream answered 401' for r in err),
          'status or error_message differ' if err else 'no row')
    okrows = [r for rid, _, _, tool in expect if tool == '/ok' for r in by_id.get(rid, [])]

    def query_ok(r):
        p = parsed(r.get('params'))
        q = parsed(p.get('query')) if isinstance(p, dict) else None
        return isinstance(q, dict) and q.get('page') == '2' and q.get('api_key') == '[redacted]'

    check('the /ok row records page 2 and a redacted api_key',
          bool(okrows) and all(query_ok(r) for r in okrows), 'params.query differs' if okrows else 'no row')
    brows = [r for r in blocked if r.get('request_id') == revoked]
    check('the revoked call is one blocked row with no key',
          len(brows) == 1 and brows[0].get('status') == 'blocked' and not brows[0].get('virtual_key_id')
          and brows[0].get('tool_name') == '/ok',
          '%d rows, or status, key or tool_name differ' % len(brows))
    text = '\n'.join(raws)
    leak = any(s in text for s in secrets(tmp)) or bool(KEY_RE.search(text))
    check('no secret in the logs or the admin events', not leak, 'a stored credential or a key shape is present')
    print('\n'.join(out))


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
            print(json.dumps(json.loads(text), sort_keys=True))
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
    elif cmd == 'len':
        print(len(walk(pick(read(sys.argv[2]), None), sys.argv[3]) or []))
    elif cmd == 'missing':
        rows = walk(pick(read(sys.argv[2]), None), 'logs') or []
        have = {r.get('request_id') for r in rows if isinstance(r, dict)}
        with open(sys.argv[3]) as f:
            ids = [l.strip() for l in f if l.strip()]
        print(sum(1 for i in ids if i not in have))
    elif cmd == 'record_key':
        # record_key BODY HDRFILE SECRETS: the plaintext goes to the header
        # file and the secrets list, never to stdout; the id is printed.
        # Under Actions it is also registered as a mask through descriptor
        # 3 when that is open (see mask in the shell).
        d = pick(read(sys.argv[2]), None) or {}
        key = d.get('api_key') if isinstance(d, dict) else None
        if isinstance(key, str) and key:
            with open(sys.argv[3], 'w') as f:
                f.write('Authorization: Bearer %s\n' % key)
            with open(sys.argv[4], 'a') as f:
                f.write(key + '\n')
            if os.environ.get('GITHUB_ACTIONS') == 'true':
                try:
                    os.write(3, ('::add-mask::%s\n' % key).encode())
                except OSError:
                    pass
        print(d.get('id') or '' if isinstance(d, dict) else '')
    elif cmd == 'audit':
        audit(sys.argv[2], sys.argv[3])
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

# mask VALUE: under Actions, registers VALUE with the runner as a mask
# through file descriptor 3, which the CI step points at its own stdout
# while it captures the script's output. The value never goes to stdout or
# stderr, so the captured output stays free of it. With no descriptor 3
# open, nothing is written.
mask() {
  if [ "${GITHUB_ACTIONS:-}" = true ] && [ -n "$1" ] && { true >&3; } 2>/dev/null; then
    echo "::add-mask::$1" >&3
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
  last_rid="$rid"
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
  last_rid="$rid"
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

# handshake URL HDRFILE IDFILE LABEL [REQUIRE_SESSION] [SEND_VERSION]:
# initialize and the notification on one door. Leaves the session in
# $hs_session and the version in $hs_version. REQUIRE_SESSION makes a
# missing Mcp-Session-Id a FAIL; SEND_VERSION puts the answered version on
# the notification. The group door answers no session and gets neither
# header, as its own requests say nothing about a member.
hs_session=""
hs_version=""
handshake() {
  local url="$1" hdrfile="$2" idfile="$3" label="$4" require_session="${5:-}" send_version="${6:-}"
  hs_session=""
  hs_version=""
  rpc "$url" "$hdrfile" "$(rpc_body 1 initialize "$INIT_PARAMS")" "$idfile"
  if [ "$(code)" != 200 ]; then
    fail "$label initialize" "status $(code)" "$tmp/body"
    return 1
  fi
  hs_version="$(jget "$tmp/body" result.protocolVersion 1)"
  hs_session="$(py header_value "$tmp/hdr" Mcp-Session-Id)"
  case "$hs_version" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *)
      # Only a date-shaped version is ever printed on a PASS line.
      hs_version=""
      fail "$label initialize" "protocolVersion is missing or not date-shaped" "$tmp/body"
      return 1
      ;;
  esac
  if [ -n "$require_session" ] && [ -z "$hs_session" ]; then
    fail "$label initialize" "no Mcp-Session-Id in the answer"
    return 1
  fi
  local v=""
  if [ -n "$send_version" ]; then
    v="$hs_version"
  fi
  rpc "$url" "$hdrfile" "$NOTIFY" "$idfile" "$hs_session" "$v"
  case "$(code)" in
    200|202|204) ;;
    *) fail "$label notifications/initialized" "status $(code)" "$tmp/body"; return 1 ;;
  esac
  return 0
}

# The full section. Every id is recorded the instant its create answers,
# before any assertion, so full_teardown can delete it on any exit path.
up_mcp=""
up_http=""
grp=""
k1=""
k2=""
k3=""
before=""
since=""
last_rid=""

# count_all prints the lengths of the three lists.
count_all() {
  local u g k
  api GET /api/v1/upstreams; u="$(py len "$tmp/body" upstreams)"
  api GET /api/v1/groups; g="$(py len "$tmp/body" groups)"
  api GET /api/v1/virtual-keys; k="$(py len "$tmp/body" virtual_keys)"
  echo "upstreams $u, groups $g, keys $k"
}

# expect STATUS UPSTREAM TOOL records what the audit row for the last
# request must say: its status, whether it names an upstream (yes or no)
# and its tool_name (or - for none).
expect() {
  echo "$last_rid $1 $2 $3" >> "$tmp/expect"
}

# create LABEL PATH JSON VAR: one admin create; the id lands in VAR. A 201
# without a parsable id is a FAIL that stops further creates.
create() {
  api POST "$2" "$3" 30
  local id
  id="$(jget "$tmp/body" id)"
  if [ "$(code)" = 201 ] && [ -n "$id" ]; then
    printf -v "$4" '%s' "$id"
    pass "$1 created"
    return 0
  fi
  fail "$1 created" "status $(code)" "$tmp/body"
  return 1
}

# mint LABEL JSON N: one key create; the id lands in k<N>, the plaintext in
# $tmp/hdr.k<N> and the secrets list, never in a shell variable.
mint() {
  api POST /api/v1/virtual-keys "$2"
  local id
  id="$(py record_key "$tmp/body" "$tmp/hdr.k$3" "$tmp/secrets")"
  if [ "$(code)" = 201 ] && [ -n "$id" ]; then
    printf -v "k$3" '%s' "$id"
    : > "$tmp/ids.k$3"
    return 0
  fi
  fail "$1 minted" "status $(code)" "$tmp/body"
  return 1
}

# proof_checks LABEL FILE ID MESSAGE: the assertions on one tools/call echo
# answer: the message came back, one Authorization value whose digest is
# the stored bearer's, and no virtual key anywhere in the request.
proof_checks() {
  py proof "$2" "$3" > "$tmp/proof"
  if [ "$(jget "$tmp/proof" message)" = "$4" ]; then
    pass "tools/call echo returns the message"
  else
    fail "tools/call echo returns the message" "status $(code)" "$2"
  fi
  if [ "$(jget "$tmp/proof" proof.auth_count)" = 1 ] && [ "$(jget "$tmp/proof" proof.auth_sha256)" = "$BEARER_SHA" ]; then
    pass "the stub saw one Authorization value, the stored bearer"
  else
    fail "the stub saw one Authorization value, the stored bearer" "auth_count $(jget "$tmp/proof" proof.auth_count), digest differs"
  fi
  if [ "$(jget "$tmp/proof" proof.pory_seen)" = false ]; then
    pass "the stub never saw a virtual key"
  else
    fail "the stub never saw a virtual key" "pory_seen $(jget "$tmp/proof" proof.pory_seen)"
  fi
}

# mcp_door LABEL URL HDRFILE IDFILE TOOL STUB UPSTREAM: handshake, list and
# call on one MCP door. STUB set means the door forwards to the stub: a
# session is required, protocolVersion must be 2025-11-25 and both headers
# are sent after initialize. STUB empty is the group door: no session, no
# version header, nothing asserted about the version beyond its shape. The
# handshake rows and the list row are recorded with UPSTREAM as the caller
# says; the call row always names one.
mcp_door() {
  local label="$1" url="$2" hdrfile="$3" idfile="$4" tool="$5" require="$6" upstream="$7"
  say "$label"
  if ! handshake "$url" "$hdrfile" "$idfile" "$label" "$require" "$require"; then
    return 1
  fi
  if [ -n "$require" ] && [ "$hs_version" != 2025-11-25 ]; then
    fail "$label initialize answers protocolVersion 2025-11-25" "got $hs_version"
    return 1
  fi
  local v=""
  if [ -n "$require" ]; then
    v="$hs_version"
  fi
  # handshake sent two requests: initialize, then the notification.
  local init_rid notify_rid
  notify_rid="$(tail -n 1 "$idfile")"
  init_rid="$(tail -n 2 "$idfile" | head -n 1)"
  echo "$init_rid success $upstream -" >> "$tmp/expect"
  echo "$notify_rid success $upstream -" >> "$tmp/expect"
  if [ -n "$hs_session" ]; then
    pass "initialize answers protocolVersion $hs_version and a session"
  else
    pass "initialize answers protocolVersion $hs_version"
  fi
  rpc "$url" "$hdrfile" "$(rpc_body 2 tools/list)" "$idfile" "$hs_session" "$v"
  expect success "$upstream" -
  if [ "$(code)" = 200 ] && py has_tool "$tmp/body" "$tool" 2; then
    pass "tools/list carries $tool"
  else
    fail "tools/list carries $tool" "status $(code)" "$tmp/body"
  fi
  local msg="smoke-$sfx"
  rpc "$url" "$hdrfile" "$(rpc_body 3 tools/call "{\"name\":\"$tool\",\"arguments\":{\"message\":\"$msg\"}}")" "$idfile" "$hs_session" "$v"
  expect success yes "$tool"
  if [ "$(code)" != 200 ]; then
    fail "tools/call $tool is 200" "status $(code)" "$tmp/body"
    return 1
  fi
  proof_checks "$label" "$tmp/body" 3 "$msg"
}

# wait_rows KEY_ID IDSFILE OUT: polls the key's rows until every id in the
# file has one, or 15 s pass.
wait_rows() {
  local deadline=$((SECONDS + 15)) missing=""
  while :; do
    api GET "/api/v1/logs?virtual_key_id=$1&limit=100"
    cp "$tmp/body" "$3"
    missing="$(py missing "$3" "$2")"
    if [ "$missing" = 0 ]; then
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "rows for every request id" "$missing of $(wc -l < "$2") ids have no row after 15 s"
      return 1
    fi
    sleep 0.2
  done
}

# wait_blocked RID OUT: polls the blocked rows since the run start until
# the revoked call's row appears, or 15 s pass.
wait_blocked() {
  local deadline=$((SECONDS + 15))
  while :; do
    api GET "/api/v1/logs?status=blocked&since=$since&limit=50"
    cp "$tmp/body" "$2"
    if grep -qF "\"$1\"" "$2"; then
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "the revoked call has a blocked row" "no row with its request id after 15 s"
      return 1
    fi
    sleep 0.2
  done
}

# full_teardown deletes what run_full created, by recorded id, keys first,
# then the group, then the upstreams, and compares the counts with the
# start. It repairs nothing.
full_teardown() {
  if [ -z "$before" ]; then
    return 0
  fi
  say teardown
  local ok=1 id
  for id in $k1 $k2 $k3; do
    api DELETE "/api/v1/virtual-keys/$id"
    case "$(code)" in 200|204) ;; *) ok=""; fail "delete key" "status $(code)" "$tmp/body" ;; esac
  done
  if [ -n "$grp" ]; then
    api DELETE "/api/v1/groups/$grp"
    case "$(code)" in 200|204) ;; *) ok=""; fail "delete group" "status $(code)" "$tmp/body" ;; esac
  fi
  for id in $up_mcp $up_http; do
    api DELETE "/api/v1/upstreams/$id"
    case "$(code)" in 200|204) ;; *) ok=""; fail "delete upstream" "status $(code)" "$tmp/body" ;; esac
  done
  if [ -n "$ok" ]; then
    pass "keys, group and upstreams deleted"
  fi
  local after
  after="$(count_all)"
  if [ "$after" = "$before" ]; then
    pass "counts match the start ($after)"
  else
    fail "counts match the start" "before: $before; after: $after"
  fi
}

run_full() {
  say register
  : > "$tmp/expect"
  : > "$tmp/ids.revoked"
  BEARER_SHA="$(sha "Bearer $BEARER")"
  QVALUE_SHA="$(sha "$QVALUE")"
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  before="$(count_all)"
  local slug_mcp="smoke_mcp_$sfx" slug_http="smoke_api_$sfx" slug_grp="smoke_grp_$sfx"
  create "mcp upstream" /api/v1/upstreams "$(py body "name=$slug_mcp" "slug=$slug_mcp" kind=mcp "url=$STUB_URL/mcp" transport=streamable-http auth_type=bearer "auth_config=@{\"token\":\"$BEARER\"}")" up_mcp || return
  create "http upstream" /api/v1/upstreams "$(py body "name=$slug_http" "slug=$slug_http" kind=http "url=$STUB_URL/v1" test_path=/ok auth_type=query "auth_config=@{\"param\":\"api_key\",\"value\":\"$QVALUE\"}")" up_http || return
  create group /api/v1/groups "$(py body "name=$slug_grp" "upstream_ids=@[\"$up_mcp\",\"$up_http\"]")" grp || return
  api POST "/api/v1/upstreams/$up_mcp/discover" "" 30
  if [ "$(code)" = 200 ] && [ "$(jget "$tmp/body" ok)" = true ] && grep -qF '"echo"' "$tmp/body"; then
    pass "discovery of the mcp upstream lists echo"
  else
    fail "discovery of the mcp upstream lists echo" "status $(code)" "$tmp/body"
  fi
  api POST "/api/v1/upstreams/$up_http/discover" "" 30
  if [ "$(code)" = 200 ] && [ "$(jget "$tmp/body" ok)" = true ]; then
    pass "discovery of the http upstream is ok"
  else
    fail "discovery of the http upstream is ok" "status $(code)" "$tmp/body"
  fi
  mint "mcp key" "$(py body "name=${slug_mcp}_key" target_type=upstream "target_id=$up_mcp")" 1 || return
  mint "group key" "$(py body "name=${slug_grp}_key" target_type=group "target_id=$grp")" 2 || return
  mint "http key" "$(py body "name=${slug_http}_key" target_type=upstream "target_id=$up_http")" 3 || return
  pass "three keys minted"

  mcp_door "mcp single" "$SMOKE_BASE/$k1/mcp" "$tmp/hdr.k1" "$tmp/ids.k1" echo 1 yes

  say "mcp shared"
  if handshake "$SMOKE_BASE/mcp" "$tmp/hdr.k1" "$tmp/ids.k1" "mcp shared" 1 1 && [ "$hs_version" = 2025-11-25 ]; then
    echo "$(tail -n 2 "$tmp/ids.k1" | head -n 1) success yes -" >> "$tmp/expect"
    echo "$(tail -n 1 "$tmp/ids.k1") success yes -" >> "$tmp/expect"
    pass "initialize on /mcp with the bearer answers protocolVersion 2025-11-25 and a session"
    rpc "$SMOKE_BASE/mcp" "$tmp/hdr.k1" "$(rpc_body 2 tools/list)" "$tmp/ids.k1" "$hs_session" "$hs_version"
    expect success yes -
    if [ "$(code)" = 200 ] && py has_tool "$tmp/body" echo 2; then
      pass "tools/list carries echo"
    else
      fail "tools/list carries echo" "status $(code)" "$tmp/body"
    fi
    del "$SMOKE_BASE/mcp" "$tmp/hdr.k1" "$hs_session"
    case "$(code)" in
      2*|405) pass "DELETE with the session answered $(code)" ;;
      *) fail "DELETE with the session is accepted" "status $(code)" "$tmp/body" ;;
    esac
  fi

  mcp_door "mcp group" "$SMOKE_BASE/$k2/mcp" "$tmp/hdr.k2" "$tmp/ids.k2" "${slug_mcp}__echo" "" no
  mcp_door "mcp member" "$SMOKE_BASE/$k2/$slug_mcp/mcp" "$tmp/hdr.k2" "$tmp/ids.k2" echo 1 yes

  say relay
  relay "/$k3/api/ok?api_key=spoof&page=2" "$tmp/hdr.k3" "$tmp/ids.k3"
  expect success yes /ok
  if [ "$(code)" = 200 ] && [ "$(jget "$tmp/body" proof.page)" = 2 ]; then
    pass "GET /api/ok is 200 with page=2"
  else
    fail "GET /api/ok is 200 with page=2" "status $(code)" "$tmp/body"
  fi
  if [ "$(jget "$tmp/body" proof.cred_count)" = 1 ] && [ "$(jget "$tmp/body" proof.cred_sha256)" = "$QVALUE_SHA" ] \
    && [ "$(jget "$tmp/body" proof.spoof)" = false ] && [ "$(jget "$tmp/body" proof.auth_count)" = 0 ] \
    && [ "$(jget "$tmp/body" proof.pory_seen)" = false ]; then
    pass "the stub saw the stored query value once, spoof never, and no Authorization"
  else
    fail "the stub saw the stored query value once, spoof never, and no Authorization" "cred_count $(jget "$tmp/body" proof.cred_count), spoof $(jget "$tmp/body" proof.spoof), auth_count $(jget "$tmp/body" proof.auth_count), pory_seen $(jget "$tmp/body" proof.pory_seen)"
  fi
  relay "/$k3/api/json401" "$tmp/hdr.k3" "$tmp/ids.k3"
  expect error yes /json401
  if [ "$(code)" = 401 ] && grep -qF '[redacted]' "$tmp/body" && ! grep -qF "$QVALUE" "$tmp/body"; then
    pass "GET /api/json401 is 401 with [redacted] and not the stored value"
  else
    fail "GET /api/json401 is 401 with [redacted] and not the stored value" "status $(code)" "$tmp/body"
  fi

  say revoke
  api POST "/api/v1/virtual-keys/$k3/revoke"
  if [ "$(code)" = 200 ]; then
    relay "/$k3/api/ok" "$tmp/hdr.k3" "$tmp/ids.revoked"
    if [ "$(code)" = 401 ]; then
      pass "the revoked key answers 401"
    else
      fail "the revoked key answers 401" "status $(code)" "$tmp/body"
    fi
  else
    fail "revoke is 200" "status $(code)" "$tmp/body"
  fi

  say audit
  wait_rows "$k1" "$tmp/ids.k1" "$tmp/rows.k1"
  wait_rows "$k2" "$tmp/ids.k2" "$tmp/rows.k2"
  wait_rows "$k3" "$tmp/ids.k3" "$tmp/rows.k3"
  wait_blocked "$(cat "$tmp/ids.revoked")" "$tmp/rows.blocked"
  api GET /api/v1/admin-events
  cp "$tmp/body" "$tmp/admin_events"
  local line
  while IFS= read -r line; do
    case "$line" in
      PASS\ *) pass "${line#PASS }" ;;
      FAIL\ *) line="${line#FAIL }"; fail "${line%%: *}" "${line#*: }" ;;
    esac
  done < <(py audit "$tmp" "$(cat "$tmp/ids.revoked")")
}

# teardown runs once, on every exit path: the full section's deletes, the
# summary line, then the temp directory.
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
  if handshake "$SMOKE_BASE/mcp" "$tmp/hdr.deploy" "$tmp/ids.deploy" "deploy key" "" 1; then
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
# echo stub.
if [ -n "$ADMIN_API_KEY" ] && [ -n "$STUB_URL" ]; then
  if [ -z "$loopback" ]; then
    echo "skip: the full section runs against a loopback instance only"
  else
    run_full
  fi
else
  echo "skip: the full section needs ADMIN_API_KEY and STUB_URL"
fi
