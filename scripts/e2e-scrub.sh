#!/usr/bin/env bash
# e2e-scrub.sh makes a Playwright HTML report fit to upload from a job that
# holds the admin key. A trace records every request header, every input
# value and every action argument, and the report embeds its data as a base64
# zip, so a plain grep over the files sees nothing. This script decodes every
# layer, withholds the forms the tree already withholds elsewhere (KEY_RE and
# scrub() in scripts/smoke.sh, addKeyForms in cmd/server/binary_test.go, the
# sed in the docker job's failure step; the four lists move together), and
# then checks the result with unzip, base64 and grep, which share no code with
# the rewrite. It prints counts and fixed lines, never a value or a path.
#
#   ADMIN_API_KEY=... ENCRYPTION_KEY=... bash scripts/e2e-scrub.sh <report-dir> <results-dir>
#   ADMIN_API_KEY=... ENCRYPTION_KEY=... bash scripts/e2e-scrub.sh --self-test
#
# Exit 0 only when the check finds nothing after the rewrite and every zip and
# trace line still reads. The self-test plants the keys at every layer in a
# throwaway report, requires the check to catch them, then requires the
# rewrite to remove them.
set -u
case $- in *x*)
  echo 'FAIL input: xtrace is on; a trace prints keys' >&2
  exit 1
  ;;
esac
set +x
umask 077

[ -n "${ADMIN_API_KEY:-}" ] || { echo 'FAIL input: ADMIN_API_KEY is not set' >&2; exit 1; }
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"
export ADMIN_API_KEY ENCRYPTION_KEY
for tool in python3 base64 grep; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL input: $tool is not installed" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/scrub.py" <<'PY'
import base64
import io
import json
import os
import re
import sys
import zipfile

ADMIN = os.environ.get('ADMIN_API_KEY', '')
ENC = os.environ.get('ENCRYPTION_KEY', '')
WITHHELD = b'<withheld>'
KEY_RE = re.compile(rb'pory_[0-9a-f]{16,}')
HEX64_RE = re.compile(rb'[0-9a-f]{64}')
LITERAL_RE = re.compile(rb'(smokeplain|e2eplain)(alpha|bravo)')
TEMPLATE_RE = re.compile(
    rb'(<template id="playwrightReportBase64">data:application/zip;base64,)([^<]*)(</template>)', re.S)
counts = {'keys': 0, 'shapes': 0, 'literals': 0}


def key_forms():
    forms = []
    for k in (ADMIN, ENC):
        if not k:
            continue
        kb = k.encode()
        forms += [kb, kb.upper(), base64.b64encode(kb)]
    if ADMIN:
        forms.append(ADMIN[:12].encode())
    # Longest first, so a whole key is withheld before its own prefix is.
    return sorted(set(forms), key=len, reverse=True)


FORMS = key_forms()


def is_zip(data):
    return data[:4] == b'PK\x03\x04'


def rewrite_bytes(data):
    for form in FORMS:
        n = data.count(form)
        if n:
            counts['keys'] += n
            data = data.replace(form, WITHHELD)
    data, n = KEY_RE.subn(WITHHELD, data)
    counts['shapes'] += n
    data, n = HEX64_RE.subn(WITHHELD, data)
    counts['shapes'] += n
    data, n = LITERAL_RE.subn(WITHHELD, data)
    counts['literals'] += n
    return data


def rewrite_zip(data):
    try:
        src = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return rewrite_bytes(data)
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            body = src.read(info)
            body = rewrite_zip(body) if is_zip(body) else rewrite_bytes(body)
            ni = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            ni.compress_type = zipfile.ZIP_DEFLATED
            ni.external_attr = info.external_attr
            dst.writestr(ni, body)
    return out.getvalue()


def rewrite_html(data):
    def repl(m):
        return m.group(1) + base64.b64encode(rewrite_zip(base64.b64decode(m.group(2)))) + m.group(3)
    return rewrite_bytes(TEMPLATE_RE.sub(repl, data))


def files(dirs):
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for root, _, names in os.walk(d):
            for n in sorted(names):
                yield os.path.join(root, n)


def rewrite(dirs):
    for p in files(dirs):
        with open(p, 'rb') as f:
            data = f.read()
        if p.endswith('index.html'):
            new = rewrite_html(data)
        elif p.endswith('.zip') or is_zip(data):
            new = rewrite_zip(data)
        else:
            new = rewrite_bytes(data)
        if new != data:
            with open(p, 'wb') as f:
                f.write(new)
    print('scrub: key forms %d, pory shapes %d, literals %d' % (counts['keys'], counts['shapes'], counts['literals']))


def check_zip(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    if z.testzip() is not None:
        raise ValueError('a zip entry is damaged')
    for info in z.infolist():
        body = z.read(info)
        if is_zip(body):
            check_zip(body)
        elif info.filename.endswith(('.trace', '.network')):
            for line in body.split(b'\n'):
                if line.strip():
                    json.loads(line)


def valid(dirs):
    for p in files(dirs):
        with open(p, 'rb') as f:
            data = f.read()
        if p.endswith('index.html'):
            for m in TEMPLATE_RE.finditer(data):
                check_zip(base64.b64decode(m.group(2)))
        elif p.endswith('.zip') or is_zip(data):
            check_zip(data)


def zip_bytes(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, body in entries:
            z.writestr(name, body)
    return out.getvalue()


def build_selftest(report, results):
    # A throwaway report that carries the keys at every layer a real one can:
    # the base64 template, a trace's after event, a resource, a nested zip and
    # a plain file.
    admin = ADMIN.encode()
    enc = (ENC or ADMIN).encode()
    fake_key = b'pory_' + b'ab' * 32
    trace = b'\n'.join([
        json.dumps({'type': 'after', 'callId': 'c1', 'result': {'k': ADMIN, 'v': ENC or ADMIN}}).encode(),
        b'{"type":"log","message":"e2eplainalpha"}',
        json.dumps({'type': 'action', 'title': 'Fill "%s"' % ADMIN}).encode(),
    ]) + b'\n'
    inner = zip_bytes([('trace.trace', trace), ('trace.network', b'{"h":"Bearer %s"}\n' % admin),
                       ('resources/' + '0' * 40, fake_key + b' ' + base64.b64encode(admin))])
    nested = zip_bytes([('inner.zip', inner)])
    report_zip = zip_bytes([('report.json', json.dumps({'title': 'Fill "%s"' % ADMIN, 'b64': base64.b64encode(admin).decode()}).encode())])
    os.makedirs(os.path.join(report, 'data'), exist_ok=True)
    with open(os.path.join(report, 'index.html'), 'wb') as f:
        f.write(b'<html><template id="playwrightReportBase64">data:application/zip;base64,' +
                base64.b64encode(report_zip) + b'</template><p>' + enc.upper() + b'</p></html>')
    with open(os.path.join(report, 'data', '1' * 40 + '.zip'), 'wb') as f:
        f.write(inner)
    with open(os.path.join(report, 'data', '2' * 40 + '.zip'), 'wb') as f:
        f.write(nested)
    os.makedirs(os.path.join(results, 'x'), exist_ok=True)
    with open(os.path.join(results, 'x', 'trace.zip'), 'wb') as f:
        f.write(inner)
    with open(os.path.join(results, 'x', 'error-context.md'), 'wb') as f:
        f.write(b'# error\n' + admin + b'\n')


try:
    mode, dirs = sys.argv[1], sys.argv[2:]
    if mode == 'rewrite':
        rewrite(dirs)
    elif mode == 'valid':
        valid(dirs)
    elif mode == 'build-selftest':
        build_selftest(dirs[0], dirs[1])
    else:
        raise ValueError('unknown mode')
except Exception:
    print('the scrub failed')
    sys.exit(1)
PY

# The fixed strings the check greps for: each key raw, upper-case and base64.
write_patterns() {
  : > "$tmp/fixed"
  for k in "$ADMIN_API_KEY" "$ENCRYPTION_KEY"; do
    [ -n "$k" ] || continue
    printf '%s\n' "$k" "$(printf '%s' "$k" | tr 'a-f' 'A-F')" "$(printf '%s' "$k" | base64 -w0)" >> "$tmp/fixed"
  done
}

# unzip where it exists (the CI runner has it), else bsdtar, else python's own
# zipfile command line; the first two share no code with the rewrite, the last
# shares the library and not the rewrite's code.
extract_zip() {
  mkdir -p "$2"
  if command -v unzip >/dev/null 2>&1; then
    unzip -o -qq "$1" -d "$2" 2>/dev/null
  elif command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xf "$1" -C "$2" 2>/dev/null
  else
    python3 -m zipfile -e "$1" "$2" 2>/dev/null
  fi
  return 0
}

# Copies a directory and opens every layer with tools other than the rewrite:
# the base64 template with base64 -d, every zip (nested ones too) with
# extract_zip.
extract_all() {
  local src="$1" out="$2" pass z
  mkdir -p "$out"
  cp -r "$src"/. "$out"/ 2>/dev/null || return 0
  find "$out" -name index.html -type f | while IFS= read -r f; do
    grep -o 'id="playwrightReportBase64">data:application/zip;base64,[A-Za-z0-9+/=]*' "$f" 2>/dev/null |
      sed 's/^.*base64,//' | base64 -d > "$f.report.zip" 2>/dev/null || true
  done
  for pass in 1 2 3 4; do
    find "$out" -name '*.zip' -type f | while IFS= read -r z; do
      extract_zip "$z" "$z.d"
      mv "$z" "$z.opened"
    done
    [ -n "$(find "$out" -name '*.zip' -type f | head -n 1)" ] || break
  done
}

# Returns 1 when any decoded byte still carries a key form, a pory_ shape or
# one of the stored-credential words.
check() {
  local x="$tmp/check"
  rm -rf "$x"
  mkdir -p "$x"
  extract_all "$1" "$x/report"
  [ -d "$2" ] && extract_all "$2" "$x/results"
  if grep -rqF -f "$tmp/fixed" "$x" 2>/dev/null; then return 1; fi
  if grep -rqE 'pory_[0-9a-f]{16,}|(smokeplain|e2eplain)(alpha|bravo)' "$x" 2>/dev/null; then return 1; fi
  return 0
}

scrub() {
  local report="$1" results="$2"
  [ -d "$report" ] || { echo 'FAIL input: the report directory is missing' >&2; return 1; }
  write_patterns
  python3 "$tmp/scrub.py" rewrite "$report" "$results" || return 1
  check "$report" "$results" || { echo 'the report still carries a key'; return 1; }
  python3 "$tmp/scrub.py" valid "$report" "$results" || { echo 'the report is not readable after the rewrite'; return 1; }
  return 0
}

self_test() {
  local report="$tmp/st/report" results="$tmp/st/results" counts
  python3 "$tmp/scrub.py" build-selftest "$report" "$results" || { echo 'self-test: could not build the report'; return 1; }
  write_patterns
  if check "$report" "$results"; then
    echo 'self-test: the check missed a planted key'
    return 1
  fi
  counts="$(python3 "$tmp/scrub.py" rewrite "$report" "$results")" || { echo 'self-test: the rewrite failed'; return 1; }
  echo "$counts"
  case "$counts" in
    *'key forms 0'*|*'pory shapes 0'*|*'literals 0'*) echo 'self-test: a planted form was not counted'; return 1 ;;
  esac
  check "$report" "$results" || { echo 'self-test: a planted key survived the rewrite'; return 1; }
  python3 "$tmp/scrub.py" valid "$report" "$results" || { echo 'self-test: the report is not readable after the rewrite'; return 1; }
  echo 'self-test: ok'
  return 0
}

case "${1:-}" in
  --self-test) self_test ;;
  *)
    [ $# -eq 2 ] || { echo 'usage: e2e-scrub.sh <report-dir> <results-dir> | --self-test' >&2; exit 1; }
    scrub "$1" "$2"
    ;;
esac
