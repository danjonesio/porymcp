#!/usr/bin/env bash
# edge-deploy.sh redeploys the deployment that follows edge and waits for it
# to finish (PORM-220). The deploy job in .github/workflows/ci.yml runs it on
# main, after publish and both verify legs. It reads its inputs from the
# environment only:
#
#   DEPLOY_WEBHOOK_URL    the deploy webhook of the deployment that follows edge
#   DEPLOY_TOKEN          an API token that may deploy and read deployments
#   EDGE_DEPLOY_INTERVAL  seconds between polls, default 10 (set by the test only)
#   EDGE_DEPLOY_BUDGET    seconds to wait in all, default 600 (set by the test only)
#
# With neither secret set it prints a notice and exits 0, so a fork or a copy
# of the repository stays green. Otherwise it exits 0 only when the platform
# reports the deployment finished, and 1 on anything else. It never prints
# the webhook URL, the token, the status record's logs, or what curl and jq
# write to stderr: both secrets reach curl in a config on stdin and never on
# its command line, and the script refuses to run under xtrace. Platform text
# reaches the log as printable ASCII after a fixed prefix, and the step
# summary carries only the deployment id and a known status.
set -u
case $- in *x*)
  echo 'FAIL input: xtrace is on; a trace prints keys' >&2
  exit 1
  ;;
esac
set +x
umask 077
export LC_ALL=C

url="${DEPLOY_WEBHOOK_URL:-}"
token="${DEPLOY_TOKEN:-}"
interval="${EDGE_DEPLOY_INTERVAL:-10}"
budget="${EDGE_DEPLOY_BUDGET:-600}"

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "$1" >>"$GITHUB_STEP_SUMMARY"
  fi
}

# fail REASON: the FAIL line and exit 1. Under Actions the annotation is fixed
# text, because the reason can carry platform text.
fail() {
  echo "FAIL $1"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo '::error title=edge-deploy::the deploy failed; see the step log'
  fi
  exit 1
}

# not_started REASON [DETAIL]: a failure before the platform gave an id. The
# summary takes the fixed reason only; the log line adds the detail.
not_started() {
  summary "Deploy not started: $1"
  fail "$1${2:-}"
}

if [ -z "$url" ] && [ -z "$token" ]; then
  echo 'edge-deploy: no deployment is configured; nothing requested'
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo '::notice title=edge-deploy::no deployment is configured'
  fi
  summary 'No deployment is configured; nothing was requested'
  exit 0
fi
[ -n "$token" ] || not_started 'input: DEPLOY_WEBHOOK_URL is set and DEPLOY_TOKEN is not'
[ -n "$url" ] || not_started 'input: DEPLOY_TOKEN is set and DEPLOY_WEBHOOK_URL is not'

# Both values go inside quoted values in curl's config. The token set and the
# URL rule leave no quote, backslash, space or control character, so nothing
# needs escaping there and no value can add a line to the config.
if ! [[ $token =~ ^[A-Za-z0-9._~+/=|-]+$ ]]; then
  not_started 'input: DEPLOY_TOKEN has a character outside the token set'
fi
if [[ $url =~ [^[:graph:]] ]] || [[ $url == *[\"\\]* ]] || [[ $url != *://* ]]; then
  not_started 'input: DEPLOY_WEBHOOK_URL is not a URL'
fi
# The origin, for the status route. It is never printed: GitHub masks the
# secret itself, not a string cut from it.
scheme="${url%%://*}"
rest="${url#*://}"
authority="${rest%%[/?#]*}"
# Userinfo is refused before the loopback test, so 127.0.0.1:80@host does not
# pass as loopback.
if [ -z "$authority" ] || [[ $authority == *@* ]]; then
  not_started 'input: DEPLOY_WEBHOOK_URL has no host or has userinfo'
fi
# https only, so the token never travels in clear. Plain http is for a
# loopback stub, which is how the test runs the script.
case "$scheme" in
https) proto='=https' ;;
http)
  case "$authority" in
  127.0.0.1 | 127.0.0.1:* | localhost | localhost:*) proto='=http,https' ;;
  *) not_started 'input: DEPLOY_WEBHOOK_URL is not an https URL' ;;
  esac
  ;;
*) not_started 'input: DEPLOY_WEBHOOK_URL is not an https URL' ;;
esac
origin="$scheme://$authority"

# The test knobs may only shorten the defaults, and the interval is never 0.
if ! [[ $interval =~ ^(10|[0-9](\.[0-9]+)?)$ ]] || [[ $interval =~ ^0(\.0*)?$ ]]; then
  not_started 'input: EDGE_DEPLOY_INTERVAL is not a number of seconds from 0.01 to 10'
fi
if ! [[ $budget =~ ^[0-9]{1,3}$ ]] || ((10#$budget < 1 || 10#$budget > 600)); then
  not_started 'input: EDGE_DEPLOY_BUDGET is not a number of seconds from 1 to 600'
fi
budget=$((10#$budget))

tmp="$(mktemp -d)"
# Every line tolerates failure, so the trap never replaces the exit status.
cleanup() {
  rm -rf "$tmp" || true
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# call METHOD URL: one request. The body lands in $tmp/body, which is never
# printed, and the status code in $code; curl's own failure leaves code 000
# and its exit status in $curl_exit.
call() {
  : >"$tmp/body"
  curl_exit=0
  # -q first: curl then reads no curlrc, so a user's verbose, location or
  # trace setting cannot reach a run. No -L, so a redirect is never followed
  # and the token never reaches a second host.
  code="$(printf 'url = "%s"\nheader = "Authorization: Bearer %s"\nheader = "Accept: application/json"\nrequest = "%s"\n' "$2" "$token" "$1" |
    curl -q -K - --proto "$proto" -sS --connect-timeout 10 --max-time 30 -o "$tmp/body" -w '%{http_code}' 2>/dev/null)" || curl_exit=$?
}

# field PATH: one field of the last body, empty when the body is not JSON or
# has another shape.
field() {
  jq -r "$1 // empty" "$tmp/body" 2>/dev/null || true
}

# clean: printable ASCII without %, at most 200 bytes. This drops newlines,
# escapes and the runner's %0A form, so platform text cannot start a line or
# a workflow command.
clean() {
  tr -cd '\040-\044\046-\176' | head -c 200
}

call POST "$url"
if [ "$curl_exit" -ne 0 ]; then
  not_started "deploy: request failed (curl exit $curl_exit)"
fi
case "$code" in
2??) ;;
*)
  msg="$(field .message | clean)"
  not_started "deploy: HTTP $code" "${msg:+: $msg}"
  ;;
esac
id="$(field '.deployments[0].deployment_uuid')"
msg="$(field '.deployments[0].message' | clean)"
# The id goes into the status URL, so it is checked before any use.
if ! [[ $id =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
  not_started 'deploy: the answer has no valid deployment id' "${msg:+: $msg}"
fi
echo "deploy: requested $id${msg:+: $msg}"

# finish STATUS: the summary line. Only a known status reaches it.
finish() {
  case "$1" in
  queued | in_progress | finished | failed | cancelled-by-user) summary "Deployment \`$id\`: $1" ;;
  *) summary "Deployment \`$id\`: unknown" ;;
  esac
}

# A 401, 403 or 404 on a poll will not change by waiting. Anything else that
# is not an answer (a 5xx, a curl error, a 2xx with no status) is recorded and
# the loop keeps waiting until the budget.
start=$SECONDS
status="" shown="" last_err="no answer yet"
while ((SECONDS - start < budget)); do
  sleep "$interval"
  call GET "$origin/api/v1/deployments/$id"
  if [ "$curl_exit" -ne 0 ]; then
    last_err="request failed (curl exit $curl_exit)"
    continue
  fi
  case "$code" in
  2??) ;;
  401 | 403 | 404)
    finish unknown
    msg="$(field .message | clean)"
    fail "deploy: $id: HTTP $code${msg:+: $msg}"
    ;;
  *)
    last_err="HTTP $code"
    continue
    ;;
  esac
  s="$(field .status)"
  if [ -z "$s" ]; then
    last_err="no status in the answer"
    continue
  fi
  last_err=""
  status="$s"
  case "$s" in
  finished)
    finish finished
    echo "PASS deploy: $id finished"
    exit 0
    ;;
  failed | cancelled-by-user)
    finish "$s"
    fail "deploy: $id $s"
    ;;
  esac
  now="$(printf '%s' "$s" | clean)"
  if [ "$now" != "$shown" ]; then
    echo "deploy: $id status $now"
    shown="$now"
  fi
done

finish "$status"
if [ -n "$last_err" ]; then
  fail "deploy: $id did not finish in ${budget}s; last error $last_err"
fi
fail "deploy: $id did not finish in ${budget}s; last status $shown"
