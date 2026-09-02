/** Which of the three things the Status cell's second line says. */
export type TestTone = 'never' | 'passed' | 'failed'

/**
 * One rendered line: the word, and — when there is a test to point at — the
 * relative label and the exact instant for `<time dateTime>`. `ago` and `at` are
 * both null or both set; `never` is the only tone with neither.
 */
export type TestState = { tone: TestTone; word: string; ago: string | null; at: string | null }

const MINUTE = 60
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const MONTH = 30 * DAY
const YEAR = 365 * DAY

/**
 * How long ago an instant was, in the fewest characters that still read as
 * English: `just now`, `3m ago`, `2h ago`, `5d ago`, `7mo ago`, `2y ago`.
 *
 * Deterministic and hand-rolled rather than Intl.RelativeTimeFormat: the narrow
 * forms are locale data supplied by the runtime, so a test would pin Node's ICU
 * while the cell renders the browser's, and this would be the first Intl use in
 * web/src. A ladder is a dozen lines and asserts exact strings.
 *
 * Each step rounds on its own unit and is bounded on the rounded count, not on
 * the raw next unit, so the label changes at the halfway point of the unit it is
 * about to show and a rung never prints the next unit's full count on its way
 * out: 59 min 30 s is "1h ago", not "60m ago". Anything under 45 seconds — a
 * future timestamp included, because clock skew between the server and the
 * browser must never print "in 2m" — is "just now".
 *
 * `iso` must be a timestamp Date.parse understands; testState is the only caller
 * and it checks that first.
 */
export function relativeTime(iso: string, nowMs: number): string {
  const s = (nowMs - Date.parse(iso)) / 1000
  if (s < 45) return 'just now'
  if (s < 90) return '1m ago'
  const m = Math.round(s / MINUTE)
  if (m < 60) return `${m}m ago`
  const h = Math.round(s / HOUR)
  if (h < 24) return `${h}h ago`
  const d = Math.round(s / DAY)
  if (d < 30) return `${d}d ago`
  const mo = Math.round(s / MONTH)
  if (mo < 12) return `${mo}mo ago`
  return `${Math.round(s / YEAR)}y ago`
}

/**
 * The one rule behind the Status cell's second line: a test exists only when
 * `last_test_at` parses and `last_test_ok` is a real boolean. Either field null,
 * or a timestamp only a hand-edited database could hold, is "Not tested" — a row
 * nobody tested through PoryMCP can never show a green dot.
 *
 * The two fields are written together by POST /upstreams/{id}/discover and NULLed
 * together by a connection edit, so this reads them as one fact rather than two.
 */
export function testState(
  u: { last_test_at: string | null; last_test_ok: boolean | null },
  nowMs: number
): TestState {
  const at = u.last_test_at
  if (!at || Number.isNaN(Date.parse(at)) || typeof u.last_test_ok !== 'boolean') {
    return { tone: 'never', word: 'Not tested', ago: null, at: null }
  }
  return {
    tone: u.last_test_ok ? 'passed' : 'failed',
    word: u.last_test_ok ? 'Passed' : 'Failed',
    ago: relativeTime(at, nowMs),
    at,
  }
}
