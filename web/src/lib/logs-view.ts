import type { PageEnd } from './cursor-pages.ts'
import { plural } from './plural.ts'

/**
 * The Logs page's period, query and copy (PORM-20), kept apart from the markup
 * so `node --test` can reach them. Times typed into the Custom inputs are the
 * browser's local time and become RFC 3339 here; the server's parser stays
 * strict, because reading a zone-less time there would use the server's zone
 * and shift the window without a word.
 */

export const PAGE_SIZE = 50

export const PERIODS = [
  { value: '24h', label: 'Last 24 hours', hours: 24 },
  { value: '7d', label: 'Last 7 days', hours: 168 },
  { value: '30d', label: 'Last 30 days', hours: 720 },
  { value: 'custom', label: 'Custom', hours: 0 },
] as const

export type Period = (typeof PERIODS)[number]['value']

/**
 * The Proxy calls filters as the controls hold them. `since` and `until` are
 * the raw datetime-local values and `sinceBad`/`untilBad` that input's
 * `validity.badInput`; all four are read only for Custom.
 */
export type LogFilters = {
  virtual_key_id: string
  method: string
  tool: string
  status: string
  period: Period
  since: string
  until: string
  sinceBad: boolean
  untilBad: boolean
}

export const DEFAULT_FILTERS: LogFilters = {
  virtual_key_id: '',
  method: '',
  tool: '',
  status: '',
  period: '7d',
  since: '',
  until: '',
  sinceBad: false,
  untilBad: false,
}

export const LOAD_MORE_CALLS = 'Load more calls'
export const LOAD_MORE_CHANGES = 'Load more changes'
export const LOADING_MORE = 'Loading…'
export const NO_LOGS = 'No matching log entries.'
export const NOT_LISTED = 'Not in the upstream list.'
export const SINCE_MISSING = 'Enter a start time.'
export const INPUT_INCOMPLETE = 'Enter a full date and time.'
export const UNTIL_BEFORE_SINCE = 'Until is earlier than Since.'

const HOUR_MS = 3_600_000

// A datetime-local value: a date, a T, hours and minutes, optional seconds.
// A date alone would parse as UTC, not local time, so it is not accepted.
const LOCAL_INPUT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/

function parseLocal(v: string): Date | undefined {
  if (!LOCAL_INPUT.test(v)) return undefined
  // A date-time with no offset is local time (ES spec). A local time that does
  // not exist (a daylight-saving gap) moves forward; an ambiguous one takes the
  // earlier offset.
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? undefined : d
}

/** A Since value as RFC 3339 for the API; undefined when empty or unparseable, never a throw. */
export function fromLocalInput(v: string): string | undefined {
  return parseLocal(v)?.toISOString()
}

/**
 * An Until value as RFC 3339, at the last nanosecond of the picked minute, so
 * "Until 10:00" keeps a call at 10:00:30 (until is inclusive and exact). Works
 * for a value that already carries seconds.
 */
export function untilFromLocalInput(v: string): string | undefined {
  const d = parseLocal(v)
  if (!d) return undefined
  d.setSeconds(59, 999)
  return d.toISOString().replace(/\.999Z$/, '.999999999Z')
}

/** An instant as a datetime-local value in local time, to the minute. */
export function toLocalInput(ms: number): string {
  const d = new Date(ms)
  const two = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}`
}

function presetHours(period: Period): number {
  return PERIODS.find((p) => p.value === period)?.hours ?? 0
}

/**
 * The window a filter set asks for. A preset sends since only, measured from
 * the anchor (the moment the filters last changed, never a Load more), so the
 * window does not slide under an open cursor; the cursor bounds every later
 * page from above. Custom sends what the two inputs hold.
 */
export function logWindow(f: LogFilters, anchor: number): { since?: string; until?: string } {
  if (f.period === 'custom') return { since: fromLocalInput(f.since), until: untilFromLocalInput(f.until) }
  return { since: new Date(anchor - presetHours(f.period) * HOUR_MS).toISOString() }
}

/** What Since holds when the period switches to Custom: the current preset's start, so the switch does not widen the window. */
export function customPrefill(f: LogFilters, anchor: number): string {
  if (f.period === 'custom') return f.since
  return toLocalInput(anchor - presetHours(f.period) * HOUR_MS)
}

/** The message each Custom input shows, if any. */
export function customProblems(f: LogFilters): { since?: string; until?: string } {
  if (f.period !== 'custom') return {}
  const out: { since?: string; until?: string } = {}
  const since = fromLocalInput(f.since)
  if (f.sinceBad) out.since = INPUT_INCOMPLETE
  else if (!since) out.since = SINCE_MISSING
  const until = untilFromLocalInput(f.until)
  if (f.untilBad) out.until = INPUT_INCOMPLETE
  else if (since && until && Date.parse(until) < Date.parse(since)) out.until = UNTIL_BEFORE_SINCE
  return out
}

/**
 * The /logs query for a filter set, or null when nothing should be sent: a
 * Custom period with no usable start, or an Until the browser could not read.
 * An Until earlier than Since is still sent; the server answers an empty page.
 * Built with URLSearchParams in a fixed order, never by concatenation, so a
 * typed value such as `x&limit=200` stays one tool value. No limit or cursor:
 * pagePath adds those.
 */
export function logQuery(f: LogFilters, anchor: number): string | null {
  if (f.period === 'custom' && (customProblems(f).since || f.untilBad)) return null
  const q = new URLSearchParams()
  if (f.virtual_key_id) q.set('virtual_key_id', f.virtual_key_id)
  if (f.method) q.set('method', f.method)
  if (f.tool) q.set('tool', f.tool)
  if (f.status) q.set('status', f.status)
  const { since, until } = logWindow(f, anchor)
  if (since) q.set('since', since)
  if (until) q.set('until', until)
  return q.toString()
}

/** One page's path: the query, limit 50, and the cursor when there is one. */
export function pagePath(path: string, query: string, cursor: string): string {
  const q = new URLSearchParams(query)
  q.set('limit', String(PAGE_SIZE))
  if (cursor) q.set('cursor', cursor)
  return `${path}?${q}`
}

export type UpstreamName = { name: string; slug: string }

export type UpstreamCell =
  | { kind: 'absent' }
  | { kind: 'loading' }
  | { kind: 'name'; name: string; slug: string }
  | { kind: 'id'; id: string }

/**
 * What the Log detail dialog shows for a row's upstream. The name is the
 * upstream's current one, from the list fetched when the page opened. A miss
 * (deleted, or created after the page opened) or a failed list shows the full
 * id, which is what joins the row to admin events and the server log.
 */
export function upstreamCell(
  id: string | undefined,
  names: ReadonlyMap<string, UpstreamName> | null,
  failed: boolean,
): UpstreamCell {
  if (!id) return { kind: 'absent' }
  if (failed) return { kind: 'id', id }
  if (names === null) return { kind: 'loading' }
  const hit = names.get(id)
  return hit ? { kind: 'name', name: hit.name, slug: hit.slug } : { kind: 'id', id }
}

/**
 * The line under a table: how many rows are shown and, on the last page, that
 * nothing older matched. Empty while the rows are not the current query's
 * answer, so it never describes rows fetched for another filter.
 */
export function countLine(n: number, noun: 'call' | 'change', end: PageEnd | null): string {
  if (end === null) return ''
  const shown = `${plural(n, noun)} shown.`
  if (end !== 'last') return shown
  return noun === 'call' ? `${shown} No older calls in this period.` : `${shown} No older changes.`
}
