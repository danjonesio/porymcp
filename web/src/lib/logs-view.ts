import { ApiError, type LogFacets, requestErrorMessage } from './api.ts'
import type { PageEnd, PagedPath } from './cursor-pages.ts'
import { ABSENT } from './placeholder.ts'
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
  /** None is chosen in the Tool select: has_tool=false, and tool is ''. */
  noTool: boolean
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
  noTool: false,
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

/** The server's text for a read its deadline stopped (internal/api/helpers.go errLogReadTimeout). */
export const LOG_READ_TIMEOUT = 'log query took too long'
export const SLOW_CALLS = 'This query took too long. Choose a shorter period or a narrower filter.'
export const SLOW_CHANGES = 'This query took too long. Choose All resources or reload the page.'
export const SLOW_FACETS = 'Counting the calls in this period took too long. Choose a shorter period or a virtual key.'
/** The sentence each paged table shows for a read its deadline stopped (PORM-224). */
export const SLOW_QUERY: Record<PagedPath, string> = { '/logs': SLOW_CALLS, '/admin-events': SLOW_CHANGES }

/**
 * One sentence for a failed audit read: the deadline's own copy, then the
 * house mapper. Keyed on 503 and the exact server text, so another 503 (an
 * upstream that is busy, an OAuth step, an edge proxy in front of PoryMCP)
 * keeps its own words.
 */
export function listErrorMessage(err: unknown, slow: string): string {
  if (err instanceof ApiError && err.status === 503 && err.message === LOG_READ_TIMEOUT) return slow
  return requestErrorMessage(err)
}

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
 * value such as `x&limit=200` stays one tool value. None sends has_tool=false
 * and never a tool. No limit or cursor: pagePath adds those.
 */
export function logQuery(f: LogFilters, anchor: number): string | null {
  if (f.period === 'custom' && (customProblems(f).since || f.untilBad)) return null
  const q = new URLSearchParams()
  if (f.virtual_key_id) q.set('virtual_key_id', f.virtual_key_id)
  if (f.method) q.set('method', f.method)
  if (f.noTool) q.set('has_tool', 'false')
  else if (f.tool) q.set('tool', f.tool)
  if (f.status) q.set('status', f.status)
  const { since, until } = logWindow(f, anchor)
  if (since) q.set('since', since)
  if (until) q.set('until', until)
  return q.toString()
}

/**
 * The /logs/facets query for a filter set: the virtual key, status and window
 * only (PORM-149), so a Method or Tool pick leaves it the same string. Null
 * exactly when logQuery is.
 */
export function facetQuery(f: LogFilters, anchor: number): string | null {
  return logQuery({ ...f, method: '', tool: '', noTool: false }, anchor)
}

export const ALL_METHODS = 'All methods'
export const ALL_TOOLS = 'All tools'
export const ALL_STATUSES = 'All statuses'
export const NO_TOOL = 'no tool'
/** The store's cap on each facet list (internal/store facetCap). */
export const FACET_CAP = 200
export const FACET_CUT = 'The 200 most frequent are listed. The API accepts any exact value.'
export const STATUSES = [
  { value: 'success', label: 'Success' },
  { value: 'error', label: 'Error' },
  { value: 'blocked', label: 'Blocked' },
] as const
/** The Tool select's value for None. A named tool's value is 'tool:' + its name, so no name can equal it or ''. */
export const NONE_CHOICE = 'none'
/** How long the facet request waits for the rows' first answer before it starts anyway, so a slow list and the facet walk share one deadline window. */
export const FACET_WAIT_MS = 250

export type FilterOption = { value: string; label: string }
/** A facet answer or failure, tagged with the facet query it answers. */
export type FacetAnswer = { fq: string; facets: LogFacets | null; error: string }

const NAMED_TOOL = 'tool:'

/** The Tool select's value for a filter set: '' for All, NONE_CHOICE, or 'tool:' + the name. */
export function toolChoice(f: Pick<LogFilters, 'tool' | 'noTool'>): string {
  if (f.noTool) return NONE_CHOICE
  return f.tool ? NAMED_TOOL + f.tool : ''
}

/** The filters a Tool select value stands for; the inverse of toolChoice. */
export function fromToolChoice(v: string): Pick<LogFilters, 'tool' | 'noTool'> {
  if (v === NONE_CHOICE) return { tool: '', noTool: true }
  if (v.startsWith(NAMED_TOOL)) return { tool: v.slice(NAMED_TOOL.length), noTool: false }
  return { tool: '', noTool: false }
}

// The bidi embedding, override and isolate controls, U+202A to U+202E and
// U+2066 to U+2069.
const BIDI_CONTROLS = /[\u202a-\u202e\u2066-\u2069]/g

/**
 * 'name (n)'. Bidi controls (U+202A to U+202E, U+2066 to U+2069) are dropped
 * from the name, which then sits between U+2068 and U+2069, so an
 * upstream-chosen name cannot reorder the count. An `<option>` cannot hold a
 * `<bdi>`, so the isolate is written into the text. The option's value keeps
 * the raw name.
 */
export function counted(label: string, count: number): string {
  return `\u2068${label.replace(BIDI_CONTROLS, '')}\u2069 (${count})`
}

/**
 * The Method select's options: All methods, then each recorded method in the
 * API's order with its count. '' (rows from before v0.1.0) is never offered,
 * because method= cannot select it. A selected method the list does not hold
 * is added last, bare, so the filter stays visible until it is changed.
 */
export function methodOptions(facets: LogFacets | null, selected: string): FilterOption[] {
  const out: FilterOption[] = [{ value: '', label: ALL_METHODS }]
  for (const e of facets?.methods ?? []) {
    if (e.value) out.push({ value: e.value, label: counted(e.value, e.count) })
  }
  if (selected && !out.some((o) => o.value === selected)) out.push({ value: selected, label: selected })
  return out
}

/**
 * The Tool select's options: All tools; None first when the window holds
 * calls with no tool or None is chosen, counted when listed; then the named
 * tools in the API's order, counted; a selected tool the list does not hold
 * last, bare. When a rendered tool shows as None, the empty option reads
 * `None (no tool)` so the two differ. That is decided on the tool's name as
 * its option shows it (bidi controls dropped, as `counted` drops them, and the
 * ends trimmed, as an option's text is), never on a label's text, so a name
 * such as U+202E then None cannot pass for the empty option.
 */
export function toolOptions(facets: LogFacets | null, f: Pick<LogFilters, 'tool' | 'noTool'>): FilterOption[] {
  const named: FilterOption[] = []
  const names: string[] = []
  let empty: number | undefined
  for (const e of facets?.tools ?? []) {
    if (e.value === '') empty = e.count
    else {
      named.push({ value: NAMED_TOOL + e.value, label: counted(e.value, e.count) })
      names.push(e.value)
    }
  }
  if (f.tool && !f.noTool && !named.some((o) => o.value === NAMED_TOOL + f.tool)) {
    named.push({ value: NAMED_TOOL + f.tool, label: f.tool })
    names.push(f.tool)
  }
  const out: FilterOption[] = [{ value: '', label: ALL_TOOLS }]
  if (empty !== undefined || f.noTool) {
    const clash = names.some((n) => n.replace(BIDI_CONTROLS, '').trim() === ABSENT)
    const label = clash ? `${ABSENT} (${NO_TOOL})` : ABSENT
    out.push({ value: NONE_CHOICE, label: empty === undefined ? label : counted(label, empty) })
  }
  return out.concat(named)
}

/** The Status select's options: All statuses, then the three in a fixed order, counted (0 when absent) once facets arrive, bare before. */
export function statusOptions(facets: LogFacets | null): FilterOption[] {
  const out: FilterOption[] = [{ value: '', label: ALL_STATUSES }]
  for (const s of STATUSES) {
    const count = facets?.statuses.find((e) => e.value === s.value)?.count ?? 0
    out.push({ value: s.value, label: facets ? counted(s.label, count) : s.label })
  }
  return out
}

/** Whether the cut sentence goes under a list: the answer was truncated and this list holds the cap. */
export function facetCut(facets: LogFacets | null, list: 'methods' | 'tools'): boolean {
  return facets?.truncated === true && facets[list].length === FACET_CAP
}

/** Whether the facet request for fq should start now. */
export function facetFetchDue(heldFq: string | null, fq: string | null, listAnswered: boolean, waited: boolean): boolean {
  return fq !== null && heldFq !== fq && (listAnswered || waited)
}

/** The facets and error for the current fq, from an answer that may belong to an older one. */
export function facetsFor(answer: FacetAnswer | null, fq: string | null): { facets: LogFacets | null; error: string } {
  return answer !== null && answer.fq === fq ? { facets: answer.facets, error: answer.error } : { facets: null, error: '' }
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
