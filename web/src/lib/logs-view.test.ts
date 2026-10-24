import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError, type LogFacets } from './api.ts'
import {
  ALL_METHODS,
  ALL_STATUSES,
  ALL_TOOLS,
  countLine,
  counted,
  customPrefill,
  customProblems,
  DEFAULT_FILTERS,
  FACET_CAP,
  type FacetAnswer,
  facetCut,
  facetFetchDue,
  facetQuery,
  facetsFor,
  fromLocalInput,
  fromToolChoice,
  LOG_READ_TIMEOUT,
  type LogFilters,
  listErrorMessage,
  logQuery,
  methodOptions,
  NONE_CHOICE,
  statusOptions,
  toolChoice,
  toolOptions,
  logWindow,
  NO_LOGS,
  PERIODS,
  pagePath,
  SLOW_CALLS,
  SLOW_CHANGES,
  SLOW_QUERY,
  toLocalInput,
  untilFromLocalInput,
  upstreamCell,
} from './logs-view.ts'
import { ABSENT } from './placeholder.ts'

// CI's web job runs in UTC, where local time and UTC agree and a bug that reads
// a datetime-local value as UTC passes. Node applies a TZ set at runtime, so
// every case below runs in New York (UTC-5 in winter, UTC-4 in summer).
process.env.TZ = 'America/New_York'

test('the zone is New York for the rest of this file', () => {
  assert.equal(new Date(2026, 0, 15).getTimezoneOffset(), 300)
})

const custom = (patch: Partial<LogFilters>): LogFilters => ({ ...DEFAULT_FILTERS, period: 'custom', ...patch })

// S3 and the frozen window: a preset is a since measured from the anchor,
// never a sliding now, and no until, because the cursor bounds every later page.
test('logWindow: a preset sends since only, from the anchor', () => {
  const anchor = Date.UTC(2026, 9, 21, 12, 0, 0)
  assert.deepEqual(logWindow(DEFAULT_FILTERS, anchor), { since: '2026-10-14T12:00:00.000Z' })
  assert.deepEqual(logWindow({ ...DEFAULT_FILTERS, period: '24h' }, anchor), { since: '2026-10-20T12:00:00.000Z' })
  assert.deepEqual(logWindow({ ...DEFAULT_FILTERS, period: '30d' }, anchor), { since: '2026-09-21T12:00:00.000Z' })
})

// Criterion 3 and S4: both inputs are local time; 09:30 in New York in October
// (UTC-4) is 13:30Z, which a UTC reading would get wrong by four hours.
test('logWindow: Custom reads both inputs as local time', () => {
  const f = custom({ since: '2026-10-21T09:30', until: '2026-10-20T00:00' })
  assert.deepEqual(logWindow(f, 0), {
    since: '2026-10-21T13:30:00.000Z',
    until: '2026-10-20T04:00:59.999999999Z',
  })
  assert.equal(fromLocalInput('2026-10-21T09:30'), new Date(2026, 9, 21, 9, 30).toISOString())
})

test('untilFromLocalInput: the last nanosecond of the minute, also for a value with seconds', () => {
  assert.equal(untilFromLocalInput('2026-10-21T14:30'), '2026-10-21T18:30:59.999999999Z')
  assert.equal(untilFromLocalInput('2026-10-21T14:30:15'), '2026-10-21T18:30:59.999999999Z')
  assert.equal(untilFromLocalInput('2026-01-15T14:30'), '2026-01-15T19:30:59.999999999Z')
  assert.equal(untilFromLocalInput(''), undefined)
})

test('fromLocalInput: empty or unparseable is undefined, never a throw', () => {
  for (const v of ['', 'garbage', '2026-13-45T99:99', '2026-10-21']) {
    assert.equal(fromLocalInput(v), undefined, v)
    assert.equal(untilFromLocalInput(v), undefined, v)
  }
})

test('customProblems: empty Since, incomplete input, Until before Since', () => {
  assert.deepEqual(customProblems(DEFAULT_FILTERS), {})
  assert.deepEqual(customProblems(custom({})), { since: 'Enter a start time.' })
  assert.deepEqual(customProblems(custom({ sinceBad: true })), { since: 'Enter a full date and time.' })
  assert.deepEqual(customProblems(custom({ since: '2026-10-21T00:00', untilBad: true })), {
    until: 'Enter a full date and time.',
  })
  assert.deepEqual(customProblems(custom({ since: '2026-10-21T00:00', until: '2026-10-20T00:00' })), {
    until: 'Until is earlier than Since.',
  })
  assert.deepEqual(customProblems(custom({ since: '2026-10-21T00:00', until: '2026-10-21T00:00' })), {})
})

test('logQuery: null for a Custom problem; fixed order; no limit or cursor', () => {
  assert.equal(logQuery(custom({}), 0), null)
  assert.equal(logQuery(custom({ since: '2026-10-21T00:00', untilBad: true }), 0), null)
  // An Until before Since is still sent: the server answers the empty page criterion 3 names.
  assert.notEqual(logQuery(custom({ since: '2026-10-21T00:00', until: '2026-10-20T00:00' }), 0), null)
  const anchor = Date.UTC(2026, 9, 21, 12, 0, 0)
  const q = logQuery({ ...DEFAULT_FILTERS, status: 'error', virtual_key_id: 'k1', tool: 'search', method: 'tools/call' }, anchor)
  assert.equal(q, 'virtual_key_id=k1&method=tools%2Fcall&tool=search&status=error&since=2026-10-14T12%3A00%3A00.000Z')
  const none = logQuery({ ...DEFAULT_FILTERS, status: 'error', virtual_key_id: 'k1', noTool: true, method: 'tools/call' }, anchor)
  assert.equal(none, 'virtual_key_id=k1&method=tools%2Fcall&has_tool=false&status=error&since=2026-10-14T12%3A00%3A00.000Z')
})

test('logQuery: None sends has_tool=false and never tool', () => {
  const q = new URLSearchParams(logQuery({ ...DEFAULT_FILTERS, noTool: true, tool: 'echo' }, 0) ?? '')
  assert.deepEqual(q.getAll('has_tool'), ['false'])
  assert.deepEqual(q.getAll('tool'), [])
  assert.deepEqual(new URLSearchParams(logQuery(DEFAULT_FILTERS, 0) ?? '').getAll('has_tool'), [])
})

test('facetQuery: key, status and window only, and the same string when only Method or Tool changes', () => {
  const anchor = Date.UTC(2026, 9, 21, 12, 0, 0)
  const f = { ...DEFAULT_FILTERS, virtual_key_id: 'k1', status: 'error' }
  const q = facetQuery(f, anchor)
  assert.equal(q, 'virtual_key_id=k1&status=error&since=2026-10-14T12%3A00%3A00.000Z')
  assert.equal(facetQuery({ ...f, method: 'tools/call' }, anchor), q)
  assert.equal(facetQuery({ ...f, tool: 'echo' }, anchor), q)
  assert.equal(facetQuery({ ...f, noTool: true }, anchor), q)
  assert.notEqual(facetQuery({ ...f, status: '' }, anchor), q)
  assert.equal(facetQuery(custom({}), 0), null)
  assert.equal(logQuery(custom({}), 0), null)
})

// S6 and S7: the three kinds of value cannot collide, whatever an upstream
// names its tool, and a name stays one tool value on the wire.
test('toolChoice and fromToolChoice round-trip for None, none, tool:, None (no tool) and x&has_tool=false&limit=200', () => {
  for (const tool of ['None', 'none', 'tool:', 'None (no tool)', 'x&has_tool=false&limit=200']) {
    const v = toolChoice({ tool, noTool: false })
    assert.notEqual(v, NONE_CHOICE)
    assert.notEqual(v, '')
    assert.deepEqual(fromToolChoice(v), { tool, noTool: false })
    const q = new URLSearchParams(logQuery({ ...DEFAULT_FILTERS, tool }, 0) ?? '')
    assert.deepEqual(q.getAll('tool'), [tool])
    assert.deepEqual(q.getAll('has_tool'), [])
    assert.deepEqual(q.getAll('limit'), [])
  }
  assert.deepEqual(fromToolChoice(toolChoice({ tool: '', noTool: true })), { tool: '', noTool: true })
  assert.deepEqual(fromToolChoice(toolChoice({ tool: '', noTool: false })), { tool: '', noTool: false })
  assert.equal(toolChoice({ tool: '', noTool: true }), NONE_CHOICE)
})

const facetsOf = (patch: Partial<LogFacets>): LogFacets => ({ methods: [], tools: [], statuses: [], truncated: false, ...patch })
const noPick = { tool: '', noTool: false }

test("toolOptions: None first with its count, then the API's order", () => {
  const f = facetsOf({ tools: [{ value: 'firecrawl_scrape', count: 30 }, { value: '', count: 5 }, { value: 'fetch', count: 2 }] })
  assert.deepEqual(toolOptions(f, noPick), [
    { value: '', label: ALL_TOOLS },
    { value: NONE_CHOICE, label: counted(ABSENT, 5) },
    { value: 'tool:firecrawl_scrape', label: counted('firecrawl_scrape', 30) },
    { value: 'tool:fetch', label: counted('fetch', 2) },
  ])
  // No calls without a tool: no None, unless it is the current choice.
  const named = facetsOf({ tools: [{ value: 'fetch', count: 2 }] })
  assert.deepEqual(toolOptions(named, noPick).map((o) => o.value), ['', 'tool:fetch'])
  assert.deepEqual(toolOptions(named, { tool: '', noTool: true }).slice(0, 2), [
    { value: '', label: ALL_TOOLS },
    { value: NONE_CHOICE, label: ABSENT },
  ])
})

test('toolOptions: a named tool None gives the empty option the (no tool) suffix, decided by the name as shown', () => {
  const f = facetsOf({ tools: [{ value: '', count: 5 }, { value: 'None', count: 3 }] })
  const opts = toolOptions(f, noPick)
  assert.deepEqual(opts[1], { value: NONE_CHOICE, label: counted(`${ABSENT} (no tool)`, 5) })
  assert.deepEqual(opts[2], { value: 'tool:None', label: counted('None', 3) })
  // A name that shows as None once its bidi controls are dropped, or its ends
  // trimmed, gets the suffix too; its value keeps the raw name.
  for (const name of ['\u202eNone', '\u2066None\u2069', ' None ']) {
    const lookalike = toolOptions(facetsOf({ tools: [{ value: '', count: 5 }, { value: name, count: 3 }] }), noPick)
    assert.equal(lookalike[1].label, counted(`${ABSENT} (no tool)`, 5), JSON.stringify(name))
    assert.equal(lookalike[2].value, `tool:${name}`)
  }
  // A name that only contains None does not.
  assert.equal(toolOptions(facetsOf({ tools: [{ value: '', count: 5 }, { value: 'None2', count: 3 }] }), noPick)[1].label, counted(ABSENT, 5))
  // The suffix also follows a kept, bare selection named None.
  assert.equal(toolOptions(facetsOf({ tools: [{ value: '', count: 1 }] }), { tool: 'None', noTool: false })[1].label, counted(`${ABSENT} (no tool)`, 1))
})

// PORM-149 criterion 7: a selected value the new list does not hold stays,
// with no count, until the operator changes it; S9: with no facets at all the
// selects keep All and the current choice.
test('methodOptions and toolOptions: a selected value not in the list stays last, bare', () => {
  const f = facetsOf({ methods: [{ value: 'tools/list', count: 1 }], tools: [{ value: 'fetch', count: 2 }] })
  assert.deepEqual(methodOptions(f, 'tools/call').at(-1), { value: 'tools/call', label: 'tools/call' })
  assert.deepEqual(toolOptions(f, { tool: 'echo', noTool: false }).at(-1), { value: 'tool:echo', label: 'echo' })
  assert.equal(methodOptions(f, 'tools/list').length, 2)
  assert.deepEqual(methodOptions(null, 'tools/call'), [
    { value: '', label: ALL_METHODS },
    { value: 'tools/call', label: 'tools/call' },
  ])
  assert.deepEqual(toolOptions(null, { tool: 'echo', noTool: false }), [
    { value: '', label: ALL_TOOLS },
    { value: 'tool:echo', label: 'echo' },
  ])
  assert.deepEqual(toolOptions(null, { tool: '', noTool: true }), [
    { value: '', label: ALL_TOOLS },
    { value: NONE_CHOICE, label: ABSENT },
  ])
})

test('methodOptions: an empty method is not offered', () => {
  const f = facetsOf({ methods: [{ value: 'tools/call', count: 4 }, { value: '', count: 2 }] })
  assert.deepEqual(methodOptions(f, ''), [
    { value: '', label: ALL_METHODS },
    { value: 'tools/call', label: counted('tools/call', 4) },
  ])
})

test('statusOptions: fixed order, counts with 0 for an absent status, bare without facets', () => {
  const f = facetsOf({ statuses: [{ value: 'error', count: 4 }, { value: 'success', count: 40 }] })
  assert.deepEqual(statusOptions(f), [
    { value: '', label: ALL_STATUSES },
    { value: 'success', label: counted('Success', 40) },
    { value: 'error', label: counted('Error', 4) },
    { value: 'blocked', label: counted('Blocked', 0) },
  ])
  assert.deepEqual(statusOptions(null).map((o) => o.label), [ALL_STATUSES, 'Success', 'Error', 'Blocked'])
})

test('facetCut: only a list of 200 under truncated', () => {
  const full = Array.from({ length: FACET_CAP }, (_, i) => ({ value: `t${i}`, count: 1 }))
  assert.equal(facetCut(facetsOf({ tools: full, truncated: true }), 'tools'), true)
  assert.equal(facetCut(facetsOf({ tools: full, truncated: true }), 'methods'), false)
  assert.equal(facetCut(facetsOf({ tools: full }), 'tools'), false)
  assert.equal(facetCut(facetsOf({ tools: full.slice(1), truncated: true }), 'tools'), false)
  assert.equal(facetCut(null, 'tools'), false)
})

// S20: an upstream-chosen name cannot carry a bidi control into the option
// text, so the count always reads after the name.
test('counted: a name holding U+202E, and one holding U+2069 then U+202E, cannot reorder the count', () => {
  assert.equal(counted('fetch', 3), '\u2068fetch\u2069 (3)')
  for (const name of ['ab\u202ecd', 'ab\u2069\u202ecd', '\u2066x\u2067y\u2068z\u202a\u202b\u202c\u202d']) {
    const label = counted(name, 7)
    const inner = label.slice(1, label.indexOf('\u2069'))
    assert.equal(/[\u202a-\u202e\u2066-\u2069]/.test(inner), false, `controls left in ${JSON.stringify(label)}`)
    assert.ok(label.startsWith('\u2068'))
    assert.ok(label.endsWith('\u2069 (7)'))
    assert.equal(label.split('\u2069').length, 2, 'exactly one closing isolate')
  }
})

test('facetFetchDue: not before the list answers or the wait ends; never twice for one fq; never for null', () => {
  assert.equal(facetFetchDue(null, 'q', false, false), false)
  assert.equal(facetFetchDue(null, 'q', true, false), true)
  assert.equal(facetFetchDue(null, 'q', false, true), true)
  assert.equal(facetFetchDue('q', 'q', true, true), false)
  assert.equal(facetFetchDue('old', 'q', true, false), true)
  assert.equal(facetFetchDue(null, null, true, true), false)
})

test('facetsFor: an answer for an older fq gives nothing', () => {
  const facets = facetsOf({ methods: [{ value: 'ping', count: 1 }] })
  const answer: FacetAnswer = { fq: 'old', facets, error: '' }
  assert.deepEqual(facetsFor(answer, 'new'), { facets: null, error: '' })
  assert.deepEqual(facetsFor(answer, 'old'), { facets, error: '' })
  assert.deepEqual(facetsFor({ fq: 'q', facets: null, error: 'slow' }, 'q'), { facets: null, error: 'slow' })
  assert.deepEqual(facetsFor(null, 'q'), { facets: null, error: '' })
  assert.deepEqual(facetsFor(answer, null), { facets: null, error: '' })
})

// S1 and S2: a typed value cannot add a limit or a cursor of its own.
test('logQuery and pagePath keep a typed value whole', () => {
  const tool = '/a+b&limit=200#x%'
  const q = logQuery({ ...DEFAULT_FILTERS, tool }, 0)
  assert.ok(q !== null)
  const parsed = new URLSearchParams(q)
  assert.deepEqual(parsed.getAll('tool'), [tool])
  assert.deepEqual(parsed.getAll('limit'), [])
  const path = pagePath('/logs', q, '')
  const sent = new URLSearchParams(path.slice('/logs?'.length))
  assert.deepEqual(sent.getAll('tool'), [tool])
  assert.deepEqual(sent.getAll('limit'), ['50'])
  assert.deepEqual(sent.getAll('cursor'), [])
})

// Criterion 1: every page asks for 50 rows; a Load more adds the cursor.
test('pagePath: limit 50 always, cursor only when set', () => {
  assert.equal(pagePath('/logs', '', ''), '/logs?limit=50')
  assert.equal(pagePath('/admin-events', 'resource_type=upstream', 'abc'), '/admin-events?resource_type=upstream&limit=50&cursor=abc')
})

test('toLocalInput: round-trips through fromLocalInput', () => {
  const ms = new Date(2026, 9, 21, 9, 5).getTime()
  assert.equal(toLocalInput(ms), '2026-10-21T09:05')
  assert.equal(fromLocalInput(toLocalInput(ms)), new Date(ms).toISOString())
})

test('customPrefill: the current preset start, or what Custom already holds', () => {
  const anchor = new Date(2026, 9, 21, 9, 5).getTime()
  assert.equal(customPrefill(DEFAULT_FILTERS, anchor), '2026-10-14T09:05')
  assert.equal(customPrefill({ ...DEFAULT_FILTERS, period: '24h' }, anchor), '2026-10-20T09:05')
  assert.equal(customPrefill(custom({ since: '2026-01-01T00:00' }), anchor), '2026-01-01T00:00')
})

// Criterion 4 and S5: the name and slug when listed, the placeholder with no
// upstream, the full id on a miss or when the list could not be read.
test('upstreamCell: absent, loading, name and slug, the id on a miss or a failed list', () => {
  const names = new Map([['u1', { name: 'Docs', slug: 'docs' }]])
  assert.deepEqual(upstreamCell(undefined, names, false), { kind: 'absent' })
  assert.deepEqual(upstreamCell('', names, false), { kind: 'absent' })
  assert.deepEqual(upstreamCell('u1', null, false), { kind: 'loading' })
  assert.deepEqual(upstreamCell('u1', names, false), { kind: 'name', name: 'Docs', slug: 'docs' })
  assert.deepEqual(upstreamCell('u2', names, false), { kind: 'id', id: 'u2' })
  assert.deepEqual(upstreamCell('u1', null, true), { kind: 'id', id: 'u1' })
})

test('countLine: null, more, last for calls and for changes, refused; 1 call vs 2 calls', () => {
  assert.equal(countLine(50, 'call', null), '')
  assert.equal(countLine(150, 'call', 'more'), '150 calls shown.')
  assert.equal(countLine(1, 'call', 'more'), '1 call shown.')
  assert.equal(countLine(137, 'call', 'last'), '137 calls shown. No older calls in this period.')
  assert.equal(countLine(137, 'change', 'last'), '137 changes shown. No older changes.')
  assert.equal(countLine(2, 'change', 'refused'), '2 changes shown.')
})

test('DEFAULT_FILTERS: Last 7 days', () => {
  assert.equal(DEFAULT_FILTERS.period, '7d')
  assert.equal(PERIODS.find((p) => p.value === DEFAULT_FILTERS.period)?.label, 'Last 7 days')
  assert.equal(NO_LOGS, 'No matching log entries.')
})

// S18: the mapping keys on 503 and the server's exact text, so the upstream
// busy and OAuth 503s, an edge proxy's 503, and every other status keep the
// house mapper's words.
test("listErrorMessage: the deadline's 503 gets the table's sentence; another 503 and a 500 keep the server text; a TypeError gets the network sentence", () => {
  assert.equal(SLOW_QUERY['/logs'], SLOW_CALLS)
  assert.equal(SLOW_QUERY['/admin-events'], SLOW_CHANGES)
  assert.equal(listErrorMessage(new ApiError(503, LOG_READ_TIMEOUT), SLOW_CALLS), SLOW_CALLS)
  assert.equal(listErrorMessage(new ApiError(503, LOG_READ_TIMEOUT), SLOW_CHANGES), SLOW_CHANGES)
  assert.equal(listErrorMessage(new ApiError(503, 'upstream is busy'), SLOW_CALLS), 'upstream is busy')
  assert.equal(listErrorMessage(new ApiError(500, LOG_READ_TIMEOUT), SLOW_CALLS), LOG_READ_TIMEOUT)
  assert.equal(listErrorMessage(new ApiError(500, 'internal error'), SLOW_CALLS), 'internal error')
  assert.equal(
    listErrorMessage(new TypeError('Failed to fetch'), SLOW_CALLS),
    'Could not reach PoryMCP. Check that the server is still running.',
  )
})
