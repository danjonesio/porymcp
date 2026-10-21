import assert from 'node:assert/strict'
import test from 'node:test'
import {
  countLine,
  customPrefill,
  customProblems,
  DEFAULT_FILTERS,
  fromLocalInput,
  type LogFilters,
  logQuery,
  logWindow,
  NO_LOGS,
  PERIODS,
  pagePath,
  toLocalInput,
  untilFromLocalInput,
  upstreamCell,
} from './logs-view.ts'

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
