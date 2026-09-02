import assert from 'node:assert/strict'
import test from 'node:test'
import { relativeTime, testState } from './upstream-test.ts'

// Run with: npm test (node --test). The .ts extension above is required —
// Node will not resolve an extensionless TypeScript specifier; tsconfig.json
// sets allowImportingTsExtensions so tsc accepts them.

const NOW = Date.parse('2026-08-29T14:00:00.000Z')
const SECOND = 1000
const MINUTE = 60 * SECOND
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

/** The ISO string a test recorded `ms` milliseconds before NOW. A negative value is in the future. */
function ago(ms: number): string {
  return new Date(NOW - ms).toISOString()
}

test('testState reports Not tested when neither field is set', () => {
  assert.deepEqual(testState({ last_test_at: null, last_test_ok: null }, NOW), {
    tone: 'never',
    word: 'Not tested',
    ago: null,
    at: null,
  })
})

test('testState reports Not tested when the outcome is missing', () => {
  // Both columns are written together, so this is a row no PoryMCP write produced.
  assert.equal(testState({ last_test_at: ago(3 * MINUTE), last_test_ok: null }, NOW).tone, 'never')
})

test('testState reports Not tested when the timestamp does not parse', () => {
  // A hand-edited database can never show a green dot.
  assert.deepEqual(testState({ last_test_at: 'yesterday', last_test_ok: true }, NOW), {
    tone: 'never',
    word: 'Not tested',
    ago: null,
    at: null,
  })
})

test('testState reports a passed test with its instant and its relative label', () => {
  const at = ago(3 * MINUTE)
  assert.deepEqual(testState({ last_test_at: at, last_test_ok: true }, NOW), {
    tone: 'passed',
    word: 'Passed',
    ago: '3m ago',
    at,
  })
})

test('testState reports a failed test the same way', () => {
  const at = ago(2 * HOUR)
  assert.deepEqual(testState({ last_test_at: at, last_test_ok: false }, NOW), {
    tone: 'failed',
    word: 'Failed',
    ago: '2h ago',
    at,
  })
})

test('relativeTime climbs one rung at a time', () => {
  assert.equal(relativeTime(ago(5 * SECOND), NOW), 'just now')
  assert.equal(relativeTime(ago(44 * SECOND), NOW), 'just now')
  assert.equal(relativeTime(ago(45 * SECOND), NOW), '1m ago')
  assert.equal(relativeTime(ago(89 * SECOND), NOW), '1m ago')
  assert.equal(relativeTime(ago(90 * SECOND), NOW), '2m ago')
  assert.equal(relativeTime(ago(59 * MINUTE), NOW), '59m ago')
  assert.equal(relativeTime(ago(60 * MINUTE), NOW), '1h ago')
  assert.equal(relativeTime(ago(23 * HOUR), NOW), '23h ago')
  assert.equal(relativeTime(ago(24 * HOUR), NOW), '1d ago')
  assert.equal(relativeTime(ago(29 * DAY), NOW), '29d ago')
  assert.equal(relativeTime(ago(30 * DAY), NOW), '1mo ago')
  assert.equal(relativeTime(ago(11 * 30 * DAY), NOW), '11mo ago')
  assert.equal(relativeTime(ago(365 * DAY), NOW), '1y ago')
})

test('relativeTime rounds up into the next rung rather than printing a full unit', () => {
  // Each rung is bounded on its rounded count, so the tail of one reads as the
  // head of the next: no '60m ago', '24h ago', '30d ago' or '12mo ago'.
  assert.equal(relativeTime(ago(59 * MINUTE + 30 * SECOND), NOW), '1h ago')
  assert.equal(relativeTime(ago(23 * HOUR + 45 * MINUTE), NOW), '1d ago')
  assert.equal(relativeTime(ago(29 * DAY + 13 * HOUR), NOW), '1mo ago')
  assert.equal(relativeTime(ago(345 * DAY), NOW), '1y ago')
})

test('relativeTime never counts forwards', () => {
  // Clock skew between the server that stamped the row and the browser rendering
  // it must not print "in 10s".
  assert.equal(relativeTime(ago(-10 * SECOND), NOW), 'just now')
})
