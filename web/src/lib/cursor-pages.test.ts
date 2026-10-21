import assert from 'node:assert/strict'
import test from 'node:test'
import {
  afterMoreFailure,
  appended,
  emptyPages,
  exposedEnd,
  firstPage,
  nextRequest,
  showEmpty,
  startQuery,
} from './cursor-pages.ts'

// S1: rows, the end and the next request belong to the query that produced them.
test('a first page replaces the rows and is exposed only for its own query', () => {
  const p = firstPage('status=error', ['a', 'b'], 'c1')
  assert.deepEqual(p.rows, ['a', 'b'])
  assert.equal(exposedEnd(p, 'status=error'), 'more')
  assert.equal(exposedEnd(p, 'status=success'), null)
  assert.equal(exposedEnd(firstPage('q', ['a'], ''), 'q'), 'last')
})

// S1: a filter change keeps the old rows on screen but claims nothing about
// them, so a Load more in flight for the old query has nothing to land in.
test('startQuery keeps the rows and exposes no end', () => {
  const p = startQuery(firstPage('q1', ['a', 'b'], 'c1'))
  assert.deepEqual(p.rows, ['a', 'b'])
  assert.equal(exposedEnd(p, 'q1'), null)
  assert.equal(exposedEnd(p, 'q2'), null)
  assert.equal(nextRequest(p, 'q1'), null)
  assert.equal(nextRequest(p, 'q2'), null)
})

test('showEmpty is false after a failed first page and while a new query is pending', () => {
  // A failed first page leaves the page set as it was: nothing answered yet.
  assert.equal(showEmpty(emptyPages<string>(), 'q'), false)
  // An empty answer for the old query, then a new query still in flight.
  assert.equal(showEmpty(startQuery(firstPage<string>('q1', [], '')), 'q2'), false)
  // The current query answered with nothing.
  assert.equal(showEmpty(firstPage<string>('q2', [], ''), 'q2'), true)
  assert.equal(showEmpty(firstPage('q2', ['a'], ''), 'q2'), false)
})

test('appended adds rows and takes the new cursor', () => {
  const p = appended(firstPage('q', ['a', 'b'], 'c1'), ['c'], '')
  assert.deepEqual(p.rows, ['a', 'b', 'c'])
  assert.equal(p.cursor, '')
  assert.equal(exposedEnd(p, 'q'), 'last')
  assert.equal(exposedEnd(appended(firstPage('q', ['a'], 'c1'), ['b'], 'c2'), 'q'), 'more')
})

test('a 400 after Load more refuses and clears the cursor', () => {
  const p = afterMoreFailure(firstPage('q', ['a'], 'c1'), 400)
  assert.equal(exposedEnd(p, 'q'), 'refused')
  assert.equal(p.cursor, '')
  assert.equal(nextRequest(p, 'q'), null)
})

test('a 503 after Load more keeps the cursor', () => {
  const before = firstPage('q', ['a'], 'c1')
  assert.equal(afterMoreFailure(before, 503), before)
  assert.equal(afterMoreFailure(before, undefined), before)
  assert.deepEqual(nextRequest(before, 'q'), { query: 'q', cursor: 'c1' })
})

test('nextRequest is null unless the exposed end is more, and carries the frozen query', () => {
  assert.equal(nextRequest(emptyPages(), 'q'), null)
  assert.equal(nextRequest(firstPage('q', ['a'], ''), 'q'), null)
  assert.equal(nextRequest(firstPage('q1', ['a'], 'c1'), 'q2'), null)
  assert.deepEqual(nextRequest(firstPage('since=x', ['a'], 'c1'), 'since=x'), { query: 'since=x', cursor: 'c1' })
})
