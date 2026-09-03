import assert from 'node:assert/strict'
import test from 'node:test'
import { ABSENT, LOADING } from './placeholder.ts'

// Run with: npm test (node --test). The .ts extension above is required; see
// discovery.test.ts.

// PORM-130: a typed space collapses the Overview tile, U+00A0 does not, and
// the two look the same in an editor. Pin the code point.
test('LOADING is exactly one non-breaking space', () => {
  assert.equal(LOADING.length, 1)
  assert.equal(LOADING.charCodeAt(0), 0xa0)
})

test('ABSENT is the word the groups table already renders', () => {
  assert.equal(ABSENT, 'None')
})
