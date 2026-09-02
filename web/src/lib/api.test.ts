import assert from 'node:assert/strict'
import test from 'node:test'
import { retryAfterSeconds } from './api.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier; tsconfig.json
// sets allowImportingTsExtensions so tsc accepts it.

test('retryAfterSeconds reads the delta-seconds form PoryMCP sends', () => {
  assert.equal(retryAfterSeconds('3'), 3)
  assert.equal(retryAfterSeconds(' 5 '), 5)
})

// PoryMCP's own tooManyRequests never sends a zero; something between us and it
// can. "Try again in 0 seconds." would tell an operator to press again at once.
test('retryAfterSeconds never promises a retry in no time at all', () => {
  assert.equal(retryAfterSeconds('0'), 1)
  assert.equal(retryAfterSeconds(new Date(Date.now() - 60_000).toUTCString()), 1)
})

test('retryAfterSeconds yields undefined when there is no usable number', () => {
  assert.equal(retryAfterSeconds(null), undefined)
  assert.equal(retryAfterSeconds(''), undefined)
  assert.equal(retryAfterSeconds('abc'), undefined)
  assert.equal(retryAfterSeconds('-1'), undefined)
})

test('retryAfterSeconds accepts the HTTP-date form a proxy might rewrite it to', () => {
  const future = new Date(Date.now() + 30_000).toUTCString()
  const seconds = retryAfterSeconds(future)
  assert.ok(seconds !== undefined && seconds > 0 && seconds <= 31, `expected about 30, got ${seconds}`)
})
