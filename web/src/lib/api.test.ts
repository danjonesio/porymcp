import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError, requestErrorMessage, retryAfterSeconds } from './api.ts'

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

// The house mapper (PORM-20): every failed management request on the Logs page
// and in the Edit dialogs reads one of these sentences.
test('requestErrorMessage: the admin limiter 429, with and without Retry-After', () => {
  assert.equal(requestErrorMessage(new ApiError(429, 'too many requests', 7)), 'Too many requests. Try again in 7 seconds.')
  assert.equal(requestErrorMessage(new ApiError(429, 'too many requests', 1)), 'Too many requests. Try again in 1 second.')
  assert.equal(requestErrorMessage(new ApiError(429, 'too many requests')), 'Too many requests. Try again in a minute.')
})

test('requestErrorMessage: 401, the server sentence, and the network sentence', () => {
  assert.equal(
    requestErrorMessage(new ApiError(401, 'unauthorized')),
    'This browser session is no longer signed in. Reload the page to sign in again.',
  )
  assert.equal(requestErrorMessage(new ApiError(400, 'invalid cursor')), 'invalid cursor')
  assert.equal(
    requestErrorMessage(new TypeError('Failed to fetch')),
    'Could not reach PoryMCP. Check that the server is still running.',
  )
})
