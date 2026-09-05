import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from './api.ts'
import { editErrorMessage } from './edit-error.ts'

// Run with: npm test (node --test). The .ts extensions above are required:
// Node will not resolve an extensionless TypeScript specifier.

test('editErrorMessage: a 404 names the resource that went away', () => {
  assert.equal(
    editErrorMessage(new ApiError(404, 'not found'), 'upstream'),
    'This upstream no longer exists. Close this dialog to see the current list.'
  )
  assert.equal(
    editErrorMessage(new ApiError(404, 'not found'), 'group'),
    'This group no longer exists. Close this dialog to see the current list.'
  )
})

test('editErrorMessage: a 409 on an upstream says what still holds it', () => {
  assert.equal(
    editErrorMessage(new ApiError(409, 'resource is still referenced'), 'upstream'),
    'This upstream is still used by a group or a virtual key. Remove it there first.'
  )
})

test('editErrorMessage: a 409 on a group says what still targets it', () => {
  assert.equal(
    editErrorMessage(new ApiError(409, 'resource is still referenced'), 'group'),
    'This group is still targeted by a virtual key. Delete that key first.'
  )
})

test('editErrorMessage: a 429 with Retry-After names the wait and no budget', () => {
  assert.equal(editErrorMessage(new ApiError(429, 'too many requests', 30), 'upstream'), 'Too many requests. Try again in 30 seconds.')
  assert.equal(editErrorMessage(new ApiError(429, 'too many requests', 1), 'group'), 'Too many requests. Try again in 1 second.')
})

test('editErrorMessage: a 429 without Retry-After says a minute', () => {
  assert.equal(editErrorMessage(new ApiError(429, 'too many requests'), 'upstream'), 'Too many requests. Try again in a minute.')
})

// AC6: the server's own validation message reaches the dialog untouched.
test('editErrorMessage: a 400 returns the server message verbatim', () => {
  assert.equal(editErrorMessage(new ApiError(400, 'unknown upstream_id: u9'), 'group'), 'unknown upstream_id: u9')
  assert.equal(editErrorMessage(new ApiError(400, 'name cannot be empty'), 'upstream'), 'name cannot be empty')
})

test('editErrorMessage: a 401 returns the signed-out sentence', () => {
  assert.equal(
    editErrorMessage(new ApiError(401, 'unauthorized'), 'upstream'),
    'This browser session is no longer signed in. Reload the page to sign in again.'
  )
})

test('editErrorMessage: anything but an ApiError means PoryMCP itself was unreachable', () => {
  assert.equal(
    editErrorMessage(new TypeError('Failed to fetch'), 'group'),
    'Could not reach PoryMCP. Check that the server is still running.'
  )
})
