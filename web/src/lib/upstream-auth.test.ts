import assert from 'node:assert/strict'
import test from 'node:test'
import { authState } from './upstream-auth.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier.

test('authState: ok shows the usual suffix and no badge', () => {
  assert.deepEqual(authState({ auth_status: 'ok' }), { tone: 'ok', label: '' })
})

test('authState: none shows nothing beside the type', () => {
  assert.deepEqual(authState({ auth_status: 'none' }), { tone: 'none', label: '' })
})

test('authState: undecryptable is the key problem, badged Unreadable (AC10)', () => {
  assert.deepEqual(authState({ auth_status: 'undecryptable' }), { tone: 'broken', label: 'Unreadable' })
})

test('authState: unreadable is the credential problem, badged Incomplete', () => {
  assert.deepEqual(authState({ auth_status: 'unreadable' }), { tone: 'broken', label: 'Incomplete' })
})

test('authState: an unknown future value renders no badge, never red', () => {
  assert.deepEqual(authState({ auth_status: 'quarantined' }), { tone: 'ok', label: '' })
  assert.deepEqual(authState({ auth_status: '' }), { tone: 'ok', label: '' })
})
