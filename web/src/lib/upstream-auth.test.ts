import assert from 'node:assert/strict'
import test from 'node:test'
import { authState, connectLabel, oauthConnected } from './upstream-auth.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier.

test('authState: ok shows the usual suffix and no badge', () => {
  assert.deepEqual(authState({ auth_status: 'ok' }), { tone: 'ok', label: '', expiresAt: null })
})

test('authState: none shows nothing beside the type', () => {
  assert.deepEqual(authState({ auth_status: 'none' }), { tone: 'none', label: '', expiresAt: null })
})

test('authState: undecryptable is the key problem, badged Unreadable (AC10)', () => {
  assert.deepEqual(authState({ auth_status: 'undecryptable' }), { tone: 'broken', label: 'Unreadable', expiresAt: null })
})

test('authState: unreadable is the credential problem, badged Incomplete', () => {
  assert.deepEqual(authState({ auth_status: 'unreadable' }), { tone: 'broken', label: 'Incomplete', expiresAt: null })
})

test('authState: an unknown future value renders no badge, never red', () => {
  assert.deepEqual(authState({ auth_status: 'quarantined' }), { tone: 'ok', label: '', expiresAt: null })
  assert.deepEqual(authState({ auth_status: '' }), { tone: 'ok', label: '', expiresAt: null })
})

// PORM-139: the oauth states. Not connected is plain text, Expired is the
// amber badge the badge rule gives "held or expired" (amendment A1), a set
// with no refresh token names its expiry, and a bearer row's unreadable still
// reads Incomplete.
test('authState: an oauth row with nothing usable stored reads Not connected as plain text', () => {
  assert.deepEqual(authState({ auth_type: 'oauth', auth_status: 'unreadable' }), { tone: 'idle', label: 'Not connected', expiresAt: null })
  assert.deepEqual(
    authState({ auth_type: 'oauth', auth_status: 'unreadable', oauth: { expires_at: null, has_refresh_token: false, client_source: 'supplied' } }),
    { tone: 'idle', label: 'Not connected', expiresAt: null },
  )
  assert.deepEqual(authState({ auth_type: 'bearer', auth_status: 'unreadable' }), { tone: 'broken', label: 'Incomplete', expiresAt: null })
})

test('authState: expired is the amber badge, whatever the type', () => {
  assert.deepEqual(authState({ auth_type: 'oauth', auth_status: 'expired' }), { tone: 'held', label: 'Expired', expiresAt: null })
})

test('authState: an oauth row that is ok reads set, or set until its expiry when the vendor issued no refresh token', () => {
  assert.deepEqual(
    authState({ auth_type: 'oauth', auth_status: 'ok', oauth: { expires_at: '2026-09-23T11:00:00Z', has_refresh_token: true, client_source: 'document' } }),
    { tone: 'ok', label: '', expiresAt: null },
  )
  assert.deepEqual(
    authState({ auth_type: 'oauth', auth_status: 'ok', oauth: { expires_at: '2026-09-23T11:00:00Z', has_refresh_token: false, client_source: 'document' } }),
    { tone: 'ok', label: 'set until', expiresAt: '2026-09-23T11:00:00Z' },
  )
  assert.deepEqual(authState({ auth_type: 'oauth', auth_status: 'undecryptable' }), { tone: 'broken', label: 'Unreadable', expiresAt: null })
})

test('connectLabel and oauthConnected: Reconnect once a token set is stored', () => {
  assert.equal(connectLabel({}), 'Connect')
  assert.equal(connectLabel({ oauth: { expires_at: null, has_refresh_token: false, client_source: 'supplied' } }), 'Connect')
  assert.equal(connectLabel({ oauth: { expires_at: '2026-09-23T11:00:00Z', has_refresh_token: true, client_source: null } }), 'Reconnect')
  assert.equal(oauthConnected({ auth_type: 'oauth', oauth: { expires_at: '2026-09-23T11:00:00Z', has_refresh_token: true, client_source: null } }), true)
  assert.equal(oauthConnected({ auth_type: 'oauth', oauth: { expires_at: null, has_refresh_token: false, client_source: 'supplied' } }), false)
  assert.equal(oauthConnected({ auth_type: 'bearer' }), false)
})
