import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from './api.ts'
import {
  REGISTER_CHOICE_KEY,
  REVOKE_COPY,
  authorizationURLIsWeb,
  connectErrorMessage,
  loadRegisterChoices,
  revokeKind,
  revokeResultLine,
  saveRegisterChoices,
} from './oauth-connect.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier.

test('connectErrorMessage: 404 reloads the list, 400 and 502 keep the server\'s sentence, the rest is the house mapper', () => {
  assert.equal(connectErrorMessage(new ApiError(404, 'not found')), 'This upstream no longer exists. The list has been reloaded.')
  assert.equal(connectErrorMessage(new ApiError(400, 'PUBLIC_URL must be an https address to connect an OAuth upstream')), 'PUBLIC_URL must be an https address to connect an OAuth upstream')
  assert.equal(connectErrorMessage(new ApiError(502, 'authorization server metadata not found')), 'authorization server metadata not found')
  assert.equal(connectErrorMessage(new ApiError(429, 'too many discovery requests', 7)), 'Too many discovery requests. Try again in 7 seconds.')
  assert.equal(connectErrorMessage(new ApiError(401, 'unauthorized')), 'This browser session is no longer signed in. Reload the page to sign in again.')
  assert.equal(connectErrorMessage(new TypeError('fetch failed')), 'Could not reach PoryMCP. Check that the server is still running.')
})

test('revokeResultLine: one line per vendor answer, and a client-only row reads as a removed client', () => {
  assert.equal(revokeResultLine({ vendor_revocation: 'revoked' }, 'connected'), 'Disconnected. The vendor revoked the token.')
  assert.equal(
    revokeResultLine({ vendor_revocation: 'failed' }, 'connected'),
    "Disconnected. The vendor did not confirm the revocation. Remove PoryMCP's access in the vendor's account settings.",
  )
  assert.equal(
    revokeResultLine({ vendor_revocation: 'not_offered' }, 'connected'),
    'Disconnected. This vendor offers no way to revoke the token, so it stays valid there until it expires.',
  )
  assert.equal(revokeResultLine({ vendor_revocation: 'no_token' }, 'connected'), 'Removed the stored client ID.')
  assert.equal(revokeResultLine({ vendor_revocation: 'revoked' }, 'client'), 'Removed the stored client ID.')
  assert.equal(revokeResultLine({ vendor_revocation: 'surprise' }, 'connected'), 'Disconnected.')
})

test('authorizationURLIsWeb: only http and https URLs are ever navigated to', () => {
  assert.equal(authorizationURLIsWeb('https://as.example/authorize?state=x'), true)
  assert.equal(authorizationURLIsWeb('http://127.0.0.1:8080/authorize'), true)
  assert.equal(authorizationURLIsWeb('javascript:alert(1)'), false)
  assert.equal(authorizationURLIsWeb('data:text/html,hi'), false)
  assert.equal(authorizationURLIsWeb('not a url'), false)
})

test('revokeKind: a token set, a client alone, an unreadable value, or nothing', () => {
  assert.equal(revokeKind({ auth_type: 'oauth', auth_status: 'ok', auth_configured: true, oauth: { expires_at: '2026-09-23T11:00:00Z' } }), 'connected')
  assert.equal(revokeKind({ auth_type: 'oauth', auth_status: 'unreadable', auth_configured: true, oauth: { expires_at: null } }), 'client')
  assert.equal(revokeKind({ auth_type: 'oauth', auth_status: 'undecryptable', auth_configured: true }), 'unreadable')
  assert.equal(revokeKind({ auth_type: 'oauth', auth_status: 'unreadable', auth_configured: false }), null)
  assert.equal(revokeKind({ auth_type: 'bearer', auth_status: 'ok', auth_configured: true }), null)
  assert.equal(REVOKE_COPY.unreadable.button, 'Remove the stored value')
  assert.match(REVOKE_COPY.unreadable.description('Vendor', false), /The vendor is not asked to revoke it/)
  assert.match(REVOKE_COPY.connected.description('Vendor', true), /The client ID and secret you entered are removed too\.$/)
  assert.equal(revokeResultLine({ vendor_revocation: 'no_token' }, 'unreadable'), 'Removed the stored value. Connect to sign in again.')
})

test('register choices: round trip through a storage, junk and refusals read as no choice', () => {
  const store = new Map<string, string>()
  const storage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) }
  saveRegisterChoices(storage, { a: true, b: false })
  assert.equal(store.get(REGISTER_CHOICE_KEY), '{"a":true}')
  assert.deepEqual(loadRegisterChoices(storage), { a: true })
  store.set(REGISTER_CHOICE_KEY, '[1,2]')
  assert.deepEqual(loadRegisterChoices(storage), {})
  store.set(REGISTER_CHOICE_KEY, 'not json')
  assert.deepEqual(loadRegisterChoices(storage), {})
  assert.deepEqual(loadRegisterChoices(undefined), {})
  const refusing = { getItem: () => { throw new Error('blocked') }, setItem: () => { throw new Error('blocked') } }
  assert.deepEqual(loadRegisterChoices(refusing), {})
  assert.doesNotThrow(() => saveRegisterChoices(refusing, { a: true }))
})
