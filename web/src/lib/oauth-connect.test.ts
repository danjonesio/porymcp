import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from './api.ts'
import { authorizationURLIsWeb, connectErrorMessage, revokeResultLine } from './oauth-connect.ts'

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
  assert.equal(revokeResultLine({ vendor_revocation: 'revoked' }, true), 'Disconnected. The vendor revoked the token.')
  assert.equal(
    revokeResultLine({ vendor_revocation: 'failed' }, true),
    "Disconnected. The vendor did not confirm the revocation. Remove PoryMCP's access in the vendor's account settings.",
  )
  assert.equal(
    revokeResultLine({ vendor_revocation: 'not_offered' }, true),
    'Disconnected. This vendor offers no way to revoke the token, so it stays valid there until it expires.',
  )
  assert.equal(revokeResultLine({ vendor_revocation: 'no_token' }, true), 'Removed the stored client ID.')
  assert.equal(revokeResultLine({ vendor_revocation: 'revoked' }, false), 'Removed the stored client ID.')
  assert.equal(revokeResultLine({ vendor_revocation: 'surprise' }, true), 'Disconnected.')
})

test('authorizationURLIsWeb: only http and https URLs are ever navigated to', () => {
  assert.equal(authorizationURLIsWeb('https://as.example/authorize?state=x'), true)
  assert.equal(authorizationURLIsWeb('http://127.0.0.1:8080/authorize'), true)
  assert.equal(authorizationURLIsWeb('javascript:alert(1)'), false)
  assert.equal(authorizationURLIsWeb('data:text/html,hi'), false)
  assert.equal(authorizationURLIsWeb('not a url'), false)
})
