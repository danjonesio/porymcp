import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from './api.ts'
import { discoverable, discoveryErrorMessage, hostOf, plainHTTPCredential, scopedToolName } from './discovery.ts'

// Run with: npm test (node --test). The .ts extensions above are required:
// Node will not resolve an extensionless TypeScript specifier; tsconfig.json
// sets allowImportingTsExtensions so tsc accepts them.

test('scopedToolName joins the slug and the tool name the way the proxy does', () => {
  assert.equal(scopedToolName('github', 'create_issue'), 'github__create_issue')
})

test('scopedToolName leaves a tool name that already contains the separator alone', () => {
  // ParseCanonical splits on the first separator, so this round-trips to
  // slug "github", tool "a__b".
  assert.equal(scopedToolName('github', 'a__b'), 'github__a__b')
})

test('scopedToolName yields nothing without a slug', () => {
  assert.equal(scopedToolName('', 'x'), '')
})

test('discoverable accepts absolute http and https URLs', () => {
  assert.equal(discoverable('https://h/mcp'), true)
  assert.equal(discoverable('http://h:3001/mcp'), true)
  assert.equal(discoverable('  https://h/mcp  '), true)
})

test('discoverable rejects anything Discover cannot be pointed at', () => {
  assert.equal(discoverable(''), false)
  assert.equal(discoverable('  '), false)
  assert.equal(discoverable('h/mcp'), false)
  assert.equal(discoverable('ftp://h'), false)
  assert.equal(discoverable('javascript:alert(1)'), false)
})

test('hostOf never carries the credential out of a URL', () => {
  const host = hostOf('https://user:secret@host:3001/mcp')
  assert.equal(host, 'host:3001')
  assert.ok(!host.includes('secret'))
  assert.ok(!host.includes('user'))
})

test('hostOf yields nothing for an unparseable URL', () => {
  assert.equal(hostOf('nonsense'), '')
})

test('plainHTTPCredential warns only when a credential really travels in the clear', () => {
  assert.equal(plainHTTPCredential('http://example.test/mcp', 'bearer'), true)
  assert.equal(plainHTTPCredential('http://example.test/mcp', 'none'), false)
  assert.equal(plainHTTPCredential('https://example.test/mcp', 'bearer'), false)
  assert.equal(plainHTTPCredential('http://localhost:3001/mcp', 'bearer'), false)
  assert.equal(plainHTTPCredential('http://127.0.0.1:3001/mcp', 'header'), false)
  assert.equal(plainHTTPCredential('http://[::1]:3001/mcp', 'api_key'), false)
  assert.equal(plainHTTPCredential('nonsense', 'bearer'), false)
})

test('discoveryErrorMessage counts the seconds a 429 gave us', () => {
  assert.equal(
    discoveryErrorMessage(new ApiError(429, 'too many discovery requests', 1)),
    'Too many discovery requests. Try again in 1 second.',
  )
  assert.equal(
    discoveryErrorMessage(new ApiError(429, 'too many discovery requests', 30)),
    'Too many discovery requests. Try again in 30 seconds.',
  )
})

test('discoveryErrorMessage names no number when the 429 carried none', () => {
  assert.equal(
    discoveryErrorMessage(new ApiError(429, 'too many discovery requests')),
    'Too many discovery requests. Try again shortly.',
  )
})

test('discoveryErrorMessage explains a 401 instead of redirecting', () => {
  assert.equal(
    discoveryErrorMessage(new ApiError(401, 'unauthorized')),
    'This browser session is no longer signed in. Reload the page to sign in again.',
  )
})

test('discoveryErrorMessage prints any other API error verbatim', () => {
  assert.equal(discoveryErrorMessage(new ApiError(500, 'boom')), 'boom')
})

test('discoveryErrorMessage says PoryMCP itself is unreachable when fetch rejects', () => {
  assert.equal(
    discoveryErrorMessage(new TypeError('fetch failed')),
    'Could not reach PoryMCP. Check that the server is still running.',
  )
})
