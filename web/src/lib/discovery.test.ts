import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from './api.ts'
import {
  discoverable,
  discoveryErrorMessage,
  hostOf,
  plainHTTPCredential,
  probeRequestLine,
  protocolSummary,
} from './discovery.ts'

// Run with: npm test (node --test). The .ts extensions above are required:
// Node will not resolve an extensionless TypeScript specifier; tsconfig.json
// sets allowImportingTsExtensions so tsc accepts them.

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

// PORM-151: the five things the Protocol row can say. The label beside it is
// the literal "Protocol", so the first two read "Protocol 2026-07-28, stateless"
// and "Protocol 2025-06-18, handshake".
test('protocolSummary names the version and the era of a modern server', () => {
  assert.equal(protocolSummary({ era: 'modern', protocol_version: '2026-07-28' }), '2026-07-28, stateless')
})

test('protocolSummary names the version and the era of a handshake server', () => {
  assert.equal(protocolSummary({ era: 'legacy', protocol_version: '2025-06-18' }), '2025-06-18, handshake')
})

test('protocolSummary says no version was agreed when a failure knows only the era', () => {
  assert.equal(protocolSummary({ era: 'modern' }), 'stateless, no version agreed')
  assert.equal(protocolSummary({ era: 'legacy' }), 'handshake, no version agreed')
})

test('protocolSummary shows the version alone when the response carries no era', () => {
  assert.equal(protocolSummary({ protocol_version: '2025-06-18' }), '2025-06-18')
})

test('protocolSummary is empty when there is nothing to show', () => {
  assert.equal(protocolSummary({}), '')
})

// PORM-146: the Request row of an HTTP API test.
test('probeRequestLine names the test path or the base', () => {
  assert.equal(probeRequestLine('/user'), 'GET /user')
  assert.equal(probeRequestLine(''), 'GET /')
  assert.equal(probeRequestLine(undefined), 'GET /')
})
