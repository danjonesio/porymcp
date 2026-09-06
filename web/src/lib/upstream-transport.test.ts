import assert from 'node:assert/strict'
import test from 'node:test'
import { transportUnsupported } from './upstream-transport.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier.

// PORM-28: the badge, the select's extra option and the group dialog's member
// line all hang off this one predicate.
test('streamable-http and the empty default are supported', () => {
  assert.equal(transportUnsupported('streamable-http'), false)
  assert.equal(transportUnsupported(''), false)
})

test('sse and any hand-edited value are unsupported', () => {
  assert.equal(transportUnsupported('sse'), true)
  assert.equal(transportUnsupported('websocket'), true)
})
