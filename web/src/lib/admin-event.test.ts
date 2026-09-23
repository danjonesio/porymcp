import assert from 'node:assert/strict'
import test from 'node:test'
import { changedText, eventSentence, fromText } from './admin-event.ts'
import type { AdminEvent, AdminEventDetails } from './api.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier.

function ev(action: string, details: AdminEventDetails, name = 'GitHub'): AdminEvent {
  return {
    id: 'e1',
    timestamp: '2026-09-05T10:12:33.481293Z',
    actor: 'admin',
    action,
    resource_type: action.split('.')[0],
    resource_id: 'r1',
    resource_name: name,
    details,
    request_id: 'req',
    remote_addr: '203.0.113.10',
  }
}

test('eventSentence: one sentence per action, in the buttons’ own verbs', () => {
  assert.equal(eventSentence(ev('upstream.create', {})), 'Added upstream GitHub')
  assert.equal(eventSentence(ev('upstream.update', {})), 'Changed upstream GitHub')
  assert.equal(eventSentence(ev('upstream.delete', {})), 'Deleted upstream GitHub')
  assert.equal(eventSentence(ev('group.create', {}, 'Research')), 'Created group Research')
  assert.equal(eventSentence(ev('group.update', {}, 'Research')), 'Changed group Research')
  assert.equal(eventSentence(ev('group.delete', {}, 'Research')), 'Deleted group Research')
  assert.equal(eventSentence(ev('virtual_key.create', {}, 'demo-vk')), 'Created virtual key demo-vk')
  assert.equal(eventSentence(ev('virtual_key.update', {}, 'demo-vk')), 'Changed virtual key demo-vk')
  assert.equal(eventSentence(ev('virtual_key.rotate', {}, 'demo-vk')), 'Rotated virtual key demo-vk')
  assert.equal(eventSentence(ev('virtual_key.revoke', {}, 'demo-vk')), 'Revoked virtual key demo-vk')
  assert.equal(eventSentence(ev('virtual_key.delete', {}, 'demo-vk')), 'Deleted virtual key demo-vk')
})

test('eventSentence: an unknown action is shown as itself, never dropped', () => {
  assert.equal(eventSentence(ev('upstream.archive', {})), 'upstream.archive GitHub')
})

test('eventSentence: a row with no name falls back to the id', () => {
  assert.equal(eventSentence(ev('upstream.delete', {}, '')), 'Deleted upstream r1')
})

test('changedText: creates show the bounded values the server records', () => {
  assert.equal(
    changedText(ev('upstream.create', { slug: 'github', auth_type: 'bearer', auth_changed: true })),
    'slug github, auth type bearer, credential set',
  )
  assert.equal(changedText(ev('upstream.create', { slug: 'github', auth_type: 'none' })), 'slug github, auth type none')
  assert.equal(changedText(ev('group.create', { upstream_count: 2, tool_filter_set: true })), '2 upstreams, tool filter set')
  assert.equal(changedText(ev('group.create', { upstream_count: 1 })), '1 upstream')
  assert.equal(changedText(ev('group.create', { upstream_count: 0 })), '0 upstreams')
  assert.equal(
    changedText(ev('virtual_key.create', { target_type: 'upstream', target_id: 'u1', key_prefix: 'pmcp_7Qa3' })),
    'target upstream, key prefix pmcp_7Qa3',
  )
})

test('changedText: updates list the changed fields by label', () => {
  assert.equal(changedText(ev('upstream.update', { fields: ['url', 'enabled'] })), 'url, enabled')
  assert.equal(changedText(ev('virtual_key.update', { fields: ['rate_limit', 'expires_at'] })), 'rate limit, expiry')
  assert.equal(changedText(ev('virtual_key.update', { fields: ['tool_allowlist', 'tool_denylist', 'metadata'] })), 'allowlist, denylist, metadata')
})

test('changedText: a retarget sends both target fields and reads as one target', () => {
  assert.equal(changedText(ev('virtual_key.update', { fields: ['target_type', 'target_id'] })), 'target')
})

test('changedText: a credential is a flag, never a field or a value', () => {
  assert.equal(changedText(ev('upstream.update', { auth_type: 'bearer', auth_changed: true })), 'credential')
  assert.equal(
    changedText(ev('upstream.update', { fields: ['auth_type'], auth_type: 'bearer', auth_changed: true })),
    'auth type bearer, credential',
  )
})

test('changedText: a cleared field reads as cleared, with or without a matching field', () => {
  assert.equal(changedText(ev('group.update', { fields: ['tool_filter'], cleared: ['tool_filter'] })), 'tool filter, tool filter cleared')
  assert.equal(changedText(ev('group.update', { cleared: ['tool_filter'] })), 'tool filter cleared')
  assert.equal(changedText(ev('virtual_key.update', { fields: ['rate_limit'], cleared: ['rate_limit'] })), 'rate limit, rate limit cleared')
})

// PORM-120: a removed credential is the word "credential" in cleared, which
// the raw-name fallback renders with no label entry.
test('changedText: a cleared credential reads as credential cleared, on a type change and on a none row', () => {
  assert.equal(
    changedText(ev('upstream.update', { fields: ['auth_type'], cleared: ['credential'], auth_type: 'none' })),
    'auth type none, credential cleared'
  )
  assert.equal(changedText(ev('upstream.update', { cleared: ['credential'] })), 'credential cleared')
})

test('changedText: a membership change carries the new count', () => {
  assert.equal(changedText(ev('group.update', { fields: ['upstream_ids'], upstream_count: 3 })), 'upstreams (3)')
})

test('changedText: rotate shows the new prefix; revoke, delete and a no-op show nothing', () => {
  assert.equal(changedText(ev('virtual_key.rotate', { key_prefix: 'pmcp_7Qa3' })), 'key prefix pmcp_7Qa3')
  assert.equal(changedText(ev('virtual_key.revoke', {})), '')
  assert.equal(changedText(ev('virtual_key.delete', {})), '')
  assert.equal(changedText(ev('upstream.update', {})), '')
})

test('changedText: an unknown detail key is shown by name only, never its value', () => {
  const details = { fields: ['url'], region: { secret: 'never' } } as unknown as AdminEventDetails
  assert.equal(changedText(ev('upstream.update', details)), 'url, region')
})

// PORM-139: the three OAuth events.
test('eventSentence: the OAuth verbs', () => {
  assert.equal(eventSentence(ev('upstream.oauth_connect', {}, 'Linear')), 'Connected upstream Linear')
  assert.equal(eventSentence(ev('upstream.oauth_refresh', {}, 'Linear')), 'Refreshed the token for upstream Linear')
  assert.equal(eventSentence(ev('upstream.oauth_revoke', {}, 'Linear')), 'Disconnected upstream Linear')
})

test('changedText: the OAuth details read as words, and a refresh token that was issued says nothing', () => {
  assert.equal(
    changedText(ev('upstream.oauth_connect', { auth_type: 'oauth', client: 'document', refresh_token: true, issuer: 'mcp.example' })),
    'client document, issuer mcp.example',
  )
  assert.equal(
    changedText(ev('upstream.oauth_connect', { auth_type: 'oauth', client: 'registered', refresh_token: false, issuer: 'mcp.example' })),
    'client registered, no refresh token, issuer mcp.example',
  )
  assert.equal(changedText(ev('upstream.oauth_refresh', {})), '')
  assert.equal(changedText(ev('upstream.oauth_revoke', { cleared: ['credential'], vendor_revocation: 'revoked' })), 'credential cleared')
  assert.equal(changedText(ev('upstream.oauth_revoke', { cleared: ['credential'], vendor_revocation: 'failed' })), 'credential cleared, vendor revocation failed')
  assert.equal(changedText(ev('upstream.oauth_revoke', { cleared: ['credential'], vendor_revocation: 'not_offered' })), 'credential cleared, vendor revocation not offered')
  assert.equal(changedText(ev('upstream.oauth_revoke', { cleared: ['credential'], vendor_revocation: 'no_token' })), 'credential cleared')
})

test('fromText: the address of the request, or the actor when there was none', () => {
  assert.equal(fromText({ actor: 'admin', remote_addr: '203.0.113.10' }), '203.0.113.10')
  assert.equal(fromText({ actor: 'proxy', remote_addr: '' }), 'proxy')
})
