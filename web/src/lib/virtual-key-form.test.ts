import assert from 'node:assert/strict'
import test from 'node:test'
import type { VirtualKey } from './api.ts'
import {
  blankVirtualKeyForm,
  formFromVirtualKey,
  keyPolicyStale,
  keyRulesBadge,
  keySaveBlocked,
  virtualKeyCreateBody,
  virtualKeyPatchBody,
} from './virtual-key-form.ts'

// Run with: npm test (node --test).

function key(over: Partial<VirtualKey> = {}): VirtualKey {
  return {
    id: 'k1',
    name: 'Claude Code',
    key_prefix: 'pmk_abcd',
    target_type: 'group',
    target_id: 'g1',
    status: 'active',
    created_at: '2026-09-01T00:00:00Z',
    endpoints: [],
    ...over,
  }
}

// PORM-4 step 5: the create body the page used to build inline, unchanged.
test('virtualKeyCreateBody equals the old inline literal after a JSON round trip', () => {
  for (const rate_limit of ['', '60']) {
    const f = { ...blankVirtualKeyForm(), name: 'K', target_type: 'group' as const, target_id: 'g1', rate_limit }
    const old = {
      name: f.name,
      target_type: f.target_type,
      target_id: f.target_id,
      rate_limit: f.rate_limit ? Number(f.rate_limit) : undefined,
    }
    assert.deepEqual(virtualKeyCreateBody(f), JSON.parse(JSON.stringify(old)))
  }
})

test('virtualKeyCreateBody sends a list only when it holds something', () => {
  const f = { ...blankVirtualKeyForm(), name: 'K', target_id: 'u1', tool_denylist: ['gh__delete_repo'] }
  assert.deepEqual(virtualKeyCreateBody(f), {
    name: 'K',
    target_type: 'upstream',
    target_id: 'u1',
    tool_denylist: ['gh__delete_repo'],
  })
})

test('formFromVirtualKey: absent lists are empty lists, and the seeded arrays are copies', () => {
  const vk = key({ tool_denylist: ['gh__x'], rate_limit: 30 })
  const f = formFromVirtualKey(vk)
  assert.deepEqual(f.tool_allowlist, [])
  assert.deepEqual(f.tool_denylist, ['gh__x'])
  assert.equal(f.rate_limit, '30')
  f.tool_denylist.push('y')
  assert.deepEqual(vk.tool_denylist, ['gh__x'])
})

// SR3: an untouched list is never sent.
test('virtualKeyPatchBody: neither list when neither changed, whatever else did', () => {
  const before = key({ tool_allowlist: ['search'], tool_denylist: ['gh__x'] })
  const f = formFromVirtualKey(before)
  assert.deepEqual(virtualKeyPatchBody(before, f), {})
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, name: ' Renamed ' }), { name: 'Renamed' })
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, tool_denylist: ['gh__x'], tool_allowlist: ['search'] }), {})
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, rate_limit: '10' }), { rate_limit: 10 })
  assert.deepEqual(virtualKeyPatchBody(key({ rate_limit: 10 }), { ...formFromVirtualKey(key({ rate_limit: 10 })), rate_limit: '' }), {
    rate_limit: null,
  })
})

test('virtualKeyPatchBody: only the list whose set changed; an emptied list is []', () => {
  const before = key({ tool_allowlist: ['gh__a', 'gh__b'], tool_denylist: ['gh__x'] })
  const f = formFromVirtualKey(before)
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, tool_allowlist: ['gh__b', 'gh__a'] }), {})
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, tool_denylist: ['gh__x', 'gh__y'] }), { tool_denylist: ['gh__x', 'gh__y'] })
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, tool_allowlist: [] }), { tool_allowlist: [] })
  // A key that never had a list does not send an empty one: that would record a clear that did not happen.
  assert.deepEqual(virtualKeyPatchBody(key(), formFromVirtualKey(key())), {})
})

// SR6: a key whose lists cannot be read is never rewritten unasked.
test('virtualKeyPatchBody: an unreadable key sends neither list until Replace, then both', () => {
  const before = key({ lists_malformed: true })
  const f = formFromVirtualKey(before)
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, name: 'Renamed' }), { name: 'Renamed' })
  // Even a typed entry goes nowhere without the press.
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, tool_denylist: ['gh__x'] }), {})
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, listsReplace: true, tool_denylist: ['gh__x'] }), {
    tool_allowlist: [],
    tool_denylist: ['gh__x'],
  })
  assert.deepEqual(virtualKeyPatchBody(before, { ...f, listsReplace: true }), { tool_allowlist: [], tool_denylist: [] })
})

// SR12: the one-time plaintext key never travels back.
test('no body ever carries api_key', () => {
  const before = key({ api_key: 'pmk_secret', tool_denylist: ['gh__x'] })
  const f = { ...formFromVirtualKey(before), name: 'N', tool_denylist: [] }
  assert.equal('api_key' in virtualKeyPatchBody(before, f), false)
  assert.equal(JSON.stringify(virtualKeyPatchBody(before, f)).includes('pmk_secret'), false)
  assert.equal('api_key' in virtualKeyCreateBody(f), false)
})

// SR3: a stored legacy entry never stops an unrelated save.
test('keySaveBlocked: a list is judged only when the body would carry it', () => {
  const before = key({ tool_allowlist: ['search'] }) // unscoped on a group key: a 400 if sent today
  const f = formFromVirtualKey(before)
  assert.equal(keySaveBlocked(before, { ...f, name: 'Renamed' }, true), '')
  assert.equal(keySaveBlocked(before, { ...f, tool_denylist: ['gh__x'] }, true), '')
  assert.match(keySaveBlocked(before, { ...f, tool_allowlist: ['search', 'gh__y'] }, true), /"search" names no member/)
  // The same list is fine on a single-upstream key, and on the deny side of a group key.
  assert.equal(keySaveBlocked(key({ target_type: 'upstream' }), { ...f, tool_allowlist: ['search', 'gh__y'] }, false), '')
  assert.equal(keySaveBlocked(key(), { ...formFromVirtualKey(key()), tool_denylist: ['search'] }, true), '')
  // Create judges whatever it will send.
  assert.match(keySaveBlocked(null, { ...blankVirtualKeyForm(), tool_allowlist: ['search'] }, true), /names no member/)
  assert.equal(keySaveBlocked(null, blankVirtualKeyForm(), true), '')
})

// SR13.
test('keyPolicyStale: per field, so an edit to the other list does not refuse this save', () => {
  const seed = key({ tool_allowlist: ['gh__a'], tool_denylist: ['gh__x'] })
  const otherListChanged = key({ tool_allowlist: ['gh__a', 'gh__b'], tool_denylist: ['gh__x'] })
  assert.equal(keyPolicyStale(seed, otherListChanged, ['tool_denylist']), false)
  assert.equal(keyPolicyStale(seed, otherListChanged, ['tool_allowlist']), true)
  assert.equal(keyPolicyStale(seed, key({ tool_allowlist: ['gh__a'], tool_denylist: ['gh__x'], name: 'Renamed' }), ['tool_allowlist', 'tool_denylist']), false)
  assert.equal(keyPolicyStale(seed, key({ tool_denylist: ['gh__x'], tool_allowlist: ['gh__a'] }), []), false)
})

test('keyPolicyStale: a key that became unreadable, or was repaired, is always stale', () => {
  // Both serve no lists, so only the flag can tell them apart.
  assert.equal(keyPolicyStale(key({ lists_malformed: true }), key(), ['tool_allowlist', 'tool_denylist']), true)
  assert.equal(keyPolicyStale(key(), key({ lists_malformed: true }), ['tool_denylist']), true)
  assert.equal(keyPolicyStale(key({ lists_malformed: true }), key({ lists_malformed: true }), ['tool_allowlist', 'tool_denylist']), false)
})

test('keyRulesBadge: counts, the unreadable mark, or nothing', () => {
  assert.equal(keyRulesBadge(key()), null)
  assert.deepEqual(keyRulesBadge(key({ tool_allowlist: ['a', 'b', 'c'] })), { label: '3 allowed', tone: 'zinc' })
  assert.deepEqual(keyRulesBadge(key({ tool_denylist: ['a', 'b'] })), { label: '2 denied', tone: 'zinc' })
  assert.deepEqual(keyRulesBadge(key({ tool_allowlist: ['a', 'b', 'c'], tool_denylist: ['a', 'b'] })), {
    label: '3 allowed, 2 denied',
    tone: 'zinc',
  })
  // Both lists are absent on such a key, so without the flag it would read as "no rules".
  assert.deepEqual(keyRulesBadge(key({ lists_malformed: true })), { label: 'Rules unreadable', tone: 'pink' })
})
