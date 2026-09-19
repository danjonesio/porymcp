import assert from 'node:assert/strict'
import test from 'node:test'
import type { Group } from './api.ts'
import {
  blankGroupForm,
  formFromGroup,
  groupCreateBody,
  groupPatchBody,
  groupPolicyStale,
  groupSaveBlocked,
  sameMembers,
} from './group-form.ts'
import { ZERO_ENTRIES } from './tool-filter.ts'

// Run with: npm test (node --test). The .ts extensions above are required:
// Node will not resolve an extensionless TypeScript specifier.

function group(over: Partial<Group> = {}): Group {
  return {
    id: 'g1',
    name: 'Tools',
    description: 'Everything an agent needs',
    upstream_ids: ['u1', 'u2', 'u3'],
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    ...over,
  }
}

// AC9: a reorder is not a change.
test('groupPatchBody: omits upstream_ids when the same members are selected in a different order', () => {
  const before = group()
  // Untick u1 and tick it again: the form now holds u2, u3, u1.
  assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), upstream_ids: ['u2', 'u3', 'u1'] }), {})
})

test('groupPatchBody: removing one member sends the remaining ids in stored order', () => {
  const before = group()
  assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), upstream_ids: ['u1', 'u3'] }), {
    upstream_ids: ['u1', 'u3'],
  })
})

test('groupPatchBody: adding one member sends it after the retained ids', () => {
  const before = group()
  assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), upstream_ids: ['u1', 'u2', 'u3', 'u4'] }), {
    upstream_ids: ['u1', 'u2', 'u3', 'u4'],
  })
})

test('groupPatchBody: clearing every member emits an empty upstream_ids', () => {
  const before = group()
  assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), upstream_ids: [] }), { upstream_ids: [] })
})

// Security requirement 10: an unchanged field is never sent.
test('groupPatchBody: an unchanged form yields {} and a name-only change yields exactly {name}', () => {
  const before = group()
  assert.deepEqual(groupPatchBody(before, formFromGroup(before)), {})
  assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), name: 'Tools prod' }), { name: 'Tools prod' })
})

test('groupPatchBody: description cleared to empty against a stored description is emitted', () => {
  const before = group()
  assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), description: '' }), { description: '' })
  assert.deepEqual(groupPatchBody(group({ description: undefined }), { ...formFromGroup(before), description: '' }), {})
})

test('sameMembers: order-insensitive, and different lengths are different', () => {
  assert.equal(sameMembers(['a', 'b'], ['b', 'a']), true)
  assert.equal(sameMembers([], []), true)
  assert.equal(sameMembers(['a'], ['a', 'b']), false)
  assert.equal(sameMembers(['a', 'b'], ['a', 'c']), false)
})

test('groupCreateBody: carries name, description and upstream_ids and nothing else', () => {
  assert.deepEqual(groupCreateBody({ ...blankGroupForm(), name: 'Tools', description: '', upstream_ids: ['u2', 'u1'] }), {
    name: 'Tools',
    description: '',
    upstream_ids: ['u2', 'u1'],
  })
})

test('formFromGroup and blankGroupForm: the seeded form copies the row and the blank one is empty', () => {
  const f = formFromGroup(group())
  const noFilter = { filter: { mode: '', tools: [], prefixes: [] }, filterUnreadable: '', filterReplace: false, filterChosen: false }
  assert.deepEqual(f, { name: 'Tools', description: 'Everything an agent needs', upstream_ids: ['u1', 'u2', 'u3'], ...noFilter })
  f.upstream_ids.push('u9')
  assert.equal(group().upstream_ids.length, 3)
  assert.equal(formFromGroup(group({ description: undefined })).description, '')
  assert.deepEqual(blankGroupForm(), { name: '', description: '', upstream_ids: [], ...noFilter })
})

// ---- PORM-4: the group's tool_filter ------------------------------------------

const apiWritten = { mode: 'deny', tools: ['github__delete_repo'], prefixes: ['delete_'] }

test('formFromGroup seeds the filter from what the API served', () => {
  assert.deepEqual(formFromGroup(group({ tool_filter: apiWritten })).filter, apiWritten)
  assert.deepEqual(formFromGroup(group()).filter, { mode: '', tools: [], prefixes: [] })
  const bad = formFromGroup(group({ tool_filter: { mode: 'Deny' } }))
  assert.equal(bad.filterUnreadable, '{"mode":"Deny"}')
  assert.deepEqual(bad.filter, { mode: '', tools: [], prefixes: [] })
})

// SR3: an untouched policy field is never sent, whatever is wrong with it.
test('groupPatchBody: a name change never carries an untouched filter', () => {
  const stored: unknown[] = [
    apiWritten,
    {}, // stored and served as {} after a PATCH of {}
    null, // a pre-PORM-21 row
    { mode: 'deny' }, // accepted by the API, blocks nothing
    { mode: 'allow', tools: ['search'] }, // legacy: passes the read side, fails the write side
    { Mode: 'deny', Tools: ['github__x'], prefixes: null },
    { mode: 'Deny' }, // unreadable
  ]
  for (const tool_filter of stored) {
    const before = group({ tool_filter })
    assert.deepEqual(groupPatchBody(before, { ...formFromGroup(before), name: 'Renamed' }), { name: 'Renamed' }, JSON.stringify(tool_filter))
    assert.equal(groupSaveBlocked(before, { ...formFromGroup(before), name: 'Renamed' }), '', JSON.stringify(tool_filter))
  }
})

test('groupPatchBody: a reordered filter is not a change; a new entry sends the whole filter in stored order', () => {
  const before = group({ tool_filter: apiWritten })
  const f = formFromGroup(before)
  assert.deepEqual(groupPatchBody(before, { ...f, filter: { ...f.filter, tools: [...f.filter.tools].reverse() } }), {})
  const added = { ...f, filter: { ...f.filter, tools: [...f.filter.tools, 'github__create_issue'] } }
  assert.equal(
    JSON.stringify(groupPatchBody(before, added)),
    '{"tool_filter":{"mode":"deny","tools":["github__delete_repo","github__create_issue"],"prefixes":["delete_"]}}',
  )
})

// SR4: No filter is null, which the server records as a clear.
test('groupPatchBody: switching to No filter sends null', () => {
  const before = group({ tool_filter: apiWritten })
  const f = formFromGroup(before)
  assert.deepEqual(groupPatchBody(before, { ...f, filter: { mode: '', tools: [], prefixes: [] } }), { tool_filter: null })
})

// SR6: an unreadable stored filter is never sent until Replace filter AND a mode were pressed.
test('groupPatchBody: an unreadable filter goes nowhere until it is explicitly replaced', () => {
  const before = group({ tool_filter: { mode: 'Deny' } })
  const f = formFromGroup(before)
  assert.deepEqual(groupPatchBody(before, f), {})
  assert.deepEqual(groupPatchBody(before, { ...f, filterReplace: true }), {})
  assert.notEqual(groupSaveBlocked(before, { ...f, filterReplace: true }), '')
  // No filter counts as the choice: it is how a broken filter is removed.
  assert.deepEqual(groupPatchBody(before, { ...f, filterReplace: true, filterChosen: true }), { tool_filter: null })
  assert.equal(groupSaveBlocked(before, { ...f, filterReplace: true, filterChosen: true }), '')
  const deny = { ...f, filterReplace: true, filterChosen: true, filter: { mode: 'deny' as const, tools: ['gh__x'], prefixes: [] } }
  assert.deepEqual(groupPatchBody(before, deny), { tool_filter: { mode: 'deny', tools: ['gh__x'] } })
})

// SR3, SR5: a problem holds Save back only when the body would carry the filter.
test('groupSaveBlocked: a seeded empty deny saves a rename, and an empty mode the operator chose does not save', () => {
  const before = group({ tool_filter: { mode: 'deny' } })
  const f = formFromGroup(before)
  assert.equal(groupSaveBlocked(before, { ...f, name: 'Renamed' }), '')
  assert.equal(groupSaveBlocked(before, { ...f, filter: { ...f.filter, mode: 'allow' } }), ZERO_ENTRIES)
  const plain = group()
  assert.equal(groupSaveBlocked(plain, { ...formFromGroup(plain), filter: { mode: 'deny', tools: [], prefixes: [] } }), ZERO_ENTRIES)
  // Create has no stored filter: any chosen mode is judged.
  assert.equal(groupSaveBlocked(null, { ...blankGroupForm(), filter: { mode: 'allow', tools: [], prefixes: [] } }), ZERO_ENTRIES)
  assert.equal(groupSaveBlocked(null, blankGroupForm()), '')
})

test('groupSaveBlocked: a legacy entry blocks Save only once the filter is edited', () => {
  const before = group({ tool_filter: { mode: 'allow', tools: ['search'] } })
  const f = formFromGroup(before)
  assert.equal(groupSaveBlocked(before, f), '')
  const edited = { ...f, filter: { ...f.filter, tools: ['search', 'gh__x'] } }
  assert.match(groupSaveBlocked(before, edited), /"search" names no member/)
})

// D6.
test('groupCreateBody: tool_filter goes only when a mode is chosen', () => {
  const f = { ...blankGroupForm(), name: 'G', upstream_ids: ['u1'] }
  assert.equal('tool_filter' in groupCreateBody(f), false)
  assert.deepEqual(groupCreateBody({ ...f, filter: { mode: 'deny', tools: ['gh__x'], prefixes: [] } }).tool_filter, {
    mode: 'deny',
    tools: ['gh__x'],
  })
})

// SR13.
test('groupPolicyStale: true only when the stored filter changed in meaning', () => {
  const seed = group({ tool_filter: apiWritten })
  assert.equal(groupPolicyStale(seed, group({ tool_filter: apiWritten, name: 'Renamed elsewhere' })), false)
  assert.equal(groupPolicyStale(seed, group({ tool_filter: { mode: 'deny', prefixes: ['delete_'], tools: ['github__delete_repo'] } })), false)
  assert.equal(groupPolicyStale(seed, group({ tool_filter: { ...apiWritten, tools: [] } })), true)
  assert.equal(groupPolicyStale(seed, group()), true)
  assert.equal(groupPolicyStale(group({ tool_filter: {} }), group()), false)
  assert.equal(groupPolicyStale(group({ tool_filter: { mode: 'Deny' } }), group({ tool_filter: { mode: 'Deny' } })), false)
  assert.equal(groupPolicyStale(group({ tool_filter: { mode: 'Deny' } }), group({ tool_filter: { mode: 'DENY' } })), true)
  assert.equal(groupPolicyStale(group({ tool_filter: { mode: 'Deny' } }), group({ tool_filter: { mode: 'deny', tools: ['a__b'] } })), true)
})
