import assert from 'node:assert/strict'
import test from 'node:test'
import type { Group } from './api.ts'
import { blankGroupForm, formFromGroup, groupCreateBody, groupPatchBody, sameMembers } from './group-form.ts'

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
  assert.deepEqual(groupCreateBody({ name: 'Tools', description: '', upstream_ids: ['u2', 'u1'] }), {
    name: 'Tools',
    description: '',
    upstream_ids: ['u2', 'u1'],
  })
})

test('formFromGroup and blankGroupForm: the seeded form copies the row and the blank one is empty', () => {
  const f = formFromGroup(group())
  assert.deepEqual(f, { name: 'Tools', description: 'Everything an agent needs', upstream_ids: ['u1', 'u2', 'u3'] })
  f.upstream_ids.push('u9')
  assert.equal(group().upstream_ids.length, 3)
  assert.equal(formFromGroup(group({ description: undefined })).description, '')
  assert.deepEqual(blankGroupForm(), { name: '', description: '', upstream_ids: [] })
})
