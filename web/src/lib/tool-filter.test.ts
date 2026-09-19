import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ZERO_ENTRIES,
  blankFilterForm,
  clampText,
  filterAdmitsNothing,
  filterListsNothing,
  filterProblem,
  filterValue,
  listProblem,
  parseToolFilter,
  sameEntries,
  sameFilter,
  toggleEntry,
  wholeMemberLabel,
  wholeMemberPrefix,
} from './tool-filter.ts'
import type { FilterForm } from './tool-filter.ts'

// Run with: npm test (node --test).

function form(over: Partial<FilterForm> = {}): FilterForm {
  return { ...blankFilterForm(), ...over }
}

// PORM-4 SR6, AC4: what models.ValidateToolFilter calls "no filter".
test('parseToolFilter: absent, null, {} and an object with no mode and no entries are no filter', () => {
  for (const raw of [undefined, null, {}, { tools: [] }, { mode: '' }, { mode: '', tools: null, prefixes: [] }]) {
    assert.deepEqual(parseToolFilter(raw), { kind: 'none' }, JSON.stringify(raw))
  }
})

// PORM-4 SR6, AC7: shapes the read side accepts and a stricter parser would call unreadable.
test('parseToolFilter: accepts what the proxy enforces', () => {
  assert.deepEqual(parseToolFilter({ mode: 'deny', tools: ['gh__x'], prefixes: ['delete_'] }), {
    kind: 'filter',
    form: { mode: 'deny', tools: ['gh__x'], prefixes: ['delete_'] },
  })
  // Go matches member names case-insensitively; only the mode's VALUE is exact.
  assert.deepEqual(parseToolFilter({ Mode: 'deny', Tools: ['gh__x'] }), {
    kind: 'filter',
    form: { mode: 'deny', tools: ['gh__x'], prefixes: [] },
  })
  // A client that writes absent optionals as null.
  assert.deepEqual(parseToolFilter({ mode: 'deny', tools: ['gh__x'], prefixes: null }), {
    kind: 'filter',
    form: { mode: 'deny', tools: ['gh__x'], prefixes: [] },
  })
  // The last of two spellings of one member wins, as Go's decoder binds them.
  assert.deepEqual(parseToolFilter({ mode: 'allow', Mode: 'deny', tools: ['gh__x'] }), {
    kind: 'filter',
    form: { mode: 'deny', tools: ['gh__x'], prefixes: [] },
  })
  // An empty deny is accepted and blocks nothing.
  assert.deepEqual(parseToolFilter({ mode: 'deny' }), { kind: 'filter', form: form({ mode: 'deny' }) })
  // A legacy unscoped allow entry passes the read side. It is a write-side problem only.
  assert.deepEqual(parseToolFilter({ mode: 'allow', tools: ['search'] }), {
    kind: 'filter',
    form: form({ mode: 'allow', tools: ['search'] }),
  })
  // So does a head that is not a slug, and an entry ending at the separator.
  assert.equal(parseToolFilter({ mode: 'deny', tools: ['GitHub__x', 'gh__'] }).kind, 'filter')
})

test('parseToolFilter: duplicates are dropped, first position kept', () => {
  assert.deepEqual(parseToolFilter({ mode: 'deny', tools: ['a__b', 'c__d', 'a__b'] }), {
    kind: 'filter',
    form: form({ mode: 'deny', tools: ['a__b', 'c__d'] }),
  })
})

// PORM-4 SR6: everything the read side rejects blocks every tool, and must not render as a rule or as no rule.
test('parseToolFilter: unreadable is exactly what the read side rejects', () => {
  const cases: unknown[] = [
    '', // a served JSON string is not an object; never "no filter"
    'deny',
    0,
    true,
    [],
    ['gh__x'],
    { mode: 'deny', tool: ['gh__x'] }, // unknown member
    { mode: 'Deny', tools: ['gh__x'] }, // the mode's value is byte-exact
    { mode: 'block' },
    { mode: 5 },
    { tools: ['gh__x'] }, // entries with no mode
    { mode: '', prefixes: ['delete_'] },
    { mode: 'allow' }, // an allowlist of nothing
    { mode: 'allow', tools: [], prefixes: null },
    { mode: 'deny', tools: 'gh__x' }, // not an array
    { mode: 'deny', tools: [7] }, // not a string
    { mode: 'deny', tools: [null] },
    { mode: 'deny', tools: ['delete repo'] }, // fails CleanToolEntry
    { mode: 'deny', tools: [''] },
    { mode: 'deny', prefixes: ['a\u0001'] },
  ]
  for (const raw of cases) {
    const got = parseToolFilter(raw)
    assert.equal(got.kind, 'unreadable', JSON.stringify(raw))
    if (got.kind === 'unreadable') assert.equal(got.text, JSON.stringify(raw))
  }
})

// PORM-4 D5, D6.
test('filterValue: no filter is null; one member order; empty lists left out', () => {
  assert.equal(filterValue(form()), null)
  assert.equal(filterValue(form({ mode: '', tools: ['ignored'] })), null)
  assert.equal(
    JSON.stringify(filterValue(form({ mode: 'deny', prefixes: ['p_'], tools: ['a__b'] }))),
    '{"mode":"deny","tools":["a__b"],"prefixes":["p_"]}',
  )
  assert.equal(JSON.stringify(filterValue(form({ mode: 'deny', tools: ['a__b'] }))), '{"mode":"deny","tools":["a__b"]}')
  assert.equal(JSON.stringify(filterValue(form({ mode: 'allow', prefixes: ['gh__'] }))), '{"mode":"allow","prefixes":["gh__"]}')
})

// PORM-4 SR3.
test('sameFilter: order is not meaning; mode and membership are', () => {
  const a = form({ mode: 'deny', tools: ['a__b', 'c__d'], prefixes: ['x_', 'y_'] })
  assert.equal(sameFilter(a, form({ mode: 'deny', tools: ['c__d', 'a__b'], prefixes: ['y_', 'x_'] })), true)
  assert.equal(sameFilter(a, { ...a, mode: 'allow' }), false)
  assert.equal(sameFilter(a, { ...a, tools: ['a__b'] }), false)
  assert.equal(sameFilter(a, { ...a, tools: ['a__b', 'c__d', 'e__f'] }), false)
  assert.equal(sameFilter(a, { ...a, prefixes: ['x_'] }), false)
  // A tools entry and a prefixes entry with the same text are different rules.
  assert.equal(sameFilter(form({ mode: 'deny', tools: ['x'] }), form({ mode: 'deny', prefixes: ['x'] })), false)
  assert.equal(sameFilter(form(), form()), true)
})

test('sameEntries: absent and empty are the same list', () => {
  assert.equal(sameEntries(undefined, []), true)
  assert.equal(sameEntries(['a', 'b'], ['b', 'a']), true)
  assert.equal(sameEntries(['a'], ['a', 'b']), false)
})

// PORM-4 D4.
test('toggleEntry: adding twice changes nothing, removing takes every occurrence, order is kept', () => {
  const list = ['a__b', 'c__d']
  assert.equal(toggleEntry(list, 'a__b', true), list)
  assert.deepEqual(toggleEntry(list, 'e__f', true), ['a__b', 'c__d', 'e__f'])
  assert.deepEqual(toggleEntry(['a__b', 'c__d', 'a__b'], 'a__b', false), ['c__d'])
  assert.deepEqual(toggleEntry(list, 'absent', false), list)
})

// PORM-4 SR5.
test('filterProblem: a mode that lists nothing, then the first entry the API would refuse', () => {
  assert.equal(filterProblem(form()), '')
  assert.equal(filterProblem(form({ mode: 'allow' })), ZERO_ENTRIES)
  assert.equal(filterProblem(form({ mode: 'deny' })), ZERO_ENTRIES)
  assert.equal(filterProblem(form({ mode: 'deny', tools: ['gh__x'], prefixes: ['gh__'] })), '')
  assert.match(filterProblem(form({ mode: 'allow', tools: ['gh__x', 'search'] })), /"search" names no member/)
  assert.match(filterProblem(form({ mode: 'deny', tools: ['gh__'] })), /names no tool/)
  // An unscoped entry is fine under deny.
  assert.equal(filterProblem(form({ mode: 'deny', tools: ['search'] })), '')
})

test('listProblem: an unscoped allow entry is a problem on a group key only, and an empty list is fine', () => {
  assert.equal(listProblem([], 'allow', true), '')
  assert.match(listProblem(['gh__x', 'search'], 'allow', true), /"search" names no member/)
  assert.equal(listProblem(['search'], 'deny', true), '')
  assert.equal(listProblem(['search'], 'allow', false), '')
  assert.match(listProblem(['delete repo'], 'deny', false), /space or a control character/)
})

// PORM-4 SR7: the one stored shape that blocks every tool without being unreadable.
test('filterAdmitsNothing: an allow rule whose every entry is unscoped', () => {
  assert.notEqual(filterAdmitsNothing(form({ mode: 'allow', tools: ['search'] })), '')
  assert.notEqual(filterAdmitsNothing(form({ mode: 'allow', tools: ['search'], prefixes: ['del'] })), '')
  assert.equal(filterAdmitsNothing(form({ mode: 'allow', tools: ['search', 'gh__search'] })), '')
  assert.equal(filterAdmitsNothing(form({ mode: 'deny', tools: ['search'] })), '')
  assert.equal(filterAdmitsNothing(form({ mode: 'allow' })), '')
  assert.equal(filterAdmitsNothing(form()), '')
})

test('filterListsNothing: a stored empty deny only', () => {
  assert.notEqual(filterListsNothing(form({ mode: 'deny' })), '')
  assert.equal(filterListsNothing(form({ mode: 'deny', prefixes: ['x'] })), '')
  assert.equal(filterListsNothing(form({ mode: 'allow' })), '')
  assert.equal(filterListsNothing(form()), '')
})

test('wholeMemberLabel is worded from the mode, and the prefix is the slug and the separator', () => {
  assert.equal(wholeMemberLabel('deny', 'gh'), 'Deny every tool on gh, including tools it adds later.')
  assert.equal(wholeMemberLabel('allow', 'gh'), 'Allow every tool on gh, including tools it adds later.')
  assert.equal(wholeMemberPrefix('gh'), 'gh__')
})

// PORM-4 SR10.
test('clampText cuts by code point and never leaves half a surrogate pair', () => {
  assert.deepEqual(clampText('abc', 3), { text: 'abc', cut: false })
  assert.deepEqual(clampText('abcd', 3), { text: 'abc', cut: true })
  const s = 'a\u{1f600}\u{1f600}'
  const got = clampText(s, 2)
  assert.deepEqual(got, { text: 'a\u{1f600}', cut: true })
  assert.equal(got.text.length, 3)
})
