import assert from 'node:assert/strict'
import test from 'node:test'
import type { Discovery } from './api.ts'
import {
  blocksEverything,
  catalogueComplete,
  catalogueSummary,
  coveredNote,
  coveringEntry,
  entryMark,
  idleMember,
  incompleteLine,
  incompleteMembers,
  memberFromDiscovery,
  unmatchedEntries,
  unnameableRowNote,
} from './catalogue.ts'
import type { Catalogue, Member, MemberCatalogue } from './catalogue.ts'
import { filterPermits } from './tool-entry.ts'

// Run with: npm test (node --test).

function member(slug: string, over: Partial<Member> = {}): Member {
  return { upstream_id: 'id-' + slug, slug, name: slug.toUpperCase(), enabled: true, transport: 'streamable_http', ...over }
}

function loaded(slug: string, tools: string[], over: Partial<MemberCatalogue> = {}): MemberCatalogue {
  return { ...idleMember(member(slug)), state: 'ok', tools: tools.map((name) => ({ name })), ...over }
}

function cat(...members: MemberCatalogue[]): Catalogue {
  return { members }
}

test('memberFromDiscovery: ok carries the tools; not ok is a failure with the server sentence', () => {
  const ok: Discovery = { ok: true, latency_ms: 1, tool_count: 1, tools: [{ name: 'search' }], truncated: true, unnameable_tools: 2 }
  assert.deepEqual(memberFromDiscovery(member('gh'), ok), {
    ...member('gh'),
    state: 'ok',
    tools: [{ name: 'search' }],
    truncated: true,
    unnameable: 2,
    error: '',
  })
  const bad: Discovery = { ok: false, latency_ms: 1, tool_count: 0, tools: [], truncated: false, unnameable_tools: 0, error: 'Refused.', upstream_message: 'nope' }
  const got = memberFromDiscovery(member('gh'), bad)
  assert.equal(got.state, 'failed')
  assert.equal(got.error, 'Refused. The server said: nope')
})

// PORM-4 SR8.
test('catalogueComplete: every current member answered with its whole catalogue', () => {
  assert.equal(catalogueComplete(cat()), false)
  assert.equal(catalogueComplete(cat(loaded('gh', ['a']), loaded('linear', []))), true)
  assert.equal(catalogueComplete(cat(loaded('gh', ['a']), idleMember(member('linear')))), false)
  assert.equal(catalogueComplete(cat(loaded('gh', ['a']), { ...idleMember(member('linear')), state: 'loading' })), false)
  assert.equal(catalogueComplete(cat(loaded('gh', ['a']), { ...idleMember(member('linear')), state: 'failed', error: 'x' })), false)
  assert.equal(catalogueComplete(cat(loaded('gh', ['a'], { truncated: true }))), false)
  // Unnameable tools do not count against it: no entry could have been matching one.
  assert.equal(catalogueComplete(cat(loaded('gh', ['a'], { unnameable: 3 }))), true)
  // A disabled member loads like any other and counts.
  assert.equal(catalogueComplete(cat(loaded('gh', ['a'], { enabled: false }))), true)
})

test('incompleteMembers and incompleteLine name who is missing, and say nothing before a load or when complete', () => {
  const partial = cat(loaded('gh', ['a']), { ...idleMember(member('linear')), state: 'failed', error: 'x' })
  assert.deepEqual(incompleteMembers(partial), ['LINEAR'])
  assert.equal(
    incompleteLine(partial),
    'Entries are not checked against what is advertised, because one catalogue is incomplete: LINEAR.',
  )
  assert.match(incompleteLine(cat(loaded('gh', ['a'], { truncated: true }), idleMember(member('linear')))), /these catalogues are incomplete: GH, LINEAR\./)
  assert.equal(incompleteLine(cat(idleMember(member('gh')), idleMember(member('linear')))), '')
  assert.equal(incompleteLine(cat(loaded('gh', ['a']))), '')
})

// PORM-4 SR8: a flag from a partial view would call a working rule dead.
test('unmatchedEntries: nothing when incomplete, the dead entry when complete', () => {
  const entries = ['gh__search', 'gh__gone', 'linear__list']
  const partial = cat(loaded('gh', ['search']), { ...idleMember(member('linear')), state: 'failed', error: 'x' })
  assert.deepEqual(unmatchedEntries(entries, partial, { prefix: false }), [])
  const complete = cat(loaded('gh', ['search']), loaded('linear', ['list']))
  assert.deepEqual(unmatchedEntries(entries, complete, { prefix: false }), ['gh__gone'])
  assert.deepEqual(unmatchedEntries(['sea', 'zzz', 'gh__'], complete, { prefix: true }), ['zzz'])
})

test('unmatchedEntries: an entry scoped to a loaded disabled member still matches', () => {
  const c = cat(loaded('gh', ['search'], { enabled: false }))
  assert.deepEqual(unmatchedEntries(['gh__search'], c, { prefix: false }), [])
})

// PORM-4 D4, SR8: a row never reads the opposite of the rule.
test('coveringEntry: a whole-member prefix covers every row of that member and no other', () => {
  const o = { tools: [] as string[], prefixes: ['gh__'], side: 'deny' as const, groupTarget: true }
  assert.equal(coveringEntry('gh', 'search', o), 'gh__')
  assert.equal(coveringEntry('gh', 'delete_repo', o), 'gh__')
  assert.equal(coveringEntry('linear', 'search', o), '')
})

test('coveringEntry: a bare entry covers on the deny side and on an upstream target, never on a group allow side', () => {
  assert.equal(coveringEntry('gh', 'search', { tools: ['search'], prefixes: [], side: 'deny', groupTarget: true }), 'search')
  assert.equal(coveringEntry('gh', 'search', { tools: ['search'], prefixes: [], side: 'allow', groupTarget: false }), 'search')
  assert.equal(coveringEntry('gh', 'search', { tools: ['search'], prefixes: [], side: 'allow', groupTarget: true }), '')
  assert.equal(coveringEntry('gh', 'search', { tools: [], prefixes: ['sea'], side: 'allow', groupTarget: true }), '')
})

test("coveringEntry: the row's own scoped entry is not what covers it", () => {
  assert.equal(coveringEntry('gh', 'search', { tools: ['gh__search'], prefixes: [], side: 'deny', groupTarget: true }), '')
  assert.equal(
    coveringEntry('gh', 'search', { tools: ['gh__search', 'search'], prefixes: [], side: 'deny', groupTarget: true }),
    'search',
  )
})

// PORM-4 SR7, SR8.
test('blocksEverything: never on an incomplete catalogue', () => {
  const nothing = filterPermits({ mode: 'allow', tools: ['gh__absent'], prefixes: [] })
  assert.equal(blocksEverything(nothing, cat(loaded('gh', ['search']), idleMember(member('linear')))), false)
  assert.equal(blocksEverything(nothing, cat(loaded('gh', ['search'], { truncated: true }))), false)
})

test('blocksEverything: an allow of an absent tool, an unscoped allow, and a deny prefix over a one-member group', () => {
  const c = cat(loaded('gh', ['search', 'delete_repo']))
  assert.equal(blocksEverything(filterPermits({ mode: 'allow', tools: ['gh__absent'], prefixes: [] }), c), true)
  assert.equal(blocksEverything(filterPermits({ mode: 'allow', tools: ['search'], prefixes: [] }), c), true)
  assert.equal(blocksEverything(filterPermits({ mode: 'deny', tools: [], prefixes: ['gh__'] }), c), true)
  assert.equal(blocksEverything(filterPermits({ mode: 'deny', tools: ['gh__search'], prefixes: [] }), c), false)
  assert.equal(blocksEverything(filterPermits({ mode: '', tools: [], prefixes: [] }), c), false)
})

test('blocksEverything: disabled members are left out, and a target that advertises nothing blocks nothing', () => {
  const denyGh = filterPermits({ mode: 'deny', tools: [], prefixes: ['gh__'] })
  // linear is disabled, so the proxy lists only gh, and gh is wholly denied.
  assert.equal(blocksEverything(denyGh, cat(loaded('gh', ['search']), loaded('linear', ['list'], { enabled: false }))), true)
  assert.equal(blocksEverything(denyGh, cat(loaded('gh', ['search']), loaded('linear', ['list']))), false)
  assert.equal(blocksEverything(denyGh, cat(loaded('gh', []))), false)
})

test('catalogueSummary reads the loaded members, and says so when some or all could not be loaded', () => {
  assert.equal(
    catalogueSummary(cat(loaded('gh', ['a', 'b']), loaded('linear', ['c']), idleMember(member('docs')))),
    'GH, 2 tools. LINEAR, 1 tool.',
  )
  const down: MemberCatalogue = { ...idleMember(member('docs')), state: 'failed', error: 'x' }
  assert.equal(catalogueSummary(cat(loaded('gh', ['a']), down)), 'GH, 1 tool. 1 upstream could not be loaded.')
  assert.equal(catalogueSummary(cat(down, { ...down, upstream_id: 'other' })), '2 upstreams could not be loaded.')
})

// PORM-4 SR8, SR11: a tool no entry can name is still reached by a prefix, and the row must say so.
test('coveringEntry answers for a name that holds a space', () => {
  const o = { tools: [] as string[], prefixes: ['gh__my'], side: 'allow' as const, groupTarget: true }
  assert.equal(coveringEntry('gh', 'my tool', o), 'gh__my')
  assert.equal(coveringEntry('gh', 'other tool', o), '')
})

// PORM-4 SR11.
test('unnameableRowNote names the prefix route where there are prefixes, and the allow consequence', () => {
  assert.equal(
    unnameableRowNote('deny', true, false),
    'This name holds a space or a control character, so no tool entry can name it. A prefix that stops before that character can.',
  )
  assert.match(unnameableRowNote('allow', true, false), /It stays blocked, because it is not on the list\.$/)
  assert.doesNotMatch(unnameableRowNote('deny', false, false), /prefix/)
  // Once a prefix reaches it, the row must not go on saying it is blocked: under allow it is permitted.
  assert.equal(
    unnameableRowNote('allow', true, true),
    'This name holds a space or a control character, so no tool entry can name it.',
  )
})

test('entryMark: a problem wins, then Not advertised, then the kind of entry', () => {
  const o = { kind: 'tool' as const, side: 'allow' as 'allow' | 'deny', groupTarget: true, keyList: false, unmatched: ['gh__gone', 'search'] }
  assert.equal(entryMark('search', o).badge, 'Cannot be saved')
  assert.match(entryMark('search', o).note, /names no member/)
  assert.deepEqual(entryMark('gh__gone', o), {
    badge: 'Not advertised',
    note: 'No member advertises this tool right now, so this entry admits nothing.',
  })
  assert.equal(entryMark('gh__gone', { ...o, side: 'deny' }).note, 'No member advertises this tool right now. The rule is kept and applies if the tool comes back.')
  // A key's lists also govern prompts and resources by bare name, so the claim is tools-only.
  assert.equal(entryMark('gh__gone', { ...o, keyList: true }).note, 'No tool advertised right now carries this name. The rule is kept.')
  assert.deepEqual(entryMark('gh__', { ...o, kind: 'prefix' as const, unmatched: [] }), { badge: 'Prefix', note: '' })
  assert.deepEqual(entryMark('search', { ...o, side: 'deny', unmatched: [] }), { badge: 'Any member', note: '' })
  // On a single-upstream key a bare name reaches one member only, so the badge says nothing.
  assert.deepEqual(entryMark('search', { ...o, side: 'deny', groupTarget: false, unmatched: [] }), { badge: '', note: '' })
  assert.deepEqual(entryMark('gh__search', { ...o, unmatched: [] }), { badge: '', note: '' })
})

test('coveredNote names the entry that covers the row', () => {
  assert.equal(coveredNote('gh__'), 'Covered by gh__. Change it in the entries above.')
})

// PORM-181: an overruled allow entry outranks Not advertised, and a prefix row carries what it matches.
test('entryMark: Also denied sits after a problem and before Not advertised; a prefix row carries its note', () => {
  const o = { kind: 'tool' as const, side: 'allow' as const, groupTarget: true, keyList: true, unmatched: ['gh__gone'] }
  assert.deepEqual(entryMark('gh__gone', { ...o, overruled: 'Deny wins.' }), { badge: 'Also denied', note: 'Deny wins.' })
  assert.equal(entryMark('search', { ...o, overruled: 'Deny wins.' }).badge, 'Cannot be saved')
  assert.deepEqual(entryMark('gh__', { ...o, kind: 'prefix' as const, side: 'deny' as const, unmatched: [], prefixNote: 'Matches 2 tools.' }), {
    badge: 'Prefix',
    note: 'Matches 2 tools.',
  })
})
