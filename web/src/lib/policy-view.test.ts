import assert from 'node:assert/strict'
import test from 'node:test'
import type { PolicyView } from './api.ts'
import {
  GROUP_GONE_SENTENCE,
  UPSTREAM_GONE_SENTENCE,
  alwaysRefusedCount,
  blockedLine,
  egressSentences,
  listEmptySentence,
  methodsSentence,
  shownForCountsOnly,
  statusLine,
  targetGoneSentence,
  visibleBlocks,
} from './policy-view.ts'
import { allowEntryDeniedBy, groupFilterSummary } from './rule-conflicts.ts'
import { METHODS_UNREADABLE_SENTENCE } from './virtual-key-form.ts'

// Run with: npm test (node --test). PORM-209: the Policy dialog's copy
// contract and its visibility rules. S5 in the plan: an unreadable rule never
// reads as one that refuses nothing.

const RULES = [
  'key_denylist',
  'key_allowlist',
  'key_lists_unreadable',
  'group_tool_filter',
  'group_tool_filter_unreadable',
  'http_methods',
  'http_methods_unreadable',
]
const CLASSES = ['metadata', 'loopback', 'unspecified', 'multicast', 'link-local', 'private']

function view(over: Partial<PolicyView> = {}, counts: Record<string, number> = {}): PolicyView {
  const by_rule = Object.fromEntries(RULES.map((r) => [r, counts[r] ?? 0]))
  const by_class = Object.fromEntries(CLASSES.map((c) => [c, counts[c] ?? 0]))
  return {
    virtual_key_id: 'k1',
    status: 'active',
    target_type: 'upstream',
    target_slug: 'github',
    target_kinds: ['mcp'],
    order: ['key_denylist', 'key_allowlist', 'group_tool_filter', 'http_methods'],
    lists_malformed: false,
    group_tool_filter: null,
    http_methods: null,
    http_methods_malformed: false,
    egress: { allow_loopback: false, deny_private: false },
    blocked: {
      since: '2026-10-06T00:00:00Z',
      until: '2026-10-13T00:00:00Z',
      by_rule,
      upstream_address_denied: CLASSES.reduce((n, c) => n + (counts[c] ?? 0), 0),
      upstream_address_denied_by_class: by_class,
    },
    ...over,
  }
}

test('the blocked line counts in words for 0, 1 and many', () => {
  assert.equal(blockedLine(0), 'Blocked no calls in the last 7 days.')
  assert.equal(blockedLine(1), 'Blocked 1 call in the last 7 days.')
  assert.equal(blockedLine(12), 'Blocked 12 calls in the last 7 days.')
})

test('each empty key list has its own sentence', () => {
  assert.equal(listEmptySentence('deny'), 'No entries. This list blocks nothing.')
  assert.equal(listEmptySentence('allow'), 'No entries. Every tool passes this list.')
})

test('unreadable methods are refused, not every method allowed (S5)', () => {
  assert.deepEqual(methodsSentence([], true), { tone: 'pink', sentence: METHODS_UNREADABLE_SENTENCE })
  assert.deepEqual(methodsSentence([], false), { tone: 'zinc', sentence: 'Every method is allowed.' })
  assert.equal(methodsSentence(['GET'], false), null)
})

test('a group filter the server calls malformed is unreadable even when the browser sees no filter (S5)', () => {
  const s = groupFilterSummary({ name: 'ops', tool_filter: undefined }, { malformed: true, listsAbove: true })
  assert.equal(s.tone, 'pink')
  assert.match(s.sentence, /cannot be read, so every tool on it is blocked/)
})

test('listsAbove points the no-filter sentence at the lists drawn before it', () => {
  const above = groupFilterSummary({ name: 'ops', tool_filter: undefined }, { listsAbove: true })
  assert.equal(above.sentence, "The group ops has no filter, so the key's two lists above are the only rules on this key.")
  const below = groupFilterSummary({ name: 'ops', tool_filter: undefined })
  assert.equal(below.sentence, 'The group ops has no filter, so the two lists below are the only rules on this key.')
})

test('egress switches read as sentences either way', () => {
  assert.deepEqual(egressSentences({ allow_loopback: false, deny_private: false }), {
    loopback: 'Loopback addresses are refused. Set UPSTREAM_ALLOW_LOOPBACK to allow them.',
    private: 'Private addresses are allowed. Set UPSTREAM_DENY_PRIVATE to refuse them.',
  })
  assert.deepEqual(egressSentences({ allow_loopback: true, deny_private: true }), {
    loopback: 'Loopback addresses are allowed by UPSTREAM_ALLOW_LOOPBACK.',
    private: 'Private addresses are refused by UPSTREAM_DENY_PRIVATE.',
  })
})

test('the always-refused count sums the four classes no switch controls', () => {
  assert.equal(alwaysRefusedCount(view({}, { metadata: 2, loopback: 5, 'link-local': 1, private: 3 })), 3)
})

test('revoked and expired keys each get their own status line', () => {
  assert.equal(statusLine('active'), null)
  assert.equal(statusLine('revoked'), 'This key is revoked. Its rules no longer run, and the counts stop at revocation.')
  assert.equal(statusLine('expired'), 'This key has expired. Its rules no longer run, and the counts stop at expiry.')
})

test('blocks follow the key doors', () => {
  assert.deepEqual(visibleBlocks(view()), ['mcp', 'outbound'])
  assert.deepEqual(visibleBlocks(view({ target_type: 'group', target_kinds: ['mcp', 'http'], http_methods: [] })), [
    'mcp',
    'http',
    'outbound',
  ])
})

test('a door that holds counts stays visible after the door went away', () => {
  const v = view({}, { http_methods: 3 })
  assert.deepEqual(visibleBlocks(v), ['mcp', 'http', 'outbound'])
  assert.equal(shownForCountsOnly(v, 'http'), true)
  assert.equal(shownForCountsOnly(v, 'mcp'), false)
})

test('a target that is gone shows outbound only, with a line saying why', () => {
  const group = view({ target_type: 'group', target_kinds: [], target_slug: '' })
  assert.deepEqual(visibleBlocks(group), ['outbound'])
  assert.equal(targetGoneSentence(group), GROUP_GONE_SENTENCE)
  const upstream = view({ target_kinds: [], target_slug: '' })
  assert.equal(targetGoneSentence(upstream), UPSTREAM_GONE_SENTENCE)
  assert.equal(targetGoneSentence(view()), null)
})

test('an unscoped allow entry on a single-upstream key is marked when the deny list names it', () => {
  const v = view({ key_allowlist: ['create_issue'], key_denylist: ['github__create_issue'] })
  assert.notEqual(allowEntryDeniedBy('create_issue', v.key_denylist ?? [], v.target_slug), '')
  assert.equal(allowEntryDeniedBy('create_issue', v.key_denylist ?? [], ''), '')
})
