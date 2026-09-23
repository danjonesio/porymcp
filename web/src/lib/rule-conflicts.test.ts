import assert from 'node:assert/strict'
import test from 'node:test'
import { idleMember } from './catalogue.ts'
import type { Catalogue, MemberCatalogue } from './catalogue.ts'
import {
  ALSO_DENIED_NOTE,
  allowEntryDeniedBy,
  allowListAdmitsNothing,
  deniedBy,
  entryTool,
  groupBlocks,
  groupFilterSummary,
  prefixMatchNote,
  prefixMatches,
} from './rule-conflicts.ts'

// Run with: npm test (node --test). PORM-181.

function loaded(slug: string, tools: string[], over: Partial<MemberCatalogue> = {}): MemberCatalogue {
  const m = { upstream_id: 'id-' + slug, slug, name: slug, enabled: true, transport: 'streamable-http', kind: 'mcp' }
  return { ...idleMember(m), state: 'ok', tools: tools.map((name) => ({ name })), ...over }
}
const cat = (...members: MemberCatalogue[]): Catalogue => ({ members })

test('entryTool: a scoped entry names its tool; a bare one only on a single-upstream key', () => {
  assert.deepEqual(entryTool('gh__search', ''), { slug: 'gh', name: 'search' })
  assert.deepEqual(entryTool('search', 'gh'), { slug: 'gh', name: 'search' })
  assert.equal(entryTool('search', ''), null)
  assert.equal(entryTool('gh__', ''), null)
})

// AC1: the rules Dan built on dev. Deny scrape, map and search; allow search.
test('an allow entry that is also on the deny list is overruled', () => {
  const deny = ['firecrawl__firecrawl_scrape', 'firecrawl__firecrawl_map', 'firecrawl__firecrawl_search']
  assert.equal(allowEntryDeniedBy('firecrawl__firecrawl_search', deny, 'firecrawl'), 'firecrawl__firecrawl_search')
  assert.equal(allowEntryDeniedBy('firecrawl__firecrawl_crawl', deny, 'firecrawl'), '')
  assert.match(ALSO_DENIED_NOTE, /Deny wins/)
})

// AC2.
test('a bare deny entry overrules a scoped allow entry; a deny entry scoped to another upstream does not', () => {
  assert.equal(allowEntryDeniedBy('gh__search', ['search'], ''), 'search')
  assert.equal(allowEntryDeniedBy('gh__search', ['linear__search'], ''), '')
  assert.equal(deniedBy('gh', 'search', ['gh__search_code']), '')
})

// AC3.
test('on a single-upstream key a bare allow entry is overruled by the scoped deny entry for that upstream', () => {
  assert.equal(allowEntryDeniedBy('search', ['gh__search'], 'gh'), 'gh__search')
  assert.equal(allowEntryDeniedBy('search', ['linear__search'], 'gh'), '')
  // Before a target is chosen nothing is claimed.
  assert.equal(allowEntryDeniedBy('search', ['gh__search'], ''), '')
})

// AC1, AC4.
test('allowListAdmitsNothing: only when every allow entry is dead, and never for an empty list', () => {
  const deny = ['gh__scrape', 'gh__map', 'gh__search']
  assert.equal(
    allowListAdmitsNothing(['gh__search'], deny, false, 'gh'),
    'Every tool on the allow list is also denied, so this key can call nothing.',
  )
  assert.equal(allowListAdmitsNothing(['gh__search', 'gh__crawl'], deny, false, 'gh'), '')
  // An empty allow list allows everything that is not denied.
  assert.equal(allowListAdmitsNothing([], deny, false, 'gh'), '')
  assert.equal(allowListAdmitsNothing(['gh__search'], [], false, 'gh'), '')
})

test('allowListAdmitsNothing: on a group key an entry that names no member admits nothing either', () => {
  assert.match(allowListAdmitsNothing(['search', 'gh__map'], ['gh__map'], true, ''), /denied or names no member/)
  assert.match(allowListAdmitsNothing(['search'], [], true, ''), /names no member/)
  assert.equal(allowListAdmitsNothing(['search', 'gh__crawl'], ['gh__map'], true, ''), '')
})

test('allowListAdmitsNothing claims nothing about a bare entry while the target is unknown', () => {
  assert.equal(allowListAdmitsNothing(['search'], ['search'], false, ''), '')
})

// AC6: the prefix Dan typed where he meant a tool name.
test('prefixMatches names every advertised tool the prefix reaches, on a complete catalogue only', () => {
  const tools = ['firecrawl_search', 'firecrawl_search_feedback', 'firecrawl_developer_search', 'firecrawl_scrape']
  const c = cat(loaded('firecrawl', tools))
  assert.deepEqual(prefixMatches('firecrawl__firecrawl_search', c), [
    'firecrawl__firecrawl_search',
    'firecrawl__firecrawl_search_feedback',
  ])
  assert.equal(
    prefixMatchNote('firecrawl__firecrawl_search', c),
    'Matches 2 tools advertised now: firecrawl__firecrawl_search, firecrawl__firecrawl_search_feedback.',
  )
  // A bare prefix reaches every member.
  assert.equal(prefixMatches('firecrawl_s', cat(loaded('a', tools), loaded('b', ['firecrawl_scrape']))).length, 4)
  // Nothing is claimed from a partial catalogue, and nothing is said about a prefix that matches nothing.
  assert.deepEqual(prefixMatches('firecrawl__firecrawl_search', cat(loaded('firecrawl', tools, { truncated: true }))), [])
  assert.equal(prefixMatchNote('firecrawl__firecrawl_search', cat(loaded('firecrawl', tools), idleMember({ upstream_id: 'x', slug: 'x', name: 'x', enabled: true, transport: '', kind: 'mcp' }))), '')
  assert.equal(prefixMatchNote('zzz', c), '')
})

test('prefixMatchNote counts the rest past five names', () => {
  const c = cat(loaded('gh', ['t1', 't2', 't3', 't4', 't5', 't6', 't7']))
  assert.equal(prefixMatchNote('gh__', c), 'Matches 7 tools advertised now: gh__t1, gh__t2, gh__t3, gh__t4, gh__t5, and 2 more.')
  assert.equal(prefixMatchNote('gh__t1', c), 'Matches 1 tool advertised now: gh__t1.')
})

// AC7.
test('groupFilterSummary: no filter, deny, allow, unreadable, and the two shapes that block or do nothing', () => {
  const none = groupFilterSummary({ name: 'Dev', tool_filter: undefined })
  assert.equal(none.tone, 'zinc')
  assert.match(none.sentence, /The group Dev has no filter/)

  const deny = groupFilterSummary({ name: 'Dev', tool_filter: { mode: 'deny', tools: ['gh__delete_repo'], prefixes: ['gh__admin_'] } })
  assert.match(deny.sentence, /already denies what is listed here, whatever this key allows/)
  assert.deepEqual([deny.tools, deny.prefixes, deny.more], [['gh__delete_repo'], ['gh__admin_'], 0])

  const allow = groupFilterSummary({ name: 'Dev', tool_filter: { mode: 'allow', tools: ['gh__search'] } })
  assert.match(allow.sentence, /allows only what is listed here/)

  const bad = groupFilterSummary({ name: 'Dev', tool_filter: { mode: 'Deny' } })
  assert.equal(bad.tone, 'pink')
  assert.match(bad.sentence, /cannot be read, so every tool on it is blocked whatever this key allows/)

  const dead = groupFilterSummary({ name: 'Dev', tool_filter: { mode: 'allow', tools: ['search'] } })
  assert.equal(dead.tone, 'pink')
  assert.match(dead.sentence, /name no member/)

  const empty = groupFilterSummary({ name: 'Dev', tool_filter: { mode: 'deny' } })
  assert.match(empty.sentence, /lists nothing, so it blocks nothing/)
})

test('groupFilterSummary lists at most twelve entries and counts the rest', () => {
  const tools = Array.from({ length: 10 }, (_, i) => `gh__t${i}`)
  const prefixes = ['a_', 'b_', 'c_', 'd_']
  const s = groupFilterSummary({ name: 'Dev', tool_filter: { mode: 'deny', tools, prefixes } })
  assert.deepEqual([s.tools.length, s.prefixes.length, s.more], [10, 2, 2])
})

// AC8.
test('groupBlocks follows the group filter as the proxy reads it', () => {
  const deny = groupBlocks({ tool_filter: { mode: 'deny', prefixes: ['gh__firecrawl_search'] } })
  assert.equal(deny('gh', 'firecrawl_search_feedback'), true)
  assert.equal(deny('gh', 'firecrawl_scrape'), false)
  const allow = groupBlocks({ tool_filter: { mode: 'allow', tools: ['gh__search'] } })
  assert.equal(allow('gh', 'search'), false)
  assert.equal(allow('gh', 'map'), true)
  assert.equal(groupBlocks({ tool_filter: undefined })('gh', 'search'), false)
  assert.equal(groupBlocks({ tool_filter: { mode: 'Deny' } })('gh', 'search'), true)
})
