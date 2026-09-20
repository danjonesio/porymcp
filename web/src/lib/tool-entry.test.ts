import assert from 'node:assert/strict'
import test from 'node:test'
import type { DiscoveredTool } from './api.ts'
import {
  cleanEntry,
  entryProblem,
  filterPermits,
  matchToolEntry,
  scopedToolName,
  splitEntry,
  tickEntry,
} from './tool-entry.ts'

// Run with: npm test (node --test). The .ts extensions above are required:
// Node will not resolve an extensionless TypeScript specifier.

test('scopedToolName joins the slug and the tool name the way the proxy does', () => {
  assert.equal(scopedToolName('github', 'create_issue'), 'github__create_issue')
})

test('scopedToolName leaves a tool name that already contains the separator alone', () => {
  // ParseCanonical splits on the first separator, so this round-trips to
  // slug "github", tool "a__b".
  assert.equal(scopedToolName('github', 'a__b'), 'github__a__b')
})

test('scopedToolName yields nothing without a slug', () => {
  assert.equal(scopedToolName('', 'x'), '')
})

// PORM-4 D3: a tick writes the scoped identity the saved discover route composed.
test('tickEntry prefers the scoped_name the server composed, and falls back to composing it', () => {
  const served: DiscoveredTool = { name: 'search', scoped_name: 'gh__search' }
  assert.equal(tickEntry('ignored', served), 'gh__search')
  assert.equal(tickEntry('gh', { name: 'search' }), 'gh__search')
})

test('splitEntry: scoped needs something before the separator', () => {
  assert.deepEqual(splitEntry('docs__search'), { head: 'docs', rest: 'search', scoped: true })
  assert.deepEqual(splitEntry('search'), { head: '', rest: 'search', scoped: false })
  // An upstream may advertise a tool really called "__search".
  assert.deepEqual(splitEntry('__search'), { head: '', rest: '__search', scoped: false })
  assert.deepEqual(splitEntry('docs__'), { head: 'docs', rest: '', scoped: true })
})

// Mirrors models.MatchToolEntry (internal/models/toolidentity.go).
test('matchToolEntry: a scoped entry matches only its member, an unscoped one matches every member', () => {
  assert.equal(matchToolEntry('gh__search', 'gh', 'search', false), true)
  assert.equal(matchToolEntry('gh__search', 'linear', 'search', false), false)
  assert.equal(matchToolEntry('search', 'gh', 'search', false), true)
  assert.equal(matchToolEntry('search', 'linear', 'search', false), true)
  assert.equal(matchToolEntry('search', 'gh', 'search_code', false), false)
})

// PORM-4 SR14: a prefix is compared with the tool's OWN name (policy.go matches).
test('matchToolEntry prefix: own name on every member, scoped to one, or a whole member', () => {
  assert.equal(matchToolEntry('delete_', 'gh', 'delete_repo', true), true)
  assert.equal(matchToolEntry('delete_', 'linear', 'delete_issue', true), true)
  assert.equal(matchToolEntry('gh__delete_', 'gh', 'delete_repo', true), true)
  assert.equal(matchToolEntry('gh__delete_', 'linear', 'delete_issue', true), false)
  assert.equal(matchToolEntry('gh__', 'gh', 'anything_at_all', true), true)
  assert.equal(matchToolEntry('gh__', 'linear', 'anything_at_all', true), false)
  // The composed name is never what a prefix is compared with.
  assert.equal(matchToolEntry('gh_', 'gh', 'search', true), false)
})

test('matchToolEntry: an empty entry matches nothing, even as a prefix', () => {
  assert.equal(matchToolEntry('', 'gh', 'search', false), false)
  assert.equal(matchToolEntry('', 'gh', 'search', true), false)
})

// Mirrors models.CleanToolEntry.
test('cleanEntry refuses empty, spaces, controls, U+FFFD and a lone surrogate', () => {
  assert.equal(cleanEntry('gh__search'), true)
  assert.equal(cleanEntry(''), false)
  assert.equal(cleanEntry('delete repo'), false)
  assert.equal(cleanEntry('delete repo'), false) // NBSP
  assert.equal(cleanEntry('delete repo'), false) // em space, category Zs
  assert.equal(cleanEntry('a\tb'), false)
  assert.equal(cleanEntry('a\u0085b'), false) // NEL: space and control in Go
  assert.equal(cleanEntry('a\u007fb'), false)
  assert.equal(cleanEntry('a�b'), false)
  assert.equal(cleanEntry('a\ud800b'), false)
  // Not spaces and not controls in Go, so not here either. PORM-83 owns these.
  assert.equal(cleanEntry('a​b'), true)
  assert.equal(cleanEntry('a﻿b'), true)
  // A well-formed astral character is fine.
  assert.equal(cleanEntry('tool\u{1f600}'), true)
})

// PORM-4 SR11: the write-side rules, asked only of an entry about to be sent.
test('entryProblem: the text rules', () => {
  const o = { kind: 'tool', side: 'deny', groupTarget: true } as const
  assert.notEqual(entryProblem('', o), '')
  assert.match(entryProblem('gh__delete repo', o), /space or a control character/)
  assert.match(entryProblem('gh__delete repo', o), /space or a control character/)
  assert.match(entryProblem('a\u0001b', o), /space or a control character/)
  assert.match(entryProblem('a�b', o), /space or a control character/)
  assert.equal(entryProblem('gh__delete_repo', o), '')
})

test('entryProblem: the shape rules', () => {
  const tool = { kind: 'tool', side: 'deny', groupTarget: true } as const
  const prefix = { kind: 'prefix', side: 'deny', groupTarget: true } as const
  // Nothing after the separator names no tool, but is "every tool on gh" as a prefix.
  assert.match(entryProblem('gh__', tool), /names no tool/)
  assert.equal(entryProblem('gh__', prefix), '')
  // The head must be a slug: uppercase, a separator run and a uuid are not.
  assert.match(entryProblem('My Upstream__x', tool), /space/)
  assert.match(entryProblem('GitHub__x', tool), /upstream's slug/)
  assert.match(entryProblem('a--b__x', tool), /upstream's slug/)
  assert.match(entryProblem('123e4567-e89b-12d3-a456-426614174000__x', tool), /upstream's slug/)
})

test('entryProblem: an unscoped entry is a problem only on the allow side of a group target', () => {
  assert.match(entryProblem('search', { kind: 'tool', side: 'allow', groupTarget: true }), /names no member/)
  assert.match(entryProblem('delete_', { kind: 'prefix', side: 'allow', groupTarget: true }), /names no member/)
  assert.equal(entryProblem('search', { kind: 'tool', side: 'deny', groupTarget: true }), '')
  assert.equal(entryProblem('search', { kind: 'tool', side: 'allow', groupTarget: false }), '')
  assert.equal(entryProblem('search', { kind: 'tool', side: 'deny', groupTarget: false }), '')
})

test('entryProblem: a prefix that stops before a space is clean, so it can cover a tool no tools entry can name', () => {
  assert.equal(entryProblem('gh__delete', { kind: 'prefix', side: 'deny', groupTarget: true }), '')
  assert.equal(matchToolEntry('gh__delete', 'gh', 'delete everything', true), true)
})

// PORM-4 SR7. Mirrors TestUnscopedAllowEntryIsSkippedOnAGroup
// (internal/proxy/policy_test.go): under allow, an unscoped entry admits nothing.
test('filterPermits: allow skips unscoped entries, so an allow rule holding nothing else admits nothing', () => {
  const bare = filterPermits({ mode: 'allow', tools: ['search'], prefixes: [] })
  assert.equal(bare('gh', 'search'), false)
  const scoped = filterPermits({ mode: 'allow', tools: ['gh__search'], prefixes: [] })
  assert.equal(scoped('gh', 'search'), true)
  assert.equal(scoped('gh', 'delete_repo'), false)
  assert.equal(scoped('linear', 'search'), false)
  const barePrefix = filterPermits({ mode: 'allow', tools: [], prefixes: ['sea'] })
  assert.equal(barePrefix('gh', 'search'), false)
})

test('filterPermits: deny honours unscoped entries and prefixes', () => {
  const f = filterPermits({ mode: 'deny', tools: ['delete_repo'], prefixes: ['gh__admin_'] })
  assert.equal(f('gh', 'delete_repo'), false)
  assert.equal(f('linear', 'delete_repo'), false)
  assert.equal(f('gh', 'admin_reset'), false)
  assert.equal(f('linear', 'admin_reset'), true)
  assert.equal(f('gh', 'search'), true)
  const whole = filterPermits({ mode: 'deny', tools: [], prefixes: ['gh__'] })
  assert.equal(whole('gh', 'search'), false)
  assert.equal(whole('linear', 'search'), true)
})

test('filterPermits: no mode permits everything', () => {
  assert.equal(filterPermits({ mode: '', tools: [], prefixes: [] })('gh', 'search'), true)
})
