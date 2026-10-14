import assert from 'node:assert/strict'
import test from 'node:test'
import type { UpstreamOAuth } from './api.ts'
import {
  actionsTriggerName,
  bindRowActions,
  CONNECTING,
  groupActions,
  type RowMenuSpec,
  rowConnectState,
  toolsLabel,
  upstreamActions,
  virtualKeyActions,
} from './row-actions.ts'

// Run with: npm test (node --test). The .ts extension above is required:
// Node will not resolve an extensionless TypeScript specifier.

const labels = <A extends string>(menu: RowMenuSpec<A>) => menu.map((s) => s.map((i) => i.label))

const connected: UpstreamOAuth = { expires_at: '2026-10-14T12:00:00Z', has_refresh_token: true, client_source: 'registered' }
const notConnected: UpstreamOAuth = { expires_at: null, has_refresh_token: false, client_source: null }

const mcp = { kind: 'mcp', auth_type: 'none' }
const http = { kind: 'http', auth_type: 'bearer' }

const everyMenu = (): [string, RowMenuSpec<string>][] => [
  ['virtual key', virtualKeyActions()],
  ['mcp upstream', upstreamActions(mcp)],
  ['http upstream', upstreamActions(http)],
  ['oauth not connected', upstreamActions({ kind: 'mcp', auth_type: 'oauth', oauth: notConnected })],
  ['oauth connected', upstreamActions({ kind: 'mcp', auth_type: 'oauth', oauth: connected })],
  ['oauth unreadable', upstreamActions({ kind: 'mcp', auth_type: 'oauth' })],
  ['group', groupActions()],
]

test('virtualKeyActions: Policy and Edit, then Rotate, Revoke and Delete', () => {
  assert.deepEqual(labels(virtualKeyActions()), [
    ['Policy', 'Edit'],
    ['Rotate', 'Revoke', 'Delete'],
  ])
})

test('upstreamActions: an MCP server with no oauth offers Tools and Edit, then Delete', () => {
  assert.deepEqual(labels(upstreamActions(mcp)), [['Tools', 'Edit'], ['Delete']])
})

test('upstreamActions: an HTTP API offers Test in place of Tools', () => {
  assert.deepEqual(labels(upstreamActions(http)), [['Test', 'Edit'], ['Delete']])
})

test('upstreamActions: an oauth row not connected starts with Connect', () => {
  assert.deepEqual(labels(upstreamActions({ kind: 'mcp', auth_type: 'oauth', oauth: notConnected })), [
    ['Connect', 'Tools', 'Edit'],
    ['Delete'],
  ])
})

test('upstreamActions: an oauth row holding a token set starts with Reconnect, expired or ok', () => {
  // The menu reads only the stored set, so an expired set and a live one
  // both offer Reconnect; the Auth badge is what tells them apart.
  const expiredSet: UpstreamOAuth = { ...connected, has_refresh_token: false }
  assert.equal(upstreamActions({ kind: 'mcp', auth_type: 'oauth', oauth: connected })[0][0].label, 'Reconnect')
  assert.equal(upstreamActions({ kind: 'mcp', auth_type: 'oauth', oauth: expiredSet })[0][0].label, 'Reconnect')
})

test('upstreamActions: an oauth row whose stored value cannot be read starts with Connect', () => {
  // An undecryptable oauth row arrives with no oauth object at all.
  assert.deepEqual(labels(upstreamActions({ kind: 'mcp', auth_type: 'oauth' })), [['Connect', 'Tools', 'Edit'], ['Delete']])
})

test('groupActions: Edit, then Delete', () => {
  assert.deepEqual(labels(groupActions()), [['Edit'], ['Delete']])
})

test('every menu: Delete is the only destructive item and comes last (AC 1)', () => {
  for (const [name, menu] of everyMenu()) {
    const flat = menu.flat()
    const last = flat[flat.length - 1]
    assert.equal(last.label, 'Delete', name)
    assert.equal(last.destructive, true, name)
    assert.deepEqual(
      flat.filter((i) => i.destructive).map((i) => i.label),
      ['Delete'],
      name
    )
  }
})

test('every menu: Rotate, Revoke and Delete are never the first item (security 4)', () => {
  // A held Enter on a trigger opens the menu on its first item and fires it.
  for (const [name, menu] of everyMenu()) {
    assert.ok(!['Rotate', 'Revoke', 'Delete'].includes(menu[0][0].label), name)
  }
})

test('every menu: no empty section and no repeated label', () => {
  for (const [name, menu] of everyMenu()) {
    assert.ok(
      menu.every((s) => s.length > 0),
      name
    )
    const flat = menu.flat().map((i) => i.label)
    assert.equal(new Set(flat).size, flat.length, name)
  }
})

test('toolsLabel: Test for http, Tools otherwise', () => {
  assert.equal(toolsLabel('http'), 'Test')
  assert.equal(toolsLabel('mcp'), 'Tools')
})

test('bindRowActions: keeps sections and order and runs the handler named by each action', () => {
  const ran: string[] = []
  const bound = bindRowActions(groupActions(), { edit: () => ran.push('edit'), delete: () => ran.push('delete') })
  assert.deepEqual(
    bound.map((s) => s.map((i) => [i.label, i.destructive ?? false])),
    [[['Edit', false]], [['Delete', true]]]
  )
  bound[1][0].onSelect()
  bound[0][0].onSelect()
  assert.deepEqual(ran, ['delete', 'edit'])
})

test('rowConnectState: nothing in flight leaves every trigger enabled with no label', () => {
  assert.deepEqual(rowConnectState('u1', null), { disabled: false, busyLabel: null })
})

test('rowConnectState: a connect in flight holds every trigger and labels only the pressed row', () => {
  assert.deepEqual(rowConnectState('u1', 'u1'), { disabled: true, busyLabel: CONNECTING })
  assert.deepEqual(rowConnectState('u2', 'u1'), { disabled: true, busyLabel: null })
})

test('actionsTriggerName: Actions for the name; Connecting… and the name while busy; a long name carried whole', () => {
  assert.equal(actionsTriggerName('github', null), 'Actions for github')
  assert.equal(actionsTriggerName('github', CONNECTING), 'Connecting… github')
  const long = 'a'.repeat(200)
  assert.equal(actionsTriggerName(long, null), `Actions for ${long}`)
})
