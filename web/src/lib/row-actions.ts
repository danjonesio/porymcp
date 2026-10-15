import type { Upstream } from './api.ts'
import { connectLabel } from './upstream-auth.ts'

/**
 * The row Actions menus on Virtual keys, Upstreams and Groups (PORM-219).
 * Each table's menu is declared here, so the three pages only bind handlers
 * and render, and the order is one rule the tests pin: the row's own
 * actions first (Policy, Connect, Tools, Edit), then the consequential ones
 * after a divider, with Delete last and the only destructive item. The lib
 * returns action ids and
 * labels, never callbacks: the page binds each id to a closure over its own
 * row, so an item can never act on a row it was not built for.
 */

/** The visible label on the pressed row's trigger while a connect is in flight. */
export const CONNECTING = 'Connecting…'

/** Item labels shared by the menus and imported by the browser suite. */
export const ROW_ACTION_LABELS = {
  policy: 'Policy',
  edit: 'Edit',
  rotate: 'Rotate',
  revoke: 'Revoke',
  delete: 'Delete',
} as const

/** An HTTP API's connection test is Test; an MCP server's tool listing is Tools. */
export function toolsLabel(kind: string): 'Tools' | 'Test' {
  return kind === 'http' ? 'Test' : 'Tools'
}

export type RowActionSpec<A extends string> = { action: A; label: string; destructive?: true }
/** One menu as sections; RowActions draws a divider between two sections. */
export type RowMenuSpec<A extends string> = RowActionSpec<A>[][]
export type RowAction = { label: string; onSelect: () => void; destructive?: true }

export type VirtualKeyAction = 'policy' | 'edit' | 'rotate' | 'revoke' | 'delete'
export type UpstreamAction = 'connect' | 'tools' | 'edit' | 'delete'
export type GroupAction = 'edit' | 'delete'

const remove = { action: 'delete', label: ROW_ACTION_LABELS.delete, destructive: true } as const

/**
 * A key's menu. The list does not change with the key's status: a revoked
 * or expired key still offers every item, and the API's own answer is
 * shown, as it was with the buttons.
 */
export function virtualKeyActions(): RowMenuSpec<VirtualKeyAction> {
  return [
    [
      { action: 'policy', label: ROW_ACTION_LABELS.policy },
      { action: 'edit', label: ROW_ACTION_LABELS.edit },
    ],
    [{ action: 'rotate', label: ROW_ACTION_LABELS.rotate }, { action: 'revoke', label: ROW_ACTION_LABELS.revoke }, remove],
  ]
}

/**
 * An upstream's menu. Connect or Reconnect leads on an oauth row, so the
 * item the amber Auth badge points at is the first one; the server refuses
 * oauth on an HTTP API, so Connect and Test never share a menu.
 */
export function upstreamActions(u: Pick<Upstream, 'kind' | 'auth_type' | 'oauth'>): RowMenuSpec<UpstreamAction> {
  const first: RowActionSpec<UpstreamAction>[] = []
  if (u.auth_type === 'oauth') first.push({ action: 'connect', label: connectLabel(u) })
  first.push({ action: 'tools', label: toolsLabel(u.kind) }, { action: 'edit', label: ROW_ACTION_LABELS.edit })
  return [first, [remove]]
}

export function groupActions(): RowMenuSpec<GroupAction> {
  return [[{ action: 'edit', label: ROW_ACTION_LABELS.edit }], [remove]]
}

/**
 * Pairs each item with the page's handler for its id. `run` is a record over
 * every id the menu can hold, so a page that leaves one out fails the type
 * check rather than rendering a dead item.
 */
export function bindRowActions<A extends string>(menu: RowMenuSpec<A>, run: Record<A, () => void>): RowAction[][] {
  return menu.map((section) =>
    section.map(({ action, label, destructive }) =>
      destructive ? { label, onSelect: run[action], destructive } : { label, onSelect: run[action] }
    )
  )
}

/**
 * While one connect is in flight every row's trigger is held, so a second
 * sign-in cannot start, and only the pressed row says why.
 */
export function rowConnectState(rowId: string, connecting: string | null): { disabled: boolean; busyLabel: string | null } {
  return { disabled: connecting !== null, busyLabel: connecting === rowId ? CONNECTING : null }
}

/**
 * The trigger's accessible name. While busy the visible label starts the
 * name, so speech input can say what the screen shows, and the row's name
 * still follows it whole.
 */
export function actionsTriggerName(name: string, busyLabel: string | null): string {
  return busyLabel ? `${busyLabel} ${name}` : `Actions for ${name}`
}
