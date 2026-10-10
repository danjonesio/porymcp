import { expect } from '@playwright/test'
import type { Group, Upstream, VirtualKey } from '../src/lib/api.ts'

// The management API as the specs call it from Node, for setup and for the
// rows a test must delete. It mirrors web/src/lib/api.ts (api(), :51-66) and
// cannot reuse it: that client reads the key from sessionStorage, which Node
// does not have, and its ApiError carries the server's message, which a spec
// must never put in an error. Errors here carry the status only. Node's own
// fetch is used, not Playwright's request fixture, because the fixture is
// traced with its headers.
const base = (process.env.PORYMCP_BASE_URL ?? '').replace(/\/$/, '')
const adminKey = process.env.ADMIN_API_KEY ?? ''

// List paths and the envelope each answer wraps its rows in, in one place for
// the counts projects and the sweep (the count_all idiom in scripts/smoke.sh).
export const LISTS = { upstreams: 'upstreams', groups: 'groups', 'virtual-keys': 'virtual_keys' } as const
export type ListPath = keyof typeof LISTS

type Row = { id: string; name: string }

function headers(withBody: boolean): Record<string, string> {
  const h: Record<string, string> = { Authorization: `Bearer ${adminKey}`, Accept: 'application/json' }
  if (withBody) h['Content-Type'] = 'application/json'
  return h
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: headers(body !== undefined),
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${method} ${path} answered ${res.status}`)
  const text = await res.text()
  return (text ? JSON.parse(text) : null) as T
}

export async function listRows(path: ListPath): Promise<Row[]> {
  const data = await api<Record<string, Row[]>>('GET', `/${path}`)
  const rows = data[LISTS[path]]
  if (!Array.isArray(rows)) throw new Error(`GET /${path} answered without a ${LISTS[path]} array`)
  return rows
}

export async function count(path: ListPath): Promise<number> {
  return (await listRows(path)).length
}

// The id of a row the UI has just created, polled with expect.poll, so a spec
// records it before any assertion that could fail and leave the row behind.
export async function waitForRow(path: ListPath, name: string): Promise<string> {
  let id = ''
  await expect
    .poll(
      async () => {
        id = (await listRows(path)).find((r) => r.name === name)?.id ?? ''
        return id
      },
      { message: `the created row is listed under /${path}`, timeout: 10_000 }
    )
    .not.toBe('')
  return id
}

export function createUpstream(body: Record<string, unknown>): Promise<Upstream> {
  return api<Upstream>('POST', '/upstreams', body)
}

export function patchUpstream(id: string, body: Record<string, unknown>): Promise<Upstream> {
  return api<Upstream>('PATCH', `/upstreams/${id}`, body)
}

export function createGroup(body: Record<string, unknown>): Promise<Group> {
  return api<Group>('POST', '/groups', body)
}

export function createKey(body: Record<string, unknown>): Promise<VirtualKey> {
  return api<VirtualKey>('POST', '/virtual-keys', body)
}

export function revokeKey(id: string): Promise<VirtualKey> {
  return api<VirtualKey>('POST', `/virtual-keys/${id}/revoke`)
}

// A row a test already deleted through the UI answers 404, which is the state
// wanted, so it is not an error here.
export async function remove(path: ListPath, id: string): Promise<void> {
  const res = await fetch(`${base}/api/v1/${path}/${id}`, { method: 'DELETE', headers: headers(false) })
  if (!res.ok && res.status !== 404) throw new Error(`DELETE /${path}/${id} answered ${res.status}`)
}
