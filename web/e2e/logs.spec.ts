import { eventSentence } from '../src/lib/admin-event.ts'
import type { AdminEvent } from '../src/lib/api.ts'
import { api, createKey, createUpstream, revokeKey } from './api.ts'
import { expect, STUB_URL, test } from './fixtures.ts'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

const base = (process.env.PORYMCP_BASE_URL ?? '').replace(/\/$/, '')

type Rpc = { status: number; session: string | null; version: string | null }

// A JSON-RPC call through the key's own door from Node. The answer may be
// plain JSON or one SSE event; only the status, the session id and the
// protocol version are kept.
async function rpc(id: string, plaintext: string, method: string, params: unknown, prior?: Rpc): Promise<Rpc> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${plaintext}`,
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  }
  if (prior?.session) headers['Mcp-Session-Id'] = prior.session
  if (prior?.version) headers['MCP-Protocol-Version'] = prior.version
  const res = await fetch(`${base}/${id}/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const text = await res.text()
  const data = text
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trim())
    .join('\n')
  let version: string | null = null
  try {
    const parsed = JSON.parse(data || text) as { result?: { protocolVersion?: string } }
    version = parsed.result?.protocolVersion ?? null
  } catch {
    version = null
  }
  return { status: res.status, session: res.headers.get('Mcp-Session-Id'), version }
}

test('proxy rows for the run key appear and the filters narrow them; admin activity names the run rows', async ({
  page,
  prefix,
  created,
}) => {
  const u = await createUpstream({
    name: `${prefix} lg mcp`,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'none',
    auth_config: {},
  })
  created.upstreams.push(u.id)
  const keyName = `${prefix} lg key`
  const k = await createKey({ name: keyName, target_type: 'upstream', target_id: u.id })
  created.keys.push(k.id)
  const plaintext = k.api_key ?? ''

  const init = await rpc(k.id, plaintext, 'initialize', {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'e2e', version: '0' },
  })
  expect(init.status, 'initialize through the active key').toBe(200)
  const list = await rpc(k.id, plaintext, 'tools/list', {}, init)
  expect(list.status, 'tools/list through the active key').toBe(200)
  await revokeKey(k.id)
  const refused = await rpc(k.id, plaintext, 'initialize', { protocolVersion: '2025-11-25', capabilities: {} })
  expect(refused.status, 'initialize through the revoked key').toBe(401)

  // The audit rows land a moment after the answers; wait for both through
  // the API before the page reads them once.
  await expect
    .poll(async () => (await api<{ logs: unknown[] }>('GET', `/logs?virtual_key_id=${k.id}&limit=100`)).logs.length)
    .toBe(2)

  await page.goto('/logs/')
  await expect(page.getByRole('heading', { name: 'Logs', exact: true })).toBeVisible()
  const proxyTable = page.getByRole('table').filter({ has: page.getByRole('columnheader', { name: 'Latency', exact: true }) })
  await page.getByLabel('Virtual key', { exact: true }).selectOption({ label: keyName })
  await expect(proxyTable.getByRole('row').filter({ hasText: 'tools/list' })).toHaveCount(1)
  await expect(proxyTable.getByRole('row').filter({ hasText: 'initialize' })).toHaveCount(1)
  await page.getByLabel('Status', { exact: true }).selectOption({ label: 'Success' })
  await expect(proxyTable.getByRole('row').filter({ hasText: 'tools/list' })).toHaveCount(1)
  await expect(proxyTable.getByRole('row').filter({ hasText: 'initialize' })).toHaveCount(1)
  await page.getByLabel('Method', { exact: true }).fill('tools/call')
  // web/src/app/(app)/logs/page.tsx:98
  await expect(page.getByText('No matching log entries.', { exact: true })).toBeVisible()
  await page.getByLabel('Method', { exact: true }).fill('')
  await proxyTable.getByRole('row').filter({ hasText: 'tools/list' }).click()
  await expect(page.getByRole('heading', { name: 'Log detail', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Log detail', exact: true })).toBeHidden()

  const adminTable = page.getByRole('table').filter({ has: page.getByRole('columnheader', { name: 'Event', exact: true }) })
  const sentence = (action: string) => eventSentence({ action, resource_name: keyName } as AdminEvent)
  await expect(adminTable).toContainText(sentence('virtual_key.create'))
  await expect(adminTable).toContainText(sentence('virtual_key.revoke'))
})
