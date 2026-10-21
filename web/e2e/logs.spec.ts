import type { Page } from '@playwright/test'
import { eventSentence } from '../src/lib/admin-event.ts'
import type { AdminEvent } from '../src/lib/api.ts'
import { countLine, LOAD_MORE_CALLS, LOAD_MORE_CHANGES, NO_LOGS, toLocalInput } from '../src/lib/logs-view.ts'
import { api, createGroup, createKey, createUpstream, patchUpstream, revokeKey } from './api.ts'
import { type Created, expect, STUB_URL, slugOf, test } from './fixtures.ts'

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

const INIT = { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } }

// The audit rows land a moment after the answers: wait through the API until
// a key has n rows before the page reads them.
async function waitForRows(keyId: string, n: number): Promise<void> {
  await expect
    .poll(async () => (await api<{ logs: unknown[] }>('GET', `/logs?virtual_key_id=${keyId}&limit=100`)).logs.length)
    .toBe(n)
}

// A key on its own upstream with n proxy rows of its own (one initialize,
// then tools/list), so a paging test never depends on rows another test left.
// The calls run one after another with no poll between them: the suite has a
// five-minute budget in CI.
async function seededKey(prefix: string, created: Created, tag: string, n: number) {
  const u = await createUpstream({
    name: `${prefix} ${tag} mcp`,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'none',
    auth_config: {},
  })
  created.upstreams.push(u.id)
  const name = `${prefix} ${tag} key`
  const k = await createKey({ name, target_type: 'upstream', target_id: u.id })
  created.keys.push(k.id)
  const plaintext = k.api_key ?? ''
  const init = await rpc(k.id, plaintext, 'initialize', INIT)
  expect(init.status, 'initialize through the seeded key').toBe(200)
  for (let i = 1; i < n; i++) await rpc(k.id, plaintext, 'tools/list', {}, init)
  await waitForRows(k.id, n)
  return { id: k.id, name, plaintext, init }
}

// A filter change waits for its own /logs answer before the table is read.
async function filtered(page: Page, answer: (url: string) => boolean, change: () => Promise<unknown>) {
  const res = page.waitForResponse((r) => r.url().includes('/api/v1/logs?') && answer(r.url()))
  await change()
  await res
}

const proxyTableOf = (page: Page) =>
  page.getByRole('table').filter({ has: page.getByRole('columnheader', { name: 'Latency', exact: true }) })
const proxyRows = (page: Page) => proxyTableOf(page).locator('tbody > tr')
const loadMoreCalls = (page: Page) => page.getByRole('button', { name: LOAD_MORE_CALLS, exact: true })
const isCursorPage = (u: URL) => u.pathname === '/api/v1/logs' && u.searchParams.has('cursor')

async function showKey(page: Page, keyId: string, keyName: string) {
  await filtered(
    page,
    (u) => u.includes(`virtual_key_id=${keyId}`),
    () => page.getByLabel('Virtual key', { exact: true }).selectOption({ label: keyName })
  )
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
  // A group key's aggregate initialize is answered by PoryMCP itself, so its
  // row carries no upstream_id. Made before the page loads: the Virtual key
  // options load once, on mount.
  const g = await createGroup({ name: `${prefix} lg group`, upstream_ids: [u.id] })
  created.groups.push(g.id)
  const groupKeyName = `${prefix} lg group key`
  const gk = await createKey({ name: groupKeyName, target_type: 'group', target_id: g.id })
  created.keys.push(gk.id)
  const groupInit = await rpc(gk.id, gk.api_key ?? '', 'initialize', INIT)
  expect(groupInit.status, 'initialize through the group key').toBe(200)

  const init = await rpc(k.id, plaintext, 'initialize', INIT)
  expect(init.status, 'initialize through the active key').toBe(200)
  const list = await rpc(k.id, plaintext, 'tools/list', {}, init)
  expect(list.status, 'tools/list through the active key').toBe(200)
  await revokeKey(k.id)
  const refused = await rpc(k.id, plaintext, 'initialize', { protocolVersion: '2025-11-25', capabilities: {} })
  expect(refused.status, 'initialize through the revoked key').toBe(401)

  await waitForRows(k.id, 2)
  await waitForRows(gk.id, 1)

  await page.goto('/logs/')
  await expect(page.getByRole('heading', { name: 'Logs', exact: true })).toBeVisible()
  const proxyTable = proxyTableOf(page)
  const rows = (text: string) => proxyTable.getByRole('row').filter({ hasText: text })
  // Every filter change refetches and the page drops any older answer
  // (useCursorPages); each change still waits for its own answer before the
  // table is read, and each filter is shown to remove a row that was there
  // before it.
  // The refused call's row carries no key, so the key filter must drop it.
  await expect(rows('blocked')).not.toHaveCount(0)
  await filtered(
    page,
    (u) => u.includes(`virtual_key_id=${k.id}`),
    () => page.getByLabel('Virtual key', { exact: true }).selectOption({ label: keyName })
  )
  await expect(rows('tools/list')).toHaveCount(1)
  await expect(rows('initialize')).toHaveCount(1)
  await expect(rows('blocked')).toHaveCount(0)
  await filtered(
    page,
    (u) => u.includes('status=error'),
    () => page.getByLabel('Status', { exact: true }).selectOption({ label: 'Error' })
  )
  await expect(page.getByText(NO_LOGS, { exact: true })).toBeVisible()
  await filtered(
    page,
    (u) => u.includes('status=success'),
    () => page.getByLabel('Status', { exact: true }).selectOption({ label: 'Success' })
  )
  await expect(rows('tools/list')).toHaveCount(1)
  await expect(rows('initialize')).toHaveCount(1)
  await filtered(
    page,
    (u) => u.includes('method='),
    () => page.getByLabel('Method', { exact: true }).fill('tools/call')
  )
  await expect(page.getByText(NO_LOGS, { exact: true })).toBeVisible()
  await filtered(
    page,
    (u) => u.includes('status=success') && !u.includes('method='),
    () => page.getByLabel('Method', { exact: true }).fill('')
  )
  await expect(rows('tools/list')).toHaveCount(1)
  await rows('tools/list').click()
  await expect(page.getByRole('heading', { name: 'Log detail', exact: true })).toBeVisible()
  // Criterion 4: the Upstream detail names the upstream, with its slug
  // beside it, not its id.
  const upstreamDetail = page.locator('dt:text-is("Upstream") + dd')
  await expect(upstreamDetail.getByText(u.name, { exact: true })).toBeVisible()
  await expect(upstreamDetail.getByText(slugOf(u.name), { exact: true })).toBeVisible()
  await expect(upstreamDetail).not.toContainText(u.id)
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Log detail', exact: true })).toBeHidden()

  // A row that reached no upstream reads the placeholder.
  await showKey(page, gk.id, groupKeyName)
  await rows('initialize').click()
  await expect(page.getByRole('heading', { name: 'Log detail', exact: true })).toBeVisible()
  await expect(page.locator('dt:text-is("Upstream") + dd')).toHaveText('None')
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Log detail', exact: true })).toBeHidden()

  const adminTable = page.getByRole('table').filter({ has: page.getByRole('columnheader', { name: 'Event', exact: true }) })
  const sentence = (action: string) => eventSentence({ action, resource_name: keyName } as AdminEvent)
  await expect(adminTable).toContainText(sentence('virtual_key.create'))
  await expect(adminTable).toContainText(sentence('virtual_key.revoke'))
})

// Criteria 1 and 2: Load more appends the next page without dropping the rows
// shown, goes on the last page, and a filter change starts again from page one.
test('Load more pages the proxy calls and a filter change starts again', async ({ page, prefix, created }) => {
  const key = await seededKey(prefix, created, 'lm', 50)

  await page.goto('/logs/')
  await showKey(page, key.id, key.name)
  // Exactly one page: no control.
  await expect(proxyRows(page)).toHaveCount(50)
  await expect(page.getByText(countLine(50, 'call', 'last'), { exact: true })).toBeVisible()
  await expect(loadMoreCalls(page)).toHaveCount(0)

  await rpc(key.id, key.plaintext, 'tools/list', {}, key.init)
  await waitForRows(key.id, 51)
  await filtered(page, (u) => !u.includes('virtual_key_id='), () =>
    page.getByLabel('Virtual key', { exact: true }).selectOption({ label: 'All virtual keys' })
  )
  await showKey(page, key.id, key.name)
  await expect(proxyRows(page)).toHaveCount(50)
  await expect(page.getByText(countLine(50, 'call', 'more'), { exact: true })).toBeVisible()

  // Pressed from the keyboard: the control goes on the last page and focus
  // moves to the count line instead of falling to the page.
  await loadMoreCalls(page).focus()
  await page.keyboard.press('Enter')
  await expect(proxyRows(page)).toHaveCount(51)
  const last = page.getByText(countLine(51, 'call', 'last'), { exact: true })
  await expect(last).toBeVisible()
  await expect(loadMoreCalls(page)).toHaveCount(0)
  await expect(last).toBeFocused()

  await filtered(page, (u) => u.includes('status=success'), () =>
    page.getByLabel('Status', { exact: true }).selectOption({ label: 'Success' })
  )
  await filtered(page, (u) => !u.includes('status='), () =>
    page.getByLabel('Status', { exact: true }).selectOption({ label: 'All statuses' })
  )
  await expect(proxyRows(page)).toHaveCount(50)
  await expect(loadMoreCalls(page)).toBeVisible()
})

// S1: a Load more still in flight when the filter changes is dropped, never
// appended under the new filter.
test('A Load more in flight is dropped when the filter changes', async ({ page, prefix, created }) => {
  const key = await seededKey(prefix, created, 'lf', 51)
  let release: () => void = () => {}
  const held = new Promise<void>((r) => {
    release = r
  })
  await page.route(isCursorPage, async (route) => {
    await held
    await route.continue()
  })

  await page.goto('/logs/')
  await showKey(page, key.id, key.name)
  await expect(proxyRows(page)).toHaveCount(50)
  const heldPage = page.waitForResponse((r) => isCursorPage(new URL(r.url())))
  await loadMoreCalls(page).click()
  await filtered(page, (u) => u.includes('status=success'), () =>
    page.getByLabel('Status', { exact: true }).selectOption({ label: 'Success' })
  )
  release()
  await heldPage
  await page.evaluate(() => new Promise(requestAnimationFrame))
  await expect(proxyRows(page)).toHaveCount(50)
  await expect(page.getByText(countLine(50, 'call', 'more'), { exact: true })).toBeVisible()
  await expect(loadMoreCalls(page)).toBeVisible()
})

// S1: a slow first page for an older filter never replaces a newer answer.
test('A stale first page never lands', async ({ page, prefix, created }) => {
  const key = await seededKey(prefix, created, 'sf', 2)
  let release: () => void = () => {}
  const held = new Promise<void>((r) => {
    release = r
  })
  const isErrorPage = (u: URL) => u.pathname === '/api/v1/logs' && u.searchParams.get('status') === 'error'
  await page.route(isErrorPage, async (route) => {
    await held
    await route.continue()
  })

  await page.goto('/logs/')
  await showKey(page, key.id, key.name)
  const heldPage = page.waitForResponse((r) => isErrorPage(new URL(r.url())))
  await page.getByLabel('Status', { exact: true }).selectOption({ label: 'Error' })
  await filtered(page, (u) => u.includes('status=success'), () =>
    page.getByLabel('Status', { exact: true }).selectOption({ label: 'Success' })
  )
  release()
  await heldPage
  await page.evaluate(() => new Promise(requestAnimationFrame))
  await expect(proxyRows(page)).toHaveCount(2)
  await expect(page.getByText(NO_LOGS, { exact: true })).toHaveCount(0)
})

// A 400 to a Load more is a cursor the server refuses: the control goes and
// nothing retries. Any other failure keeps the control for a manual retry.
test('A refused cursor stops Load more; a failed one can be retried', async ({ page, prefix, created }) => {
  const key = await seededKey(prefix, created, 'rc', 51)
  let cursorRequests = 0
  page.on('request', (r) => {
    if (isCursorPage(new URL(r.url()))) cursorRequests++
  })
  await page.route(
    isCursorPage,
    (route) => route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: 'invalid cursor' }) }),
    { times: 1 }
  )

  await page.goto('/logs/')
  await showKey(page, key.id, key.name)
  await loadMoreCalls(page).click()
  await expect(page.getByRole('alert').filter({ hasText: 'invalid cursor' })).toBeVisible()
  await expect(loadMoreCalls(page)).toHaveCount(0)
  await expect(proxyRows(page)).toHaveCount(50)
  expect(cursorRequests, 'one cursor request, no retry').toBe(1)

  const refusal = 'The test refused this page.'
  await page.route(
    isCursorPage,
    (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: refusal }) }),
    { times: 1 }
  )
  await page.reload()
  await showKey(page, key.id, key.name)
  await loadMoreCalls(page).click()
  await expect(page.getByRole('alert').filter({ hasText: refusal })).toBeVisible()
  await expect(loadMoreCalls(page)).toBeVisible()
  await loadMoreCalls(page).click()
  await expect(proxyRows(page)).toHaveCount(51)
  await expect(page.getByRole('alert').filter({ hasText: refusal })).toHaveCount(0)
})

// A failed first load is not "nothing matched": the error shows and the empty
// copy does not.
test('A failed first load shows the error, not the empty copy', async ({ page }) => {
  const refusal = 'The test refused the first page.'
  await page.route(
    (u) => u.pathname === '/api/v1/logs' && !u.searchParams.has('cursor'),
    (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: refusal }) }),
    { times: 1 }
  )
  await page.goto('/logs/')
  await expect(page.getByText(refusal, { exact: true })).toBeVisible()
  await expect(page.getByText(NO_LOGS, { exact: true })).toHaveCount(0)
  await expect(proxyTableOf(page)).toHaveCount(0)
})

// Criterion 3: Since today and Until yesterday is an empty window: the empty
// copy, Until's message, and no console error.
test('Custom since today and until yesterday shows the empty copy', async ({ page }) => {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text())
  })
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const yesterday = new Date(today)
  yesterday.setDate(today.getDate() - 1)

  await page.goto('/logs/')
  await expect(page.getByRole('heading', { name: 'Proxy calls', exact: true })).toBeVisible()
  await page.getByLabel('Period', { exact: true }).selectOption({ label: 'Custom' })
  await page.getByLabel('Since', { exact: true }).fill(toLocalInput(today.getTime()))
  await filtered(page, (u) => u.includes('until='), () =>
    page.getByLabel('Until', { exact: true }).fill(toLocalInput(yesterday.getTime()))
  )
  await expect(page.getByText(NO_LOGS, { exact: true })).toBeVisible()
  await expect(page.getByText('Until is earlier than Since.', { exact: true })).toBeVisible()
  expect(errors).toEqual([])
})

// Admin activity pages too. The database is shared with the other specs, so
// the check is growth past one page, not a total.
test('Admin activity loads more changes', async ({ page, prefix, created }) => {
  const u = await createUpstream({
    name: `${prefix} ae mcp`,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'none',
    auth_config: {},
  })
  created.upstreams.push(u.id)
  for (let i = 0; i < 51; i++) await patchUpstream(u.id, { description: `change ${i}` })

  await page.goto('/logs/')
  const adminTable = page.getByRole('table').filter({ has: page.getByRole('columnheader', { name: 'Event', exact: true }) })
  const adminRows = adminTable.locator('tbody > tr')
  const answered = page.waitForResponse((r) => r.url().includes('/api/v1/admin-events?') && r.url().includes('resource_type=upstream'))
  await page.getByLabel('Resource', { exact: true }).selectOption({ label: 'Upstreams' })
  await answered
  await expect(adminRows).toHaveCount(50)
  await page.getByRole('button', { name: LOAD_MORE_CHANGES, exact: true }).click()
  await expect.poll(async () => adminRows.count()).toBeGreaterThan(50)
})
