import { createKey, createUpstream } from './api.ts'
import { expect, rowNamed, STUB_URL, test } from './fixtures.ts'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

const base = (process.env.PORYMCP_BASE_URL ?? '').replace(/\/$/, '')

// One initialize through the key's own door, from Node with the plaintext
// as the bearer. A GET answers 405 before auth (PORM-30), so the probe is a
// POST. Only the status comes back; nothing prints the URL or the header.
async function probe(id: string, plaintext: string): Promise<number> {
  const res = await fetch(`${base}/${id}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${plaintext}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } },
    }),
  })
  await res.text()
  return res.status
}

test('a revoked key reads revoked and the proxy answers 401', async ({ page, prefix, created }) => {
  const u = await createUpstream({
    name: `${prefix} rv mcp`,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'none',
    auth_config: {},
  })
  created.upstreams.push(u.id)
  const keyName = `${prefix} rv key`
  const k = await createKey({ name: keyName, target_type: 'upstream', target_id: u.id })
  created.keys.push(k.id)
  const plaintext = k.api_key ?? ''
  expect(plaintext !== '', 'the create answer carries the plaintext once').toBe(true)
  expect(await probe(k.id, plaintext), 'the active key is accepted').toBe(200)

  await page.goto('/virtual-keys/')
  const keyRow = rowNamed(page, keyName)
  await expect(keyRow).toContainText('active')
  // Revoke posts at once, with no confirm step (virtual-keys/page.tsx:314-321).
  await keyRow.getByRole('button', { name: 'Revoke', exact: true }).click()
  await expect(keyRow).toContainText('revoked')

  expect(await probe(k.id, plaintext), 'the revoked key is refused').toBe(401)
})
