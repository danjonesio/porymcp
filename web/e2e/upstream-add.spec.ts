import { AUTH_TYPE_LABELS, KIND_LABELS } from '../src/lib/upstream-form.ts'
import { testState } from '../src/lib/upstream-test.ts'
import { ROW_ACTION_LABELS, toolsLabel } from '../src/lib/row-actions.ts'
import { waitForRow } from './api.ts'
import { alertTitled, expect, rowAction, rowNamed, STUB_URL, test } from './fixtures.ts'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

test('an MCP upstream with a bearer credential is listed, not tested, then passes, and a wrong path fails', async ({
  page,
  prefix,
  created,
}) => {
  const mcp = `${prefix} ua mcp`
  const nope = `${prefix} ua nope`
  const notTested = testState({ last_test_at: null, last_test_ok: null }, 0).word

  await page.goto('/upstreams/')
  await expect(page.getByRole('heading', { name: 'Upstreams', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Add upstream', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Add upstream', exact: true })).toBeVisible()
  await expect(page.getByRole('radio', { name: KIND_LABELS.mcp, exact: true })).toBeChecked()
  await page.getByLabel('Name', { exact: true }).fill(mcp)
  await page.getByLabel('URL', { exact: true }).fill(`${STUB_URL}/mcp`)
  await page.getByLabel('Auth type', { exact: true }).selectOption({ label: AUTH_TYPE_LABELS.bearer })
  await page.getByLabel('Bearer token', { exact: true }).fill('e2eplainalpha')
  await page.getByRole('button', { name: 'Create', exact: true }).click()
  created.upstreams.push(await waitForRow('upstreams', mcp))
  await expect(page.getByRole('heading', { name: 'Add upstream', exact: true })).toBeHidden()

  const mcpRow = rowNamed(page, mcp)
  await expect(mcpRow).toBeVisible()
  await expect(mcpRow).toContainText(KIND_LABELS.mcp)
  await expect(mcpRow).toContainText('bearer')
  await expect(mcpRow).toContainText('· set')
  await expect(mcpRow).toContainText('Enabled')
  // Create runs no discovery; the state moves only when the Tools item in
  // the row's Actions menu records one (openTools in upstreams/page.tsx).
  await expect(mcpRow).toContainText(notTested)
  await rowAction(page, mcp, toolsLabel('mcp'))
  await expect(page.getByRole('heading', { name: 'Tools', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(mcpRow).toContainText(/Passed/)

  // The form resets between opens (PORM-2). The auth type persists by design
  // (upstreams/page.tsx:332-333), so only the name is asserted empty.
  await page.getByRole('button', { name: 'Add upstream', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Add upstream', exact: true })).toBeVisible()
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('')
  await page.getByLabel('Name', { exact: true }).fill(nope)
  await page.getByLabel('URL', { exact: true }).fill(`${STUB_URL}/nope`)
  await page.getByLabel('Auth type', { exact: true }).selectOption({ label: AUTH_TYPE_LABELS.none })
  await page.getByRole('button', { name: 'Create', exact: true }).click()
  created.upstreams.push(await waitForRow('upstreams', nope))
  await expect(page.getByRole('heading', { name: 'Add upstream', exact: true })).toBeHidden()

  const nopeRow = rowNamed(page, nope)
  await expect(nopeRow).toBeVisible()
  await expect(nopeRow).toContainText(notTested)
  await rowAction(page, nope, toolsLabel('mcp'))
  await expect(page.getByRole('heading', { name: 'Tools', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(nopeRow).toContainText(/Failed/)

  for (const name of [mcp, nope]) {
    await rowAction(page, name, ROW_ACTION_LABELS.delete)
    await alertTitled(page, 'Delete this upstream?').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(rowNamed(page, name)).toHaveCount(0)
  }
})
