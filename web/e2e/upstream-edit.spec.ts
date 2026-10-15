import { ROW_ACTION_LABELS } from '../src/lib/row-actions.ts'
import { AUTH_TYPE_LABELS } from '../src/lib/upstream-form.ts'
import { createUpstream, patchUpstream, waitForRow } from './api.ts'
import { expect, rowAction, rowNamed, STUB_URL, test } from './fixtures.ts'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

test('editing keeps the row and the None switch warns; a stored value on a None row is removed through the checkbox', async ({
  page,
  prefix,
  created,
}) => {
  const mcp = `${prefix} ue mcp`
  const u = await createUpstream({
    name: mcp,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'bearer',
    auth_config: { token: 'e2eplainalpha' },
  })
  created.upstreams.push(u.id)

  await page.goto('/upstreams/')
  const mcpRow = rowNamed(page, mcp)
  await rowAction(page, mcp, ROW_ACTION_LABELS.edit)
  await expect(page.getByRole('heading', { name: 'Edit upstream', exact: true })).toBeVisible()
  await expect(page.getByText(/^Slug: /)).toBeVisible()
  await page.getByLabel('Description', { exact: true }).fill('edited')
  await page.getByRole('button', { name: 'Save changes', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Edit upstream', exact: true })).toBeHidden()
  await expect(mcpRow).toBeVisible()

  await rowAction(page, mcp, ROW_ACTION_LABELS.edit)
  await expect(page.getByLabel('Description', { exact: true })).toHaveValue('edited')
  await page.getByLabel('Auth type', { exact: true }).selectOption({ label: AUTH_TYPE_LABELS.none })
  // web/src/lib/upstream-form.ts:503-507
  await expect(
    page.getByText(
      'Saving removes the stored credential. It cannot be recovered. Switching back later means entering it again.',
      { exact: true }
    )
  ).toBeVisible()
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Edit upstream', exact: true })).toBeHidden()

  // PORM-120: the checkbox renders only on a None row that still holds a
  // stored value. A credential sent alone to a none row is stored
  // (internal/api/upstreams.go:667-670, the path PORM-138 keeps legal), so
  // that state is seeded through one PATCH.
  const none = `${prefix} ue none`
  await page.getByRole('button', { name: 'Add upstream', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Add upstream', exact: true })).toBeVisible()
  await page.getByLabel('Name', { exact: true }).fill(none)
  await page.getByLabel('URL', { exact: true }).fill(`${STUB_URL}/mcp`)
  await page.getByLabel('Auth type', { exact: true }).selectOption({ label: AUTH_TYPE_LABELS.none })
  await page.getByRole('button', { name: 'Create', exact: true }).click()
  const noneId = await waitForRow('upstreams', none)
  created.upstreams.push(noneId)
  await expect(page.getByRole('heading', { name: 'Add upstream', exact: true })).toBeHidden()
  const noneRow = rowNamed(page, none)
  await expect(noneRow).toBeVisible()
  await patchUpstream(noneId, { auth_config: { token: 'e2eplainbravo' } })

  await page.reload()
  await rowAction(page, none, ROW_ACTION_LABELS.edit)
  await expect(page.getByRole('heading', { name: 'Edit upstream', exact: true })).toBeVisible()
  const clear = page.getByLabel('Remove the stored value', { exact: true })
  await expect(clear).toBeVisible()
  await clear.check()
  await page.getByRole('button', { name: 'Save changes', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Edit upstream', exact: true })).toBeHidden()

  await rowAction(page, none, ROW_ACTION_LABELS.edit)
  await expect(page.getByRole('heading', { name: 'Edit upstream', exact: true })).toBeVisible()
  await expect(page.getByLabel('Remove the stored value', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()
})
