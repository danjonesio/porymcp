import { ROW_ACTION_LABELS } from '../src/lib/row-actions.ts'
import { ZERO_ENTRIES } from '../src/lib/tool-filter.ts'
import { createUpstream, waitForRow } from './api.ts'
import { alertTitled, expect, rowAction, rowNamed, slugOf, STUB_URL, test } from './fixtures.ts'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

test('a group of two upstreams with an allow filter validates entries and the form resets', async ({
  page,
  prefix,
  created,
}) => {
  const names = [`${prefix} gr mcp`, `${prefix} gr nope`]
  for (const name of names) {
    const u = await createUpstream({
      name,
      kind: 'mcp',
      url: `${STUB_URL}/mcp`,
      transport: 'streamable-http',
      auth_type: 'none',
      auth_config: {},
    })
    created.upstreams.push(u.id)
  }
  const group = `${prefix} gr group`
  const create = page.getByRole('button', { name: 'Create', exact: true })

  await page.goto('/groups/')
  await page.getByRole('button', { name: 'Create group', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Create group', exact: true })).toBeVisible()
  await page.getByLabel('Name', { exact: true }).fill(group)
  for (const name of names) await page.getByLabel(name, { exact: true }).check()
  await page
    .getByRole('radiogroup', { name: 'Tool filter mode', exact: true })
    .getByRole('radio', { name: 'Allow only these tools', exact: true })
    .check()
  await expect(create).toBeDisabled()
  // The sentence renders as the empty note and as the blocked line
  // (web/src/app/tool-filter-fields.tsx:104, groups/page.tsx:381).
  await expect(page.getByText(ZERO_ENTRIES, { exact: true })).toHaveCount(2)

  const entry = page.getByLabel('Add a tool by name', { exact: true })
  await entry.fill('echo')
  await entry.press('Enter')
  await expect(page.getByText('Cannot be saved', { exact: true })).toBeVisible()
  await expect(create).toBeDisabled()
  await page.getByRole('button', { name: 'Remove echo', exact: true }).click()
  await entry.fill(`${slugOf(names[0])}__echo`)
  await entry.press('Enter')
  await expect(create).toBeEnabled()
  await create.click()
  created.groups.push(await waitForRow('groups', group))
  await expect(page.getByRole('heading', { name: 'Create group', exact: true })).toBeHidden()

  const groupRow = rowNamed(page, group)
  await expect(groupRow).toBeVisible()
  await expect(groupRow).toContainText('Allow filter')

  // The form resets between opens (PORM-2).
  await page.getByRole('button', { name: 'Create group', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Create group', exact: true })).toBeVisible()
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('')
  for (const name of names) await expect(page.getByLabel(name, { exact: true })).not.toBeChecked()
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()

  await rowAction(page, group, ROW_ACTION_LABELS.delete)
  await alertTitled(page, 'Delete this group?').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(rowNamed(page, group)).toHaveCount(0)
})
