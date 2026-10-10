import { expect, test } from './fixtures.ts'

// Settings renders the session key's first 12 characters and the retention
// note; it makes no health call (web/src/app/(app)/settings/page.tsx:16-71).
// The prefix line is matched by shape only; no key value is read here.
test('the settings page shows the session key prefix and the retention note', async ({ page }) => {
  await page.goto('/settings/')
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible()
  await expect(page.getByText('Admin key', { exact: true })).toBeVisible()
  await expect(page.getByText('Retention', { exact: true })).toBeVisible()
  await expect(page.getByText(/^Current session key: .{12}…$/)).toBeVisible()
  await expect(page.getByLabel('Replace session key', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Update', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible()
})
