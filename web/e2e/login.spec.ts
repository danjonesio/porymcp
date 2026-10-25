import { expect, test } from '@playwright/test'
import { ADMIN_KEY_STORAGE } from './fixtures.ts'

// The login flow uses Playwright's own test, not the seeded fixture: the seed
// would sign the page back in on every load, which is the opposite of what
// sign out and the redirect prove.

test('a wrong key shows the refusal line', async ({ page }) => {
  await page.goto('/login/')
  await expect(page.getByRole('heading', { name: 'Sign in to PoryMCP', exact: true })).toBeVisible()
  await page.getByLabel('Admin API key', { exact: true }).fill('notthekey')
  // The page shows the same line for a 500 or a network failure, so the
  // status of the probe is what proves a refusal.
  const probe = page.waitForResponse((r) => r.url().endsWith('/api/v1/stats'))
  await page.getByRole('button', { name: 'Open dashboard', exact: true }).click()
  expect((await probe).status(), 'the probe with a wrong key answers 401').toBe(401)
  // web/src/app/login/page.tsx:33
  const line = page.locator('p[role="alert"]')
  await expect(line).toHaveText('That admin key was not accepted.')
  // PORM-225 criterion 1: drawn with errorLine, the line is pink, not the
  // grey of body text, in light and in dark.
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme })
    const [alert, text] = await Promise.all([
      line.evaluate((el) => getComputedStyle(el).color),
      page.locator('p[data-slot="text"]').first().evaluate((el) => getComputedStyle(el).color),
    ])
    expect(alert !== text, `the refusal line has its own colour in ${scheme} mode`).toBe(true)
  }
})

test('the right key opens the overview and sign out returns to the login page', async ({ page }) => {
  await page.goto('/login/')
  await page.getByLabel('Admin API key', { exact: true }).fill(process.env.ADMIN_API_KEY ?? '')
  await page.getByRole('button', { name: 'Open dashboard', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible()
  const main = page.getByRole('main')
  for (const title of ['Active virtual keys', 'Calls today', 'Upstreams', 'Error rate']) {
    await expect(main.getByText(title, { exact: true })).toBeVisible()
  }
  // The sidebar menu button's name joins two spans; the regex tolerates the
  // join (web/src/app/application-layout.tsx:96-108).
  await page.getByRole('button', { name: /^Admin\s*Management API$/ }).click()
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to PoryMCP', exact: true })).toBeVisible()
  await expect(page).toHaveURL(/\/login\/$/)
  const cleared = await page.evaluate((name) => sessionStorage.getItem(name) === null, ADMIN_KEY_STORAGE)
  expect(cleared, 'sign out removed the stored key').toBe(true)
})

test('a page without a key redirects to login', async ({ page }) => {
  await page.goto('/upstreams/')
  await expect(page).toHaveURL(/\/login\/$/)
})
