import { readFileSync } from 'node:fs'
import path from 'node:path'
import { expect, type Locator, type Page, test as base } from '@playwright/test'
import { actionsTriggerName } from '../src/lib/row-actions.ts'
import { deriveSlug } from '../src/lib/slug.ts'
import { remove } from './api.ts'

// The storage key mirrors web/src/lib/api.ts (getAdminKey, setAdminKey,
// clearAdminKey); the dashboard exports no constant for it.
export const ADMIN_KEY_STORAGE = 'porymcp.adminKey'

// Written by counts.setup.ts after Playwright clears the output directory,
// read by the prefix fixture and by counts.teardown.ts.
export const COUNTS_FILE = path.join(__dirname, '..', 'test-results', 'e2e-counts.json')

export type Counts = { prefix: string; upstreams: number; groups: number; virtual_keys: number }

// The echo stub as the server reaches it. Empty when the run has no stub; the
// specs that need one skip with that reason.
export const STUB_URL = (process.env.STUB_URL ?? '').replace(/\/$/, '')

export const slugOf = (name: string) => deriveSlug(name)

// A row is found by its first cell, the Name cell, which holds the run's
// unique name; each row's one Actions button is found inside it (PORM-219).
// The match is on that cell's text, not the whole row's: a key
// row's Target cell names its upstream too. A substring match on the cell is
// safe because no run name contains another, and it still matches a Name
// cell that carries a badge beside the name.
export const rowNamed = (page: Page, name: string): Locator =>
  page.getByRole('row').filter({ has: page.locator('td:first-of-type', { hasText: name }) })

// Runs one of a row's actions: opens the row's Actions menu, then chooses the
// item by exact name. The item is found on the page, not in the row: an
// anchored Headless menu is portalled to the end of the body, and a closed
// menu's items are absent, so the names the menus share across rows only
// ever match the one open menu.
export async function rowAction(page: Page, rowName: string, label: string): Promise<void> {
  await rowNamed(page, rowName).getByRole('button', { name: actionsTriggerName(rowName, null), exact: true }).click()
  await page.getByRole('menuitem', { name: label, exact: true }).click()
}

// Headless UI gives an Alert a boxless role=dialog wrapper that role queries
// read as hidden, so its buttons are found under the wrapper that holds the
// Alert's title. The wrapper is a portal sibling, never a descendant of the
// dialog that opened it.
export const alertTitled = (page: Page, title: string): Locator =>
  page.locator('[role="dialog"]', { has: page.getByRole('heading', { name: title, exact: true }) })

// Every row a test creates is recorded here the moment its id is known. The
// fixture deletes what is left when the test ends, pass or fail, keys first
// because the store refuses to delete an upstream a key or group still names.
export type Created = { upstreams: string[]; groups: string[]; keys: string[] }

export const test = base.extend<{ created: Created }, { prefix: string }>({
  prefix: [
    async ({}, use) => {
      const counts = JSON.parse(readFileSync(COUNTS_FILE, 'utf8')) as Counts
      await use(counts.prefix)
    },
    { scope: 'worker' },
  ],
  created: async ({}, use) => {
    const c: Created = { upstreams: [], groups: [], keys: [] }
    await use(c)
    for (const id of c.keys) await remove('virtual-keys', id)
    for (const id of c.groups) await remove('groups', id)
    for (const id of c.upstreams) await remove('upstreams', id)
  },
  // Sign in the way the dashboard does, by placing the admin key in the
  // page's sessionStorage before the first script runs. The script runs on
  // every document load, so a spec that signs out must not use this fixture.
  page: async ({ page, baseURL }, use) => {
    const key = process.env.ADMIN_API_KEY ?? ''
    const origin = new URL(baseURL ?? '').origin
    await page.addInitScript(
      ([o, name, k]) => {
        if (location.origin === o) sessionStorage.setItem(name, k)
      },
      [origin, ADMIN_KEY_STORAGE, key] as const
    )
    await use(page)
  },
})

export { expect }
