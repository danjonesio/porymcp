import { CONNECTING, actionsTriggerName, groupActions, ROW_ACTION_LABELS, toolsLabel, upstreamActions, virtualKeyActions } from '../src/lib/row-actions.ts'
import { connectLabel } from '../src/lib/upstream-auth.ts'
import { createGroup, createKey, createUpstream } from './api.ts'
import { expect, rowAction, rowNamed, STUB_URL, test } from './fixtures.ts'
import type { Page } from '@playwright/test'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

// PORM-219: each table row has one Actions button whose menu holds the row's
// actions. The menu's labels come from the lib, so these tests compare the
// page against the one rule the unit tests pin.

const flatLabels = (menu: { label: string }[][]) => menu.flat().map((i) => i.label)

const trigger = (page: Page, rowName: string) =>
  rowNamed(page, rowName).getByRole('button', { name: actionsTriggerName(rowName, null), exact: true })

async function menuLabels(page: Page, rowName: string): Promise<string[]> {
  await trigger(page, rowName).click()
  const labels = await page.getByRole('menuitem').allTextContents()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menuitem')).toHaveCount(0)
  return labels
}

function mcpBody(name: string, extra: Record<string, unknown> = {}) {
  return { name, kind: 'mcp', url: `${STUB_URL}/mcp`, transport: 'streamable-http', auth_type: 'none', auth_config: {}, ...extra }
}

test("each table's row holds one Actions button whose menu lists the row's actions in order, and each runs", async ({
  page,
  prefix,
  created,
}) => {
  const mcp = `${prefix} ra mcp`
  const http = `${prefix} ra http`
  const group = `${prefix} ra group`
  const keyName = `${prefix} ra key`
  const u = await createUpstream(mcpBody(mcp))
  created.upstreams.push(u.id)
  const h = await createUpstream({ name: http, kind: 'http', url: `${STUB_URL}/v1`, auth_type: 'none', auth_config: {} })
  created.upstreams.push(h.id)
  const g = await createGroup({ name: group, upstream_ids: [u.id] })
  created.groups.push(g.id)
  const k = await createKey({ name: keyName, target_type: 'upstream', target_id: u.id })
  created.keys.push(k.id)

  // Virtual keys: one button in the Actions cell, the documented order, Delete in red.
  await page.goto('/virtual-keys/')
  const keyRow = rowNamed(page, keyName)
  await expect(keyRow).toBeVisible()
  await expect(keyRow.locator('td:last-child').getByRole('button')).toHaveCount(1)
  expect(await menuLabels(page, keyName)).toEqual(flatLabels(virtualKeyActions()))

  await trigger(page, keyName).click()
  await page.mouse.move(0, 0)
  // A focused item is white on the focus fill, so the colours are read with
  // no item active, as a pointer-opened menu starts.
  await expect(page.locator('[role="menuitem"][data-focus]')).toHaveCount(0)
  const colours = await page.evaluate(() => {
    const items = Array.from(document.querySelectorAll('[role="menuitem"]'))
    const colour = (label: string) => {
      const el = items.find((i) => i.textContent?.trim() === label)
      return el ? getComputedStyle(el).color : ''
    }
    return { edit: colour('Edit'), del: colour('Delete') }
  })
  expect(colours.edit, 'the Edit item has a colour').not.toBe('')
  expect(colours.del, 'the Delete item has a colour').not.toBe('')
  expect(colours.del, 'Delete is drawn in another colour than Edit').not.toBe(colours.edit)
  await page.keyboard.press('Escape')

  await rowAction(page, keyName, ROW_ACTION_LABELS.policy)
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeHidden()

  await rowAction(page, keyName, ROW_ACTION_LABELS.edit)
  await expect(page.getByRole('heading', { name: 'Edit virtual key', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Edit virtual key', exact: true })).toBeHidden()

  await rowAction(page, keyName, ROW_ACTION_LABELS.rotate)
  await expect(page.getByRole('heading', { name: 'Copy this key now', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Done', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Copy this key now', exact: true })).toBeHidden()

  // Upstreams: Tools on an MCP server, Test on an HTTP API.
  await page.goto('/upstreams/')
  await expect(rowNamed(page, mcp)).toBeVisible()
  await expect(rowNamed(page, mcp).locator('td:last-child').getByRole('button')).toHaveCount(1)
  expect(await menuLabels(page, mcp)).toEqual(flatLabels(upstreamActions({ kind: 'mcp', auth_type: 'none' })))
  expect(await menuLabels(page, http)).toEqual(flatLabels(upstreamActions({ kind: 'http', auth_type: 'none' })))
  await rowAction(page, mcp, toolsLabel('mcp'))
  await expect(page.getByRole('heading', { name: toolsLabel('mcp'), exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await rowAction(page, http, toolsLabel('http'))
  await expect(page.getByRole('heading', { name: toolsLabel('http'), exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()

  // Groups.
  await page.goto('/groups/')
  await expect(rowNamed(page, group)).toBeVisible()
  await expect(rowNamed(page, group).locator('td:last-child').getByRole('button')).toHaveCount(1)
  expect(await menuLabels(page, group)).toEqual(flatLabels(groupActions()))
  await rowAction(page, group, ROW_ACTION_LABELS.edit)
  await expect(page.getByRole('heading', { name: 'Edit group', exact: true })).toBeVisible()
})

test("the Actions menu works from the keyboard and a chosen item's dialog takes focus", async ({ page, prefix, created }) => {
  const mcp = `${prefix} rk mcp`
  const group = `${prefix} rk group`
  const u = await createUpstream(mcpBody(mcp))
  created.upstreams.push(u.id)
  const g = await createGroup({ name: group, upstream_ids: [u.id] })
  created.groups.push(g.id)

  await page.goto('/groups/')
  const row = rowNamed(page, group)
  await expect(row).toBeVisible()
  const button = trigger(page, group)
  const triggerFocused = () => button.evaluate((el) => el === document.activeElement)

  // Clicking the Name cell sets where sequential focus starts; the row's only
  // control after it is the Actions button.
  await row.locator('td:first-of-type').click()
  await page.keyboard.press('Tab')
  expect(await triggerFocused(), 'Tab reaches the Actions button').toBe(true)

  await page.keyboard.press('Enter')
  const edit = page.getByRole('menuitem', { name: ROW_ACTION_LABELS.edit, exact: true })
  const del = page.getByRole('menuitem', { name: ROW_ACTION_LABELS.delete, exact: true })
  await expect(edit).toHaveAttribute('data-focus', '')
  await page.keyboard.press('ArrowDown')
  await expect(del).toHaveAttribute('data-focus', '')
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menuitem')).toHaveCount(0)
  await expect.poll(triggerFocused, { message: 'Escape returns focus to the Actions button' }).toBe(true)

  await page.keyboard.press('Space')
  await expect(edit).toHaveAttribute('data-focus', '')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Edit group', exact: true })).toBeVisible()
  await expect
    .poll(() => page.evaluate(() => document.activeElement?.closest('[role="dialog"]') !== null), {
      message: "focus is inside the item's dialog",
    })
    .toBe(true)
})

/** An oauth upstream with nothing stored reads Not connected, and a none upstream beside it. */
async function oauthRows(prefix: string, created: { upstreams: string[] }, tag: string) {
  const oauth = `${prefix} ${tag} oauth`
  const plain = `${prefix} ${tag} none`
  const o = await createUpstream({ name: oauth, kind: 'mcp', url: `${STUB_URL}/mcp`, transport: 'streamable-http', auth_type: 'oauth' })
  created.upstreams.push(o.id)
  const p = await createUpstream(mcpBody(plain))
  created.upstreams.push(p.id)
  return { oauth, plain }
}

// A fixed sentence the held start answers with; the page shows a 502's own
// error text (connectErrorMessage in oauth-connect.ts), so no sign-in URL is
// ever fetched or assigned.
const REFUSAL = 'The test held this sign-in and refused it.'

test('an oauth upstream that is not connected shows the amber badge, offers Connect first, and holds every trigger while connecting', async ({
  page,
  prefix,
  created,
}) => {
  const { oauth, plain } = await oauthRows(prefix, created, 'ro')
  let release: () => void = () => {}
  const held = new Promise<void>((r) => {
    release = r
  })
  await page.route('**/api/v1/upstreams/*/oauth/start', async (route) => {
    await held
    await route.fulfill({ status: 502, contentType: 'application/json', body: JSON.stringify({ error: REFUSAL }) })
  })

  await page.goto('/upstreams/')
  const row = rowNamed(page, oauth)
  await expect(row).toBeVisible()
  // The exact text is the badge alone: the old plain-text rendering read
  // "· Not connected" and had no fill of its own.
  const badge = row.getByText('Not connected', { exact: true })
  await expect(badge).toBeVisible()
  const fill = await badge.evaluate((el) => getComputedStyle(el).backgroundColor)
  expect(fill, 'Not connected is drawn as a filled badge').not.toBe('rgba(0, 0, 0, 0)')
  expect(await menuLabels(page, oauth)).toEqual(flatLabels(upstreamActions({ kind: 'mcp', auth_type: 'oauth' })))
  const connect = connectLabel({})
  expect((await menuLabels(page, oauth))[0]).toBe(connect)

  await rowAction(page, oauth, connect)
  const busy = row.getByRole('button', { name: actionsTriggerName(oauth, CONNECTING), exact: true })
  await expect(busy).toBeDisabled()
  await expect(busy).toContainText(CONNECTING)
  await expect(trigger(page, plain)).toBeDisabled()

  release()
  await expect(page.locator('p[role="alert"]')).toHaveText(REFUSAL)
  await expect(trigger(page, oauth)).toBeEnabled()
  await expect(trigger(page, plain)).toBeEnabled()
})

test('a double activation of Connect starts one sign-in', async ({ page, prefix, created }) => {
  const { oauth } = await oauthRows(prefix, created, 'rd')
  let calls = 0
  let release: () => void = () => {}
  const held = new Promise<void>((r) => {
    release = r
  })
  await page.route('**/api/v1/upstreams/*/oauth/start', async (route) => {
    calls++
    await held
    await route.fulfill({ status: 502, contentType: 'application/json', body: JSON.stringify({ error: REFUSAL }) })
  })

  await page.goto('/upstreams/')
  await expect(rowNamed(page, oauth)).toBeVisible()
  await trigger(page, oauth).click()
  // The second click lands while the menu fades out; the ref in connect()
  // is what refuses it.
  await page.getByRole('menuitem', { name: connectLabel({}), exact: true }).dblclick()
  release()
  await expect(page.locator('p[role="alert"]')).toHaveText(REFUSAL)
  expect(calls, 'one oauth/start request for two activations').toBe(1)
})
