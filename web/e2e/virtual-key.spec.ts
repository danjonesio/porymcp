import { blockedLine, listEmptySentence } from '../src/lib/policy-view.ts'
import { createKey, createUpstream, waitForRow } from './api.ts'
import { alertTitled, expect, rowNamed, STUB_URL, test } from './fixtures.ts'

test.skip(() => !STUB_URL, 'STUB_URL is not set')

// Runs inside the page and returns facts about where the plaintext sits,
// never the plaintext itself in an assertion. The trace still records the
// call's result; the scrub in CI is the control for that.
function keyFacts() {
  const input = document.querySelector<HTMLInputElement>('input[name=api_key]')
  const k = input ? input.value : ''
  const holders = Array.from(document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input, textarea')).filter(
    (el) => k !== '' && el.value.includes(k)
  )
  const dialog = Array.from(document.querySelectorAll('[role="dialog"]')).find((d) =>
    Array.from(d.querySelectorAll('h1, h2, h3')).some((h) => h.textContent?.trim() === 'Copy this key now')
  )
  const skip = new Set(['INPUT', 'TEXTAREA', 'SCRIPT', 'STYLE', 'TEMPLATE'])
  let text = false
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    let inControl = false
    for (let p = n.parentElement; p; p = p.parentElement) {
      if (skip.has(p.tagName)) {
        inControl = true
        break
      }
    }
    if (!inControl && k !== '' && (n.textContent ?? '').includes(k)) {
      text = true
      break
    }
  }
  return {
    shape: /^pory_[0-9a-f]{64}$/.test(k),
    controls: holders.length,
    inDialog: dialog ? holders.every((el) => dialog.contains(el)) : false,
    text,
    k,
  }
}

function controlsHolding(k: string): number {
  return Array.from(document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input, textarea')).filter((el) =>
    el.value.includes(k)
  ).length
}

test('the plaintext shows in the secret dialog and is gone after Done and a reload', async ({
  page,
  context,
  prefix,
  created,
}) => {
  const mcp = `${prefix} vk mcp`
  const keyName = `${prefix} vk key`
  const u = await createUpstream({
    name: mcp,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'none',
    auth_config: {},
  })
  created.upstreams.push(u.id)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])

  await page.goto('/virtual-keys/')
  await page.getByRole('button', { name: 'Create virtual key', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Create virtual key', exact: true })).toBeVisible()
  await page.getByLabel('Name', { exact: true }).fill(keyName)
  await page.getByLabel('Target type', { exact: true }).selectOption({ label: 'Upstream' })
  await page.getByLabel('Target', { exact: true }).selectOption({ label: mcp })
  await page.getByRole('button', { name: 'Create', exact: true }).click()
  created.keys.push(await waitForRow('virtual-keys', keyName))
  await expect(page.getByRole('heading', { name: 'Copy this key now', exact: true })).toBeVisible()

  const facts = await page.evaluate(keyFacts)
  expect(facts.shape, 'the key input holds a pory_ key').toBe(true)
  // The key input and the install snippet hold it, by design
  // (web/src/app/(app)/virtual-keys/page.tsx:584 and :722-728).
  expect(facts.controls, 'two controls hold the plaintext').toBe(2)
  expect(facts.inDialog, 'every control holding the plaintext is inside the secret dialog').toBe(true)
  expect(facts.text, 'no visible text holds the plaintext').toBe(false)

  await page.getByRole('button', { name: 'Copy snippet', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Copied', exact: true })).toBeVisible()
  const copied = await page.evaluate(async () => {
    const value = document.querySelector<HTMLInputElement>('input[name=api_key]')?.value ?? ''
    return value !== '' && (await navigator.clipboard.readText()).includes(value)
  })
  expect(copied, 'the clipboard holds the snippet with the key').toBe(true)

  await page.getByRole('button', { name: 'Done', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Copy this key now', exact: true })).toBeHidden()
  await page.reload()
  const keyRow = rowNamed(page, keyName)
  await expect(keyRow).toBeVisible()
  expect((await page.content()).includes(facts.k), 'the page no longer carries the plaintext').toBe(false)
  expect(await page.evaluate(controlsHolding, facts.k), 'no control holds the plaintext').toBe(0)
  await expect(keyRow).toContainText(/pory_[0-9a-f]{7}…/)
  await expect(keyRow).toContainText('active')

  await keyRow.getByRole('button', { name: 'Delete', exact: true }).click()
  await alertTitled(page, 'Delete this virtual key?').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(rowNamed(page, keyName)).toHaveCount(0)
})

// PORM-209: the Policy dialog shows the key's rules and never its secret.
test("the Policy dialog shows a key's rules in order and no secret", async ({ page, prefix, created }) => {
  const mcp = `${prefix} pol mcp`
  const keyName = `${prefix} pol key`
  const u = await createUpstream({
    name: mcp,
    kind: 'mcp',
    url: `${STUB_URL}/mcp`,
    transport: 'streamable-http',
    auth_type: 'none',
    auth_config: {},
  })
  created.upstreams.push(u.id)
  const k = await createKey({ name: keyName, target_type: 'upstream', target_id: u.id, tool_denylist: ['delete_repo'] })
  created.keys.push(k.id)
  const plaintext = k.api_key ?? ''
  expect(plaintext, 'create answered a plaintext key').not.toBe('')

  await page.goto('/virtual-keys/')
  await rowNamed(page, keyName).getByRole('button', { name: 'Policy', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible()
  const dialog = page.locator('[role="dialog"]', { has: page.getByRole('heading', { name: 'Policy', exact: true }) })
  await expect(dialog.getByRole('heading', { name: 'Outbound connections', exact: true })).toBeVisible()

  const blocks = await dialog.locator('h3').allTextContents()
  expect(blocks, 'the blocks in order; a single MCP upstream has no HTTP API door').toEqual([
    'MCP endpoints',
    'Outbound connections',
  ])
  const rules = await dialog.locator('h4').allTextContents()
  expect(rules.slice(0, 2)).toEqual(['Deny list', 'Allow list'])
  await expect(dialog.getByRole('list', { name: 'Tools this key denies', exact: true })).toContainText('delete_repo')
  await expect(dialog.getByText(listEmptySentence('allow'), { exact: true })).toBeVisible()
  await expect(dialog.getByText(blockedLine(0), { exact: true }).first()).toBeVisible()

  const text = (await dialog.textContent()) ?? ''
  expect(text.includes(plaintext), 'the dialog never shows the plaintext key').toBe(false)
  expect(text.includes('pory_'), 'the dialog shows no key form at all').toBe(false)

  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeHidden()
})
