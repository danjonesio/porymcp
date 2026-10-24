import { expect, test } from './fixtures.ts'

// PORM-225 criterion 2: a failed load on the Overview shows its error in a
// pink role="alert" line drawn with errorLine, not in the grey of the Text
// beside it, in light and in dark. Needs no stub: the failure is the route's.
test('a failed stats request shows a pink alert line', async ({ page }) => {
  const refusal = 'The test refused the stats.'
  await page.route(
    (u) => u.pathname === '/api/v1/stats',
    (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: refusal }) }),
    { times: 1 }
  )
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible()
  const line = page.locator('p[role="alert"]')
  await expect(line).toHaveText(refusal)
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme })
    const [alert, text] = await Promise.all([
      line.evaluate((el) => getComputedStyle(el).color),
      page.getByRole('main').locator('p[data-slot="text"]').first().evaluate((el) => getComputedStyle(el).color),
    ])
    expect(alert !== text, `the error line has its own colour in ${scheme} mode`).toBe(true)
  }
})
