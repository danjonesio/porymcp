import { defineConfig, devices } from '@playwright/test'

// The browser suite runs against a PoryMCP that is already up: the porymcp:ci
// container in the docker job, or the binary scripts/web-e2e.sh starts. The
// config never starts a server and never mints a key; both come from the
// environment, so every worker reads the same values.
function required(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`${name} is not set`)
  return v
}
const trimSlash = (u: string) => u.replace(/\/$/, '')
const base = trimSlash(required('PORYMCP_BASE_URL'))
required('ADMIN_API_KEY')
const ci = !!process.env.CI

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  // One server, one admin failure budget and one row-count baseline: the
  // specs run one at a time.
  fullyParallel: false,
  workers: 1,
  forbidOnly: ci,
  retries: ci ? 1 : 0,
  timeout: 60_000,
  // In CI the suite ends itself before the step's timeout would, so the
  // captured output is still printed and the report is still written.
  globalTimeout: ci ? 5 * 60_000 : 0,
  maxFailures: ci ? 3 : 0,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  use: {
    baseURL: base,
    actionTimeout: 15_000,
    // A pixel cannot be scrubbed: no screenshots, no video, and traces
    // without screenshots. Text in a trace is scrubbed before any upload.
    screenshot: 'off',
    video: 'off',
    trace: { mode: 'retain-on-failure', screenshots: false, snapshots: true, sources: true },
  },
  projects: [
    { name: 'counts', testMatch: /counts\.setup\.ts/, teardown: 'counts-check' },
    { name: 'counts-check', testMatch: /counts\.teardown\.ts/ },
    { name: 'chromium', use: { ...devices['Desktop Chrome'] }, dependencies: ['counts'] },
  ],
})
