import { randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { test as setup } from '@playwright/test'
import { count } from './api.ts'
import { COUNTS_FILE, type Counts } from './fixtures.ts'

// The baseline for criterion 7 and the one run prefix every spec names its
// rows with. Minted once here rather than per worker, so a retry's new worker
// and the teardown see the same prefix.
setup('record the row counts and the run prefix', async () => {
  const letters = Array.from(randomBytes(6), (b) => String.fromCharCode(97 + (b % 26))).join('')
  const counts: Counts = {
    prefix: `e2e${letters}`,
    upstreams: await count('upstreams'),
    groups: await count('groups'),
    virtual_keys: await count('virtual-keys'),
  }
  mkdirSync(path.dirname(COUNTS_FILE), { recursive: true })
  writeFileSync(COUNTS_FILE, JSON.stringify(counts))
})
