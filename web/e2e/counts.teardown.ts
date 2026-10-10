import { readFileSync } from 'node:fs'
import { expect, test as teardown } from '@playwright/test'
import { count, type ListPath, listRows, remove } from './api.ts'
import { COUNTS_FILE, type Counts } from './fixtures.ts'

// The evidence for criterion 7: the three tables end at the counts the setup
// recorded. The assertion runs first and the sweep after, so a leftover row is
// reported, not repaired away. The sweep deletes only rows named with this
// run's exact prefix and a space, never anything a person created.
teardown('the row counts match the start', async () => {
  const start = JSON.parse(readFileSync(COUNTS_FILE, 'utf8')) as Counts
  try {
    const now = {
      upstreams: await count('upstreams'),
      groups: await count('groups'),
      virtual_keys: await count('virtual-keys'),
    }
    const { prefix: _, ...expected } = start
    expect(now, 'the three tables hold the counts recorded at the start').toEqual(expected)
  } finally {
    const order: ListPath[] = ['virtual-keys', 'groups', 'upstreams']
    for (const kind of order) {
      for (const row of await listRows(kind)) {
        if (row.name.startsWith(`${start.prefix} `)) await remove(kind, row.id)
      }
    }
  }
})
