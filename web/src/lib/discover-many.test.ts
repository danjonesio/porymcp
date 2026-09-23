import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from './api.ts'
import type { Discovery } from './api.ts'
import type { Member, MemberCatalogue } from './catalogue.ts'
import { PICKER_IN_FLIGHT, discoverMembers } from './discover-many.ts'

// Run with: npm test (node --test). PORM-4 SR9: discovery is a bounded act.

function members(n: number): Member[] {
  return Array.from({ length: n }, (_, i) => ({
    upstream_id: `u${i}`,
    slug: `s${i}`,
    name: `Upstream ${i}`,
    enabled: true,
    transport: 'streamable_http',
    kind: 'mcp',
  }))
}

function answer(tools: string[]): Discovery {
  return { ok: true, kind: 'mcp', latency_ms: 1, tool_count: tools.length, tools: tools.map((name) => ({ name })), truncated: false, unnameable_tools: 0 }
}

const tick = () => new Promise<void>((r) => setImmediate(r))

test('discoverMembers holds at most PICKER_IN_FLIGHT calls in flight and reports every member', async () => {
  assert.equal(PICKER_IN_FLIGHT, 2)
  let inFlight = 0
  let peak = 0
  const final = new Map<string, MemberCatalogue>()
  const out = await discoverMembers(
    members(5),
    async (id) => {
      inFlight++
      peak = Math.max(peak, inFlight)
      await tick()
      inFlight--
      return answer([id + '_tool'])
    },
    (m) => final.set(m.upstream_id, m),
    () => false,
  )
  assert.equal(peak, 2)
  assert.equal(out.rateLimited, '')
  assert.equal(final.size, 5)
  for (const m of final.values()) {
    assert.equal(m.state, 'ok')
    assert.equal(m.tools[0].name, m.upstream_id + '_tool')
  }
})

test('discoverMembers reports loading before the answer', async () => {
  const states: string[] = []
  await discoverMembers(members(1), async () => answer([]), (m) => states.push(m.state), () => false)
  assert.deepEqual(states, ['loading', 'ok'])
})

test('discoverMembers: a failure is that member alone, with the mapped sentence', async () => {
  const final = new Map<string, MemberCatalogue>()
  await discoverMembers(
    members(2),
    async (id) => {
      if (id === 'u0') throw new ApiError(502, 'upstream refused the connection')
      return answer(['x'])
    },
    (m) => final.set(m.upstream_id, m),
    () => false,
  )
  assert.equal(final.get('u0')?.state, 'failed')
  assert.equal(final.get('u0')?.error, 'upstream refused the connection')
  assert.equal(final.get('u1')?.state, 'ok')
})

test('discoverMembers: a 429 stops the members not yet started, returns its sentence once, and retries nothing', async () => {
  const calls: string[] = []
  const final = new Map<string, MemberCatalogue>()
  const out = await discoverMembers(
    members(6),
    async (id) => {
      calls.push(id)
      // The refusal lands while u0 is still in flight, which is the ordinary
      // case: the server answers a 429 before it dials anything.
      if (id === 'u1') throw new ApiError(429, 'too many discoveries', 7)
      await tick()
      return answer(['x'])
    },
    (m) => final.set(m.upstream_id, m),
    () => false,
  )
  assert.equal(out.rateLimited, 'Too many discovery requests. Try again in 7 seconds.')
  // u0 and u1 started together; nothing new starts once the 429 has landed.
  assert.deepEqual(calls, ['u0', 'u1'])
  assert.equal(final.get('u0')?.state, 'ok')
  // The refused member is back to Not loaded, not failed: nothing is wrong with it.
  assert.equal(final.get('u1')?.state, 'idle')
  assert.equal(final.has('u2'), false)
})

test('discoverMembers drops every answer once the dialog moved on', async () => {
  let closed = false
  const seen: string[] = []
  await discoverMembers(
    members(3),
    async () => {
      await tick()
      closed = true
      return answer(['x'])
    },
    (m) => seen.push(`${m.upstream_id}:${m.state}`),
    () => closed,
  )
  assert.deepEqual(seen, ['u0:loading', 'u1:loading'])
})
