import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { discoverUpstream } from '@/lib/api'
import { idleMember } from '@/lib/catalogue'
import type { Catalogue, Member, MemberCatalogue } from '@/lib/catalogue'
import { discoverMembers } from '@/lib/discover-many'

/**
 * The one owner of a dialog's tool catalogue, for the Groups page and the
 * Virtual keys page alike. The rules it holds are in catalogue.ts and
 * discover-many.ts, where `node --test` reaches them; this only keeps state.
 *
 * Nothing loads until `load` is called: a discovery sends the stored credential
 * upstream and records a test on the row, so it is a press, never an effect.
 * Answers are kept per upstream id for as long as `resetKey` stays the same, so
 * unticking and re-ticking a member neither fetches nor stamps again. A new
 * `resetKey` (the dialog's open count) drops everything and makes every answer
 * still in flight stale.
 *
 * One run at a time: a press that arrives while a run is in flight is dropped.
 * discoverMembers bounds ONE run to two calls, so a second concurrent run would
 * double that against the server's gate of four, and could discover a member
 * the first run had not reached yet a second time: two credential-carrying
 * handshakes and two last-test stamps for one intent. The picker draws its
 * buttons as unavailable meanwhile; this is the guard that does not depend on it.
 *
 * The catalogue returned is narrowed to `members`, in their order: a verdict
 * must never weigh a member the target no longer has.
 */
export function useCatalogue(
  members: Member[],
  resetKey: number,
): { catalogue: Catalogue; rateLimited: string; load: (upstreamId?: string) => void } {
  const [byId, setById] = useState<Record<string, MemberCatalogue>>({})
  const [rateLimited, setRateLimited] = useState('')
  const [seenKey, setSeenKey] = useState(resetKey)
  if (seenKey !== resetKey) {
    setSeenKey(resetKey)
    setById({})
    setRateLimited('')
  }

  // What `stale` compares with. Written in an effect, never during render.
  const current = useRef(resetKey)
  useEffect(() => {
    current.current = resetKey
  }, [resetKey])
  // The reset key of the run in flight, or null. Keyed, so a run left over from
  // a dialog that closed neither blocks the next dialog's press nor, when it
  // settles late, frees the slot a newer run is holding.
  const running = useRef<number | null>(null)

  const catalogue = useMemo<Catalogue>(
    () => ({ members: members.map((m) => (byId[m.upstream_id] ? { ...byId[m.upstream_id], ...m } : idleMember(m))) }),
    [members, byId],
  )

  const load = useCallback(
    (upstreamId?: string) => {
      const started = resetKey
      if (running.current === started) return
      running.current = started
      const stale = () => current.current !== started
      const targets = upstreamId ? members.filter((m) => m.upstream_id === upstreamId) : members
      setRateLimited('')
      void discoverMembers(
        targets,
        discoverUpstream,
        (m) => setById((prev) => ({ ...prev, [m.upstream_id]: m })),
        stale,
      ).then((out) => {
        if (running.current === started) running.current = null
        if (!stale()) setRateLimited(out.rateLimited)
      })
    },
    [members, resetKey],
  )

  return { catalogue, rateLimited, load }
}
