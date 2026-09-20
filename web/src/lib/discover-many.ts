import { ApiError } from './api.ts'
import type { Discovery } from './api.ts'
import { idleMember, memberFromDiscovery } from './catalogue.ts'
import type { Member, MemberCatalogue } from './catalogue.ts'
import { discoveryErrorMessage } from './discovery.ts'

/**
 * How many member discoveries one Load tools press runs at once. The server's
 * gate is maxInFlightDiscoveries = 4 for the whole deployment, and it refuses a
 * fifth call with a 429 instead of queueing it (internal/api/discover.go), so a
 * picker that took all four would lock the Tools dialog out for every operator.
 * Two leaves half of it free.
 */
export const PICKER_IN_FLIGHT = 2

/**
 * Discovers each member through `discover`, at most PICKER_IN_FLIGHT at a time,
 * and reports each member as it starts and as it settles.
 *
 * A 429 stops the members that have not started: each call spends a token of
 * one deployment-wide budget, so the next one would be refused too. Its sentence
 * is returned once for the whole press, the member it hit goes back to Not
 * loaded, and nothing is retried. The operator presses again.
 *
 * `stale` is the dialog's sequence check: once it is true every late answer is
 * dropped, so a dialog that closed or moved to another target is never painted
 * with the last one's tools.
 *
 * `discover` is a parameter so `node --test` needs no fetch; the app passes
 * discoverUpstream, and nothing else may be passed there: it is the one
 * credential-carrying discovery path.
 */
export async function discoverMembers(
  members: Member[],
  discover: (upstreamId: string) => Promise<Discovery>,
  onUpdate: (m: MemberCatalogue) => void,
  stale: () => boolean,
): Promise<{ rateLimited: string }> {
  let next = 0
  let rateLimited = ''
  const worker = async () => {
    while (next < members.length && !rateLimited && !stale()) {
      const m = members[next++]
      onUpdate({ ...idleMember(m), state: 'loading' })
      try {
        const d = await discover(m.upstream_id)
        if (stale()) return
        onUpdate(memberFromDiscovery(m, d))
      } catch (err) {
        if (stale()) return
        if (err instanceof ApiError && err.status === 429) {
          rateLimited = rateLimited || discoveryErrorMessage(err)
          onUpdate(idleMember(m))
        } else {
          onUpdate({ ...idleMember(m), state: 'failed', error: discoveryErrorMessage(err) })
        }
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(PICKER_IN_FLIGHT, members.length) }, worker))
  return { rateLimited }
}
