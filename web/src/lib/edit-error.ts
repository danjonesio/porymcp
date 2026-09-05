import { ApiError } from './api.ts'
import { discoveryErrorMessage } from './discovery.ts'

export type EditResource = 'upstream' | 'group'

/**
 * One sentence for a failed save or delete from the Upstreams or Groups page.
 *
 * 404: the row went away while the dialog was open; the caller reloads the
 * list before showing this, so closing the dialog does show the current one.
 * 409: the delete callers only. `DeleteUpstream` and `DeleteGroup` refuse a row
 * something still references (internal/store), and the server's own sentence,
 * "resource is still referenced", names neither the group nor the key. No PATCH
 * returns 409 (the stale-write one is PORM-119), so the branch is dead from a
 * save and harmless there.
 * 429: the failed-admin-auth limiter that sits in front of every management
 * route (internal/api/api.go requireAdmin), which a stale session key reaches
 * by pressing Save. discoveryErrorMessage would name the discovery budget for
 * the same status, so this branch runs first.
 * Everything else is the house mapper's business: the 401 sentence, the
 * server's own message verbatim (`unknown upstream_id: …`, `name cannot be
 * empty`), or the network sentence.
 */
export function editErrorMessage(err: unknown, resource: EditResource): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return `This ${resource} no longer exists. Close this dialog to see the current list.`
    if (err.status === 409) {
      return resource === 'upstream'
        ? 'This upstream is still used by a group or a virtual key. Remove it there first.'
        : 'This group is still targeted by a virtual key. Delete that key first.'
    }
    if (err.status === 429) {
      const n = err.retryAfterSeconds
      if (n === undefined) return 'Too many requests. Try again in a minute.'
      return `Too many requests. Try again in ${n} ${n === 1 ? 'second' : 'seconds'}.`
    }
  }
  return discoveryErrorMessage(err)
}
