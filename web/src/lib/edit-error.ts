import { ApiError } from './api.ts'
import { discoveryErrorMessage } from './discovery.ts'

export type EditResource = 'upstream' | 'group'
export type EditAction = 'save' | 'delete'

/**
 * One sentence for a failed save or delete from the Upstreams or Groups page.
 *
 * 404: the row went away while the dialog was open; the caller reloads the
 * list before showing this, so closing the dialog does show the current one.
 * 409 on a delete: `DeleteUpstream` and `DeleteGroup` refuse a row something
 * still references (internal/store), and the server's own sentence,
 * "resource is still referenced", names neither the group nor the key. A 409
 * on a save is a different thing and keeps the server's words: `POST
 * /upstreams` answers "slug is already taken" or "could not derive a unique
 * slug; supply one explicitly" (internal/api/upstreams.go), and no PATCH
 * returns 409 until PORM-119.
 * 429: the failed-admin-auth limiter that sits in front of every management
 * route (internal/api/api.go requireAdmin), which a stale session key reaches
 * by pressing Save. discoveryErrorMessage would name the discovery budget for
 * the same status, so this branch runs first.
 * Everything else is the house mapper's business: the 401 sentence, the
 * server's own message verbatim (`unknown upstream_id: …`, `name cannot be
 * empty`), or the network sentence.
 */
export function editErrorMessage(err: unknown, resource: EditResource, action: EditAction): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return `This ${resource} no longer exists. Close this dialog to see the current list.`
    if (err.status === 409 && action === 'delete') {
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
