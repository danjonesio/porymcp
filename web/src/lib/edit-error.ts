import { ApiError, requestErrorMessage } from './api.ts'

export type EditResource = 'upstream' | 'group' | 'virtual key'
/** 'load' is a read a dialog makes on open, such as the Policy dialog's; it maps as a save does. */
export type EditAction = 'save' | 'delete' | 'load'

/**
 * One sentence for a failed save, delete or load from the Upstreams, Groups or
 * Virtual keys page.
 *
 * 404: the row went away while the dialog was open; the caller reloads the
 * list before showing this, so closing the dialog does show the current one.
 * 409 on a delete: `DeleteUpstream` and `DeleteGroup` refuse a row something
 * still references (internal/store), and the server's own sentence,
 * "resource is still referenced", names neither the group nor the key. A 409
 * on a save is a different thing and keeps the server's words: `POST
 * /upstreams` answers "slug is already taken" or "could not derive a unique
 * slug; supply one explicitly" (internal/api/upstreams.go), and no PATCH
 * returns 409 until PORM-119. `DELETE /virtual-keys/{id}` never answers 409
 * (nothing references a key), so that resource has no sentence of its own and
 * keeps the server's words, through an arm of its own so that a third
 * resource can never fall into the group sentence.
 * Everything else is the house mapper's business (requestErrorMessage): the
 * admin limiter's 429, which a stale session key reaches by pressing Save, the
 * 401 sentence, the server's own message verbatim (`unknown upstream_id: …`,
 * `name cannot be empty`), or the network sentence.
 */
export function editErrorMessage(err: unknown, resource: EditResource, action: EditAction): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return `This ${resource} no longer exists. Close this dialog to see the current list.`
    if (err.status === 409 && action === 'delete') {
      if (resource === 'upstream') return 'This upstream is still used by a group or a virtual key. Remove it there first.'
      if (resource === 'group') return 'This group is still targeted by a virtual key. Delete that key first.'
      return err.message
    }
  }
  return requestErrorMessage(err)
}
