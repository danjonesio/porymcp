import type { Group } from './api.ts'

/**
 * The Create and Edit group dialogs share one form shape. Everything that turns
 * it into a request body lives here so `node --test` can reach it.
 */
export type GroupForm = { name: string; description: string; upstream_ids: string[] }

export function blankGroupForm(): GroupForm {
  return { name: '', description: '', upstream_ids: [] }
}

export function formFromGroup(g: Group): GroupForm {
  return { name: g.name, description: g.description ?? '', upstream_ids: [...g.upstream_ids] }
}

/**
 * Order-insensitive membership equality. The member checkboxes filter or
 * append, so unticking and re-ticking an upstream moves it to the end of the
 * array without changing who is in the group; the server compares arrays with
 * slices.Equal and would record that as a change (internal/api/admin_events.go).
 */
export function sameMembers(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  const set = new Set(b)
  return a.every((id) => set.has(id))
}

/** The `POST /groups` body, as the Create dialog has always sent it. */
export function groupCreateBody(f: GroupForm): Record<string, unknown> {
  return { name: f.name, description: f.description, upstream_ids: f.upstream_ids }
}

/**
 * The `PATCH /groups/{id}` body: only the keys whose value differs from the row
 * the dialog was seeded with. An absent key leaves the field unchanged
 * (docs/03-api.md, Partial updates). `upstream_ids` goes only when the set of
 * members changed; the array is sent as the form holds it, so retained members
 * keep their stored order and new ones follow in the order they were ticked,
 * the same order create stores.
 */
export function groupPatchBody(before: Group, f: GroupForm): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  const name = f.name.trim()
  if (name !== before.name) body.name = name
  if (f.description !== (before.description ?? '')) body.description = f.description
  if (!sameMembers(f.upstream_ids, before.upstream_ids)) body.upstream_ids = f.upstream_ids
  return body
}
