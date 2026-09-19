import type { Group } from './api.ts'
import { blankFilterForm, filterProblem, filterValue, parseToolFilter, sameFilter } from './tool-filter.ts'
import type { FilterForm } from './tool-filter.ts'

/**
 * The Create and Edit group dialogs share one form shape. Everything that turns
 * it into a request body lives here so `node --test` can reach it.
 */
export type GroupForm = {
  name: string
  description: string
  upstream_ids: string[]
  filter: FilterForm
  /** What the API served, as text, when the proxy rejects the stored filter; '' otherwise. The section shows it and edits nothing until Replace filter. */
  filterUnreadable: string
  /** Replace filter was pressed on an unreadable stored filter. Closing the dialog undoes it. */
  filterReplace: boolean
  /** A mode radio was pressed since Replace. No filter counts: it is how a broken filter is removed. */
  filterChosen: boolean
}

export function blankGroupForm(): GroupForm {
  return {
    name: '',
    description: '',
    upstream_ids: [],
    filter: blankFilterForm(),
    filterUnreadable: '',
    filterReplace: false,
    filterChosen: false,
  }
}

export function formFromGroup(g: Group): GroupForm {
  const stored = parseToolFilter(g.tool_filter)
  return {
    name: g.name,
    description: g.description ?? '',
    upstream_ids: [...g.upstream_ids],
    filter: stored.kind === 'filter' ? { ...stored.form } : blankFilterForm(),
    filterUnreadable: stored.kind === 'unreadable' ? stored.text : '',
    filterReplace: false,
    filterChosen: false,
  }
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

/**
 * The `POST /groups` body. `tool_filter` goes only when a mode is chosen: an
 * omitted key stores no filter, where `{}` would be stored and served as `{}`.
 */
export function groupCreateBody(f: GroupForm): Record<string, unknown> {
  const body: Record<string, unknown> = { name: f.name, description: f.description, upstream_ids: f.upstream_ids }
  if (f.filter.mode !== '') body.tool_filter = filterValue(f.filter)
  return body
}

/** True when the PATCH for this form would carry tool_filter. The one definition, shared by the body and the save gate. */
function sendsFilter(before: Group, f: GroupForm): boolean {
  const stored = parseToolFilter(before.tool_filter)
  if (stored.kind === 'unreadable') return f.filterReplace && f.filterChosen
  return !sameFilter(stored.kind === 'filter' ? stored.form : blankFilterForm(), f.filter)
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
  // tool_filter goes only when its MEANING changed (sameFilter), never because
  // the dialog re-serialised it. An untouched filter sent back is judged by
  // today's write rules and can be refused (docs/03-api.md, Round-trips), and
  // the admin event compares bytes, so a reorder would record a change. "No
  // filter" is null, which the server records as a clear. A stored filter the
  // proxy rejects is never sent until Replace filter and a mode were pressed:
  // deriving "no filter" from a parse failure would clear a group that is
  // currently closed.
  if (sendsFilter(before, f)) body.tool_filter = filterValue(f.filter)
  return body
}

/**
 * '' when Save may proceed, otherwise the sentence that says why not. The
 * filter's problems hold Save back only when the body would carry the filter. A
 * stored filter with a problem the operator never touched (an empty deny, a
 * legacy unscoped allow entry) must not stop them renaming the group: the only
 * ways out would be policy edits they did not come to make.
 */
export function groupSaveBlocked(before: Group | null, f: GroupForm): string {
  if (f.filterReplace && !f.filterChosen) return 'Choose a mode to replace the stored filter.'
  const sends = before ? sendsFilter(before, f) : f.filter.mode !== ''
  return sends ? filterProblem(f.filter) : ''
}

/**
 * True when the group's stored filter is no longer the one this dialog was
 * seeded with. Asked of a fresh read just before a PATCH that carries
 * tool_filter: PATCH replaces the whole filter and the API has no 409 yet
 * (PORM-119), so a stale dialog would silently drop another operator's entry.
 * Compared by meaning, so a reorder or `{}` against an absent filter is not a
 * change; an unreadable filter compares as text.
 */
export function groupPolicyStale(seed: Group, fresh: Group): boolean {
  const a = parseToolFilter(seed.tool_filter)
  const b = parseToolFilter(fresh.tool_filter)
  if (a.kind !== b.kind) return true
  if (a.kind === 'unreadable' && b.kind === 'unreadable') return a.text !== b.text
  if (a.kind === 'filter' && b.kind === 'filter') return !sameFilter(a.form, b.form)
  return false
}

/** Shown in the dialog when groupPolicyStale stopped a save. Nothing was sent. */
export const GROUP_FILTER_STALE =
  "This group's filter changed since you opened it. Close this dialog and open it again to see the current filter."

/**
 * The badge under a group's name in the table: that it has a filter, or that
 * the proxy cannot read the one it has and is blocking every tool on the group.
 * null when there is nothing to say, which is the ordinary case.
 */
export function groupFilterBadge(g: Group): { label: string; tone: 'zinc' | 'pink' } | null {
  const stored = parseToolFilter(g.tool_filter)
  if (stored.kind === 'unreadable') return { label: 'Filter unreadable', tone: 'pink' }
  if (stored.kind === 'filter') return { label: stored.form.mode === 'allow' ? 'Allow filter' : 'Deny filter', tone: 'zinc' }
  return null
}
