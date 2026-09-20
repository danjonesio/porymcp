import { TOOL_SEPARATOR, cleanEntry, entryProblem, splitEntry } from './tool-entry.ts'

// A group's tool_filter as the dashboard holds it, and the sentences that depend
// on it. Everything that turns the form into a request value lives here so
// `node --test` can reach it; the components only render.

/** What the API serves and accepts for a group's tool_filter. Group.tool_filter stays `unknown`, because it must also hold the shapes parseToolFilter rejects. */
export type ToolFilterWire = { mode?: 'allow' | 'deny' | ''; tools?: string[] | null; prefixes?: string[] | null }

/** '' is "No filter". */
export type FilterMode = '' | 'allow' | 'deny'

/** One list of tool entries and one of prefixes. A tick and a typed entry are the same string in the same list. */
export type FilterForm = { mode: FilterMode; tools: string[]; prefixes: string[] }

export type ParsedFilter =
  | { kind: 'none' }
  | { kind: 'filter'; form: FilterForm }
  /** The proxy rejects this filter and blocks every tool on the group. `text` is what was served. */
  | { kind: 'unreadable'; text: string }

export function blankFilterForm(): FilterForm {
  return { mode: '', tools: [], prefixes: [] }
}

function unique(list: string[]): string[] {
  return list.filter((e, i) => list.indexOf(e) === i)
}

/**
 * The dialog's verdict on a served tool_filter, which has to be the proxy's
 * verdict. Mirrors models.ValidateToolFilter (internal/models/toolfilter.go),
 * the read side, exactly and only:
 *
 *   - a missing or null filter, `{}`, and an object with no mode and no entries
 *     are "no filter";
 *   - member names match case-insensitively and the last duplicate wins, as Go's
 *     decoder binds them, so `{"Mode":"deny"}` is an ordinary deny filter;
 *   - a null `tools` or `prefixes` is an empty list;
 *   - everything the read side rejects is `unreadable`: not an object (a served
 *     `""` included), an unknown member, a mode that is not exactly `allow`,
 *     `deny` or empty, no mode with entries, `allow` with no entries, a list
 *     that is not an array of strings, and any entry cleanEntry refuses.
 *
 * It applies none of the write-side rules (entryProblem). A stored entry that
 * fails those is still enforced as written, and calling it unreadable would tell
 * an operator that a working filter blocks everything.
 *
 * Duplicates are dropped: the proxy stops at the first match, so a repeated
 * entry means nothing, and keeping one would make Remove a silent no-op.
 */
export function parseToolFilter(raw: unknown): ParsedFilter {
  if (raw === undefined || raw === null) return { kind: 'none' }
  // Built only when it is returned: this runs per table row and per keystroke
  // while a dialog is open, and the stored value can be large.
  const unreadable = (): ParsedFilter => ({ kind: 'unreadable', text: JSON.stringify(raw) ?? String(raw) })
  if (typeof raw !== 'object' || Array.isArray(raw)) return unreadable()

  const folded: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const k = key.toLowerCase()
    if (k !== 'mode' && k !== 'tools' && k !== 'prefixes') return unreadable()
    // Go decodes a JSON null into a string as a no-op, so `"Mode": null` after
    // `"mode": "deny"` leaves the mode at deny. Into a slice, null is an empty
    // list, which the list loop below already reads it as.
    if (k === 'mode' && value === null) continue
    folded[k] = value
  }

  const mode = folded.mode ?? ''
  if (mode !== '' && mode !== 'allow' && mode !== 'deny') return unreadable()

  const lists: string[][] = []
  for (const value of [folded.tools, folded.prefixes]) {
    if (value === undefined || value === null) {
      lists.push([])
      continue
    }
    if (!Array.isArray(value)) return unreadable()
    for (const e of value) {
      if (typeof e !== 'string' || !cleanEntry(e)) return unreadable()
    }
    lists.push(unique(value as string[]))
  }
  const [tools, prefixes] = lists
  const entries = tools.length + prefixes.length

  if (mode === '') return entries === 0 ? { kind: 'none' } : unreadable()
  if (mode === 'allow' && entries === 0) return unreadable()
  return { kind: 'filter', form: { mode, tools, prefixes } }
}

/**
 * The value to send. "No filter" is null: on PATCH that stores '' and is
 * recorded as a clear (internal/api/groups.go), where `{}` would be recorded
 * the same way and then stored and served as `{}` for ever. One fixed member
 * order, empty lists left out, so a second unchanged save produces the same
 * bytes the first one stored.
 */
export function filterValue(f: FilterForm): null | ToolFilterWire {
  if (f.mode === '') return null
  const out: ToolFilterWire = { mode: f.mode }
  if (f.tools.length > 0) out.tools = [...f.tools]
  if (f.prefixes.length > 0) out.prefixes = [...f.prefixes]
  return out
}

function sameSet(a: string[], b: string[]): boolean {
  const sa = new Set(a)
  const sb = new Set(b)
  if (sa.size !== sb.size) return false
  for (const e of sa) if (!sb.has(e)) return false
  return true
}

/**
 * True when two forms mean the same filter. Order is not meaning, and the admin
 * event compares the stored bytes (internal/api/admin_events.go), so re-sending
 * a reordered filter would record a change that did not happen. This is the same
 * question sameMembers answers for a group's members.
 */
export function sameFilter(a: FilterForm, b: FilterForm): boolean {
  // Under No filter the lists are not sent (filterValue), so they are not
  // meaning either. The form keeps them so that a mode picked again by mistake
  // gets its entries back; a group with no filter must not be "changed" by that.
  if (a.mode === '' && b.mode === '') return true
  return a.mode === b.mode && sameSet(a.tools, b.tools) && sameSet(a.prefixes, b.prefixes)
}

/** True when two entry lists hold the same entries, in any order. */
export function sameEntries(a: string[] | undefined, b: string[] | undefined): boolean {
  return sameSet(a ?? [], b ?? [])
}

/**
 * Adds or removes one entry. Adding an entry that is already there changes
 * nothing; removing takes every occurrence. Stored order is kept and a new
 * entry goes last, so an API-written filter is never reordered by an edit.
 */
export function toggleEntry(list: string[], entry: string, on: boolean): string[] {
  if (on) return list.includes(entry) ? list : [...list, entry]
  return list.filter((e) => e !== entry)
}

/** Shown under a mode that lists nothing, and the reason Save is held back once that was the operator's edit. */
export const ZERO_ENTRIES = 'List at least one tool or prefix, or choose No filter.'

/**
 * '' when the API would accept this filter, otherwise one sentence. `allow` with
 * nothing listed is a 400; `deny` with nothing listed is accepted and blocks
 * nothing, which is not something to save from a rule editor. Asked only when
 * the filter is about to be sent (groupSaveBlocked): an untouched stored filter
 * with a problem keeps its sentence and never holds Save back.
 */
export function filterProblem(f: FilterForm): string {
  if (f.mode === '') return ''
  if (f.tools.length + f.prefixes.length === 0) return ZERO_ENTRIES
  for (const e of f.tools) {
    const p = entryProblem(e, { kind: 'tool', side: f.mode, groupTarget: true })
    if (p) return p
  }
  for (const e of f.prefixes) {
    const p = entryProblem(e, { kind: 'prefix', side: f.mode, groupTarget: true })
    if (p) return p
  }
  return ''
}

/** filterProblem for one of a virtual key's two lists. A key has no prefixes, and an empty list is fine. */
export function listProblem(list: string[], side: 'allow' | 'deny', groupTarget: boolean): string {
  for (const e of list) {
    const p = entryProblem(e, { kind: 'tool', side, groupTarget })
    if (p) return p
  }
  return ''
}

/**
 * The standing sentence for an allow filter that admits nothing by its grammar
 * alone: every entry is unscoped, and the proxy skips an unscoped entry under
 * allow on a group (internal/proxy/policy.go, matchesAny). Such a filter passes
 * read validation, so nothing else in the section would say the group is dead.
 * No catalogue is needed to know it.
 */
export function filterAdmitsNothing(f: FilterForm): string {
  if (f.mode !== 'allow') return ''
  const entries = [...f.tools, ...f.prefixes]
  if (entries.length === 0 || entries.some((e) => splitEntry(e).scoped)) return ''
  return 'Every entry in this allow rule names no member, so it admits nothing and every tool on this group is blocked.'
}

/** Shown for a stored deny filter that lists nothing. The API accepts one and it does nothing. */
export function filterListsNothing(f: FilterForm): string {
  return f.mode === 'deny' && f.tools.length + f.prefixes.length === 0 ? 'This filter lists nothing, so it blocks nothing.' : ''
}

/**
 * Under "Add a tool by name". Says that the entry is ONE tool, because the input
 * below it looks the same and means something else.
 */
export function addToolHint(side: 'allow' | 'deny'): string {
  const verb = side === 'allow' ? 'Allows' : 'Denies'
  return `${verb} one tool. Write its full name: the upstream's slug, two underscores, then the tool's own name.`
}

/**
 * Under "Add a prefix". A prefix reads like a tool name and reaches every tool
 * whose name starts with it, which is how a rule meant for one tool ends up
 * covering two.
 */
export function addPrefixHint(side: 'allow' | 'deny'): string {
  const verb = side === 'allow' ? 'Allows' : 'Denies'
  return `${verb} every tool whose own name starts with this text, so it can match more than one. For a single tool, use the box above.`
}

/** The label of a member's whole-member checkbox. Under allow the same tick is a standing permit, so the word changes with the mode. */
export function wholeMemberLabel(mode: FilterMode, slug: string): string {
  const verb = mode === 'allow' ? 'Allow' : 'Deny'
  return `${verb} every tool on ${slug}, including tools it adds later.`
}

/** The prefixes entry a member's whole-member checkbox toggles: every tool on that member. */
export function wholeMemberPrefix(slug: string): string {
  return slug + TOOL_SEPARATOR
}

/**
 * Cuts a string for display without splitting a character: by code point, so a
 * surrogate pair is never left as half of itself. The unreadable stored filter
 * is whatever sits in the column, up to the API's 1 MiB body limit.
 */
export function clampText(s: string, max: number): { text: string; cut: boolean } {
  const points = Array.from(s)
  if (points.length <= max) return { text: s, cut: false }
  return { text: points.slice(0, max).join(''), cut: true }
}
