import type { Group } from './api.ts'
import { catalogueComplete } from './catalogue.ts'
import type { Catalogue } from './catalogue.ts'
import { filterPermits, matchToolEntry, scopedToolName, splitEntry } from './tool-entry.ts'
import { filterAdmitsNothing, parseToolFilter } from './tool-filter.ts'

// What one rule does to another (PORM-181). A virtual key's deny list is checked
// before its allow list, and its group's filter after both, so rules that each
// look fine can add up to a key that calls nothing, or to an allow entry that
// never takes effect. Every verdict here is read off stored text with the same
// matcher the proxy uses (matchToolEntry); none of them needs a tool catalogue,
// except the list of tools a prefix matches, which says nothing without a
// complete one. Nothing here holds a save back: the proxy accepts these rules,
// and the dashboard says what they do.

/**
 * The one tool an allow entry names. A scoped entry names it outright. A bare
 * entry names a tool only on a single-upstream key, where `targetSlug` is that
 * upstream's slug; on a group it names no member (and is already marked Cannot
 * be saved), and while the target is unknown nothing can be said.
 */
export function entryTool(entry: string, targetSlug: string): { slug: string; name: string } | null {
  const { head, rest, scoped } = splitEntry(entry)
  if (scoped) return rest === '' ? null : { slug: head, name: rest }
  return targetSlug && entry !== '' ? { slug: targetSlug, name: entry } : null
}

/** The first deny entry that names this tool, or ''. A bare deny entry names it on every member. */
export function deniedBy(slug: string, name: string, deny: string[]): string {
  return deny.find((d) => matchToolEntry(d, slug, name, false)) ?? ''
}

/** The deny entry that overrules this allow entry, or ''. */
export function allowEntryDeniedBy(entry: string, deny: string[], targetSlug: string): string {
  const tool = entryTool(entry, targetSlug)
  return tool ? deniedBy(tool.slug, tool.name, deny) : ''
}

/** Beside an allow entry the deny list overrules. */
export const ALSO_DENIED_NOTE = 'This tool is on the deny list too. Deny wins, so it stays blocked.'

/**
 * The standing sentence for an allow list nothing can get through: every entry
 * is either overruled by the deny list or, on a group key, names no member (the
 * proxy skips those). A non-empty allow list blocks everything it does not name,
 * so such a key can call nothing. '' when the list is empty (an empty allow list
 * allows everything not denied) or when any entry may still admit a tool,
 * including an entry that cannot be judged because the target is not known yet.
 */
export function allowListAdmitsNothing(allow: string[], deny: string[], groupTarget: boolean, targetSlug: string): string {
  if (allow.length === 0) return ''
  let unnamed = false
  for (const entry of allow) {
    if (groupTarget && !splitEntry(entry).scoped) {
      unnamed = true
      continue
    }
    if (!entryTool(entry, targetSlug)) return ''
    if (!allowEntryDeniedBy(entry, deny, targetSlug)) return ''
  }
  return unnamed
    ? 'Every entry on the allow list is either denied or names no member, so this key can call nothing.'
    : 'Every tool on the allow list is also denied, so this key can call nothing.'
}

/** Under a picker row while ticks go to the allow list, for a tool the deny list names. */
export function deniedRowNote(denyEntry: string): string {
  return `On the deny list as ${denyEntry}, so it stays blocked whatever is ticked here.`
}

/** How many matched names a prefix row spells out before it counts the rest. */
const PREFIX_NAMES_SHOWN = 5

/**
 * The scoped names of the advertised tools a prefixes entry matches. Empty
 * unless the catalogue is complete: a partial list would understate what the
 * prefix reaches, which is the mistake this exists to catch.
 */
export function prefixMatches(prefix: string, c: Catalogue): string[] {
  if (!catalogueComplete(c)) return []
  const out: string[] = []
  for (const m of c.members) {
    for (const t of m.tools) {
      if (matchToolEntry(prefix, m.slug, t.name, true)) out.push(scopedToolName(m.slug, t.name))
    }
  }
  return out
}

/**
 * Beside a Prefix row: which tools it reaches right now. A prefix typed where a
 * tool name was meant reads the same in the list; the names are what show that
 * `firecrawl__firecrawl_search` is two tools. '' when nothing can be said, and
 * when it matches nothing (the Not advertised badge says that).
 */
export function prefixMatchNote(prefix: string, c: Catalogue): string {
  const names = prefixMatches(prefix, c)
  if (names.length === 0) return ''
  const shown = names.slice(0, PREFIX_NAMES_SHOWN).join(', ')
  const more = names.length - PREFIX_NAMES_SHOWN
  const count = `${names.length} ${names.length === 1 ? 'tool' : 'tools'}`
  return `Matches ${count} advertised now: ${shown}${more > 0 ? `, and ${more} more` : ''}.`
}

/** How many of a group's entries the key dialog lists before it counts the rest. */
const GROUP_ENTRIES_SHOWN = 12

export type GroupFilterSummary = {
  /** pink when the group blocks every tool whatever the key says. */
  tone: 'zinc' | 'pink'
  sentence: string
  tools: string[]
  prefixes: string[]
  /** Entries left out of the two lists above. */
  more: number
}

/**
 * What a key's group already does, for the read-only block in the key dialog.
 * The group's filter is the third check the proxy runs, after the key's two
 * lists, and it can only take tools away, so the key dialog is where an operator
 * needs to see it. The verdict is parseToolFilter's, which is the proxy's.
 */
export function groupFilterSummary(group: Pick<Group, 'name' | 'tool_filter'>): GroupFilterSummary {
  const stored = parseToolFilter(group.tool_filter)
  const where = 'It is edited on the Groups page.'
  if (stored.kind === 'unreadable') {
    return {
      tone: 'pink',
      sentence: `The group ${group.name} has a filter that cannot be read, so every tool on it is blocked whatever this key allows. Replace it on the Groups page.`,
      tools: [],
      prefixes: [],
      more: 0,
    }
  }
  if (stored.kind === 'none') {
    return {
      tone: 'zinc',
      sentence: `The group ${group.name} has no filter, so the two lists below are the only rules on this key.`,
      tools: [],
      prefixes: [],
      more: 0,
    }
  }
  const f = stored.form
  const tools = f.tools.slice(0, GROUP_ENTRIES_SHOWN)
  const prefixes = f.prefixes.slice(0, Math.max(0, GROUP_ENTRIES_SHOWN - tools.length))
  const more = f.tools.length + f.prefixes.length - tools.length - prefixes.length
  if (filterAdmitsNothing(f)) {
    return {
      tone: 'pink',
      sentence: `The group ${group.name} has an allow filter whose entries name no member, so every tool on it is blocked whatever this key allows. ${where}`,
      tools,
      prefixes,
      more,
    }
  }
  if (f.tools.length + f.prefixes.length === 0) {
    return {
      tone: 'zinc',
      sentence: `The group ${group.name} has a deny filter that lists nothing, so it blocks nothing.`,
      tools,
      prefixes,
      more,
    }
  }
  const sentence =
    f.mode === 'allow'
      ? `The group ${group.name} allows only what is listed here. Everything else is blocked whatever this key allows. ${where}`
      : `The group ${group.name} already denies what is listed here, whatever this key allows. ${where}`
  return { tone: 'zinc', sentence, tools, prefixes, more }
}

/** Whether the group's filter stops a tool. An unreadable filter stops every tool; no filter stops none. */
export function groupBlocks(group: Pick<Group, 'tool_filter'>): (slug: string, name: string) => boolean {
  const stored = parseToolFilter(group.tool_filter)
  if (stored.kind === 'unreadable') return () => true
  if (stored.kind === 'none') return () => false
  const permits = filterPermits(stored.form)
  return (slug, name) => !permits(slug, name)
}

/** Under a picker row in the key dialog, for a tool the key's group stops. */
export const GROUP_BLOCKS_NOTE = "Blocked by the group's filter, whatever this key allows."
