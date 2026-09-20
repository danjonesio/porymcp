import type { DiscoveredTool, Discovery } from './api.ts'
import { matchToolEntry, scopedToolName, splitEntry, entryProblem } from './tool-entry.ts'

// What a Load tools press learned about a target's members, and every verdict
// and sentence that depends on it. The rule that runs through this file: a flag
// or a warning is computed only over a COMPLETE catalogue. A member that is down,
// rate limited or truncated would otherwise make a working deny entry read as
// dead, and an operator who believes that deletes it.

/** One upstream a group or a virtual key reaches. */
export type Member = { upstream_id: string; slug: string; name: string; enabled: boolean; transport: string }

export type MemberCatalogue = Member & {
  state: 'idle' | 'loading' | 'ok' | 'failed'
  tools: DiscoveredTool[]
  truncated: boolean
  unnameable: number
  /** The server's or discoveryErrorMessage's sentence, printed verbatim. */
  error: string
}

/** Always already narrowed to the target's CURRENT members (useCatalogue does it), in their order. */
export type Catalogue = { members: MemberCatalogue[] }

export function idleMember(m: Member): MemberCatalogue {
  return { ...m, state: 'idle', tools: [], truncated: false, unnameable: 0, error: '' }
}

/** One member's state from the discover route's answer. `ok: false` is the upstream failing, not the request. */
export function memberFromDiscovery(m: Member, d: Discovery): MemberCatalogue {
  if (!d.ok) {
    const said = d.upstream_message ? ` The server said: ${d.upstream_message}` : ''
    return { ...idleMember(m), state: 'failed', error: (d.error || 'That server could not be reached.') + said }
  }
  return { ...m, state: 'ok', tools: d.tools ?? [], truncated: d.truncated, unnameable: d.unnameable_tools ?? 0, error: '' }
}

function whole(m: MemberCatalogue): boolean {
  return m.state === 'ok' && !m.truncated
}

/**
 * True when every current member answered with its whole catalogue. A truncated
 * catalogue is incomplete: a name it never carried could be what an entry
 * matches. Unnameable tools do not count against it, because no entry can hold
 * such a name (CleanToolEntry), so none could have been matching one. A disabled
 * member loads like any other, since the discover route has no enabled check,
 * and counts here: its entries are live again the moment it is re-enabled.
 */
export function catalogueComplete(c: Catalogue): boolean {
  return c.members.length > 0 && c.members.every(whole)
}

/** The names of the members whose catalogue is missing or partial, for the line that says so. */
export function incompleteMembers(c: Catalogue): string[] {
  return c.members.filter((m) => !whole(m)).map((m) => m.name)
}

/**
 * The entries no advertised tool matches. Empty unless the catalogue is
 * complete: the absence of a flag is never a claim, and a flag computed from a
 * partial view would be a false one.
 */
export function unmatchedEntries(entries: string[], c: Catalogue, o: { prefix: boolean }): string[] {
  if (!catalogueComplete(c)) return []
  return entries.filter((e) => !c.members.some((m) => m.tools.some((t) => matchToolEntry(e, m.slug, t.name, o.prefix))))
}

/**
 * The entry, other than the row's own scoped one, that already names this tool:
 * a prefix, a whole-member prefix, or an unscoped tools entry. Such a row
 * renders checked and disabled, and is changed from the Entries list: unticking
 * one row must never delete a rule that covers other tools too. An unscoped
 * entry on the allow side of a group target covers nothing, because the proxy
 * skips it there (internal/proxy/policy.go, matchesAny).
 */
export function coveringEntry(
  slug: string,
  name: string,
  o: { tools: string[]; prefixes: string[]; side: 'allow' | 'deny'; groupTarget: boolean },
): string {
  const own = scopedToolName(slug, name)
  const skipped = (e: string) => o.side === 'allow' && o.groupTarget && !splitEntry(e).scoped
  for (const e of o.tools) {
    if (e !== own && !skipped(e) && matchToolEntry(e, slug, name, false)) return e
  }
  for (const e of o.prefixes) {
    if (!skipped(e) && matchToolEntry(e, slug, name, true)) return e
  }
  return ''
}

/**
 * True only on a complete catalogue whose enabled members advertise at least
 * one tool, none of which `permits` lets through. Disabled members are left out
 * because the proxy does not list them. Advisory: it words a confirm and a
 * standing line, and never holds a save back.
 */
export function blocksEverything(permits: (slug: string, name: string) => boolean, c: Catalogue): boolean {
  if (!catalogueComplete(c)) return false
  let seen = false
  for (const m of c.members) {
    if (!m.enabled) continue
    for (const t of m.tools) {
      seen = true
      if (permits(m.slug, t.name)) return false
    }
  }
  return seen
}

/** The line under a row another entry already names. Such a row is changed from the Entries list, never by unticking it. */
export function coveredNote(entry: string): string {
  return `Covered by ${entry}. Change it in the entries above.`
}

/** The standing line for a filter that, against a complete catalogue, leaves nothing callable. */
export const BLOCKS_EVERYTHING_NOW = 'As it stands, this filter blocks every tool on this group.'

/** The polite live-region summary of a load: what arrived, without reading fifty rows aloud. */
export function catalogueSummary(c: Catalogue): string {
  const failed = c.members.filter((m) => m.state === 'failed').length
  const ok = c.members
    .filter((m) => m.state === 'ok')
    .map((m) => `${m.name}, ${m.tools.length} ${m.tools.length === 1 ? 'tool' : 'tools'}.`)
  // A load in which nothing answered must still be announced: silence after a
  // press reads as "still working" to someone who cannot see the pink lines.
  if (failed > 0) ok.push(`${failed} ${failed === 1 ? 'upstream' : 'upstreams'} could not be loaded.`)
  return ok.join(' ')
}

/** Why no entry carries a Not advertised badge right now. '' before any load and on a complete catalogue. */
export function incompleteLine(c: Catalogue): string {
  if (c.members.every((m) => m.state === 'idle')) return ''
  const names = incompleteMembers(c)
  if (names.length === 0) return ''
  const which = names.length === 1 ? 'one catalogue is incomplete' : 'these catalogues are incomplete'
  return `Entries are not checked against what is advertised, because ${which}: ${names.join(', ')}.`
}

/** The panel's sentence for a catalogue the server cut short (web/src/app/discovery-panel.tsx uses it too). */
export function truncatedNote(shown: number): string {
  return `Not every tool is listed. ${shown} shown. This server offers more.`
}

/** The panel's sentence for tools whose names discovery dropped (web/src/app/discovery-panel.tsx uses it too). */
export function unnameableNote(n: number): string {
  if (n <= 0) return ''
  return n === 1
    ? '1 tool is not listed: its name contains characters PoryMCP cannot hold a caller to.'
    : `${n} tools are not listed: their names contain characters PoryMCP cannot hold a caller to.`
}

/** Under a disabled member of a group. The discover route has no enabled check, so its tools still load and can still be ticked. */
export const MEMBER_DISABLED = 'Disabled. A virtual key on this group gets no endpoint for it.'

/** Under a member whose transport PoryMCP does not speak (PORM-28). Discovery fails before it dials, so there is nothing to try again. */
export const MEMBER_NOT_IMPLEMENTED =
  "Not implemented. This member's endpoint fails, and so does the group endpoint, until the transport is Streamable HTTP or the member is disabled."

/** What a Load tools press does besides listing tools. Said before the press, because it is a write. */
export const LOAD_RECORDS_A_TEST =
  "Loading connects to each upstream with its stored credential and records the result as that upstream's last test."

/** Under an allow rule a tool the picker cannot show cannot be ticked, so it stays blocked. Said once per affected member. */
export const UNLISTED_STAYS_BLOCKED = 'A tool that is not listed cannot be ticked and stays blocked.'

/**
 * The line under a row whose scoped name no tools entry can carry: the API
 * refuses an entry holding a space or a control character, while the proxy
 * advertises and calls such a tool. A prefix that stops before that character
 * still reaches it, and the sentence says so, or an operator under deny
 * concludes the tool cannot be blocked.
 */
export function unnameableRowNote(side: 'allow' | 'deny', prefixes: boolean, covered: boolean): string {
  const base = 'This name holds a space or a control character, so no tool entry can name it.'
  // Once a prefix does reach it, the row says which one (coveredNote) and must
  // not go on claiming the tool is blocked: under allow that prefix permits it.
  if (covered) return base
  const route = prefixes ? ' A prefix that stops before that character can.' : ''
  const allow = side === 'allow' ? ' It stays blocked, because it is not on the list.' : ''
  return base + route + allow
}

/** The sentence beside a Not advertised badge. A key's lists also govern prompts and resources by bare name, so there it claims less. */
export function notAdvertisedNote(side: 'allow' | 'deny', keyList: boolean): string {
  if (keyList) return 'No tool advertised right now carries this name. The rule is kept.'
  return side === 'allow'
    ? 'No member advertises this tool right now, so this entry admits nothing.'
    : 'No member advertises this tool right now. The rule is kept and applies if the tool comes back.'
}

export type EntryMark = { badge: '' | 'Cannot be saved' | 'Not advertised' | 'Prefix' | 'Any member'; note: string }

/**
 * The badge and sentence for one row of the Entries list. A write-side problem
 * wins, then Not advertised (complete catalogue only, via `unmatched`), then
 * what kind of entry it is.
 */
export function entryMark(
  entry: string,
  o: { kind: 'tool' | 'prefix'; side: 'allow' | 'deny'; groupTarget: boolean; keyList: boolean; unmatched: string[] },
): EntryMark {
  const problem = entryProblem(entry, o)
  if (problem) return { badge: 'Cannot be saved', note: problem }
  if (o.unmatched.includes(entry)) return { badge: 'Not advertised', note: notAdvertisedNote(o.side, o.keyList) }
  if (o.kind === 'prefix') return { badge: 'Prefix', note: '' }
  // Only where there is more than one member for a bare name to reach.
  if (o.groupTarget && !splitEntry(entry).scoped) return { badge: 'Any member', note: '' }
  return { badge: '', note: '' }
}
