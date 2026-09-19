import type { DiscoveredTool } from './api.ts'

// The browser's copy of the tool identity and entry rules. Every function here
// names the Go function it mirrors. None of them decides policy: the proxy
// (internal/proxy/policy.go) enforces and the API (internal/models/toolfilter.go)
// validates. These only decide what the dashboard shows, and what it refuses to
// send because the server would refuse it anyway. Run by `node --test`.

/** Mirrors models.ToolSeparator (internal/models/toolidentity.go). */
export const TOOL_SEPARATOR = '__'

/**
 * The identity a group endpoint advertises for one of this upstream's tools, and
 * the form a group tool_filter allow rule has to be written in. Mirrors
 * models.ToolIdentity.Canonical: slug, two underscores, then the tool's own name,
 * which ParseCanonical splits on the first separator, so a tool called `a__b`
 * keeps its own underscores. An empty slug yields an empty string, and the caller
 * shows only the published name.
 */
export function scopedToolName(slug: string, name: string): string {
  if (!slug) return ''
  return slug + TOOL_SEPARATOR + name
}

/**
 * The entry a tick writes. The saved discover route composes `scoped_name` with
 * the upstream's stored slug, so it is preferred; scopedToolName is the fallback
 * for a response that predates the field. Always the scoped form, on a group
 * target and on a single upstream alike: the proxy honours it on both
 * (internal/proxy/proxy.go composes with the upstream's slug), and it is the one
 * spelling a group allow rule accepts.
 */
export function tickEntry(slug: string, tool: DiscoveredTool): string {
  return tool.scoped_name || scopedToolName(slug, tool.name)
}

/**
 * Mirrors models.SplitEntry. An entry is scoped when it holds the separator with
 * something before it. For an unscoped entry head is '' and rest is the whole
 * entry, including one that starts with the separator.
 */
export function splitEntry(e: string): { head: string; rest: string; scoped: boolean } {
  const i = e.indexOf(TOOL_SEPARATOR)
  if (i <= 0) return { head: '', rest: e, scoped: false }
  return { head: e.slice(0, i), rest: e.slice(i + TOOL_SEPARATOR.length), scoped: true }
}

// Go's unicode.IsSpace: the Latin-1 spaces plus category Z. Written as code
// points because the project's TypeScript target predates \p{...} in a regex.
function isSpace(cp: number): boolean {
  return (
    (cp >= 0x09 && cp <= 0x0d) ||
    cp === 0x20 ||
    cp === 0x85 ||
    cp === 0xa0 ||
    cp === 0x1680 ||
    (cp >= 0x2000 && cp <= 0x200a) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x202f ||
    cp === 0x205f ||
    cp === 0x3000
  )
}

// Go's unicode.IsControl: category Cc only.
function isControl(cp: number): boolean {
  return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)
}

/**
 * Mirrors models.CleanToolEntry: not empty, and holding no whitespace, no control
 * character and no U+FFFD. A lone surrogate counts as U+FFFD, because that is
 * what Go's JSON decoder would have stored in its place.
 */
export function cleanEntry(e: string): boolean {
  if (e === '') return false
  for (const ch of e) {
    const cp = ch.codePointAt(0) ?? 0
    if (cp === 0xfffd || (cp >= 0xd800 && cp <= 0xdfff) || isSpace(cp) || isControl(cp)) return false
  }
  return true
}

/**
 * Mirrors models.MatchToolEntry. A scoped entry matches only on its own member
 * and compares its rest with the tool's OWN name; an unscoped entry compares
 * with the own name on every member. `prefix` selects startsWith over equality.
 * An empty entry matches nothing.
 */
export function matchToolEntry(entry: string, slug: string, name: string, prefix: boolean): boolean {
  if (entry === '') return false
  const { head, rest, scoped } = splitEntry(entry)
  if (scoped && head !== slug) return false
  return prefix ? name.startsWith(rest) : rest === name
}

// Mirrors models.ValidSlug (internal/models/slug.go): the three patterns there.
const SLUG_PATTERN = /^[a-z0-9]([a-z0-9_-]{0,38}[a-z0-9])?$/
const SLUG_SEP_RUN = /[_-]{2,}/
const UUID_LIKE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
function validSlug(s: string): boolean {
  return SLUG_PATTERN.test(s) && !SLUG_SEP_RUN.test(s) && !UUID_LIKE.test(s)
}

/**
 * '' when the API would accept this entry, otherwise one sentence that quotes
 * it. These are the WRITE-side rules (validateEntries and requireScoped in
 * internal/models/toolfilter.go), so they are asked only of an entry that is
 * about to be sent. A stored entry that fails them is still enforced as written,
 * which is why parseToolFilter never asks.
 *
 * kind 'prefix' is a tool_filter prefixes entry, the one list where an entry
 * may end at the separator. side and groupTarget select requireScoped: an allow
 * rule on a group must name a member. A group's own tool_filter is always a
 * group target.
 */
export function entryProblem(
  entry: string,
  o: { kind: 'tool' | 'prefix'; side: 'allow' | 'deny'; groupTarget: boolean },
): string {
  const shown = JSON.stringify(entry)
  if (entry === '') return 'An entry cannot be empty.'
  if (!cleanEntry(entry)) {
    return `${shown} holds a space or a control character. An entry is compared with the tool name character for character.`
  }
  const { head, rest, scoped } = splitEntry(entry)
  if (scoped) {
    if (!validSlug(head)) return `${shown}: the text before ${TOOL_SEPARATOR} must be an upstream's slug.`
    if (rest === '' && o.kind === 'tool') {
      return `${shown}: nothing follows ${TOOL_SEPARATOR}, so it names no tool. Add it as a prefix to cover every tool on that upstream.`
    }
    return ''
  }
  if (o.side === 'allow' && o.groupTarget) {
    return `${shown} names no member, so it admits nothing. Write it as slug${TOOL_SEPARATOR}${entry}.`
  }
  return ''
}

/**
 * Whether a group's tool_filter lets a tool through. Mirrors the group arm of
 * blockedBy and matchesAny (internal/proxy/policy.go). A group filter is always
 * a group target, on the combined endpoint and on each per-upstream endpoint, so
 * the proxy's skip of unscoped entries under allow is unconditional here: such
 * an entry admits nothing.
 *
 * The parameter is the FilterForm shape, written out so this module does not
 * import the one that imports it.
 */
export function filterPermits(f: {
  mode: string
  tools: string[]
  prefixes: string[]
}): (slug: string, name: string) => boolean {
  if (f.mode !== 'allow' && f.mode !== 'deny') return () => true
  const allow = f.mode === 'allow'
  const usable = (e: string) => !allow || splitEntry(e).scoped
  const tools = f.tools.filter(usable)
  const prefixes = f.prefixes.filter(usable)
  return (slug, name) => {
    const listed =
      tools.some((e) => matchToolEntry(e, slug, name, false)) || prefixes.some((e) => matchToolEntry(e, slug, name, true))
    return allow ? listed : !listed
  }
}
