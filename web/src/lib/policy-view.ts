import type { PolicyView } from './api.ts'
import { plural } from './plural.ts'
import { METHODS_UNREADABLE_SENTENCE } from './virtual-key-form.ts'

/**
 * The Policy dialog's rules and copy (PORM-209), kept apart from the markup so
 * `node --test` can reach them. The verdicts are the server's: every
 * *_malformed flag is read before the value beside it, because an unreadable
 * rule refuses every call and must never read as one that refuses nothing.
 */

/** The three blocks of the dialog: the door a rule runs on, then the egress switches. */
export type PolicyBlock = 'mcp' | 'http' | 'outbound'

/** The rule ids each door block holds, so a block with counts stays visible after its door went away. */
const MCP_RULES = ['key_denylist', 'key_allowlist', 'key_lists_unreadable', 'group_tool_filter', 'group_tool_filter_unreadable']
const HTTP_RULES = ['http_methods', 'http_methods_unreadable']

export const PERIOD_TEXT = 'in the last 7 days'

/** "Blocked no calls in the last 7 days." The dashboard never sends a period, so the server's default is the one it names. */
export function blockedLine(n: number): string {
  return n === 0 ? `Blocked no calls ${PERIOD_TEXT}.` : `Blocked ${plural(n, 'call')} ${PERIOD_TEXT}.`
}

/** A rule's count, zero when the id is missing (the server sends every id, so that is never expected). */
export function ruleCount(view: PolicyView, id: string): number {
  return view.blocked.by_rule[id] ?? 0
}

function anyCount(view: PolicyView, ids: string[]): boolean {
  return ids.some((id) => ruleCount(view, id) > 0)
}

/**
 * Which blocks to draw. Outbound always. A door block when the key has that
 * door, or when one of its rules refused something in the period: an HTTP
 * member that has since left the group still has counts worth seeing.
 */
export function visibleBlocks(view: PolicyView): PolicyBlock[] {
  const out: PolicyBlock[] = []
  if (view.target_kinds.includes('mcp') || anyCount(view, MCP_RULES)) out.push('mcp')
  if (view.target_kinds.includes('http') || anyCount(view, HTTP_RULES)) out.push('http')
  out.push('outbound')
  return out
}

/** Whether a visible door block is shown only for its counts. */
export function shownForCountsOnly(view: PolicyView, block: PolicyBlock): boolean {
  if (block === 'mcp') return !view.target_kinds.includes('mcp')
  if (block === 'http') return !view.target_kinds.includes('http')
  return false
}

export const COUNTS_ONLY_NOTE = 'This key has no such endpoint now; the counts are from earlier calls.'

export const GROUP_GONE_SENTENCE = 'The group this key targets no longer exists, so every call on it fails.'
export const UPSTREAM_GONE_SENTENCE = 'The upstream this key targets no longer exists, so every call on it fails.'

/** The line above every block when the key's target is gone, or null. */
export function targetGoneSentence(view: PolicyView): string | null {
  if (view.target_kinds.length > 0) return null
  return view.target_type === 'group' ? GROUP_GONE_SENTENCE : UPSTREAM_GONE_SENTENCE
}

/** The sentence for an empty key list. The allow list judges prompts and resources by name too, but tools are the common case. */
export function listEmptySentence(list: 'deny' | 'allow'): string {
  return list === 'deny' ? 'No entries. This list blocks nothing.' : 'No entries. Every tool passes this list.'
}

/**
 * The Allowed methods sentence. The malformed flag is checked first: an
 * unreadable list arrives as [], which would otherwise read as every method
 * allowed. null when the verbs themselves are the answer (drawn as badges).
 */
export function methodsSentence(
  methods: string[] | null,
  malformed: boolean,
): { tone: 'zinc' | 'pink'; sentence: string } | null {
  if (malformed) return { tone: 'pink', sentence: METHODS_UNREADABLE_SENTENCE }
  if (methods !== null && methods.length === 0) return { tone: 'zinc', sentence: 'Every method is allowed.' }
  return null
}

export const ALWAYS_REFUSED_SENTENCE = 'Cloud metadata, link-local, multicast and unspecified addresses are always refused.'
export const EVERY_KEY_NOTE = 'These apply to every key.'
export const OUTBOUND_LOGS_NOTE = 'These are recorded as errors on the Logs page.'

/** The two egress switches as sentences, loopback first. */
export function egressSentences(egress: PolicyView['egress']): { loopback: string; private: string } {
  return {
    loopback: egress.allow_loopback
      ? 'Loopback addresses are allowed by UPSTREAM_ALLOW_LOOPBACK.'
      : 'Loopback addresses are refused. Set UPSTREAM_ALLOW_LOOPBACK to allow them.',
    private: egress.deny_private
      ? 'Private addresses are refused by UPSTREAM_DENY_PRIVATE.'
      : 'Private addresses are allowed. Set UPSTREAM_DENY_PRIVATE to refuse them.',
  }
}

/** Refusals of the four classes neither switch controls. */
export function alwaysRefusedCount(view: PolicyView): number {
  const c = view.blocked.upstream_address_denied_by_class
  return (c.metadata ?? 0) + (c['link-local'] ?? 0) + (c.multicast ?? 0) + (c.unspecified ?? 0)
}

/** A line under the description for a key that no longer authenticates, or null. */
export function statusLine(status: string): string | null {
  if (status === 'revoked') return 'This key is revoked. Its rules no longer run, and the counts stop at revocation.'
  if (status === 'expired') return 'This key has expired. Its rules no longer run, and the counts stop at expiry.'
  return null
}

export const ORDER_NOTE = 'An unreadable group filter or key list is checked first and refuses every call.'
export const EDITED_RULES_NOTE =
  'Counts include calls refused by entries that have since changed. Rule edits are listed under Admin events on the Logs page.'

/** The dialog's line for a load that took longer than the server's deadline. */
export const SLOW_COUNT_SENTENCE = "Counting this key's refusals took too long. Close this dialog and try again."
