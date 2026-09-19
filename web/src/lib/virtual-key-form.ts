import type { VirtualKey } from './api.ts'
import { listProblem, sameEntries } from './tool-filter.ts'

/**
 * The Create and Edit virtual key dialogs share one form shape. Everything that
 * turns it into a request body lives here so `node --test` can reach it.
 *
 * Edit never sends the target: a retarget re-judges a scoped allow list
 * (internal/api/virtual_keys.go, checkRetargetedAllowlist), and PORM-3 owns the
 * rest of that dialog. Bodies are built from named keys and never by spreading
 * a row, so a response's one-time `api_key` cannot travel back.
 */
export type KeyForm = {
  name: string
  /** Create only. */
  target_type: 'upstream' | 'group'
  /** Create only. */
  target_id: string
  /** '' means no limit. */
  rate_limit: string
  tool_allowlist: string[]
  tool_denylist: string[]
  /** Replace the stored rules was pressed on a key whose stored lists cannot be read. Closing the dialog undoes it. */
  listsReplace: boolean
}

export function blankVirtualKeyForm(): KeyForm {
  return {
    name: '',
    target_type: 'upstream',
    target_id: '',
    rate_limit: '',
    tool_allowlist: [],
    tool_denylist: [],
    listsReplace: false,
  }
}

export function formFromVirtualKey(vk: VirtualKey): KeyForm {
  return {
    name: vk.name,
    target_type: vk.target_type === 'group' ? 'group' : 'upstream',
    target_id: vk.target_id,
    rate_limit: vk.rate_limit ? String(vk.rate_limit) : '',
    // Both lists are omitempty on the wire, so absent means empty. On a key
    // that reports lists_malformed, a list that did not decode is absent too
    // (one that did is served as stored), which is why that flag exists: an
    // empty array here is not necessarily the key's rule.
    tool_allowlist: [...(vk.tool_allowlist ?? [])],
    tool_denylist: [...(vk.tool_denylist ?? [])],
    listsReplace: false,
  }
}

/**
 * The `POST /virtual-keys` body. A key is left out when it has nothing to say,
 * never set to undefined, so the body is what JSON.stringify would have sent
 * from the literal this replaced.
 */
export function virtualKeyCreateBody(f: KeyForm): Record<string, unknown> {
  const body: Record<string, unknown> = { name: f.name, target_type: f.target_type, target_id: f.target_id }
  if (f.rate_limit) body.rate_limit = Number(f.rate_limit)
  if (f.tool_allowlist.length > 0) body.tool_allowlist = f.tool_allowlist
  if (f.tool_denylist.length > 0) body.tool_denylist = f.tool_denylist
  return body
}

/** Which of the two lists the PATCH for this form would carry. The one definition, shared by the body, the save gate and the stale check. */
export function listsSent(before: VirtualKey, f: KeyForm): ('tool_allowlist' | 'tool_denylist')[] {
  // A key whose stored lists cannot be read accepts both lists together or
  // neither (patchVirtualKey answers 400 to one alone). Both go only after the
  // operator pressed Replace the stored rules: sent unasked, two empty lists
  // would turn a key that refuses every call into one with no rules at all,
  // from a dialog that never showed a rule.
  if (before.lists_malformed) return f.listsReplace ? ['tool_allowlist', 'tool_denylist'] : []
  const out: ('tool_allowlist' | 'tool_denylist')[] = []
  if (!sameEntries(before.tool_allowlist, f.tool_allowlist)) out.push('tool_allowlist')
  if (!sameEntries(before.tool_denylist, f.tool_denylist)) out.push('tool_denylist')
  return out
}

/**
 * The `PATCH /virtual-keys/{id}` body: only what differs from the row the
 * dialog was seeded with (docs/03-api.md, Partial updates). A list goes only
 * when its SET changed. An untouched list sent back is judged by today's rules
 * and can be refused, and sending an already-empty list records a clear that
 * did not happen (the server computes `cleared` from presence). An emptied list
 * is `[]`, which the server records as the clear it is.
 */
export function virtualKeyPatchBody(before: VirtualKey, f: KeyForm): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  const name = f.name.trim()
  if (name !== before.name) body.name = name
  const limit = f.rate_limit ? Number(f.rate_limit) : null
  if (limit !== (before.rate_limit ?? null)) body.rate_limit = limit
  for (const field of listsSent(before, f)) body[field] = f[field]
  return body
}

/**
 * '' when Save may proceed, otherwise the sentence that says why not. A list's
 * problems hold Save back only when the body would carry that list, so a stored
 * legacy entry never stops a rename. Create sends every non-empty list.
 */
export function keySaveBlocked(before: VirtualKey | null, f: KeyForm, groupTarget: boolean): string {
  const sent = before ? listsSent(before, f) : (['tool_denylist', 'tool_allowlist'] as const)
  for (const field of ['tool_denylist', 'tool_allowlist'] as const) {
    if (!sent.includes(field)) continue
    const p = listProblem(f[field], field === 'tool_allowlist' ? 'allow' : 'deny', groupTarget)
    if (p) return p
  }
  return ''
}

/**
 * True when a list this save would replace is no longer the one the dialog was
 * seeded with, or when the key became unreadable or was repaired meanwhile.
 * Asked of a fresh read just before a PATCH that carries a list: the API has no
 * 409 yet (PORM-119). Per field, because PATCH replaces only what it is sent:
 * another operator's edit to the allow list must not refuse a deny-list save.
 * The flag is compared because an undecodable list is served as absent, so a
 * repair made elsewhere that ended with that list empty would otherwise compare
 * equal and be overwritten by Replace.
 */
export function keyPolicyStale(
  seed: VirtualKey,
  fresh: VirtualKey,
  fields: readonly ('tool_allowlist' | 'tool_denylist')[],
): boolean {
  if (!!seed.lists_malformed !== !!fresh.lists_malformed) return true
  return fields.some((field) => !sameEntries(seed[field], fresh[field]))
}

/** Shown in the dialog when keyPolicyStale stopped a save. Nothing was sent. */
export const KEY_RULES_STALE =
  "This key's tool rules changed since you opened it. Close this dialog and open it again to see the current rules."

/**
 * The badge under a key's target in the table: how many rules it carries, or
 * that the proxy cannot read them and refuses every call. null for a key with no
 * rules, which is the ordinary case and needs no mark.
 */
export function keyRulesBadge(vk: VirtualKey): { label: string; tone: 'zinc' | 'pink' } | null {
  if (vk.lists_malformed) return { label: 'Rules unreadable', tone: 'pink' }
  const parts: string[] = []
  const allowed = vk.tool_allowlist?.length ?? 0
  const denied = vk.tool_denylist?.length ?? 0
  if (allowed > 0) parts.push(`${allowed} allowed`)
  if (denied > 0) parts.push(`${denied} denied`)
  return parts.length > 0 ? { label: parts.join(', '), tone: 'zinc' } : null
}
