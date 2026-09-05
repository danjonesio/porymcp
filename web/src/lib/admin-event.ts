import type { AdminEvent } from './api'

/**
 * The verb for each action, in the words the product's own buttons use ("Add
 * upstream", "Create group", "Create virtual key"). An action this map does
 * not know renders as itself, so a newer server is shown rather than hidden.
 */
const VERBS: Record<string, string> = {
  'upstream.create': 'Added upstream',
  'upstream.update': 'Changed upstream',
  'upstream.delete': 'Deleted upstream',
  'group.create': 'Created group',
  'group.update': 'Changed group',
  'group.delete': 'Deleted group',
  'virtual_key.create': 'Created virtual key',
  'virtual_key.update': 'Changed virtual key',
  'virtual_key.rotate': 'Rotated virtual key',
  'virtual_key.revoke': 'Revoked virtual key',
  'virtual_key.delete': 'Deleted virtual key',
}

/** How a changed field reads in the Details cell. A field not listed reads as its own name. */
const FIELD_LABELS: Record<string, string> = {
  auth_type: 'auth type',
  upstream_ids: 'upstreams',
  tool_filter: 'tool filter',
  rate_limit: 'rate limit',
  expires_at: 'expiry',
  tool_allowlist: 'allowlist',
  tool_denylist: 'denylist',
  target_type: 'target',
  target_id: 'target',
}

/** The keys the server composes. Anything else is shown by name only. */
const KNOWN_KEYS = new Set([
  'fields',
  'cleared',
  'slug',
  'auth_type',
  'auth_changed',
  'upstream_count',
  'tool_filter_set',
  'target_type',
  'target_id',
  'key_prefix',
])

function label(field: string): string {
  return FIELD_LABELS[field] ?? field
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

/** "Added upstream GitHub", "Rotated virtual key demo-vk". */
export function eventSentence(e: AdminEvent): string {
  const name = e.resource_name || e.resource_id
  return `${VERBS[e.action] ?? e.action} ${name}`
}

/**
 * The Details cell: a comma list of what the event carries. "" when there is
 * nothing to say (the cell then shows the absent placeholder). Changed fields
 * read by their label, de-duplicated after mapping so a retarget's two fields
 * read as one "target"; a cleared field reads "<label> cleared"; a credential
 * change reads "credential" ("credential set" on a create). Values appear only
 * for the bounded identifiers the server records: slug, auth type, target
 * type, key prefix, member count.
 *
 * This is the one function that iterates details. The cast below exists so a
 * key a newer server adds is shown by name rather than dropped; its value is
 * never rendered.
 */
export function changedText(e: AdminEvent): string {
  const d = e.details as Record<string, unknown>
  const create = e.action.endsWith('.create')
  const fields = strings(d.fields)
  const labels: string[] = []
  for (const f of fields) {
    let text = label(f)
    if (f === 'auth_type' && typeof d.auth_type === 'string' && d.auth_type) {
      text = `auth type ${d.auth_type}`
    }
    if (f === 'upstream_ids' && typeof d.upstream_count === 'number') {
      text = `upstreams (${d.upstream_count})`
    }
    if (!labels.includes(text)) labels.push(text)
  }
  const parts: string[] = [...labels]
  for (const c of strings(d.cleared)) {
    parts.push(`${label(c)} cleared`)
  }
  if (typeof d.slug === 'string' && d.slug) parts.push(`slug ${d.slug}`)
  if (create && typeof d.auth_type === 'string' && d.auth_type) parts.push(`auth type ${d.auth_type}`)
  if (d.auth_changed === true) parts.push(create ? 'credential set' : 'credential')
  if (create && typeof d.upstream_count === 'number') parts.push(plural(d.upstream_count, 'upstream'))
  if (d.tool_filter_set === true) parts.push('tool filter set')
  if (typeof d.target_type === 'string' && d.target_type) parts.push(`target ${d.target_type}`)
  if (typeof d.key_prefix === 'string' && d.key_prefix) parts.push(`key prefix ${d.key_prefix}`)
  for (const k of Object.keys(d)) {
    if (!KNOWN_KEYS.has(k)) parts.push(k)
  }
  return parts.join(', ')
}
