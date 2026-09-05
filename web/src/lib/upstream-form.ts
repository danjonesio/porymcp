import type { Upstream } from './api.ts'
import { authState } from './upstream-auth.ts'

/**
 * The Add and Edit upstream dialogs share one form shape: the row's fields plus
 * the three credential boxes, which hold what the operator typed and never what
 * is stored. Everything that turns this shape into a request body lives here
 * so `node --test` can reach it; the dialog itself has no test runner.
 */
export type UpstreamForm = {
  name: string
  slug: string
  description: string
  url: string
  transport: string
  auth_type: string
  token: string
  header: string
  value: string
  enabled: boolean
}

/**
 * The fields a discovery result describes. Editing one of them in the Add
 * dialog throws the panel away, because it answered for the connection as it
 * was. Name, slug and description are not here: they only change previewed tool
 * names, which recompute on render.
 */
export const CONNECTION_FIELDS = ['url', 'transport', 'auth_type', 'token', 'header', 'value'] as const

/** The header name the Add dialog starts with. PORM-39 changes it here and nowhere else. */
export const DEFAULT_HEADER = 'Authorization'

/** What the auth type select shows for each stored value. */
export const AUTH_TYPE_LABELS: Record<string, string> = {
  none: 'None',
  bearer: 'Bearer',
  header: 'Header',
  api_key: 'API key',
  custom: 'Custom',
}

export function authTypeLabel(authType: string): string {
  return AUTH_TYPE_LABELS[authType] ?? authType
}

/** The three auth types whose credential is a header name and a value. */
export function headerShaped(authType: string): boolean {
  return authType === 'header' || authType === 'api_key' || authType === 'custom'
}

/** The Add dialog's initial state. */
export function blankUpstreamForm(): UpstreamForm {
  return {
    name: '',
    slug: '',
    description: '',
    url: '',
    transport: 'streamable-http',
    auth_type: 'none',
    token: '',
    header: DEFAULT_HEADER,
    value: '',
    enabled: true,
  }
}

/**
 * Seed the Edit dialog from a row. The credential boxes start empty on every
 * row: the server never sends a stored value, and the dialog never asks for one
 * unless the operator is changing it. The header name comes from `auth_hint`,
 * which the server sends only when the stored credential reads and carries a
 * header. When it is absent (bearer, none, an undecryptable or unreadable row)
 * the box starts empty rather than with a guess: a header name the operator did
 * not choose is a silent failure of a different shape. `headerRequired` is what
 * stops a credential being sent with no header name.
 */
export function formFromUpstream(u: Upstream): UpstreamForm {
  return {
    name: u.name,
    slug: u.slug,
    description: u.description ?? '',
    url: u.url,
    transport: u.transport,
    auth_type: u.auth_type,
    token: '',
    header: u.auth_hint?.header ?? '',
    value: '',
    enabled: u.enabled,
  }
}

/**
 * The form's credential fields, in the shape the API stores them. Returns `{}`
 * for a blank box, which create and discover depend on; a PATCH must not send
 * that (see upstreamPatchBody), because `{}` is a value to the server and seals
 * an empty credential over the stored one.
 */
export function authConfigFrom(form: Pick<UpstreamForm, 'auth_type' | 'token' | 'header' | 'value'>): Record<
  string,
  string
> {
  const auth_config: Record<string, string> = {}
  if (form.auth_type === 'bearer' && form.token) auth_config.token = form.token
  if (headerShaped(form.auth_type) && form.value) {
    auth_config.header = form.header
    auth_config.value = form.value
  }
  return auth_config
}

/** True when the operator typed a credential this dialog can send. */
export function credentialTyped(f: Pick<UpstreamForm, 'auth_type' | 'token' | 'value'>): boolean {
  if (f.auth_type === 'bearer') return f.token.trim() !== ''
  if (headerShaped(f.auth_type)) return f.value.trim() !== ''
  return false
}

/** The `POST /upstreams` body, exactly as the Add dialog has always sent it. */
export function upstreamCreateBody(f: UpstreamForm, slugTouched: boolean): Record<string, unknown> {
  return {
    name: f.name,
    slug: slugTouched ? f.slug : '',
    description: f.description,
    url: f.url,
    transport: f.transport,
    auth_type: f.auth_type,
    auth_config: authConfigFrom(f),
    enabled: f.enabled,
  }
}

/**
 * The `PATCH /upstreams/{id}` body: only the keys whose value differs from the
 * row the dialog was seeded with. An absent key leaves the field unchanged
 * (docs/03-api.md, Partial updates), and the admin event lists exactly the
 * keys sent, so an unchanged field is never sent. `auth_config` goes only when
 * a credential was typed; never `{}`, never `null`. `slug` never goes: the
 * server refuses any change and the dialog has no input for it. The URL is
 * trimmed before comparing because the server's own reset predicate trims
 * (internal/api/upstreams.go, patchUpstream); an untrimmed compare would send a
 * URL the server treats as unchanged and reset the health dot for nothing.
 */
export function upstreamPatchBody(before: Upstream, f: UpstreamForm): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  const name = f.name.trim()
  if (name !== before.name) body.name = name
  if (f.description !== (before.description ?? '')) body.description = f.description
  const url = f.url.trim()
  if (url !== before.url) body.url = url
  if (f.transport !== before.transport) body.transport = f.transport
  if (f.auth_type !== before.auth_type) body.auth_type = f.auth_type
  if (f.enabled !== before.enabled) body.enabled = f.enabled
  if (credentialTyped(f)) body.auth_config = authConfigFrom(f)
  return body
}

/**
 * Whether the Edit dialog must have a credential before it can save. Two cases.
 * The auth type changed to one that needs a credential: the server would accept
 * the new type over the old blob and the row would read unreadable, with no 400
 * to stop it. Or the header name changed on a header-shaped type: the name is
 * sealed inside the credential, so it cannot change without the value. The
 * header is compared against the seeded value, not the raw hint, so a row whose
 * hint is absent can be renamed without re-entering anything.
 *
 * header, api_key and custom share one stored shape, so switching between them
 * would in fact leave a working blob behind. Forcing re-entry there is the
 * issue's deliberate default (PORM-2), not a server requirement.
 *
 * An unusable stored credential (undecryptable, unreadable) is a notice in
 * credentialHelp, not a block: an operator may want to rename or disable a
 * broken upstream without repairing it.
 */
export function credentialRequired(before: Upstream, f: UpstreamForm): boolean {
  if (f.auth_type !== before.auth_type) return f.auth_type !== 'none'
  if (headerShaped(f.auth_type)) return f.header.trim() !== formFromUpstream(before).header
  return false
}

/**
 * Whether the header-name box must be filled: whenever a credential is about to
 * be sent for a header-shaped type. The proxy sends nothing for `header` and
 * `custom` with an empty header name and silently substitutes X-API-Key for
 * `api_key` (internal/mcpclient/inject.go, headersFor), so a body with an empty
 * name must never leave the browser. Undefined `before` is the Add dialog.
 */
export function headerRequired(before: Upstream | undefined, f: UpstreamForm): boolean {
  if (!headerShaped(f.auth_type)) return false
  return credentialTyped(f) || (before !== undefined && credentialRequired(before, f))
}

const HEADER_SUFFIX = ' The header name is stored with it, so enter that too.'

/**
 * The helper text under the credential box in the Edit dialog when nothing
 * forces a re-entry. Branches on authState so this sentence and the table's
 * Auth badge cannot disagree: the two broken tones split by status, and an
 * `auth_status` neither knows reads as ok, the same default authState takes.
 */
export function credentialHelp(before: Upstream, f: UpstreamForm): string {
  const suffix = headerShaped(f.auth_type) ? HEADER_SUFFIX : ''
  const state = authState(before)
  if (state.tone === 'broken') {
    if (before.auth_status === 'undecryptable') {
      return (
        'The stored credential cannot be read with the current encryption key. Enter it again, or restore the key it was saved under. Until then this upstream cannot authenticate.' +
        suffix
      )
    }
    return 'No usable credential is stored for this auth type. Enter one, or this upstream cannot authenticate.' + suffix
  }
  if (state.tone === 'none') return `Enter the credential for ${authTypeLabel(f.auth_type)}.`
  const header = before.auth_hint?.header
  if (header) return `Leave blank to keep the stored credential. It currently sends the ${header} header. A value here replaces it.`
  return 'Leave blank to keep the stored credential. A value here replaces it.'
}
