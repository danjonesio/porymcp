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
  /** `mcp` or `http` (PORM-146). Chosen on Add; shown read-only on Edit and never sent by upstreamPatchBody. */
  kind: string
  url: string
  transport: string
  /** The connection test's path on an http row; '' means the base URL. Never sent on an mcp row. */
  test_path: string
  auth_type: string
  token: string
  header: string
  value: string
  /**
   * The optional client identity of an oauth upstream (PORM-139): what the
   * vendor issued in its own settings, when it did. Both start empty on Edit
   * (blank means keep). register_client sends `client: registered` on
   * Connect, for a deployment the vendor cannot fetch the client document
   * from; it is never sent to the server as a field.
   */
  client_id: string
  client_secret: string
  register_client: boolean
  enabled: boolean
  /**
   * The "Remove the stored value" checkbox in the Edit dialog, offered only on
   * a none row that still holds stored bytes. Never sent on create; read by
   * upstreamPatchBody alone (PORM-120).
   */
  clear_stored: boolean
}

/**
 * The fields a discovery result describes. Editing one of them in the Add
 * dialog throws the panel away, because it answered for the connection as it
 * was. Name, slug and description are not here: they only change previewed tool
 * names, which recompute on render.
 */
export const CONNECTION_FIELDS = ['kind', 'url', 'transport', 'test_path', 'auth_type', 'token', 'header', 'value'] as const

/** The header name the Add dialog starts with. PORM-39 changes it here and nowhere else. */
export const DEFAULT_HEADER = 'Authorization'

/**
 * What the Kind radio and the Kind column show for each stored value. One
 * map for both, so the table and the dialog name a thing the same way.
 */
export const KIND_LABELS: Record<string, string> = {
  mcp: 'MCP server',
  http: 'HTTP API',
}

export function kindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind
}

/**
 * The form after the Kind radio changed. Typed values stay, with one rule:
 * an HTTP API row cannot be oauth (the server refuses it), so a form that
 * had OAuth selected falls back to None and drops the client boxes rather
 * than leave a native select showing an option that is not the state.
 */
export function applyKindChange(f: UpstreamForm, kind: string): UpstreamForm {
  const next = { ...f, kind }
  if (kind === 'http' && f.auth_type === 'oauth') {
    next.auth_type = 'none'
    next.client_id = ''
    next.client_secret = ''
    next.register_client = false
  }
  return next
}

/** What the auth type select shows for each stored value. */
export const AUTH_TYPE_LABELS: Record<string, string> = {
  none: 'None',
  bearer: 'Bearer',
  header: 'Header',
  api_key: 'API key',
  custom: 'Custom',
  oauth: 'OAuth',
}

/**
 * What the transport select offers. One entry: `streamable-http` is the only
 * value the API accepts on write (PORM-28). A row stored with another value
 * is shown by the dialog as an extra `(unsupported)` option so the native
 * select cannot snap to a value the operator did not choose.
 */
export const TRANSPORT_LABELS: Record<string, string> = {
  'streamable-http': 'Streamable HTTP',
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
    kind: 'mcp',
    url: '',
    transport: 'streamable-http',
    test_path: '',
    auth_type: 'none',
    token: '',
    header: DEFAULT_HEADER,
    value: '',
    client_id: '',
    client_secret: '',
    register_client: false,
    enabled: true,
    clear_stored: false,
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
    kind: u.kind,
    url: u.url,
    transport: u.transport,
    test_path: u.test_path ?? '',
    auth_type: u.auth_type,
    token: '',
    header: u.auth_hint?.header ?? '',
    value: '',
    client_id: '',
    client_secret: '',
    register_client: false,
    enabled: u.enabled,
    clear_stored: false,
  }
}

/**
 * The form's credential fields, in the shape the API stores them. Returns `{}`
 * for a blank box, which create and discover depend on: the server stores
 * nothing for an object with no members (PORM-120). A PATCH must not send it
 * (see upstreamPatchBody), because on a row with a credential it would empty
 * the stored value.
 */
export function authConfigFrom(
  form: Pick<UpstreamForm, 'auth_type' | 'token' | 'header' | 'value' | 'client_id' | 'client_secret'>,
): Record<string, string> {
  const auth_config: Record<string, string> = {}
  if (form.auth_type === 'bearer' && form.token) auth_config.token = form.token
  if (headerShaped(form.auth_type) && form.value) {
    auth_config.header = form.header
    auth_config.value = form.value
  }
  // An oauth client goes only when an id was typed: the server refuses a
  // secret alone (clientSecretAlone is what keeps Save disabled until then),
  // and a public client has no secret.
  if (form.auth_type === 'oauth' && form.client_id.trim()) {
    auth_config.client_id = form.client_id.trim()
    if (form.client_secret) auth_config.client_secret = form.client_secret
  }
  return auth_config
}

/**
 * True when the operator typed a credential this dialog can send. For oauth
 * that is a client id; the tokens are never typed.
 */
export function credentialTyped(f: Pick<UpstreamForm, 'auth_type' | 'token' | 'value' | 'client_id'>): boolean {
  if (f.auth_type === 'bearer') return f.token.trim() !== ''
  if (headerShaped(f.auth_type)) return f.value.trim() !== ''
  if (f.auth_type === 'oauth') return f.client_id.trim() !== ''
  return false
}

/**
 * The one invalid shape the client boxes can take: a secret with no id. The
 * dialog never drops a typed value silently, so Save is held with this
 * sentence until the id is entered or the secret removed.
 */
export const CLIENT_SECRET_ALONE = 'Enter the client ID that goes with this secret.'

export function clientSecretAlone(f: Pick<UpstreamForm, 'auth_type' | 'client_id' | 'client_secret'>): boolean {
  return f.auth_type === 'oauth' && f.client_secret !== '' && f.client_id.trim() === ''
}

/**
 * The `POST /upstreams` body, exactly as the Add dialog has always sent it,
 * plus kind (always) and test_path (an http row's, when set: the server
 * refuses one on an mcp row).
 */
export function upstreamCreateBody(f: UpstreamForm, slugTouched: boolean): Record<string, unknown> {
  const body: Record<string, unknown> = {
    name: f.name,
    slug: slugTouched ? f.slug : '',
    description: f.description,
    kind: f.kind,
    url: f.url,
    transport: f.transport,
    auth_type: f.auth_type,
    auth_config: authConfigFrom(f),
    enabled: f.enabled,
  }
  if (f.kind === 'http' && f.test_path.trim() !== '') body.test_path = f.test_path.trim()
  return body
}

/**
 * The `PATCH /upstreams/{id}` body: only the keys whose value differs from the
 * row the dialog was seeded with. An absent key leaves the field unchanged
 * (docs/03-api.md, Partial updates), and the admin event lists exactly the
 * keys sent, so an unchanged field is never sent, with one exception:
 * `auth_type: 'none'` goes for a row already at none when the operator ticked
 * "Remove the stored value", because that is the request that removes the
 * stored bytes (PORM-120). The flag is only ever true for the row the form was
 * seeded from: formFromUpstream seeds it false. `auth_config` goes only when
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
  // kind never goes: the server refuses any change and the dialog has no
  // input for it on Edit. test_path goes when it changed, on an http row
  // only; the server refuses one on an mcp row.
  if (before.kind === 'http' && f.test_path.trim() !== (before.test_path ?? '')) body.test_path = f.test_path.trim()
  if (f.auth_type !== before.auth_type || (f.auth_type === 'none' && f.clear_stored)) body.auth_type = f.auth_type
  if (f.enabled !== before.enabled) body.enabled = f.enabled
  if (credentialTyped(f)) {
    // The header name is trimmed here and not in authConfigFrom, which the
    // create body reproduces byte for byte. A name that is blank after the trim
    // never goes: the proxy would accept it (headersFor gates on != "") and then
    // fail every call on a field name of spaces, with the old ciphertext gone.
    // The input's `pattern` refuses it first; this is the guarantee the test
    // pins if that ever changes.
    const auth_config = authConfigFrom(f)
    if ('header' in auth_config) {
      const header = auth_config.header.trim()
      if (header === '') return body
      auth_config.header = header
    }
    body.auth_config = auth_config
  }
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
  // An oauth upstream has nothing to type: the credential arrives through
  // Connect after the save (PORM-139).
  if (f.auth_type === 'oauth') return false
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
 * A stored `none` never arrives here: with the type unchanged no credential
 * box renders, and with it changed editCredentialDescription answers first.
 */
export function credentialHelp(before: Upstream, f: UpstreamForm): string {
  if (f.auth_type === 'oauth') return oauthDescription(before)
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
  const header = before.auth_hint?.header
  if (header) return `Leave blank to keep the stored credential. It currently sends the ${header} header. A value here replaces it.`
  return 'Leave blank to keep the stored credential. A value here replaces it.'
}

/**
 * Everything the credential box says in the Edit dialog, in priority order.
 * A row that was sending nothing and now has a credential type asks for that
 * credential plainly ("changing the auth type changes what PoryMCP sends"
 * would be misleading there). Any other type change says re-entry is needed
 * and names the new type. A changed header name on a header-shaped type says
 * why the value is needed again. Otherwise blank means keep, per
 * credentialHelp. The first three are exactly the cases credentialRequired
 * marks the box required for.
 */
export function editCredentialDescription(before: Upstream, f: UpstreamForm): string {
  if (f.auth_type === 'oauth' && before.auth_type !== 'oauth') {
    return before.auth_configured
      ? 'Saving removes the stored credential. Connect the upstream after saving.'
      : 'Connect the upstream after saving.'
  }
  if (credentialRequired(before, f)) {
    if (f.auth_type !== before.auth_type) {
      const label = authTypeLabel(f.auth_type)
      return before.auth_type === 'none'
        ? `Enter the credential for ${label}.`
        : `Changing the auth type changes what PoryMCP sends. Enter the credential for ${label} to save.`
    }
    return 'The header name is stored inside the credential. Enter the value again to change the name.'
  }
  return credentialHelp(before, f)
}

/**
 * The sentence under the Auth type select of an oauth row (PORM-139): the
 * state the row is in and what to press. It reads the same status the table
 * badge reads, so the two cannot disagree. The lib formats no date: the
 * expiry is on the row itself.
 */
export function oauthDescription(before: Upstream): string {
  const state = authState(before)
  switch (state.tone) {
    case 'idle':
      return 'Not connected. Press Connect on the upstream\'s row to sign in to the vendor.'
    case 'held':
      return 'The vendor refused to renew the access token, or it lapsed with no refresh token. Press Connect on the upstream\'s row to sign in again.'
    case 'broken':
      return 'The stored token cannot be read with the current encryption key. Restore the key it was saved under, or press Connect to sign in again.'
    default:
      if (state.expiresAt) {
        return 'Connected. The vendor issued no refresh token, so the connection ends at the time shown in the table. Press Connect on the row again after that.'
      }
      return 'Connected. PoryMCP renews the access token before it expires.'
  }
}

/**
 * Whether the URL box's "changes take effect" sentence renders: the URL was
 * edited on a row whose stored credential reads. Never on an oauth row, where
 * a URL change disconnects instead (urlChangeDescription).
 */
export function urlChanged(before: Upstream | undefined, f: Pick<UpstreamForm, 'url'>): boolean {
  return !!before && f.url.trim() !== before.url && before.auth_status === 'ok' && before.auth_type !== 'oauth'
}

/**
 * The sentence under the URL box when the pending save changes where the
 * credential goes. On an oauth row that holds a token set, a new URL removes
 * it: the token was minted for the old address (the server clears it, and
 * records the removal). A row holding only a client ID loses that instead,
 * and says so. Null when nothing changes.
 */
export function urlChangeDescription(before: Upstream | undefined, f: Pick<UpstreamForm, 'url'>): string | null {
  if (!before || f.url.trim() === before.url) return null
  if (before.auth_type === 'oauth') {
    if (!before.auth_configured) return null
    return before.oauth?.expires_at
      ? 'Saving a new URL disconnects this upstream. Connect it again afterwards.'
      : 'Saving a new URL removes the stored client ID. Enter it again if the new address needs it.'
  }
  if (before.auth_status === 'ok') return 'PoryMCP sends the stored credential to the new address from the next request.'
  return null
}

/**
 * The sentence under the Auth type select when the pending save would remove
 * a stored credential: the row holds one (`auth_configured`), its type is not
 * none, and None is selected. Saving then sends `auth_type: 'none'`, which the
 * server answers by emptying the column (PORM-120). Null otherwise: on Add, on
 * a row that holds nothing, and on a row already at none, whose stored bytes
 * are the checkbox's business (clearStoredDescription).
 */
export function removeCredentialDescription(before: Upstream | undefined, f: UpstreamForm): string | null {
  if (before === undefined || before.auth_type === 'none' || !before.auth_configured) return null
  if (f.auth_type !== 'none') return null
  return 'Saving removes the stored credential. It cannot be recovered. Switching back later means entering it again.'
}

/**
 * The description of the "Remove the stored value" checkbox, and the test for
 * rendering it: the row is already none and still holds stored bytes (a
 * credential switched to None by an earlier build, the sealed `{}` earlier
 * builds wrote for a blank box, or a credential a client sent alone to a none
 * row; the server cannot tell which), and None is
 * still selected. The checkbox renders on the same `f.auth_type === 'none'`
 * test upstreamPatchBody reads for clear_stored, so a ticked box is on screen
 * whenever it can change the request; if the two ever diverge, a ticked box
 * could remove data with no control visible. Null otherwise, and the checkbox
 * is not rendered.
 */
export function clearStoredDescription(before: Upstream | undefined, f: UpstreamForm): string | null {
  if (before === undefined || before.auth_type !== 'none' || !before.auth_configured) return null
  if (f.auth_type !== 'none') return null
  return 'A value is still stored for this upstream and is not sent, because the auth type is None. Saving with this ticked removes it.'
}
