import { ApiError, type OAuthRevokeResult } from './api.ts'
import { discoveryErrorMessage } from './discovery.ts'

/**
 * One sentence for a Connect press that never produced an authorization URL
 * (PORM-139). 404: the row went away; the page reloads the list, so there is
 * no dialog to close. A 400 or a 502 is the server's own fixed sentence
 * (PUBLIC_URL, the auth type, the authorization server). Everything else is
 * the house mapper's: the 429 of the discovery budget the start route shares,
 * the 401 sentence, the network sentence.
 */
export function connectErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return 'This upstream no longer exists. The list has been reloaded.'
    if (err.status === 400 || err.status === 502) return err.message
  }
  return discoveryErrorMessage(err)
}

/**
 * What the revoke route would remove from a row, which decides every word
 * around the Disconnect button: a token set (connected), a supplied client
 * with no token (client), or a value PoryMCP cannot read under the current
 * key (unreadable), where nothing can be sent to the vendor. A row with
 * nothing stored has no kind and the button is disabled.
 */
export type RevokeKind = 'connected' | 'client' | 'unreadable'

export function revokeKind(u: {
  auth_type?: string
  auth_status?: string
  auth_configured?: boolean
  oauth?: { expires_at: string | null }
}): RevokeKind | null {
  if (u.auth_type !== 'oauth' || !u.auth_configured) return null
  if (u.auth_status === 'undecryptable') return 'unreadable'
  return u.oauth?.expires_at ? 'connected' : 'client'
}

export const REVOKE_COPY: Record<
  RevokeKind,
  { button: string; caption: string; title: string; description: (name: string, supplied: boolean) => string; confirm: string }
> = {
  connected: {
    button: 'Disconnect',
    caption:
      'Asks the vendor to revoke the token, then removes it from PoryMCP. Calls through this upstream fail until it is connected again.',
    title: 'Disconnect this upstream?',
    description: (name, supplied) =>
      `${name} stops sending a token. PoryMCP asks the vendor to revoke it, then removes it. Calls through this upstream fail until it is connected again.` +
      (supplied ? ' The client ID and secret you entered are removed too.' : ''),
    confirm: 'Disconnect',
  },
  client: {
    button: 'Remove client ID',
    caption: 'Removes the client ID and secret stored for this upstream.',
    title: 'Remove the stored client ID?',
    description: (name) => `${name} forgets the client ID and secret you entered. Connect then uses the vendor’s own registration.`,
    confirm: 'Remove',
  },
  unreadable: {
    button: 'Remove the stored value',
    caption: 'Removes the value PoryMCP cannot read under the current key. The vendor is not asked to revoke anything.',
    title: 'Remove the stored value?',
    description: (name) =>
      `${name} forgets the stored value, which PoryMCP cannot read under the current key. The vendor is not asked to revoke it, so any token in it stays valid there until it expires. Connect afterwards to sign in again.`,
    confirm: 'Remove',
  },
}

/**
 * The line under the Disconnect button after the answer. `kind` is what the
 * row held when the button was pressed: a client-only row reads as a removed
 * client, an unreadable one as a removed value, never as a revoked token.
 */
export function revokeResultLine(result: Pick<OAuthRevokeResult, 'vendor_revocation'>, kind: RevokeKind): string {
  if (kind === 'unreadable') return 'Removed the stored value. Connect to sign in again.'
  if (kind === 'client' || result.vendor_revocation === 'no_token') return 'Removed the stored client ID.'
  switch (result.vendor_revocation) {
    case 'revoked':
      return 'Disconnected. The vendor revoked the token.'
    case 'failed':
      return "Disconnected. The vendor did not confirm the revocation. Remove PoryMCP's access in the vendor's account settings."
    case 'not_offered':
      return 'Disconnected. This vendor offers no way to revoke the token, so it stays valid there until it expires.'
    default:
      return 'Disconnected.'
  }
}

/**
 * The per-row "register PoryMCP with the vendor" choice, kept in session
 * storage so it survives the round trip to the vendor and back: the choice
 * is ticked in the Edit dialog, the row's Connect reads it, and the page is
 * a fresh load when the callback brings the operator back. Session storage
 * is per tab, like the admin key, and may be absent or refuse; both read as
 * no choice.
 */
export const REGISTER_CHOICE_KEY = 'porymcp.oauthRegister'

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>

export function loadRegisterChoices(storage: StorageLike | undefined): Record<string, boolean> {
  try {
    const raw = storage?.getItem(REGISTER_CHOICE_KEY)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    const out: Record<string, boolean> = {}
    for (const [id, v] of Object.entries(parsed)) if (v === true) out[id] = true
    return out
  } catch {
    return {}
  }
}

export function saveRegisterChoices(storage: StorageLike | undefined, choices: Record<string, boolean>): void {
  try {
    const kept: Record<string, boolean> = {}
    for (const [id, v] of Object.entries(choices)) if (v) kept[id] = true
    storage?.setItem(REGISTER_CHOICE_KEY, JSON.stringify(kept))
  } catch {
    // Storage refused (private window, quota): the choice lives for this page only.
  }
}

/**
 * Defence in depth before the page navigates to the authorization URL the
 * server answered: only an http or https URL is ever assigned to
 * window.location.
 */
export function authorizationURLIsWeb(url: string): boolean {
  try {
    const u = new URL(url)
    return u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    return false
  }
}
