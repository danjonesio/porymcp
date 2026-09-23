import type { UpstreamOAuth } from './api.ts'

/**
 * Which of the five things the Auth cell says beside the auth type. `held`
 * and `idle` are PORM-139's: an amber Expired badge, and plain "Not
 * connected" text.
 */
export type AuthTone = 'ok' | 'none' | 'broken' | 'held' | 'idle'

/**
 * One rendered cell suffix: `ok` shows "· set" (or "· set until <time>" when
 * `expiresAt` is set), `none` shows nothing, `broken` shows a pink badge whose
 * label says what is wrong, `held` an amber badge, `idle` the label as plain
 * text. The lib does no date formatting: the page renders `expiresAt` as a
 * <time> element, so these rules stay clock-free.
 */
export type AuthState = { tone: AuthTone; label: string; expiresAt: string | null }

/**
 * The one rule behind the Auth cell (PORM-52, PORM-139). `auth_status` is the
 * server's verdict on the stored credential (see `Upstream` in api.ts). Two
 * values are broken and get a pink badge: `undecryptable` (ENCRYPTION_KEY
 * changed; the fix is a key) reads "Unreadable", `unreadable` (nothing
 * stored, or nothing the auth type can send; the fix is the credential) reads
 * "Incomplete", except on an oauth row, where it reads "Not connected" as
 * plain text: the fix is Connect, and nothing is wrong with the setup.
 * `expired` (an oauth token lapsed with no refresh token, or the vendor
 * refused to renew it) gets the amber badge the badge rule reserves for
 * "held or expired", as expired virtual keys do; the fix is Connect again. An
 * oauth row that is `ok` with no refresh token reads "set until" its expiry.
 * Anything this helper does not know renders as `ok` with no badge rather
 * than red: a value a future server adds must not paint every row as broken.
 */
export function authState(u: { auth_type?: string; auth_status: string; oauth?: UpstreamOAuth }): AuthState {
  const oauth = u.auth_type === 'oauth'
  switch (u.auth_status) {
    case 'undecryptable':
      return { tone: 'broken', label: 'Unreadable', expiresAt: null }
    case 'unreadable':
      if (oauth) return { tone: 'idle', label: 'Not connected', expiresAt: null }
      return { tone: 'broken', label: 'Incomplete', expiresAt: null }
    case 'expired':
      return { tone: 'held', label: 'Expired', expiresAt: null }
    case 'none':
      return { tone: 'none', label: '', expiresAt: null }
    default:
      if (oauth && u.oauth && !u.oauth.has_refresh_token && u.oauth.expires_at) {
        return { tone: 'ok', label: 'set until', expiresAt: u.oauth.expires_at }
      }
      return { tone: 'ok', label: '', expiresAt: null }
  }
}

/** The Connect row action's label: Reconnect once a token set is stored. */
export function connectLabel(u: { oauth?: UpstreamOAuth }): 'Connect' | 'Reconnect' {
  return u.oauth?.expires_at ? 'Reconnect' : 'Connect'
}

/** True when the oauth row holds a token set, the state Disconnect asks the vendor about. */
export function oauthConnected(u: { auth_type?: string; oauth?: UpstreamOAuth }): boolean {
  return u.auth_type === 'oauth' && !!u.oauth?.expires_at
}
