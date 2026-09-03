/** Which of the three things the Auth cell says beside the auth type. */
export type AuthTone = 'ok' | 'none' | 'broken'

/**
 * One rendered cell suffix: `ok` shows the usual "· set", `none` shows nothing,
 * `broken` shows a badge whose label says what is wrong.
 */
export type AuthState = { tone: AuthTone; label: string }

/**
 * The one rule behind the Auth cell (PORM-52). `auth_status` is the server's
 * verdict on the stored credential (see `Upstream` in api.ts). Two values are
 * broken and get a badge: `undecryptable` (ENCRYPTION_KEY changed; the fix is a
 * key) reads "Unreadable", `unreadable` (nothing stored, or nothing the auth
 * type can send; the fix is the credential) reads "Incomplete". Anything this
 * helper does not know renders as `ok` with no badge rather than red: a value a
 * future server adds must not paint every row as broken.
 */
export function authState(u: { auth_status: string }): AuthState {
  switch (u.auth_status) {
    case 'undecryptable':
      return { tone: 'broken', label: 'Unreadable' }
    case 'unreadable':
      return { tone: 'broken', label: 'Incomplete' }
    case 'none':
      return { tone: 'none', label: '' }
    default:
      return { tone: 'ok', label: '' }
  }
}
