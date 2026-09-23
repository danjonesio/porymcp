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
 * The line under the Disconnect button after the answer. `connected` is
 * whether the row held a token set when the button was pressed: a client-only
 * row reads as a removed client, not a revoked token.
 */
export function revokeResultLine(result: Pick<OAuthRevokeResult, 'vendor_revocation'>, connected: boolean): string {
  if (!connected || result.vendor_revocation === 'no_token') return 'Removed the stored client ID.'
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
