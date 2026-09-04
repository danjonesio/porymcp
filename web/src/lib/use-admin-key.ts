import { useSyncExternalStore } from 'react'
import { getAdminKey } from '@/lib/api'

// The key changes only when the sign-in page writes it and navigates, or when
// sign-out clears it and navigates, so a subscription that registers nothing
// is correct. It is declared once at module scope so React keeps one
// subscription per mount. The server snapshot is null because sessionStorage
// does not exist during the static export; that keeps the prerendered HTML
// and the first client render identical, and the client re-renders once it
// has hydrated.
const subscribeNothing = () => () => {}

const serverSnapshot = () => null

export function useAdminKey(): string | null {
  return useSyncExternalStore(subscribeNothing, getAdminKey, serverSnapshot)
}
