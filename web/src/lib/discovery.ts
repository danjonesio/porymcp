import { ApiError } from './api.ts'

/** Mirrors models.ToolSeparator (internal/models/toolidentity.go). */
export const TOOL_SEPARATOR = '__'

/**
 * The identity a group endpoint advertises for one of this upstream's tools, and
 * the form a group tool_filter allow rule has to be written in. Mirrors
 * models.ToolIdentity.Canonical: slug, two underscores, then the tool's own name,
 * which ParseCanonical splits on the first separator, so a tool called `a__b`
 * keeps its own underscores. An empty slug yields an empty string, and the caller
 * shows only the published name.
 */
export function scopedToolName(slug: string, name: string): string {
  if (!slug) return ''
  return slug + TOOL_SEPARATOR + name
}

/**
 * True when a URL is one discovery can be pointed at: absolute, http or https.
 * Discover is not a submit, so the form's `required` and `type="url"` never run
 * for it: without this a press on `githu` spends a rate-limit token on a call
 * that cannot work.
 */
export function discoverable(url: string): boolean {
  try {
    const u = new URL(url.trim())
    return u.protocol === 'http:' || u.protocol === 'https:'
  } catch {
    return false
  }
}

/**
 * The host for the "Connecting to …" line. URL.host never includes userinfo, so a
 * URL of the form https://user:secret@host/mcp cannot leak its credential into the
 * dashboard, the same rule the API applies to its own error strings. Pinned by a
 * test so nobody replaces this with a regex.
 */
export function hostOf(url: string): string {
  try {
    return new URL(url.trim()).host
  } catch {
    return ''
  }
}

/** Hosts where plain http keeps the credential inside the machine. */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])

/**
 * The one sentence shown when plainHTTPCredential is true: under a discovery
 * result in the Add dialog, and under the URL field in the Edit dialog, where
 * no discovery runs.
 */
export const PLAIN_HTTP_NOTE = 'This upstream uses plain http, so the credential travels unencrypted.'

/**
 * True when discovering this upstream puts a real credential on the wire in the
 * clear. Loopback is exempt: the request never leaves the machine, and PoryMCP is
 * routinely run at http://localhost:8080.
 */
export function plainHTTPCredential(url: string, authType: string): boolean {
  if (!authType || authType === 'none') return false
  try {
    const u = new URL(url.trim())
    return u.protocol === 'http:' && !LOOPBACK.has(u.hostname === '::1' ? '[::1]' : u.hostname)
  } catch {
    return false
  }
}

/**
 * One sentence for a request that never produced a Discovery. An upstream that
 * answers badly is not this function's business: that arrives as `ok: false`
 * with the server's own sentence in `error`.
 */
export function discoveryErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 429) {
      const n = err.retryAfterSeconds
      if (n === undefined) return 'Too many discovery requests. Try again shortly.'
      return `Too many discovery requests. Try again in ${n} ${n === 1 ? 'second' : 'seconds'}.`
    }
    // No redirect to the login page: the other four pages would not do it either,
    // and a redirect on one of five is worse than none (PORM-31).
    if (err.status === 401) return 'This browser session is no longer signed in. Reload the page to sign in again.'
    return err.message
  }
  return 'Could not reach PoryMCP. Check that the server is still running.'
}
