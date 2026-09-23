const base = process.env.NEXT_PUBLIC_API_URL ?? ''

export class ApiError extends Error {
  status: number
  /** Seconds from the response's `Retry-After`, when the server sent a usable one. */
  retryAfterSeconds?: number
  constructor(status: number, message: string, retryAfterSeconds?: number) {
    super(message)
    this.status = status
    this.retryAfterSeconds = retryAfterSeconds
  }
}

/**
 * Seconds from a `Retry-After` header. PoryMCP sends delta-seconds
 * (internal/api/helpers.go's tooManyRequests writes strconv.Itoa of a whole
 * number); the HTTP-date form is accepted too, so a proxy that rewrites the
 * header cannot make the dashboard say "try again in NaN seconds". Anything else
 * yields undefined, and the caller falls back to copy that names no number.
 *
 * A parseable header is floored at one second, exactly as tooManyRequests floors
 * what it sends: "Try again in 0 seconds." is an invitation to retry now, which
 * is the one thing a budget exists to prevent, and a date already in the past is
 * the ordinary way to arrive at it.
 */
export function retryAfterSeconds(header: string | null): number | undefined {
  if (!header) return undefined
  const value = header.trim()
  if (/^\d+$/.test(value)) return Math.max(1, Number(value))
  // Every HTTP-date form carries whitespace; without it Date.parse still guesses
  // (it reads "-1" as a year) and the dashboard would name a wait nobody sent.
  if (!/\s/.test(value)) return undefined
  const when = Date.parse(value)
  if (Number.isNaN(when)) return undefined
  return Math.max(1, Math.ceil((when - Date.now()) / 1000))
}

export function getAdminKey(): string | null {
  if (typeof window === 'undefined') return null
  return sessionStorage.getItem('porymcp.adminKey')
}

export function setAdminKey(key: string) {
  sessionStorage.setItem('porymcp.adminKey', key)
}

export function clearAdminKey() {
  sessionStorage.removeItem('porymcp.adminKey')
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const key = getAdminKey()
  const headers = new Headers(init.headers)
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json')
  }
  if (key) headers.set('Authorization', `Bearer ${key}`)
  const res = await fetch(`${base}/api/v1${path}`, { ...init, headers })
  if (res.status === 204) return undefined as T
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    throw new ApiError(res.status, data?.error || res.statusText, retryAfterSeconds(res.headers.get('Retry-After')))
  }
  return data as T
}

export type Upstream = {
  id: string
  name: string
  slug: string
  description?: string
  /**
   * `mcp` or `http` (PORM-146), always present and fixed at create: an MCP
   * server reached through the /mcp doors, or an HTTP API relayed through
   * the /api/ doors. Typed as a string like every other server enum here.
   */
  kind: string
  url: string
  transport: string
  /** The path the connection test requests on an HTTP API upstream; absent or "" means the base URL. */
  test_path?: string
  auth_type: string
  enabled: boolean
  /** A credential blob is stored, whatever it holds. */
  auth_configured: boolean
  /**
   * Whether PoryMCP can use the stored credential (PORM-52), always present.
   * `none` iff `auth_type` is none; `ok`; `undecryptable`: no configured key
   * opens the blob, ENCRYPTION_KEY changed; `unreadable`: nothing stored, or
   * nothing the auth type can send (a blank token). Typed as a string like every
   * other server enum here; `authState()` in upstream-auth.ts decides what the
   * table shows, and renders nothing for a value it does not know.
   */
  auth_status: string
  /**
   * The header name the stored credential sends, and only the name
   * (internal/api/upstreams.go presentUpstream). Present only when the blob
   * decrypts and the auth type carries a header, so absent for bearer, for
   * none, and for every undecryptable or unreadable row. Typed as this one
   * key so nothing widens the one field that carries decrypted material to
   * the browser.
   */
  auth_hint?: { header?: string }
  /**
   * Present on an oauth row whose stored blob is absent or opens (PORM-139).
   * `expires_at` null means not connected. Never a token, a secret, an
   * issuer URL, a scope or an endpoint. `client_source` is document,
   * registered or supplied, or null before any client is known.
   */
  oauth?: UpstreamOAuth
  // Required and nullable, not the `field?: string` this file uses elsewhere: the
  // Status cell is three-state, so "never tested" has to arrive as an explicit
  // null rather than as a missing key, and an Upstream is only ever produced by
  // an api<…>() call: nothing here writes one as an object literal.
  /** null until the first Tools/Refresh press. Written together with last_test_ok; reset by a connection edit. */
  last_test_at: string | null
  last_test_ok: boolean | null
  created_at: string
  updated_at: string
}

/**
 * Hints an MCP server may publish beside a tool. A fixed set of fields, not open
 * JSON, so an upstream cannot decide what arrives here. Nothing renders them yet
 * PORM-95 adds the hint chips.
 */
export type ToolAnnotations = {
  title?: string
  readOnlyHint?: boolean
  destructiveHint?: boolean
  idempotentHint?: boolean
  openWorldHint?: boolean
}

/** One tool as an upstream's `tools/list` reports it. Every string here is upstream-controlled text. */
export type DiscoveredTool = {
  name: string
  title?: string
  description?: string
  /** Present only when the server's description was longer than discovery will carry. */
  description_truncated?: boolean
  /** The group-endpoint identity, `{slug}__{name}`. Saved route only. */
  scoped_name?: string
  annotations?: ToolAnnotations
}

/**
 * The result of one admin-side `tools/list` against an upstream. `ok` describes the
 * upstream; the HTTP status described the request. It never carries the credential,
 * `auth_config`, or the upstream's own response bytes.
 */
export type Discovery = {
  ok: boolean
  /** The upstream's kind the run was for, `mcp` or `http`, on every path including a refusal before any request. */
  kind: string
  /** The status an HTTP API answered the probe with (PORM-146); absent on an MCP run and when nothing answered. */
  http_status?: number
  /** Always present: the server sends it on a failed discovery too. */
  latency_ms: number
  protocol_version?: string
  /**
   * Which MCP era the upstream spoke: `modern` is the stateless 2026-07-28
   * revision, `legacy` the initialize handshake. Absent when nothing answered,
   * and on a response from a PoryMCP that predates the field.
   */
  era?: 'modern' | 'legacy'
  /** The versions the upstream said it supports. At most 8. Upstream-controlled text. */
  supported_versions?: string[]
  /** The names of what the upstream advertised. At most 16. Upstream-controlled text. */
  capabilities?: string[]
  server_info?: { name: string; version?: string }
  /** The upstream's stored slug. Absent on the unsaved-payload route. */
  slug?: string
  tool_count: number
  tools: DiscoveredTool[]
  /** True when the upstream offered more tools than this call returns. */
  truncated: boolean
  /** Tools whose names a group endpoint cannot hold a caller to: counted, never named. */
  unnameable_tools: number
  /** Why the upstream did not answer: a closed set of sentences, printed verbatim. */
  error?: string
  /** The upstream's own JSON-RPC error message, sanitised and bounded. */
  upstream_message?: string
}

/** The unsaved-payload body: what `POST /upstreams` accepts, minus what persistence needs. */
export type DiscoverPayload = {
  name?: string
  kind?: string
  url: string
  transport?: string
  test_path?: string
  auth_type?: string
  auth_config?: Record<string, string>
}

/** Discover a saved upstream, using its stored credential. The result is recorded on the row as its last test. */
export function discoverUpstream(id: string): Promise<Discovery> {
  // body: '{}' follows rotate/revoke: api() only sets Content-Type when there is a body.
  return api<Discovery>(`/upstreams/${id}/discover`, { method: 'POST', body: '{}' })
}

/** Discover an upstream that has not been created yet. Nothing is persisted. */
export function discoverUpstreamPayload(body: DiscoverPayload): Promise<Discovery> {
  return api<Discovery>('/upstreams/discover', { method: 'POST', body: JSON.stringify(body) })
}

export type Group = {
  id: string
  name: string
  description?: string
  upstream_ids: string[]
  tool_filter?: unknown
  created_at: string
  updated_at: string
}

/** One URL that speaks to exactly one upstream, 1:1. */
export type Endpoint = {
  upstream_id: string
  slug: string
  name: string
  /** `mcp` (the URL ends in /mcp and takes an MCP client) or `http` (it ends in /api/ and takes a plain HTTP client). */
  kind: string
  url: string
}

export type VirtualKey = {
  id: string
  name: string
  key_prefix: string
  target_type: string
  target_id: string
  rate_limit?: number
  expires_at?: string
  status: string
  last_used_at?: string
  created_at: string
  api_key?: string
  proxy_url?: string
  /** Absent when empty: the server omits an empty list, so absent and [] are the same rule. */
  tool_allowlist?: string[]
  /** Absent when empty, like tool_allowlist. The deny list is checked first. */
  tool_denylist?: string[]
  /**
   * True when one of this key's stored lists could not be decoded. That list is
   * then absent, which looks like a key with no such rule, while the proxy
   * refuses every call on it. A PATCH must send both lists to replace them. Response only.
   */
  lists_malformed?: boolean
  /**
   * The verbs the key may relay through an /api/ door (PORM-146), always
   * present: [] means every one of the six. Ignored on the /mcp doors.
   */
  http_methods: string[]
  /**
   * True when the stored http_methods could not be read. The relay door then
   * refuses every request on the key; a PATCH that carries http_methods
   * replaces the column. Response only.
   */
  http_methods_malformed?: boolean
  /** Enabled members only, always an array. A single-upstream key has one entry mirroring proxy_url. */
  endpoints: Endpoint[]
}

export type AuditLog = {
  id: string
  timestamp: string
  virtual_key_id: string
  virtual_key_name: string
  method: string
  tool_name?: string
  params?: unknown
  status: string
  latency_ms: number
  response_size_bytes?: number
  upstream_id?: string
  error_message?: string
  request_id: string
}

/**
 * The closed detail object of an admin event. A fixed set of keys, not open
 * JSON, so the server decides what arrives here: field names, an auth type, a
 * changed flag, a key prefix, a target and a member count. Never a credential,
 * a ciphertext or a plaintext key. Read field by field; the one place that
 * iterates it is changedText in admin-event.ts.
 */
export type AdminEventDetails = {
  fields?: string[]
  cleared?: string[]
  slug?: string
  /** The upstream's kind on a create (PORM-146). */
  kind?: string
  auth_type?: string
  auth_changed?: boolean
  upstream_count?: number
  tool_filter_set?: boolean
  target_type?: string
  target_id?: string
  key_prefix?: string
  /** The OAuth connect and disconnect events (PORM-139). */
  client?: string
  refresh_token?: boolean
  issuer?: string
  vendor_revocation?: string
}

export type UpstreamOAuth = {
  expires_at: string | null
  has_refresh_token: boolean
  client_source: string | null
}

/** What POST /upstreams/{id}/oauth/start answers: the URL the browser is sent to. */
export type OAuthStart = {
  authorization_url: string
  expires_in: number
  issuer: string
  client: string
}

/** What POST /upstreams/{id}/oauth/revoke answers: the row after the clear, and what the vendor said. */
export type OAuthRevokeResult = {
  upstream: Upstream
  vendor_revocation: 'revoked' | 'failed' | 'not_offered' | 'no_token' | string
}

/** The Client ID Metadata Document, served without a key; the dashboard reads the redirect URI from it. */
export type OAuthClientMetadata = {
  client_id: string
  redirect_uris: string[]
}

/**
 * Start a sign-in for an oauth upstream. `client: 'registered'` forces
 * dynamic registration where the vendor cannot fetch this PoryMCP's client
 * document. body: '{}' follows discover: api() only sets Content-Type when
 * there is a body.
 */
export function oauthStart(id: string, body?: { client?: 'document' | 'registered' }): Promise<OAuthStart> {
  return api<OAuthStart>(`/upstreams/${id}/oauth/start`, { method: 'POST', body: JSON.stringify(body ?? {}) })
}

/** Disconnect an oauth upstream: the vendor is asked to revoke, then the stored value is removed. */
export function oauthRevoke(id: string): Promise<OAuthRevokeResult> {
  return api<OAuthRevokeResult>(`/upstreams/${id}/oauth/revoke`, { method: 'POST', body: '{}' })
}

export function oauthClientMetadata(): Promise<OAuthClientMetadata> {
  return api<OAuthClientMetadata>('/oauth/client-metadata')
}

/** One successful management-plane change, as GET /api/v1/admin-events returns it. Every key is always present. */
export type AdminEvent = {
  id: string
  timestamp: string
  actor: string
  action: string
  resource_type: string
  resource_id: string
  resource_name: string
  details: AdminEventDetails
  request_id: string
  remote_addr: string
}

export type Stats = {
  active_virtual_keys: number
  total_virtual_keys: number
  upstreams: number
  groups: number
  calls_today: number
  errors_today: number
  error_rate: number
  calls_last_7_days: number
  blocked_today: number
  /** Upstreams whose stored credential no configured ENCRYPTION_KEY opens (PORM-52). Drives the Overview banner. */
  undecryptable_upstreams: number
  /** Upstreams whose stored credential is empty or unusable for its auth type, never a key problem. */
  unreadable_upstreams: number
  /** Upstreams still sealed under a previous key: a rotation `porymcp rekey` has not finished. */
  upstreams_under_previous_key: number
}
