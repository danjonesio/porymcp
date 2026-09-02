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
  url: string
  transport: string
  auth_type: string
  enabled: boolean
  /** A credential blob is stored — whatever it holds. */
  auth_configured: boolean
  /**
   * Whether PoryMCP can use the stored credential (PORM-52), always present.
   * `none` iff `auth_type` is none; `ok`; `undecryptable` — no configured key
   * opens the blob, ENCRYPTION_KEY changed; `unreadable` — nothing stored, or
   * nothing the auth type can send (a blank token). Typed as a string like every
   * other server enum here; `authState()` in upstream-auth.ts decides what the
   * table shows, and renders nothing for a value it does not know.
   */
  auth_status: string
  // Required and nullable, not the `field?: string` this file uses elsewhere: the
  // Status cell is three-state, so "never tested" has to arrive as an explicit
  // null rather than as a missing key, and an Upstream is only ever produced by
  // an api<…>() call — nothing here writes one as an object literal.
  /** null until the first Tools/Refresh press. Written together with last_test_ok; reset by a connection edit. */
  last_test_at: string | null
  last_test_ok: boolean | null
  created_at: string
  updated_at: string
}

/**
 * Hints an MCP server may publish beside a tool. A fixed set of fields, not open
 * JSON, so an upstream cannot decide what arrives here. Nothing renders them yet
 * — PORM-95 adds the hint chips.
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
  /** Always present: the server sends it on a failed discovery too. */
  latency_ms: number
  protocol_version?: string
  server_info?: { name: string; version?: string }
  /** The upstream's stored slug. Absent on the unsaved-payload route. */
  slug?: string
  tool_count: number
  tools: DiscoveredTool[]
  /** True when the upstream offered more tools than this call returns. */
  truncated: boolean
  /** Tools whose names a group endpoint cannot hold a caller to — counted, never named. */
  unnameable_tools: number
  /** Why the upstream did not answer: a closed set of sentences, printed verbatim. */
  error?: string
  /** The upstream's own JSON-RPC error message, sanitised and bounded. */
  upstream_message?: string
}

/** The unsaved-payload body: what `POST /upstreams` accepts, minus what persistence needs. */
export type DiscoverPayload = {
  name?: string
  url: string
  transport?: string
  auth_type?: string
  auth_config?: Record<string, string>
}

/** Discover a saved upstream, using its stored credential. The result is recorded on the row as its last test. */
export function discoverUpstream(id: string): Promise<Discovery> {
  // body: '{}' follows rotate/revoke — api() only sets Content-Type when there is a body.
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
  /** Upstreams whose stored credential is empty or unusable for its auth type — never a key problem. */
  unreadable_upstreams: number
  /** Upstreams still sealed under a previous key: a rotation `porymcp rekey` has not finished. */
  upstreams_under_previous_key: number
}
