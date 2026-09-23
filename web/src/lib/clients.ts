export type ClientKind = 'claude-code' | 'cursor' | 'codex' | 'opencode' | 'gemini' | 'curl'

/**
 * One endpoint as a client config sees it: a display/config name and the URL
 * it speaks to. kind is `mcp` (the default when absent) or `http` (PORM-146):
 * an http entry is an API base URL a plain HTTP client is pointed at, and only
 * the curl snippet prints it; the MCP client snippets leave it out. testPath is
 * the upstream's test path, which the curl example requests.
 */
export type SnippetServer = { name: string; url: string; kind?: 'mcp' | 'http'; testPath?: string }

/** The one sentence under a curl snippet that carries an HTTP API endpoint. */
export const HTTP_CURL_HINT =
  'Replace the path after /api/ with any path the API serves. An SDK takes this endpoint as its base URL and the key as its API key. Send the key as a bearer token or in X-Api-Key.'

function isHTTP(s: SnippetServer): boolean {
  return s.kind === 'http'
}

export const clientLabels: Record<ClientKind, string> = {
  'claude-code': 'Claude Code',
  cursor: 'Cursor',
  codex: 'Codex',
  opencode: 'OpenCode',
  gemini: 'Gemini CLI',
  curl: 'curl',
}

export function slugName(name: string) {
  const s = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
  return s || 'porymcp'
}

/**
 * TOML table keys for the Codex snippet. A `-` is rewritten to `_` to match
 * `docs/09-clients.md`, but `github-mcp` and `github_mcp` are both legal
 * upstream slugs and would collide into one `[mcp_servers.github_mcp]` table,
 * a duplicate-key error that fails the whole config.toml. Suffix the
 * collisions so every table header stays distinct. The suffix is bumped until
 * the key is one nothing has already taken, rather than counted per base: a
 * count would let a suffixed key collide with a later literal one, so
 * `github-mcp`, `github_mcp`, `github_mcp_2` become `github_mcp`,
 * `github_mcp_2`, `github_mcp_2_2`.
 */
function tomlKeys(servers: SnippetServer[]): string[] {
  const used = new Set<string>()
  return servers.map((s) => {
    const base = s.name.replace(/-/g, '_')
    let key = base
    for (let n = 2; used.has(key); n++) key = `${base}_${n}`
    used.add(key)
    return key
  })
}

/**
 * Install snippet for one client over N servers. A virtual key with a group
 * target has one server per enabled member; every other case is a single
 * server, whose output is byte-identical to the one-server snippet we have
 * always emitted. Names are used verbatim: the caller decides whether a
 * server is named after its upstream slug or after the virtual key.
 */
export function clientSnippet(kind: ClientKind, all: SnippetServer[], apiKey: string): string {
  // The MCP client configs take the MCP entries only; curl prints both, MCP
  // first. This is the one place the split happens.
  const servers = all.filter((s) => !isHTTP(s))
  const apis = all.filter(isHTTP)
  if (kind !== 'curl' && servers.length === 0) return ''
  if (kind === 'curl' && all.length === 0) return ''
  const auth = `Authorization: Bearer ${apiKey}`
  switch (kind) {
    case 'claude-code':
      return servers
        .map((s) => `claude mcp add --transport http ${s.name} ${s.url} --header "${auth}"`)
        .join('\n')
    case 'cursor':
      return JSON.stringify(
        {
          mcpServers: Object.fromEntries(
            servers.map((s) => [
              s.name,
              {
                url: s.url,
                headers: { Authorization: `Bearer ${apiKey}` },
              },
            ]),
          ),
        },
        null,
        2,
      )
    case 'codex': {
      const keys = tomlKeys(servers)
      const tables = servers.map((s, i) =>
        [`[mcp_servers.${keys[i]}]`, `url = "${s.url}"`, `bearer_token_env_var = "PORYMCP_KEY"`].join('\n'),
      )
      // The key goes in the environment, never in the file: a snippet whose
      // first line names config.toml invites pasting the whole thing into it,
      // which is exactly what bearer_token_env_var exists to avoid.
      return [
        '# In the shell that launches Codex:',
        `export PORYMCP_KEY='${apiKey}'`,
        '',
        '# ~/.codex/config.toml',
        tables.join('\n\n'),
      ].join('\n')
    }
    case 'opencode':
      return JSON.stringify(
        {
          $schema: 'https://opencode.ai/config.json',
          mcp: Object.fromEntries(
            servers.map((s) => [
              s.name,
              {
                type: 'remote',
                url: s.url,
                oauth: false,
                headers: { Authorization: `Bearer ${apiKey}` },
              },
            ]),
          ),
        },
        null,
        2,
      )
    case 'gemini':
      return JSON.stringify(
        {
          mcpServers: Object.fromEntries(
            servers.map((s) => [
              s.name,
              {
                httpUrl: s.url,
                headers: { Authorization: `Bearer ${apiKey}` },
              },
            ]),
          ),
        },
        null,
        2,
      )
    case 'curl': {
      // One command is unambiguous on its own; N need a label to tell apart.
      const labelled = all.length > 1
      const mcp = servers.map((s) =>
        [
          ...(labelled ? [`# ${s.name}`] : []),
          `curl -sS -X POST ${s.url} \\`,
          `  -H "${auth}" \\`,
          `  -H "Content-Type: application/json" \\`,
          `  -H "Accept: application/json, text/event-stream" \\`,
          `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`,
        ].join('\n'),
      )
      // The URL is single-quoted: a test path may hold a character the shell
      // reads (; $ & *), and the endpoint is pasted into a terminal.
      const http = apis.map((s) =>
        [
          ...(labelled ? [`# ${s.name}`] : []),
          `curl -sS '${s.url}${(s.testPath ?? '').replace(/^\//, '')}' \\`,
          `  -H "${auth}"`,
        ].join('\n'),
      )
      return [...mcp, ...http].join('\n\n')
    }
  }
}

/**
 * The sentence under the snippet. shape says which endpoint kinds the snippet
 * carries, for curl, whose sentence differs for an HTTP API: a mixed key
 * reads both, MCP first.
 */
export function clientHint(kind: ClientKind, shape: { mcp?: boolean; http?: boolean } = { mcp: true }): string {
  if (kind === 'curl') {
    const parts: string[] = []
    if (shape.mcp ?? !shape.http) parts.push('Sanity-check the proxy before wiring a client.')
    if (shape.http) parts.push(HTTP_CURL_HINT)
    return parts.join(' ')
  }
  switch (kind) {
    case 'claude-code':
      return 'Run in a terminal, then /mcp inside Claude Code. Add -s user for every project.'
    case 'cursor':
      return 'Merge into .cursor/mcp.json in the project (or your Cursor user MCP config), then reload MCP.'
    case 'codex':
      return 'Add to ~/.codex/config.toml and export PORYMCP_KEY in the shell that launches Codex.'
    case 'opencode':
      return 'Merge into opencode.json. oauth must be false so OpenCode does not start an OAuth flow.'
    case 'gemini':
      return 'Merge into Gemini CLI settings.json (mcpServers).'
    default:
      return ''
  }
}
