export type ClientKind = 'claude-code' | 'cursor' | 'codex' | 'opencode' | 'gemini' | 'curl'

/** One MCP server as a client config sees it: a display/config name and the URL it speaks to. */
export type SnippetServer = { name: string; url: string }

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
 * upstream slugs and would collide into one `[mcp_servers.github_mcp]` table —
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
 * always emitted. Names are used verbatim — the caller decides whether a
 * server is named after its upstream slug or after the virtual key.
 */
export function clientSnippet(kind: ClientKind, servers: SnippetServer[], apiKey: string): string {
  if (servers.length === 0) return ''
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
    case 'curl':
      return servers
        .map((s) =>
          [
            // One command is unambiguous on its own; N need a label to tell apart.
            ...(servers.length > 1 ? [`# ${s.name}`] : []),
            `curl -sS -X POST ${s.url} \\`,
            `  -H "${auth}" \\`,
            `  -H "Content-Type: application/json" \\`,
            `  -H "Accept: application/json, text/event-stream" \\`,
            `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`,
          ].join('\n'),
        )
        .join('\n\n')
  }
}

export function clientHint(kind: ClientKind): string {
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
    case 'curl':
      return 'Sanity-check the proxy before wiring a client.'
  }
}
