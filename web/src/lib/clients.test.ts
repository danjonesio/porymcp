import assert from 'node:assert/strict'
import test from 'node:test'
import { clientSnippet, slugName, type ClientKind, type SnippetServer } from './clients.ts'

// Run with: npm test (node --test). The import above keeps its .ts extension
// because Node will not resolve an extensionless TypeScript specifier;
// tsconfig.json sets allowImportingTsExtensions so tsc accepts it.

const KEY = 'pory_KEY'

/** A two-member group key: one endpoint per enabled upstream. */
const GROUP: SnippetServer[] = [
  { name: 'github', url: 'http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp' },
  { name: 'linear', url: 'http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp' },
]

/** The single-connection form: one server named after the virtual key. */
const SOLO: SnippetServer[] = [{ name: 'my-agent', url: 'http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp' }]

function lines(...l: string[]): string {
  return l.join('\n')
}

const groupSnippets: Record<ClientKind, string> = {
  'claude-code': lines(
    'claude mcp add --transport http github http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp --header "Authorization: Bearer pory_KEY"',
    'claude mcp add --transport http linear http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp --header "Authorization: Bearer pory_KEY"',
  ),
  cursor: lines(
    '{',
    '  "mcpServers": {',
    '    "github": {',
    '      "url": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp",',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    },',
    '    "linear": {',
    '      "url": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp",',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    }',
    '  }',
    '}',
  ),
  codex: lines(
    '# In the shell that launches Codex:',
    "export PORYMCP_KEY='pory_KEY'",
    '',
    '# ~/.codex/config.toml',
    '[mcp_servers.github]',
    'url = "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp"',
    'bearer_token_env_var = "PORYMCP_KEY"',
    '',
    '[mcp_servers.linear]',
    'url = "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp"',
    'bearer_token_env_var = "PORYMCP_KEY"',
  ),
  opencode: lines(
    '{',
    '  "$schema": "https://opencode.ai/config.json",',
    '  "mcp": {',
    '    "github": {',
    '      "type": "remote",',
    '      "url": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp",',
    '      "oauth": false,',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    },',
    '    "linear": {',
    '      "type": "remote",',
    '      "url": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp",',
    '      "oauth": false,',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    }',
    '  }',
    '}',
  ),
  gemini: lines(
    '{',
    '  "mcpServers": {',
    '    "github": {',
    '      "httpUrl": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp",',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    },',
    '    "linear": {',
    '      "httpUrl": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp",',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    }',
    '  }',
    '}',
  ),
  curl: lines(
    '# github',
    'curl -sS -X POST http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/github/mcp \\',
    '  -H "Authorization: Bearer pory_KEY" \\',
    '  -H "Content-Type: application/json" \\',
    '  -H "Accept: application/json, text/event-stream" \\',
    `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`,
    '',
    '# linear',
    'curl -sS -X POST http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/linear/mcp \\',
    '  -H "Authorization: Bearer pory_KEY" \\',
    '  -H "Content-Type: application/json" \\',
    '  -H "Accept: application/json, text/event-stream" \\',
    `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`,
  ),
}

// Pinned from the implementation that shipped before member endpoints existed:
// every existing single-upstream user must keep the snippet they already have.
// Codex is the one deliberate exception — its header no longer carries the
// plaintext key, because that line named the file people paste into.
const soloSnippets: Record<ClientKind, string> = {
  'claude-code':
    'claude mcp add --transport http my-agent http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp --header "Authorization: Bearer pory_KEY"',
  cursor: lines(
    '{',
    '  "mcpServers": {',
    '    "my-agent": {',
    '      "url": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp",',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    }',
    '  }',
    '}',
  ),
  codex: lines(
    '# In the shell that launches Codex:',
    "export PORYMCP_KEY='pory_KEY'",
    '',
    '# ~/.codex/config.toml',
    '[mcp_servers.my_agent]',
    'url = "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp"',
    'bearer_token_env_var = "PORYMCP_KEY"',
  ),
  opencode: lines(
    '{',
    '  "$schema": "https://opencode.ai/config.json",',
    '  "mcp": {',
    '    "my-agent": {',
    '      "type": "remote",',
    '      "url": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp",',
    '      "oauth": false,',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    }',
    '  }',
    '}',
  ),
  gemini: lines(
    '{',
    '  "mcpServers": {',
    '    "my-agent": {',
    '      "httpUrl": "http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp",',
    '      "headers": {',
    '        "Authorization": "Bearer pory_KEY"',
    '      }',
    '    }',
    '  }',
    '}',
  ),
  curl: lines(
    'curl -sS -X POST http://localhost:8080/77232bc0-dd4a-44d5-8ae7-ef2f679879ec/mcp \\',
    '  -H "Authorization: Bearer pory_KEY" \\',
    '  -H "Content-Type: application/json" \\',
    '  -H "Accept: application/json, text/event-stream" \\',
    `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`,
  ),
}

const kinds = Object.keys(groupSnippets) as ClientKind[]

for (const kind of kinds) {
  test(`${kind}: a two-member group gets one server per endpoint`, () => {
    assert.equal(clientSnippet(kind, GROUP, KEY), groupSnippets[kind])
  })

  test(`${kind}: one server keeps the single-connection snippet`, () => {
    assert.equal(clientSnippet(kind, SOLO, KEY), soloSnippets[kind])
  })

  test(`${kind}: no servers means no snippet`, () => {
    assert.equal(clientSnippet(kind, [], KEY), '')
  })
}

test('codex keeps two distinct tables for slugs that normalise the same', () => {
  const snippet = clientSnippet(
    'codex',
    [
      { name: 'github-mcp', url: 'http://localhost:8080/k/github-mcp/mcp' },
      { name: 'github_mcp', url: 'http://localhost:8080/k/github_mcp/mcp' },
    ],
    KEY,
  )
  const headers = snippet.split('\n').filter((l) => l.startsWith('[mcp_servers.'))
  assert.deepEqual(headers, ['[mcp_servers.github_mcp]', '[mcp_servers.github_mcp_2]'])
  assert.equal(new Set(headers).size, headers.length)
})

// The de-dup suffix must be checked against the keys already emitted, not
// counted per base: counting turns github_mcp_2 into a second github_mcp_2 and
// reintroduces the duplicate-key error the suffix exists to prevent.
test('codex keeps three distinct tables when a suffixed key meets a literal one', () => {
  const snippet = clientSnippet(
    'codex',
    [
      { name: 'github-mcp', url: 'http://localhost:8080/k/github-mcp/mcp' },
      { name: 'github_mcp', url: 'http://localhost:8080/k/github_mcp/mcp' },
      { name: 'github_mcp_2', url: 'http://localhost:8080/k/github_mcp_2/mcp' },
    ],
    KEY,
  )
  const headers = snippet.split('\n').filter((l) => l.startsWith('[mcp_servers.'))
  assert.deepEqual(headers, [
    '[mcp_servers.github_mcp]',
    '[mcp_servers.github_mcp_2]',
    '[mcp_servers.github_mcp_2_2]',
  ])
  assert.equal(new Set(headers).size, headers.length)
})

test('slugName collapses to hyphens', () => {
  // Pinned so nobody unifies it with deriveSlug, which collapses to underscores
  // and would rename every existing single-upstream user's server.
  assert.equal(slugName('My Agent'), 'my-agent')
})
