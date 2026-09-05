import assert from 'node:assert/strict'
import test from 'node:test'
import type { Upstream } from './api.ts'
import {
  DEFAULT_HEADER,
  blankUpstreamForm,
  credentialHelp,
  credentialRequired,
  editCredentialDescription,
  formFromUpstream,
  headerRequired,
  upstreamCreateBody,
  upstreamPatchBody,
  type UpstreamForm,
} from './upstream-form.ts'

// Run with: npm test (node --test). The .ts extensions above are required:
// Node will not resolve an extensionless TypeScript specifier.

/** A stored row as GET /upstreams returns it: a bearer credential that reads. */
function up(over: Partial<Upstream> = {}): Upstream {
  return {
    id: 'u1',
    name: 'GitHub',
    slug: 'github',
    description: 'Issues and pull requests',
    url: 'https://api.example.com/mcp',
    transport: 'streamable-http',
    auth_type: 'bearer',
    enabled: true,
    auth_configured: true,
    auth_status: 'ok',
    last_test_at: null,
    last_test_ok: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    ...over,
  }
}

/** A header-type row whose hint names the header it sends. */
function headerUp(over: Partial<Upstream> = {}): Upstream {
  return up({ auth_type: 'header', auth_hint: { header: 'X-Api-Key' }, ...over })
}

function edit(before: Upstream, over: Partial<UpstreamForm> = {}): UpstreamForm {
  return { ...formFromUpstream(before), ...over }
}

// Security requirement 2, AC2: a blank credential box never rewrites the stored credential.
test('upstreamPatchBody: omits auth_config when the credential box is blank, for every auth type', () => {
  for (const auth_type of ['bearer', 'header', 'api_key', 'custom', 'none']) {
    const before = up({ auth_type, auth_hint: auth_type === 'bearer' || auth_type === 'none' ? undefined : { header: 'X' } })
    const body = upstreamPatchBody(before, edit(before, { name: 'Renamed' }))
    assert.equal('auth_config' in body, false, auth_type)
    assert.deepEqual(body, { name: 'Renamed' }, auth_type)
  }
})

test('upstreamPatchBody: includes auth_config when a token is typed', () => {
  const before = up()
  assert.deepEqual(upstreamPatchBody(before, edit(before, { token: 'new-token' })), {
    auth_config: { token: 'new-token' },
  })
})

test('upstreamPatchBody: includes auth_config when a header value is typed', () => {
  const before = headerUp()
  assert.deepEqual(upstreamPatchBody(before, edit(before, { value: 'v' })), {
    auth_config: { header: 'X-Api-Key', value: 'v' },
  })
})

// Security requirement 12: a header name of spaces satisfies `required` but not the proxy.
test('upstreamPatchBody: trims the header name and never emits an auth_config whose header is blank after trimming', () => {
  const before = up({ auth_type: 'header', auth_status: 'unreadable' })
  assert.deepEqual(upstreamPatchBody(before, edit(before, { header: ' X-Api-Key ', value: 'v' })), {
    auth_config: { header: 'X-Api-Key', value: 'v' },
  })
  const body = upstreamPatchBody(before, edit(before, { header: '   ', value: 'v', name: 'Renamed' }))
  assert.equal('auth_config' in body, false)
  assert.deepEqual(body, { name: 'Renamed' })
})

test('upstreamPatchBody: never emits slug, even when the form slug differs from the row', () => {
  const before = up()
  const body = upstreamPatchBody(before, edit(before, { slug: 'something-else', name: 'Renamed' }))
  assert.equal('slug' in body, false)
})

// AC4, security requirement 10: an unchanged field is never sent.
test('upstreamPatchBody: an unchanged form yields {} and a name-only change yields exactly {name}', () => {
  const before = up()
  assert.deepEqual(upstreamPatchBody(before, edit(before)), {})
  assert.deepEqual(upstreamPatchBody(before, edit(before, { name: 'GitHub prod' })), { name: 'GitHub prod' })
})

test('upstreamPatchBody: a URL differing only by surrounding whitespace is not sent', () => {
  const before = up()
  assert.deepEqual(upstreamPatchBody(before, edit(before, { url: '  https://api.example.com/mcp  ' })), {})
})

test('upstreamPatchBody: description cleared to empty against a stored description is emitted', () => {
  const before = up()
  assert.deepEqual(upstreamPatchBody(before, edit(before, { description: '' })), { description: '' })
})

test('upstreamPatchBody: an auth_type change with a typed credential emits both keys', () => {
  const before = up()
  assert.deepEqual(upstreamPatchBody(before, edit(before, { auth_type: 'header', header: 'X-Api-Key', value: 'v' })), {
    auth_type: 'header',
    auth_config: { header: 'X-Api-Key', value: 'v' },
  })
})

test('upstreamPatchBody: URL and enabled changes travel together and nothing else does', () => {
  const before = up()
  assert.deepEqual(upstreamPatchBody(before, edit(before, { url: 'https://new.example.com/mcp', enabled: false })), {
    url: 'https://new.example.com/mcp',
    enabled: false,
  })
})

// Security requirements 1, 3, 12: the form never holds a stored secret and never guesses a header name.
test('formFromUpstream: token and value are empty and header comes from auth_hint', () => {
  const f = formFromUpstream(headerUp())
  assert.equal(f.token, '')
  assert.equal(f.value, '')
  assert.equal(f.header, 'X-Api-Key')
  assert.equal(f.description, 'Issues and pull requests')
})

test('formFromUpstream: header is empty when auth_hint is absent', () => {
  assert.equal(formFromUpstream(up()).header, '')
  assert.equal(formFromUpstream(up({ auth_type: 'header', auth_status: 'unreadable' })).header, '')
  assert.equal(formFromUpstream(up({ description: undefined })).description, '')
})

test('blankUpstreamForm: equals the initial state the Add dialog has always had, header included', () => {
  assert.deepEqual(blankUpstreamForm(), {
    name: '',
    slug: '',
    description: '',
    url: '',
    transport: 'streamable-http',
    auth_type: 'none',
    token: '',
    header: DEFAULT_HEADER,
    value: '',
    enabled: true,
  })
  assert.equal(DEFAULT_HEADER, 'Authorization')
})

test('upstreamCreateBody: matches the POST body the Add dialog has always sent', () => {
  const f: UpstreamForm = {
    ...blankUpstreamForm(),
    name: 'GitHub',
    slug: 'gh',
    url: 'https://api.example.com/mcp',
    auth_type: 'bearer',
    token: 't',
  }
  assert.deepEqual(upstreamCreateBody(f, true), {
    name: 'GitHub',
    slug: 'gh',
    description: '',
    url: 'https://api.example.com/mcp',
    transport: 'streamable-http',
    auth_type: 'bearer',
    auth_config: { token: 't' },
    enabled: true,
  })
  // An untouched slug goes as '' so the server derives it; a blank credential goes as {} on create.
  assert.equal(upstreamCreateBody(f, false).slug, '')
  assert.deepEqual(upstreamCreateBody({ ...f, token: '' }, false).auth_config, {})
})

// Security requirement 4.
test('credentialRequired: true on an auth_type change to a credential type, false on a change to none', () => {
  const before = up()
  assert.equal(credentialRequired(before, edit(before, { auth_type: 'header' })), true)
  assert.equal(credentialRequired(before, edit(before, { auth_type: 'api_key' })), true)
  assert.equal(credentialRequired(before, edit(before, { auth_type: 'none' })), false)
  // header to api_key shares a stored shape; re-entry there is the issue's deliberate default.
  const h = headerUp()
  assert.equal(credentialRequired(h, edit(h, { auth_type: 'api_key' })), true)
})

test('credentialRequired: true on a header-name change, false when unchanged', () => {
  const before = headerUp()
  assert.equal(credentialRequired(before, edit(before)), false)
  assert.equal(credentialRequired(before, edit(before, { header: 'X-Other' })), true)
  assert.equal(credentialRequired(before, edit(before, { header: ' X-Api-Key ' })), false)
})

test('credentialRequired: false on an unreadable row with the header untouched, true once it changes', () => {
  const before = up({ auth_type: 'header', auth_status: 'unreadable' })
  assert.equal(credentialRequired(before, edit(before, { name: 'Renamed' })), false)
  assert.equal(credentialRequired(before, edit(before, { header: 'X-Api-Key' })), true)
})

// Security requirement 12: a credential is never sent with an empty header name.
test('headerRequired: true for a header-shaped type once a value is typed', () => {
  const before = up({ auth_type: 'header', auth_status: 'unreadable' })
  assert.equal(headerRequired(before, edit(before, { value: 'v' })), true)
  assert.equal(headerRequired(undefined, { ...blankUpstreamForm(), auth_type: 'api_key', header: '', value: 'v' }), true)
})

test('headerRequired: true when credentialRequired is true', () => {
  const before = up()
  assert.equal(headerRequired(before, edit(before, { auth_type: 'header' })), true)
})

test('headerRequired: false on a rename of an unreadable row with nothing typed', () => {
  const before = up({ auth_type: 'header', auth_status: 'unreadable' })
  assert.equal(headerRequired(before, edit(before, { name: 'Renamed' })), false)
})

test('headerRequired: false for bearer and none', () => {
  const before = up()
  assert.equal(headerRequired(before, edit(before, { token: 't' })), false)
  assert.equal(headerRequired(undefined, blankUpstreamForm()), false)
})

test('credentialHelp: names the header when auth_hint is present', () => {
  const before = headerUp()
  assert.equal(
    credentialHelp(before, edit(before)),
    'Leave blank to keep the stored credential. It currently sends the X-Api-Key header. A value here replaces it.'
  )
})

test('credentialHelp: the ok sentence without a header when the hint is absent', () => {
  const before = up()
  assert.equal(credentialHelp(before, edit(before)), 'Leave blank to keep the stored credential. A value here replaces it.')
})

test('credentialHelp: undecryptable and unreadable sentences, with the header suffix only for header-shaped types', () => {
  const undecryptable = up({ auth_status: 'undecryptable' })
  assert.equal(
    credentialHelp(undecryptable, edit(undecryptable)),
    'The stored credential cannot be read with the current encryption key. Enter it again, or restore the key it was saved under. Until then this upstream cannot authenticate.'
  )
  const unreadableHeader = up({ auth_type: 'header', auth_status: 'unreadable' })
  assert.equal(
    credentialHelp(unreadableHeader, edit(unreadableHeader)),
    'No usable credential is stored for this auth type. Enter one, or this upstream cannot authenticate. The header name is stored with it, so enter that too.'
  )
})

// The copy the box actually shows, in the order the component resolves it.
test('editCredentialDescription: a stored none with a credential type chosen asks for that credential by its label', () => {
  const before = up({ auth_type: 'none', auth_status: 'none' })
  assert.equal(editCredentialDescription(before, edit(before, { auth_type: 'api_key' })), 'Enter the credential for API key.')
})

test('editCredentialDescription: an auth type change away from a credential says what changes and names the new type', () => {
  const before = up()
  assert.equal(
    editCredentialDescription(before, edit(before, { auth_type: 'header' })),
    'Changing the auth type changes what PoryMCP sends. Enter the credential for Header to save.'
  )
})

test('editCredentialDescription: a header-name change says why the value is needed again', () => {
  const before = headerUp()
  assert.equal(
    editCredentialDescription(before, edit(before, { header: 'X-Other' })),
    'The header name is stored inside the credential. Enter the value again to change the name.'
  )
})

test('editCredentialDescription: with nothing forcing a re-entry it is the blank-means-keep help', () => {
  const before = headerUp()
  assert.equal(
    editCredentialDescription(before, edit(before)),
    'Leave blank to keep the stored credential. It currently sends the X-Api-Key header. A value here replaces it.'
  )
})

test('credentialHelp: an unknown auth_status reads as the ok sentence, as the table badge does', () => {
  const before = up({ auth_status: 'quarantined' })
  assert.equal(credentialHelp(before, edit(before)), 'Leave blank to keep the stored credential. A value here replaces it.')
})
