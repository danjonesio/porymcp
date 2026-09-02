'use client'

import { DiscoveryPanel, IDLE, type DiscoveryState } from '@/app/discovery-panel'
import { Badge } from '@/components/badge'
import { Button } from '@/components/button'
import { Checkbox, CheckboxField } from '@/components/checkbox'
import { Dialog, DialogActions, DialogBody, DialogDescription, DialogTitle } from '@/components/dialog'
import { Divider } from '@/components/divider'
import { Description, Field, FieldGroup, Label } from '@/components/fieldset'
import { Heading } from '@/components/heading'
import { HelpDisclosure } from '@/components/help-disclosure'
import { Input } from '@/components/input'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { Strong, Text } from '@/components/text'
import { api, discoverUpstream, discoverUpstreamPayload, type Discovery, type Upstream } from '@/lib/api'
import { discoverable, discoveryErrorMessage } from '@/lib/discovery'
import { deriveSlug } from '@/lib/slug'
import { authState } from '@/lib/upstream-auth'
import { testState } from '@/lib/upstream-test'
import clsx from 'clsx'
import { useEffect, useRef, useState } from 'react'

/** The form's credential fields, in the shape the API stores them. */
function authConfigFrom(form: { auth_type: string; token: string; header: string; value: string }): Record<
  string,
  string
> {
  const auth_config: Record<string, string> = {}
  if (form.auth_type === 'bearer' && form.token) auth_config.token = form.token
  if ((form.auth_type === 'header' || form.auth_type === 'api_key' || form.auth_type === 'custom') && form.value) {
    auth_config.header = form.header
    auth_config.value = form.value
  }
  return auth_config
}

/**
 * The second line of the Status cell: whether the last deliberate connection
 * test passed, and how long ago it ran. A press of Tools or Refresh records it,
 * and changing the URL, transport, auth type or credential clears it back to
 * "Not tested": a green dot against a connection nobody has tried is worse
 * than no dot.
 *
 * `nowMs` is read where the list arrives rather than here, because a clock read
 * in render is impure: the same row would print a different label on a render
 * nothing else changed, and it would run on the prerendered pass too. Every run
 * of a test refreshes the list, so "just now" is right when it matters; there is
 * no timer, and the exact instant is in the time element either way.
 */
function TestStateLine({ upstream, nowMs }: { upstream: Upstream; nowMs: number }) {
  const s = testState(upstream, nowMs)
  return (
    <span className="flex items-center gap-1.5 text-sm/5 text-zinc-500 sm:text-xs/5 dark:text-zinc-400">
      <span aria-hidden="true" className={clsx('size-1.5 shrink-0 rounded-full forced-colors:outline', DOT[s.tone])} />
      <span>{s.word}{s.at ? <> <time dateTime={s.at}>{s.ago}</time></> : null}</span>
    </span>
  )
}

function AuthCell({ upstream }: { upstream: Upstream }) {
  const a = authState(upstream)
  return (
    <span className="inline-flex items-center gap-2">
      <span>{upstream.auth_type}</span>
      {a.tone === 'broken' ? (
        <Badge color="pink">{a.label}</Badge>
      ) : a.tone === 'ok' ? (
        <span className="text-zinc-500 dark:text-zinc-400">· set</span>
      ) : null}
    </span>
  )
}

/** The dot is decoration: the word beside it is the whole text alternative. */
const DOT = {
  never: 'bg-zinc-400 dark:bg-zinc-500',
  passed: 'bg-lime-500 dark:bg-lime-400',
  failed: 'bg-pink-500 dark:bg-pink-400',
}

export default function UpstreamsPage() {
  const [items, setItems] = useState<Upstream[]>([])
  /** When the list on screen arrived: the clock the Status cell's "3m ago" counts from. */
  const [loadedAt, setLoadedAt] = useState(0)
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const [formError, setFormError] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [form, setForm] = useState({
    name: '',
    slug: '',
    description: '',
    url: '',
    transport: 'streamable-http',
    auth_type: 'none',
    token: '',
    header: 'Authorization',
    value: '',
    enabled: true,
  })
  const [formDiscovery, setFormDiscovery] = useState<DiscoveryState>(IDLE)
  /** The row whose Tools dialog is open, and that dialog's own discovery. */
  const [tools, setTools] = useState<Upstream | null>(null)
  const [rowDiscovery, setRowDiscovery] = useState<DiscoveryState>(IDLE)
  // Discovery has a ten-second budget, so a second press can easily land while
  // the first is in flight. Each surface counts its own requests and paints only
  // the newest one.
  const formSeq = useRef(0)
  const rowSeq = useRef(0)

  /**
   * Run one discovery request into one surface's state. Every setState below
   * fires from a handler or a promise callback, never from an effect body.
   */
  async function run(seq: React.RefObject<number>, set: (s: DiscoveryState) => void, call: () => Promise<Discovery>) {
    const mine = ++seq.current
    set({ result: null, pending: true, error: '' })
    try {
      const result = await call()
      if (seq.current !== mine) return
      set({ result, pending: false, error: '' })
    } catch (err) {
      if (seq.current !== mine) return
      set({ result: null, pending: false, error: discoveryErrorMessage(err) })
    }
  }

  /**
   * Throw away whatever the Add upstream dialog's panel is showing. Every path
   * that changes or clears the form goes through here, because a panel that
   * outlives the connection it describes is a lie: an edited field, a cancelled
   * dialog, a completed create, a freshly opened one.
   *
   * Bumping the sequence is half the reset. A request still in flight asked
   * about the connection as it was, and `run` paints only the newest request's
   * answer, so the bump is what stops a stale reply landing under a form that
   * has moved on.
   */
  function resetFormDiscovery() {
    formSeq.current++
    setFormDiscovery(IDLE)
  }

  /**
   * Edit one of the fields discovery actually used. The panel below describes
   * the URL, transport and credential (header name included) as they were
   * when it ran, so it is a lie the moment one of them changes. Name, slug and
   * description are not here: they only change the previewed tool names, which
   * recompute from props on every render.
   */
  function editConnection(patch: Partial<typeof form>) {
    setForm((f) => ({ ...f, ...patch }))
    resetFormDiscovery()
  }

  function discoverForm() {
    run(formSeq, setFormDiscovery, () =>
      discoverUpstreamPayload({
        name: form.name,
        url: form.url,
        transport: form.transport,
        auth_type: form.auth_type,
        auth_config: authConfigFrom(form),
      })
    )
  }

  function discoverRow(u: Upstream) {
    // The saved route stamps the row, so the table is stale the moment this
    // resolves. The refresh hangs off the promise rather than sitting inside
    // run(): closeTools bumps rowSeq, and a refresh behind that guard would be
    // skipped in exactly the case the record was made for: a dialog closed
    // while the handshake was still running.
    void run(rowSeq, setRowDiscovery, () => discoverUpstream(u.id)).then(refresh)
  }

  function openTools(u: Upstream) {
    setTools(u)
    discoverRow(u)
  }

  function closeTools() {
    // Drop the list with the dialog: reopening on another row must not flash the
    // previous row's tools, and bumping the sequence discards an answer that is
    // still on its way to a dialog nobody is looking at.
    rowSeq.current++
    setTools(null)
    setRowDiscovery(IDLE)
  }

  /**
   * Take one list from the server. The clock is read here, in a promise
   * callback, rather than in the cell that prints "3m ago": a clock read during
   * render is impure: it would give one row two answers on two renders of the
   * same data, and it would run on the prerendered pass as well.
   */
  function show(d: { upstreams: Upstream[] }) {
    setItems(d.upstreams)
    setLoadedAt(Date.now())
  }

  function load() {
    api<{ upstreams: Upstream[] }>('/upstreams')
      .then(show)
      .catch((e: Error) => setError(e.message))
  }

  /**
   * Read the table again, because the durable record of a test lives on the
   * server and not in the Discovery the dialog just showed. Not load(): load()'s
   * catch paints the page-level error line, and a failed background refresh
   * after a successful test is not a page error: items stays as it was until
   * the next load.
   */
  function refresh() {
    return api<{ upstreams: Upstream[] }>('/upstreams').then(show).catch(() => {})
  }

  useEffect(load, [])

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')
    const auth_config = authConfigFrom(form)
    try {
      await api('/upstreams', {
        method: 'POST',
        body: JSON.stringify({
          name: form.name,
          slug: slugTouched ? form.slug : '',
          description: form.description,
          url: form.url,
          transport: form.transport,
          auth_type: form.auth_type,
          auth_config,
          enabled: form.enabled,
        }),
      })
      setOpen(false)
      setForm({ ...form, name: '', slug: '', description: '', url: '', token: '', value: '' })
      setSlugTouched(false)
      resetFormDiscovery()
      load()
    } catch (err) {
      setFormError((err as Error).message)
    }
  }

  async function remove(id: string) {
    if (!confirm('Delete this upstream?')) return
    try {
      await api(`/upstreams/${id}`, { method: 'DELETE' })
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <Heading>Upstreams</Heading>
        <Button
          type="button"
          color="cyan"
          onClick={() => {
            // Reset everything on open: the form is otherwise only cleared on a
            // successful create, so a cancelled dialog would reopen with the old
            // values and a stale slugTouched that silently disables auto-fill.
            setFormError('')
            setSlugTouched(false)
            setForm((f) => ({ ...f, name: '', slug: '', description: '', url: '', token: '', value: '' }))
            resetFormDiscovery()
            setOpen(true)
          }}
        >
          Add upstream
        </Button>
      </div>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        Real MCP servers. Credentials are encrypted at rest and never shown again.
      </p>
      {error ? <p className="mt-4 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{error}</p> : null}

      {items.length === 0 ? (
        <p className="mt-10 text-base/7 text-zinc-500 sm:text-sm/6">No upstreams yet. Add the first real MCP server.</p>
      ) : (
        <Table className="mt-8 [--gutter:--spacing(6)] lg:[--gutter:--spacing(10)]">
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Slug</TableHeader>
              <TableHeader>URL</TableHeader>
              <TableHeader>Transport</TableHeader>
              <TableHeader>Auth</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader className="text-right">Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.name}</TableCell>
                <TableCell className="font-mono text-xs text-zinc-500">{u.slug}</TableCell>
                <TableCell className="max-w-xs truncate text-zinc-500">{u.url}</TableCell>
                <TableCell>{u.transport}</TableCell>
                <TableCell>
                  {/* The type, then what the stored credential is worth: "· set"
                      when PoryMCP can use it, a badge when it cannot (Unreadable
                      is the key, Incomplete is the credential) and nothing for
                      none. The Status cell's Failed line says a test failed; this
                      cell says why. */}
                  <AuthCell upstream={u} />
                </TableCell>
                <TableCell>
                  {/* Two facts, two labels: the badge is a flag someone set, the
                      line under it is what the upstream itself last said. */}
                  <div className="flex flex-col items-start gap-1">
                    <Badge color={u.enabled ? 'lime' : 'zinc'}>{u.enabled ? 'Enabled' : 'Disabled'}</Badge>
                    <TestStateLine upstream={u} nowMs={loadedAt} />
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <span className="inline-flex gap-2">
                    <Button type="button" plain onClick={() => openTools(u)}>
                      Tools
                    </Button>
                    <Button type="button" plain onClick={() => remove(u.id)}>
                      Delete
                    </Button>
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onClose={setOpen}>
        <form onSubmit={create}>
          <DialogTitle>Add upstream</DialogTitle>
          <DialogBody>
            {formError ? (
              <p className="mb-4 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{formError}</p>
            ) : null}
            <FieldGroup>
              <Field>
                <Label>Name</Label>
                <Input
                  name="name"
                  value={form.name}
                  onChange={(e) => {
                    const name = e.target.value
                    // Reading slugTouched from render scope is correct: only the Slug
                    // input sets it, and the two inputs cannot fire in one React batch.
                    setForm((f) => ({ ...f, name, slug: slugTouched ? f.slug : deriveSlug(name) }))
                  }}
                  required
                />
              </Field>
              <Field>
                <Label>Slug</Label>
                <Input
                  name="slug"
                  value={form.slug}
                  placeholder="up"
                  maxLength={40}
                  onChange={(e) => {
                    setSlugTouched(true)
                    setForm((f) => ({ ...f, slug: e.target.value }))
                  }}
                />
                <Description>
                  Used in URLs and in tool names on the group endpoint. Fixed once the upstream is created.
                </Description>
              </Field>
              {/* The disclosure rides with the field rather than as its own
                  FieldGroup child, so it sits under the input instead of a full
                  field's gap below it. */}
              <div>
                <Field>
                  <Label>URL</Label>
                  <Input
                    type="url"
                    name="url"
                    value={form.url}
                    onChange={(e) => editConnection({ url: e.target.value })}
                    required
                  />
                </Field>
                <div className="mt-3">
                  <HelpDisclosure label="What URL should I use?">
                    <p>
                      <Strong>
                        The MCP endpoint, not the home page.
                      </Strong>{' '}
                      Usually the address ends in <span className="font-mono wrap-break-word">/mcp</span>. Copy it from
                      the server’s documentation or from a working Claude Code or Cursor config.
                    </p>
                    <p>
                      <Strong>The final address.</Strong> PoryMCP
                      sends this upstream’s credential to exactly the URL you enter and never follows a redirect. An{' '}
                      <span className="font-mono wrap-break-word">http://</span> address that redirects to{' '}
                      <span className="font-mono wrap-break-word">https://</span>, or a path missing its trailing
                      slash, fails with <span className="font-mono">502</span> and a log entry reading{' '}
                      <span className="font-mono wrap-break-word">upstream redirected to …</span>. Use{' '}
                      <span className="font-mono wrap-break-word">https://</span> and the exact path the server serves.
                    </p>
                    <p>
                      <Strong>Check it before you save.</Strong>{' '}
                      Discover tools connects with these settings and lists what the server offers.
                    </p>
                  </HelpDisclosure>
                </div>
              </div>
              <Field>
                <Label>Description</Label>
                <Input
                  name="description"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </Field>
              <Field>
                <Label>Transport</Label>
                <Select
                  name="transport"
                  value={form.transport}
                  onChange={(e) => editConnection({ transport: e.target.value })}
                >
                  <option value="streamable-http">Streamable HTTP</option>
                  <option value="sse">SSE</option>
                </Select>
              </Field>
              <Field>
                <Label>Auth type</Label>
                <Select
                  name="auth_type"
                  value={form.auth_type}
                  onChange={(e) => editConnection({ auth_type: e.target.value })}
                >
                  <option value="none">None</option>
                  <option value="bearer">Bearer</option>
                  <option value="header">Header</option>
                  <option value="api_key">API key</option>
                  <option value="custom">Custom</option>
                </Select>
              </Field>
              {form.auth_type === 'bearer' ? (
                <Field>
                  <Label>Bearer token</Label>
                  <Input
                    type="password"
                    name="token"
                    value={form.token}
                    onChange={(e) => editConnection({ token: e.target.value })}
                  />
                  <Description>Stored encrypted. It will not be shown after save.</Description>
                </Field>
              ) : null}
              {form.auth_type === 'header' || form.auth_type === 'api_key' || form.auth_type === 'custom' ? (
                <>
                  <Field>
                    <Label>Header name</Label>
                    <Input
                      name="header"
                      value={form.header}
                      onChange={(e) => editConnection({ header: e.target.value })}
                    />
                  </Field>
                  <Field>
                    <Label>Header value</Label>
                    <Input
                      type="password"
                      name="value"
                      value={form.value}
                      onChange={(e) => editConnection({ value: e.target.value })}
                    />
                  </Field>
                </>
              ) : null}
              <CheckboxField>
                <Checkbox
                  name="enabled"
                  checked={form.enabled}
                  onChange={(checked) => setForm({ ...form, enabled: checked })}
                />
                <Label>Enabled</Label>
              </CheckboxField>
            </FieldGroup>

            {/* Discover sits at the foot of the body, not in DialogActions: that
                row stacks in reverse below sm:, which would bury an exploratory
                action between Create and Cancel, and Create stays the dialog's
                one primary button. */}
            <Divider soft className="my-8" />
            <div>
              <Button
                type="button"
                outline
                disabled={!discoverable(form.url) || formDiscovery.pending}
                onClick={discoverForm}
              >
                {formDiscovery.pending ? 'Discovering…' : 'Discover tools'}
              </Button>
              <Text className="mt-2">
                Connects to the URL above using these credentials and lists the tools that server offers. Nothing is
                saved, and this check is not recorded as a test.
              </Text>
            </div>
            <DiscoveryPanel
              {...formDiscovery}
              className="mt-8"
              url={form.url}
              authType={form.auth_type}
              slug={form.slug.trim()}
              surface="draft"
            />
          </DialogBody>
          <DialogActions>
            <Button
              type="button"
              plain
              onClick={() => {
                resetFormDiscovery()
                setOpen(false)
              }}
            >
              Cancel
            </Button>
            <Button type="submit" color="cyan">
              Create
            </Button>
          </DialogActions>
        </form>
      </Dialog>

      <Dialog open={!!tools} onClose={closeTools} size="2xl">
        <DialogTitle>Tools</DialogTitle>
        <DialogDescription>{tools?.name}</DialogDescription>
        <DialogBody>
          {tools ? (
            <DiscoveryPanel
              {...rowDiscovery}
              url={tools.url}
              authType={tools.auth_type}
              slug={tools.slug}
              surface="saved"
            />
          ) : null}
        </DialogBody>
        <DialogActions>
          <Button type="button" plain onClick={closeTools}>
            Close
          </Button>
          <Button
            type="button"
            color="cyan"
            disabled={rowDiscovery.pending}
            onClick={() => tools && discoverRow(tools)}
          >
            {rowDiscovery.pending ? 'Refreshing…' : 'Refresh'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  )
}
