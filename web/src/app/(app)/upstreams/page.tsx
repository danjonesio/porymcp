'use client'

import { DiscoveryPanel, IDLE, type DiscoveryState } from '@/app/discovery-panel'
import { UpstreamFields } from '@/app/upstream-form'
import { Alert, AlertActions, AlertDescription, AlertTitle } from '@/components/alert'
import { Badge } from '@/components/badge'
import { Button } from '@/components/button'
import { Dialog, DialogActions, DialogBody, DialogDescription, DialogTitle } from '@/components/dialog'
import { Divider } from '@/components/divider'
import { Heading } from '@/components/heading'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { Text } from '@/components/text'
import { ApiError, api, discoverUpstream, discoverUpstreamPayload, type Discovery, type Upstream } from '@/lib/api'
import { discoverable, discoveryErrorMessage } from '@/lib/discovery'
import { editErrorMessage } from '@/lib/edit-error'
import { deriveSlug } from '@/lib/slug'
import { authState } from '@/lib/upstream-auth'
import {
  CONNECTION_FIELDS,
  authConfigFrom,
  blankUpstreamForm,
  formFromUpstream,
  upstreamCreateBody,
  upstreamPatchBody,
  type UpstreamForm,
} from '@/lib/upstream-form'
import { testState } from '@/lib/upstream-test'
import clsx from 'clsx'
import { useEffect, useRef, useState } from 'react'

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

const errorLine = 'text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400'

export default function UpstreamsPage() {
  const [items, setItems] = useState<Upstream[]>([])
  /** When the list on screen arrived: the clock the Status cell's "3m ago" counts from. */
  const [loadedAt, setLoadedAt] = useState(0)
  const [open, setOpen] = useState(false)
  /** The row the dialog is editing; null while it is adding. Decides the mode, the title and the submit. */
  const [editing, setEditing] = useState<Upstream | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [formError, setFormError] = useState('')
  // Counts failures, not messages: two saves rejected with the same sentence
  // leave formError unchanged, and the scroll below has to run for the second.
  const [formErrorSeq, setFormErrorSeq] = useState(0)
  const [slugTouched, setSlugTouched] = useState(false)
  const [form, setForm] = useState<UpstreamForm>(blankUpstreamForm)
  const [formDiscovery, setFormDiscovery] = useState<DiscoveryState>(IDLE)
  /** The row whose Tools dialog is open, and that dialog's own discovery. */
  const [tools, setTools] = useState<Upstream | null>(null)
  const [rowDiscovery, setRowDiscovery] = useState<DiscoveryState>(IDLE)
  /** The row the delete Alert is asking about, and the Alert's own error line. */
  const [pendingDelete, setPendingDelete] = useState<Upstream | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  // Discovery has a ten-second budget, so a second press can easily land while
  // the first is in flight. Each surface counts its own requests and paints only
  // the newest one.
  const formSeq = useRef(0)
  const rowSeq = useRef(0)
  // Mirrors `open` for a save whose dialog was closed while it was in flight:
  // its failure belongs on the page, not in a dialog nobody is looking at.
  const openRef = useRef(false)
  const formErrorRef = useRef<HTMLParagraphElement>(null)

  const mode: 'create' | 'edit' = editing ? 'edit' : 'create'

  useEffect(() => {
    // The dialog body is long and the panel is a bottom sheet on a phone, so a
    // failed submit's message would otherwise sit off-screen above the operator.
    formErrorRef.current?.scrollIntoView({ block: 'nearest' })
  }, [formErrorSeq])

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
   * One field changed in the dialog. In edit mode the patch is the whole story.
   * In create mode three reactions ride along: the Slug input marks itself
   * touched, the Name input derives the slug until then (reading slugTouched
   * from render scope is correct: only the Slug input sets it, and the two
   * inputs cannot fire in one React batch), and a change to a field discovery
   * used throws the panel away, because it described the URL, transport and
   * credential (header name included) as they were when it ran. Name, slug and
   * description are not connection fields: they only change the previewed tool
   * names, which recompute from props on every render.
   */
  function onFieldChange(patch: Partial<UpstreamForm>) {
    if (mode === 'edit') {
      setForm((f) => ({ ...f, ...patch }))
      return
    }
    if ('slug' in patch) setSlugTouched(true)
    setForm((f) => {
      const next = { ...f, ...patch }
      if ('name' in patch && !('slug' in patch) && !slugTouched) next.slug = deriveSlug(next.name)
      return next
    })
    if (CONNECTION_FIELDS.some((k) => k in patch)) resetFormDiscovery()
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

  /**
   * Open the dialog to add. The reset is the one this button has always done:
   * the form is otherwise only cleared on a successful create, so a cancelled
   * dialog would reopen with the old values and a stale slugTouched that
   * silently disables auto-fill. Transport, auth type, header name and enabled
   * persist across opens on purpose, for the operator adding three upstreams
   * behind the same scheme.
   */
  function openAdd() {
    setEditing(null)
    setFormError('')
    setSlugTouched(false)
    setForm((f) => ({ ...f, name: '', slug: '', description: '', url: '', token: '', value: '' }))
    resetFormDiscovery()
    openRef.current = true
    setOpen(true)
  }

  /** Open the dialog on a row. The credential boxes start empty; blank means keep. */
  function openEdit(u: Upstream) {
    setEditing(u)
    setFormError('')
    setForm(formFromUpstream(u))
    resetFormDiscovery()
    openRef.current = true
    setOpen(true)
  }

  /** Every way out: Cancel, Escape, the backdrop, a successful submit. */
  function close() {
    openRef.current = false
    setOpen(false)
    setEditing(null)
    // A typed credential never survives into the next dialog, whichever row it opens on.
    setForm((f) => ({ ...f, token: '', value: '' }))
    resetFormDiscovery()
  }

  function failed(err: unknown) {
    const message = editErrorMessage(err, 'upstream')
    // The row went away under the dialog: reload so "the current list" is true
    // when the operator closes it.
    if (err instanceof ApiError && err.status === 404) void load()
    if (openRef.current) {
      setFormError(message)
      setFormErrorSeq((n) => n + 1)
    } else {
      setError(message)
    }
  }

  async function create() {
    setSaving(true)
    try {
      await api('/upstreams', { method: 'POST', body: JSON.stringify(upstreamCreateBody(form, slugTouched)) })
      close()
      setSlugTouched(false)
      load()
    } catch (err) {
      failed(err)
    } finally {
      setSaving(false)
    }
  }

  /**
   * Send only what changed. The body carries the keys whose value differs from
   * the row the dialog opened on, and never `auth_config` for a blank credential
   * box or `slug` at all (see upstreamPatchBody). The 200 is the row itself,
   * with the last test already reset when the connection changed, so the table
   * takes it in place of the old row and no second request is needed.
   */
  async function save() {
    const row = editing
    if (!row) return
    const body = upstreamPatchBody(row, form)
    if (Object.keys(body).length === 0) {
      close()
      return
    }
    setSaving(true)
    try {
      const saved = await api<Upstream>(`/upstreams/${row.id}`, { method: 'PATCH', body: JSON.stringify(body) })
      setItems((list) => list.map((x) => (x.id === saved.id ? saved : x)))
      close()
    } catch (err) {
      failed(err)
    } finally {
      setSaving(false)
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')
    if (mode === 'edit') void save()
    else void create()
  }

  function closeDelete() {
    setPendingDelete(null)
    setDeleteError('')
  }

  /** Delete the row the Alert is asking about. A failure keeps the Alert open with its reason. */
  async function remove() {
    const row = pendingDelete
    if (!row) return
    setDeleting(true)
    setDeleteError('')
    try {
      await api(`/upstreams/${row.id}`, { method: 'DELETE' })
      setItems((list) => list.filter((x) => x.id !== row.id))
      closeDelete()
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) void load()
      setDeleteError(editErrorMessage(err, 'upstream'))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <Heading>Upstreams</Heading>
        <Button type="button" color="cyan" onClick={openAdd}>
          Add upstream
        </Button>
      </div>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        Real MCP servers. Credentials are encrypted at rest and never shown again.
      </p>
      {error ? <p className={clsx('mt-4', errorLine)}>{error}</p> : null}

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
                    <Button type="button" plain onClick={() => openEdit(u)}>
                      Edit
                    </Button>
                    <Button type="button" plain onClick={() => setPendingDelete(u)}>
                      Delete
                    </Button>
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onClose={close}>
        <form onSubmit={submit}>
          <DialogTitle>{editing ? 'Edit upstream' : 'Add upstream'}</DialogTitle>
          {editing ? (
            // The slug is fixed once created and has no input here, so it has
            // no path into the body; this line is where the operator reads it.
            <DialogDescription>Slug: {editing.slug}. It is fixed once the upstream is created.</DialogDescription>
          ) : null}
          <DialogBody>
            {formError ? (
              // role="alert" because this answers a submit the operator just
              // made; the page-level error line above the table describes a
              // background load and stays a plain paragraph.
              <p ref={formErrorRef} role="alert" className={clsx('mb-4', errorLine)}>
                {formError}
              </p>
            ) : null}
            <UpstreamFields mode={mode} form={form} onChange={onFieldChange} before={editing ?? undefined} />

            {mode === 'create' ? (
              <>
                {/* Discover sits at the foot of the body, not in DialogActions: that
                    row stacks in reverse below sm:, which would bury an exploratory
                    action between Create and Cancel, and Create stays the dialog's
                    one primary button. It is a create-only affordance: from an edit
                    dialog the payload route would probe with whatever credential
                    the operator typed, which for a blank box is none, and blame a
                    working token for the 401. Tools on the row tests the saved
                    upstream with its stored credential. */}
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
                    Connects to the URL above using these credentials and lists the tools that server offers. Nothing
                    is saved, and this check is not recorded as a test.
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
              </>
            ) : null}
          </DialogBody>
          <DialogActions>
            {/* Cancel stays enabled while a save is in flight: Escape and the
                backdrop would close the dialog anyway, and a failure that lands
                after a close goes to the page-level line (see failed). */}
            <Button type="button" plain onClick={close}>
              Cancel
            </Button>
            <Button type="submit" color="cyan" disabled={saving}>
              {saving ? 'Saving…' : editing ? 'Save changes' : 'Create'}
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

      <Alert open={!!pendingDelete} onClose={closeDelete}>
        <AlertTitle>Delete this upstream?</AlertTitle>
        <AlertDescription>
          {pendingDelete
            ? `${pendingDelete.name} will be removed. Its stored credential is deleted with it. This cannot be undone.`
            : ''}
        </AlertDescription>
        {deleteError ? (
          <p role="alert" className={clsx('mt-2 text-center sm:text-left', errorLine)}>
            {deleteError}
          </p>
        ) : null}
        <AlertActions>
          <Button type="button" plain onClick={closeDelete}>
            Cancel
          </Button>
          <Button type="button" color="red" disabled={deleting} onClick={remove}>
            {deleting ? 'Deleting…' : 'Delete'}
          </Button>
        </AlertActions>
      </Alert>
    </>
  )
}
