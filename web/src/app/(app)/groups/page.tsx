'use client'

import { GroupFields } from '@/app/group-form'
import { Alert, AlertActions, AlertDescription, AlertTitle } from '@/components/alert'
import { Button } from '@/components/button'
import { Dialog, DialogActions, DialogBody, DialogTitle } from '@/components/dialog'
import { Heading } from '@/components/heading'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { ApiError, api, type Group, type Upstream } from '@/lib/api'
import { editErrorMessage } from '@/lib/edit-error'
import { blankGroupForm, formFromGroup, groupCreateBody, groupPatchBody, type GroupForm } from '@/lib/group-form'
import { ABSENT } from '@/lib/placeholder'
import clsx from 'clsx'
import { useEffect, useRef, useState } from 'react'

const errorLine = 'text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400'

export default function GroupsPage() {
  const [groups, setGroups] = useState<Group[]>([])
  const [upstreams, setUpstreams] = useState<Upstream[]>([])
  const [open, setOpen] = useState(false)
  /** The row the dialog is editing; null while it is creating. Decides the mode, the title and the submit. */
  const [editing, setEditing] = useState<Group | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [formError, setFormError] = useState('')
  // Counts failures, not messages: two saves rejected with the same sentence
  // leave formError unchanged, and the scroll below has to run for the second.
  const [formErrorSeq, setFormErrorSeq] = useState(0)
  const [form, setForm] = useState<GroupForm>(blankGroupForm)
  /** The save is waiting on the remove-every-member confirm. */
  const [confirmEmpty, setConfirmEmpty] = useState(false)
  /** The row the delete Alert is asking about, and the Alert's own error line. */
  const [pendingDelete, setPendingDelete] = useState<Group | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  // Mirrors `open` for a save whose dialog was closed while it was in flight:
  // its failure belongs on the page, not in a dialog nobody is looking at.
  const openRef = useRef(false)
  const formErrorRef = useRef<HTMLParagraphElement>(null)

  const mode: 'create' | 'edit' = editing ? 'edit' : 'create'

  useEffect(() => {
    // The panel is a bottom sheet on a phone, so a failed submit's message
    // would otherwise sit off-screen above the operator.
    formErrorRef.current?.scrollIntoView({ block: 'nearest' })
  }, [formErrorSeq])

  function load() {
    Promise.all([api<{ groups: Group[] }>('/groups'), api<{ upstreams: Upstream[] }>('/upstreams')])
      .then(([g, u]) => {
        setGroups(g.groups)
        setUpstreams(u.upstreams)
      })
      .catch((e: Error) => setError(e.message))
  }

  useEffect(load, [])

  function nameFor(id: string) {
    return upstreams.find((u) => u.id === id)?.name || id.slice(0, 8)
  }

  function onFieldChange(patch: Partial<GroupForm>) {
    setForm((f) => ({ ...f, ...patch }))
  }

  function openCreate() {
    setEditing(null)
    setFormError('')
    setForm(blankGroupForm())
    openRef.current = true
    setOpen(true)
  }

  function openEdit(g: Group) {
    setEditing(g)
    setFormError('')
    setForm(formFromGroup(g))
    openRef.current = true
    setOpen(true)
  }

  /** Every way out: Cancel, Escape, the backdrop, a successful submit. */
  function close() {
    openRef.current = false
    setOpen(false)
    setEditing(null)
    setConfirmEmpty(false)
  }

  function failed(err: unknown) {
    const message = editErrorMessage(err, 'group')
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
      await api('/groups', { method: 'POST', body: JSON.stringify(groupCreateBody(form)) })
      close()
      setForm(blankGroupForm())
      load()
    } catch (err) {
      failed(err)
    } finally {
      setSaving(false)
    }
  }

  /**
   * Send only what changed (see groupPatchBody). Emptying the group is allowed
   * by the API but takes every endpoint off every virtual key targeting it, so
   * that one body waits for the Alert below; `confirmed` is the Alert's answer,
   * and the body is computed again from the live form rather than kept from the
   * first press. The 200 is the row itself, so the table takes it in place.
   */
  async function save(confirmed = false) {
    const row = editing
    if (!row) return
    const body = groupPatchBody(row, form)
    if (Object.keys(body).length === 0) {
      close()
      return
    }
    if (Array.isArray(body.upstream_ids) && body.upstream_ids.length === 0 && !confirmed) {
      setConfirmEmpty(true)
      return
    }
    setSaving(true)
    try {
      const saved = await api<Group>(`/groups/${row.id}`, { method: 'PATCH', body: JSON.stringify(body) })
      setGroups((list) => list.map((x) => (x.id === saved.id ? saved : x)))
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

  function confirmRemoveAll() {
    // The Alert closes first: a failure lands in the dialog's own error line.
    setConfirmEmpty(false)
    void save(true)
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
      await api(`/groups/${row.id}`, { method: 'DELETE' })
      setGroups((list) => list.filter((x) => x.id !== row.id))
      closeDelete()
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) void load()
      setDeleteError(editErrorMessage(err, 'group'))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <Heading>Groups</Heading>
        <Button type="button" color="cyan" onClick={openCreate}>
          Create group
        </Button>
      </div>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        A group combines several upstreams so one virtual key can reach all of them.
      </p>
      {error ? <p className={clsx('mt-4', errorLine)}>{error}</p> : null}

      {groups.length === 0 ? (
        <p className="mt-10 text-base/7 text-zinc-500 sm:text-sm/6">No groups yet.</p>
      ) : (
        <Table className="mt-8 [--gutter:--spacing(6)] lg:[--gutter:--spacing(10)]">
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Upstreams</TableHeader>
              <TableHeader className="text-right">Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {groups.map((g) => (
              <TableRow key={g.id}>
                <TableCell className="font-medium">{g.name}</TableCell>
                <TableCell className="text-zinc-500">
                  {g.upstream_ids.length === 0 ? ABSENT : g.upstream_ids.map(nameFor).join(', ')}
                </TableCell>
                <TableCell className="text-right">
                  <span className="inline-flex gap-2">
                    <Button type="button" plain onClick={() => openEdit(g)}>
                      Edit
                    </Button>
                    <Button type="button" plain onClick={() => setPendingDelete(g)}>
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
          <DialogTitle>{editing ? 'Edit group' : 'Create group'}</DialogTitle>
          <DialogBody>
            {formError ? (
              // role="alert" because this answers a submit the operator just
              // made; the page-level error line above the table describes a
              // background load and stays a plain paragraph.
              <p ref={formErrorRef} role="alert" className={clsx('mb-4', errorLine)}>
                {formError}
              </p>
            ) : null}
            <GroupFields mode={mode} form={form} onChange={onFieldChange} upstreams={upstreams} />
          </DialogBody>
          <DialogActions>
            <Button type="button" plain onClick={close}>
              Cancel
            </Button>
            <Button type="submit" color="cyan" disabled={saving}>
              {saving ? 'Saving…' : editing ? 'Save changes' : 'Create'}
            </Button>
          </DialogActions>
        </form>

        {/* Inside the dialog's React tree, beside the form and never inside it:
            Headless treats a dialog rendered within another as nested, so a
            click on these buttons is not an outside click that closes the
            dialog underneath, and the two focus traps stack. */}
        <Alert open={confirmEmpty} onClose={() => setConfirmEmpty(false)}>
          <AlertTitle>Remove every upstream from this group?</AlertTitle>
          <AlertDescription>
            {editing
              ? `${editing.name} will have no members. Every virtual key targeting it loses its endpoints, and its calls fail until a member is added.`
              : ''}
          </AlertDescription>
          <AlertActions>
            <Button type="button" plain onClick={() => setConfirmEmpty(false)}>
              Cancel
            </Button>
            <Button type="button" color="red" onClick={confirmRemoveAll}>
              Remove all
            </Button>
          </AlertActions>
        </Alert>
      </Dialog>

      <Alert open={!!pendingDelete} onClose={closeDelete}>
        <AlertTitle>Delete this group?</AlertTitle>
        <AlertDescription>
          {pendingDelete ? `${pendingDelete.name} will be removed. The upstreams in it are kept.` : ''}
        </AlertDescription>
        {deleteError ? (
          <p role="alert" className="mt-2 text-center text-base/7 text-pink-600 sm:text-left sm:text-sm/6 dark:text-pink-400">
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
