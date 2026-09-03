'use client'

import { Button } from '@/components/button'
import { Checkbox, CheckboxField, CheckboxGroup } from '@/components/checkbox'
import { Dialog, DialogActions, DialogBody, DialogTitle } from '@/components/dialog'
import { Field, FieldGroup, Label } from '@/components/fieldset'
import { Heading } from '@/components/heading'
import { Input } from '@/components/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { api, type Group, type Upstream } from '@/lib/api'
import { ABSENT } from '@/lib/placeholder'
import { useEffect, useState } from 'react'

export default function GroupsPage() {
  const [groups, setGroups] = useState<Group[]>([])
  const [upstreams, setUpstreams] = useState<Upstream[]>([])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ name: '', description: '', upstream_ids: [] as string[] })

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

  async function create(e: React.FormEvent) {
    e.preventDefault()
    try {
      await api('/groups', { method: 'POST', body: JSON.stringify(form) })
      setOpen(false)
      setForm({ name: '', description: '', upstream_ids: [] })
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  async function remove(id: string) {
    if (!confirm('Delete this group?')) return
    try {
      await api(`/groups/${id}`, { method: 'DELETE' })
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  function toggle(id: string, checked: boolean) {
    setForm((f) => ({
      ...f,
      upstream_ids: checked ? [...f.upstream_ids, id] : f.upstream_ids.filter((x) => x !== id),
    }))
  }

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <Heading>Groups</Heading>
        <Button type="button" color="cyan" onClick={() => setOpen(true)}>
          Create group
        </Button>
      </div>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        A group combines several upstreams so one virtual key can reach all of them.
      </p>
      {error ? <p className="mt-4 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{error}</p> : null}

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
                  <Button type="button" plain onClick={() => remove(g.id)}>
                    Delete
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onClose={setOpen}>
        <form onSubmit={create}>
          <DialogTitle>Create group</DialogTitle>
          <DialogBody>
            <FieldGroup>
              <Field>
                <Label>Name</Label>
                <Input name="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
              </Field>
              <Field>
                <Label>Description</Label>
                <Input
                  name="description"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </Field>
              <Field>
                <Label>Upstreams</Label>
                <CheckboxGroup>
                  {upstreams.map((u) => (
                    <CheckboxField key={u.id}>
                      <Checkbox
                        name="upstream_ids"
                        checked={form.upstream_ids.includes(u.id)}
                        onChange={(checked) => toggle(u.id, checked)}
                      />
                      <Label>{u.name}</Label>
                    </CheckboxField>
                  ))}
                </CheckboxGroup>
              </Field>
            </FieldGroup>
          </DialogBody>
          <DialogActions>
            <Button type="button" plain onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" color="cyan">
              Create
            </Button>
          </DialogActions>
        </form>
      </Dialog>
    </>
  )
}
