'use client'

import { Alert, AlertActions, AlertDescription, AlertTitle } from '@/components/alert'
import { Badge } from '@/components/badge'
import { Button } from '@/components/button'
import { DescriptionDetails, DescriptionList, DescriptionTerm } from '@/components/description-list'
import { Dialog, DialogActions, DialogBody, DialogDescription, DialogTitle } from '@/components/dialog'
import { Description, Field, FieldGroup, Fieldset, Label, Legend } from '@/components/fieldset'
import { Heading, Subheading } from '@/components/heading'
import { HelpDisclosure } from '@/components/help-disclosure'
import { Input } from '@/components/input'
import { Radio, RadioField, RadioGroup } from '@/components/radio'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { Strong } from '@/components/text'
import { Textarea } from '@/components/textarea'
import { api, type Endpoint, type Group, type Upstream, type VirtualKey } from '@/lib/api'
import { clientHint, clientLabels, clientSnippet, slugName, type ClientKind, type SnippetServer } from '@/lib/clients'
import { ABSENT } from '@/lib/placeholder'
import { Fragment, useEffect, useState } from 'react'

/** How the dialog offers a key's endpoints: one server per upstream, or the single aggregate URL. */
type ConnectionMode = 'per-server' | 'aggregate'

/**
 * True when the key has member endpoints that differ from its aggregate URL.
 * A single-upstream key has one endpoint whose URL *is* the aggregate URL, so
 * there is nothing to choose between.
 */
function splitAvailable(vk: VirtualKey | null): boolean {
  const eps = vk?.endpoints ?? []
  if (eps.length === 0) return false
  return !(eps.length === 1 && eps[0].url === vk?.proxy_url)
}

/**
 * The members named in prose, capped at two so the sentence stays a sentence:
 * "GitHub", "GitHub and Linear", "GitHub, Linear and 2 more".
 */
function memberNames(endpoints: Endpoint[]): string {
  const names = endpoints.map((e) => e.name)
  if (names.length <= 2) return names.join(' and ')
  return `${names[0]}, ${names[1]} and ${names.length - 2} more`
}

/** One plain sentence for the per-server shape, counted and named from this key's own members. */
function separateSummary(endpoints: Endpoint[]): string {
  const names = memberNames(endpoints)
  return endpoints.length === 1
    ? `Recommended. Your client sees one server, ${names}, with its own tools.`
    : `Recommended. Your client sees ${endpoints.length} servers, ${names}, each with its own tools.`
}

export default function VirtualKeysPage() {
  const [keys, setKeys] = useState<VirtualKey[]>([])
  const [upstreams, setUpstreams] = useState<Upstream[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [open, setOpen] = useState(false)
  const [secret, setSecret] = useState<VirtualKey | null>(null)
  const [pendingDelete, setPendingDelete] = useState<VirtualKey | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState<string | null>(null)
  const [client, setClient] = useState<ClientKind>('claude-code')
  const [mode, setMode] = useState<ConnectionMode>('aggregate')
  const [form, setForm] = useState({
    name: '',
    target_type: 'upstream',
    target_id: '',
    rate_limit: '',
  })

  function load() {
    Promise.all([
      api<{ virtual_keys: VirtualKey[] }>('/virtual-keys'),
      api<{ upstreams: Upstream[] }>('/upstreams'),
      api<{ groups: Group[] }>('/groups'),
    ])
      .then(([a, u, g]) => {
        setKeys(a.virtual_keys)
        setUpstreams(u.upstreams)
        setGroups(g.groups)
      })
      .catch((e: Error) => setError(e.message))
  }

  useEffect(load, [])

  function targetName(a: VirtualKey) {
    if (a.target_type === 'group') {
      return groups.find((g) => g.id === a.target_id)?.name || 'Group'
    }
    return upstreams.find((u) => u.id === a.target_id)?.name || 'Upstream'
  }

  async function create(e: React.FormEvent) {
    e.preventDefault()
    try {
      const created = await api<VirtualKey>('/virtual-keys', {
        method: 'POST',
        body: JSON.stringify({
          name: form.name,
          target_type: form.target_type,
          target_id: form.target_id,
          rate_limit: form.rate_limit ? Number(form.rate_limit) : undefined,
        }),
      })
      setOpen(false)
      setSecret(created)
      setMode(splitAvailable(created) ? 'per-server' : 'aggregate')
      setForm({ name: '', target_type: 'upstream', target_id: '', rate_limit: '' })
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  async function rotate(id: string) {
    try {
      const a = await api<VirtualKey>(`/virtual-keys/${id}/rotate`, { method: 'POST', body: '{}' })
      setSecret(a)
      setMode(splitAvailable(a) ? 'per-server' : 'aggregate')
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  async function revoke(id: string) {
    try {
      await api(`/virtual-keys/${id}/revoke`, { method: 'POST', body: '{}' })
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  async function remove() {
    if (!pendingDelete) return
    try {
      await api(`/virtual-keys/${pendingDelete.id}`, { method: 'DELETE' })
      setPendingDelete(null)
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  async function copy(text: string, tag: string) {
    await navigator.clipboard.writeText(text)
    setCopied(tag)
    setTimeout(() => setCopied(null), 1500)
  }

  const targets = form.target_type === 'group' ? groups : upstreams

  const endpoints = secret?.endpoints ?? []
  const canSplit = splitAvailable(secret)
  // canSplit implies at least one endpoint, so the example below always has a
  // real slug; the fallback only keeps the dialog rendering if that ever changes.
  const example = endpoints[0] ?? { slug: 'upstream', name: 'each upstream' }
  const effectiveMode: ConnectionMode = canSplit ? mode : 'aggregate'
  const servers: SnippetServer[] =
    effectiveMode === 'per-server'
      ? endpoints.map((e) => ({ name: e.slug, url: e.url }))
      : [{ name: slugName(secret?.name ?? ''), url: secret?.proxy_url ?? '' }]
  const snippet =
    secret?.api_key && servers.length > 0 && servers.every((s) => s.url)
      ? clientSnippet(client, servers, secret.api_key)
      : ''

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <Heading>Virtual keys</Heading>
        <Button type="button" color="cyan" onClick={() => setOpen(true)}>
          Create virtual key
        </Button>
      </div>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        One identity per client: its own key, target, limits and audit trail. The key is shown once.
      </p>
      {error ? <p className="mt-4 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{error}</p> : null}

      {keys.length === 0 ? (
        <p className="mt-10 text-base/7 text-zinc-500 sm:text-sm/6">No virtual keys yet.</p>
      ) : (
        <Table className="mt-8 [--gutter:--spacing(6)] lg:[--gutter:--spacing(10)]">
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Key</TableHeader>
              <TableHeader>Endpoint</TableHeader>
              <TableHeader>Target</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Last used</TableHeader>
              <TableHeader className="text-right">Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {keys.map((a) => (
              <TableRow key={a.id}>
                <TableCell className="font-medium">{a.name}</TableCell>
                <TableCell className="font-mono text-zinc-500">{a.key_prefix}…</TableCell>
                <TableCell className="max-w-xs font-mono text-zinc-500">
                  <div className="truncate">{a.proxy_url || ABSENT}</div>
                  {(a.endpoints?.length ?? 0) > 1 ? (
                    <div className="text-base/6 sm:text-sm/6">+{a.endpoints?.length ?? 0} per-server</div>
                  ) : null}
                </TableCell>
                <TableCell>
                  {a.target_type}: {targetName(a)}
                </TableCell>
                <TableCell>
                  <Badge color={a.status === 'active' ? 'lime' : a.status === 'revoked' ? 'pink' : 'amber'}>
                    {a.status}
                  </Badge>
                </TableCell>
                <TableCell className="tabular-nums text-zinc-500">
                  {a.last_used_at ? new Date(a.last_used_at).toLocaleString() : 'Never'}
                </TableCell>
                <TableCell className="text-right">
                  <span className="inline-flex gap-2">
                    <Button type="button" plain onClick={() => rotate(a.id)}>
                      Rotate
                    </Button>
                    <Button type="button" plain onClick={() => revoke(a.id)}>
                      Revoke
                    </Button>
                    <Button type="button" plain onClick={() => setPendingDelete(a)}>
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
          <DialogTitle>Create virtual key</DialogTitle>
          <DialogBody>
            <FieldGroup>
              <Field>
                <Label>Name</Label>
                <Input name="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
              </Field>
              <Field>
                <Label>Target type</Label>
                <Select
                  name="target_type"
                  value={form.target_type}
                  onChange={(e) => setForm({ ...form, target_type: e.target.value, target_id: '' })}
                >
                  <option value="upstream">Upstream</option>
                  <option value="group">Group</option>
                </Select>
              </Field>
              <Field>
                <Label>Target</Label>
                <Select
                  name="target_id"
                  value={form.target_id}
                  onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                  required
                >
                  <option value="">Select…</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field>
                <Label>Rate limit</Label>
                <Input
                  type="number"
                  name="rate_limit"
                  min={0}
                  value={form.rate_limit}
                  onChange={(e) => setForm({ ...form, rate_limit: e.target.value })}
                />
                <Description>Optional requests per minute.</Description>
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

      <Dialog open={!!secret} onClose={() => setSecret(null)} size="2xl">
        <DialogTitle>Copy this key now</DialogTitle>
        <DialogDescription>
          The plaintext key is shown only once. It authenticates every endpoint below.
        </DialogDescription>
        <DialogBody>
          <FieldGroup>
            <Field>
              <Label>Virtual key</Label>
              <Input name="api_key" readOnly value={secret?.api_key ?? ''} />
            </Field>

            {canSplit ? (
              <Fieldset>
                <Legend>Connection shape</Legend>
                <RadioGroup name="mode" value={mode} onChange={(v) => setMode(v as ConnectionMode)}>
                  <RadioField>
                    <Radio value="per-server" color="cyan" />
                    <Label>Separate servers</Label>
                    <Description>{separateSummary(endpoints)}</Description>
                  </RadioField>
                  <RadioField>
                    <Radio value="aggregate" color="cyan" />
                    <Label>One combined server</Label>
                    <Description>
                      Your client sees one server, with every tool renamed to say whose it is, like{' '}
                      <span className="font-mono wrap-break-word">{example.slug}__search</span>.
                    </Description>
                  </RadioField>
                </RadioGroup>
                <div className="mt-6">
                  <HelpDisclosure label="What’s the difference?">
                    <p>
                      A server is one entry in your MCP client’s config. The client connects to it and lists the tools
                      it offers.
                    </p>
                    <p>
                      <Strong>Separate servers</Strong> gives this
                      key {endpoints.length} {endpoints.length === 1 ? 'entry' : 'entries'}, one per upstream. Tool
                      names arrive exactly as the upstream publishes them, and you can switch one server off in your
                      client without touching the others.
                    </p>
                    <p>
                      <Strong>One combined server</Strong> gives
                      this key one entry. Every upstream’s tools land in a single list, each renamed to its slug, two
                      underscores, then the tool name: <span className="font-mono wrap-break-word">search</span> on{' '}
                      {example.name} becomes <span className="font-mono wrap-break-word">{example.slug}__search</span>.
                      The client switches them all on or off together.
                    </p>
                    <p>The install snippet below follows whichever you pick.</p>
                  </HelpDisclosure>
                </div>
              </Fieldset>
            ) : null}

            {effectiveMode === 'per-server' ? (
              <div>
                <Subheading level={3}>Endpoints</Subheading>
                <DescriptionList className="mt-3">
                  {endpoints.map((e) => (
                    <Fragment key={e.upstream_id}>
                      <DescriptionTerm>{e.name}</DescriptionTerm>
                      <DescriptionDetails className="flex items-start gap-2">
                        <span className="min-w-0 font-mono break-all">{e.url}</span>
                        <Button
                          type="button"
                          plain
                          className="shrink-0"
                          aria-label={`Copy the ${e.name} URL`}
                          onClick={() => copy(e.url, e.upstream_id)}
                        >
                          {copied === e.upstream_id ? 'Copied' : 'Copy'}
                        </Button>
                      </DescriptionDetails>
                    </Fragment>
                  ))}
                </DescriptionList>
              </div>
            ) : (
              <Field>
                <Label>Proxy URL</Label>
                <Input name="proxy_url" readOnly value={secret?.proxy_url ?? ''} />
                {secret?.target_type === 'group' && endpoints.length === 0 ? (
                  <Description>This group has no enabled upstreams, so calls through this key will fail.</Description>
                ) : null}
              </Field>
            )}

            <Field>
              <Label>Client</Label>
              <Select name="client" value={client} onChange={(e) => setClient(e.target.value as ClientKind)}>
                {(Object.keys(clientLabels) as ClientKind[]).map((k) => (
                  <option key={k} value={k}>
                    {clientLabels[k]}
                  </option>
                ))}
              </Select>
            </Field>

            <Field>
              <Label>Install snippet</Label>
              <Textarea
                name="install_snippet"
                rows={Math.min(24, 8 + Math.max(0, servers.length - 1) * 5)}
                resizable
                readOnly
                value={snippet}
              />
              <Description>{clientHint(client)}</Description>
            </Field>
          </FieldGroup>
        </DialogBody>
        <DialogActions>
          <Button type="button" plain onClick={() => setSecret(null)}>
            Done
          </Button>
          <Button type="button" color="cyan" disabled={!snippet} onClick={() => copy(snippet, 'snippet')}>
            {copied === 'snippet' ? 'Copied' : 'Copy snippet'}
          </Button>
        </DialogActions>
      </Dialog>

      <Alert open={!!pendingDelete} onClose={() => setPendingDelete(null)}>
        <AlertTitle>Delete this virtual key?</AlertTitle>
        <AlertDescription>
          {pendingDelete
            ? `${pendingDelete.name} will be removed. Its key stops working immediately. Audit logs are kept.`
            : ''}
        </AlertDescription>
        <AlertActions>
          <Button type="button" plain onClick={() => setPendingDelete(null)}>
            Cancel
          </Button>
          <Button type="button" color="red" onClick={remove}>
            Delete
          </Button>
        </AlertActions>
      </Alert>
    </>
  )
}
