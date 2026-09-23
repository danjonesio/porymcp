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
import { errorLine } from '@/components/primitives'
import { Radio, RadioField, RadioGroup } from '@/components/radio'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { Strong, Text } from '@/components/text'
import { Textarea } from '@/components/textarea'
import { HttpMethodsFields } from '@/app/http-methods-fields'
import { ToolListFields } from '@/app/tool-list-fields'
import { ApiError, api, type Endpoint, type Group, type Upstream, type VirtualKey } from '@/lib/api'
import type { Member } from '@/lib/catalogue'
import { clientHint, clientLabels, clientSnippet, slugName, type ClientKind, type SnippetServer } from '@/lib/clients'
import { editErrorMessage } from '@/lib/edit-error'
import { ABSENT } from '@/lib/placeholder'
import { useCatalogue } from '@/lib/use-catalogue'
import {
  KEY_RULES_STALE,
  blankVirtualKeyForm,
  formFromVirtualKey,
  keyPolicyStale,
  keyRulesBadge,
  keySaveBlocked,
  listsSent,
  virtualKeyCreateBody,
  virtualKeyPatchBody,
  type KeyForm,
  mcpDoorShown,
} from '@/lib/virtual-key-form'
import clsx from 'clsx'
import { Fragment, useEffect, useMemo, useRef, useState } from 'react'

/** How the dialog offers a key's endpoints: one server per upstream, or the single aggregate URL. */
type ConnectionMode = 'per-server' | 'aggregate'

/**
 * True when the key has member endpoints that differ from its aggregate URL.
 * A single-upstream key has one endpoint whose URL *is* the aggregate URL, so
 * there is nothing to choose between.
 */
function splitAvailable(vk: VirtualKey | null): boolean {
  // MCP endpoints only: an HTTP API endpoint (PORM-146) is its own door and
  // never part of the aggregate, so it is not a shape to choose between.
  const eps = (vk?.endpoints ?? []).filter((e) => e.kind !== 'http')
  if (eps.length === 0) return false
  return !(eps.length === 1 && eps[0].url === vk?.proxy_url)
}

/**
 * The Endpoint column's main line: the aggregate /mcp door, or, for a key that
 * reaches no MCP server, its first HTTP API endpoint, because the /mcp door of
 * such a key answers 400 and is not what an operator hands out.
 */
function endpointLine(vk: VirtualKey): string {
  const eps = vk.endpoints ?? []
  const mcp = eps.filter((e) => e.kind !== 'http')
  if (mcp.length === 0 && eps.length > 0) return eps[0].url
  return vk.proxy_url ?? ''
}

/** The Endpoint column's second line: what the main line leaves out, counted by kind. '' when nothing. */
function endpointExtra(vk: VirtualKey): string {
  const eps = vk.endpoints ?? []
  const mcp = eps.filter((e) => e.kind !== 'http').length
  const http = eps.length - mcp
  const parts: string[] = []
  if (mcp > 1) parts.push(`+${mcp} per-server`)
  const extraHTTP = mcp === 0 ? http - 1 : http
  if (extraHTTP > 0) parts.push(`+${extraHTTP} HTTP API`)
  return parts.join(', ')
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
  /** The row the dialog is editing; null while it is creating. Decides the mode, the title and the submit. */
  const [editing, setEditing] = useState<VirtualKey | null>(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')
  // Counts failures, not messages, so a second identical refusal still scrolls into view.
  const [formErrorSeq, setFormErrorSeq] = useState(0)
  // The same in-flight bookkeeping as the Groups page: `openRef` mirrors `open`
  // for a save whose dialog was closed meanwhile, and `dialogSeq` tells a
  // request which open it belongs to, since one dialog serves every row.
  const openRef = useRef(false)
  const dialogSeq = useRef(0)
  const formErrorRef = useRef<HTMLParagraphElement>(null)
  // The tool catalogue's reset key: every open, and every change of target on
  // create, starts from nothing loaded and drops the last target's answers.
  const [catalogueKey, setCatalogueKey] = useState(0)
  const [secret, setSecret] = useState<VirtualKey | null>(null)
  const [pendingDelete, setPendingDelete] = useState<VirtualKey | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState<string | null>(null)
  const [client, setClient] = useState<ClientKind>('claude-code')
  const [mode, setMode] = useState<ConnectionMode>('aggregate')
  const [form, setForm] = useState<KeyForm>(blankVirtualKeyForm)

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


  useEffect(() => {
    // The panel is a bottom sheet on a phone, so a failed submit's message
    // would otherwise sit off-screen above the operator.
    formErrorRef.current?.scrollIntoView({ block: 'nearest' })
  }, [formErrorSeq])

  // What the dialog's key points at: the row's target on an edit, where it is
  // fixed, and the form's on a create.
  const targetType = editing ? editing.target_type : form.target_type
  const targetId = editing ? editing.target_id : form.target_id
  const groupTarget = targetType === 'group'
  const members = useMemo<Member[]>(() => {
    const ids = groupTarget ? (groups.find((g) => g.id === targetId)?.upstream_ids ?? []) : targetId ? [targetId] : []
    return ids.flatMap((id) => {
      const u = upstreams.find((x) => x.id === id)
      // An HTTP API member (PORM-146) has no tools to load, so it stays out
      // of the catalogue rather than being probed and stamped for nothing.
      return u && u.kind !== 'http'
        ? [{ upstream_id: u.id, slug: u.slug, name: u.name, enabled: u.enabled, transport: u.transport, kind: u.kind }]
        : []
    })
  }, [groupTarget, targetId, groups, upstreams])
  const { catalogue, rateLimited, load: loadTools } = useCatalogue(members, catalogueKey)
  // Every member of the target whatever its kind, enabled or not, for the two
  // questions the dialog asks about kinds (PORM-146): is there an HTTP API
  // here (show Allowed methods) and an MCP server (show Tool rules).
  const targetKinds = useMemo(() => {
    const ids = groupTarget ? (groups.find((g) => g.id === targetId)?.upstream_ids ?? []) : targetId ? [targetId] : []
    return ids.map((id) => upstreams.find((x) => x.id === id)?.kind ?? '')
  }, [groupTarget, targetId, groups, upstreams])
  const hasHTTPTarget = targetKinds.includes('http')
  const hasMCPTarget = targetKinds.includes('mcp')
  const blocked = keySaveBlocked(editing, form, groupTarget)

  function openCreate() {
    setEditing(null)
    setForm(blankVirtualKeyForm())
    opened()
  }

  function openEdit(vk: VirtualKey) {
    setEditing(vk)
    setForm(formFromVirtualKey(vk))
    opened()
  }

  /** The part of every open that the in-flight bookkeeping depends on. */
  function opened() {
    dialogSeq.current++
    openRef.current = true
    setCatalogueKey((n) => n + 1)
    setFormError('')
    setSaving(false)
    setOpen(true)
  }

  /** Every way out. `editing` is left alone so the closing panel does not re-render as the Create form. */
  function close() {
    openRef.current = false
    setOpen(false)
  }

  /** A failed save or create. `mine` is the dialog count the request started under. */
  function failed(message: string, mine: number, err?: unknown) {
    if (err instanceof ApiError && err.status === 404) void load()
    if (openRef.current && dialogSeq.current === mine) {
      setFormError(message)
      setFormErrorSeq((n) => n + 1)
    } else {
      setError(message)
    }
  }

  /**
   * Entries name slugs, so they belong to the target they were ticked under. A
   * new target clears both lists, and the catalogue with its rate-limit line.
   */
  function retarget(patch: Partial<KeyForm>) {
    // The ticked verbs go too: the Allowed methods fieldset may be hidden
    // under the new target, and a hidden value is never sent.
    setForm((f) => ({ ...f, ...patch, tool_allowlist: [], tool_denylist: [], http_methods: [], methodsReplace: false }))
    setCatalogueKey((n) => n + 1)
  }

  function targetName(a: VirtualKey) {
    if (a.target_type === 'group') {
      return groups.find((g) => g.id === a.target_id)?.name || 'Group'
    }
    return upstreams.find((u) => u.id === a.target_id)?.name || 'Upstream'
  }

  async function create() {
    const mine = dialogSeq.current
    setSaving(true)
    try {
      const created = await api<VirtualKey>('/virtual-keys', {
        method: 'POST',
        body: JSON.stringify(virtualKeyCreateBody(form)),
      })
      if (dialogSeq.current === mine) {
        close()
        setForm(blankVirtualKeyForm())
      }
      setSecret(created)
      setMode(splitAvailable(created) ? 'per-server' : 'aggregate')
      load()
    } catch (err) {
      failed(editErrorMessage(err, 'virtual key', 'save'), mine, err)
    } finally {
      if (dialogSeq.current === mine) setSaving(false)
    }
  }

  /**
   * Send only what changed (see virtualKeyPatchBody). A body that carries a list
   * is checked for staleness as the last act before the PATCH, for the lists it
   * carries only: PATCH replaces a whole list and the API has no 409 yet
   * (PORM-119). The re-read is inside the try, so if it fails nothing is sent.
   * The 200 is the row itself, so the table takes it in place.
   */
  async function save() {
    const row = editing
    if (!row) return
    const body = virtualKeyPatchBody(row, form)
    if (Object.keys(body).length === 0) {
      close()
      return
    }
    const mine = dialogSeq.current
    setSaving(true)
    try {
      const fields = listsSent(row, form)
      if (fields.length > 0) {
        const fresh = await api<VirtualKey | null>(`/virtual-keys/${row.id}`)
        // No readable row is not a fresh row: refuse, as for a changed one.
        if (!fresh || keyPolicyStale(row, fresh, fields)) {
          failed(KEY_RULES_STALE, mine)
          return
        }
      }
      const saved = await api<VirtualKey>(`/virtual-keys/${row.id}`, { method: 'PATCH', body: JSON.stringify(body) })
      setKeys((list) => list.map((x) => (x.id === saved.id ? saved : x)))
      if (dialogSeq.current === mine) close()
    } catch (err) {
      failed(editErrorMessage(err, 'virtual key', 'save'), mine, err)
    } finally {
      if (dialogSeq.current === mine) setSaving(false)
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')
    if (blocked) return
    if (editing) void save()
    else void create()
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
  // The two kinds are two sections of the dialog (PORM-146): the MCP
  // endpoints take the connection shape and the client configs, the HTTP API
  // endpoints are listed on their own and appear in the curl snippet only.
  const mcpEndpoints = endpoints.filter((e) => e.kind !== 'http')
  const httpEndpoints = endpoints.filter((e) => e.kind === 'http')
  // The aggregate URL and its shape are shown when the key reaches an MCP
  // server, and for an empty group or a disabled MCP upstream, whose /mcp URL
  // is still the one to hand out; never for a key whose door is /api/.
  const showMCP = secret ? mcpDoorShown(secret) : false
  const canSplit = splitAvailable(secret)
  // canSplit implies at least one endpoint, so the example below always has a
  // real slug; the fallback only keeps the dialog rendering if that ever changes.
  const example = mcpEndpoints[0] ?? { slug: 'upstream', name: 'each upstream' }
  const effectiveMode: ConnectionMode = canSplit ? mode : 'aggregate'
  const mcpServers: SnippetServer[] = !showMCP
    ? []
    : effectiveMode === 'per-server'
      ? mcpEndpoints.map((e) => ({ name: e.slug, url: e.url }))
      : [{ name: slugName(secret?.name ?? ''), url: secret?.proxy_url ?? '' }]
  // One list, split by clientSnippet on kind and nowhere else. The test path
  // is the upstream row's; an endpoint entry does not carry it.
  const httpServers: SnippetServer[] = httpEndpoints.map((e) => ({
    name: e.slug,
    url: e.url,
    kind: 'http',
    testPath: upstreams.find((u) => u.id === e.upstream_id)?.test_path,
  }))
  const servers = [...mcpServers, ...httpServers]
  const clientKinds: ClientKind[] = showMCP ? (Object.keys(clientLabels) as ClientKind[]) : ['curl']
  // A key with no MCP endpoint has only curl to offer: derived here rather
  // than written into state, so the select never shows a client config that
  // would print nothing, and the operator's last choice survives for the next
  // key that has MCP endpoints.
  const effectiveClient: ClientKind = clientKinds.includes(client) ? client : 'curl'
  const snippet =
    secret?.api_key && servers.length > 0 && servers.every((s) => s.url)
      ? clientSnippet(effectiveClient, servers, secret.api_key)
      : ''

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <Heading>Virtual keys</Heading>
        <Button type="button" color="cyan" onClick={openCreate}>
          Create virtual key
        </Button>
      </div>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        One identity per client: its own key, target, limits and audit trail. The key is shown once.
      </p>
      {error ? <p className={clsx('mt-4', errorLine)}>{error}</p> : null}

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
            {keys.map((a) => {
              const rules = keyRulesBadge(a)
              return (
                <TableRow key={a.id}>
                  <TableCell className="font-medium">{a.name}</TableCell>
                  <TableCell className="font-mono text-zinc-500">{a.key_prefix}…</TableCell>
                  <TableCell className="max-w-xs font-mono text-zinc-500">
                    <div className="truncate">{endpointLine(a) || ABSENT}</div>
                    {endpointExtra(a) ? <div className="text-base/6 sm:text-sm/6">{endpointExtra(a)}</div> : null}
                  </TableCell>
                  <TableCell>
                    {a.target_type}: {targetName(a)}
                    {rules ? (
                      <div className="mt-1">
                        <Badge color={rules.tone}>{rules.label}</Badge>
                      </div>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Badge color={a.status === 'active' ? 'lime' : a.status === 'revoked' ? 'pink' : 'amber'}>
                      {a.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-zinc-500 tabular-nums">
                    {a.last_used_at ? new Date(a.last_used_at).toLocaleString() : 'Never'}
                  </TableCell>
                  <TableCell className="text-right">
                    <span className="inline-flex gap-2">
                      <Button type="button" plain onClick={() => openEdit(a)}>
                        Edit
                      </Button>
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
              )
            })}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onClose={close} size="2xl">
        <form onSubmit={submit}>
          <DialogTitle>{editing ? 'Edit virtual key' : 'Create virtual key'}</DialogTitle>
          {editing ? (
            <DialogDescription>
              {`${editing.target_type === 'group' ? 'Group' : 'Upstream'}: ${targetName(editing)}. The target is fixed here.`}
            </DialogDescription>
          ) : null}
          <DialogBody>
            {formError ? (
              <p ref={formErrorRef} role="alert" className={clsx('mb-4', errorLine)}>
                {formError}
              </p>
            ) : null}
            <FieldGroup>
              <Field>
                <Label>Name</Label>
                <Input name="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
              </Field>
              {editing ? null : (
                <>
                  <Field>
                    <Label>Target type</Label>
                    <Select
                      name="target_type"
                      value={form.target_type}
                      onChange={(e) =>
                        retarget({ target_type: e.target.value === 'group' ? 'group' : 'upstream', target_id: '' })
                      }
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
                      onChange={(e) => retarget({ target_id: e.target.value })}
                      required
                    >
                      <option value="">Select…</option>
                      {targets.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.name}
                        </option>
                      ))}
                    </Select>
                    <Description>Changing the target clears both lists.</Description>
                  </Field>
                </>
              )}
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
              {/* Only when the target has an HTTP API (PORM-146); hidden, the
                  stored value is never sent. Before Tool rules, which stays last. */}
              {hasHTTPTarget ? (
                <HttpMethodsFields
                  form={form}
                  onChange={(patch) => setForm((f) => ({ ...f, ...patch }))}
                  groupTarget={groupTarget}
                  unreadable={!!editing?.http_methods_malformed}
                />
              ) : null}
              {/* Last, so Save is one Tab past the final tool row. Hidden when
                  the target holds no MCP server: an HTTP API has no tools, and
                  a tool rule on such a key is accepted and ignored. */}
              {!targetId || hasMCPTarget ? (
              <ToolListFields
                form={form}
                onChange={(patch) => setForm((f) => ({ ...f, ...patch }))}
                groupTarget={groupTarget}
                group={groupTarget ? groups.find((g) => g.id === targetId) : undefined}
                targetSlug={groupTarget ? '' : (members[0]?.slug ?? '')}
                unreadable={!!editing?.lists_malformed}
                catalogue={catalogue}
                rateLimited={rateLimited}
                onLoad={loadTools}
                emptyHint={
                  // On the target, not on the mode: a create can pick a group
                  // that has no members, and the chosen target is then on screen.
                  !targetId
                    ? 'Choose a target to see its tools.'
                    : groupTarget
                      ? 'This group has no upstreams, so there are no tools to tick.'
                      : 'This upstream is no longer there, so there are no tools to tick.'
                }
              />
              ) : groupTarget ? (
                <Text>This group has no MCP servers, so there are no tools to tick.</Text>
              ) : null}
              {blocked ? <p className={errorLine}>{blocked}</p> : null}
            </FieldGroup>
          </DialogBody>
          <DialogActions>
            <Button type="button" plain onClick={close}>
              Cancel
            </Button>
            <Button type="submit" color="cyan" disabled={saving || !!blocked}>
              {saving ? 'Saving…' : editing ? 'Save changes' : 'Create'}
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

            {!showMCP ? null : effectiveMode === 'per-server' ? (
              <div>
                <Subheading level={3}>Endpoints</Subheading>
                <DescriptionList className="mt-3">
                  {mcpEndpoints.map((e) => (
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

            {httpEndpoints.length > 0 || !showMCP ? (
              <div>
                <Subheading level={3}>HTTP API endpoints</Subheading>
                <Text className="mt-2">
                  An SDK takes the URL as its base URL and this key as its API key. Requests are relayed to the API
                  with the stored credential.
                </Text>
                {httpEndpoints.length === 0 ? (
                  <Text className="mt-2">
                    Its upstream is disabled, so requests to this URL are refused until it is enabled again.
                  </Text>
                ) : null}
                <DescriptionList className="mt-3">
                  {(httpEndpoints.length > 0
                    ? httpEndpoints
                    : // A key on a disabled HTTP API upstream has no endpoint entry
                      // yet, but its door is still the /api/ proxy_url, which is the
                      // URL to hand out once the upstream is enabled.
                      [
                        {
                          upstream_id: secret?.target_id ?? '',
                          name: upstreams.find((u) => u.id === secret?.target_id)?.name ?? 'Upstream',
                          url: secret?.proxy_url ?? '',
                        },
                      ]
                  ).map((e) => (
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
            ) : null}

            <Field>
              <Label>Client</Label>
              <Select name="client" value={effectiveClient} onChange={(e) => setClient(e.target.value as ClientKind)}>
                {clientKinds.map((k) => (
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
              <Description>{clientHint(effectiveClient, { mcp: mcpServers.length > 0, http: httpServers.length > 0 })}</Description>
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
