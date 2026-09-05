'use client'

import { Badge } from '@/components/badge'
import { Button } from '@/components/button'
import { Dialog, DialogActions, DialogBody, DialogTitle } from '@/components/dialog'
import { Field, Label } from '@/components/fieldset'
import { Heading, Subheading } from '@/components/heading'
import { Input } from '@/components/input'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { api, type AuditLog, type VirtualKey } from '@/lib/api'
import { ABSENT } from '@/lib/placeholder'
import { AdminEvents } from '@/app/admin-events'
import { useEffect, useState } from 'react'

export default function LogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [keys, setKeys] = useState<VirtualKey[]>([])
  const [selected, setSelected] = useState<AuditLog | null>(null)
  const [error, setError] = useState('')
  const [filters, setFilters] = useState({ virtual_key_id: '', method: '', status: '', tool: '' })

  function load() {
    const q = new URLSearchParams()
    q.set('limit', '50')
    if (filters.virtual_key_id) q.set('virtual_key_id', filters.virtual_key_id)
    if (filters.method) q.set('method', filters.method)
    if (filters.status) q.set('status', filters.status)
    if (filters.tool) q.set('tool', filters.tool)
    Promise.all([api<{ logs: AuditLog[] }>(`/logs?${q}`), api<{ virtual_keys: VirtualKey[] }>('/virtual-keys')])
      .then(([l, a]) => {
        setLogs(l.logs)
        setKeys(a.virtual_keys)
      })
      .catch((e: Error) => setError(e.message))
  }

  useEffect(load, [filters.virtual_key_id, filters.method, filters.status, filters.tool])

  return (
    <>
      <Heading>Logs</Heading>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">Proxy calls and admin changes.</p>

      <Subheading className="mt-10">Proxy calls</Subheading>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        Every proxied MCP method is recorded. Secrets in params are redacted.
      </p>
      {error ? <p className="mt-4 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{error}</p> : null}

      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Field>
          <Label>Virtual key</Label>
          <Select
            name="virtual_key_id"
            value={filters.virtual_key_id}
            onChange={(e) => setFilters({ ...filters, virtual_key_id: e.target.value })}
          >
            <option value="">All virtual keys</option>
            {keys.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field>
          <Label>Method</Label>
          <Input
            name="method"
            value={filters.method}
            onChange={(e) => setFilters({ ...filters, method: e.target.value })}
            placeholder="tools/call"
          />
        </Field>
        <Field>
          <Label>Tool</Label>
          <Input name="tool" value={filters.tool} onChange={(e) => setFilters({ ...filters, tool: e.target.value })} />
        </Field>
        <Field>
          <Label>Status</Label>
          <Select name="status" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
            <option value="">All statuses</option>
            <option value="success">Success</option>
            <option value="error">Error</option>
            <option value="blocked">Blocked</option>
          </Select>
        </Field>
      </div>

      {logs.length === 0 ? (
        <p className="mt-10 text-base/7 text-zinc-500 sm:text-sm/6">No matching log entries.</p>
      ) : (
        <Table className="mt-8 [--gutter:--spacing(6)] lg:[--gutter:--spacing(10)]">
          <TableHead>
            <TableRow>
              <TableHeader>Time</TableHeader>
              <TableHeader>Virtual key</TableHeader>
              <TableHeader>Method</TableHeader>
              <TableHeader>Tool</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader className="text-right">Latency</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.map((log) => (
              <TableRow key={log.id} onClick={() => setSelected(log)} className="cursor-pointer">
                <TableCell className="tabular-nums text-zinc-500">{new Date(log.timestamp).toLocaleString()}</TableCell>
                <TableCell>{log.virtual_key_name}</TableCell>
                <TableCell>{log.method}</TableCell>
                <TableCell>{log.tool_name || ABSENT}</TableCell>
                <TableCell>
                  <Badge color={log.status === 'success' ? 'lime' : log.status === 'blocked' ? 'amber' : 'pink'}>
                    {log.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-right tabular-nums">{log.latency_ms} ms</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={!!selected} onClose={() => setSelected(null)} size="2xl">
        <DialogTitle>Log detail</DialogTitle>
        <DialogBody>
          {selected ? (
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <dt className="text-base/7 font-medium sm:text-sm/6">Request</dt>
                <dd className="mt-1 font-mono text-base/7 sm:text-sm/6">{selected.request_id}</dd>
              </div>
              <div>
                <dt className="text-base/7 font-medium sm:text-sm/6">Upstream</dt>
                <dd className="mt-1 text-base/7 sm:text-sm/6">{selected.upstream_id || ABSENT}</dd>
              </div>
              {selected.error_message ? (
                <div className="sm:col-span-2">
                  <dt className="text-base/7 font-medium sm:text-sm/6">Error</dt>
                  <dd className="mt-1 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{selected.error_message}</dd>
                </div>
              ) : null}
              <div className="sm:col-span-2">
                <dt className="text-base/7 font-medium sm:text-sm/6">Params</dt>
                <dd className="mt-2 overflow-x-auto rounded-lg bg-zinc-50 p-3 ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:shadow-none dark:inset-ring dark:inset-ring-white/5">
                  <pre className="text-base/7 sm:text-sm/6">{JSON.stringify(selected.params ?? {}, null, 2)}</pre>
                </dd>
              </div>
            </dl>
          ) : null}
        </DialogBody>
        <DialogActions>
          <Button type="button" plain onClick={() => setSelected(null)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      <Subheading className="mt-14">Admin activity</Subheading>
      <AdminEvents />
    </>
  )
}
