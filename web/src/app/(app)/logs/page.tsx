'use client'

import clsx from 'clsx'
import { useEffect, useMemo, useState } from 'react'
import { AdminEvents } from '@/app/admin-events'
import { LoadMore } from '@/app/load-more'
import { Badge } from '@/components/badge'
import { Button } from '@/components/button'
import { DescriptionDetails, DescriptionList, DescriptionTerm } from '@/components/description-list'
import { Dialog, DialogActions, DialogBody, DialogTitle } from '@/components/dialog'
import { Description, Field, Label } from '@/components/fieldset'
import { Heading, Subheading } from '@/components/heading'
import { Input } from '@/components/input'
import { errorLine } from '@/components/primitives'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { Text } from '@/components/text'
import { type AuditLog, api, requestErrorMessage, type Upstream, type VirtualKey } from '@/lib/api'
import {
  customPrefill,
  customProblems,
  DEFAULT_FILTERS,
  LOAD_MORE_CALLS,
  type LogFilters,
  logQuery,
  NO_LOGS,
  NOT_LISTED,
  PERIODS,
  type Period,
  type UpstreamCell,
  type UpstreamName,
  upstreamCell,
} from '@/lib/logs-view'
import { ABSENT, LOADING } from '@/lib/placeholder'
import { useCursorPages } from '@/lib/use-cursor-pages'

/**
 * The Logs page: Proxy calls, 50 at a time with Load more, narrowed by a
 * period (Last 7 days by default) and four filters; then Admin activity.
 *
 * Every control goes through `change`, which also moves the anchor the
 * period's start is measured from, so the window is fixed for a listing and a
 * Load more never moves it. useCursorPages owns the rows and drops any answer
 * for an older filter. The virtual key and upstream lists load once, on their
 * own: neither failing withholds the rows. The upstream name in the detail
 * dialog is the upstream's current one; a row whose upstream is not in the
 * list shows its full id.
 */
export default function LogsPage() {
  const [keys, setKeys] = useState<VirtualKey[]>([])
  const [keysError, setKeysError] = useState('')
  const [names, setNames] = useState<ReadonlyMap<string, UpstreamName> | null>(null)
  const [namesFailed, setNamesFailed] = useState(false)
  const [selected, setSelected] = useState<AuditLog | null>(null)
  const [filters, setFilters] = useState<LogFilters>(DEFAULT_FILTERS)
  // Read only to build the query, never rendered, so the static export never
  // bakes a build-time window; the client sets its own on first render.
  const [anchor, setAnchor] = useState(() => Date.now())

  const query = useMemo(() => logQuery(filters, anchor), [filters, anchor])
  const pages = useCursorPages<AuditLog>('/logs', query)
  const problems = customProblems(filters)

  useEffect(() => {
    api<{ virtual_keys: VirtualKey[] }>('/virtual-keys')
      .then((r) => setKeys(r.virtual_keys))
      .catch((err: unknown) => setKeysError(requestErrorMessage(err)))
    api<{ upstreams: Upstream[] }>('/upstreams')
      .then((r) => setNames(new Map(r.upstreams.map((u) => [u.id, { name: u.name, slug: u.slug }]))))
      .catch(() => setNamesFailed(true))
  }, [])

  function change(patch: Partial<LogFilters>) {
    setFilters((f) => ({ ...f, ...patch }))
    setAnchor(Date.now())
  }

  function changePeriod(period: Period) {
    // Custom starts where the preset started, so the switch does not widen
    // the window; Until starts empty, which is no upper bound.
    if (period === 'custom' && filters.period !== 'custom') {
      change({ period, since: customPrefill(filters, anchor), until: '', sinceBad: false, untilBad: false })
    } else {
      change({ period })
    }
  }

  // Chromium fires one change event when a filled datetime-local loses its
  // first segment (value "", badInput true) and none while the rest are
  // cleared or on blur, so badInput is also read on key-up and on blur:
  // otherwise a cleared Until would stay incomplete and send nothing.
  function syncInput(field: 'since' | 'until', el: HTMLInputElement) {
    const bad = field === 'since' ? filters.sinceBad : filters.untilBad
    if (el.value === filters[field] && el.validity.badInput === bad) return
    change(field === 'since' ? { since: el.value, sinceBad: el.validity.badInput } : { until: el.value, untilBad: el.validity.badInput })
  }

  const error = pages.error || keysError
  // Read in the browser and only once Custom is chosen, so the static export
  // never bakes in the build host's zone. Each input carries it as its
  // description; the visible line under the row is the same sentence.
  const zoneSentence =
    filters.period === 'custom'
      ? `Times are in ${Intl.DateTimeFormat().resolvedOptions().timeZone}. Both ends are included.`
      : ''

  return (
    <>
      <Heading>Logs</Heading>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">Proxy calls and admin changes.</p>

      <Subheading className="mt-10">Proxy calls</Subheading>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        Every proxied MCP method and HTTP API request is recorded. Secrets in params and credential-shaped text in
        error messages are redacted. HTTP API request bodies are not recorded.
      </p>
      {error ? (
        <p role="alert" className={clsx('mt-4', errorLine)}>
          {error}
        </p>
      ) : null}

      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Field>
          <Label>Period</Label>
          <Select name="period" value={filters.period} onChange={(e) => changePeriod(e.target.value as Period)}>
            {PERIODS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </Select>
        </Field>
        {filters.period === 'custom' ? (
          <>
            <Field>
              <Label>Since</Label>
              <Input
                type="datetime-local"
                name="since"
                value={filters.since}
                invalid={!!problems.since}
                onChange={(e) => syncInput('since', e.target)}
                onKeyUp={(e) => syncInput('since', e.currentTarget)}
                onBlur={(e) => syncInput('since', e.currentTarget)}
              />
              {problems.since ? (
                <Description>
                  <span className="text-pink-600 dark:text-pink-400">{problems.since}</span>
                </Description>
              ) : null}
              <Description className="sr-only">{zoneSentence}</Description>
            </Field>
            <Field>
              <Label>Until</Label>
              <Input
                type="datetime-local"
                name="until"
                value={filters.until}
                invalid={!!problems.until}
                onChange={(e) => syncInput('until', e.target)}
                onKeyUp={(e) => syncInput('until', e.currentTarget)}
                onBlur={(e) => syncInput('until', e.currentTarget)}
              />
              {problems.until ? (
                <Description>
                  <span className="text-pink-600 dark:text-pink-400">{problems.until}</span>
                </Description>
              ) : null}
              <Description className="sr-only">{zoneSentence}</Description>
            </Field>
          </>
        ) : null}
      </div>
      {filters.period === 'custom' ? (
        <Text aria-hidden="true" className="mt-3">
          {zoneSentence}
        </Text>
      ) : null}

      <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Field>
          <Label>Virtual key</Label>
          <Select name="virtual_key_id" value={filters.virtual_key_id} onChange={(e) => change({ virtual_key_id: e.target.value })}>
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
          <Input name="method" value={filters.method} onChange={(e) => change({ method: e.target.value })} placeholder="tools/call" />
        </Field>
        <Field>
          <Label>Tool</Label>
          <Input name="tool" value={filters.tool} onChange={(e) => change({ tool: e.target.value })} />
        </Field>
        <Field>
          <Label>Status</Label>
          <Select name="status" value={filters.status} onChange={(e) => change({ status: e.target.value })}>
            <option value="">All statuses</option>
            <option value="success">Success</option>
            <option value="error">Error</option>
            <option value="blocked">Blocked</option>
          </Select>
        </Field>
      </div>

      {pages.rows.length === 0 ? null : (
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
            {pages.rows.map((log) => (
              <TableRow key={log.id} onClick={() => setSelected(log)} className="cursor-pointer">
                <TableCell className="tabular-nums text-zinc-500">{new Date(log.timestamp).toLocaleString()}</TableCell>
                <TableCell>{log.virtual_key_name}</TableCell>
                <TableCell>{log.method}</TableCell>
                {/* On a relayed HTTP API call the tool is the request path
                    (PORM-146), which can run to 256 bytes: clipped like the
                    Upstreams URL cell, and whole in the detail dialog. */}
                <TableCell className="max-w-xs truncate" dir="ltr">
                  {log.tool_name || ABSENT}
                </TableCell>
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
      <LoadMore label={LOAD_MORE_CALLS} noun="call" empty={NO_LOGS} pages={pages} />

      <Dialog open={!!selected} onClose={() => setSelected(null)} size="2xl">
        <DialogTitle>Log detail</DialogTitle>
        <DialogBody>
          {selected ? (
            <>
              {/* Request, Method and Tool are caller text: left to right and
                  free to break anywhere, never clipped or titled. */}
              <DescriptionList>
                <DescriptionTerm>Request</DescriptionTerm>
                <DescriptionDetails dir="ltr" className="font-mono break-all">
                  {selected.request_id}
                </DescriptionDetails>
                <DescriptionTerm>Upstream</DescriptionTerm>
                <DescriptionDetails>
                  <UpstreamValue cell={upstreamCell(selected.upstream_id, names, namesFailed)} />
                </DescriptionDetails>
                <DescriptionTerm>Method</DescriptionTerm>
                <DescriptionDetails dir="ltr" className="font-mono break-all">
                  {selected.method}
                </DescriptionDetails>
                <DescriptionTerm>Tool</DescriptionTerm>
                <DescriptionDetails dir="ltr" className="font-mono break-all">
                  {selected.tool_name || ABSENT}
                </DescriptionDetails>
                {selected.error_message ? (
                  <>
                    <DescriptionTerm>Error</DescriptionTerm>
                    <DescriptionDetails>
                      {/* Colour only: the list sets the line height, and its
                          own text colour would win over a class on the dd. */}
                      <span className="wrap-anywhere text-pink-600 dark:text-pink-400">{selected.error_message}</span>
                    </DescriptionDetails>
                  </>
                ) : null}
              </DescriptionList>
              <Subheading level={3} className="mt-6">
                Params
              </Subheading>
              <div className="mt-3 overflow-x-auto rounded-lg bg-zinc-50 p-3 ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:shadow-none dark:inset-ring dark:inset-ring-white/5">
                <pre className="text-base/7 sm:text-sm/6">{JSON.stringify(selected.params ?? {}, null, 2)}</pre>
              </div>
            </>
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

/**
 * The Upstream value in the detail dialog: the current name with the slug
 * beside it, the placeholder for a row with no upstream, the loading
 * placeholder before the list answers, or the full id with the reason when
 * the list does not hold it.
 */
function UpstreamValue({ cell }: { cell: UpstreamCell }) {
  switch (cell.kind) {
    case 'absent':
      return ABSENT
    case 'loading':
      return LOADING
    case 'name':
      return (
        <span className="flex flex-wrap items-baseline gap-x-2">
          <span>{cell.name}</span>
          <span dir="ltr" className="font-mono break-all text-zinc-500 dark:text-zinc-400">
            {cell.slug}
          </span>
        </span>
      )
    case 'id':
      return (
        <span className="flex flex-wrap items-baseline gap-x-2">
          <span dir="ltr" className="font-mono break-all">
            {cell.id}
          </span>
          <span className="text-zinc-500 dark:text-zinc-400">{NOT_LISTED}</span>
        </span>
      )
  }
}
