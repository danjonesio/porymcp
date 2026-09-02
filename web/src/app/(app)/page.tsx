'use client'

import { Stat } from '@/app/stat'
import { Badge } from '@/components/badge'
import { Heading, Subheading } from '@/components/heading'
import { Link } from '@/components/link'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { Text } from '@/components/text'
import { api, type AuditLog, type Stats } from '@/lib/api'
import { LOADING } from '@/lib/placeholder'
import { useEffect, useState } from 'react'

function formatRate(n: number) {
  return `${Math.round(n * 100)}%`
}

/**
 * The one notice the Overview shows about stored credentials (PORM-52). Driven
 * by the live counts on /stats (the same sweep the boot line and the Upstreams
 * badges use), never by /health: this notice tracks live credential state,
 * and /health's verdict is a boot fact. Two variants,
 * the worse one first: credentials the current key cannot read (the proxy
 * refuses those upstreams until the key or the credential is fixed), else a
 * rotation left unfinished. Nothing while stats are still loading, so it
 * cannot flash on first paint; unreadable rows are the badge's job, not a
 * banner's. The copy is written here: no server string is rendered.
 *
 * The caller mounts the live region itself, always, so a screen reader is
 * already observing it when content arrives: a region inserted together with
 * its content is announced inconsistently (discovery-panel.tsx does the same).
 * The guards are written as !(n > 0) so an absent count renders nothing.
 */
function CredentialNotice({ stats }: { stats: Stats }) {
  const bad = stats.undecryptable_upstreams
  const pending = stats.upstreams_under_previous_key
  if (!(bad > 0) && !(pending > 0)) return null
  return (
    <div className="mt-8 rounded-lg bg-zinc-50 p-4 ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:shadow-none dark:inset-ring dark:inset-ring-white/5">
      {bad > 0 ? (
        <>
          <p className="text-base/7 font-medium text-pink-600 sm:text-sm/6 dark:text-pink-400">
            {bad === 1 ? 'One upstream credential' : `${bad} upstream credentials`} cannot be read with the current{' '}
            <span className="font-mono">ENCRYPTION_KEY</span>.
          </p>
          <p className="mt-1 max-w-[72ch] text-base/7 text-pretty text-zinc-600 sm:text-sm/6 dark:text-zinc-400">
            PoryMCP refuses to call {bad === 1 ? 'that upstream' : 'those upstreams'}. Restore the previous key, or set{' '}
            <span className="font-mono">ENCRYPTION_KEY_PREVIOUS</span> to it, restart, run{' '}
            <span className="font-mono">porymcp rekey</span>, then restart without it. If the key is gone for good, re-enter
            each credential. See docs/07-security.md.
          </p>
        </>
      ) : (
        <>
          <p className="text-base/7 font-medium text-zinc-950 sm:text-sm/6 dark:text-white">
            Key rotation in progress: {pending === 1 ? 'one credential still uses' : `${pending} credentials still use`} a
            previous key.
          </p>
          <p className="mt-1 max-w-[72ch] text-base/7 text-pretty text-zinc-600 sm:text-sm/6 dark:text-zinc-400">
            Run <span className="font-mono">porymcp rekey</span>, then restart without{' '}
            <span className="font-mono">ENCRYPTION_KEY_PREVIOUS</span>.
          </p>
        </>
      )}
      <p className="mt-2 text-base/7 sm:text-sm/6">
        <Link
          href="/upstreams/"
          className="font-medium text-zinc-950 underline decoration-zinc-950/20 dark:text-white dark:decoration-white/30"
        >
          See the affected upstreams
        </Link>
      </p>
    </div>
  )
}

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([api<Stats>('/stats'), api<{ logs: AuditLog[] }>('/logs?limit=8')])
      .then(([s, l]) => {
        setStats(s)
        setLogs(l.logs)
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  return (
    <>
      <Heading>Overview</Heading>
      <Text className="mt-2 max-w-[56ch] text-pretty">
        This page summarises your virtual keys, upstream connections and recent proxy activity.
      </Text>
      {error ? <Text className="mt-4 text-pink-600 dark:text-pink-400">{error}</Text> : null}
      <div role="status" aria-live="polite">
        {stats ? <CredentialNotice stats={stats} /> : null}
      </div>

      <div className="@container mt-8">
        <div className="grid gap-8 sm:grid-cols-2 xl:grid-cols-4">
          <Stat title="Active virtual keys" value={stats ? String(stats.active_virtual_keys) : LOADING} hint="Not revoked or expired" />
          <Stat title="Calls today" value={stats ? String(stats.calls_today) : LOADING} hint="Last 24 hours" />
          <Stat title="Upstreams" value={stats ? String(stats.upstreams) : LOADING} hint="Registered MCP servers" />
          <Stat
            title="Error rate"
            value={stats ? formatRate(stats.error_rate) : LOADING}
            hint={stats ? `${stats.errors_today} errors today` : undefined}
          />
        </div>
      </div>

      <Subheading className="mt-14">Recent activity</Subheading>
      {logs.length === 0 ? (
        <Text className="mt-4">No proxy traffic yet. Create a virtual key and point a client at its proxy URL.</Text>
      ) : (
        <Table className="mt-4 [--gutter:--spacing(6)] lg:[--gutter:--spacing(10)]">
          <TableHead>
            <TableRow>
              <TableHeader>Time</TableHeader>
              <TableHeader>Virtual key</TableHeader>
              <TableHeader>Method</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader className="text-right">Latency</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.map((log) => (
              <TableRow key={log.id} href="/logs/">
                <TableCell className="tabular-nums text-zinc-500">
                  {new Date(log.timestamp).toLocaleString()}
                </TableCell>
                <TableCell>{log.virtual_key_name}</TableCell>
                <TableCell>{log.tool_name || log.method}</TableCell>
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
    </>
  )
}
