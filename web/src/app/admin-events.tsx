'use client'

import { Field, Label } from '@/components/fieldset'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { changedText, eventSentence } from '@/lib/admin-event'
import { api, type AdminEvent } from '@/lib/api'
import { ABSENT } from '@/lib/placeholder'
import { useEffect, useState } from 'react'

/**
 * AdminEvents is the Admin activity section of the Logs page: the 50 most
 * recent management-plane changes, newest first, narrowed by resource type.
 *
 * Every cell is a server-composed field drawn as text by named key; details is
 * never rendered as JSON. Rows take no click handler, so the table adds no
 * keyboard gap. Nothing renders below the filter until the first response
 * settles, so the empty copy cannot flash a false negative on first paint;
 * loaded never goes back to false, so a filter change replaces the rows when
 * its answer lands. A failed re-fetch shows the error and keeps the rows it
 * had, as the proxy table above does. remote_addr renders verbatim: the
 * server writes the literal "unknown" when it could not parse the socket
 * address, and that is a value the row has, not one it lacks.
 */
export function AdminEvents() {
  const [events, setEvents] = useState<AdminEvent[]>([])
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')
  const [resourceType, setResourceType] = useState('')

  useEffect(() => {
    const q = new URLSearchParams()
    q.set('limit', '50')
    if (resourceType) q.set('resource_type', resourceType)
    api<{ admin_events: AdminEvent[]; next_cursor: string }>(`/admin-events?${q}`)
      .then((r) => {
        setEvents(r.admin_events)
        setLoaded(true)
      })
      .catch((e: Error) => setError(e.message))
  }, [resourceType])

  return (
    <>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        Changes made with the admin key, newest first. The 50 most recent are shown. A request that was refused is not
        recorded here.
      </p>
      {error ? <p className="mt-4 text-base/7 text-pink-600 sm:text-sm/6 dark:text-pink-400">{error}</p> : null}

      <div className="mt-8 max-w-xs">
        <Field>
          <Label>Resource</Label>
          <Select name="resource_type" value={resourceType} onChange={(e) => setResourceType(e.target.value)}>
            <option value="">All resources</option>
            <option value="upstream">Upstreams</option>
            <option value="group">Groups</option>
            <option value="virtual_key">Virtual keys</option>
          </Select>
        </Field>
      </div>

      {!loaded ? null : events.length === 0 ? (
        <p className="mt-10 text-base/7 text-zinc-500 sm:text-sm/6">
          {resourceType ? 'No matching changes.' : 'No changes recorded yet.'}
        </p>
      ) : (
        <Table className="mt-8 [--gutter:--spacing(6)] lg:[--gutter:--spacing(10)]">
          <TableHead>
            <TableRow>
              <TableHeader>Time</TableHeader>
              <TableHeader>Event</TableHeader>
              <TableHeader>Details</TableHeader>
              <TableHeader>From</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {events.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="tabular-nums text-zinc-500">{new Date(e.timestamp).toLocaleString()}</TableCell>
                <TableCell>{eventSentence(e)}</TableCell>
                <TableCell>{changedText(e) || ABSENT}</TableCell>
                <TableCell className="font-mono">{e.remote_addr}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  )
}
