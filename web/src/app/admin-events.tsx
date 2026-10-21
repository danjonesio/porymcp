'use client'

import clsx from 'clsx'
import { useState } from 'react'
import { Field, Label } from '@/components/fieldset'
import { errorLine } from '@/components/primitives'
import { Select } from '@/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/table'
import { changedText, eventSentence, fromText } from '@/lib/admin-event'
import type { AdminEvent } from '@/lib/api'
import { LOAD_MORE_CHANGES } from '@/lib/logs-view'
import { ABSENT } from '@/lib/placeholder'
import { useCursorPages } from '@/lib/use-cursor-pages'
import { LoadMore } from './load-more'

/**
 * AdminEvents is the Admin activity section of the Logs page: management-plane
 * changes, newest first, 50 at a time with Load more (PORM-20), narrowed by
 * resource type.
 *
 * Every cell is a server-composed field drawn as text by named key; details is
 * never rendered as JSON. Rows take no click handler, so the table adds no
 * keyboard gap. useCursorPages owns the rows: the empty copy, in LoadMore's
 * status line, shows only once the current filter has answered with nothing,
 * so it cannot flash a false negative on first paint or after a failed fetch,
 * and an answer for a previous filter never lands under the new one. A failed
 * re-fetch shows the error and keeps the rows it had, as the proxy table above
 * does. remote_addr renders verbatim: the server writes the literal "unknown"
 * when it could not parse the socket address, and that is a value the row has,
 * not one it lacks. A row with no
 * address at all (a token refresh the proxy made on its own, PORM-139) shows
 * its actor instead: fromText.
 */
export function AdminEvents() {
  const [resourceType, setResourceType] = useState('')
  const query = resourceType ? new URLSearchParams({ resource_type: resourceType }).toString() : ''
  const pages = useCursorPages<AdminEvent>('/admin-events', query)

  return (
    <>
      <p className="mt-2 max-w-[56ch] text-pretty text-base/7 text-zinc-500 sm:text-sm/6">
        Changes made with the admin key, newest first. A request that was refused is not recorded here.
      </p>
      {pages.error ? (
        <p role="alert" className={clsx('mt-4', errorLine)}>
          {pages.error}
        </p>
      ) : null}

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

      {pages.rows.length === 0 ? null : (
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
            {pages.rows.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="tabular-nums text-zinc-500">{new Date(e.timestamp).toLocaleString()}</TableCell>
                <TableCell>{eventSentence(e)}</TableCell>
                <TableCell>{changedText(e) || ABSENT}</TableCell>
                <TableCell className="font-mono">{fromText(e)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <LoadMore
        label={LOAD_MORE_CHANGES}
        noun="change"
        empty={resourceType ? 'No matching changes.' : 'No changes recorded yet.'}
        pages={pages}
      />
    </>
  )
}
