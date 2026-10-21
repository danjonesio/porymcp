import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, api, requestErrorMessage } from '@/lib/api'
import {
  afterMoreFailure,
  appended,
  emptyPages,
  exposedEnd,
  firstPage,
  nextRequest,
  PAGED_FIELD,
  type PageEnd,
  type PagedPath,
  type Pages,
  showEmpty,
  startQuery,
} from '@/lib/cursor-pages'
import { pagePath } from '@/lib/logs-view'

export type CursorPages<T> = {
  rows: T[]
  /** True only when the current query answered with no rows. */
  showEmpty: boolean
  /** A failed first page: the previous rows stay under it. */
  error: string
  /** A failed Load more, shown under the control. */
  moreError: string
  /** How the current query's rows ended; null while they are not its answer yet. */
  end: PageEnd | null
  busy: boolean
  loadMore: () => void
}

/**
 * The one owner of a paged audit table's rows, for Proxy calls and Admin
 * activity alike (PORM-20). The rules it applies are in cursor-pages.ts, where
 * `node --test` reaches them; this only keeps state and sends requests.
 *
 * A new `query` (any filter change) starts a generation: `seq` moves on, so
 * every answer still in flight for an older query, a first page or a Load
 * more, is dropped when it lands. A null query sends nothing: the Custom
 * period has no usable start. A Load more sends the frozen query that produced
 * the rows plus their cursor, read from `next`, which is written in the same
 * callback that applies an answer; a press while a page is in flight is
 * dropped. The control draws itself as busy meanwhile; `inFlight` is the
 * guard that does not depend on it.
 */
export function useCursorPages<T>(path: PagedPath, query: string | null): CursorPages<T> {
  const [pages, setPages] = useState<Pages<T>>(emptyPages)
  const [error, setError] = useState('')
  const [moreError, setMoreError] = useState('')
  const [busy, setBusy] = useState(false)
  const seq = useRef(0)
  const inFlight = useRef(false)
  const next = useRef<{ query: string; cursor: string } | null>(null)

  useEffect(() => {
    const mine = ++seq.current
    inFlight.current = false
    next.current = null
    setPages(startQuery)
    setError('')
    setMoreError('')
    setBusy(false)
    if (query === null) return
    api<Record<string, unknown>>(pagePath(path, query, ''))
      .then((body) => {
        if (seq.current !== mine) return
        const p = firstPage(query, rowsOf<T>(body, path), cursorOf(body))
        next.current = nextRequest(p, query)
        setPages(p)
      })
      .catch((err: unknown) => {
        if (seq.current === mine) setError(requestErrorMessage(err))
      })
  }, [path, query])

  const loadMore = useCallback(() => {
    const req = next.current
    if (inFlight.current || req === null) return
    inFlight.current = true
    setBusy(true)
    setMoreError('')
    const mine = seq.current
    api<Record<string, unknown>>(pagePath(path, req.query, req.cursor))
      .then((body) => {
        if (seq.current !== mine) return
        const rows = rowsOf<T>(body, path)
        const cursor = cursorOf(body)
        setPages((p) => appended(p, rows, cursor))
        next.current = cursor ? { query: req.query, cursor } : null
        inFlight.current = false
        setBusy(false)
      })
      .catch((err: unknown) => {
        if (seq.current !== mine) return
        const status = err instanceof ApiError ? err.status : undefined
        setMoreError(requestErrorMessage(err))
        setPages((p) => afterMoreFailure(p, status))
        if (status === 400) next.current = null
        inFlight.current = false
        setBusy(false)
      })
  }, [path])

  return {
    rows: pages.rows,
    showEmpty: showEmpty(pages, query),
    error,
    moreError,
    end: exposedEnd(pages, query),
    busy,
    loadMore,
  }
}

function rowsOf<T>(body: Record<string, unknown>, path: PagedPath): T[] {
  const rows = body[PAGED_FIELD[path]]
  return Array.isArray(rows) ? (rows as T[]) : []
}

function cursorOf(body: Record<string, unknown>): string {
  return typeof body.next_cursor === 'string' ? body.next_cursor : ''
}
