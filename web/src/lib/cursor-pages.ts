/**
 * The paging rules both Logs tables follow (PORM-20), kept apart from the hook
 * in use-cursor-pages.ts so `node --test` can reach them. A page set is tagged
 * with the query that produced it, and the rows, the Load more control and the
 * count line belong to that query only: an answer for one filter is never
 * appended to, counted with or summarised as another filter's rows.
 */

/** How a listing's last answer ended: another page waits, the walk ended, or the server refused the cursor. */
export type PageEnd = 'more' | 'last' | 'refused'

export type Pages<T> = {
  /** The query whose answer the rows are; null while a newer query has no answer yet. */
  query: string | null
  rows: T[]
  cursor: string
  end: PageEnd
}

/** The list routes that page, and the envelope field each answers in (the e2e/api.ts LISTS shape). */
export const PAGED_FIELD = { '/logs': 'logs', '/admin-events': 'admin_events' } as const
export type PagedPath = keyof typeof PAGED_FIELD

export function emptyPages<T>(): Pages<T> {
  return { query: null, rows: [], cursor: '', end: 'last' }
}

/** A new query started: the rows stay on screen, but nothing belongs to a query until it answers. */
export function startQuery<T>(p: Pages<T>): Pages<T> {
  return { ...p, query: null, cursor: '', end: 'last' }
}

/** A query's first answer replaces the rows. */
export function firstPage<T>(query: string, rows: T[], next: string): Pages<T> {
  return { query, rows, cursor: next, end: next ? 'more' : 'last' }
}

/** A Load more's answer is added below the rows already shown. */
export function appended<T>(p: Pages<T>, rows: T[], next: string): Pages<T> {
  return { ...p, rows: [...p.rows, ...rows], cursor: next, end: next ? 'more' : 'last' }
}

/**
 * A failed Load more. A 400 is a cursor the server refuses: sending it again
 * gets the same answer, so the control goes and nothing can loop. Any other
 * failure keeps the cursor for a press that retries it; nothing retries on
 * its own.
 */
export function afterMoreFailure<T>(p: Pages<T>, status: number | undefined): Pages<T> {
  return status === 400 ? { ...p, cursor: '', end: 'refused' } : p
}

/** How the rows on screen ended, or null when they are not the current query's answer. */
export function exposedEnd<T>(p: Pages<T>, query: string | null): PageEnd | null {
  return p.query !== null && p.query === query ? p.end : null
}

/**
 * True only when the current query answered with no rows. A failed first
 * page, or a query still waiting for its answer, shows no empty copy: on an
 * audit view "No matching log entries." would read as "nothing happened".
 */
export function showEmpty<T>(p: Pages<T>, query: string | null): boolean {
  return exposedEnd(p, query) !== null && p.rows.length === 0
}

/** The request a Load more sends: the frozen query that produced the rows, never the live one. */
export function nextRequest<T>(p: Pages<T>, query: string | null): { query: string; cursor: string } | null {
  if (p.query === null || exposedEnd(p, query) !== 'more') return null
  return { query: p.query, cursor: p.cursor }
}
