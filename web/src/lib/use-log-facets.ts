import { useEffect, useRef, useState } from 'react'
import { api, type LogFacets } from '@/lib/api'
import { FACET_WAIT_MS, type FacetAnswer, facetFetchDue, facetsFor, listErrorMessage, SLOW_FACETS } from '@/lib/logs-view'

/**
 * The facet lists for the Logs page (PORM-149): fetched once per facet query,
 * when the rows' first answer lands or FACET_WAIT_MS after the facet query
 * changed, whichever comes first, and aborted on a new facet query and on
 * unmount. A fast page so lands before the facet walk takes the one SQLite
 * connection, and a slow page shares its deadline window with the walk
 * instead of running back to back with it. The start rule is facetFetchDue in
 * logs-view.ts, where `node --test` reaches it.
 *
 * `held` is the request in flight or done for one facet query, so a Method or
 * Tool pick, which starts a new list generation under the same facet query,
 * neither aborts nor refetches, and a failed request is not retried until the
 * key, period or status changes or the page reloads. `waitedFor` is the facet
 * query whose wait has ended: a boolean reset by the [fq] effect would still
 * read true in the render where fq changes, and start the next fetch at once.
 * The [fq] cleanup clears it, so a Custom period that comes back to an
 * earlier facet query within the wait waits again.
 * Under StrictMode the [fq] cleanup runs between the two mounts, so the first
 * request is aborted and the second mount sends one.
 */
export function useLogFacets(fq: string | null, listAnswered: boolean): { facets: LogFacets | null; error: string } {
  const held = useRef<{ fq: string; ctrl: AbortController } | null>(null)
  const [answer, setAnswer] = useState<FacetAnswer | null>(null)
  const [waitedFor, setWaitedFor] = useState<string | null>(null)
  const waited = fq !== null && waitedFor === fq

  useEffect(() => {
    const timer = fq === null ? undefined : setTimeout(() => setWaitedFor(fq), FACET_WAIT_MS)
    return () => {
      clearTimeout(timer)
      held.current?.ctrl.abort()
      held.current = null
      setWaitedFor(null)
    }
  }, [fq])

  useEffect(() => {
    if (fq === null || !facetFetchDue(held.current?.fq ?? null, fq, listAnswered, waited)) return
    const ctrl = new AbortController()
    held.current = { fq, ctrl }
    api<LogFacets>(`/logs/facets?${fq}`, { signal: ctrl.signal })
      .then((facets) => {
        if (ctrl.signal.aborted) return
        setAnswer({ fq, facets, error: '' })
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return
        setAnswer({ fq, facets: null, error: listErrorMessage(err, SLOW_FACETS) })
      })
  }, [fq, listAnswered, waited])

  return facetsFor(answer, fq)
}
