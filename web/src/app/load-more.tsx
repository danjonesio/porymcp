'use client'

import { useEffect, useRef } from 'react'
import { Button } from '@/components/button'
import { errorLine } from '@/components/primitives'
import { countLine, LOADING_MORE } from '@/lib/logs-view'
import type { CursorPages } from '@/lib/use-cursor-pages'

/**
 * What sits under a paged audit table (PORM-20): a count line, the failure of
 * the last Load more, and the Load more button while another page waits.
 *
 * The count line stays mounted, empty while the rows are not the current
 * query's answer, so every change to it is announced and it never describes
 * rows fetched for another filter. The button is aria-disabled, not disabled,
 * while a page is in flight: a disabled button drops focus to the page, and a
 * press meanwhile is dropped by useCursorPages. On the last page the button
 * goes; if it held focus, focus would fall to the page body, so it moves to
 * the count line instead.
 */
export function LoadMore<T>({ label, noun, pages }: { label: string; noun: 'call' | 'change'; pages: CursorPages<T> }) {
  const { rows, end, busy, moreError, loadMore } = pages
  const status = useRef<HTMLParagraphElement>(null)
  const pressed = useRef(false)

  useEffect(() => {
    if (end === 'more' || !pressed.current) return
    pressed.current = false
    const active = document.activeElement
    if (active === null || active === document.body) status.current?.focus()
  }, [end])

  function press() {
    pressed.current = true
    loadMore()
  }

  return (
    <div className="mt-6 flex flex-col items-start gap-4">
      <p ref={status} role="status" tabIndex={-1} className="text-base/7 text-zinc-500 tabular-nums outline-hidden sm:text-sm/6">
        {rows.length > 0 ? countLine(rows.length, noun, end) : ''}
      </p>
      {moreError ? (
        <p role="alert" className={errorLine}>
          {moreError}
        </p>
      ) : null}
      {end === 'more' ? (
        <Button type="button" outline aria-disabled={busy} className="aria-disabled:opacity-50" onClick={press}>
          {busy ? LOADING_MORE : label}
        </Button>
      ) : null}
    </div>
  )
}
