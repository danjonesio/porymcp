'use client'

import clsx from 'clsx'
import { createContext, useContext, useState } from 'react'
import { Link } from './link'

const RowContext = createContext<{ href?: string }>({})

/**
 * The table wrapper the make-responsive skill prescribes: an outer `flow-root`
 * (so a caller's top margin does not collapse out of its parent), a scroller
 * with negative `--gutter` margins that carries the caller's className, and an
 * inline-block inner div that pads by `--gutter` from `sm:` so the table can
 * fill or overflow the scroller. Pages set `--gutter`; it falls back to 2 units.
 */
export function Table({ className, children, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return (
    <div className="flow-root">
      <div {...props} className={clsx(className, '-mx-(--gutter,--spacing(2))', 'overflow-x-auto whitespace-nowrap')}>
        <div className={clsx('inline-block min-w-full align-middle', 'sm:px-(--gutter,--spacing(2))')}>
          <table className={clsx('min-w-full text-left text-sm/6', 'text-zinc-950 dark:text-white')}>{children}</table>
        </div>
      </div>
    </div>
  )
}

export function TableHead({ className, ...props }: React.ComponentPropsWithoutRef<'thead'>) {
  return <thead className={clsx(className, 'text-zinc-500 dark:text-zinc-400')} {...props} />
}

export function TableBody(props: React.ComponentPropsWithoutRef<'tbody'>) {
  return <tbody {...props} />
}

/**
 * A row. With `href` the whole row is one link (see TableCell): it gets a
 * hover wash and draws the focus outline when its link is keyboard-focused —
 * `:focus-visible`, so a mouse click does not paint it.
 */
const linkedRow = clsx(
  'hover:bg-zinc-950/2.5 dark:hover:bg-white/2.5',
  'has-[a:focus-visible]:outline-2 has-[a:focus-visible]:-outline-offset-2 has-[a:focus-visible]:outline-focus',
  'dark:has-[a:focus-visible]:bg-white/2.5'
)

export function TableRow({ href, className, ...props }: { href?: string } & React.ComponentPropsWithoutRef<'tr'>) {
  return (
    <RowContext.Provider value={{ href }}>
      <tr className={clsx(className, href && linkedRow)} {...props} />
    </RowContext.Provider>
  )
}

/** Cells use the gutter for their outer padding only on a phone; from `sm:` the inner wrapper carries it. */
const edgePadding = clsx('first:pl-(--gutter,--spacing(2))', 'last:pr-(--gutter,--spacing(2))', 'sm:first:pl-1 sm:last:pr-1')

export function TableHeader({ className, ...props }: React.ComponentPropsWithoutRef<'th'>) {
  return (
    <th
      className={clsx(className, 'px-4 py-2 font-medium', 'border-b border-b-zinc-950/10 dark:border-b-white/10', edgePadding)}
      {...props}
    />
  )
}

/**
 * A cell. In a linked row every cell carries an absolutely-inset link so the
 * whole row is clickable, and only the first cell's link is tabbable — one
 * tab stop per row. The ref callback re-renders once the cell is mounted so
 * `previousElementSibling` can be read; a counter would reset per render.
 */
export function TableCell({ className, children, ...props }: React.ComponentPropsWithoutRef<'td'>) {
  const { href } = useContext(RowContext)
  const [cell, setCell] = useState<HTMLTableCellElement | null>(null)
  return (
    <td
      ref={href ? setCell : undefined}
      className={clsx(className, 'relative p-4', 'border-b border-zinc-950/5 dark:border-white/5', edgePadding)}
      {...props}
    >
      {href ? <Link href={href} tabIndex={cell?.previousElementSibling === null ? 0 : -1} className="absolute inset-0 focus:outline-hidden" /> : null}
      {children}
    </td>
  )
}
