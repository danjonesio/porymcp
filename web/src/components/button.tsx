import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { focusRing, TouchTarget } from './primitives'

/**
 * Exactly one look per button: a solid colour, `outline`, or `plain`. Every call
 * site names one, so there is no default to fall back on, and the `?: never`
 * guards keep the three from being combined.
 */
type Variant =
  | { color: 'cyan' | 'red'; outline?: never; plain?: never }
  | { outline: true; color?: never; plain?: never }
  | { plain: true; color?: never; outline?: never }

export type ButtonProps = Variant & { className?: string; children: React.ReactNode } & Omit<
    Headless.ButtonProps,
    'as' | 'className'
  >

/**
 * Shared by every look: the mobile-first size scale, the focus ring, icon
 * sizing off `data-slot="icon"` (which Heroicons emit themselves), and the
 * arrow cursor — buttons here are controls, not links. Borders are inset
 * rings so the padding needs no pixel arithmetic.
 */
const base = clsx(
  'relative isolate inline-flex cursor-default items-center justify-center gap-x-2 rounded-lg px-3.5 py-2.5 text-base/6 font-semibold sm:px-3 sm:py-1.5 sm:text-sm/6',
  '*:data-[slot=icon]:size-5 *:data-[slot=icon]:shrink-0 *:data-[slot=icon]:self-center sm:*:data-[slot=icon]:size-4',
  'data-disabled:opacity-50 data-disabled:shadow-none',
  // The rings above are box-shadows, which forced-colors mode strips; this keeps a boundary there.
  'forced-colors:outline',
  focusRing
)

const looks = {
  cyan: 'bg-cyan-300 text-cyan-950 shadow-sm ring-1 ring-cyan-950/15 ring-inset data-active:bg-cyan-200 data-hover:bg-cyan-200',
  red: 'bg-red-600 text-white shadow-sm ring-1 ring-red-800/60 ring-inset data-active:bg-red-500 data-hover:bg-red-500',
  outline:
    'text-zinc-950 ring-1 ring-zinc-950/10 ring-inset data-active:bg-zinc-950/2.5 data-hover:bg-zinc-950/2.5 dark:text-white dark:ring-white/15 dark:data-active:bg-white/5 dark:data-hover:bg-white/5',
  plain:
    'text-zinc-950 data-active:bg-zinc-950/5 data-hover:bg-zinc-950/5 dark:text-white dark:data-active:bg-white/10 dark:data-hover:bg-white/10',
}

export function Button({ color, outline, plain, className, children, ...props }: ButtonProps) {
  const look = plain ? looks.plain : outline ? looks.outline : looks[color ?? 'cyan']
  return (
    <Headless.Button className={clsx(className, base, look)} {...props}>
      <TouchTarget />
      {children}
    </Headless.Button>
  )
}
