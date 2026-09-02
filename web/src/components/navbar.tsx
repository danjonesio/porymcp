'use client'

import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { Link } from './link'
import { focusRing, TouchTarget } from './primitives'

/** The mobile header bar (below `lg`). Sections sit in a row; the spacer pushes them apart. */
export function Navbar({ className, ...props }: React.ComponentPropsWithoutRef<'nav'>) {
  return <nav className={clsx(className, 'flex flex-1 items-center gap-4 py-2.5')} {...props} />
}

export function NavbarSection({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return <div className={clsx(className, 'flex items-center gap-3')} {...props} />
}

export function NavbarSpacer({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return <div aria-hidden="true" className={clsx(className, '-ml-4 flex-1')} {...props} />
}

/**
 * Icon-only here, so the accessible name is the caller's `aria-label`. The
 * icon is sized off `data-slot="icon"`, which Heroicons emit themselves.
 */
const item = clsx(
  'relative flex items-center gap-3',
  'min-w-0 rounded-lg p-2',
  'cursor-default text-left text-base/6 font-medium sm:text-sm/5',
  'text-zinc-950 dark:text-white',
  '*:data-[slot=icon]:size-6 *:data-[slot=icon]:shrink-0 sm:*:data-[slot=icon]:size-5',
  '*:data-[slot=icon]:text-zinc-500 dark:*:data-[slot=icon]:text-zinc-400',
  'data-active:bg-zinc-950/5 data-hover:bg-zinc-950/5 dark:data-active:bg-white/5 dark:data-hover:bg-white/5',
  'data-hover:*:data-[slot=icon]:text-zinc-950 data-active:*:data-[slot=icon]:text-zinc-950',
  'dark:data-hover:*:data-[slot=icon]:text-white dark:data-active:*:data-[slot=icon]:text-white',
  focusRing
)

type NavbarItemProps = {
  ref?: React.Ref<HTMLAnchorElement | HTMLButtonElement>
  className?: string
  children: React.ReactNode
} & (
  | ({ href: string } & Omit<React.ComponentPropsWithoutRef<typeof Link>, 'href' | 'as' | 'type' | 'className' | 'children'>)
  | ({ href?: never } & Omit<Headless.ButtonProps, 'as' | 'className' | 'children'>)
)

/** A link when it has `href`, a Headless button otherwise. Accepts a ref so Headless can render it via `as=`. */
export function NavbarItem({ ref, className, children, ...props }: NavbarItemProps) {
  const classes = clsx(className, item)
  if (props.href !== undefined) {
    return (
      <Link ref={ref as React.Ref<HTMLAnchorElement>} className={classes} {...props}>
        <TouchTarget />
        {children}
      </Link>
    )
  }
  return (
    <Headless.Button ref={ref as React.Ref<HTMLButtonElement>} className={classes} {...props}>
      <TouchTarget />
      {children}
    </Headless.Button>
  )
}
