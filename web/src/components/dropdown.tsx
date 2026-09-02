'use client'

import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { Link } from './link'

/** A Headless menu. Keyboard is Headless's: Enter/Space/↓ open, ↑/↓ move, Home/End jump, typeahead, Escape closes and restores focus. */
export function Dropdown(props: Headless.MenuProps) {
  return <Headless.Menu {...props} />
}

/**
 * The trigger. `as` is required: the one call site renders it as a sidebar
 * row, and there is no sensible default now that Button needs a variant.
 */
export function DropdownButton<T extends React.ElementType>(props: { as: T } & Omit<Headless.MenuButtonProps<T>, 'as'>) {
  // Callers are typed by this signature. Headless's own generic cannot be
  // re-narrowed with a required `as` without tripping its ref typing, so the
  // element is rendered through an untyped alias.
  const Trigger = Headless.MenuButton as React.ElementType
  return <Trigger {...props} />
}

/** The floating panel, anchored by Headless (`anchor="top start"` for the sidebar footer). */
export function DropdownMenu({
  anchor = 'bottom',
  className,
  ...props
}: { className?: string } & Omit<Headless.MenuItemsProps, 'as' | 'className'>) {
  return (
    <Headless.MenuItems
      {...props}
      transition
      anchor={anchor}
      className={clsx(
        className,
        'isolate w-max min-w-48 rounded-xl bg-white/75 p-1 shadow-lg ring-1 ring-zinc-950/10 backdrop-blur-xl focus:outline-hidden transition duration-100 ease-in [--anchor-gap:--spacing(2)] [--anchor-padding:--spacing(1)] data-closed:scale-95 data-closed:opacity-0 data-leave:ease-in dark:bg-zinc-800/75 dark:ring-white/10 forced-colors:outline'
      )}
    />
  )
}

const itemClasses = clsx(
  'group flex w-full cursor-default items-center gap-x-3 rounded-lg px-3.5 py-2.5 text-left text-base/6 text-zinc-950 focus:outline-hidden sm:px-3 sm:py-1.5 sm:text-sm/6 dark:text-white',
  'data-focus:bg-focus data-focus:text-white',
  '*:data-[slot=icon]:size-5 *:data-[slot=icon]:shrink-0 *:data-[slot=icon]:text-zinc-500 sm:*:data-[slot=icon]:size-4 dark:*:data-[slot=icon]:text-zinc-400 data-focus:*:data-[slot=icon]:text-white',
  'forced-colors:data-focus:bg-[Highlight] forced-colors:data-focus:text-[HighlightText]'
)

type ItemProps = { className?: string; children: React.ReactNode } & (
  | ({ href: string } & Omit<React.ComponentPropsWithoutRef<typeof Link>, 'href' | 'as' | 'className' | 'children'>)
  | ({ href?: never } & Omit<React.ComponentPropsWithoutRef<'button'>, 'className' | 'children'>)
)

/** One row of the menu: a link when it has `href`, a button otherwise. Focus paints a solid fill. */
export function DropdownItem({ className, children, ...props }: ItemProps) {
  const classes = clsx(className, itemClasses)
  if (props.href !== undefined) {
    return (
      <Headless.MenuItem as={Link} className={classes} {...props}>
        {children}
      </Headless.MenuItem>
    )
  }
  return (
    <Headless.MenuItem as="button" type="button" className={classes} {...props}>
      {children}
    </Headless.MenuItem>
  )
}

export function DropdownLabel({ className, ...props }: React.ComponentPropsWithoutRef<'span'>) {
  return <span data-slot="label" className={clsx(className, 'truncate')} {...props} />
}

export function DropdownDivider({ className, ...props }: { className?: string } & Omit<Headless.MenuSeparatorProps, 'as' | 'className'>) {
  return (
    <Headless.MenuSeparator
      className={clsx(className, 'mx-3.5 my-1 h-px bg-zinc-950/5 sm:mx-3 dark:bg-white/10 forced-colors:bg-[CanvasText]')}
      {...props}
    />
  )
}
