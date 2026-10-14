'use client'

import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { Link } from './link'

/** A Headless menu. Keyboard is Headless's: Enter/Space/↓ open, ↑/↓ move, Home/End jump, typeahead, Escape closes and restores focus. */
export function Dropdown(props: Headless.MenuProps) {
  return <Headless.Menu {...props} />
}

/**
 * The trigger. `as` is required: the two call sites render it as a sidebar
 * row (the account menu) and as a plain Button (each table row's Actions
 * menu, app/row-actions.tsx), and there is no sensible default now that
 * Button needs a variant.
 */
export function DropdownButton<T extends React.ElementType>(props: { as: T } & Omit<Headless.MenuButtonProps<T>, 'as'>) {
  // Callers are typed by this signature. Headless's own generic cannot be
  // re-narrowed with a required `as` without tripping its ref typing, so the
  // element is rendered through an untyped alias.
  const Trigger = Headless.MenuButton as React.ElementType
  return <Trigger {...props} />
}

/** The floating panel, anchored by Headless (`anchor="top start"` for the sidebar footer, `"bottom end"` for a row's Actions menu). */
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
  'group flex w-full cursor-default items-center gap-x-3 rounded-lg px-3.5 py-2.5 text-left text-base/6 focus:outline-hidden sm:px-3 sm:py-1.5 sm:text-sm/6',
  'data-focus:bg-focus data-focus:text-white',
  '*:data-[slot=icon]:size-5 *:data-[slot=icon]:shrink-0 *:data-[slot=icon]:text-zinc-500 sm:*:data-[slot=icon]:size-4 dark:*:data-[slot=icon]:text-zinc-400 data-focus:*:data-[slot=icon]:text-white',
  'forced-colors:data-focus:bg-[Highlight] forced-colors:data-focus:text-[HighlightText]'
)

// The text colour is a tone, not part of itemClasses, so a destructive item
// never relies on a call-site class winning over the base colour. Focus keeps
// the one focus fill for both tones.
const itemTones = {
  plain: 'text-zinc-950 dark:text-white',
  destructive: 'text-red-600 dark:text-red-400',
}

type ItemProps = { className?: string; destructive?: boolean; children: React.ReactNode } & (
  | ({ href: string } & Omit<React.ComponentPropsWithoutRef<typeof Link>, 'href' | 'as' | 'className' | 'children'>)
  | ({ href?: never } & Omit<React.ComponentPropsWithoutRef<'button'>, 'className' | 'children'>)
)

/**
 * One row of the menu: a link when it has `href`, a button otherwise. Focus
 * paints a solid fill. `destructive` draws the label in red, for Delete.
 */
export function DropdownItem({ className, destructive = false, children, ...props }: ItemProps) {
  const classes = clsx(className, itemClasses, destructive ? itemTones.destructive : itemTones.plain)
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
