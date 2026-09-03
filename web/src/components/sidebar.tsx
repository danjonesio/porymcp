'use client'

import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { LayoutGroup, motion } from 'motion/react'
import { useId } from 'react'
import { Link } from './link'
import { focusRing, TouchTarget } from './primitives'

/** The navigation column: a header, a scrolling body and a footer, each a stack of sections. */
export function Sidebar({ className, ...props }: React.ComponentPropsWithoutRef<'nav'>) {
  return <nav className={clsx(className, 'flex h-full min-h-0 flex-col')} {...props} />
}

const hairline = 'border-zinc-950/5 dark:border-white/5'
const sectionGap = '[&>[data-slot=section]+[data-slot=section]]:mt-2.5'

export function SidebarHeader({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return <div className={clsx(className, 'flex flex-col p-4', 'border-b', hairline, sectionGap)} {...props} />
}

export function SidebarBody({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return (
    <div
      className={clsx(className, 'flex flex-1 flex-col overflow-y-auto p-4', '[&>[data-slot=section]+[data-slot=section]]:mt-8')}
      {...props}
    />
  )
}

export function SidebarFooter({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return <div className={clsx(className, 'flex flex-col p-4', 'border-t', hairline, sectionGap)} {...props} />
}

/**
 * A group of items. The `LayoutGroup` keyed on `useId()` matters: below `lg`
 * the same sidebar node is mounted twice at once (the hidden desktop rail and
 * the drawer), and both render the current-page indicator with one
 * `layoutId`: the group keeps the two animations in separate scopes so the
 * indicator never flies between the two trees when the drawer opens.
 */
export function SidebarSection({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  const id = useId()
  return (
    <LayoutGroup id={id}>
      <div data-slot="section" className={clsx(className, 'flex flex-col gap-0.5')} {...props} />
    </LayoutGroup>
  )
}

const item = clsx(
  'flex w-full min-w-0 items-center gap-3 rounded-lg px-2 py-2.5 sm:py-2',
  'cursor-default text-left text-base/6 font-medium sm:text-sm/5',
  'text-zinc-950 dark:text-white',
  '*:data-[slot=icon]:size-6 *:data-[slot=icon]:shrink-0 sm:*:data-[slot=icon]:size-5',
  '*:data-[slot=icon]:text-zinc-500 dark:*:data-[slot=icon]:text-zinc-400',
  'data-active:bg-zinc-950/5 data-hover:bg-zinc-950/5 dark:data-active:bg-white/5 dark:data-hover:bg-white/5',
  'data-hover:*:data-[slot=icon]:text-zinc-950 data-active:*:data-[slot=icon]:text-zinc-950 data-current:*:data-[slot=icon]:text-zinc-950',
  'dark:data-hover:*:data-[slot=icon]:text-white dark:data-active:*:data-[slot=icon]:text-white dark:data-current:*:data-[slot=icon]:text-white',
  focusRing
)

type SidebarItemProps = {
  ref?: React.Ref<HTMLAnchorElement | HTMLButtonElement>
  current?: boolean
  className?: string
  children: React.ReactNode
} & (
  | ({ href: string } & Omit<React.ComponentPropsWithoutRef<typeof Link>, 'href' | 'as' | 'type' | 'className' | 'children'>)
  | ({ href?: never } & Omit<Headless.ButtonProps, 'as' | 'className' | 'children'>)
)

/**
 * One row of the sidebar. With `href` it is a Headless CloseButton rendered as
 * a Link: that is what dismisses the mobile drawer when a nav item is tapped
 * (on the desktop rail, outside any Dialog, CloseButton is a no-op). Without
 * `href` it is a Headless button, which is how the account menu mounts its
 * trigger (`DropdownButton as={SidebarItem}`); the ref and the injected props
 * travel through. `current` paints the indicator beside the row.
 */
export function SidebarItem({ ref, current, className, children, ...props }: SidebarItemProps) {
  const classes = clsx(className, item)
  const currentAttr = current ? 'true' : undefined
  const indicator = current ? (
    <motion.span
      layoutId="sidebar-current"
      className={clsx('absolute top-1/2 -left-4 h-5 w-0.5 -translate-y-1/2 rounded-full', 'bg-zinc-950 dark:bg-white')}
    />
  ) : null
  if (props.href !== undefined) {
    return (
      <span className="relative">
        {indicator}
        <Headless.CloseButton as={Link} ref={ref as React.Ref<HTMLAnchorElement>} className={classes} data-current={currentAttr} {...props}>
          <TouchTarget />
          {children}
        </Headless.CloseButton>
      </span>
    )
  }
  return (
    <span className="relative">
      {indicator}
      {/* A button, not a link: forced-colors mode boxes it like every other button. */}
      <Headless.Button
        ref={ref as React.Ref<HTMLButtonElement>}
        className={clsx(classes, 'forced-colors:outline')}
        data-current={currentAttr}
        {...props}
      >
        <TouchTarget />
        {children}
      </Headless.Button>
    </span>
  )
}

export function SidebarLabel({ className, ...props }: React.ComponentPropsWithoutRef<'span'>) {
  return <span className={clsx(className, 'truncate')} {...props} />
}
