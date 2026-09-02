'use client'

import * as Headless from '@headlessui/react'
import { Bars3Icon, XMarkIcon } from '@heroicons/react/20/solid'
import clsx from 'clsx'
import { motion } from 'motion/react'
import { useState } from 'react'
import { NavbarItem } from './navbar'

/** The rail's width and the content offset that matches it. */
const RAIL = 'w-64'
const RAIL_OFFSET = 'lg:pl-64'

/** The surface treatment shared by the drawer card and the desktop content card: a lifted white card with a hairline; in dark, a lighter panel with an inset ring instead of a shadow. */
const card = clsx('rounded-lg bg-white shadow-xs', 'ring-1 ring-zinc-950/5', 'dark:bg-zinc-900 dark:ring-white/10')

/**
 * The drawer that holds the sidebar below `lg`. A Headless Dialog, so it traps
 * focus and closes on Escape and backdrop; a SidebarItem inside it is a
 * CloseButton, so navigating closes it too.
 */
function Drawer({ open, onClose, children }: React.PropsWithChildren<{ open: boolean; onClose: () => void }>) {
  return (
    <Headless.Dialog open={open} onClose={onClose} className="lg:hidden">
      <Headless.DialogBackdrop
        transition
        className={clsx(
          'fixed inset-0 bg-black/30',
          'transition-opacity data-closed:opacity-0',
          'data-enter:duration-300 data-enter:ease-out data-leave:duration-200 data-leave:ease-in'
        )}
      />
      <Headless.DialogPanel
        transition
        className={clsx(
          'fixed inset-y-0 left-0 w-full max-w-80 p-2',
          'transition-transform duration-300 ease-in-out data-closed:-translate-x-full'
        )}
      >
        <div className={clsx('flex h-full flex-col', card)}>
          <Headless.CloseButton as={NavbarItem} aria-label="Close navigation" className="mx-4 mt-3 -mb-3 self-start">
            <XMarkIcon />
          </Headless.CloseButton>
          {children}
        </div>
      </Headless.DialogPanel>
    </Headless.Dialog>
  )
}

/**
 * The application shell. From `lg` the sidebar is a fixed 16rem rail
 * (`layoutScroll` so the current-page indicator measures correctly while the
 * rail scrolls) and the content sits in a card; below `lg` there is a header
 * with a hamburger and the navbar, and the same sidebar node in the drawer.
 * `svh` on purpose: `dvh` would reflow the shell as a phone's browser chrome
 * collapses.
 */
export function SidebarLayout({
  navbar,
  sidebar,
  children,
}: React.PropsWithChildren<{ navbar: React.ReactNode; sidebar: React.ReactNode }>) {
  const [drawerOpen, setDrawerOpen] = useState(false)
  return (
    <div className={clsx('relative isolate flex min-h-svh w-full max-lg:flex-col', 'bg-white lg:bg-zinc-100 dark:bg-zinc-900 dark:lg:bg-zinc-950')}>
      <motion.div layoutScroll className={clsx('fixed inset-y-0 left-0', RAIL, 'max-lg:hidden')}>
        {sidebar}
      </motion.div>

      <Drawer open={drawerOpen} onClose={() => setDrawerOpen(false)}>
        {sidebar}
      </Drawer>

      <header className={clsx('flex items-center px-4', 'lg:hidden')}>
        <NavbarItem className="my-2.5" onClick={() => setDrawerOpen(true)} aria-label="Open navigation">
          <Bars3Icon />
        </NavbarItem>
        <div className="min-w-0 grow">{navbar}</div>
      </header>

      <main className={clsx('flex flex-1 flex-col pb-2', 'lg:min-w-0 lg:pt-2 lg:pr-2', RAIL_OFFSET)}>
        <div className={clsx('grow p-6 lg:p-10', 'lg:rounded-lg lg:bg-white dark:lg:bg-zinc-900', 'lg:shadow-xs lg:ring-1 lg:ring-zinc-950/5 dark:lg:ring-white/10')}>
          <div className="mx-auto w-full max-w-6xl">{children}</div>
        </div>
      </main>
    </div>
  )
}
