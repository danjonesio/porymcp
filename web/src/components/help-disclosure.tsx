'use client'

import * as Headless from '@headlessui/react'
import { ChevronDownIcon } from '@heroicons/react/16/solid'

/**
 * A one-line question that expands in place into the long answer.
 *
 * PoryMCP's own Headless UI disclosure, and the house pattern for every
 * component in this directory. It is deliberately the dullest possible affordance: a real button
 * that opens on click, Enter and Space and on nothing else — no hover, no
 * focus-open, nothing that fires before the reader asked. The answer expands
 * into a well below it and pushes the rest of the dialog down rather than
 * covering it, so the options it compares stay on screen while it is read.
 *
 * Headless owns `aria-expanded` and `aria-controls`; Escape needs no handling
 * because nothing opens without a deliberate press, and the dialog around this
 * one is welcome to take Escape for itself.
 */
export function HelpDisclosure({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Headless.Disclosure>
      <Headless.DisclosureButton className="group relative flex items-center gap-1 rounded-lg text-base/6 font-medium text-zinc-950 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus sm:text-sm/6 dark:text-white">
        <span
          aria-hidden="true"
          className="absolute top-1/2 left-1/2 size-[max(100%,3rem)] -translate-1/2 pointer-fine:hidden"
        />
        {label}
        <ChevronDownIcon className="size-4 shrink-0 fill-zinc-400 transition-transform group-data-open:rotate-180 dark:fill-zinc-500" />
      </Headless.DisclosureButton>
      <Headless.DisclosurePanel className="mt-3 space-y-3 rounded-xl bg-zinc-950/2.5 p-4 text-base/6 text-pretty text-zinc-500 sm:text-sm/6 dark:bg-white/2.5 dark:text-zinc-400">
        {children}
      </Headless.DisclosurePanel>
    </Headless.Disclosure>
  )
}
