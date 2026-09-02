import * as Headless from '@headlessui/react'
import { ChevronUpDownIcon } from '@heroicons/react/16/solid'
import clsx from 'clsx'
import { controlField, controlFrame } from './primitives'

/**
 * A native `<select>` in the text-control chrome, with a chevron on the right.
 * The keyboard behaviour is the browser's. Unlike Input, the focus outline is
 * drawn at every width.
 */
export function Select({ className, ...props }: { className?: string } & Omit<Headless.SelectProps, 'as' | 'className'>) {
  return (
    <span data-slot="control" className={clsx(className, controlFrame, 'group')}>
      <Headless.Select
        className={clsx(controlField, 'pr-10 sm:pr-9', 'focus:outline-2 focus:-outline-offset-2 focus:outline-focus focus:outline-solid')}
        {...props}
      />
      <ChevronUpDownIcon
        aria-hidden="true"
        className="pointer-events-none absolute top-1/2 right-3 size-5 -translate-y-1/2 text-zinc-500 group-has-data-disabled:text-zinc-600 sm:right-2.5 sm:size-4 dark:text-zinc-400 forced-colors:text-[CanvasText]"
      />
    </span>
  )
}
