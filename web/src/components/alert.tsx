import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { Text } from './text'

/**
 * A short confirmation dialog: the same Headless machinery as Dialog (focus
 * trap, Escape and outside-click both reach `onClose`, so a click-through can
 * never confirm), a lighter backdrop, a narrower panel that is always a
 * centred card, and centred copy on a phone.
 */
const backdrop = clsx(
  'fixed inset-0',
  'bg-zinc-950/15 dark:bg-zinc-950/50',
  'transition-opacity duration-100 ease-out data-closed:opacity-0 data-leave:ease-in'
)
const panel = clsx(
  'my-auto w-full min-w-0 shrink-0 sm:my-0 sm:max-w-md',
  'rounded-2xl p-8 sm:p-6',
  'bg-white shadow-lg ring-1 ring-zinc-950/10 dark:bg-zinc-900 dark:ring-white/10 forced-colors:outline',
  'transition duration-100 ease-out will-change-transform data-leave:ease-in',
  'data-closed:scale-95 data-closed:opacity-0'
)

export function Alert({
  className,
  children,
  ...props
}: { className?: string; children: React.ReactNode } & Omit<Headless.DialogProps, 'as' | 'className'>) {
  return (
    <Headless.Dialog {...props}>
      <Headless.DialogBackdrop transition className={backdrop} />
      <div className={clsx('fixed inset-0 w-screen overflow-y-auto', 'flex flex-col items-center px-8 pt-6 sm:p-4')}>
        {/* The same container as the dialog: from sm the panel sits a quarter of the way down the free space (1:3); on a phone it is centred below a 6-unit top inset. */}
        <div aria-hidden="true" className="hidden shrink sm:block sm:grow" />
        <Headless.DialogPanel transition className={clsx(className, panel)}>
          {children}
        </Headless.DialogPanel>
        <div aria-hidden="true" className="hidden shrink sm:block sm:grow-3" />
      </div>
    </Headless.Dialog>
  )
}

export function AlertTitle({ className, ...props }: { className?: string } & Omit<Headless.DialogTitleProps, 'as' | 'className'>) {
  return (
    <Headless.DialogTitle
      className={clsx(
        className,
        'text-base/6 font-semibold text-balance sm:text-sm/6',
        'text-center sm:text-left',
        'text-zinc-950 dark:text-white'
      )}
      {...props}
    />
  )
}

export function AlertDescription({
  className,
  ...props
}: { className?: string } & Omit<Headless.DescriptionProps<typeof Text>, 'as' | 'className'>) {
  return <Headless.Description as={Text} className={clsx(className, 'mt-2 text-pretty', 'text-center sm:text-left')} {...props} />
}

/** Reverse-stacked and full-width on a phone so the destructive action is last; right-aligned from `sm:`. */
export function AlertActions({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return (
    <div
      className={clsx(
        className,
        'mt-6 sm:mt-4',
        'flex flex-col-reverse items-center gap-3 sm:flex-row sm:justify-end',
        '*:w-full sm:*:w-auto'
      )}
      {...props}
    />
  )
}
