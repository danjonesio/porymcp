import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { Text } from './text'

const widths = {
  lg: 'sm:max-w-lg',
  '2xl': 'sm:max-w-2xl',
}

/**
 * A modal dialog. Headless owns the focus trap, initial focus, focus restore,
 * scroll lock, Escape and outside-click: `onClose` is passed straight through
 * so every dismissal path reaches the caller. On a phone the panel is a
 * bottom sheet that slides up; from `sm:` it is a centred card that scales in.
 */
const backdrop = clsx(
  'fixed inset-0',
  'bg-zinc-950/25 dark:bg-zinc-950/50',
  'transition-opacity duration-100 ease-out data-closed:opacity-0 data-leave:ease-in'
)
const panel = clsx(
  'mt-auto w-full min-w-0 shrink-0 sm:mt-0',
  'rounded-t-3xl p-(--gutter) [--gutter:--spacing(8)] sm:rounded-2xl',
  'bg-white shadow-lg ring-1 ring-zinc-950/10 dark:bg-zinc-900 dark:ring-white/10 forced-colors:outline',
  'transition duration-100 ease-out will-change-transform data-leave:ease-in',
  'data-closed:translate-y-12 data-closed:opacity-0 sm:data-closed:translate-y-0 sm:data-closed:scale-95'
)

export function Dialog({
  size = 'lg',
  className,
  children,
  ...props
}: { size?: keyof typeof widths; className?: string; children: React.ReactNode } & Omit<
  Headless.DialogProps,
  'as' | 'className'
>) {
  return (
    <Headless.Dialog {...props}>
      <Headless.DialogBackdrop transition className={backdrop} />
      <div className={clsx('fixed inset-0 w-screen overflow-y-auto', 'flex flex-col items-center pt-6 sm:p-4')}>
        {/* From sm: the panel sits a quarter of the way down the free space (1:3), not centred; both spacers give way when the panel is taller than the viewport. */}
        <div aria-hidden="true" className="hidden shrink sm:block sm:grow" />
        <Headless.DialogPanel transition className={clsx(className, widths[size], panel)}>
          {children}
        </Headless.DialogPanel>
        <div aria-hidden="true" className="hidden shrink sm:block sm:grow-3" />
      </div>
    </Headless.Dialog>
  )
}

export function DialogTitle({ className, ...props }: { className?: string } & Omit<Headless.DialogTitleProps, 'as' | 'className'>) {
  return (
    <Headless.DialogTitle
      className={clsx(className, 'text-lg/6 font-semibold text-balance sm:text-base/6', 'text-zinc-950 dark:text-white')}
      {...props}
    />
  )
}

export function DialogDescription({
  className,
  ...props
}: { className?: string } & Omit<Headless.DescriptionProps<typeof Text>, 'as' | 'className'>) {
  return <Headless.Description as={Text} className={clsx(className, 'mt-2 text-pretty')} {...props} />
}

export function DialogBody({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return <div className={clsx(className, 'mt-6')} {...props} />
}

/** The action row: right-aligned from `sm:`, reverse-stacked and full-width on a phone so the primary action sits on top. */
export function DialogActions({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return (
    <div
      className={clsx(
        className,
        'mt-8',
        'flex flex-col-reverse items-center gap-3 sm:flex-row sm:justify-end',
        '*:w-full sm:*:w-auto'
      )}
      {...props}
    />
  )
}
