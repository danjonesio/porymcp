import * as Headless from '@headlessui/react'
import clsx from 'clsx'

/**
 * Thin wrappers over Headless UI's form primitives. Headless owns every id,
 * `htmlFor` and `aria-describedby`; these add the look and the `data-slot`
 * values the vertical rhythm keys on.
 */

const scale = 'text-base/6 sm:text-sm/6'
const primary = 'text-zinc-950 dark:text-white'
const muted = 'text-zinc-500 dark:text-zinc-400'
const dimWhenDisabled = 'data-disabled:opacity-50'

/**
 * The legend's gap is put on the control that follows it, not on "whatever
 * follows the legend": Headless's RadioGroup renders two hidden inputs as
 * siblings right after the legend, and a next-sibling rule would land there.
 */
export function Fieldset({ className, ...props }: { className?: string } & Omit<Headless.FieldsetProps, 'as' | 'className'>) {
  return (
    <Headless.Fieldset
      className={clsx(className, '[&>[data-slot=control]:not(:first-child)]:mt-6', '*:data-[slot=text]:mt-1')}
      {...props}
    />
  )
}

export function Legend({ className, ...props }: { className?: string } & Omit<Headless.LegendProps, 'as' | 'className'>) {
  return (
    <Headless.Legend data-slot="legend" className={clsx(className, scale, 'font-semibold', primary, dimWhenDisabled)} {...props} />
  )
}

/** Stacks fields 8 units apart. */
export function FieldGroup({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return <div data-slot="control" className={clsx(className, 'space-y-8')} {...props} />
}

/**
 * The rhythm inside a field: a description sits 1 unit under its label, the
 * control 3 units under whatever precedes it, and a description that follows
 * the control 3 units under that.
 */
const fieldRhythm = clsx(
  '*:data-[slot=label]:font-medium',
  '[&>[data-slot=description]]:mt-1',
  '[&>[data-slot=control]]:mt-3',
  '[&>[data-slot=control]+[data-slot=description]]:mt-3'
)

export function Field({ className, ...props }: { className?: string } & Omit<Headless.FieldProps, 'as' | 'className'>) {
  return <Headless.Field className={clsx(className, fieldRhythm)} {...props} />
}

export function Label({ className, ...props }: { className?: string } & Omit<Headless.LabelProps, 'as' | 'className'>) {
  return (
    <Headless.Label data-slot="label" className={clsx(className, scale, 'select-none', primary, dimWhenDisabled)} {...props} />
  )
}

export function Description({
  className,
  ...props
}: { className?: string } & Omit<Headless.DescriptionProps, 'as' | 'className'>) {
  return <Headless.Description data-slot="description" className={clsx(className, scale, muted, dimWhenDisabled)} {...props} />
}
