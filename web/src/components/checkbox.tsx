import * as Headless from '@headlessui/react'
import { CheckIcon, MinusIcon } from '@heroicons/react/16/solid'
import clsx from 'clsx'
import { focusRing, optionField } from './primitives'

/** Stacks checkbox fields; wider apart when any of them carries a description. */
export function CheckboxGroup({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return (
    <div
      data-slot="control"
      className={clsx(className, 'space-y-3 has-data-[slot=description]:space-y-6', '**:data-[slot=label]:font-normal')}
      {...props}
    />
  )
}

/**
 * One control beside its label, with an optional description under the label.
 * A two-column grid that lets the control size its own column; the
 * description is the only child that needs placing. Shared with RadioField.
 */

export function CheckboxField({ className, ...props }: { className?: string } & Omit<Headless.FieldProps, 'as' | 'className'>) {
  return <Headless.Field data-slot="field" className={clsx(className, optionField)} {...props} />
}

/**
 * Headless UI's checkbox — a `role="checkbox"` element, not a native input —
 * drawn as an 18px box (16px from `sm:`) that fills near-black when checked.
 * The tick and the indeterminate dash are Heroicons, cross-faded by state.
 */
export function Checkbox({
  className,
  ...props
}: { className?: string } & Omit<Headless.CheckboxProps, 'as' | 'className' | 'children'>) {
  const box = clsx(
    'relative flex items-center justify-center',
    'size-4.5 rounded-[0.3125rem] sm:size-4',
    'bg-white ring-1 ring-zinc-950/15 ring-inset group-data-hover:ring-zinc-950/30',
    'dark:bg-white/5 dark:ring-white/15 dark:group-data-hover:ring-white/30',
    'group-data-checked:bg-zinc-900 group-data-checked:ring-zinc-900 dark:group-data-checked:bg-zinc-600 dark:group-data-checked:ring-zinc-600',
    'group-data-indeterminate:bg-zinc-900 group-data-indeterminate:ring-zinc-900 dark:group-data-indeterminate:bg-zinc-600 dark:group-data-indeterminate:ring-zinc-600',
    'group-data-disabled:opacity-50',
    'forced-colors:group-data-checked:bg-[Highlight] forced-colors:group-data-checked:ring-[Highlight] forced-colors:group-data-indeterminate:bg-[Highlight]'
  )
  const glyph = 'absolute size-4 text-white opacity-0 sm:size-3.5 forced-colors:text-[HighlightText]'
  return (
    <Headless.Checkbox data-slot="control" className={clsx(className, 'group inline-flex rounded-[0.3125rem]', focusRing)} {...props}>
      <span className={box}>
        <CheckIcon aria-hidden="true" className={clsx(glyph, 'group-data-checked:opacity-100')} />
        <MinusIcon aria-hidden="true" className={clsx(glyph, 'group-data-indeterminate:opacity-100')} />
      </span>
    </Headless.Checkbox>
  )
}
