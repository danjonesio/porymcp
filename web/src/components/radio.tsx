import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { focusRing, optionField } from './primitives'

/** Stacks radio fields; arrow keys move and select within the group (Headless). */
export function RadioGroup<TType>({
  className,
  ...props
}: { className?: string } & Omit<Headless.RadioGroupProps<'div', TType>, 'as' | 'className'>) {
  return (
    <Headless.RadioGroup
      data-slot="control"
      className={clsx(className, 'space-y-3 has-data-[slot=description]:space-y-6', '**:data-[slot=label]:font-normal')}
      {...props}
    />
  )
}

/** One radio beside its label, with an optional description under the label, the same grid as CheckboxField. */
export function RadioField({ className, ...props }: { className?: string } & Omit<Headless.FieldProps, 'as' | 'className'>) {
  return <Headless.Field data-slot="field" className={clsx(className, optionField)} {...props} />
}

/** A 19px (17px from `sm:`) circle that fills pale cyan with a dark dot when checked. */
export function Radio<TType>({
  color = 'cyan',
  className,
  ...props
}: { color?: 'cyan'; className?: string } & Omit<Headless.RadioProps<'span', TType>, 'as' | 'className' | 'children'>) {
  void color
  const circle = clsx(
    'flex size-4.75 items-center justify-center rounded-full sm:size-4.25',
    'bg-white ring-1 ring-zinc-950/15 ring-inset group-data-hover:ring-zinc-950/30',
    'dark:bg-white/5 dark:ring-white/15 dark:group-data-hover:ring-white/30',
    'group-data-checked:bg-cyan-300 group-data-checked:ring-cyan-950/15 dark:group-data-checked:bg-cyan-300 dark:group-data-checked:ring-cyan-950/15',
    'group-data-disabled:opacity-50',
    'forced-colors:group-data-checked:bg-[Highlight] forced-colors:group-data-checked:ring-[Highlight]'
  )
  return (
    <Headless.Radio data-slot="control" className={clsx(className, 'group inline-flex rounded-full', focusRing)} {...props}>
      <span className={circle}>
        <span className="size-1.75 rounded-full bg-cyan-950 opacity-0 group-data-checked:opacity-100 sm:size-1.5 forced-colors:bg-[HighlightText]" />
      </span>
    </Headless.Radio>
  )
}
