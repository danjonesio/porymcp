import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { controlField, controlFrame } from './primitives'

/** A multi-line text field with the same chrome as Input. `resizable` (the default) allows vertical resizing only. */
export function Textarea({
  className,
  resizable = true,
  ...props
}: { className?: string; resizable?: boolean } & Omit<Headless.TextareaProps, 'as' | 'className'>) {
  return (
    <span data-slot="control" className={clsx(className, controlFrame)}>
      <Headless.Textarea
        className={clsx(
          controlField,
          'sm:focus:outline-2 sm:focus:-outline-offset-2 sm:focus:outline-focus sm:focus:outline-solid',
          resizable ? 'resize-y' : 'resize-none'
        )}
        {...props}
      />
    </span>
  )
}
