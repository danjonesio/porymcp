import * as Headless from '@headlessui/react'
import clsx from 'clsx'
import { controlField, controlFrame } from './primitives'

/**
 * A text field. `type` is the narrow set the dashboard uses; every other
 * `<input>` prop travels through Headless to the element. The focus outline is
 * drawn inset on the field itself and only from `sm:` up, the same treatment
 * the dashboard has always had on phones.
 */
export function Input({
  className,
  type,
  ...props
}: {
  className?: string
  type?: 'email' | 'number' | 'password' | 'search' | 'tel' | 'text' | 'url'
} & Omit<Headless.InputProps, 'as' | 'className' | 'type'>) {
  return (
    <span data-slot="control" className={clsx(className, controlFrame)}>
      <Headless.Input
        type={type}
        className={clsx(controlField, 'sm:focus:outline-2 sm:focus:-outline-offset-2 sm:focus:outline-focus sm:focus:outline-solid')}
        {...props}
      />
    </span>
  )
}
