import * as Headless from '@headlessui/react'
import NextLink from 'next/link'

/**
 * The one place the dashboard renders next/link. Headless UI's DataInteractive
 * publishes `data-hover`, `data-focus` (focus-visible only) and `data-active`
 * on the anchor, and every component that styles a link keys on them: drop
 * the wrapper and keyboard focus stops being visible on nav items and linked
 * table rows.
 */
export function Link({ ref, ...props }: React.ComponentPropsWithRef<typeof NextLink>) {
  return (
    <Headless.DataInteractive>
      <NextLink ref={ref} {...props} />
    </Headless.DataInteractive>
  )
}
