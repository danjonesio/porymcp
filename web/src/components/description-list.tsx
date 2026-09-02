import clsx from 'clsx'

/**
 * Term/detail pairs: stacked on a phone, a two-column grid from `sm:` with the
 * term column capped so long details (endpoint URLs) get the room. A hairline
 * separates rows; the first row has none.
 */
export function DescriptionList({ className, ...props }: React.ComponentPropsWithoutRef<'dl'>) {
  return (
    <dl
      className={clsx(className, 'grid grid-cols-1 text-base/6 sm:text-sm/6', 'sm:grid-cols-[min(50%,--spacing(80))_auto]')}
      {...props}
    />
  )
}

export function DescriptionTerm({ className, ...props }: React.ComponentPropsWithoutRef<'dt'>) {
  return (
    <dt
      className={clsx(
        className,
        'col-start-1 pt-3 sm:py-3',
        'text-zinc-500 dark:text-zinc-400',
        'border-t border-zinc-950/5 first:border-none dark:border-white/5'
      )}
      {...props}
    />
  )
}

export function DescriptionDetails({ className, ...props }: React.ComponentPropsWithoutRef<'dd'>) {
  return (
    <dd
      className={clsx(
        className,
        'pt-1 pb-3 sm:py-3',
        'text-zinc-950 dark:text-white',
        'sm:border-t sm:border-zinc-950/5 sm:nth-2:border-none dark:sm:border-white/5'
      )}
      {...props}
    />
  )
}
