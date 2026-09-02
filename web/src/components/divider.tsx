import clsx from 'clsx'

/**
 * A full-width hairline rule. `soft` is the lighter variant a dialog uses to
 * separate a secondary action from the form above it.
 */
export function Divider({ soft = false, className, ...props }: { soft?: boolean } & React.ComponentPropsWithoutRef<'hr'>) {
  return (
    <hr
      role="presentation"
      className={clsx(
        className,
        'w-full border-t',
        soft ? 'border-zinc-950/5 dark:border-white/5' : 'border-zinc-950/10 dark:border-white/10'
      )}
      {...props}
    />
  )
}
