import clsx from 'clsx'

/**
 * The status language of the dashboard: lime is good or enabled, amber is held
 * or expired, pink is broken or revoked, zinc is neutral or disabled. The four
 * pairs are exact — a badge is how an operator reads a row at a glance.
 */
const tones = {
  lime: ['bg-lime-400/20 text-lime-700', 'dark:bg-lime-400/10 dark:text-lime-300'],
  amber: ['bg-amber-400/20 text-amber-700', 'dark:bg-amber-400/10 dark:text-amber-400'],
  pink: ['bg-pink-400/15 text-pink-700', 'dark:bg-pink-400/10 dark:text-pink-400'],
  zinc: ['bg-zinc-600/10 text-zinc-700', 'dark:bg-white/5 dark:text-zinc-400'],
}

export type BadgeColor = keyof typeof tones

export function Badge({
  color = 'zinc',
  className,
  ...props
}: { color?: BadgeColor } & React.ComponentPropsWithoutRef<'span'>) {
  return (
    <span
      className={clsx(
        className,
        'inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5',
        'text-sm/5 font-medium sm:text-xs/5',
        'forced-colors:outline',
        tones[color]
      )}
      {...props}
    />
  )
}
