import clsx from 'clsx'

/** The body scale: larger on a phone, a step down from `sm:`. Shared by Text and the field descriptions. */
const bodyScale = 'text-base/6 sm:text-sm/6'

/**
 * Body copy in the secondary text colour. Every `<p>` prop travels through,
 * which is how `dir="ltr"` reaches an upstream-controlled string.
 * `data-slot="text"` lets a Fieldset space it.
 */
export function Text({ className, ...props }: React.ComponentPropsWithoutRef<'p'>) {
  return <p data-slot="text" className={clsx(className, bodyScale, 'text-zinc-500 dark:text-zinc-400')} {...props} />
}

/** An inline code chip: a hairline border and a faint tint, a step smaller than the text around it. */
export function Code({ className, ...props }: React.ComponentPropsWithoutRef<'code'>) {
  return (
    <code
      className={clsx(
        className,
        'rounded-sm px-0.5 text-sm font-medium sm:text-[0.8125rem]',
        'border border-zinc-950/10 bg-zinc-950/2.5 text-zinc-950',
        'dark:border-white/20 dark:bg-white/5 dark:text-white'
      )}
      {...props}
    />
  )
}

/** Medium-weight emphasis in the primary text colour. */
export function Strong({ className, ...props }: React.ComponentPropsWithoutRef<'strong'>) {
  return <strong className={clsx(className, 'font-medium', 'text-zinc-950 dark:text-white')} {...props} />
}
