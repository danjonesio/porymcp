import clsx from 'clsx'

type Level = 1 | 2 | 3 | 4 | 5 | 6
type HeadingProps = { level?: Level } & React.ComponentPropsWithoutRef<'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6'>

/** The page title — one per route, larger on a phone than from `sm`. */
export function Heading({ level = 1, className, ...props }: HeadingProps) {
  const Tag = `h${level}` as const
  return (
    <Tag className={clsx(className, 'text-2xl/8 font-semibold text-zinc-950 sm:text-xl/8 dark:text-white')} {...props} />
  )
}

/** A section title beneath the page title. `level` picks the element; the look is fixed. */
export function Subheading({ level = 2, className, ...props }: HeadingProps) {
  const Tag = `h${level}` as const
  return (
    <Tag className={clsx(className, 'text-base/7 font-semibold text-zinc-950 sm:text-sm/6 dark:text-white')} {...props} />
  )
}
