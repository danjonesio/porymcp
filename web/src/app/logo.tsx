import clsx from 'clsx'

export function Logo({ className }: { className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <svg viewBox="0 0 32 32" className="size-6 shrink-0" aria-hidden="true">
        <path
          d="M6 22 16 4l10 18-10 6Z"
          className="fill-cyan-500 dark:fill-cyan-400"
        />
        <path d="M16 10 9.5 22h13Z" className="fill-white dark:fill-zinc-950" />
      </svg>
      <span className="font-semibold tracking-tight text-zinc-950 dark:text-white">PoryMCP</span>
    </span>
  )
}
