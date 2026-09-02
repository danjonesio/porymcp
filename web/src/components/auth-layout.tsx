import clsx from 'clsx'

/**
 * The sign-in frame: a full-height grid that centres its child. On a phone the
 * child sits on the page ground; from `lg` the cell becomes a card with the
 * same treatment as the app's content card.
 */
export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="grid min-h-dvh grid-rows-1 p-2">
      <section
        className={clsx(
          'grid place-items-center p-6 lg:p-10',
          'lg:rounded-lg lg:bg-white dark:lg:bg-zinc-900',
          'lg:shadow-xs lg:ring-1 lg:ring-zinc-950/5 dark:lg:ring-white/10'
        )}
      >
        {children}
      </section>
    </main>
  )
}
