import '@/styles/tailwind.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: {
    template: '%s · PoryMCP',
    default: 'PoryMCP',
  },
  description: 'One key. Many shapes. An MCP credential proxy.',
}

/**
 * The document base: a painted ground at every width (white on a phone, the
 * zinc-100 page behind the content card from `lg`, zinc-950 in dark) so the
 * pre-gate placeholder is never transparent, and the primary text colour.
 */
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="bg-white text-zinc-950 lg:bg-zinc-100 dark:bg-zinc-950 dark:text-white">
      <head>
        <link rel="preconnect" href="https://rsms.me/" />
      </head>
      <body className="isolate font-sans antialiased">{children}</body>
    </html>
  )
}
