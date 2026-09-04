'use client'

import { ApplicationLayout } from '@/app/application-layout'
import { getAdminKey } from '@/lib/api'
import { useAdminKey } from '@/lib/use-admin-key'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const hasKey = useAdminKey() !== null

  useEffect(() => {
    // Read the key at effect time rather than trusting hasKey: on the
    // hydration render the snapshot is still the server's null, and the
    // re-render that corrects it is scheduled after this effect has run.
    if (!getAdminKey()) {
      router.replace('/login/')
    }
  }, [hasKey, router])

  if (!hasKey) {
    return <div className="min-h-dvh bg-white dark:bg-zinc-950" />
  }

  return <ApplicationLayout>{children}</ApplicationLayout>
}
