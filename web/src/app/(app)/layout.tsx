'use client'

import { ApplicationLayout } from '@/app/application-layout'
import { useAdminKey } from '@/lib/use-admin-key'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const hasKey = useAdminKey() !== null

  useEffect(() => {
    if (!hasKey) {
      router.replace('/login/')
    }
  }, [hasKey, router])

  if (!hasKey) {
    return <div className="min-h-dvh bg-white dark:bg-zinc-950" />
  }

  return <ApplicationLayout>{children}</ApplicationLayout>
}
