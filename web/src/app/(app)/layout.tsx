'use client'

import { ApplicationLayout } from '@/app/application-layout'
import { getAdminKey } from '@/lib/api'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [ready, setReady] = useState(false)

  useEffect(() => {
    if (!getAdminKey()) {
      router.replace('/login/')
      return
    }
    setReady(true)
  }, [router])

  if (!ready) {
    return <div className="min-h-dvh bg-white dark:bg-zinc-950" />
  }

  return <ApplicationLayout>{children}</ApplicationLayout>
}
