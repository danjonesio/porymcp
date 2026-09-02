'use client'

import { Logo } from '@/app/logo'
import { AuthLayout } from '@/components/auth-layout'
import { Button } from '@/components/button'
import { Field, Label } from '@/components/fieldset'
import { Heading } from '@/components/heading'
import { Input } from '@/components/input'
import { Text } from '@/components/text'
import { ApiError, api, setAdminKey } from '@/lib/api'
import { useRouter } from 'next/navigation'
import { useState } from 'react'

export default function LoginPage() {
  const router = useRouter()
  const [key, setKey] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError('')
    setAdminKey(key.trim())
    try {
      await api('/stats')
      router.replace('/')
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError('Too many failed attempts. Try again shortly.')
      } else {
        setError('That admin key was not accepted.')
      }
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="bg-white dark:bg-zinc-950">
      <AuthLayout>
        <form onSubmit={onSubmit} className="grid w-full max-w-xs grid-cols-1 gap-8">
          <Logo className="text-zinc-950 dark:text-white" />
          <Heading>Sign in to PoryMCP</Heading>
          <Text className="text-pretty">
            Use the management API key from ADMIN_API_KEY. It never leaves this browser session.
          </Text>
          <Field>
            <Label>Admin API key</Label>
            <Input
              type="password"
              name="admin_key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoComplete="off"
              required
            />
          </Field>
          {error ? <Text className="text-pink-600 dark:text-pink-400">{error}</Text> : null}
          <Button type="submit" color="cyan" className="w-full" disabled={pending}>
            {pending ? 'Checking…' : 'Open dashboard'}
          </Button>
        </form>
      </AuthLayout>
    </div>
  )
}
