'use client'

import { Button } from '@/components/button'
import { Field, FieldGroup, Label } from '@/components/fieldset'
import { Heading, Subheading } from '@/components/heading'
import { Input } from '@/components/input'
import { Text } from '@/components/text'
import { clearAdminKey, getAdminKey, setAdminKey } from '@/lib/api'
import { useRouter } from 'next/navigation'
import { useState } from 'react'

export default function SettingsPage() {
  const router = useRouter()
  const [key, setKey] = useState('')
  const current = typeof window !== 'undefined' ? getAdminKey() : null
  const prefix = current ? current.slice(0, 12) + '…' : 'Not set'

  function save(e: React.FormEvent) {
    e.preventDefault()
    setAdminKey(key.trim())
    setKey('')
    router.refresh()
  }

  return (
    <>
      <Heading>Settings</Heading>
      <Text className="mt-2 max-w-[56ch] text-pretty">
        The dashboard talks to the management API with the admin key stored in this browser session.
      </Text>

      <Subheading className="mt-10">Admin key</Subheading>
      <Text className="mt-2">Current session key: {prefix}</Text>
      <form onSubmit={save} className="mt-6 max-w-xs">
        <FieldGroup>
          <Field>
            <Label>Replace session key</Label>
            <Input
              type="password"
              name="admin_key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoComplete="off"
            />
          </Field>
        </FieldGroup>
        <div className="mt-6 flex gap-3">
          <Button type="submit" color="cyan">
            Update
          </Button>
          <Button
            type="button"
            outline
            onClick={() => {
              clearAdminKey()
              router.push('/login/')
            }}
          >
            Sign out
          </Button>
        </div>
      </form>

      <Subheading className="mt-14">Retention</Subheading>
      <Text className="mt-2 max-w-[56ch] text-pretty">
        Audit logs stay in the configured database until you delete them. SQLite lives on the data volume; set
        DATABASE_URL to use Postgres.
      </Text>
    </>
  )
}
