'use client'

import { Button } from '@/components/button'
import { Checkbox, CheckboxField, CheckboxGroup } from '@/components/checkbox'
import { Fieldset, Label, Legend } from '@/components/fieldset'
import { errorLine } from '@/components/primitives'
import { Text } from '@/components/text'
import { HTTP_METHODS, type KeyForm } from '@/lib/virtual-key-form'

export type HttpMethodsFieldsProps = {
  form: KeyForm
  onChange: (patch: Partial<KeyForm>) => void
  /** The key's target is a group, so the list applies to its HTTP API members. */
  groupTarget: boolean
  /** The key being edited reports http_methods_malformed: its stored list cannot be read. */
  unreadable: boolean
}

/**
 * The Allowed methods section of the Create and Edit virtual key dialogs
 * (PORM-146): the verbs the key may relay through an /api/ door, rendered only
 * when the target has an HTTP API. Fields and copy only; what is sent is
 * decided in web/src/lib/virtual-key-form.ts (methodsSent). The unreadable
 * state follows tool-list-fields' Replace pattern: nothing is sent until the
 * operator says so, because an unasked [] would turn a key that refuses every
 * request into one that allows every method.
 */
export function HttpMethodsFields({ form, onChange, groupTarget, unreadable }: HttpMethodsFieldsProps) {
  if (unreadable && !form.methodsReplace) {
    return (
      <Fieldset>
        <Legend>Allowed methods</Legend>
        <p role="status" className={errorLine}>
          This key&apos;s allowed methods cannot be read, so every request on its /api/ endpoint is refused.
        </p>
        <div data-slot="control" className="space-y-3">
          <Text>Saving other changes leaves them as they are.</Text>
          <Button type="button" outline onClick={() => onChange({ methodsReplace: true })}>
            Replace the stored methods
          </Button>
        </div>
      </Fieldset>
    )
  }
  // The list is kept in HTTP_METHODS order whatever order the boxes were
  // ticked in, which is also the order the server stores.
  const toggle = (method: string, on: boolean) => {
    const set = new Set(form.http_methods)
    if (on) set.add(method)
    else set.delete(method)
    onChange({ http_methods: HTTP_METHODS.filter((m) => set.has(m)) })
  }
  return (
    <Fieldset>
      <Legend>Allowed methods</Legend>
      <Text>
        Leave all unticked to allow every method. Tick GET and HEAD for a read-only key. Any other method is refused
        with 403.{groupTarget ? ' Applies to the HTTP APIs in this group.' : ''}
      </Text>
      <CheckboxGroup>
        {HTTP_METHODS.map((method) => (
          <CheckboxField key={method}>
            <Checkbox
              name="http_methods"
              checked={form.http_methods.includes(method)}
              onChange={(on) => toggle(method, on)}
            />
            <Label>{method}</Label>
          </CheckboxField>
        ))}
      </CheckboxGroup>
    </Fieldset>
  )
}
