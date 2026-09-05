'use client'

import { Checkbox, CheckboxField, CheckboxGroup } from '@/components/checkbox'
import { Description, Field, FieldGroup, Fieldset, Label, Legend } from '@/components/fieldset'
import { Input } from '@/components/input'
import { Text } from '@/components/text'
import type { Upstream } from '@/lib/api'
import type { GroupForm } from '@/lib/group-form'

export type GroupFieldsProps = {
  className?: string
  mode: 'create' | 'edit'
  form: GroupForm
  /** One field changed. The page owns the state and the submit. */
  onChange: (patch: Partial<GroupForm>) => void
  /** Every upstream the page has loaded; the member list is drawn from it. */
  upstreams: Upstream[]
}

/**
 * The fields of the Create and Edit group dialogs. Fields and their copy only:
 * the page owns the dialog chrome, the form state and submission. The member
 * list is a fieldset with a legend rather than a labelled field, because a
 * label names one control and this names a group of them.
 */
export function GroupFields({ className, mode, form, onChange, upstreams }: GroupFieldsProps) {
  function toggle(id: string, checked: boolean) {
    onChange({
      upstream_ids: checked ? [...form.upstream_ids, id] : form.upstream_ids.filter((x) => x !== id),
    })
  }

  return (
    <FieldGroup className={className}>
      {mode === 'edit' ? (
        <Text>
          Changes take effect immediately. Adding an upstream gives every virtual key on this group access to it on
          its next call. Removing one takes that access away.
        </Text>
      ) : null}
      <Field>
        <Label>Name</Label>
        <Input name="name" value={form.name} onChange={(e) => onChange({ name: e.target.value })} required />
      </Field>
      <Field>
        <Label>Description</Label>
        <Input name="description" value={form.description} onChange={(e) => onChange({ description: e.target.value })} />
      </Field>
      <Fieldset>
        <Legend>Upstreams</Legend>
        {mode === 'edit' && upstreams.length === 0 ? (
          // A group's upstream cannot be deleted while the group holds it, so a
          // list that is empty while the group has members is a partial load;
          // the diff rule sends no upstream_ids for an untouched membership, and
          // the line says so. With no members either there is nothing to keep.
          <Text>
            {form.upstream_ids.length > 0
              ? 'No upstreams to choose from. Saving keeps the members this group has.'
              : 'No upstreams yet. Add one on the Upstreams page to give this group members.'}
          </Text>
        ) : (
          <CheckboxGroup>
            {upstreams.map((u) => (
              <CheckboxField key={u.id}>
                <Checkbox
                  name="upstream_ids"
                  checked={form.upstream_ids.includes(u.id)}
                  onChange={(checked) => toggle(u.id, checked)}
                />
                <Label>{u.name}</Label>
                {u.enabled ? null : <Description>Disabled. A virtual key on this group gets no endpoint for it.</Description>}
              </CheckboxField>
            ))}
          </CheckboxGroup>
        )}
      </Fieldset>
    </FieldGroup>
  )
}
