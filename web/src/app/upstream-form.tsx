'use client'

import { Checkbox, CheckboxField } from '@/components/checkbox'
import { Description, Field, FieldGroup, Label } from '@/components/fieldset'
import { HelpDisclosure } from '@/components/help-disclosure'
import { Input } from '@/components/input'
import { Select } from '@/components/select'
import { Strong, Text } from '@/components/text'
import type { Upstream } from '@/lib/api'
import { PLAIN_HTTP_NOTE, plainHTTPCredential } from '@/lib/discovery'
import {
  AUTH_TYPE_LABELS,
  authTypeLabel,
  credentialHelp,
  credentialRequired,
  headerRequired,
  headerShaped,
  type UpstreamForm,
} from '@/lib/upstream-form'

export type UpstreamFieldsProps = {
  className?: string
  mode: 'create' | 'edit'
  form: UpstreamForm
  /** One field changed. The page owns the state and the create-only reactions (slug derivation, the discovery reset). */
  onChange: (patch: Partial<UpstreamForm>) => void
  /** The row being edited. Read only in edit mode; every helper that needs it is called behind that guard. */
  before?: Upstream
}

/**
 * The fields of the Add and Edit upstream dialogs. Fields and their copy only:
 * the page owns the dialog chrome, the form state, submission and the Discover
 * panel, the way DiscoveryPanel is factored. The credential boxes never hold a
 * stored value; in edit mode they start empty and blank means keep.
 */
export function UpstreamFields({ className, mode, form, onChange, before }: UpstreamFieldsProps) {
  const row = mode === 'edit' ? before : undefined
  const isHeader = headerShaped(form.auth_type)
  // credentialRequired forces re-entry on any auth type change, including between
  // header, api_key and custom, which share one stored shape. That is the issue's
  // deliberate default (PORM-2), not a server requirement: see the helper's comment.
  const credRequired = row ? credentialRequired(row, form) : false
  const hdrRequired = headerRequired(row, form)

  function credentialDescription(): string | null {
    if (!row) return form.auth_type === 'bearer' ? 'Stored encrypted. It will not be shown after save.' : null
    if (credRequired) {
      return form.auth_type !== row.auth_type
        ? `Changing the auth type changes what PoryMCP sends. Enter the credential for ${authTypeLabel(form.auth_type)} to save.`
        : 'The header name is stored inside the credential. Enter the value again to change the name.'
    }
    return credentialHelp(row, form)
  }

  const credentialNote = credentialDescription()
  const urlChanged = !!row && form.url.trim() !== row.url && row.auth_status === 'ok'
  const plainHTTP = !!row && plainHTTPCredential(form.url, form.auth_type)
  const stoppedSending = !!row && form.auth_type === 'none' && row.auth_type !== 'none'

  return (
    <FieldGroup className={className}>
      {row ? (
        <Text>
          Changes take effect immediately. Virtual keys already connected use the new settings on their next call. No
          key stops working.
        </Text>
      ) : null}
      <Field>
        <Label>Name</Label>
        <Input name="name" value={form.name} onChange={(e) => onChange({ name: e.target.value })} required />
      </Field>
      {mode === 'create' ? (
        <Field>
          <Label>Slug</Label>
          <Input
            name="slug"
            value={form.slug}
            placeholder="up"
            maxLength={40}
            onChange={(e) => onChange({ slug: e.target.value })}
          />
          <Description>
            Used in URLs and in tool names on the group endpoint. Fixed once the upstream is created.
          </Description>
        </Field>
      ) : null}
      {/* The disclosure rides with the field rather than as its own FieldGroup
          child, so it sits under the input instead of a full field's gap below it. */}
      <div>
        <Field>
          <Label>URL</Label>
          <Input type="url" name="url" value={form.url} onChange={(e) => onChange({ url: e.target.value })} required />
          {urlChanged ? (
            <Description>PoryMCP sends the stored credential to the new address from the next request.</Description>
          ) : null}
          {plainHTTP ? <Description>{PLAIN_HTTP_NOTE}</Description> : null}
        </Field>
        <div className="mt-3">
          <HelpDisclosure label="What URL should I use?">
            <p>
              <Strong>The MCP endpoint, not the home page.</Strong> Usually the address ends in{' '}
              <span className="font-mono wrap-break-word">/mcp</span>. Copy it from the server’s documentation or from a
              working Claude Code or Cursor config.
            </p>
            <p>
              <Strong>The final address.</Strong> PoryMCP sends this upstream’s credential to exactly the URL you enter
              and never follows a redirect. An <span className="font-mono wrap-break-word">http://</span> address that
              redirects to <span className="font-mono wrap-break-word">https://</span>, or a path missing its trailing
              slash, fails with <span className="font-mono">502</span> and a log entry reading{' '}
              <span className="font-mono wrap-break-word">upstream redirected to …</span>. Use{' '}
              <span className="font-mono wrap-break-word">https://</span> and the exact path the server serves.
            </p>
            {mode === 'create' ? (
              <p>
                <Strong>Check it before you save.</Strong> Discover tools connects with these settings and lists what
                the server offers.
              </p>
            ) : (
              <p>
                <Strong>Check it after you save.</Strong> Tools on this row connects with the saved settings and the
                stored credential, which the browser cannot send from here.
              </p>
            )}
          </HelpDisclosure>
        </div>
      </div>
      <Field>
        <Label>Description</Label>
        <Input name="description" value={form.description} onChange={(e) => onChange({ description: e.target.value })} />
      </Field>
      <Field>
        <Label>Transport</Label>
        <Select name="transport" value={form.transport} onChange={(e) => onChange({ transport: e.target.value })}>
          <option value="streamable-http">Streamable HTTP</option>
          <option value="sse">SSE</option>
        </Select>
      </Field>
      <Field>
        <Label>Auth type</Label>
        <Select name="auth_type" value={form.auth_type} onChange={(e) => onChange({ auth_type: e.target.value })}>
          {Object.entries(AUTH_TYPE_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </Select>
        {stoppedSending ? (
          <Description>None stops sending the stored credential. It stays stored until a new one replaces it.</Description>
        ) : null}
      </Field>
      {form.auth_type === 'bearer' ? (
        <Field>
          <Label>Bearer token</Label>
          <Input
            type="password"
            name="token"
            value={form.token}
            autoComplete="new-password"
            required={credRequired}
            onChange={(e) => onChange({ token: e.target.value })}
          />
          {credentialNote ? <Description>{credentialNote}</Description> : null}
        </Field>
      ) : null}
      {isHeader ? (
        <>
          <Field>
            <Label>Header name</Label>
            {/* `required` accepts a lone space; the pattern wants one visible character. */}
            <Input
              name="header"
              value={form.header}
              autoComplete="off"
              required={hdrRequired}
              pattern=".*\S.*"
              onChange={(e) => onChange({ header: e.target.value })}
            />
          </Field>
          <Field>
            <Label>Header value</Label>
            <Input
              type="password"
              name="value"
              value={form.value}
              autoComplete="new-password"
              required={credRequired}
              onChange={(e) => onChange({ value: e.target.value })}
            />
            {credentialNote ? <Description>{credentialNote}</Description> : null}
          </Field>
        </>
      ) : null}
      <CheckboxField>
        <Checkbox name="enabled" checked={form.enabled} onChange={(checked) => onChange({ enabled: checked })} />
        <Label>Enabled</Label>
      </CheckboxField>
    </FieldGroup>
  )
}
