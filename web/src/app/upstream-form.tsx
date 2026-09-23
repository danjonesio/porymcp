'use client'

import { Button } from '@/components/button'
import { Checkbox, CheckboxField, CheckboxGroup } from '@/components/checkbox'
import { Description, Field, FieldGroup, Fieldset, Label, Legend } from '@/components/fieldset'
import { HelpDisclosure } from '@/components/help-disclosure'
import { Input } from '@/components/input'
import { Radio, RadioField, RadioGroup } from '@/components/radio'
import { Select } from '@/components/select'
import { Strong, Text } from '@/components/text'
import { oauthClientMetadata, type Upstream } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { PLAIN_HTTP_NOTE, plainHTTPCredential } from '@/lib/discovery'
import { LOADING } from '@/lib/placeholder'
import {
  AUTH_TYPE_LABELS,
  CLIENT_SECRET_ALONE,
  KIND_LABELS,
  TRANSPORT_LABELS,
  applyKindChange,
  clearStoredDescription,
  clientSecretAlone,
  credentialRequired,
  editCredentialDescription,
  headerRequired,
  headerShaped,
  removeCredentialDescription,
  urlChangeDescription,
  type UpstreamForm,
} from '@/lib/upstream-form'
import { transportUnsupported } from '@/lib/upstream-transport'
import { useEffect, useRef, useState } from 'react'

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
  const isHTTP = form.kind === 'http'
  const isHeader = headerShaped(form.auth_type)
  // credentialRequired forces re-entry on any auth type change, including between
  // header, api_key and custom, which share one stored shape. That is the issue's
  // deliberate default (PORM-2), not a server requirement: see the helper's comment.
  const credRequired = row ? credentialRequired(row, form) : false
  const hdrRequired = headerRequired(row, form)

  function credentialDescription(): string | null {
    if (!row) return form.auth_type === 'bearer' ? 'Stored encrypted. It will not be shown after save.' : null
    return editCredentialDescription(row, form)
  }

  const credentialNote = credentialDescription()
  // Both URL sentences come from the lib: the "sends to the new address" line
  // for a credential that moves with the row, and the "disconnects" line for
  // an oauth token that was minted for the old address (PORM-139).
  const urlNote = urlChangeDescription(row, form)
  const plainHTTP = !!row && plainHTTPCredential(form.url, form.auth_type)
  const isOAuth = form.auth_type === 'oauth'
  // What the Auth type select says on an oauth row: the state and the press
  // that fixes it (edit), or where Connect lives (create).
  const oauthNote = isOAuth
    ? row
      ? editCredentialDescription(row, form)
      : "After Create, press Connect on the upstream's row to sign in to the vendor."
    : null
  const secretAlone = clientSecretAlone(form)
  // Both sentences come from the lib, where node --test pins their exact text
  // and the conditions they render under (PORM-120).
  const removesCredential = removeCredentialDescription(row, form)
  const clearStored = clearStoredDescription(row, form)

  return (
    <FieldGroup className={className}>
      {row ? (
        <Text>
          Changes take effect immediately. Virtual keys already connected use the new settings on their next call. No
          key stops working.
        </Text>
      ) : null}
      {mode === 'create' ? (
        // First, because it changes what the URL box asks for. Fixed once the
        // upstream is created, so Edit shows it in the dialog's description
        // line instead (PORM-146).
        <Fieldset>
          <Legend>Kind</Legend>
          <RadioGroup name="kind" value={form.kind} onChange={(v) => onChange(applyKindChange(form, v as string))}>
            {Object.entries(KIND_LABELS).map(([value, label]) => (
              <RadioField key={value}>
                <Radio value={value} color="cyan" />
                <Label>{label}</Label>
              </RadioField>
            ))}
          </RadioGroup>
        </Fieldset>
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
          <Label>{isHTTP ? 'Base URL' : 'URL'}</Label>
          <Input type="url" name="url" value={form.url} onChange={(e) => onChange({ url: e.target.value })} required />
          {isHTTP ? (
            <Description>
              Requests to the key&apos;s endpoint are sent here with the stored credential. The path after /api/ is
              appended.
            </Description>
          ) : null}
          {urlNote ? <Description>{urlNote}</Description> : null}
          {plainHTTP ? <Description>{PLAIN_HTTP_NOTE}</Description> : null}
        </Field>
        <div className="mt-3">
          <HelpDisclosure label={isHTTP ? 'What base URL should I use?' : 'What URL should I use?'}>
            {isHTTP ? (
              <p>
                <Strong>The API’s root.</Strong> A caller’s path is added after it: for{' '}
                <span className="font-mono wrap-break-word">https://api.example.com/v1/user</span>, enter{' '}
                <span className="font-mono wrap-break-word">https://api.example.com/v1</span>.
              </p>
            ) : (
              <p>
                <Strong>The MCP endpoint, not the home page.</Strong> Usually the address ends in{' '}
                <span className="font-mono wrap-break-word">/mcp</span>. Copy it from the server’s documentation or from
                a working Claude Code or Cursor config.
              </p>
            )}
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
                <Strong>Check it before you save.</Strong>{' '}
                {isHTTP
                  ? 'Test sends one GET with these settings and shows the status.'
                  : 'Discover tools connects with these settings and lists what the server offers.'}
              </p>
            ) : (
              <p>
                <Strong>Check it after you save.</Strong>{' '}
                {isHTTP
                  ? 'Test on this row sends one GET with the saved settings and the stored credential.'
                  : 'Tools on this row connects with the saved settings and the stored credential, which the browser cannot send from here.'}
              </p>
            )}
          </HelpDisclosure>
        </div>
      </div>
      {isHTTP ? (
        <Field>
          <Label>Test path</Label>
          <Input
            name="test_path"
            value={form.test_path}
            maxLength={256}
            pattern="/.*"
            dir="ltr"
            placeholder="/user"
            autoComplete="off"
            onChange={(e) => onChange({ test_path: e.target.value })}
          />
          <Description>A path the connection test requests, such as /user. Left empty, the base URL is tested.</Description>
        </Field>
      ) : null}
      <Field>
        <Label>Description</Label>
        <Input name="description" value={form.description} onChange={(e) => onChange({ description: e.target.value })} />
      </Field>
      {isHTTP ? null : (
      <Field>
        <Label>Transport</Label>
        <Select name="transport" value={form.transport} onChange={(e) => onChange({ transport: e.target.value })}>
          {Object.entries(TRANSPORT_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
          {/* A row stored with a value the proxy refuses (sse, saved before
              PORM-28) keeps its own option, so the select shows what is stored
              instead of snapping to the one supported value, and the operator
              chooses the repair. upstreamPatchBody sends transport only when it
              changed, so saving without touching this field is not a 400. */}
          {transportUnsupported(form.transport) ? (
            <option value={form.transport}>{form.transport} (unsupported)</option>
          ) : null}
        </Select>
        {transportUnsupported(form.transport) ? (
          <Description>
            Not implemented. Requests through this upstream fail until the transport is Streamable HTTP. The URL
            stays as it is.
          </Description>
        ) : null}
      </Field>
      )}
      <Field>
        <Label>Auth type</Label>
        <Select name="auth_type" value={form.auth_type} onChange={(e) => onChange({ auth_type: e.target.value })}>
          {/* OAuth is not offered on an HTTP API: the server refuses it (PORM-146),
              and applyKindChange has already reset a selected one. */}
          {Object.entries(AUTH_TYPE_LABELS)
            .filter(([value]) => !(isHTTP && value === 'oauth'))
            .map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </Select>
        {removesCredential ? <Description>{removesCredential}</Description> : null}
        {oauthNote ? <Description>{oauthNote}</Description> : null}
      </Field>
      {isOAuth ? (
        // The client identity is optional and most vendors register PoryMCP
        // themselves, so the two boxes sit behind the house disclosure and
        // open on their own only when a supplied client is already stored.
        <div>
          <HelpDisclosure label="Did the vendor give you a client ID?" defaultOpen={row?.oauth?.client_source === 'supplied'}>
            <p>
              Only if the vendor gave you one. Most servers register PoryMCP themselves. Some need a client created
              in the vendor’s settings first, with this redirect URL allowed:
            </p>
            <RedirectURILine />
            <Field>
              <Label>Client ID</Label>
              <Input
                name="client_id"
                value={form.client_id}
                autoComplete="off"
                required={form.client_secret !== ''}
                onChange={(e) => onChange({ client_id: e.target.value })}
              />
            </Field>
            <Field>
              <Label>Client secret</Label>
              <Input
                type="password"
                name="client_secret"
                value={form.client_secret}
                autoComplete="new-password"
                aria-invalid={secretAlone || undefined}
                onChange={(e) => onChange({ client_secret: e.target.value })}
              />
              <Description>
                {secretAlone
                  ? CLIENT_SECRET_ALONE
                  : row
                    ? 'Leave blank to keep the stored client. Saving a new one disconnects this upstream.'
                    : 'Optional. A public client has no secret.'}
              </Description>
            </Field>
            {row ? (
              // The choice is read by the row's Connect and remembered per row
              // id, which Add does not have yet: it shows once the row exists.
              <CheckboxGroup>
                <CheckboxField>
                  <Checkbox
                    name="register_client"
                    checked={form.register_client}
                    onChange={(checked) => onChange({ register_client: checked })}
                  />
                  <Label>Register PoryMCP with the vendor instead of publishing its client document</Label>
                  <Description>
                    Use this when the vendor cannot reach this PoryMCP address. It applies to the next Connect on the
                    row.
                  </Description>
                </CheckboxField>
              </CheckboxGroup>
            ) : null}
          </HelpDisclosure>
        </div>
      ) : null}
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
      <CheckboxGroup>
        <CheckboxField>
          <Checkbox name="enabled" checked={form.enabled} onChange={(checked) => onChange({ enabled: checked })} />
          <Label>Enabled</Label>
        </CheckboxField>
        {clearStored ? (
          <CheckboxField>
            <Checkbox
              name="clear_stored"
              checked={form.clear_stored}
              onChange={(checked) => onChange({ clear_stored: checked })}
            />
            <Label>Remove the stored value</Label>
            <Description>{clearStored}</Description>
          </CheckboxField>
        ) : null}
      </CheckboxGroup>
    </FieldGroup>
  )
}

/**
 * The redirect URL a vendor's own client registration must allow: read from
 * the client metadata document the server publishes, so it is the exact
 * string PUBLIC_URL produces and never the address this page happens to be
 * open at, which can differ behind a proxy. Mounted only inside the oauth
 * disclosure, so the fetch runs when the operator can see it.
 */
function RedirectURILine() {
  const [redirect, setRedirect] = useState<string | null | undefined>(undefined)
  const [copied, setCopied] = useState<boolean | null>(null)
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    let alive = true
    oauthClientMetadata()
      .then((d) => alive && setRedirect(d.redirect_uris[0] ?? null))
      .catch(() => alive && setRedirect(null))
    return () => {
      alive = false
      if (copyTimer.current) clearTimeout(copyTimer.current)
    }
  }, [])

  async function copy(url: string) {
    const ok = await copyText(url)
    if (copyTimer.current) clearTimeout(copyTimer.current)
    setCopied(ok)
    copyTimer.current = setTimeout(() => setCopied(null), 1500)
  }

  if (redirect === undefined) return <p>{LOADING}</p>
  if (redirect === null) return <p>Could not load the redirect URL. Reload the page to try again.</p>
  return (
    <p className="flex flex-wrap items-center gap-2">
      <span className="font-mono wrap-break-word">{redirect}</span>
      <Button type="button" plain aria-label="Copy the redirect URL" onClick={() => copy(redirect)}>
        {copied === null ? 'Copy' : copied ? 'Copied' : 'Copy failed'}
      </Button>
    </p>
  )
}
