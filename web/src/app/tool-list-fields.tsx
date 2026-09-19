'use client'

import { ToolEntries, type EntryRow } from '@/app/tool-entries'
import { ToolPicker, ToolPickerLoad } from '@/app/tool-picker'
import { Button } from '@/components/button'
import { Fieldset, Legend } from '@/components/fieldset'
import { Subheading } from '@/components/heading'
import { errorLine } from '@/components/primitives'
import { Text } from '@/components/text'
import { entryMark, unmatchedEntries, type Catalogue } from '@/lib/catalogue'
import { toggleEntry } from '@/lib/tool-filter'
import type { KeyForm } from '@/lib/virtual-key-form'
import { useState } from 'react'

export type ToolListFieldsProps = {
  form: KeyForm
  onChange: (patch: Partial<KeyForm>) => void
  /** The key's target is a group, which is when an allow entry has to name a member. */
  groupTarget: boolean
  /** The key being edited reports lists_malformed: its stored lists cannot be read. */
  unreadable: boolean
  catalogue: Catalogue
  rateLimited: string
  onLoad: (upstreamId?: string) => void
  /** Shown instead of Load tools while no target is chosen. */
  emptyHint: string
}

/** One of the key's two lists: its entries, an input to add one by hand, and the target's tools to tick. */
function RuleList({
  title,
  field,
  side,
  form,
  onChange,
  groupTarget,
  catalogue,
  onLoad,
}: {
  title: string
  field: 'tool_allowlist' | 'tool_denylist'
  side: 'allow' | 'deny'
  form: KeyForm
  onChange: (patch: Partial<KeyForm>) => void
  groupTarget: boolean
  catalogue: Catalogue
  onLoad: (upstreamId?: string) => void
}) {
  const [showTools, setShowTools] = useState(false)
  const list = form[field]
  const set = (next: string[]) => onChange({ [field]: next })
  const unmatched = unmatchedEntries(list, catalogue, { prefix: false })
  const entries: EntryRow[] = list.map((text) => {
    const m = entryMark(text, { kind: 'tool', side, groupTarget, keyList: true, unmatched })
    return { text, kind: 'tool', badge: m.badge, note: m.note }
  })
  const loaded = catalogue.members.some((m) => m.state !== 'idle')
  return (
    <div data-slot="control" className="space-y-6">
      <Subheading level={3}>{title}</Subheading>
      <ToolEntries
        label="Entries"
        name={field}
        entries={entries}
        emptyNote=""
        onRemove={(row) => set(toggleEntry(list, row.text, false))}
        onAddTool={(entry) => set(toggleEntry(list, entry, true))}
      />
      {loaded ? (
        <Button type="button" plain aria-expanded={showTools} onClick={() => setShowTools((v) => !v)}>
          {showTools ? 'Hide the tools' : `Tick tools for the ${title.toLowerCase()}`}
        </Button>
      ) : null}
      {loaded && showTools ? (
        <ToolPicker
          catalogue={catalogue}
          side={side}
          groupTarget={groupTarget}
          tools={list}
          prefixes={[]}
          name={field}
          onTick={(entry, on) => set(toggleEntry(list, entry, on))}
          onLoad={(id) => onLoad(id)}
        />
      ) : null}
    </div>
  )
}

/**
 * The Tool rules section of the Create and Edit virtual key dialogs: a deny
 * list and an allow list over one catalogue of the target's tools. Fields and
 * copy only; the rules are in web/src/lib. A key has no prefixes, so there is no
 * prefix input and no whole-member checkbox here.
 */
export function ToolListFields({
  form,
  onChange,
  groupTarget,
  unreadable,
  catalogue,
  rateLimited,
  onLoad,
  emptyHint,
}: ToolListFieldsProps) {
  if (unreadable && !form.listsReplace) {
    return (
      <Fieldset>
        <Legend>Tool rules</Legend>
        <p role="status" className={errorLine}>
          This key&apos;s stored tool rules cannot be read, so every call on it is refused.
        </p>
        <div data-slot="control" className="space-y-3">
          <Text>Saving other changes leaves them as they are.</Text>
          <Button type="button" outline onClick={() => onChange({ listsReplace: true })}>
            Replace the stored rules
          </Button>
        </div>
      </Fieldset>
    )
  }
  return (
    <Fieldset>
      <Legend>Tool rules</Legend>
      <Text>
        The deny list is checked first, then the allow list, then the group&apos;s filter. Each one can only take tools
        away.
      </Text>
      {form.listsReplace ? (
        <Text>
          Saving replaces both lists. With both empty, this key has no rules of its own. Closing this dialog keeps the
          stored rules.
        </Text>
      ) : null}
      <div data-slot="control">
        <ToolPickerLoad catalogue={catalogue} rateLimited={rateLimited} emptyHint={emptyHint} onLoad={() => onLoad()} />
      </div>
      <RuleList
        title="Deny list"
        field="tool_denylist"
        side="deny"
        form={form}
        onChange={onChange}
        groupTarget={groupTarget}
        catalogue={catalogue}
        onLoad={onLoad}
      />
      <RuleList
        title="Allow list"
        field="tool_allowlist"
        side="allow"
        form={form}
        onChange={onChange}
        groupTarget={groupTarget}
        catalogue={catalogue}
        onLoad={onLoad}
      />
      <Text>
        Clients cache the tool list. Reconnect a client after this changes, or it keeps offering tools it can no longer
        call.
      </Text>
    </Fieldset>
  )
}
