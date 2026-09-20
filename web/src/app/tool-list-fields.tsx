'use client'

import { ReportedList } from '@/app/discovery-panel'
import { ToolEntries, type EntryRow } from '@/app/tool-entries'
import { ToolPicker, ToolPickerLoad } from '@/app/tool-picker'
import { Button } from '@/components/button'
import { Fieldset, Label, Legend } from '@/components/fieldset'
import { Subheading } from '@/components/heading'
import { errorLine } from '@/components/primitives'
import { Radio, RadioField, RadioGroup } from '@/components/radio'
import { Text } from '@/components/text'
import type { Group } from '@/lib/api'
import { entryMark, unmatchedEntries, type Catalogue } from '@/lib/catalogue'
import {
  ALSO_DENIED_NOTE,
  GROUP_BLOCKS_NOTE,
  allowEntryDeniedBy,
  allowListAdmitsNothing,
  deniedBy,
  deniedRowNote,
  groupBlocks,
  groupFilterSummary,
} from '@/lib/rule-conflicts'
import { addToolHint, toggleEntry } from '@/lib/tool-filter'
import type { KeyForm } from '@/lib/virtual-key-form'
import { useState } from 'react'

export type ToolListFieldsProps = {
  form: KeyForm
  onChange: (patch: Partial<KeyForm>) => void
  /** The key's target is a group, which is when an allow entry has to name a member. */
  groupTarget: boolean
  /** The target group, when there is one and the page has it: its filter is the third rule on this key. */
  group?: Group
  /** On a single-upstream key, that upstream's slug, so a bare entry can be judged; '' otherwise. */
  targetSlug: string
  /** The key being edited reports lists_malformed: its stored lists cannot be read. */
  unreadable: boolean
  catalogue: Catalogue
  rateLimited: string
  onLoad: (upstreamId?: string) => void
  /** Shown instead of Load tools while no target is chosen. */
  emptyHint: string
}

/** One of the key's two lists: its entries and an input to add one by hand. The tools to tick are one picker, below both. */
function RuleList({
  title,
  field,
  side,
  form,
  onChange,
  groupTarget,
  targetSlug,
  catalogue,
}: {
  title: string
  field: 'tool_allowlist' | 'tool_denylist'
  side: 'allow' | 'deny'
  form: KeyForm
  onChange: (patch: Partial<KeyForm>) => void
  groupTarget: boolean
  targetSlug: string
  catalogue: Catalogue
}) {
  const list = form[field]
  const set = (next: string[]) => onChange({ [field]: next })
  const unmatched = unmatchedEntries(list, catalogue, { prefix: false })
  const entries: EntryRow[] = list.map((text) => {
    // The deny list is checked first, so an allow entry it also names never takes effect.
    const overruled = side === 'allow' && allowEntryDeniedBy(text, form.tool_denylist, targetSlug) ? ALSO_DENIED_NOTE : ''
    const m = entryMark(text, { kind: 'tool', side, groupTarget, keyList: true, unmatched, overruled })
    return { text, kind: 'tool', badge: m.badge, note: m.note }
  })
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
        toolHint={addToolHint(side)}
      />
    </div>
  )
}

/**
 * What the key's group already does, read-only. The group's filter is the third
 * rule the proxy runs on this key, and without this block the dialog shows two
 * of the three. Its entries are stored text, drawn as the Tools panel draws a
 * reported name.
 */
function GroupFilterBlock({ group }: { group: Group }) {
  const s = groupFilterSummary(group)
  return (
    <div data-slot="control" className="space-y-3 text-base/6 sm:text-sm/6">
      {s.tone === 'pink' ? (
        <p role="status" className={errorLine}>
          {s.sentence}
        </p>
      ) : (
        <Text>{s.sentence}</Text>
      )}
      <ReportedList label={`Tools the group ${group.name} lists`} items={s.tools} />
      <ReportedList label={`Prefixes the group ${group.name} lists`} items={s.prefixes} />
      {s.more > 0 ? <Text>{`And ${s.more} more.`}</Text> : null}
    </div>
  )
}

/**
 * The Tool rules section of the Create and Edit virtual key dialogs: a deny
 * list and an allow list over ONE picker of the target's tools. A radio says
 * which list a tick writes to, and the rows show that list's ticks. One picker,
 * so each member's state (not loaded, failed with Try again, truncated, no
 * tools) is on screen once, straight after the Load press, and no tool row is
 * drawn twice. Fields and copy only; the rules are in web/src/lib. A key has no
 * prefixes, so there is no prefix input and no whole-member checkbox here.
 */
export function ToolListFields({
  form,
  onChange,
  groupTarget,
  group,
  targetSlug,
  unreadable,
  catalogue,
  rateLimited,
  onLoad,
  emptyHint,
}: ToolListFieldsProps) {
  const [ticking, setTicking] = useState<'deny' | 'allow'>('deny')
  const field = ticking === 'allow' ? 'tool_allowlist' : 'tool_denylist'
  const nothingAllowed = allowListAdmitsNothing(form.tool_allowlist, form.tool_denylist, groupTarget, targetSlug)
  const blockedByGroup = group ? groupBlocks(group) : null
  // Lines under a tool's row for the two rules this picker does not hold: the
  // group's filter, and, while ticks go to the allow list, the deny list.
  const rowNotes = (slug: string, name: string): string[] => {
    const notes: string[] = []
    if (blockedByGroup?.(slug, name)) notes.push(GROUP_BLOCKS_NOTE)
    const denied = ticking === 'allow' ? deniedBy(slug, name, form.tool_denylist) : ''
    if (denied) notes.push(deniedRowNote(denied))
    return notes
  }
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
        {groupTarget
          ? "The deny list is checked first, then the allow list, then the group's filter. Each one can only take tools away."
          : 'The deny list is checked first, then the allow list. Each one can only take tools away.'}
      </Text>
      {group ? <GroupFilterBlock group={group} /> : null}
      {nothingAllowed ? (
        // A control slot, so the Fieldset gives it the gap it gives each block.
        <div data-slot="control">
          <p role="status" className={errorLine}>
            {nothingAllowed}
          </p>
        </div>
      ) : null}
      {form.listsReplace ? (
        <Text>
          Saving replaces both lists. At least one of them could not be read, and a list that could not be read is
          shown empty here, so check both before saving. With both empty, this key has no rules of its own. Closing
          this dialog keeps the stored rules.
        </Text>
      ) : null}
      <RuleList
        title="Deny list"
        field="tool_denylist"
        side="deny"
        form={form}
        onChange={onChange}
        groupTarget={groupTarget}
        targetSlug={targetSlug}
        catalogue={catalogue}
      />
      <RuleList
        title="Allow list"
        field="tool_allowlist"
        side="allow"
        form={form}
        onChange={onChange}
        groupTarget={groupTarget}
        targetSlug={targetSlug}
        catalogue={catalogue}
      />
      <div data-slot="control" className="space-y-8">
        <ToolPickerLoad catalogue={catalogue} rateLimited={rateLimited} emptyHint={emptyHint} onLoad={() => onLoad()} />
        {catalogue.members.length > 0 ? (
          <>
            <RadioGroup
              name="tool_rules_ticking"
              aria-label="Which list a tick writes to"
              value={ticking}
              onChange={(v: 'deny' | 'allow') => setTicking(v)}
            >
              <RadioField>
                <Radio value="deny" color="cyan" />
                <Label>Ticks go to the deny list</Label>
              </RadioField>
              <RadioField>
                <Radio value="allow" color="cyan" />
                <Label>Ticks go to the allow list</Label>
              </RadioField>
            </RadioGroup>
            <ToolPicker
              catalogue={catalogue}
              side={ticking}
              groupTarget={groupTarget}
              tools={form[field]}
              prefixes={[]}
              name={field}
              onTick={(entry, on) => onChange({ [field]: toggleEntry(form[field], entry, on) })}
              onLoad={(id) => onLoad(id)}
              rowNotes={rowNotes}
            />
          </>
        ) : null}
      </div>
      <Text>
        Clients cache the tool list. Reconnect a client after this changes, or it keeps offering tools it can no longer
        call.
      </Text>
    </Fieldset>
  )
}
