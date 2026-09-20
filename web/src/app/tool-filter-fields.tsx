'use client'

import { ToolEntries, type EntryRow } from '@/app/tool-entries'
import { ToolPicker, ToolPickerLoad } from '@/app/tool-picker'
import { Button } from '@/components/button'
import { Description, Fieldset, Label, Legend } from '@/components/fieldset'
import { HelpDisclosure } from '@/components/help-disclosure'
import { errorLine } from '@/components/primitives'
import { Radio, RadioField, RadioGroup } from '@/components/radio'
import { Code, Text } from '@/components/text'
import { BLOCKS_EVERYTHING_NOW, blocksEverything, entryMark, unmatchedEntries, type Catalogue } from '@/lib/catalogue'
import type { GroupForm } from '@/lib/group-form'
import { prefixMatchNote } from '@/lib/rule-conflicts'
import { filterPermits } from '@/lib/tool-entry'
import {
  ZERO_ENTRIES,
  addPrefixHint,
  addToolHint,
  clampText,
  filterAdmitsNothing,
  filterListsNothing,
  toggleEntry,
  wholeMemberLabel,
  wholeMemberPrefix,
  type FilterForm,
  type FilterMode,
} from '@/lib/tool-filter'

/** How much of an unreadable stored filter the dialog prints. The column can hold up to the API's 1 MiB body limit. */
const UNREADABLE_SHOWN = 2000

type RadioValue = 'none' | 'allow' | 'deny'

export type ToolFilterFieldsProps = {
  form: GroupForm
  onChange: (patch: Partial<GroupForm>) => void
  catalogue: Catalogue
  rateLimited: string
  onLoad: (upstreamId?: string) => void
  /** groupSaveBlocked's sentence ('' when Save may proceed). The page prints it beside Save; here it only picks the empty-list note. */
  blocked: string
}

/**
 * The Tool filter section of the Create and Edit group dialogs. Fields and copy
 * only. Every rule is in web/src/lib: what the stored filter is
 * (parseToolFilter, through the form), what would be sent (groupPatchBody), what
 * the catalogue can and cannot say (catalogue.ts).
 */
export function ToolFilterFields({ form, onChange, catalogue, rateLimited, onLoad, blocked }: ToolFilterFieldsProps) {
  const f = form.filter
  const setFilter = (next: FilterForm) => onChange({ filter: next })

  if (form.filterUnreadable && !form.filterReplace) {
    const shown = clampText(form.filterUnreadable, UNREADABLE_SHOWN)
    return (
      <Fieldset>
        <Legend>Tool filter</Legend>
        <p role="status" className={errorLine}>
          This group&apos;s stored filter cannot be read, so every tool on it is blocked.
        </p>
        <div data-slot="control" className="space-y-3">
          {/* Whatever sits in the column: text, left to right, free to break, clamped. */}
          <p
            dir="ltr"
            className="rounded-xl bg-zinc-950/2.5 p-4 font-mono text-base/6 break-all text-zinc-950 sm:text-sm/6 dark:bg-white/2.5 dark:text-white"
          >
            {shown.text}
          </p>
          {shown.cut ? <Text>The rest is not shown.</Text> : null}
          <Text>Saving other changes leaves it as it is.</Text>
          <Button type="button" outline onClick={() => onChange({ filterReplace: true, filterChosen: false })}>
            Replace filter
          </Button>
        </div>
      </Fieldset>
    )
  }

  const side = f.mode === 'allow' ? 'allow' : 'deny'
  const radio: RadioValue | null = form.filterReplace && !form.filterChosen ? null : f.mode === '' ? 'none' : f.mode
  const unmatchedTools = unmatchedEntries(f.tools, catalogue, { prefix: false })
  const unmatchedPrefixes = unmatchedEntries(f.prefixes, catalogue, { prefix: true })
  const mark = (text: string, kind: 'tool' | 'prefix'): EntryRow => {
    const m = entryMark(text, {
      kind,
      side,
      groupTarget: true,
      keyList: false,
      unmatched: kind === 'tool' ? unmatchedTools : unmatchedPrefixes,
      // Which tools a prefix reaches right now: a prefix typed where a tool name
      // was meant looks the same in this list, and the names are what show it.
      prefixNote: kind === 'prefix' ? prefixMatchNote(text, catalogue) : undefined,
    })
    return { text, kind, badge: m.badge, note: m.note }
  }
  const entries: EntryRow[] = [...f.tools.map((e) => mark(e, 'tool')), ...f.prefixes.map((e) => mark(e, 'prefix'))]
  const standing =
    filterAdmitsNothing(f) || (f.mode !== '' && blocksEverything(filterPermits(f), catalogue) ? BLOCKS_EVERYTHING_NOW : '')
  // A stored deny filter that lists nothing says what it does; once that empty
  // mode is the operator's edit (Save is then held back), it says what to do.
  const emptyNote = blocked ? ZERO_ENTRIES : filterListsNothing(f) || ZERO_ENTRIES

  return (
    <Fieldset>
      <Legend>Tool filter</Legend>
      <Text>
        A rule names a tool as the upstream&apos;s slug, two underscores, then the tool&apos;s own name, like{' '}
        <Code>github__create_issue</Code>. That name matches on the combined endpoint and on each per-upstream
        endpoint.
      </Text>
      {form.filterReplace ? (
        <Text>Choose a mode to replace the stored filter. Closing this dialog keeps the stored filter.</Text>
      ) : null}

      <RadioGroup
        name="tool_filter_mode"
        aria-label="Tool filter mode"
        value={radio}
        onChange={(v: RadioValue | null) => {
          const mode: FilterMode = v === 'allow' || v === 'deny' ? v : ''
          onChange({ filter: { ...f, mode }, filterChosen: true })
        }}
      >
        <RadioField>
          <Radio value="none" color="cyan" />
          <Label>No filter</Label>
          <Description>
            This group adds no restriction of its own. A virtual key&apos;s own rules still apply. Removing a filter
            widens what every key on this group reaches, and the change is recorded.
          </Description>
        </RadioField>
        <RadioField>
          <Radio value="allow" color="cyan" />
          <Label>Allow only these tools</Label>
          <Description>
            Only the tools listed below pass this group&apos;s filter. Everything else is blocked, including a tool an
            upstream adds later.
          </Description>
        </RadioField>
        <RadioField>
          <Radio value="deny" color="cyan" />
          <Label>Deny these tools</Label>
          <Description>Every tool except the ones listed below passes this group&apos;s filter.</Description>
        </RadioField>
      </RadioGroup>

      {f.mode !== '' ? (
        <div data-slot="control" className="space-y-8">
          {standing ? (
            <p role="status" className={errorLine}>
              {standing}
            </p>
          ) : null}

          <div className="space-y-3">
            <ToolEntries
              label="Entries"
              name="tool_filter"
              entries={entries}
              emptyNote={emptyNote}
              onRemove={(row) =>
                setFilter(
                  row.kind === 'tool'
                    ? { ...f, tools: toggleEntry(f.tools, row.text, false) }
                    : { ...f, prefixes: toggleEntry(f.prefixes, row.text, false) },
                )
              }
              onAddTool={(entry) => setFilter({ ...f, tools: toggleEntry(f.tools, entry, true) })}
              onAddPrefix={(entry) => setFilter({ ...f, prefixes: toggleEntry(f.prefixes, entry, true) })}
              toolHint={addToolHint(side)}
              prefixHint={addPrefixHint(side)}
            />
            <HelpDisclosure label="How does a prefix match?">
              <p>
                A prefix is compared with the tool&apos;s own name. <Code>delete_</Code> matches on every member,{' '}
                <Code>github__delete_</Code> on github only, and <Code>github__</Code> is every tool on github.
              </p>
            </HelpDisclosure>
          </div>

          <ToolPickerLoad
            catalogue={catalogue}
            rateLimited={rateLimited}
            emptyHint="Tick an upstream above to choose its tools."
            onLoad={() => onLoad()}
          />
          <ToolPicker
            catalogue={catalogue}
            side={side}
            groupTarget
            tools={f.tools}
            prefixes={f.prefixes}
            name="tool_filter"
            onTick={(entry, on) => setFilter({ ...f, tools: toggleEntry(f.tools, entry, on) })}
            onLoad={(id) => onLoad(id)}
            wholeMember={{
              label: (slug) => wholeMemberLabel(f.mode, slug),
              isOn: (slug) => f.prefixes.includes(wholeMemberPrefix(slug)),
              onToggle: (slug, on) => setFilter({ ...f, prefixes: toggleEntry(f.prefixes, wholeMemberPrefix(slug), on) }),
            }}
          />

          <HelpDisclosure label="What wins when two rules disagree?">
            <p>
              Three rules run in order: the key&apos;s deny list, then the key&apos;s allow list, then the group&apos;s
              filter. Each one can only take tools away, so a key never reaches more than its group allows.
            </p>
          </HelpDisclosure>
          <Text>
            Clients cache the tool list. Reconnect a client after this changes, or it keeps offering tools it can no
            longer call.
          </Text>
        </div>
      ) : null}
    </Fieldset>
  )
}
