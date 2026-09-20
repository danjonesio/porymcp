'use client'

import { ToolRow } from '@/app/discovery-panel'
import { Button } from '@/components/button'
import { Checkbox, CheckboxField } from '@/components/checkbox'
import { Field, Fieldset, Label, Legend } from '@/components/fieldset'
import { Input } from '@/components/input'
import { errorLine } from '@/components/primitives'
import { Text } from '@/components/text'
import {
  LOAD_RECORDS_A_TEST,
  MEMBER_DISABLED,
  MEMBER_NOT_IMPLEMENTED,
  UNLISTED_STAYS_BLOCKED,
  catalogueSummary,
  coveredNote,
  coveringEntry,
  incompleteLine,
  truncatedNote,
  unnameableNote,
  unnameableRowNote,
  type Catalogue,
  type MemberCatalogue,
} from '@/lib/catalogue'
import { cleanEntry, tickEntry } from '@/lib/tool-entry'
import { transportUnsupported } from '@/lib/upstream-transport'
import clsx from 'clsx'
import { useState } from 'react'

/** Past this many loaded rows the picker offers a Find a tool input. */
const FIND_THRESHOLD = 20

/**
 * The Load tools press and what it reports for the whole target: the sentence
 * that says a press is a write, a rate-limit refusal, a polite summary of what
 * arrived, and the line that says why no entry is flagged. One per dialog, above
 * however many pickers share the catalogue.
 */
export function ToolPickerLoad({
  catalogue,
  rateLimited,
  emptyHint,
  onLoad,
}: {
  catalogue: Catalogue
  rateLimited: string
  /** Shown instead of the button while the target has no members. */
  emptyHint: string
  onLoad: () => void
}) {
  if (catalogue.members.length === 0) return <Text>{emptyHint}</Text>
  const loading = catalogue.members.some((m) => m.state === 'loading')
  const loadedAny = catalogue.members.some((m) => m.state !== 'idle')
  const incomplete = incompleteLine(catalogue)
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        {/* aria-disabled, not disabled: a disabled button drops focus to the
            dialog, and the next Tab starts from the top. A press while a run is
            in flight is dropped by useCatalogue. */}
        <Button type="button" outline aria-disabled={loading} className="aria-disabled:opacity-50" onClick={onLoad}>
          {loading ? 'Loading…' : loadedAny ? 'Reload tools' : 'Load tools'}
        </Button>
      </div>
      <Text>{LOAD_RECORDS_A_TEST}</Text>
      {rateLimited ? (
        <p role="alert" className={errorLine}>
          {rateLimited}
        </p>
      ) : null}
      {/* The summary only: a live region around fifty rows is read out in full. */}
      <p aria-live="polite" className="sr-only">
        {loading ? '' : catalogueSummary(catalogue)}
      </p>
      {!loading && incomplete ? <Text>{incomplete}</Text> : null}
    </div>
  )
}

/** A spacer the width of a Checkbox, for a row that cannot be ticked. It keeps the names in the second column. */
function NoControl() {
  return <span data-slot="control" aria-hidden="true" className="size-4.5 sm:size-4" />
}

function MemberBlock({
  member,
  busy,
  find,
  side,
  groupTarget,
  tools,
  prefixes,
  name,
  onTick,
  onLoad,
  wholeMember,
  rowNotes,
}: {
  member: MemberCatalogue
  /** Some member of this catalogue is loading: no other load may start (useCatalogue drops it). */
  busy: boolean
  find: string
  side: 'allow' | 'deny'
  groupTarget: boolean
  tools: string[]
  prefixes: string[]
  name: string
  onTick: (entry: string, on: boolean) => void
  onLoad: (upstreamId: string) => void
  wholeMember?: WholeMember
  rowNotes?: RowNotes
}) {
  // On the transport alone. The group form hides this line for a disabled
  // member because a disabled member is off the proxy's path; it is not off the
  // picker's, since the discover route has no enabled check, and a Load there
  // would spend a token on a call that fails before it dials.
  const unsupported = transportUnsupported(member.transport)
  const status = member.state === 'idle' ? 'Not loaded.' : member.state === 'loading' ? 'Loading…' : member.error
  const action =
    member.state === 'idle' ? 'Load' : member.state === 'failed' ? 'Try again' : member.state === 'loading' ? 'Loading…' : 'Reload'
  const shown = find ? member.tools.filter((t) => t.name.toLowerCase().includes(find.toLowerCase())) : member.tools
  const unlisted = side === 'allow' && (member.truncated || member.unnameable > 0)
  return (
    <Fieldset>
      <Legend>
        {member.name}{' '}
        <span dir="ltr" className="font-mono font-normal break-all text-zinc-500 dark:text-zinc-400">
          {member.slug}
        </span>
      </Legend>
      {member.enabled ? null : <Text>{MEMBER_DISABLED}</Text>}
      {unsupported ? <Text>{MEMBER_NOT_IMPLEMENTED}</Text> : null}

      {wholeMember ? (
        <div data-slot="control">
          <CheckboxField>
            <Checkbox
              name={`${name}_whole_${member.slug}`}
              checked={wholeMember.isOn(member.slug)}
              onChange={(on) => wholeMember.onToggle(member.slug, on)}
            />
            <Label>{wholeMember.label(member.slug)}</Label>
          </CheckboxField>
        </div>
      ) : null}

      <div data-slot="control" aria-busy={member.state === 'loading'} className="space-y-3">
        {/* One row and one button in every state, so the button a press landed
            on is still there, and still focused, when the state changes. */}
        <div className="flex flex-wrap items-start gap-3">
          <p
            dir="ltr"
            role={member.state === 'failed' ? 'status' : undefined}
            className={clsx(
              'min-w-0 flex-1 wrap-break-word',
              member.state === 'failed' ? errorLine : 'text-base/6 text-zinc-500 sm:text-sm/6 dark:text-zinc-400'
            )}
          >
            {member.state === 'ok' ? '' : status}
          </p>
          {unsupported ? null : (
            <Button
              type="button"
              plain
              className="shrink-0 aria-disabled:opacity-50"
              aria-disabled={busy}
              aria-label={`${action} ${member.name}`}
              onClick={() => onLoad(member.upstream_id)}
            >
              {action}
            </Button>
          )}
        </div>
        {member.state === 'ok' ? (
          <>
            {member.tools.length === 0 ? <Text>No tools. This server answered, and its catalogue is empty.</Text> : null}
            {member.tools.length > 0 && shown.length === 0 ? <Text>No tool on this upstream matches.</Text> : null}
            {shown.length > 0 ? (
              <ul
                role="list"
                aria-label={`Tools on ${member.name}`}
                className="divide-y divide-zinc-950/5 dark:divide-white/5"
              >
                {shown.map((tool, index) => {
                  // The exact string a tick writes and unticking removes. State is
                  // keyed on it, never on the rendered text: two names can look
                  // alike and still be different entries.
                  const entry = tickEntry(member.slug, tool)
                  const nameable = cleanEntry(entry)
                  // Asked of every row. A name no tools entry can hold is still
                  // reached by a prefix, and under allow that prefix PERMITS it:
                  // a row that went on saying "it stays blocked" would state the
                  // opposite of the rule.
                  const covered = coveringEntry(member.slug, tool.name, { tools, prefixes, side, groupTarget })
                  const notes: string[] = []
                  if (!nameable) notes.push(unnameableRowNote(side, !!wholeMember, !!covered))
                  if (covered) notes.push(coveredNote(covered))
                  if (rowNotes) notes.push(...rowNotes(member.slug, tool.name))
                  return (
                    <ToolRow
                      key={index}
                      tool={tool}
                      scoped={entry}
                      clamped
                      disabled={!!covered}
                      notes={notes}
                      control={
                        nameable ? (
                          <Checkbox
                            name={`${name}_tool`}
                            value={entry}
                            checked={!!covered || tools.includes(entry)}
                            disabled={!!covered}
                            onChange={(on) => onTick(entry, on)}
                          />
                        ) : (
                          <NoControl />
                        )
                      }
                    />
                  )
                })}
              </ul>
            ) : null}
            {member.truncated ? <Text>{truncatedNote(member.tools.length)}</Text> : null}
            {member.unnameable > 0 ? <Text>{unnameableNote(member.unnameable)}</Text> : null}
            {unlisted ? <Text>{UNLISTED_STAYS_BLOCKED}</Text> : null}
          </>
        ) : null}
      </div>
    </Fieldset>
  )
}

/**
 * Further lines under a tool's row, from rules the picker does not hold itself:
 * in the key dialog, that the deny list or the group's filter stops this tool.
 */
export type RowNotes = (slug: string, name: string) => string[]

/** The group dialog's whole-member rule: one prefixes entry per member, labelled from the mode. */
export type WholeMember = {
  label: (slug: string) => string
  isOn: (slug: string) => boolean
  onToggle: (slug: string, on: boolean) => void
}

/**
 * The tools of a target's members, one block per member, each tool a checkbox
 * that writes or removes one entry of `tools`. It renders what catalogue.ts and
 * tool-entry.ts decided and decides nothing itself.
 *
 * A row another entry already names (a prefix, the whole-member rule, a bare
 * name) is drawn ticked and disabled and says which entry covers it: unticking
 * one row must never delete a rule that reaches other tools too. A tool whose
 * name no entry can hold is drawn with no box and says why. Everything an
 * upstream sent is a text child through ToolRow, as in the Tools dialog.
 */
export function ToolPicker({
  catalogue,
  side,
  groupTarget,
  tools,
  prefixes,
  name,
  onTick,
  onLoad,
  wholeMember,
  rowNotes,
}: {
  catalogue: Catalogue
  side: 'allow' | 'deny'
  groupTarget: boolean
  tools: string[]
  prefixes: string[]
  /** Prefixes every control name, so two pickers in one dialog stay apart. */
  name: string
  onTick: (entry: string, on: boolean) => void
  onLoad: (upstreamId: string) => void
  wholeMember?: WholeMember
  rowNotes?: RowNotes
}) {
  const [find, setFind] = useState('')
  const rows = catalogue.members.reduce((n, m) => n + m.tools.length, 0)
  const busy = catalogue.members.some((m) => m.state === 'loading')
  return (
    <div className="space-y-8">
      {rows > FIND_THRESHOLD ? (
        <Field>
          <Label>Find a tool</Label>
          <Input
            type="search"
            name={`${name}_find`}
            value={find}
            autoComplete="off"
            onChange={(e) => setFind(e.target.value)}
            // This dialog is a form with a submit button: Enter here would save it.
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.preventDefault()
            }}
          />
        </Field>
      ) : null}
      {catalogue.members.map((member) => (
        <MemberBlock
          key={member.upstream_id}
          member={member}
          busy={busy}
          find={find.trim()}
          side={side}
          groupTarget={groupTarget}
          tools={tools}
          prefixes={prefixes}
          name={name}
          onTick={onTick}
          onLoad={onLoad}
          wholeMember={wholeMember}
          rowNotes={rowNotes}
        />
      ))}
    </div>
  )
}
