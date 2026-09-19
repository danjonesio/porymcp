'use client'

import { Badge, type BadgeColor } from '@/components/badge'
import { Button } from '@/components/button'
import { Field, Label } from '@/components/fieldset'
import { Input } from '@/components/input'
import { Text } from '@/components/text'
import { useRef, useState } from 'react'

/** One row of the list: the entry as stored, what kind it is, and what the lib said about it. */
export type EntryRow = { text: string; kind: 'tool' | 'prefix'; badge: string; note: string }

const BADGE_TONE: Record<string, BadgeColor> = { 'Cannot be saved': 'pink', 'Not advertised': 'amber' }

/**
 * One add-by-hand input. Both dialogs are forms with a submit button, so Enter
 * in a text input would save the dialog without the entry; here Enter adds the
 * entry instead, and Add is a plain button.
 */
function AddEntry({ label, name, onAdd }: { label: string; name: string; onAdd: (entry: string) => void }) {
  const [text, setText] = useState('')
  function add() {
    const entry = text.trim()
    if (!entry) return
    onAdd(entry)
    setText('')
  }
  return (
    <Field>
      <Label>{label}</Label>
      <div data-slot="control" className="flex items-start gap-3">
        <Input
          name={name}
          className="min-w-0 flex-1"
          value={text}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== 'Enter') return
            e.preventDefault()
            add()
          }}
        />
        <Button type="button" outline className="shrink-0" onClick={add}>
          Add
        </Button>
      </div>
    </Field>
  )
}

/**
 * The entries of one rule list, and the inputs that add one by hand. It holds no
 * rules: the badge and the sentence on each row come from entryMark
 * (web/src/lib/catalogue.ts), and what may be added is judged when the dialog
 * saves.
 *
 * An entry is stored text that an upstream or another client may have chosen,
 * so it gets the treatment the Tools panel gives a reported name: a React child,
 * left to right, allowed to break anywhere, never a title attribute.
 */
export function ToolEntries({
  label,
  name,
  entries,
  emptyNote,
  onRemove,
  onAddTool,
  onAddPrefix,
}: {
  label: string
  /** Prefixes the input names, so two lists in one dialog do not share one. */
  name: string
  entries: EntryRow[]
  /** Shown in place of the list when it is empty. '' shows nothing. */
  emptyNote: string
  onRemove: (row: EntryRow) => void
  onAddTool: (entry: string) => void
  /** Only a group's tool_filter has prefixes. */
  onAddPrefix?: (entry: string) => void
}) {
  // Remove unmounts the button that was pressed. Without this the focus falls
  // back to the dialog and the next Tab starts from the top; the heading is the
  // nearest thing that is always there, and it carries the new count.
  const heading = useRef<HTMLParagraphElement>(null)
  return (
    <div className="space-y-6">
      <div>
        <p
          ref={heading}
          tabIndex={-1}
          className="text-base/6 font-medium text-zinc-950 tabular-nums focus:outline-hidden sm:text-sm/6 dark:text-white"
        >
          {label} ({entries.length})
        </p>
        {entries.length === 0 ? (
          emptyNote ? (
            <Text className="mt-1">{emptyNote}</Text>
          ) : null
        ) : (
          <ul role="list" aria-label={label} className="mt-2 divide-y divide-zinc-950/5 dark:divide-white/5">
            {entries.map((row) => (
              <li key={row.kind + ':' + row.text} className="flex items-start gap-3 py-2 first:pt-0 last:pb-0">
                <div className="min-w-0 flex-1 text-base/6 sm:text-sm/6">
                  <div className="flex flex-wrap items-center gap-2">
                    <span dir="ltr" className="max-w-full min-w-0 font-mono break-all text-zinc-950 dark:text-white">
                      {row.text}
                    </span>
                    {row.badge ? <Badge color={BADGE_TONE[row.badge] ?? 'zinc'}>{row.badge}</Badge> : null}
                  </div>
                  {row.note ? (
                    <p dir="ltr" className="mt-1 text-pretty wrap-break-word text-zinc-500 dark:text-zinc-400">
                      {row.note}
                    </p>
                  ) : null}
                </div>
                <Button
                  type="button"
                  plain
                  className="shrink-0"
                  aria-label={`Remove ${row.text}`}
                  onClick={() => {
                    onRemove(row)
                    heading.current?.focus()
                  }}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <AddEntry label="Add a tool by name" name={`${name}_add_tool`} onAdd={onAddTool} />
      {onAddPrefix ? <AddEntry label="Add a prefix" name={`${name}_add_prefix`} onAdd={onAddPrefix} /> : null}
    </div>
  )
}
