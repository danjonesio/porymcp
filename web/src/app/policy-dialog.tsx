'use client'

import { ReportedList } from '@/app/discovery-panel'
import { BADGE_TONE } from '@/app/tool-entries'
import { GroupFilterBlock } from '@/app/tool-list-fields'
import { Badge } from '@/components/badge'
import { Button } from '@/components/button'
import { Dialog, DialogActions, DialogBody, DialogDescription, DialogTitle } from '@/components/dialog'
import { Subheading } from '@/components/heading'
import { errorLine } from '@/components/primitives'
import { Text } from '@/components/text'
import type { PolicyView } from '@/lib/api'
import {
  ALWAYS_REFUSED_SENTENCE,
  COUNTS_ONLY_NOTE,
  EDITED_RULES_NOTE,
  EVERY_KEY_NOTE,
  ORDER_NOTE,
  OUTBOUND_LOGS_NOTE,
  alwaysRefusedCount,
  blockedLine,
  egressSentences,
  emptyGroupSentence,
  keyListsState,
  listEmptySentence,
  methodsSentence,
  ruleCount,
  shownForCountsOnly,
  statusLine,
  targetGoneSentence,
  unreadableLine,
  visibleBlocks,
} from '@/lib/policy-view'
import { allowEntryDeniedBy } from '@/lib/rule-conflicts'
import { HTTP_METHODS, LISTS_UNREADABLE_SENTENCE } from '@/lib/virtual-key-form'

export type PolicyDialogProps = {
  /** The key's name, for the description; null while the dialog is closed. */
  keyName: string | null
  view: PolicyView | null
  /** The load failed; the sentence to show in place of the view. */
  error: string
  onClose: () => void
}

/**
 * The Policy dialog (PORM-209): every rule that applies to one virtual key,
 * grouped by the door it runs on, and what each refused in the last 7 days.
 * Read only: nothing here edits a rule. Copy and verdicts are in
 * web/src/lib/policy-view.ts; this file only lays them out.
 */
export function PolicyDialog({ keyName, view, error, onClose }: PolicyDialogProps) {
  return (
    <Dialog open={keyName !== null} onClose={onClose} size="2xl">
      <DialogTitle>Policy</DialogTitle>
      <DialogDescription>{keyName}</DialogDescription>
      <DialogBody>
        <section aria-live="polite" aria-busy={!view && !error}>
          {error ? (
            <p role="alert" className={errorLine}>
              {error}
            </p>
          ) : view ? (
            <PolicyBody view={view} />
          ) : (
            <Text>Loading…</Text>
          )}
        </section>
      </DialogBody>
      <DialogActions>
        <Button type="button" plain onClick={onClose}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  )
}

function PolicyBody({ view }: { view: PolicyView }) {
  const status = statusLine(view.status)
  const gone = targetGoneSentence(view)
  const empty = emptyGroupSentence(view)
  const blocks = visibleBlocks(view)
  return (
    <div className="space-y-8">
      {status || gone || empty ? (
        <div className="space-y-2">
          {status ? <Text>{status}</Text> : null}
          {gone ? <Pink>{gone}</Pink> : null}
          {empty ? <Text>{empty}</Text> : null}
        </div>
      ) : null}
      {blocks.includes('mcp') ? <McpBlock view={view} /> : null}
      {blocks.includes('http') ? <HttpBlock view={view} /> : null}
      <OutboundBlock view={view} />
    </div>
  )
}

/** One block: a door, or the egress switches, with its rules beneath. */
function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-6">
      <Subheading level={3}>{title}</Subheading>
      {children}
    </section>
  )
}

/**
 * One rule inside a block: its name, what it holds, and what it refused.
 * `unreadable` is what the rule refused while its stored value could not be
 * read, shown on a line of its own so it is never credited to the entries.
 */
function Rule({
  title,
  count,
  unreadable = 0,
  children,
}: {
  title: string
  count: number
  unreadable?: number
  children: React.ReactNode
}) {
  const extra = unreadableLine(unreadable)
  return (
    <div className="space-y-3 border-t border-zinc-950/5 pt-4 dark:border-white/5">
      <Subheading level={4}>{title}</Subheading>
      {children}
      <Text className="tabular-nums">{blockedLine(count)}</Text>
      {extra ? <Text className="tabular-nums">{extra}</Text> : null}
    </div>
  )
}

function Pink({ children }: { children: React.ReactNode }) {
  return (
    <p role="status" className={errorLine}>
      {children}
    </p>
  )
}

function McpBlock({ view }: { view: PolicyView }) {
  const deny = view.key_denylist ?? []
  const allow = view.key_allowlist ?? []
  const g = view.group_tool_filter
  const alsoDenied = (entry: string) =>
    allowEntryDeniedBy(entry, deny, view.target_slug) ? { label: 'Also denied', color: BADGE_TONE['Also denied'] } : null
  return (
    <Block title="MCP endpoints">
      <Text>{ORDER_NOTE}</Text>
      {shownForCountsOnly(view, 'mcp') ? <Text>{COUNTS_ONLY_NOTE}</Text> : null}
      {keyListsState(view) === 'unreadable' ? (
        <Rule title="Deny list and allow list" count={ruleCount(view, 'key_lists_unreadable')}>
          <Pink>{LISTS_UNREADABLE_SENTENCE}</Pink>
        </Rule>
      ) : (
        <>
          <Rule
            title="Deny list"
            count={ruleCount(view, 'key_denylist')}
            unreadable={ruleCount(view, 'key_lists_unreadable')}
          >
            {deny.length > 0 ? (
              <ReportedList label="Tools this key denies" items={deny} />
            ) : (
              <Text>{listEmptySentence('deny')}</Text>
            )}
          </Rule>
          <Rule title="Allow list" count={ruleCount(view, 'key_allowlist')}>
            {allow.length > 0 ? (
              <ReportedList label="Tools this key allows" items={allow} markFor={alsoDenied} />
            ) : (
              <Text>{listEmptySentence('allow')}</Text>
            )}
          </Rule>
        </>
      )}
      {g ? (
        g.malformed ? (
          <Rule title="Group filter" count={ruleCount(view, 'group_tool_filter_unreadable')}>
            <GroupFilterBlock group={{ name: g.group_name, tool_filter: g.tool_filter }} listsAbove malformed />
          </Rule>
        ) : (
          <Rule
            title="Group filter"
            count={ruleCount(view, 'group_tool_filter')}
            unreadable={ruleCount(view, 'group_tool_filter_unreadable')}
          >
            <GroupFilterBlock group={{ name: g.group_name, tool_filter: g.tool_filter }} listsAbove />
          </Rule>
        )
      ) : null}
      <Text>{EDITED_RULES_NOTE}</Text>
    </Block>
  )
}

function HttpBlock({ view }: { view: PolicyView }) {
  const sentence = methodsSentence(view.http_methods, view.http_methods_malformed)
  const verbs = HTTP_METHODS.filter((m) => (view.http_methods ?? []).includes(m))
  return (
    <Block title="HTTP API endpoints">
      {shownForCountsOnly(view, 'http') ? <Text>{COUNTS_ONLY_NOTE}</Text> : null}
      <Rule
        title="Allowed methods"
        count={ruleCount(view, view.http_methods_malformed ? 'http_methods_unreadable' : 'http_methods')}
        unreadable={view.http_methods_malformed ? 0 : ruleCount(view, 'http_methods_unreadable')}
      >
        {sentence ? (
          sentence.tone === 'pink' ? (
            <Pink>{sentence.sentence}</Pink>
          ) : (
            <Text>{sentence.sentence}</Text>
          )
        ) : verbs.length > 0 ? (
          <ul role="list" aria-label="Methods this key allows" className="flex flex-wrap gap-2">
            {verbs.map((m) => (
              <li key={m}>
                <Badge color="zinc">{m}</Badge>
              </li>
            ))}
          </ul>
        ) : null}
      </Rule>
      <Text>{EDITED_RULES_NOTE}</Text>
    </Block>
  )
}

function OutboundBlock({ view }: { view: PolicyView }) {
  const s = egressSentences(view.egress)
  const byClass = view.blocked.upstream_address_denied_by_class
  return (
    <Block title="Outbound connections">
      <Text>{EVERY_KEY_NOTE}</Text>
      <Rule title="Loopback addresses" count={byClass.loopback ?? 0}>
        <Text>{s.loopback}</Text>
      </Rule>
      <Rule title="Private addresses" count={byClass.private ?? 0}>
        <Text>{s.private}</Text>
      </Rule>
      <Rule title="Other reserved addresses" count={alwaysRefusedCount(view)}>
        <Text>{ALWAYS_REFUSED_SENTENCE}</Text>
      </Rule>
      <Text>{OUTBOUND_LOGS_NOTE}</Text>
    </Block>
  )
}
