'use client'

import { Button } from '@/components/button'
import { HelpDisclosure } from '@/components/help-disclosure'
import { Code, Text } from '@/components/text'
import type { DiscoveredTool, Discovery } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { hostOf, plainHTTPCredential, scopedToolName } from '@/lib/discovery'
import clsx from 'clsx'
import { useEffect, useRef, useState } from 'react'

/** What one discovery request looks like from the outside, on either surface. */
export type DiscoveryState = {
  result: Discovery | null
  pending: boolean
  error: string
}

export const IDLE: DiscoveryState = { result: null, pending: false, error: '' }

/**
 * The facts about the server itself, without the catalogue. Exported on its own
 * so a caller can show what the handshake learned when the rest of the panel has
 * nothing to show. PORM-58 made this dialog the connection test rather than
 * building a second surface for it: there is no other place these belong.
 */
export function DiscoverySummary({ result }: { result: Discovery }) {
  const info = result.server_info
  const server = info ? [info.name, info.version].filter(Boolean).join(' ') : ''
  return (
    <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <div>
        <dt className="text-base/7 font-medium sm:text-sm/6">Server</dt>
        {/* Upstream-controlled text: React children, left-to-right, and it wraps. */}
        <dd dir="ltr" className="mt-1 text-base/7 wrap-break-word text-zinc-500 sm:text-sm/6 dark:text-zinc-400">
          {server || 'Not reported'}
        </dd>
      </div>
      <div>
        <dt className="text-base/7 font-medium sm:text-sm/6">Tools</dt>
        <dd className="mt-1 text-base/7 text-zinc-500 tabular-nums sm:text-sm/6 dark:text-zinc-400">
          {result.tool_count}
        </dd>
      </div>
      <div>
        <dt className="text-base/7 font-medium sm:text-sm/6">Latency</dt>
        <dd className="mt-1 text-base/7 text-zinc-500 tabular-nums sm:text-sm/6 dark:text-zinc-400">
          {result.latency_ms} ms
        </dd>
      </div>
      {result.protocol_version ? (
        <div>
          <dt className="text-base/7 font-medium sm:text-sm/6">Protocol</dt>
          <dd dir="ltr" className="mt-1 text-base/7 wrap-break-word text-zinc-500 sm:text-sm/6 dark:text-zinc-400">
            {result.protocol_version}
          </dd>
        </div>
      ) : null}
    </dl>
  )
}

/**
 * One tool: the name the server publishes, the name a group endpoint gives it,
 * and the description. The row is a flex line whose first slot is free, so
 * PORM-4's per-tool checkbox drops in ahead of the names without restructuring.
 */
export function ToolRow({
  tool,
  scoped,
  clamped,
  copyLabel,
  onCopy,
}: {
  tool: DiscoveredTool
  scoped: string
  clamped: boolean
  copyLabel?: string
  onCopy?: () => void
}) {
  return (
    <li className="flex items-start gap-3 py-2 first:pt-0 last:pb-0">
      <div className="min-w-0 flex-1">
        <div dir="ltr" className="text-base/6 break-all sm:text-sm/6">
          <Code>{tool.name}</Code>
        </div>
        {scoped ? (
          <div dir="ltr" className="font-mono text-base/6 break-all text-zinc-500 sm:text-sm/6 dark:text-zinc-400">
            {scoped}
          </div>
        ) : null}
        {tool.description ? (
          <p
            dir="ltr"
            className={clsx(
              'mt-1 text-base/6 text-pretty wrap-break-word text-zinc-500 sm:text-sm/6 dark:text-zinc-400',
              clamped && 'line-clamp-3'
            )}
          >
            {tool.description}
          </p>
        ) : null}
      </div>
      {onCopy ? (
        <Button type="button" plain className="shrink-0" aria-label={`Copy ${scoped}`} onClick={onCopy}>
          {copyLabel}
        </Button>
      ) : null}
    </li>
  )
}

/**
 * The result of one discovery request, rendered the same way in the Add upstream
 * dialog and in a saved upstream's Tools dialog.
 *
 * Everything an upstream sends (tool names, descriptions, server name, the
 * message behind a JSON-RPC error) is a React text child and nothing else: no
 * markdown, no title attribute, no link built from it. Long descriptions are
 * clamped with CSS rather than cut with slice(), so the whole string is one
 * press away and nothing is hidden from a reader who is looking for it.
 *
 * `surface` says which of the two dialogs this is. On a draft the scoped names
 * are a preview computed from a slug the server has not agreed to yet, which is
 * also why the preview carries no Copy button: an allow rule written against a
 * slug that changes at create time fails open. On a saved upstream the run is
 * recorded on the row, and the panel says so.
 */
export function DiscoveryPanel({
  result,
  pending,
  error,
  url,
  authType,
  slug,
  surface,
  className,
}: DiscoveryState & {
  /** The URL this discovery was aimed at, for the pending line and the plain-http note. */
  url: string
  authType: string
  /** The upstream's slug, or the create dialog's preview of it. Empty means no scoped names. */
  slug: string
  /** A saved upstream's Tools dialog, or the Add upstream dialog's unsaved form. */
  surface: 'saved' | 'draft'
  className?: string
}) {
  // One discriminant, not two complementary flags: "the slug is a preview" and
  // "this run was not recorded" are the same fact about the same dialog.
  const provisional = surface === 'draft'
  const [expanded, setExpanded] = useState(false)
  // Keyed by the scoped name rather than the row's position: a Refresh can put a
  // different tool at the same index, and "Copied" against the wrong identity is
  // the one thing this label must never say.
  const [copied, setCopied] = useState<{ name: string; ok: boolean } | null>(null)
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const host = hostOf(url)
  // A request that never produced a Discovery, or one that did and says the
  // upstream refused. The server's sentence is printed verbatim: the dashboard
  // never pattern-matches it.
  const failure = error || (result && !result.ok ? result.error || 'That server could not be reached.' : '')
  const unnameable = result?.unnameable_tools ?? 0
  const clampable = !!result?.tools.some((t) => t.description)
  // The server keeps what the handshake learned on a discovery that failed
  // later, because "initialize worked, tools/list did not" is the most useful
  // thing an operator can be told. Show it whenever it is there.
  const learned = !!result && (!!result.protocol_version || !!result.server_info || result.latency_ms > 0)
  // Anything that prints above the summary needs a gap under it.
  const notes = !!failure || !!result?.upstream_message || (!!result && plainHTTPCredential(url, authType))

  // Only the label timer to tidy up. The dialog can close a second after a Copy,
  // and a timeout that outlives the panel would set state on nothing.
  useEffect(
    () => () => {
      if (copyTimer.current) clearTimeout(copyTimer.current)
    },
    []
  )

  async function copy(scoped: string) {
    const ok = await copyText(scoped)
    if (copyTimer.current) clearTimeout(copyTimer.current)
    setCopied({ name: scoped, ok })
    copyTimer.current = setTimeout(() => setCopied(null), 1500)
  }

  return (
    <section aria-live="polite" aria-busy={pending} className={className}>
      {pending ? <Text>{host ? `Connecting to ${host}…` : 'Connecting…'}</Text> : null}
      {failure ? (
        <p className="text-base/7 wrap-break-word text-pink-600 sm:text-sm/6 dark:text-pink-400">{failure}</p>
      ) : null}
      {result?.upstream_message ? (
        <Text dir="ltr" className="mt-2 wrap-break-word">
          The server said: {result.upstream_message}
        </Text>
      ) : null}
      {result && plainHTTPCredential(url, authType) ? (
        <Text className="mt-2">This upstream uses plain http, so the credential travels unencrypted.</Text>
      ) : null}

      {learned && result ? (
        <div className={clsx(notes && 'mt-6')}>
          <DiscoverySummary result={result} />
        </div>
      ) : null}

      {/* What PoryMCP keeps, said once a run has answered, pass or fail, and
          never under an idle, pending or errored panel, where there is nothing
          to have kept. */}
      {result ? (
        <Text className="mt-3">
          {surface === 'saved'
            ? 'PoryMCP records when this upstream was last tested and whether it passed. The Status column shows it. The tool list itself is not stored; this is what the server said just now.'
            : 'Discovered just now from the server; PoryMCP does not store this list.'}
        </Text>
      ) : null}

      {result?.ok ? (
        <>
          {result.tools.length === 0 ? (
            <Text className="mt-6">No tools. This server answered, and its catalogue is empty.</Text>
          ) : (
            <>
              <Text className="mt-6">
                {slug
                  ? 'Each tool is listed by the name this server publishes, then by the name a group endpoint gives it.'
                  : 'Each tool is listed by the name this server publishes.'}
              </Text>
              {slug ? null : (
                <Text className="mt-2">
                  Name this upstream to see the names a group endpoint would give these tools.
                </Text>
              )}

              {clampable ? (
                <div className="mt-2 flex justify-end">
                  <Button type="button" plain onClick={() => setExpanded(!expanded)}>
                    {expanded ? 'Shorten descriptions' : 'Show full descriptions'}
                  </Button>
                </div>
              ) : null}

              {/* The dialog itself scrolls, so the list only gets its own scroller
                  from sm: up, since a nested touch scroller on a phone is a trap. */}
              <div className="mt-2 rounded-lg bg-zinc-50 p-3 ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:shadow-none dark:inset-ring dark:inset-ring-white/5">
                <ul
                  role="list"
                  className="divide-y divide-zinc-950/5 sm:max-h-96 sm:overflow-y-auto dark:divide-white/5"
                >
                  {result.tools.map((tool, index) => {
                    // The server's own value when it sent one (saved route); the
                    // dialog's preview otherwise.
                    const scoped = tool.scoped_name || scopedToolName(slug, tool.name)
                    return (
                      <ToolRow
                        key={index}
                        tool={tool}
                        scoped={scoped}
                        clamped={!expanded}
                        copyLabel={copied?.name === scoped ? (copied.ok ? 'Copied' : 'Copy failed') : 'Copy'}
                        onCopy={!provisional && scoped ? () => copy(scoped) : undefined}
                      />
                    )
                  })}
                </ul>
              </div>

              {/* Not "the first 500": the page cap and the repeated-cursor guard
                  both truncate, usually well under 500, so the panel names the
                  count it actually has rather than a number it may not. */}
              {result.truncated ? (
                <Text className="mt-3">
                  {`Not every tool is listed. ${result.tool_count} shown. This server offers more.`}
                </Text>
              ) : null}
              {unnameable > 0 ? (
                <Text className="mt-3">
                  {unnameable === 1
                    ? '1 tool is not listed: its name contains characters PoryMCP cannot hold a caller to.'
                    : `${unnameable} tools are not listed: their names contain characters PoryMCP cannot hold a caller to.`}
                </Text>
              ) : null}
            </>
          )}

          {result.tools.length > 0 ? (
            <div className="mt-6">
              <HelpDisclosure label="Which name do I use?">
                <p>
                  The first name is the one this server publishes. A client connected to this upstream’s own endpoint
                  sees exactly that.
                </p>
                <p>
                  The second is the name a group endpoint gives the same tool: the upstream’s slug, two underscores,
                  then the tool’s own name. It is also the name a group’s tool filter matches, so an allow rule has to
                  be written in that form. A deny rule accepts either.
                </p>
                {provisional ? (
                  <p>
                    The slug shown here is a preview. If another upstream already holds it, PoryMCP picks the next free
                    one when you create this upstream, and these names change to match.
                  </p>
                ) : null}
              </HelpDisclosure>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  )
}
