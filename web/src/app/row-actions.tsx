'use client'

import { EllipsisHorizontalIcon } from '@heroicons/react/16/solid'
import { Fragment } from 'react'
import { Button } from '@/components/button'
import { Dropdown, DropdownButton, DropdownDivider, DropdownItem, DropdownLabel, DropdownMenu } from '@/components/dropdown'
import { actionsTriggerName, type RowAction } from '@/lib/row-actions'

/**
 * A table row's one Actions button and its menu (PORM-219). The page passes
 * the sections web/src/lib/row-actions.ts declares, already bound to its
 * handlers; a divider sits between two sections. The trigger is the icon
 * alone, named for the row, since the column header already reads Actions.
 * While `busyLabel` is set the label shows before the icon, so the icons
 * stay in one column, and it starts the accessible name. The menu opens
 * from the trigger's end so it stays inside the pane from the last column.
 */
export function RowActions({
  name,
  sections,
  disabled = false,
  busyLabel = null,
  className,
}: {
  name: string
  sections: RowAction[][]
  disabled?: boolean
  busyLabel?: string | null
  className?: string
}) {
  return (
    <Dropdown>
      <DropdownButton
        as={Button}
        plain
        disabled={disabled}
        aria-label={actionsTriggerName(name, busyLabel)}
        className={className}
      >
        {busyLabel ? <span>{busyLabel}</span> : null}
        <EllipsisHorizontalIcon />
      </DropdownButton>
      <DropdownMenu anchor="bottom end">
        {sections.map((section, i) => (
          <Fragment key={section[0].label}>
            {i > 0 ? <DropdownDivider /> : null}
            {section.map((item) => (
              <DropdownItem key={item.label} destructive={item.destructive} onClick={item.onSelect}>
                <DropdownLabel>{item.label}</DropdownLabel>
              </DropdownItem>
            ))}
          </Fragment>
        ))}
      </DropdownMenu>
    </Dropdown>
  )
}
