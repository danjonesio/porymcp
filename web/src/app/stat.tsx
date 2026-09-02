import { Divider } from '@/components/divider'

/**
 * One number on the Overview: a rule above, a truncated title, the value at
 * the display scale (a step smaller from `sm:`), and an optional muted hint.
 */
const title = 'mt-6 truncate text-lg/6 font-medium sm:text-sm/6'
const value = 'mt-3 text-3xl font-semibold tabular-nums sm:text-2xl'
const hintText = 'mt-3 text-base/7 text-zinc-500 sm:text-sm/6'

export function Stat(props: { title: string; value: string; hint?: string }) {
  return (
    <div>
      <Divider />
      <div className={title}>{props.title}</div>
      <div className={value}>{props.value}</div>
      {props.hint ? <div className={hintText}>{props.hint}</div> : null}
    </div>
  )
}
