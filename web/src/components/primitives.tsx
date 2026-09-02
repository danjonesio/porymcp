import clsx from 'clsx'

/**
 * The recipes every PoryMCP component shares — the keyboard focus ring, the
 * chrome of a text control, and the touch target — defined once so each is one
 * decision rather than a copy per file. Components compose these by name.
 * Nothing else is added here without a reason in the build record.
 */

/**
 * Keyboard-visible focus: a 2px outline in the project's focus colour, offset
 * so it clears the control. Headless UI sets `data-focus` only for
 * focus-visible, so a mouse click never paints it. `focus:outline-hidden`
 * suppresses the browser's own ring while focused (its forced-colors branch
 * keeps a transparent outline there, so high-contrast mode still shows one —
 * and only on the focused element, which is why it is gated on `focus:`).
 * In Tailwind v4 it also sets the outline style variable to `none`, which is
 * why the focused state must name `outline-solid` explicitly.
 */
export const focusRing =
  'focus:outline-hidden data-focus:outline-2 data-focus:outline-offset-2 data-focus:outline-focus data-focus:outline-solid'

/**
 * The wrapper around a text control (`data-slot="control"`): the light-mode
 * backing and shadow, nothing in dark, dimmed when the control is disabled, and
 * an outline in forced-colors mode because box-shadows are stripped there.
 */
export const controlFrame =
  'relative block w-full rounded-lg bg-white shadow-sm has-data-disabled:bg-zinc-950/5 has-data-disabled:opacity-50 has-data-disabled:shadow-none dark:bg-transparent dark:shadow-none forced-colors:outline'

/**
 * The `<input>`, `<select>` or `<textarea>` itself. The border is an inset ring,
 * so the padding is the plain mobile-first scale and the control still renders
 * at the same height as a bordered one. Each control adds its own focus
 * treatment on top (the text controls gate theirs to `sm:` and up).
 */
export const controlField =
  'block w-full appearance-none rounded-lg bg-transparent px-3.5 py-2.5 text-base/6 text-zinc-950 ring-1 ring-zinc-950/10 ring-inset placeholder:text-zinc-500 hover:ring-zinc-950/20 focus:outline-hidden data-invalid:ring-red-500 data-invalid:hover:ring-red-500 sm:px-3 sm:py-1.5 sm:text-sm/6 dark:bg-white/5 dark:text-white dark:scheme-dark dark:ring-white/10 dark:hover:ring-white/20 dark:data-invalid:ring-red-600'

/**
 * Expands a small control's hit area to 44px on coarse pointers; paints
 * nothing and is invisible to assistive tech. The parent must be `relative`;
 * render it as the first child, before the control's content.
 */
export function TouchTarget() {
  return (
    <span
      aria-hidden="true"
      className="absolute top-1/2 left-1/2 size-[max(100%,2.75rem)] -translate-1/2 pointer-fine:hidden"
    />
  )
}

/**
 * The layout of a checkbox or radio row: control in the first column, label
 * beside it, description under the label; the label turns medium when a
 * description is present. Shared by `CheckboxField` and `RadioField`.
 */
export const optionField = clsx(
  'grid grid-cols-[auto_1fr] items-start gap-x-4 gap-y-1',
  '*:data-[slot=control]:mt-0.75 sm:*:data-[slot=control]:mt-1',
  '*:data-[slot=description]:col-start-2',
  'has-data-[slot=description]:**:data-[slot=label]:font-medium'
)
