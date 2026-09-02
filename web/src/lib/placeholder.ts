/**
 * Shown while a value is still being fetched. U+00A0 (written as the escape,
 * never as a typed space) keeps a tile's line box; a plain space collapses.
 */
export const LOADING = '\u00a0'

/**
 * Shown for a value that will never exist for this row: a key with no
 * endpoint, a log line for a call that named no tool. Matches the word the
 * groups table already renders for an empty upstream list.
 */
export const ABSENT = 'None'
