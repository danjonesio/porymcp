/** "1 upstream", "3 upstreams". English plurals for the nouns the dashboard counts. */
export function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}
