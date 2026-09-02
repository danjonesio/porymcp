/**
 * Copy to the clipboard, reporting whether it worked. navigator.clipboard is
 * undefined outside a secure context, and PoryMCP is routinely served over plain
 * http on a LAN address, so the unguarded call throws and the button dies
 * silently. The caller says "Copy failed" instead of nothing. PORM-108 moves the
 * virtual-key dialog's own copy buttons onto this.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
