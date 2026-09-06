/**
 * The one rule behind the Transport cell, the Edit dialog's select and the
 * group dialog's member line (PORM-28). `streamable-http` is the only transport
 * PoryMCP speaks to an upstream; `''` reads as the same default the server
 * applies. Anything else is a stored value the proxy refuses on every request:
 * `sse`, which the API accepted before PORM-28 without implementing it, or a
 * column edited by hand. The dashboard shows the value with an Unsupported
 * badge and offers Streamable HTTP as the repair; it never rewrites the row.
 */
export function transportUnsupported(transport: string): boolean {
  return !(transport === 'streamable-http' || transport === '')
}
