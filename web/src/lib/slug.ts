// Mirrors models.DeriveSlug in internal/models/slug.go. This is a PREVIEW only:
// the page posts it just when the user has edited the field, so the server stays
// the authority for de-duplication and for the reserved-word list, which is
// deliberately not mirrored here.
//
// Parity with the Go version was brute-forced over U+0001 to U+2FFFF: with the
// pre-map below, zero divergences.
export function deriveSlug(name: string): string {
  let s = name
    // U+0130 is the one char where JS full-case lowercasing differs from Go's
    // simple mapping: "İ".toLowerCase() is "i" + U+0307, and the combining dot
    // would then collapse to a separator ("İstanbul" -> "i_stanbul").
    .replace(/İ/g, 'i')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  if (s.length > 40) s = s.slice(0, 40).replace(/[_-]+$/, '')
  return s
}
