package audit

import (
	"strings"

	"github.com/danjonesio/porymcp/internal/redact"
)

// ErrorMessageBytes is the most an audit row's error_message holds. Record
// applies it to every row after redaction, so a credential cut at the
// boundary is already gone before the cut. It is 256, the twin of
// AdminTextBytes and of internal/proxy's auditFieldBytes, kept separate for
// the reason recorded at internal/mcpclient/client.go beside MaxErrorBytes.
const ErrorMessageBytes = 256

// errorText is what Record stores: the injected literals replaced
// (PORM-208), the message cut to the scan window (with a trailing run of
// credential characters dropped when the cut fired), redacted, cut to
// ErrorMessageBytes, then cloned so a queued row never keeps the upstream's
// body alive. It does not call Text: Scrub would move exactly-pinned rows,
// and the invisible-character class is PORM-83's.
func errorText(s string, literals ...string) string {
	return strings.Clone(redact.RedactClamped(s, ErrorMessageBytes, literals))
}
