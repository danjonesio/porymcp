package proxy

import "net/http"

// copyHopHeaders forwards the headers of a client's own request that an
// upstream may need to act on. The credential the request is made with is not
// among them — mcpclient.ApplyAuth writes that, after this, from the stored
// upstream config.
func copyHopHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Accept",
		"Accept-Language",
		"Content-Type",
		"Mcp-Session-Id",
		"Mcp-Protocol-Version",
		"Last-Event-ID",
	} {
		if v := src.Get(key); v != "" {
			dst.Set(key, v)
		}
	}
}
