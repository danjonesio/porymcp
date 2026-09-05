package proxy

import "net/http"

// copyHopHeaders forwards the headers of a client's own request that an
// upstream may need to act on. The credential the request is made with is not
// among them, mcpclient.ApplyAuth writes that, after this, from the stored
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

// copyResponseHeaders writes back the upstream response headers a client needs
// to speak Streamable HTTP, and no others. It is an allowlist for the same
// reason copyHopHeaders is: a name nobody has thought about cannot cross by
// accident. Get and Set, as copyHopHeaders does, because every name here is
// single valued; Get canonicalises the lookup, so the names stay in the
// spelling the specs use. Set replaces rather than duplicates, so no name that
// applyCORS or webutil.SecurityHeaders writes may ever be added here: it would
// replace PoryMCP's value with the upstream's in silence, and no test in this
// package can see that, because the fixture runs without the middleware.
// Nothing is logged: two of the names this drops are credential-equivalent.
// PORM-5's streaming path calls this same function against the live response
// header before its first write; Mcp-Protocol-Version and Last-Event-ID are
// request headers and must not be added back there.
func copyResponseHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Content-Type",
		"Mcp-Session-Id",
		"Retry-After",
	} {
		if v := src.Get(key); v != "" {
			dst.Set(key, v)
		}
	}
}
