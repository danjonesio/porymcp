package proxy

import "net/http"

// copyHopHeaders forwards the headers of a client's own request that an
// upstream may need to act on. The credential the request is made with is not
// among them, mcpclient.ApplyAuth writes that, after this, from the stored
// upstream config. src may be nil: forward calls this a second time with the
// aggregate's override, which is nil for every request but a group's
// tools/call, so the allowlist stays the one writer of outbound client
// headers and an override cannot introduce a name that is not on it.
//
// Mcp-Method and Mcp-Name are the 2026-07-28 revision's routing headers,
// held to the body by checkRoutingHeaders before anything reaches here. The
// eight named headers are single valued and go through Set, never Add, so no
// duplicate line can be created on the way out. The Mcp-Param- family is the
// one prefix on this list. The revision says an intermediary that does not
// recognise an Mcp-Param-{Name} header MUST forward it and otherwise ignore
// it, so every value crosses, copied whole rather than through Get, which
// reads one; serve bounds the count and the size before the body is read
// (checkParamHeaders) and the character set after it (checkRoutingHeaders).
func copyHopHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Accept",
		"Accept-Language",
		"Content-Type",
		"Mcp-Session-Id",
		"Mcp-Protocol-Version",
		"Last-Event-ID",
		hdrMethod,
		hdrName,
	} {
		if v := src.Get(key); v != "" {
			dst.Set(key, v)
		}
	}
	for name, vals := range src {
		if isParamHeader(name) {
			dst[name] = append([]string(nil), vals...)
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
