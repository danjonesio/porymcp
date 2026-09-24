package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
)

// The streaming relay (PORM-5). An upstream that answers a POST with an event
// stream, a subscriptions/listen it holds open or a tools/call that sends
// progress notifications before its result, is relayed to the client as it
// arrives on a member or single-upstream endpoint: the headers go out as soon
// as the upstream's do, and every read is written and flushed at once, keep-
// alive lines included. The audit row is written once, when the stream ends,
// with the bytes relayed and a status judged from the answering event.
//
// The group endpoint never streams: it reads a member's answer whole to reduce
// or merge it, and a tools/list is read whole on every route so the per-key
// filter can rewrite it. Both are decided by streamable, from the response
// header alone, so the JSON path reads nothing it did not read before.

// streamable reports whether an upstream's answer is relayed as it arrives:
// a 2xx labelled text/event-stream, on a route that relays 1:1, for a method
// whose answer the proxy does not rewrite. A non-2xx event stream stays
// buffered so the client gets a status it can read and answerStatus judges the
// whole body; an unlabelled body stays buffered and is sniffed as before,
// because sniffing needs bytes and this decision is made before any are read.
func streamable(onAggregate bool, method string, resp *http.Response) bool {
	return !onAggregate && method != "tools/list" &&
		resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		mcpclient.MediaType(resp.Header.Get("Content-Type")) == "text/event-stream"
}

// streamCapture keeps what a stream's row needs and no more: head, the first
// judgeHeadBytes, which holds an early error and the unframed-JSON case; last,
// the most recent complete event that is not a comment, which is where a
// server puts its answer before it closes the stream; and pending, the event
// in progress. Boundaries (a blank line: a line terminator followed at once by
// another, in any of the four CR and LF spellings) are found in one forward
// pass over the new bytes, with a three-byte seam against the previous read so
// a boundary split across two reads is seen, and nothing is parsed while
// relaying. Only the last event of a read is copied, and pending is compacted
// once per read. An event that would pass judgeTailBytes is never kept: the
// event in progress is dropped the moment its next read would take it over,
// and only its last three bytes stay until the next boundary, so a stream
// that never sends a blank line costs at most one read buffer. A completed
// event over the cap leaves last empty with lastOverflow set. Arrays that grew
// past the cap are released the next time they are reset.
type streamCapture struct {
	head, last, pending []byte
	// pendingOverflow: the event in progress passed judgeTailBytes and is
	// being dropped. lastOverflow: the most recent complete event did, so last
	// is empty for that reason and not because nothing has arrived.
	pendingOverflow, lastOverflow bool
}

// tailOverflowed reports that the most recent event, complete or in progress,
// was larger than the judge keeps: an answer may have gone by unjudged.
func (c *streamCapture) tailOverflowed() bool { return c.lastOverflow || c.pendingOverflow }

// boundaryEnd is the offset just past the first blank line in b at or after
// from, or -1. Only the end matters: it is where the next event starts.
func boundaryEnd(b []byte, from int) int {
	for j := from; j < len(b); {
		k := bytes.IndexByte(b[j:], '\n')
		if k < 0 {
			return -1
		}
		j += k
		switch {
		case j+1 < len(b) && b[j+1] == '\n':
			return j + 2
		case j+2 < len(b) && b[j+1] == '\r' && b[j+2] == '\n':
			return j + 3
		}
		j++
	}
	return -1
}

// seamBytes is how much of the previous read a boundary can straddle: "\r\n\r"
// at the end of one read and "\n" at the start of the next.
const seamBytes = 3

// unknownStart marks an event whose start was dropped as oversized.
const unknownStart = math.MinInt

func (c *streamCapture) Write(p []byte) {
	if len(c.head) < judgeHeadBytes {
		n := min(len(p), judgeHeadBytes-len(c.head))
		c.head = append(c.head, p[:n]...)
	}
	// The seam: a boundary that begins in the last bytes of pending and ends
	// in p is found here, and the scan of p starts past it.
	var seam [2 * seamBytes]byte
	ov := c.pending
	if len(ov) > seamBytes {
		ov = ov[len(ov)-seamBytes:]
	}
	k := copy(seam[:], ov)
	m := copy(seam[k:], p)
	scan := 0
	if e := boundaryEnd(seam[:k+m], 0); e > k {
		scan = e - k
	}
	// Offsets are in p's coordinates; an event that began in pending starts
	// at a negative offset, and one that began in a dropped oversized event
	// at unknownStart.
	start := -len(c.pending)
	if c.pendingOverflow {
		start = unknownStart
	}
	lastStart, lastEnd, found := 0, 0, false
	consumed := false
	firstByte := func(at int) byte {
		if at < 0 {
			return c.pending[len(c.pending)+at]
		}
		return p[at]
	}
	// commentOnly reports whether every line of the event [from, to) starts
	// with a colon: a keep-alive, which never replaces the event that
	// answered. An event that opens with a comment line and carries data
	// lines after it is data. Only an event whose first byte is a colon is
	// walked, so the cost falls on keep-alives, which are a few bytes.
	commentOnly := func(from, to int) bool {
		if firstByte(from) != ':' {
			return false
		}
		lineStart := false
		for i := from; i < to; i++ {
			b := firstByte(i)
			if lineStart && b != ':' && b != '\n' && b != '\r' {
				return false
			}
			lineStart = b == '\n' || b == '\r'
		}
		return true
	}
	consume := func(end int) {
		consumed = true
		if start == unknownStart || !commentOnly(start, end) {
			lastStart, lastEnd, found = start, end, true
		}
		start = end
	}
	if scan > 0 {
		consume(scan)
	}
	for {
		e := boundaryEnd(p, scan)
		if e < 0 {
			break
		}
		consume(e)
		scan = e
	}
	if !consumed {
		switch {
		case c.pendingOverflow:
			c.pending = tailOf(c.pending, c.pending, p)
		case len(c.pending)+len(p) > judgeTailBytes:
			// The event in progress would pass the cap: drop it now, keep the
			// seam, and release the array it grew in.
			c.pendingOverflow = true
			c.pending = tailOf(make([]byte, 0, seamBytes), c.pending, p)
		default:
			c.pending = append(c.pending, p...)
		}
		return
	}
	// The last non-comment event of this read is kept whole when it fits; a
	// read that completed only comment events leaves last as it was.
	switch {
	case !found:
	case lastStart == unknownStart || lastEnd-lastStart > judgeTailBytes:
		c.lastOverflow = true
		c.last = c.last[:0]
	default:
		c.lastOverflow = false
		if cap(c.last) > judgeTailBytes {
			c.last = nil
		}
		c.last = c.last[:0]
		if lastStart < 0 {
			c.last = append(c.last, c.pending[len(c.pending)+lastStart:]...)
			c.last = append(c.last, p[:lastEnd]...)
		} else {
			c.last = append(c.last, p[lastStart:lastEnd]...)
		}
	}
	// What follows the last boundary is the new event in progress: at most
	// one read, so it cannot pass the cap here.
	c.pendingOverflow = false
	if cap(c.pending) > judgeTailBytes {
		c.pending = nil
	}
	c.pending = append(c.pending[:0], p[start:]...)
}

// tailOf writes the last seamBytes of a followed by b into dst (reset to
// empty) and returns it, allocating nothing when dst has the room.
func tailOf(dst, a, b []byte) []byte {
	dst = dst[:0]
	need := seamBytes
	if len(b) >= need {
		return append(dst, b[len(b)-need:]...)
	}
	fromA := need - len(b)
	if fromA > len(a) {
		fromA = len(a)
	}
	var tmp [seamBytes]byte
	n := copy(tmp[:], a[len(a)-fromA:])
	n += copy(tmp[n:], b)
	return append(dst, tmp[:n]...)
}

// answerDoc reports whether b holds the answer to the request carrying wantID:
// a JSON-RPC document with a result or an error member and, when the request
// had an id, that id. PickResponse picks the document out of an event stream;
// when it finds none the raw bytes are read as one document, which is what an
// unframed JSON body under an event-stream label is. A lone notification is
// not an answer, whatever PickResponse's lenient rule for a lone object says,
// and an answer to some other id is not this request's.
func answerDoc(ct string, b []byte, wantID string) bool {
	if len(bytes.TrimSpace(b)) == 0 {
		return false
	}
	doc, err := mcpclient.PickResponse(ct, b, wantID)
	if err != nil {
		doc = b
	}
	var env struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(doc, &env) != nil || (env.Result == nil && env.Error == nil) {
		return false
	}
	return wantID == "" || strings.TrimSpace(string(env.ID)) == wantID
}

// streamEnd is why a relayed stream stopped.
type streamEnd int

const (
	endUpstream  streamEnd = iota // the upstream closed the stream
	endClient                     // the client closed it, or stopped reading it
	endIdle                       // the upstream sent nothing for streamIdleBudget
	endStopped                    // the proxy is shutting down
	endRevoked                    // the key or the upstream stopped being valid
	endReadError                  // the upstream connection failed
)

func (e streamEnd) String() string {
	switch e {
	case endUpstream:
		return "upstream"
	case endClient:
		return "client"
	case endIdle:
		return "idle"
	case endStopped:
		return "stopped"
	case endRevoked:
		return "revoked"
	default:
		return "read_error"
	}
}

// endByCause reads why the upstream request's context is done, when it is:
// the proxy's own causes first, then the client's request context (a client
// that went away cancels with no cause of its own), then fallback.
func endByCause(ctx context.Context, r *http.Request, fallback streamEnd) (streamEnd, error) {
	cause := context.Cause(ctx)
	var be *budgetError
	switch {
	case errors.As(cause, &be):
		return endIdle, cause
	case errors.Is(cause, errStreamStopped):
		return endStopped, cause
	case errors.Is(cause, errStreamRevoked), errors.Is(cause, errUpstreamRemoved), errors.Is(cause, errUpstreamChanged):
		return endRevoked, cause
	case r.Context().Err() != nil:
		return endClient, nil
	}
	return fallback, nil
}

// streamVerdict is a streamed row's status and message. The answer is judged
// before the end: a tools/call whose result reached the client is a success
// however the connection ended afterwards. Only a stream with no answer falls
// through to the end rules, where a subscriptions/listen is the exception: the
// client closing it, the upstream closing it, the upstream going quiet and the
// proxy stopping are all how a listen ends, and none of them is an error.
// An event larger than judgeTailBytes is not judged; when the upstream ended
// the stream itself after one, the answer was that event and the row is a
// success (docs/03-api.md says so).
func streamVerdict(method string, status int, ct string, c *streamCapture, wantID string, end streamEnd, err error) (string, string) {
	for _, b := range [][]byte{c.last, c.head} {
		if answerDoc(ct, b, wantID) {
			return answerStatus(status, ct, b, wantID)
		}
	}
	listen := method == "subscriptions/listen"
	switch end {
	case endReadError:
		// Never err's own text: a read error names the resolved address.
		return models.StatusError, readErrorText(err)
	case endRevoked:
		return models.StatusError, err.Error()
	case endIdle:
		if listen {
			return models.StatusSuccess, ""
		}
		return models.StatusError, err.Error()
	case endStopped:
		if listen {
			return models.StatusSuccess, ""
		}
		return models.StatusError, errStreamStopped.Error()
	case endClient:
		if listen {
			return models.StatusSuccess, ""
		}
		return models.StatusError, "client closed the stream before the answer"
	default:
		if listen || c.tailOverflowed() {
			return models.StatusSuccess, ""
		}
		return models.StatusError, "upstream closed the stream before the answer"
	}
}

// streamRow is what the row and the re-check need from the request, fixed
// before the first byte is relayed.
type streamRow struct {
	vk                                   *models.VirtualKey
	requestID, method, auditMethod, tool string
	upstreamID                           string
	upstream                             *models.Upstream // as read for the request
	params                               json.RawMessage
	start                                time.Time
	wantID                               string
	memberPath                           bool
	slug                                 string
}

// relayStream relays resp's body to the client as it arrives and writes the
// row once, when the stream ends. ctx is the upstream request's context from
// upstreamContext, its answer timer already disarmed; cancel ends the upstream
// request, with the cause that becomes the row's reason.
//
// Three timers watch the stream from other goroutines: the idle bound, the
// stop signal and the re-check. Each cancels the upstream request and sets the
// client connection's write deadline to now, so a Write blocked on a client
// that stopped reading returns as well. Every callback first checks a done
// flag under one mutex, set when the relay returns, so a late callback cannot
// touch a keep-alive connection that is already serving the key's next
// request; the re-check reschedules itself only while the stream is open.
//
// The row is written from a defer, so it is written on every exit, the abort
// below included. A stream cut by the proxy (idle, revoked, a failed upstream
// read) ends with http.ErrAbortHandler, the way httputil.ReverseProxy cuts a
// broken stream: the connection is dropped and the client sees the stream cut
// short, since a status can no longer be changed and the proxy writes nothing
// of its own inside a relayed body. The other ends return normally.
func (h *Handler) relayStream(w http.ResponseWriter, r *http.Request, ctx context.Context, cancel context.CancelCauseFunc, resp *http.Response, row streamRow) {
	idle, recheck := streamIdleBudget, streamRecheckBudget

	// Before the first write, as on the buffered path, and under a context
	// that is still live: a client that leaves mid-stream cancels r.Context().
	_ = h.store.TouchVirtualKey(r.Context(), row.vk.ID)

	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	flush := func() error {
		err := rc.Flush()
		if errors.Is(err, http.ErrNotSupported) {
			return nil
		}
		return err
	}
	if err := rc.Flush(); errors.Is(err, http.ErrNotSupported) && h.log != nil {
		h.log.Warn("stream relayed without flushing: the response writer cannot flush",
			"request_id", row.requestID, "virtual_key_id", row.vk.ID, "upstream_id", row.upstreamID)
	}

	var mu sync.Mutex
	done := false
	guard := func(fn func()) {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			fn()
		}
	}
	cut := func(cause error) {
		guard(func() {
			cancel(cause)
			_ = rc.SetWriteDeadline(time.Now())
		})
	}
	idleT := time.AfterFunc(idle, func() { cut(&budgetError{what: "sent nothing for", d: idle}) })
	stop := context.AfterFunc(h.streams, func() { cut(errStreamStopped) })
	// The re-check reads the store outside the lock, for up to its own 5 s,
	// so a slow store cannot hold the idle and stop callbacks or the relay's
	// exit; the done flag is read before it runs and again before it acts.
	// The timer is assigned under the lock its callback reads it under.
	var recheckT *time.Timer
	mu.Lock()
	recheckT = time.AfterFunc(recheck, func() {
		live := false
		guard(func() { live = true })
		if !live {
			return
		}
		if cause := h.recheck(r, &row); cause != nil {
			cut(cause)
			return
		}
		guard(func() { recheckT.Reset(recheck) })
	})
	mu.Unlock()

	open := h.openStreams.Add(1)
	if h.log != nil {
		h.log.Info("stream opened", "request_id", row.requestID, "virtual_key_id", row.vk.ID,
			"upstream_id", row.upstreamID, "method", row.auditMethod, "open_streams", open)
	}

	ct := resp.Header.Get("Content-Type")
	var capture streamCapture
	var written int64
	end := endUpstream
	var endErr error

	defer func() {
		mu.Lock()
		done = true
		mu.Unlock()
		idleT.Stop()
		recheckT.Stop()
		stop()
		resp.Body.Close() // without draining: a held stream would never drain
		cancel(nil)
		st, msg := streamVerdict(row.method, resp.StatusCode, ct, &capture, row.wantID, end, endErr)
		size := int(min(written, math.MaxInt32))
		h.finish(row.vk, row.requestID, row.auditMethod, row.tool, row.upstreamID, st,
			truncate(msg, auditFieldBytes), row.start, size, row.params)
		left := h.openStreams.Add(-1)
		if h.log != nil {
			h.log.Info("stream closed", "request_id", row.requestID, "virtual_key_id", row.vk.ID,
				"upstream_id", row.upstreamID, "method", row.auditMethod, "open_streams", left,
				"bytes", written, "ms", time.Since(row.start).Milliseconds(), "end", end.String())
		}
	}()

	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			capture.Write(buf[:n])
			// The idle bound measures the upstream's silence and nothing
			// else: it is stopped while the write to the client is in
			// flight, so a client that stopped reading is ended by the
			// write's own deadline, and its row says so.
			idleT.Stop()
			_ = rc.SetWriteDeadline(time.Now().Add(idle))
			if ctx.Err() != nil {
				// A callback set the deadline to now a moment ago; do not
				// overwrite it with a write that would wait the whole bound.
				end, endErr = endByCause(ctx, r, endClient)
				break
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				end, endErr = endByCause(ctx, r, endClient)
				break
			}
			if ferr := flush(); ferr != nil {
				end, endErr = endByCause(ctx, r, endClient)
				break
			}
			written += int64(n)
			idleT.Reset(idle)
		}
		if rerr == io.EOF {
			end = endUpstream
			break
		}
		if rerr != nil {
			end, endErr = endByCause(ctx, r, endReadError)
			if end == endReadError {
				endErr = rerr
			}
			break
		}
	}
	if end == endIdle || end == endRevoked || end == endReadError {
		panic(http.ErrAbortHandler)
	}
}

// recheck re-runs the request path's key and target checks for an open
// stream. It returns the cause the stream ends with, or nil to keep it open. A
// key that is gone, revoked, expired, rotated (its lookup changed) or pointed
// at another target is no longer the key that was authenticated
// (VirtualKey.Status is the rule authenticate applies); an upstream that is
// gone, disabled, or no longer in the group a member route serves is no
// longer reachable through the key; an upstream whose URL, transport or
// credential changed since the stream opened is not the upstream the stream
// was opened against (a new name or description is not such a change, and
// leaves the stream alone). The rows are read one by one rather
// than through resolveTargets, which skips a member it cannot read, so a read
// that failed is told from a row that is gone. A store that cannot be read
// leaves the stream open and says so in the log: the proxy fails open here,
// because a store hiccup ending every stream in the deployment would be worse
// than a minute's delay on a revocation.
//
// row is updated in place: a recheck that finds the upstream unchanged
// adopts the row it just read as the stream's baseline, so a token refresh
// (new bytes, same grant) is absorbed at the next recheck and a later rename
// compares equal bytes rather than a rotated refresh token against the one
// the stream opened with (PORM-139). A refresh and a rename inside one
// recheck interval still end the stream; that window is the limit recorded
// in docs/07-security.md.
func (h *Handler) recheck(r *http.Request, row *streamRow) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	warn := func(err error) {
		if h.log != nil {
			h.log.Warn("stream re-check could not read the store", "request_id", row.requestID,
				"virtual_key_id", row.vk.ID, "err", truncate(err.Error(), auditFieldBytes))
		}
	}
	vk, err := h.store.GetVirtualKey(ctx, row.vk.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errStreamRevoked
		}
		warn(err)
		return nil
	}
	if vk.Status() != "active" || vk.KeyLookup != row.vk.KeyLookup ||
		vk.TargetType != row.vk.TargetType || vk.TargetID != row.vk.TargetID {
		return errStreamRevoked
	}
	up, err := h.store.GetUpstream(ctx, row.upstreamID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errUpstreamRemoved
		}
		warn(err)
		return nil
	}
	if !up.Enabled {
		return errUpstreamRemoved
	}
	if h.upstreamChanged(row.upstream, up) {
		return errUpstreamChanged
	}
	row.upstream = up
	if vk.TargetType == models.TargetGroup {
		g, err := h.store.GetGroup(ctx, vk.TargetID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errUpstreamRemoved
			}
			warn(err)
			return nil
		}
		member := false
		for _, id := range g.UpstreamIDs {
			if id == row.upstreamID {
				member = true
				break
			}
		}
		if !member {
			return errUpstreamRemoved
		}
	}
	return nil
}

// upstreamChanged reports whether the fields a relayed request depends on
// moved between the row read for the request and the row read now: where the
// request goes and what credential it carries.
//
// For an oauth row the credential's bytes are not the credential (PORM-139):
// a token refresh re-seals the blob about once an hour and leaves updated_at
// alone, and a rekey re-seals every blob, neither of which is the upstream
// the stream was opened against changing. So for two oauth rows a byte change
// counts only when updated_at also moved (a connect, a disconnect or a PATCH
// that wrote the credential) AND the two blobs open to different grants; a
// rename after a refresh moves updated_at over new bytes and keeps the
// stream, as d3b9df8 says a rename must. A blob that will not open counts as
// changed.
func (h *Handler) upstreamChanged(was, now *models.Upstream) bool {
	if was.URL != now.URL || was.Transport != now.Transport || was.AuthType != now.AuthType {
		return true
	}
	if bytes.Equal(was.AuthConfig, now.AuthConfig) {
		return false
	}
	if was.AuthType != models.AuthOAuth || was.UpdatedAt.Equal(now.UpdatedAt) {
		return was.AuthType != models.AuthOAuth
	}
	return !h.sameGrant(was.AuthConfig, now.AuthConfig)
}

// sameGrant reports whether two sealed oauth blobs hold the same grant: the
// same refresh token, client and issuer. A vendor that issues no refresh
// token leaves nothing but the access token to tell two sign-ins apart, so
// two empty refresh tokens compare the access tokens instead: only a connect
// moves updated_at together with such a set, and a connect is a new grant.
// One AES-GCM open per blob, on the rare recheck where both the bytes and
// updated_at moved.
func (h *Handler) sameGrant(a, b []byte) bool {
	var sets [2]models.OAuthTokenSet
	for i, blob := range [][]byte{a, b} {
		plain, _, err := h.keys.Open(string(blob))
		if err != nil || json.Unmarshal(plain, &sets[i]) != nil {
			return false
		}
	}
	if sets[0].ClientID != sets[1].ClientID || sets[0].Issuer != sets[1].Issuer {
		return false
	}
	if sets[0].RefreshToken == "" && sets[1].RefreshToken == "" {
		return sets[0].AccessToken == sets[1].AccessToken
	}
	return sets[0].RefreshToken == sets[1].RefreshToken
}

// StopStreams ends every open stream and every stream that starts after it:
// each writes its row and returns, so a Shutdown that is waiting for the
// connection to go idle gets it. It is one-shot and exists for shutdown only
// (cmd/server registers it with the server's RegisterOnShutdown); a key
// revoked while its stream is open is ended by that stream's own re-check.
func (h *Handler) StopStreams() { h.stopStreams() }
