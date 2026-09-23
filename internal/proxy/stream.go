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
// the most recent complete event, which is where a server puts its answer
// before it closes the stream; and pending, the event in progress. Boundaries
// (a blank line, "\n\n" or "\r\n\r\n") are found with a byte search over the
// new bytes plus a three-byte overlap, never over the whole buffer, and
// nothing is parsed while relaying. An event that passes judgeTailBytes is
// dropped the moment it does, tailOverflowed is set, and only the last three
// bytes are kept until the next boundary, so a stream that never sends a blank
// line costs at most one read buffer of memory.
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

var (
	boundaryLF   = []byte("\n\n")
	boundaryCRLF = []byte("\r\n\r\n")
)

// firstBoundary is the offset and length of the first event boundary in b, or
// -1, 0 when there is none.
func firstBoundary(b []byte) (int, int) {
	i, n := bytes.Index(b, boundaryLF), len(boundaryLF)
	if j := bytes.Index(b, boundaryCRLF); j >= 0 && (i < 0 || j < i) {
		i, n = j, len(boundaryCRLF)
	}
	if i < 0 {
		return -1, 0
	}
	return i, n
}

func (c *streamCapture) Write(p []byte) {
	if len(c.head) < judgeHeadBytes {
		n := min(len(p), judgeHeadBytes-len(c.head))
		c.head = append(c.head, p[:n]...)
	}
	old := len(c.pending)
	c.pending = append(c.pending, p...)
	scan := max(0, old-3)
	for {
		i, n := firstBoundary(c.pending[scan:])
		if i < 0 {
			break
		}
		end := scan + i + n
		if c.pendingOverflow {
			// The oversized event ended; nothing of it was kept.
			c.pendingOverflow, c.lastOverflow = false, true
			c.last = c.last[:0]
		} else {
			c.lastOverflow = false
			c.last = append(c.last[:0], c.pending[:end]...)
		}
		c.pending = append(c.pending[:0], c.pending[end:]...)
		scan = 0
	}
	if len(c.pending) > judgeTailBytes || (c.pendingOverflow && len(c.pending) > 3) {
		// A fresh three-byte slice, not a re-slice: the array that grew past
		// the cap is released, and only the overlap the next scan needs stays.
		c.pendingOverflow = true
		c.pending = append(make([]byte, 0, 3), c.pending[len(c.pending)-3:]...)
	}
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
	case errors.Is(cause, errStreamRevoked), errors.Is(cause, errUpstreamRemoved):
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
		msg := "upstream connection failed"
		if err != nil {
			msg = err.Error()
		}
		return models.StatusError, truncate(msg, auditFieldBytes)
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
	var recheckT *time.Timer
	recheckT = time.AfterFunc(recheck, func() {
		var cause error
		guard(func() { cause = h.recheck(r, row) })
		if cause != nil {
			cut(cause)
			return
		}
		guard(func() { recheckT.Reset(recheck) })
	})

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
// at another target is no longer the key that was authenticated; an upstream
// the route no longer resolves to is no longer reachable through it. The
// checks are the ones the request path uses (VirtualKey.Status, resolveTargets,
// resolveMember), not a second rule. A store that cannot be read leaves the
// stream open and says so in the log: the proxy fails open here, because a
// store hiccup ending every stream in the deployment would be worse than a
// minute's delay on a revocation.
func (h *Handler) recheck(r *http.Request, row streamRow) error {
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
	if row.memberPath {
		up, _, err := h.resolveMember(ctx, vk, row.slug)
		if err != nil {
			warn(err)
			return nil
		}
		if up == nil || up.ID != row.upstreamID {
			return errUpstreamRemoved
		}
		return nil
	}
	ups, _, err := h.resolveTargets(ctx, vk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, errUpstreamDisabled) || errors.Is(err, errNoUpstreams) {
			return errUpstreamRemoved
		}
		warn(err)
		return nil
	}
	if len(ups) == 0 || ups[0].ID != row.upstreamID {
		return errUpstreamRemoved
	}
	return nil
}

// StopStreams ends every open stream and every stream that starts after it:
// each writes its row and returns, so a Shutdown that is waiting for the
// connection to go idle gets it. It is one-shot and exists for shutdown only
// (cmd/server registers it with the server's RegisterOnShutdown); a key
// revoked while its stream is open is ended by that stream's own re-check.
func (h *Handler) StopStreams() { h.stopStreams() }
