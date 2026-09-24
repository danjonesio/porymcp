package proxy

import (
	"context"
	"errors"
	"io"
	"net/http/httptrace"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
)

// The budgets an upstream request runs under. Until PORM-5 the proxy's client
// carried one flat 60 s http.Client.Timeout, which covered the connection, the
// headers and the whole body: a tools/call that thought for longer died at 60
// s, and an event stream the upstream held open (a subscriptions/listen) was
// cut before a byte of it reached the client. The client now carries no
// timeout, and each request is bounded here by its context, in the shape
// probeBudget and discoverBudget already have in mcpclient: a package var a
// test shortens and restores.

// connectBudget bounds name lookup, dial and TLS for one upstream request. A
// refused port fails at once whatever this says; a black hole or a stalled
// handshake fails here rather than at the transport's own 30 s dial timeout.
// The request fails at the budget; the transport, which detaches a dial from
// the request's cancellation, finishes or abandons it on its own timers.
var connectBudget = 10 * time.Second

// answerBudget bounds a buffered answer from send to the end of its body, and a
// streamed answer from send to its response headers. Five minutes: a JSON
// answer to a tool that thinks for a while, with room over the 90 s the issue
// names, and below the hour operators give an edge that carries MCP.
var answerBudget = 5 * time.Minute

// listBudget bounds one member's era probe and tools/list during a group walk,
// as the 60 s client timeout did, so a silent member still costs the walk a
// minute and no more.
var listBudget = 60 * time.Second

// streamIdleBudget bounds the gap between two upstream reads on a relayed
// stream, and each write to the client. A live listen sends keep-alive lines
// well inside it; an upstream that goes quiet, or a client that stops reading,
// ends the stream here rather than holding a goroutine and a connection for
// as long as the other side stays connected.
var streamIdleBudget = 5 * time.Minute

// streamRecheckBudget is how often an open stream re-runs the request path's
// key and target checks, so a key that is revoked, expired, rotated or
// retargeted, or an upstream removed from it, ends the stream instead of
// receiving upstream traffic under the real credential for as long as its
// listen lives.
var streamRecheckBudget = 60 * time.Second

// judgeHeadBytes and judgeTailBytes bound what a stream keeps for its audit
// row: the first bytes, the most recent complete event, and the event in
// progress (see streamCapture).
const (
	judgeHeadBytes = 64 << 10
	judgeTailBytes = 1 << 20
)

// budgetError is the cause a budget timer cancels a request with. Its text is
// built from the budget the timer was armed with, so a test that shortens a
// var reads its own value back, and it is the proxy's own sentence: the
// transport's error for a cancelled request says "context canceled" and
// nothing about why.
type budgetError struct {
	what string // "did not connect within", "did not answer within", "sent nothing for"
	d    time.Duration
}

func (e *budgetError) Error() string { return "upstream " + e.what + " " + e.d.String() }

// The three ends of a stream that are neither the upstream's nor the client's
// doing. Each is a fixed sentence an audit row carries.
var (
	errStreamStopped   = errors.New("proxy stopped before the answer")
	errStreamRevoked   = errors.New("virtual key no longer valid during the stream")
	errUpstreamRemoved = errors.New("upstream no longer reachable through the key during the stream")
	errUpstreamChanged = errors.New("upstream changed during the stream")
)

// upstreamContext derives the context one upstream request runs under. The
// connect timer is armed now and stopped when the transport reports a
// connection (httptrace.GotConn, which fires at once on a reused one); the
// answer timer runs until disarm is called (a stream, once its headers have
// arrived) or cancel runs (a buffered answer, after ReadBody). Either timer
// cancels ctx with a *budgetError as its cause, which causeError reads back.
// cancel releases both timers and must run on every path; a stream calls it
// with its own cause when it ends the request itself.
func upstreamContext(parent context.Context, answer time.Duration) (ctx context.Context, disarm func(), cancel context.CancelCauseFunc) {
	connect := connectBudget
	ctx, cancelCause := context.WithCancelCause(parent)
	connectT := time.AfterFunc(connect, func() {
		cancelCause(&budgetError{what: "did not connect within", d: connect})
	})
	answerT := time.AfterFunc(answer, func() {
		cancelCause(&budgetError{what: "did not answer within", d: answer})
	})
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connectT.Stop() },
	})
	disarm = func() { answerT.Stop() }
	cancel = func(cause error) {
		connectT.Stop()
		answerT.Stop()
		cancelCause(cause)
	}
	return ctx, disarm, cancel
}

// causeError is the error a failed upstream request is reported with: the
// cause the request was cancelled with when that cause is the proxy's own (a
// budget, or one of the stream ends above), and err as the transport returned
// it otherwise. A client that went away cancels with no cause of its own, and
// that case keeps the transport's text, as it always had.
func causeError(ctx context.Context, err error) error {
	if ctx.Err() == nil {
		return err
	}
	cause := context.Cause(ctx)
	if cause == nil || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return err
	}
	return cause
}

// errClientWentAway is the row for a request the client abandoned before the
// upstream answered: the upstream context is done with no cause of its own
// (context.Canceled), which is how net/http cancels r.Context(). Named
// because the transport's own error for that case is a *net.OpError that
// TransportFailure would print as a refused connection.
var errClientWentAway = errors.New("client went away before the answer")

// errUpstreamURL is the row for a stored URL http.NewRequestWithContext will
// not take: the parse error would quote the URL, query string and all. The
// relay door writes the same sentence for a URL that does not parse.
var errUpstreamURL = errors.New("upstream url is not usable")

// clientWentAway says the upstream context is done because its parent was
// cancelled with no cause: a client that hung up. A budget cancels with a
// *budgetError cause and is read by causeError first.
func clientWentAway(ctx context.Context) bool {
	return ctx.Err() != nil && context.Cause(ctx) == context.Canceled
}

// upstreamFailureText is the sentence for a request to an upstream that got
// no answer, on either door. err is the error the upstream client returned
// from Open and ctx is that request's upstream context. The order: the
// proxy's own budget cause (causeError), the client's own cancellation, a
// refused redirect and an oversized body by their own typed text, then
// mcpclient.TransportFailure, which names host only when it is HostSafe.
// err's own text never reaches a row or a log line: a *url.Error quotes the
// outbound URL, query string and all.
func upstreamFailureText(ctx context.Context, err error, host string) string {
	if cause := causeError(ctx, err); cause != err {
		return cause.Error()
	}
	if clientWentAway(ctx) {
		return errClientWentAway.Error()
	}
	var redirect mcpclient.Redirect
	if errors.As(err, &redirect) {
		return redirect.Error()
	}
	var big mcpclient.BodyTooLarge
	if errors.As(err, &big) {
		return big.Error()
	}
	if !mcpclient.HostSafe(host) {
		host = ""
	}
	return mcpclient.TransportFailure(err, host)
}

// readFailureText is the sentence for a body that failed while it was being
// read, buffered, on either door: the budget cause, the client's own
// cancellation, an oversized body, then readErrorText. A read error is never
// a *url.Error and never a refused connection, so TransportFailure is the
// wrong rule for it.
func readFailureText(ctx context.Context, err error) string {
	if cause := causeError(ctx, err); cause != err {
		return cause.Error()
	}
	if clientWentAway(ctx) {
		return errClientWentAway.Error()
	}
	var big mcpclient.BodyTooLarge
	if errors.As(err, &big) {
		return big.Error()
	}
	return readErrorText(err)
}

// readErrorText is the sentence for a read error itself, buffered or
// streamed: a read error's text carries the resolved address ("read tcp
// a->b"), so only two fixed sentences are written, and the one exception is
// the constant whose text names nothing.
func readErrorText(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.ErrUnexpectedEOF.Error()
	}
	return "upstream connection failed"
}

// upstreamFailed is upstreamFailureText as an error, for the MCP door, which
// holds the upstream and not a parsed base. A guard refusal is returned as
// it came, because serve finds it by type for the Warn line and its text is
// already the sentence; everything else becomes the sentence alone, so the
// *url.Error and the URL it quotes leave the error chain here.
func upstreamFailed(ctx context.Context, err error, up *models.Upstream) error {
	var denied netguard.Denied
	if errors.As(err, &denied) {
		return denied
	}
	return errors.New(upstreamFailureText(ctx, err, mcpclient.RowHost(up.URL)))
}

// readFailed is readFailureText as an error, for the MCP door.
func readFailed(ctx context.Context, err error) error {
	return errors.New(readFailureText(ctx, err))
}
