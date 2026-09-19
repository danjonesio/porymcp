package mcpclient

import (
	"errors"
	"strings"
	"testing"
)

// TestPickResponse pins the one reducer the proxy's group path reads a member's
// answer through (PORM-171): either framing, the edge cases of the event-stream
// grammar, which document is chosen, and the rule that every failure is a fixed
// sentence carrying no byte of what the upstream sent.
func TestPickResponse(t *testing.T) {
	const (
		answer   = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}`
		other    = `{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"off"}]}}`
		third    = `{"jsonrpc":"2.0","id":8,"result":{"tools":[{"name":"off2"}]}}`
		note     = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"x"}}`
		stringID = `{"jsonrpc":"2.0","id":"abc","result":{"ok":true}}`
	)
	event := func(data string) string { return "event: message\ndata: " + data + "\n\n" }
	sse := "text/event-stream"

	for _, c := range []struct {
		name        string
		contentType string
		body        string
		wantID      string
		want        string
		wantErr     error
	}{
		{name: "json", contentType: "application/json; charset=utf-8", body: answer, wantID: "1", want: answer},
		{name: "sse", contentType: sse, body: event(answer), wantID: "1", want: answer},
		{name: "sse with CRLF endings", contentType: sse, body: "event: message\r\ndata: " + answer + "\r\n\r\n", wantID: "1", want: answer},
		{
			name: "a data field split over several lines", contentType: sse, wantID: "1",
			body: "data: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":{\"tools\":[]}}\n\n",
			want: "{\"jsonrpc\":\"2.0\",\"id\":1,\n\"result\":{\"tools\":[]}}",
		},
		{name: "no trailing blank line", contentType: sse, body: "data: " + answer, wantID: "1", want: answer},
		{name: "a notification then the answer", contentType: sse, body: event(note) + event(answer), wantID: "1", want: answer},
		{name: "an off-id document then the wanted id", contentType: sse, body: event(other) + event(answer), wantID: "1", want: answer},
		// The documented fallback: nothing carries the id, so the first document
		// that answers anything is the one read.
		{name: "two off-id documents", contentType: sse, body: event(other) + event(third), wantID: "1", want: other},
		{name: "a single off-id document", contentType: sse, body: event(other), wantID: "1", want: other},
		{name: "two notifications and no answer", contentType: sse, body: event(note) + event(note), wantID: "1", wantErr: errNoResponse},
		// A lone JSON object is returned even when it answers nothing: the
		// caller's own reader decides what an empty catalogue means.
		{name: "one notification alone", contentType: sse, body: event(note), wantID: "1", want: note},
		{name: "one data line that is not JSON", contentType: sse, body: "data: <html>secret</html>\n\n", wantID: "1", wantErr: errNoResponse},
		{name: "a JSON body that is not an envelope", contentType: "application/json", body: `"secret"`, wantID: "1", wantErr: errNoResponse},
		{name: "empty body", contentType: "application/json", body: " \n", wantID: "1", wantErr: errEmptyBody},
		{name: "an event stream with no data event", contentType: sse, body: ": keepalive\n\n", wantID: "1", wantErr: errNoEvent},
		{name: "unknown media type", contentType: "text/html", body: "<html>secret</html>", wantID: "1", wantErr: errUnknownMedia},
		{name: "sse with no content type", contentType: "", body: event(answer), wantID: "1", want: answer},
		{name: "json with no content type", contentType: "", body: answer, wantID: "1", want: answer},
		{name: "a string id token", contentType: sse, body: event(other) + event(stringID), wantID: `"abc"`, want: stringID},
		// No wanted id (a notification was sent): the match arm is skipped and
		// the first answering document is read.
		{name: "no wanted id", contentType: sse, body: event(note) + event(other), wantID: "", want: other},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := PickResponse(c.contentType, []byte(c.body), c.wantID)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if string(got) != c.want {
				t.Errorf("document = %q, want %q", got, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Errorf("err %q carries a byte of the body", err)
			}
		})
	}

	// The bound is on the splitter, not only on the search: past it no further
	// event is joined or kept, which is the cost a member could otherwise choose.
	t.Run("the splitter stops one event past its bound", func(t *testing.T) {
		body := []byte(strings.Repeat(event(note), 50))
		if got, err := eventData(body, 10); err != nil || len(got) != 11 {
			t.Errorf("bounded at 10: %d events, err %v, want 11", len(got), err)
		}
		if got, err := eventData(body, 0); err != nil || len(got) != 50 {
			t.Errorf("unbounded: %d events, err %v, want all 50", len(got), err)
		}
	})

	t.Run("more documents than will be considered", func(t *testing.T) {
		// The answer is there, past the bound: it is not looked for.
		body := strings.Repeat(event(note), maxPickDocuments) + event(answer)
		if _, err := PickResponse(sse, []byte(body), "1"); !errors.Is(err, errNoResponse) {
			t.Errorf("err = %v, want %v for %d documents", err, errNoResponse, maxPickDocuments+1)
		}
		// At the bound it still is.
		body = strings.Repeat(event(note), maxPickDocuments-1) + event(answer)
		got, err := PickResponse(sse, []byte(body), "1")
		if err != nil || string(got) != answer {
			t.Errorf("at the bound: document = %q, err = %v, want the answer", got, err)
		}
	})
}
