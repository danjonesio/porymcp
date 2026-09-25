package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// PORM-172: on a single-upstream key and a member endpoint the answer the
// client is sent does not change; only the row does. An upstream's JSON-RPC
// error that arrives in SSE framing used to be written as success with no
// message, because the classification decoded the raw bytes as JSON.

const sseErrorDoc = `{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"rate limited"}}`

// singleMember builds a group of one member, so both the single-upstream key
// (the aggregate URL of a one-member group relays to that member) and the
// member endpoint can be exercised against the same stub.
func singleMember(t *testing.T, spec upstreamSpec) *fixture {
	t.Helper()
	return newFixture(t, map[string]upstreamSpec{"solo": spec}, true, nil, nil, nil)
}

// assertRelayUnchanged is criterion 1's and 2's client half: the bytes, the
// label and the session id are the upstream's, byte for byte.
func assertRelayUnchanged(t *testing.T, rr http.Header, body, wantBody, wantCT, wantSession string) {
	t.Helper()
	if body != wantBody {
		t.Fatalf("client body changed:\n got %q\nwant %q", body, wantBody)
	}
	if got := rr.Get("Content-Type"); got != wantCT {
		t.Fatalf("Content-Type=%q want %q", got, wantCT)
	}
	if got := rr.Get("Mcp-Session-Id"); got != wantSession {
		t.Fatalf("Mcp-Session-Id=%q want %q", got, wantSession)
	}
}

// Criterion 1, security requirements 1 and 2.
func TestRelayAuditsSSEError(t *testing.T) {
	body := sseFrame(sseErrorDoc)
	f := newSingleFixture(t, upstreamSpec{
		Tools:       []string{"ping_tool"},
		CallCT:      "text/event-stream",
		CallBody:    body,
		RespHeaders: map[string]string{"Mcp-Session-Id": "s1"},
	}, nil, nil)

	rr := f.post(toolCall("7", "ping_tool"))
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200", rr.Code)
	}
	assertRelayUnchanged(t, rr.Header(), rr.Body.String(), body, "text/event-stream", "s1")
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "rate limited" {
		t.Fatalf("row status=%q error_message=%q, want error / rate limited", row.Status, row.ErrorMessage)
	}
}

// Criterion 2, security requirement 2: the same on a member endpoint, where
// the session id a client sends back must keep crossing in both directions.
func TestMemberRelayAuditsSSEError(t *testing.T) {
	body := sseFrame(sseErrorDoc)
	f := singleMember(t, upstreamSpec{
		Tools:       []string{"ping_tool"},
		CallCT:      "text/event-stream",
		CallBody:    body,
		RespHeaders: map[string]string{"Mcp-Session-Id": "s1"},
	})

	rr := f.postMemberWith("solo", toolCall("7", "ping_tool"), map[string]string{"Mcp-Session-Id": "s1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP code=%d want 200", rr.Code)
	}
	assertRelayUnchanged(t, rr.Header(), rr.Body.String(), body, "text/event-stream", "s1")
	reqs := f.requestsTo("solo")
	if got := reqs[len(reqs)-1].Header.Get("Mcp-Session-Id"); got != "s1" {
		t.Fatalf("member saw Mcp-Session-Id=%q want s1", got)
	}
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "rate limited" {
		t.Fatalf("row status=%q error_message=%q, want error / rate limited", row.Status, row.ErrorMessage)
	}
}

// D1, security requirement 1: a JSON error under a wrong label was an error
// row before this change and stays one. The fallback when nothing reduces is
// the raw-body decode, never the HTTP status alone.
func TestRelayAuditsMislabelledJSONError(t *testing.T) {
	for _, ct := range []string{"text/event-stream", "text/plain"} {
		t.Run(ct, func(t *testing.T) {
			f := newSingleFixture(t, upstreamSpec{
				Tools:    []string{"ping_tool"},
				CallCT:   ct,
				CallBody: sseErrorDoc,
			}, nil, nil)
			rr := f.post(toolCall("7", "ping_tool"))
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP code=%d want 200", rr.Code)
			}
			assertRelayUnchanged(t, rr.Header(), rr.Body.String(), sseErrorDoc, ct, "")
			row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
			if row.Status != models.StatusError || row.ErrorMessage != "rate limited" {
				t.Fatalf("row status=%q error_message=%q, want error / rate limited", row.Status, row.ErrorMessage)
			}
		})
	}
}

// Criterion 5: an answer that does not reduce is relayed and audited as
// today. A 401 carrying a body that is not a JSON-RPC envelope is an error
// row by its status, with no message, and the client gets the 401 and the
// body.
func TestRelayNonRPCJSON401AuditedAsToday(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{
		Tools:    []string{"ping_tool"},
		CallCode: http.StatusUnauthorized,
		CallBody: `{"message":"no"}`,
	}, nil, nil)
	rr := f.post(toolCall("7", "ping_tool"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP code=%d want 401", rr.Code)
	}
	if rr.Body.String() != `{"message":"no"}` {
		t.Fatalf("client body=%q want the upstream's", rr.Body.String())
	}
	row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
	if row.Status != models.StatusError || row.ErrorMessage != "" {
		t.Fatalf("row status=%q error_message=%q, want error / empty", row.Status, row.ErrorMessage)
	}
}

// TestRelayRefusalWithNothingToRedactIsUnchanged is PORM-205 criterion 2
// with amendment A2, security requirement 3: a refusal that is not JSON-RPC
// and holds nothing credential-shaped crosses byte for byte with its status
// and its label, on the single key and the member endpoint, and the row
// records the bytes sent.
func TestRelayRefusalWithNothingToRedactIsUnchanged(t *testing.T) {
	cases := []struct {
		name, ct, body string
		code           int
	}{
		{name: "text_plain", ct: "text/plain", code: http.StatusForbidden, body: "forbidden: this key may not call ping_tool\n"},
		{name: "text_html", ct: "text/html; charset=utf-8", code: http.StatusNotFound, body: "<html><body><h1>Not found</h1></body></html>"},
	}
	for _, tc := range cases {
		for _, member := range []bool{false, true} {
			name := tc.name + "/single"
			if member {
				name = tc.name + "/member"
			}
			t.Run(name, func(t *testing.T) {
				spec := upstreamSpec{Tools: []string{"ping_tool"}, CallCode: tc.code, CallCT: tc.ct, CallBody: tc.body}
				var f *fixture
				var rr *httptest.ResponseRecorder
				if member {
					f = singleMember(t, spec)
					rr = f.postMember("solo", toolCall("7", "ping_tool"))
				} else {
					f = newSingleFixture(t, spec, nil, nil)
					rr = f.post(toolCall("7", "ping_tool"))
				}
				if rr.Code != tc.code {
					t.Fatalf("HTTP code=%d want %d", rr.Code, tc.code)
				}
				assertRelayUnchanged(t, rr.Header(), rr.Body.String(), tc.body, tc.ct, "")
				row := f.waitAudit(models.LogFilter{Tool: "ping_tool"})[0]
				if row.Status != models.StatusError || row.ErrorMessage != "" || row.ResponseSizeBytes != len(tc.body) {
					t.Fatalf("row status=%q error_message=%q size=%d, want error / empty / %d", row.Status, row.ErrorMessage, row.ResponseSizeBytes, len(tc.body))
				}
			})
		}
	}
}

// Security requirement 8, D2: on a JSON body answerStatus does what the old
// two calls did and allocates exactly as much, so the common path pays
// nothing for the reduction it never runs.
func TestAnswerStatusJSONAllocs(t *testing.T) {
	for name, body := range map[string][]byte{
		"result": []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + strings.Repeat("x", 4096) + `"}]}}`),
		"error":  []byte(sseErrorDoc),
	} {
		t.Run(name, func(t *testing.T) {
			before := testing.AllocsPerRun(200, func() {
				if 200 >= 400 || rpcFailed(body) {
					_ = rpcErrorMessage(body)
				}
			})
			after := testing.AllocsPerRun(200, func() {
				_, _ = answerStatus(200, "application/json", body, "1")
			})
			if after != before {
				t.Fatalf("answerStatus allocates %.0f per run, the old classification %.0f: a JSON body must not be reduced", after, before)
			}
		})
	}
}

// A notification answered 202 with no body on a single-upstream key: the
// client gets the 202, no body, no label, and the row is success, as today.
func TestRelayNotificationRowUnchanged(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping_tool"}, RelayCode: http.StatusAccepted}, nil, nil)
	rr := f.post(`{"jsonrpc":"2.0","method":"notifications/foo"}`)
	if rr.Code != http.StatusAccepted || rr.Body.Len() != 0 || rr.Header().Get("Content-Type") != "" {
		t.Fatalf("code=%d body=%q ct=%q, want 202, no body, no label", rr.Code, rr.Body.String(), rr.Header().Get("Content-Type"))
	}
	if row := f.waitAudit(models.LogFilter{Method: "notifications/foo"})[0]; row.Status != models.StatusSuccess {
		t.Fatalf("row status=%q want success", row.Status)
	}
}
