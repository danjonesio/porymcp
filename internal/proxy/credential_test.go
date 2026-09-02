package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
)

// setStoredAuth overwrites one upstream's stored credential with a value no
// exported call could produce for this handler: a legacy blob, or a v1 value
// sealed under a key the handler does not hold.
func setStoredAuth(t *testing.T, f *fixture, slug, value string) {
	t.Helper()
	ctx := context.Background()
	u, err := f.Store.GetUpstreamBySlug(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	u.AuthConfig = []byte(value)
	if err := f.Store.UpdateUpstream(ctx, u, store.KeepTest, store.WriteAuth); err != nil {
		t.Fatal(err)
	}
}

func foreignSealed(t *testing.T, plain string) (string, []byte) {
	t.Helper()
	other, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewKeyring(other, nil).Seal([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return enc, other
}

// assert502Generic: the client sees the same 502 envelope every upstream
// failure produces, and nothing about credentials or keys (security req 4).
func assert502Generic(t *testing.T, body string, code int) {
	t.Helper()
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body %s", code, body)
	}
	if !strings.Contains(body, `"code":-32000`) || !strings.Contains(body, "upstream request failed") {
		t.Fatalf("body = %s, want the generic -32000 envelope", body)
	}
	for _, word := range []string{"credential", "key", "decrypt", "v1:"} {
		if strings.Contains(strings.ToLower(body), word) {
			t.Fatalf("body tells the client about %q: %s", word, body)
		}
	}
}

// TestUndecryptableCredentialFailsClosed covers acceptance criterion 6 on both
// routes the 502 is reachable from: a single-upstream key on KeyRoute and a
// group member on MemberRoute. Zero requests reach the upstream; the audit row
// says why; the client is told what it is told for any upstream failure.
func TestUndecryptableCredentialFailsClosed(t *testing.T) {
	t.Run("single upstream", func(t *testing.T) {
		f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Bearer: "sk-real"}, nil, nil)
		enc, _ := foreignSealed(t, `{"token":"sk-real"}`)
		setStoredAuth(t, f, "solo", enc)

		rr := f.post(toolCall("1", "ping"))
		assert502Generic(t, rr.Body.String(), rr.Code)
		if n := f.totalReqs("solo"); n != 0 {
			t.Fatalf("upstream saw %d requests; nothing may be dialled", n)
		}
		rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
		if len(rows) != 1 || rows[0].ErrorMessage != "credential undecryptable" {
			t.Fatalf("audit rows = %+v, want one error row reading credential undecryptable", rows)
		}
	})
	t.Run("group member", func(t *testing.T) {
		f := newFixture(t, map[string]upstreamSpec{
			"alpha": {Tools: []string{"a_tool"}, Bearer: "sk-a"},
			"beta":  {Tools: []string{"b_tool"}, Bearer: "sk-b"},
		}, true, nil, nil, nil)
		enc, _ := foreignSealed(t, `{"token":"sk-a"}`)
		setStoredAuth(t, f, "alpha", enc)

		rr := f.postMember("alpha", toolCall("1", "a_tool"))
		assert502Generic(t, rr.Body.String(), rr.Code)
		if n := f.totalReqs("alpha"); n != 0 {
			t.Fatalf("alpha saw %d requests", n)
		}
		rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
		if len(rows) != 1 || rows[0].ErrorMessage != "credential undecryptable" || rows[0].UpstreamID != "u1" {
			t.Fatalf("audit rows = %+v", rows)
		}
		// The healthy member is unaffected.
		if rr := f.postMember("beta", toolCall("2", "b_tool")); rr.Code != http.StatusOK {
			t.Fatalf("beta: %d %s", rr.Code, rr.Body.String())
		}
		if got := f.requestsTo("beta")[0].Header.Get("Authorization"); got != "Bearer sk-b" {
			t.Fatalf("beta saw Authorization %q", got)
		}
	})
}

// TestUnreadableCredentialFailsClosed: a blob that opens but holds nothing the
// auth type can send (the dashboard stores {} for a blank token) fails closed
// the same way, with its own reason (security req 3).
func TestUnreadableCredentialFailsClosed(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Bearer: "sk-real"}, nil, nil)
	enc, err := f.H.keys.Seal([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	setStoredAuth(t, f, "solo", enc)

	rr := f.post(toolCall("1", "ping"))
	assert502Generic(t, rr.Body.String(), rr.Code)
	if n := f.totalReqs("solo"); n != 0 {
		t.Fatalf("upstream saw %d requests", n)
	}
	rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(rows) != 1 || rows[0].ErrorMessage != "credential unreadable" {
		t.Fatalf("audit rows = %+v", rows)
	}
}

// TestAggregateSkipsUndecryptableMember records the aggregate-endpoint answer
// the plan settled: an undecryptable member is skipped exactly like any
// unlistable member — its tools leave the merged catalogue, the group's
// tools/list is audited as a success, a call for one of its tools is "unknown
// tool" (200, -32602), zero requests reach it, and the skip Warn names the
// cause. The operator's signals are auth_status, /stats, the banner and the
// boot line, not this path.
func TestAggregateSkipsUndecryptableMember(t *testing.T) {
	f := newFixture(t, map[string]upstreamSpec{
		"alpha": {Tools: []string{"a_tool"}, Bearer: "sk-a"},
		"beta":  {Tools: []string{"b_tool"}, Bearer: "sk-b"},
	}, true, nil, nil, nil)
	enc, _ := foreignSealed(t, `{"token":"sk-a"}`)
	setStoredAuth(t, f, "alpha", enc)
	var logs bytes.Buffer
	f.H.log = slog.New(slog.NewJSONHandler(&logs, nil))

	rr := f.post(listRequest)
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list: %d %s", rr.Code, rr.Body.String())
	}
	if got := strings.Join(listedNames(t, rr.Body.Bytes()), ","); got != "beta__b_tool" {
		t.Fatalf("listed %q, want only beta's tool", got)
	}
	rr = f.post(toolCall("2", "alpha__a_tool"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":-32602`) || !strings.Contains(rr.Body.String(), "unknown tool") {
		t.Fatalf("call for the skipped member's tool: %d %s", rr.Code, rr.Body.String())
	}
	if n := f.totalReqs("alpha"); n != 0 {
		t.Fatalf("alpha saw %d requests", n)
	}
	// What the audit says: the list succeeded; the call is an unknown tool.
	ok := f.waitAudit(models.LogFilter{Status: models.StatusSuccess})
	if len(ok) != 1 || ok[0].Method != "tools/list" {
		t.Fatalf("success rows = %+v, want the group tools/list", ok)
	}
	bad := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(bad) != 1 || !strings.HasPrefix(bad[0].ErrorMessage, "unknown tool") {
		t.Fatalf("error rows = %+v, want one unknown-tool row", bad)
	}
	if out := logs.String(); !strings.Contains(out, "group member skipped") || !strings.Contains(out, "credential undecryptable") || !strings.Contains(out, `"slug":"alpha"`) {
		t.Fatalf("skip Warn should name the member and the cause: %s", out)
	}
	if strings.Contains(logs.String(), "sk-a") {
		t.Fatal("a plaintext reached the log")
	}
}

// TestLegacyCiphertextStillForwards: a row written by a pre-PORM-52 build
// keeps working, for ever.
func TestLegacyCiphertextStillForwards(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Bearer: "sk-real"}, nil, nil)
	legacy, err := crypto.EncryptLegacy(f.H.cfg.EncryptionKey, []byte(`{"token":"sk-legacy"}`))
	if err != nil {
		t.Fatal(err)
	}
	setStoredAuth(t, f, "solo", legacy)
	if rr := f.post(toolCall("1", "ping")); rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if got := f.requestsTo("solo")[0].Header.Get("Authorization"); got != "Bearer sk-legacy" {
		t.Fatalf("upstream saw Authorization %q", got)
	}
}

// TestPreviousKeyStillForwards covers acceptance criterion 7 on the proxy: a
// credential sealed under the old key is presented while that key is listed
// in ENCRYPTION_KEY_PREVIOUS, and refused once it is not.
func TestPreviousKeyStillForwards(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Bearer: "sk-real"}, nil, nil)
	enc, old := foreignSealed(t, `{"token":"sk-old"}`)
	setStoredAuth(t, f, "solo", enc)

	rr := f.post(toolCall("1", "ping"))
	assert502Generic(t, rr.Body.String(), rr.Code)

	// The handler is rebuilt from a Config carrying the previous key, so this
	// exercises New -> cfg.Keyring() -> EncryptionKeyPrevious, not a hand-set
	// field (the plan's recipe).
	f.H = New(&config.Config{
		EncryptionKey:         f.H.cfg.EncryptionKey,
		EncryptionKeyPrevious: [][]byte{old},
		PublicURL:             "http://localhost:8080",
	}, f.Store, f.H.audit, nil)
	if rr := f.post(toolCall("2", "ping")); rr.Code != http.StatusOK {
		t.Fatalf("with the previous key: %d %s", rr.Code, rr.Body.String())
	}
	if got := f.requestsTo("solo")[0].Header.Get("Authorization"); got != "Bearer sk-old" {
		t.Fatalf("upstream saw Authorization %q", got)
	}
}

// TestAuditRowCarriesOnlyTheSentinel pins security requirement 1 on the row:
// error_message is the sentinel text and nothing else — no fingerprint, no
// ciphertext, no plaintext — because audit does not redact it.
func TestAuditRowCarriesOnlyTheSentinel(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}, Bearer: "sk-real"}, nil, nil)
	enc, other := foreignSealed(t, `{"token":"sk-PLAINTEXT"}`)
	setStoredAuth(t, f, "solo", enc)
	f.post(toolCall("1", "ping"))
	rows := f.waitAudit(models.LogFilter{Status: models.StatusError})
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].ErrorMessage != "credential undecryptable" {
		t.Fatalf("error_message = %q", rows[0].ErrorMessage)
	}
	for _, field := range []string{rows[0].ErrorMessage, string(rows[0].Params)} {
		if strings.Contains(field, crypto.Fingerprint(other)) || strings.Contains(field, "sk-PLAINTEXT") || strings.Contains(field, enc) {
			t.Fatalf("audit row carries key or credential material: %q", field)
		}
	}
}

// TestNoneUpstreamWithGarbageBlobStillForwards: an auth_type none upstream
// sends no credential, so whatever sits in its column is never consulted.
func TestNoneUpstreamWithGarbageBlobStillForwards(t *testing.T) {
	f := newSingleFixture(t, upstreamSpec{Tools: []string{"ping"}}, nil, nil)
	setStoredAuth(t, f, "solo", "not-ciphertext-at-all")
	if rr := f.post(toolCall("1", "ping")); rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	reqs := f.requestsTo("solo")
	if len(reqs) != 1 || reqs[0].Header.Get("Authorization") != "" {
		t.Fatalf("requests = %+v", reqs)
	}
}
