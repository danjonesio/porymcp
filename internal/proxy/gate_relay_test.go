package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// TestRelayGateMatchesMCPDoor covers PORM-146 security requirements 15 and
// 16: one table over both doors proves the shared prelude refuses the same
// things with the same statuses, each door in its own body shape, and that
// the relay door's rows carry the "/" marker and its 429 the Retry-After.
func TestRelayGateMatchesMCPDoor(t *testing.T) {
	type door struct {
		name string
		path string
		body string
		rpc  bool
	}
	doors := func(f *relayFixture) []door {
		return []door{
			{"mcp", "/a1/mcp", listRPC, true},
			{"relay", "/a1/api/x", "", false},
		}
	}
	shape := func(t *testing.T, d door, rr *httptest.ResponseRecorder, msg string) {
		t.Helper()
		if d.rpc {
			if _, got, _ := rpcErrorOf(t, rr.Body.Bytes()); got != msg {
				t.Errorf("%s: envelope message %q want %q", d.name, got, msg)
			}
			return
		}
		m := jsonBody(t, rr.Body.Bytes())
		if m["error"] != msg || m["jsonrpc"] != nil {
			t.Errorf("%s: body %s want error %q", d.name, rr.Body.String(), msg)
		}
	}
	send := func(f *relayFixture, d door, method string, hdr map[string]string, host string) *httptest.ResponseRecorder {
		req := routedRequest(method, d.path, d.body)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+f.Key)
		if d.rpc {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		f.Router.ServeHTTP(rr, req)
		return rr
	}
	method := func(d door) string {
		if d.rpc {
			return http.MethodPost
		}
		return http.MethodGet
	}

	// The key is bound to a group of an mcp member and an http member so
	// that both doors exist for it; the relay path is the member's.
	build := func(t *testing.T) *relayFixture {
		return newRelayFixture(t,
			map[string]upstreamSpec{"alpha": {Tools: []string{"a"}}},
			map[string]httpSpec{"beta": {Base: "/v1"}}, true)
	}
	memberDoors := func() []door {
		return []door{
			{"mcp", "/a1/alpha/mcp", listRPC, true},
			{"relay", "/a1/beta/api/x", "", false},
		}
	}

	t.Run("foreign host", func(t *testing.T) {
		f := build(t)
		for _, d := range memberDoors() {
			rr := send(f, d, method(d), nil, "evil.example")
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s: status %d", d.name, rr.Code)
			}
			if m := jsonBody(t, rr.Body.Bytes()); m["error"] != "invalid host" {
				t.Errorf("%s: body %s", d.name, rr.Body.String())
			}
		}
	})
	t.Run("expired key", func(t *testing.T) {
		f := build(t)
		k, _ := f.Store.GetVirtualKey(context.Background(), "a1")
		past := time.Now().Add(-time.Hour).UTC()
		k.ExpiresAt = &past
		if err := f.Store.UpdateVirtualKey(context.Background(), k); err != nil {
			t.Fatal(err)
		}
		for _, d := range memberDoors() {
			rr := send(f, d, method(d), nil, "localhost:8080")
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s: status %d", d.name, rr.Code)
			}
			shape(t, d, rr, "virtual key expired")
		}
		rows := f.waitAuditN(models.LogFilter{Status: models.StatusBlocked}, 2)
		relayRows := 0
		for _, row := range rows {
			if strings.HasPrefix(row.ToolName, "/") {
				relayRows++
			}
		}
		if relayRows != 1 {
			t.Errorf("%d rows carry the relay marker, want exactly the relay door's: %+v", relayRows, rows)
		}
	})
	t.Run("revoked key", func(t *testing.T) {
		f := build(t)
		k, _ := f.Store.GetVirtualKey(context.Background(), "a1")
		now := time.Now().UTC()
		k.RevokedAt = &now
		if err := f.Store.UpdateVirtualKey(context.Background(), k); err != nil {
			t.Fatal(err)
		}
		for _, d := range memberDoors() {
			rr := send(f, d, method(d), nil, "localhost:8080")
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s: status %d", d.name, rr.Code)
			}
			shape(t, d, rr, "virtual key revoked")
		}
	})
	t.Run("rate limited", func(t *testing.T) {
		f := build(t)
		k, _ := f.Store.GetVirtualKey(context.Background(), "a1")
		one := 1
		k.RateLimit = &one
		if err := f.Store.UpdateVirtualKey(context.Background(), k); err != nil {
			t.Fatal(err)
		}
		for _, d := range memberDoors() {
			g := build(t)
			k, _ := g.Store.GetVirtualKey(context.Background(), "a1")
			k.RateLimit = &one
			_ = g.Store.UpdateVirtualKey(context.Background(), k)
			send(g, d, method(d), nil, "localhost:8080")
			rr := send(g, d, method(d), nil, "localhost:8080")
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("%s: status %d", d.name, rr.Code)
			}
			shape(t, d, rr, "rate limit exceeded")
			ra := rr.Header().Get("Retry-After")
			if d.rpc && ra != "" {
				t.Errorf("mcp door gained Retry-After %q", ra)
			}
			if !d.rpc && ra == "" {
				t.Errorf("relay door has no Retry-After")
			}
		}
		_ = f
	})
	t.Run("wrong key", func(t *testing.T) {
		f := build(t)
		for _, d := range []door{{"mcp", "/zz/mcp", listRPC, true}, {"relay", "/zz/api/x", "", false}} {
			rr := send(f, d, method(d), nil, "localhost:8080")
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s: status %d", d.name, rr.Code)
			}
			shape(t, d, rr, "virtual key does not match this endpoint")
		}
	})
	t.Run("keyless path", func(t *testing.T) {
		f := build(t)
		// No key at all: 401 on both, as the MCP door always answered.
		for _, d := range []door{{"mcp", "//alpha/mcp", listRPC, true}, {"relay", "//api/x", "", false}, {"relay member", "//beta/api/x", "", false}} {
			rr := send(f, d, method(d), map[string]string{"Authorization": "Bearer "}, "localhost:8080")
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s without a key: status %d", d.name, rr.Code)
			}
		}
		// A valid key: the relay door refuses the binding with the uniform
		// 404, the MCP door keeps its behaviour.
		for _, d := range []door{{"relay", "//api/x", "", false}, {"relay member", "//beta/api/x", "", false}} {
			rr := send(f, d, method(d), nil, "localhost:8080")
			if rr.Code != http.StatusNotFound {
				t.Errorf("%s with a key: status %d body %s", d.name, rr.Code, rr.Body.String())
			}
			shape(t, d, rr, "unknown endpoint")
		}
		if n := len(f.APIs["beta"].requests()); n != 0 {
			t.Errorf("the keyless binding reached the upstream")
		}
	})
	t.Run("verb outside the door", func(t *testing.T) {
		f := build(t)
		for _, d := range doors(f) {
			rr := send(f, d, http.MethodConnect, nil, "localhost:8080")
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status %d", d.name, rr.Code)
			}
			shape(t, d, rr, "method not allowed")
		}
	})
}
