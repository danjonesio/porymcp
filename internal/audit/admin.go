package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/google/uuid"
)

// AdminTextBytes caps a caller-controlled string before it is stored on an
// admin_events row: a resource name or a request id. It is the twin of
// internal/proxy's auditFieldBytes, which bounds the same kind of string on
// its way to an audit_logs row; the two stay separate for the reason recorded
// at internal/mcpclient/client.go beside MaxErrorBytes.
const AdminTextBytes = 256

// adminWriteTimeout bounds the detached write. It matches SQLite's
// busy_timeout (5000 ms, internal/store) and the proxy-side audit write
// above, so lock contention cannot expire the write before the database
// would have retried. The write is synchronous and runs before the caller's
// response, so when the database lock is held it can add up to this much to
// a mutating response; it is reached only in that case.
const adminWriteTimeout = 5 * time.Second

// Text cleans and bounds a caller-controlled string for storage: control
// characters become spaces or are dropped and the result is cut at
// AdminTextBytes with valid UTF-8, the same treatment discovery gives text a
// server sends. The resource keeps its full name; only the audit row's copy
// is cleaned.
func Text(s string) string {
	out, _ := mcpclient.Clamp(mcpclient.Scrub(s), AdminTextBytes)
	return out
}

// RecordAdmin writes one admin event for a change that has already landed.
// It is the one recorder: the management API calls it after a store write
// returned nil and before the response, and credential.Presenter calls it
// after a token refresh (PORM-139). It is total: a panic here would become a
// 500 through Recoverer on a request whose mutation (a rotated key's only
// plaintext, for one) has already happened, so it recovers and logs instead.
// A failed write is one Error line naming the action, resource id and request
// id, and changes nothing about the caller's response. The Error lines never
// carry the name or a detail value.
//
// The write is detached from ctx: the mutation has committed, so a caller
// that disconnected must not cost the event. ResourceType is derived from
// the action when empty; ID and Timestamp are filled when zero; the three
// text fields are cleaned with Text.
func RecordAdmin(ctx context.Context, st store.Store, log *slog.Logger, e models.AdminEvent) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	defer func() {
		if v := recover(); v != nil {
			// Recovering here loses Recoverer's 500 on purpose: the mutation
			// has landed and the response must go out. The stack is logged so
			// the trade costs nothing at diagnosis time.
			log.Error("admin event recorder panicked", "action", e.Action, "resource_id", e.ResourceID,
				"panic", Text(fmt.Sprint(v)), "stack", string(debug.Stack()))
		}
	}()
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.ResourceType == "" {
		e.ResourceType, _, _ = strings.Cut(e.Action, ".")
	}
	if len(e.Details) == 0 {
		e.Details = json.RawMessage("{}")
	}
	e.ResourceID = Text(e.ResourceID)
	e.ResourceName = Text(e.ResourceName)
	e.RequestID = Text(e.RequestID)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), adminWriteTimeout)
	defer cancel()
	if err := st.InsertAdminEvent(ctx, &e); err != nil {
		log.Error("admin event not recorded", "action", e.Action, "resource_id", e.ResourceID,
			"request_id", e.RequestID, "err", err)
	}
}
