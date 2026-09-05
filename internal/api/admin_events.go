package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/webutil"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// adminDetails is the closed detail object of one admin event. A value is
// recorded only when the API already returns it in the clear, it is not
// operator-authored text, and it is bounded: a slug, an auth type, a key
// prefix, a target, a member count. Names, descriptions, URLs, metadata, tool
// filters, tool lists and member id lists appear only as field names in
// Fields or Cleared. No credential, ciphertext or plaintext key can be
// expressed here, and the string "auth_config" never enters a row: a
// credential change is AuthChanged. Every field is omitempty, so a key is
// present only when it carries information; UpstreamCount is a pointer so a
// count of zero survives.
//
// Fields lists the field names whose stored value differs between the row the
// handler read and the row it wrote. Cleared is the intent the two PATCH
// handlers already compute (the request nulled or emptied a field) and can
// appear without a matching Fields entry when the field was already empty.
type adminDetails struct {
	Fields        []string `json:"fields,omitempty"`
	Cleared       []string `json:"cleared,omitempty"`
	Slug          string   `json:"slug,omitempty"`
	AuthType      string   `json:"auth_type,omitempty"`
	AuthChanged   bool     `json:"auth_changed,omitempty"`
	UpstreamCount *int     `json:"upstream_count,omitempty"`
	ToolFilterSet bool     `json:"tool_filter_set,omitempty"`
	TargetType    string   `json:"target_type,omitempty"`
	TargetID      string   `json:"target_id,omitempty"`
	KeyPrefix     string   `json:"key_prefix,omitempty"`
}

// adminTextBytes caps a caller-controlled string before it is stored on an
// admin_events row: a resource name or a request id. It is the twin of
// internal/proxy's auditFieldBytes, which bounds the same kind of string on
// its way to an audit_logs row; the two stay separate for the reason recorded
// at internal/mcpclient/client.go beside MaxErrorBytes.
const adminTextBytes = 256

// adminAuditTimeout bounds the detached write. It matches SQLite's
// busy_timeout (5000 ms, internal/store) and the proxy-side audit write
// (internal/audit), so lock contention cannot expire the write before the
// database would have retried. The write is synchronous and runs before the
// response, so when the database lock is held it can add up to this much to
// a mutating response; it is reached only in that case.
const adminAuditTimeout = 5 * time.Second

// auditText cleans and bounds a caller-controlled string for storage: control
// characters become spaces or are dropped and the result is cut at
// adminTextBytes with valid UTF-8, the same treatment discovery gives text a
// server sends. The resource keeps its full name; only the audit row's copy
// is cleaned.
func auditText(s string) string {
	out, _ := mcpclient.Clamp(mcpclient.Scrub(s), adminTextBytes)
	return out
}

// recordAdmin writes one event for a change that has already landed. It is
// called after the store write returned nil and before the response, never on
// a request the store rejected. It is total: a panic here would become a 500
// through Recoverer on a request whose mutation (a rotated key's only
// plaintext, for one) has already happened, so it recovers and logs instead.
// A failed write is one Error line naming the action, resource id and request
// id, and changes nothing about the response. The Error lines never carry the
// name or a detail value.
//
// id is the id of the row the handler read, never a URL parameter; auditText
// on it is a no-op for a server-minted uuid and closes the column by
// construction.
func (s *Server) recordAdmin(r *http.Request, action, id, name string, details adminDetails) {
	defer func() {
		if v := recover(); v != nil {
			// Recovering here loses Recoverer's 500 on purpose: the mutation
			// has landed and the response must go out. The stack is logged so
			// the trade costs nothing at diagnosis time.
			s.log.Error("admin event recorder panicked", "action", action, "resource_id", id,
				"panic", auditText(fmt.Sprint(v)), "stack", string(debug.Stack()))
		}
	}()
	resourceType, _, _ := strings.Cut(action, ".")
	// A closed struct of strings, bools, an *int and []string cannot fail to
	// marshal.
	raw, _ := json.Marshal(details)
	e := models.AdminEvent{
		ID:           uuid.NewString(),
		Timestamp:    time.Now().UTC(),
		Actor:        models.ActorAdmin,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   auditText(id),
		ResourceName: auditText(name),
		Details:      raw,
		RequestID:    auditText(middleware.GetReqID(r.Context())),
		RemoteAddr:   webutil.ClientIP(r, s.cfg.TrustedProxies),
	}
	// Detached from the request: the mutation has committed, so a client that
	// disconnected must not cost the event. No early return on
	// r.Context().Err() for the same reason.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), adminAuditTimeout)
	defer cancel()
	if err := s.store.InsertAdminEvent(ctx, &e); err != nil {
		s.log.Error("admin event not recorded", "action", action, "resource_id", e.ResourceID,
			"request_id", e.RequestID, "err", err)
	}
}

// changed appends name to fields when differs is true. The diff builders
// below compare a fixed list of fields on the row a PATCH handler read and the
// row it wrote, so a field added to a model later is absent from an event by
// default rather than present.
func changed(fields *[]string, name string, differs bool) {
	if differs {
		*fields = append(*fields, name)
	}
}

func intPtrEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// timePtrEqual compares two optional instants with Equal, so a resent expiry
// carrying a different offset is not a change.
func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// upstreamPatchDetails describes a PATCH /upstreams/{id} that landed. It never
// looks at AuthConfig: ciphertexts cannot be compared (Keyring.Seal draws a
// fresh nonce per call), so the credential is reported by authChanged, which
// the handler takes from in.AuthConfig.Has(). The string "auth_config" must
// never enter a row, and the field list below is the reason it cannot. slug is
// absent because the handler refuses any slug change.
func upstreamPatchDetails(before, after models.Upstream, authChanged bool) adminDetails {
	var d adminDetails
	changed(&d.Fields, "name", before.Name != after.Name)
	changed(&d.Fields, "description", before.Description != after.Description)
	changed(&d.Fields, "url", before.URL != after.URL)
	changed(&d.Fields, "transport", before.Transport != after.Transport)
	changed(&d.Fields, "auth_type", before.AuthType != after.AuthType)
	changed(&d.Fields, "enabled", before.Enabled != after.Enabled)
	d.AuthChanged = authChanged
	if authChanged || before.AuthType != after.AuthType {
		d.AuthType = after.AuthType
	}
	return d
}

// groupPatchDetails describes a PATCH /groups/{id} that landed. The member
// list itself is never recorded (it is caller-supplied and unbounded); a
// changed membership carries the new count. cleared is the slice patchGroup
// already computes for its log line.
func groupPatchDetails(before, after models.Group, cleared []string) adminDetails {
	var d adminDetails
	changed(&d.Fields, "name", before.Name != after.Name)
	changed(&d.Fields, "description", before.Description != after.Description)
	members := !slices.Equal(before.UpstreamIDs, after.UpstreamIDs)
	changed(&d.Fields, "upstream_ids", members)
	changed(&d.Fields, "tool_filter", !bytes.Equal(before.ToolFilter, after.ToolFilter))
	if members {
		n := len(after.UpstreamIDs)
		d.UpstreamCount = &n
	}
	d.Cleared = cleared
	return d
}

// virtualKeyPatchDetails describes a PATCH /virtual-keys/{id} that landed.
// The eight names are the eight Optional fields of upsertVirtualKey. Values
// are never recorded: metadata is arbitrary operator JSON and the tool lists
// are operator-authored. cleared is the slice patchVirtualKey already
// computes for its log line.
func virtualKeyPatchDetails(before, after models.VirtualKey, cleared []string) adminDetails {
	var d adminDetails
	changed(&d.Fields, "name", before.Name != after.Name)
	changed(&d.Fields, "target_type", before.TargetType != after.TargetType)
	changed(&d.Fields, "target_id", before.TargetID != after.TargetID)
	changed(&d.Fields, "rate_limit", !intPtrEqual(before.RateLimit, after.RateLimit))
	changed(&d.Fields, "expires_at", !timePtrEqual(before.ExpiresAt, after.ExpiresAt))
	changed(&d.Fields, "tool_allowlist", !slices.Equal(before.ToolAllowlist, after.ToolAllowlist))
	changed(&d.Fields, "tool_denylist", !slices.Equal(before.ToolDenylist, after.ToolDenylist))
	changed(&d.Fields, "metadata", !bytes.Equal(before.Metadata, after.Metadata))
	d.Cleared = cleared
	return d
}

// validResourceType reports whether v is one of the three resource constants.
// Callers check it only when the query value is non-empty; an absent
// resource_type means no filter (compare the limit guard in listLogs). It
// mirrors validTransport and validAuthType in shape, not in their
// empty-string behaviour.
func validResourceType(v string) bool {
	switch v {
	case models.ResourceUpstream, models.ResourceGroup, models.ResourceVirtualKey:
		return true
	}
	return false
}

// listAdminEvents is listLogs with the admin-event filter. An unknown
// resource_type is a 400 rather than an empty page: on an audit endpoint an
// empty answer reads as "nothing happened", so a typo has to say so. An absent
// resource_type means no filter. Every error string is fixed; nothing echoes
// the query. The store clamps a limit above 200 to 50, as ListAuditLogs does.
func (s *Server) listAdminEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := models.AdminEventFilter{Cursor: q.Get("cursor")}
	if v := q.Get("resource_type"); v != "" {
		if !validResourceType(v) {
			writeError(w, http.StatusBadRequest, "invalid resource_type")
			return
		}
		f.ResourceType = v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = n
	}
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid since")
		return
	}
	f.Since = since

	events, next, err := s.store.ListAdminEvents(r.Context(), f)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"admin_events": events, "next_cursor": next})
}
