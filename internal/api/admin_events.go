package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/webutil"
	"github.com/go-chi/chi/v5/middleware"
)

// adminDetails is the closed detail object of one admin event. A value is
// recorded only when the API already returns it in the clear, it is not
// operator-authored text, and it is bounded: a slug, an auth type, a key
// prefix, a target, a member count. Names, descriptions, URLs, metadata, tool
// filters, tool lists and member id lists appear only as field names in
// Fields or Cleared. No credential, ciphertext or plaintext key can be
// expressed here, and the string "auth_config" never enters a row: a stored
// credential is AuthChanged, and a removed one is the word "credential" in
// Cleared, the one Cleared entry that is not a request field name
// (PORM-120). Every field is omitempty, so a key is present only when it
// carries information; UpstreamCount is a pointer so a count of zero
// survives.
//
// Fields lists the field names whose stored value differs between the row the
// handler read and the row it wrote. Cleared is the intent the PATCH handlers
// already compute (the request nulled or emptied a field, or removed the
// stored credential) and can appear without a matching Fields entry when the
// field was already empty.
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

// auditText is audit.Text: the one cleaning a caller-controlled string gets
// before it is stored on an admin_events row.
func auditText(s string) string { return audit.Text(s) }

// recordAdmin writes one event for a change that has already landed. It is
// called after the store write returned nil and before the response, never on
// a request the store rejected. The recorder itself (the panic guard, the
// detached bounded write, the text bounds) is audit.RecordAdmin, shared with
// the token refresh path in internal/credential; this wrapper is what a
// request contributes: the actor, the request id and the client address.
//
// id is the id of the row the handler read, never a URL parameter; audit.Text
// on it is a no-op for a server-minted uuid and closes the column by
// construction.
func (s *Server) recordAdmin(r *http.Request, action, id, name string, details adminDetails) {
	// A closed struct of strings, bools, pointers and []string cannot fail to
	// marshal.
	raw, _ := json.Marshal(details)
	audit.RecordAdmin(r.Context(), s.store, s.log, models.AdminEvent{
		Actor:        models.ActorAdmin,
		Action:       action,
		ResourceID:   id,
		ResourceName: name,
		Details:      raw,
		RequestID:    middleware.GetReqID(r.Context()),
		RemoteAddr:   webutil.ClientIP(r, s.cfg.TrustedProxies),
	})
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
// compares AuthConfig values: ciphertexts cannot be compared (Keyring.Seal
// draws a fresh nonce per call), so a stored credential is reported by
// authChanged, which the handler passes when the request carried a credential
// that was stored. The one thing it reads from AuthConfig is its length: a
// column that held bytes and holds none afterwards records "credential" in
// Cleared (PORM-120). The string "auth_config" must never enter a row, and
// the field list below is the reason it cannot. slug is absent because the
// handler refuses any slug change.
func upstreamPatchDetails(before, after models.Upstream, authChanged bool) adminDetails {
	var d adminDetails
	changed(&d.Fields, "name", before.Name != after.Name)
	changed(&d.Fields, "description", before.Description != after.Description)
	changed(&d.Fields, "url", before.URL != after.URL)
	changed(&d.Fields, "transport", before.Transport != after.Transport)
	changed(&d.Fields, "auth_type", before.AuthType != after.AuthType)
	changed(&d.Fields, "enabled", before.Enabled != after.Enabled)
	if len(before.AuthConfig) > 0 && len(after.AuthConfig) == 0 {
		d.Cleared = append(d.Cleared, "credential")
	}
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
