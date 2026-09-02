package models

import (
	"encoding/json"
	"time"
)

const (
	TransportStreamableHTTP = "streamable-http"
	TransportSSE            = "sse"

	AuthNone   = "none"
	AuthBearer = "bearer"
	AuthHeader = "header"
	AuthAPIKey = "api_key"
	AuthCustom = "custom"

	TargetUpstream = "upstream"
	TargetGroup    = "group"

	StatusSuccess = "success"
	StatusError   = "error"
	StatusBlocked = "blocked"
)

// Upstream is a real MCP server whose credentials stay inside PoryMCP.
type Upstream struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	Description string          `json:"description,omitempty"`
	URL         string          `json:"url"`
	Transport   string          `json:"transport"`
	AuthType    string          `json:"auth_type"`
	AuthConfig  json.RawMessage `json:"-"` // encrypted at rest; never serialised raw
	Enabled     bool            `json:"enabled"`
	// LastTestAt and LastTestOK record the last deliberate connection test — a
	// press of Tools or Refresh in the dashboard, which is
	// POST /upstreams/{id}/discover. Both are nil until the first one; they are
	// written together or not at all. PATCH cannot set them: upsertUpstream has
	// no such fields, and UpdateUpstream only ever NULLs them (when url,
	// transport, auth_type or auth_config changed) or leaves them alone — never
	// writes them from the struct. CreateUpstream does write the struct's values,
	// which the API always leaves nil.
	//
	// No omitempty, unlike ExpiresAt and LastUsedAt on VirtualKey: the dashboard
	// renders a three-state cell, so "never tested" must arrive as an explicit
	// null rather than as a missing key. LastTestOK mirrors Discovery.OK — the
	// whole handshake AND the catalogue — so a run that passed initialize and
	// failed tools/list records false, and so does a refused transport or an
	// undecryptable stored credential: PoryMCP could not use the upstream, which
	// is what the dot answers. Nothing the upstream said is kept: no catalogue
	// (PORM-113), no tool count, no error sentence.
	LastTestAt *time.Time `json:"last_test_at"`
	LastTestOK *bool      `json:"last_test_ok"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// AuthConfig is the decrypted credential payload for an Upstream.
type AuthConfig struct {
	Token   string            `json:"token,omitempty"`
	Header  string            `json:"header,omitempty"`
	Value   string            `json:"value,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Group is a named collection of Upstreams exposed as one MCP shape.
type Group struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	UpstreamIDs []string        `json:"upstream_ids"`
	ToolFilter  json.RawMessage `json:"tool_filter,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ToolFilter optionally allowlists or denylists tools in a Group.
type ToolFilter struct {
	Mode     string   `json:"mode,omitempty"` // allow | deny
	Tools    []string `json:"tools,omitempty"`
	Prefixes []string `json:"prefixes,omitempty"`
}

// VirtualKey is a credential PoryMCP issues to one agent (Claude Code, Cursor,
// a bot). It points at one Upstream or one Group.
type VirtualKey struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	KeyHash       string          `json:"-"`
	KeyLookup     string          `json:"-"`
	KeyPrefix     string          `json:"key_prefix"`
	TargetType    string          `json:"target_type"`
	TargetID      string          `json:"target_id"`
	RateLimit     *int            `json:"rate_limit,omitempty"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty"`
	ToolAllowlist []string        `json:"tool_allowlist,omitempty"`
	ToolDenylist  []string        `json:"tool_denylist,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	LastUsedAt    *time.Time      `json:"last_used_at,omitempty"`
	RevokedAt     *time.Time      `json:"revoked_at,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	// ListsMalformed reports that ToolAllowlist or ToolDenylist could not be
	// decoded out of storage, so neither list is the rule its operator wrote.
	//
	// It is not stored and not serialised: it describes one read of one row,
	// and there is nothing a client could do with it. The proxy reads it as
	// "refuse everything on this key" — an unreadable denylist that decoded to
	// no denylist at all would otherwise permit exactly what it was written to
	// refuse, and it would look identical to a key that never had one.
	//
	// It also travels back into the store on the way out, where it means "leave
	// both list columns alone": the two fields above are nil on a marked key,
	// so writing them would replace the unreadable rule with no rule at all.
	// Clearing it is how a caller says it has new text for both columns.
	ListsMalformed bool `json:"-"`
}

func (k VirtualKey) Status() string {
	if k.RevokedAt != nil {
		return "revoked"
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return "expired"
	}
	return "active"
}

// AuditLog records one proxied MCP method call.
type AuditLog struct {
	ID                string          `json:"id"`
	Timestamp         time.Time       `json:"timestamp"`
	VirtualKeyID      string          `json:"virtual_key_id"`
	VirtualKeyName    string          `json:"virtual_key_name"`
	Method            string          `json:"method"`
	ToolName          string          `json:"tool_name,omitempty"`
	Params            json.RawMessage `json:"params,omitempty"`
	Status            string          `json:"status"`
	LatencyMS         int             `json:"latency_ms"`
	ResponseSizeBytes int             `json:"response_size_bytes,omitempty"`
	UpstreamID        string          `json:"upstream_id,omitempty"`
	ErrorMessage      string          `json:"error_message,omitempty"`
	RequestID         string          `json:"request_id"`
}

// Stats is the dashboard overview payload.
type Stats struct {
	ActiveVirtualKeys int     `json:"active_virtual_keys"`
	TotalVirtualKeys  int     `json:"total_virtual_keys"`
	Upstreams         int     `json:"upstreams"`
	Groups            int     `json:"groups"`
	CallsToday        int     `json:"calls_today"`
	ErrorsToday       int     `json:"errors_today"`
	ErrorRate         float64 `json:"error_rate"`
	CallsLast7Days    int     `json:"calls_last_7_days"`
	BlockedToday      int     `json:"blocked_today"`
}

// LogFilter is used by the queryable logs API.
type LogFilter struct {
	VirtualKeyID string
	Since        *time.Time
	Until        *time.Time
	Method       string
	Tool         string
	Status       string
	Limit        int
	Cursor       string
}
