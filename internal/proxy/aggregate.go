package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/netcasklabs/porymcp/internal/models"
)

type mcpTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type toolRoute struct {
	Upstream *models.Upstream
	Original string
}

// buildRoutes merges the members' catalogues into the one a group endpoint
// advertises, and returns the table that takes an advertised name back to the
// member that owns it and the name that member knows it by.
//
// Every tool is advertised as its identity, always: the member's stored slug,
// ToolSeparator, and the tool's own name. Composing unconditionally is what
// makes an advertised name a property of the group's membership rather than of
// which members happened to answer, so a rule written against one keeps
// meaning what it meant when a member is added, removed or unreachable.
//
// The composition is injective, which is the property routing depends on: a
// valid slug holds no "__" of its own and ends alphanumeric, so the first "__"
// in the composed name sits at exactly len(slug) whatever the tool is called,
// and ParseCanonical recovers the pair exactly — see ParseCanonical for the
// proof. One underscore had no such property. "gh" + "_" +
// "enterprise_create_issue" and "gh_enterprise" + "_" + "create_issue" are one
// string, two members could each produce it, and the loser of that silent
// overwrite resolved to the winner's upstream: a call executed against the
// wrong credential. Two members advertising the same tool now simply get two
// names. Two entries for one name can still only come from one member
// advertising a tool twice, where last-one-wins is the upstream's own
// ambiguity and both entries route to the same credential.
func (h *Handler) buildRoutes(upstreams []*models.Upstream, lists [][]mcpTool) (merged []mcpTool, routes map[string]toolRoute) {
	routes = map[string]toolRoute{}
	for i, tools := range lists {
		up := upstreams[i]
		dropped := 0
		for _, t := range tools {
			if !models.UsableToolName(t.Name) {
				// A name the call gate would refuse is a name this catalogue
				// must not advertise: the client would be shown a tool that
				// can never be called, and for the U+FFFD case the string the
				// gate reads is not the one the upstream executes.
				dropped++
				continue
			}
			cp := t
			// The stored slug, with no derive-from-name fallback: deriving
			// would silently reinstate rename-changes-every-tool-name, which is
			// the defect PORM-48 exists to remove. An empty slug is unreachable
			// — CreateUpstream rejects it, the column is NOT NULL and the
			// unique index forbids a second empty one.
			cp.Name = models.ToolIdentity{Slug: up.Slug, Name: t.Name}.Canonical()
			merged = append(merged, cp)
			routes[cp.Name] = toolRoute{Upstream: up, Original: t.Name}
		}
		if dropped > 0 && h.log != nil {
			// One line per member, with the count and never the name. The
			// reason these were dropped is that the proxy cannot hold a caller
			// to them, and a name carrying a control character is upstream data
			// this log has no business reproducing — the same rule
			// warnListPassThrough follows.
			h.log.Warn("dropped tools whose names cannot be gated",
				"upstream_id", up.ID,
				"tools", dropped,
			)
		}
	}
	return merged, routes
}

func parseToolsList(body []byte) ([]mcpTool, error) {
	var envelope struct {
		Result struct {
			Tools []mcpTool `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("%s", envelope.Error.Message)
	}
	return envelope.Result.Tools, nil
}

func rewriteToolCallParams(params json.RawMessage, original string) json.RawMessage {
	if len(params) == 0 {
		b, _ := json.Marshal(map[string]string{"name": original})
		return b
	}
	var m map[string]any
	if err := json.Unmarshal(params, &m); err != nil {
		return params
	}
	m["name"] = original
	b, err := json.Marshal(m)
	if err != nil {
		return params
	}
	return b
}

// toolNameFromParams reads the tool a request names, and reports whether it
// found one it can hold the caller to. ok is false when params.name is absent,
// is not a JSON string, or is not a usable name.
func toolNameFromParams(params json.RawMessage) (string, bool) {
	var m struct {
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(params, &m); err != nil || m.Name == nil || !models.UsableToolName(*m.Name) {
		return "", false
	}
	return *m.Name, true
}
