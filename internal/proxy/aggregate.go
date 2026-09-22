package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
)

type mcpTool struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	// InputSchema is always emitted on the merged list, and buildRoutes makes
	// it one the 2026-07-28 schema accepts: see conformingInputSchema. The rest
	// of a tool's metadata is PORM-73's.
	InputSchema json.RawMessage `json:"inputSchema"`
}

// emptyObjectSchema is the least a tool's inputSchema may be.
var emptyObjectSchema = json.RawMessage(`{"type":"object"}`)

// conformingInputSchema makes a member's inputSchema one the 2026-07-28 schema
// accepts, which requires of every tool a JSON object whose type is the string
// "object". The group endpoint now says it speaks that revision, and a client
// that validates what it is sent rejects the WHOLE list for one tool that does
// not conform, so one careless member would cost the group every tool it has.
//
// A schema that is a JSON object is repaired, not replaced: type is set to
// "object" on the member's own object and everything else it declared stays,
// because a schema with properties and no type, or with type ["object","null"],
// is common, and replacing it would hand a client a tool with every parameter
// erased. A conforming schema crosses byte for byte. Only a value that is not an
// object at all (absent, null, an array, a string) becomes the empty schema.
func conformingInputSchema(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return emptyObjectSchema
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &schema); err != nil || schema == nil {
		return emptyObjectSchema
	}
	if t, ok := jsonString(schema["type"]); ok && t == "object" {
		return raw
	}
	schema["type"] = json.RawMessage(`"object"`)
	repaired, err := marshalRaw(schema)
	if err != nil {
		return emptyObjectSchema
	}
	return repaired
}

// The cache hint on the merged list, in milliseconds.
const (
	// defaultListTTLMs stands in for a member that reports no ttlMs, which is
	// every handshake-era member: how fresh its catalogue is cannot be known.
	defaultListTTLMs = 60000
	// minListTTLMs is the floor. A member may legally report 0, "re-fetch every
	// time", and hosted servers do; under a bare minimum that would make every
	// polite client re-list a group on every use, and each re-list walks every
	// member with its real credential. Ten seconds of list staleness costs
	// nothing, because every tools/call walks the catalogues anyway.
	minListTTLMs = 10000
	// maxListTTLMs matches what the endpoint says of its own server/discover.
	maxListTTLMs = discoverTTLMs
)

// listTTLMs reads result.ttlMs off a member's reduced tools/list answer: the
// one member-sourced value that reaches the merged list, and it is a number
// the member chose, so it is read strictly. The schema types it as a number,
// not an integer, so 3600000.0 is a legal spelling and is accepted; a string, a
// null, a negative, a fraction and anything too large to hold exactly are not
// a report at all. It is a reader of its own, beside parseToolsList and not
// inside it, because PORM-73 rewrites that function.
func listTTLMs(doc []byte) (int64, bool) {
	var env struct {
		Result struct {
			TTL json.RawMessage `json:"ttlMs"`
		} `json:"result"`
	}
	if json.Unmarshal(doc, &env) != nil {
		return 0, false
	}
	raw := bytes.TrimSpace(env.Result.TTL)
	if len(raw) == 0 || raw[0] == '"' || raw[0] == 'n' {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f < 0 || f != math.Trunc(f) || f > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// mergedTTLMs is the merged list's ttlMs: the smallest of the members' values,
// because the merged list is stale as soon as any member's is, held between the
// floor and the ceiling. With no member listed it is the default.
func mergedTTLMs(ttls []int64) int64 {
	if len(ttls) == 0 {
		return defaultListTTLMs
	}
	least := ttls[0]
	for _, v := range ttls[1:] {
		least = min(least, v)
	}
	return min(max(least, minListTTLMs), maxListTTLMs)
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
// and ParseCanonical recovers the pair exactly; see ParseCanonical for the
// proof. One underscore had no such property. "gh" + "_" +
// "enterprise_create_issue" and "gh_enterprise" + "_" + "create_issue" are one
// string, two members could each produce it, and the loser of that silent
// overwrite resolved to the winner's upstream: a call executed against the
// wrong credential. Two members advertising the same tool now get two
// names. Two entries for one name can still only come from one member
// advertising a tool twice, where last-one-wins is the upstream's own
// ambiguity and both entries route to the same credential.
//
// The merged order is part of the contract: members in the order the group
// stores them, and each member's tools in the order that member listed them.
// memberCatalogues walks the members one after another in that order, so the
// order does not depend on which member answered first.
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
			cp.InputSchema = conformingInputSchema(t.InputSchema)
			// The stored slug, with no derive-from-name fallback: deriving would
			// silently reinstate rename-changes-every-tool-name, which is the
			// defect PORM-48 exists to remove. An empty slug is unreachable,
			// CreateUpstream rejects it, the column is NOT NULL and the unique
			// index forbids a second empty one.
			cp.Name = models.ToolIdentity{Slug: up.Slug, Name: t.Name}.Canonical()
			merged = append(merged, cp)
			routes[cp.Name] = toolRoute{Upstream: up, Original: t.Name}
		}
		if dropped > 0 && h.log != nil {
			// One line per member, with the count and never the name. The reason
			// these were dropped is that the proxy cannot hold a caller to them,
			// and a name carrying a control character is upstream data this log
			// has no business reproducing, the same rule warnListPassThrough
			// follows.
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

// metaAction is what a routed call's params._meta needs for the member it is
// going to: see memberCallHeaders, which decides it with the headers, because
// the two declare the same thing and have to move together.
type metaAction int

const (
	// metaKeep leaves _meta as the client sent it. The client and the member
	// speak the same era, or the member's era is not known.
	metaKeep metaAction = iota
	// metaCompose writes the three members a 2026-07-28 request must carry, for
	// a handshake-era client calling a modern member.
	metaCompose
	// metaStrip removes those three, for a modern client calling a
	// handshake-era member.
	metaStrip
)

// modernMetaMembers is mcpclient.ModernMeta as a map: the three reserved
// members a stateless request declares itself with, and the one spelling of
// their names this package uses.
func modernMetaMembers() map[string]json.RawMessage {
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(mcpclient.ModernMeta()), &m)
	return m
}

// dropReservedMeta removes the three reserved members from a _meta object,
// under ANY spelling that folds onto their names. metaProtocolVersion reads the
// declared version through a struct tag, and encoding/json matches a tag
// without regard to case, so a client that spells the member
// IO.ModelContextProtocol/ProtocolVersion passes the version check. Deleting
// the exact key alone would leave that spelling in the body: a handshake-era
// member would be sent a request that still declares the stateless revision,
// with no header beside it, and a modern member one object declaring two
// versions. What the check can read, this removes.
func dropReservedMeta[V any](meta map[string]V) {
	reserved := modernMetaMembers()
	for k := range meta {
		for name := range reserved {
			if strings.EqualFold(k, name) {
				delete(meta, k)
				break
			}
		}
	}
}

// rewriteToolCallParams rebuilds a routed call's params for the member it is
// going to: the member's own tool name for the composed one, always, and the
// _meta the member's era expects. Only the three reserved members are written
// or removed. Anything else the client put in _meta, a progressToken say, is
// the client's and crosses as it came; _meta itself goes only when stripping
// leaves it empty.
func rewriteToolCallParams(params json.RawMessage, original string, meta metaAction) json.RawMessage {
	m := map[string]any{}
	if len(params) != 0 {
		if err := json.Unmarshal(params, &m); err != nil || m == nil {
			return params
		}
	}
	m["name"] = original
	switch meta {
	case metaCompose:
		existing, _ := m["_meta"].(map[string]any)
		if existing == nil {
			existing = map[string]any{}
		}
		dropReservedMeta(existing)
		for k, v := range modernMetaMembers() {
			existing[k] = v
		}
		m["_meta"] = existing
	case metaStrip:
		if existing, ok := m["_meta"].(map[string]any); ok {
			dropReservedMeta(existing)
			if len(existing) == 0 {
				delete(m, "_meta")
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return params
	}
	return b
}

// stripReservedMeta removes the three reserved _meta members from a request's
// params for a handshake-era member and reports whether anything was removed.
// Only the envelope of params and of _meta is decoded, each into raw members:
// every value crosses as the bytes the client sent, which
// rewriteToolCallParams, built on map[string]any, does not promise (an integer
// past 2^53 and a string with < in it come back changed there). _meta itself
// goes when nothing is left in it. params that are empty, not an object, or
// hold no reserved member come back unchanged with false, so the caller sends
// the client's bytes untouched. Member order may change; no value does.
func stripReservedMeta(params json.RawMessage) (json.RawMessage, bool) {
	if len(bytes.TrimSpace(params)) == 0 {
		return params, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(params, &m); err != nil || m == nil {
		return params, false
	}
	key := ""
	for k := range m {
		if strings.EqualFold(k, "_meta") {
			key = k
			break
		}
	}
	if key == "" {
		return params, false
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(m[key], &meta); err != nil || meta == nil {
		return params, false
	}
	before := len(meta)
	dropReservedMeta(meta)
	if len(meta) == before {
		return params, false
	}
	if len(meta) == 0 {
		delete(m, key)
	} else {
		raw, err := marshalRaw(meta)
		if err != nil {
			return params, false
		}
		m[key] = raw
	}
	out, err := marshalRaw(m)
	if err != nil {
		return params, false
	}
	return out, true
}

// replaceParams writes params into a request envelope in place of every
// spelling of the params member: parseRequest binds the key case-insensitively
// and refuses only a colliding pair, so a client may have spelled it Params,
// and a member must never be sent two spellings of one member. Every other
// envelope member, the id above all, crosses as raw bytes; marshalRaw writes
// the members in sorted order and escapes no HTML. A body that is not an
// object comes back as it came.
func replaceParams(body, params json.RawMessage) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return body
	}
	for k := range m {
		if strings.EqualFold(k, "params") {
			delete(m, k)
		}
	}
	m["params"] = params
	out, err := marshalRaw(m)
	if err != nil {
		return body
	}
	return out
}

// routingFields is the one bounded read of params that serve makes: the
// three members the routing headers are compared with, decoded in a single
// pass so the tool name the gate judges and the name the header is held to
// are the same string read once. A second decode of the same bytes would be
// a second chance to disagree about which call this is, and would scan an
// up to 8 MiB body twice.
//
// Like the envelope and params themselves (parseRequest), these are fields
// Go binds by tag, which it matches case-insensitively. distinctKeys over the
// top level of params refuses two spellings of one member together; a single
// miscased key ("Name") is read here and looked up exactly, and so ignored,
// by an upstream. That is leniency, not bypass: the gate then judges a name
// the upstream will not execute, and a routing header compared against it
// still has to agree with what the proxy read.
type routingFields struct {
	Name json.RawMessage `json:"name"`
	URI  json.RawMessage `json:"uri"`
	Meta json.RawMessage `json:"_meta"`
	// ProtocolVersion is initialize's params.protocolVersion. It is read on
	// this pass, with the rest, so the group endpoint's negotiation judges the
	// same bytes distinctKeys has already held to one spelling.
	ProtocolVersion json.RawMessage `json:"protocolVersion"`
}

// decodeRoutingFields reads params once. Params that do not decode as an
// object yield the zero value, which names nothing.
func decodeRoutingFields(params json.RawMessage) routingFields {
	var f routingFields
	if err := json.Unmarshal(params, &f); err != nil {
		return routingFields{}
	}
	return f
}

// name is the JSON string at params.name. A null, a number, an object or an
// absent member is not a name.
func (f routingFields) name() (string, bool) { return jsonString(f.Name) }

// uri is the JSON string at params.uri, the value Mcp-Name mirrors on
// resources/read. A URI is not a tool name, so UsableToolName is not applied.
func (f routingFields) uri() (string, bool) { return jsonString(f.URI) }

// toolName is name under the rule the gate applies: a string the proxy can
// hold the caller to. ok is false when params.name is absent, is not a JSON
// string, or is not a usable name.
func (f routingFields) toolName() (string, bool) {
	s, ok := f.name()
	if !ok || !models.UsableToolName(s) {
		return "", false
	}
	return s, true
}

// toolNameFromParams reads the tool a request names, and reports whether it
// found one it can hold the caller to. It is decodeRoutingFields followed by
// toolName, kept as one call for the sites that need only the name.
func toolNameFromParams(params json.RawMessage) (string, bool) {
	return decodeRoutingFields(params).toolName()
}

// protocolVersion is the JSON string at params.protocolVersion, and "" for a
// number, a null, an object or an absent member, none of which is a version.
func (f routingFields) protocolVersion() string {
	v, _ := jsonString(f.ProtocolVersion)
	return v
}

// jsonString decodes raw when it is a JSON string and reports false for
// anything else, a null included.
func jsonString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}
