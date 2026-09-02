package proxy

import (
	"encoding/json"
	"strings"

	"github.com/netcasklabs/porymcp/internal/models"
)

// The reasons a tool can be refused. They are written verbatim into the audit
// row's error_message, because the operator's question about a block is always
// "which rule do I edit?" and a single opaque string makes them diff the group
// against the key by hand. The client is told none of this (it gets one
// generic "tool blocked") so the reason cannot be used to map out a policy
// from outside.
const (
	reasonKeyDenylist   = "blocked by virtual key denylist"
	reasonKeyAllowlist  = "blocked by virtual key allowlist"
	reasonGroupFilter   = "blocked by group tool_filter"
	reasonInvalidFilter = "blocked: invalid group tool_filter"
	// reasonUnknownIdentity: the name is not one a rule could be written
	// against. serve refuses such a name on a group endpoint before the policy
	// is consulted, so this should not be reachable in production; it exists
	// because a policy asked a question it cannot answer must refuse, rather
	// than fall through every rule and permit the call.
	reasonUnknownIdentity = "blocked: not a {slug}__{tool} identity"
	// Its own reason, not reasonInvalidFilter: this one tells the operator to
	// look at the key, and the group's filter may be perfectly fine.
	reasonInvalidKeyLists = "blocked: virtual key tool lists could not be decoded"
)

// identityMode says how the name a client used is turned into the tool
// identity (the member's slug and the tool's own name) that a rule entry is
// matched against. The three modes are the three shapes of endpoint, and the
// mode is what makes one entry mean the same thing on all of them.
type identityMode int

const (
	// modeLiteral does not resolve an identity at all: the name is matched
	// whole against each entry. It is what methods other than tools/call are
	// judged by (keyListsOnly), where the name is a prompt or a resource and
	// not a tool, so a key entry "docs__search" blocks the prompt actually
	// called "docs__search", and nothing is split, scoped or skipped.
	//
	// It is the zero value, and that is deliberate: the alternative would make
	// a toolPolicy nobody built (a struct literal in a test, a field left
	// unset) resolve identities against an empty slug and refuse tools it was
	// never given a rule about. The cost is the other direction: a production
	// call site that forgot to pass a mode would judge a group's canonical
	// names literally, and an unscoped deny entry would then match none of them
	// and fail OPEN. mode is a positional argument to newToolPolicy for that
	// reason, serve is the only production caller, and
	// TestServePassesTheIdentityMode is the tripwire.
	modeLiteral identityMode = iota
	// modeCompose is an endpoint that speaks for exactly one upstream, a member
	// endpoint, or a key bound to a single upstream. The client sees the tool's
	// own name, and the identity is that name together with the slug the
	// endpoint already names.
	modeCompose
	// modeParse is a group's aggregate endpoint, where every advertised name is
	// already the identity spelled out and is split back into its two halves.
	modeParse
)

// toolPolicy is every tool rule that applies to one request, resolved once and
// then asked the same question by everything that needs an answer: the gate in
// ServeHTTP before an upstream is contacted, and the filter that decides what
// tools/list is allowed to advertise. They used to be two separate predicates
// over the same data (keyToolAllowed for the key's lists and applyToolFilter
// for the group's) which is how a group's tool_filter came to hide a tool from
// the catalogue and still let it be called.
//
// The zero value permits everything. That is deliberate and load-bearing: a
// field meaning "this policy was constructed properly" would make every
// zero-value toolPolicy (a struct literal in a test, a field nobody set)
// silently block every tool, so the flag is inverted to malformed instead.
type toolPolicy struct {
	tf    models.ToolFilter // the group's filter, empty when there is no group
	allow []string          // the virtual key's tool_allowlist
	deny  []string          // the virtual key's tool_denylist
	// mode and slug say how a name becomes an identity: see identityMode. slug
	// is the endpoint's own upstream under modeCompose and is unused by the
	// other two, where the name carries the slug or there is no slug to carry.
	mode identityMode
	slug string
	// groupTarget records that the rules apply to a group rather than to one
	// upstream. It is what makes an unscoped allow entry a rule about nothing,
	// see matchesAny.
	groupTarget bool
	// malformed records that the group's tool_filter did not validate, which
	// blocks every tool on that group. A filter with a typo'd mode decodes
	// without error into a filter that matches nothing, and "matches nothing"
	// is indistinguishable from "no filter", so the alternative to failing
	// closed is an authorization bypass that looks exactly like a working
	// deny.
	malformed bool
	// listsMalformed records that the virtual key's own tool_allowlist or
	// tool_denylist did not decode out of the database. It blocks everything
	// for the same reason malformed does: once a decoder has swallowed the
	// error, "the list is unreadable" looks exactly like "there is no list",
	// and the second one permits everything the first was written to refuse.
	//
	// Unlike malformed it SURVIVES keyListsOnly. A group's filter is dropped
	// there because it is about tools and prompts are not tools; a key's lists
	// are the whole of that policy, so a prompts/get judged by an unreadable
	// list has to fail closed as well.
	listsMalformed bool
}

// newToolPolicy resolves the rules for one request. group is nil for a key
// bound to a single upstream. mode and slug are documented on identityMode.
func newToolPolicy(group *models.Group, vk *models.VirtualKey, mode identityMode, slug string) toolPolicy {
	p := toolPolicy{mode: mode, slug: slug, groupTarget: group != nil}
	if vk != nil {
		p.allow = vk.ToolAllowlist
		p.deny = vk.ToolDenylist
		p.listsMalformed = vk.ListsMalformed
	}
	if group == nil || len(group.ToolFilter) == 0 {
		return p
	}
	// Validated, not merely decoded: {"mode":"Deny"} and {"mode":"deny","tool":
	// [...]} both unmarshal cleanly into a filter that permits everything.
	// Filters written before PORM-19 were never checked by anything, so this
	// is also the only thing standing between an old typo and a group whose
	// filter is cosmetic.
	if err := models.ValidateToolFilter(group.ToolFilter); err != nil {
		p.malformed = true
		return p
	}
	_ = json.Unmarshal(group.ToolFilter, &p.tf)
	return p
}

// active reports whether any rule applies. A policy that is not active cannot
// refuse anything, so callers that only exist to enforce it (rewriting a
// tools/list response, for one) can skip their work entirely. A malformed
// filter is active: it refuses everything, and a catalogue listing tools that
// can no longer be called would be the worst of both answers.
func (p toolPolicy) active() bool {
	return len(p.allow) > 0 || len(p.deny) > 0 || p.tf.Mode != "" || p.malformed || p.listsMalformed
}

// blockedBy returns the rule that refuses advertised, or "" when it is
// permitted. This is the only place the precedence is written down: the key's
// denylist wins over its allowlist, and both win over the group's filter, so a
// key can always be narrowed below what its group permits and never widened
// above it.
func (p toolPolicy) blockedBy(advertised string) string {
	if p.malformed {
		return reasonInvalidFilter
	}
	if p.listsMalformed {
		return reasonInvalidKeyLists
	}
	if !p.active() {
		// No rules, so nothing to resolve. Checked before the identity so that
		// a policy with nothing to say never has an opinion about the shape of
		// a name, the zero value included.
		return ""
	}
	id, ok := p.identity(advertised)
	if !ok {
		return reasonUnknownIdentity
	}
	if p.matchesAny(p.deny, advertised, id, false, false) {
		return reasonKeyDenylist
	}
	if len(p.allow) > 0 && !p.matchesAny(p.allow, advertised, id, false, true) {
		return reasonKeyAllowlist
	}
	switch p.tf.Mode {
	case "allow":
		if len(p.tf.Tools)+len(p.tf.Prefixes) > 0 &&
			!p.matchesAny(p.tf.Tools, advertised, id, false, true) &&
			!p.matchesAny(p.tf.Prefixes, advertised, id, true, true) {
			return reasonGroupFilter
		}
	case "deny":
		if p.matchesAny(p.tf.Tools, advertised, id, false, false) ||
			p.matchesAny(p.tf.Prefixes, advertised, id, true, false) {
			return reasonGroupFilter
		}
	}
	return ""
}

// identity turns the name the client used into the pair a rule is written
// against. It reports false only in modeParse, for a name that is not an
// identity at all, one serve has already refused, and one that could match no
// rule and route to no member if it ever got here.
func (p toolPolicy) identity(advertised string) (models.ToolIdentity, bool) {
	switch p.mode {
	case modeCompose:
		return models.ToolIdentity{Slug: p.slug, Name: advertised}, true
	case modeParse:
		return models.ParseCanonical(advertised)
	default: // modeLiteral resolves nothing; matches works off advertised.
		return models.ToolIdentity{}, true
	}
}

// matchesAny reports whether any entry names this tool. allowSide says the
// entries come from an allow rule (a tool_filter in mode "allow", or a key's
// tool_allowlist) which is the one place an entry can be skipped.
//
// An unscoped allow entry on a group is skipped because it cannot mean what it
// says. "search" as an allow entry is a promise that one named thing is
// permitted, and on a group there is no one named thing: reading it as "search
// on every member" would widen the rule to the whole group, which is the
// opposite of what an operator narrowing access to one member's tool meant. So
// it admits nothing, the management API refuses to write one, the store's
// migration leaves it alone (widening an allowlist is not a migration's
// decision to make) and the startup report names the key or group holding it.
// A deny entry has no such problem ("block this name wherever it appears" is
// exactly what an operator writing one means) and neither does an allow entry
// on a key bound to a single upstream, where every tool belongs to that
// upstream. The skip never applies in modeLiteral: there is no member to scope
// to, and a prompt named "search" would otherwise become uncallable.
func (p toolPolicy) matchesAny(entries []string, advertised string, id models.ToolIdentity, prefix, allowSide bool) bool {
	skipUnscoped := allowSide && p.groupTarget && p.mode != modeLiteral
	for _, e := range entries {
		if skipUnscoped {
			if _, _, scoped := models.SplitEntry(e); !scoped {
				continue
			}
		}
		if p.matches(e, advertised, id, prefix) {
			return true
		}
	}
	return false
}

// matches is one entry against one tool, byte for byte: no trimming, no case
// folding, no Unicode normalisation. Anything else would authorise a string
// the upstream does not execute.
//
// Under modeLiteral the entry is compared with the whole name the client used,
// which is what a prompt or resource name needs, it is not a tool identity and
// has no slug to split off. Everywhere else models.MatchToolEntry decides,
// which is the same function the API, the store and the startup report use, so
// an entry cannot mean one thing where it is written and another where it is
// enforced.
//
// prefix selects HasPrefix over equality, and it is the tool's OWN name that a
// prefixes entry is matched against, never the composed one. A prefixes entry
// names a shape of tool name, "everything starting delete_", and that shape
// does not survive composition: matched against "{slug}__{tool}" a deny prefix
// would match nothing and fail open, while an allow prefix that happened to
// prefix "{slug}__" would admit every tool on the member including the ones it
// was written to exclude. Scoping still works, because a scoped entry's head
// is consumed by the member check: "docs__delete_" is everything starting
// delete_ on docs, and "docs__" is every tool on docs.
func (p toolPolicy) matches(entry, advertised string, id models.ToolIdentity, prefix bool) bool {
	if p.mode != modeLiteral {
		return models.MatchToolEntry(entry, id, prefix)
	}
	if entry == "" {
		// An entry writes reject but an older list may still hold. Matching
		// nothing keeps it the no-op it has always been instead of promoting
		// it to a prefix that matches everything.
		return false
	}
	if prefix {
		return strings.HasPrefix(advertised, entry)
	}
	return entry == advertised
}

// permits is blockedBy read as a question. Both call the same algorithm, so a
// tool that is hidden from a list is exactly a tool that is refused on a call.
func (p toolPolicy) permits(advertised string) bool { return p.blockedBy(advertised) == "" }

// keyListsOnly is p with the group's filter dropped, including a malformed
// one. It is what methods other than tools/call are judged by: the key's
// allow/deny lists have always applied to anything carrying a params.name
// (prompts/get, resources/read), while a group's tool_filter is about tools
// and only tools. PORM-6 owns real prompt and resource policy; until then this
// keeps PORM-19 from quietly extending the filter's reach, and keeps a group
// with a typo in its filter from blocking prompts as collateral.
func (p toolPolicy) keyListsOnly() toolPolicy {
	p.tf = models.ToolFilter{}
	p.malformed = false
	// The identity grammar goes with it. {slug}__{tool} is a TOOL identity: it
	// exists to disambiguate one tool across the members of a group. A prompt
	// or a resource name is not one, so it is matched whole, an entry
	// "docs__search" blocks the prompt called "docs__search", a bare entry
	// blocks the prompt of that name on every path, and nothing is skipped for
	// being unscoped. Resolving one instead would silently invert both: an
	// entry that works on the key's other endpoints would go inert here, and a
	// group key's allowlist would stop admitting the prompts it names. PORM-6
	// owns real prompt and resource policy; until then this is exactly the
	// reach the key's lists have always had. slug and groupTarget are left as
	// they are, modeLiteral consults neither.
	p.mode = modeLiteral
	return p
}

// filterTools drops the tools p refuses. The result is never nil: a catalogue
// that filtered down to nothing is "tools":[], which a client understands,
// where "tools":null is a decode error waiting to happen.
func filterTools(tools []mcpTool, p toolPolicy) []mcpTool {
	out := make([]mcpTool, 0, len(tools))
	for _, t := range tools {
		if p.permits(t.Name) {
			out = append(out, t)
		}
	}
	return out
}
