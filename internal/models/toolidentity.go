package models

import "strings"

// ToolSeparator joins an upstream's slug to a tool's own name. It is two
// underscores rather than one because ValidSlug forbids a run of two
// separators inside a slug, and that is exactly what makes the join
// reversible, ParseCanonical carries the argument and the counter-example.
const ToolSeparator = "__"

// ToolIdentity is what a tool rule is really written against: a tool's own
// name together with the upstream advertising it. The name alone is not an
// identity, because two members of one group may both advertise "create_issue"
// and they are different tools with different credentials behind them.
//
// A client sees the identity spelled differently depending on where it is
// looking (Canonical on a group's aggregate endpoint, the bare Name on a
// member endpoint or a single-upstream key) but a rule naming the pair means
// the same thing on all of them.
type ToolIdentity struct {
	// Slug is the persisted slug of the upstream advertising the tool. It is
	// always a stored slug, never anything derived from the tool name, and it
	// therefore satisfies ValidSlug, which ParseCanonical depends on.
	Slug string
	// Name is the tool's name exactly as its upstream advertises it, including
	// any ToolSeparator of its own: an upstream that is itself a proxy will
	// advertise names like "mcp__server__tool".
	Name string
}

// Canonical is the identity as one string: the name a client is shown on a
// group's aggregate endpoint and writes back in tools/call.
func (t ToolIdentity) Canonical() string { return t.Slug + ToolSeparator + t.Name }

// ParseCanonical recovers the identity from a canonical string by splitting at
// the FIRST ToolSeparator. It reports false when the string is not one: no
// separator, nothing before it, or nothing after it.
//
// The split is exact (ParseCanonical(id.Canonical()) returns id for every tool
// name an upstream can advertise) and that is a property of ValidSlug rather
// than a convention:
//
//   - a valid slug contains no run of two separators, so it holds no "__" for
//     the search to stop at early; and
//   - a valid slug ends alphanumeric, so it cannot lend its last byte to the
//     join and make the first "__" begin one byte early.
//
// The first "__" in slug+"__"+name therefore sits at exactly len(slug),
// whatever the name is: "alpha" and "_search" round-trip through
// "alpha___search", "alpha" and "mcp__inner__tool" through
// "alpha__mcp__inner__tool". Because a left inverse exists, distinct identities
// have distinct canonical strings, which is what lets the aggregate endpoint
// route a call by the name the client sent back.
//
// One underscore has no such property, and the difference is not cosmetic: "gh"
// + "_" + "enterprise_create_issue" and "gh_enterprise" + "_" + "create_issue"
// are the same string. Two members can each produce it, only one can own it in
// the merged catalogue, and the loser's tool then resolves to the winner's
// upstream, a call executed against the wrong credential.
func ParseCanonical(s string) (ToolIdentity, bool) {
	i := strings.Index(s, ToolSeparator)
	if i <= 0 { // no separator, or nothing before it
		return ToolIdentity{}, false
	}
	name := s[i+len(ToolSeparator):]
	if name == "" {
		return ToolIdentity{}, false
	}
	return ToolIdentity{Slug: s[:i], Name: name}, true
}

// ValidToolIdentity reports whether s has the shape of a canonical identity: it
// parses, and the text before the separator is a syntactically valid slug.
//
// This is deliberately syntax and nothing else. It reads no group, no upstream
// and no store, so the aggregate endpoint can refuse a name that could not
// identify a tool anywhere without the refusal depending on what the caller's
// key can reach: a member's slug and a stranger's slug cost the same and get
// the same answer, so the check can never be used to enumerate the upstreams
// behind a group. Membership belongs to the policy and the router, not here,
// ValidToolIdentity("mcp__server__tool") is true even though no upstream may
// hold the reserved slug "mcp", and true for any well-formed slug the caller
// invents.
func ValidToolIdentity(s string) bool {
	id, ok := ParseCanonical(s)
	return ok && ValidSlug(id.Slug)
}

// SplitEntry classifies one rule entry (an entry of a group's tool_filter
// tools or prefixes list, or of a virtual key's tool_allowlist or
// tool_denylist) as scoped or unscoped. It is the ONE definition of that
// split, shared by the proxy, the management API, the store's migration and
// the startup report, so an entry cannot mean one thing where it is written
// and another where it is enforced.
//
// An entry is scoped when it holds the separator with something before it:
// "docs__search" names one tool on the member "docs". Everything else is
// unscoped and names a tool by its own name on every member, including
// "__search", where nothing precedes the separator, because an upstream is
// free to advertise a tool actually called "__search" and an operator has to
// be able to write that down.
//
// For an unscoped entry head is "" and rest is the WHOLE entry, not the text
// after a leading separator, so a caller can match rest without first asking
// which kind of entry it has.
func SplitEntry(e string) (head, rest string, scoped bool) {
	i := strings.Index(e, ToolSeparator)
	if i <= 0 {
		return "", e, false
	}
	return e[:i], e[i+len(ToolSeparator):], true
}

// MatchToolEntry reports whether entry names id. prefix selects the rule a
// tool_filter prefixes entry is matched by (strings.HasPrefix) over the exact
// match used by a tools entry and by a key's lists.
//
// A scoped entry matches only on its own member and matches its rest against
// the tool's OWN name (the slug is consumed by the head) so "docs__delete_" as
// a prefixes entry means "everything starting delete_ on docs", and "docs__"
// means every tool on docs. An unscoped entry is matched against the own name
// on every member, so one entry covers a group's aggregate endpoint and each
// member endpoint alike: the client sees different strings there, but the
// identity is the same one.
//
// Two consequences worth naming. A ToolIdentity with an empty Slug (the zero
// value, or a policy that never learned which member it stands on) matches no
// scoped entry at all, because a scoped entry's head is non-empty by
// construction. And an empty entry matches nothing: writes reject it, but a
// list stored before that check existed may still hold one, and matching
// nothing keeps it the no-op it has always been instead of promoting it to a
// prefix that matches every tool in the catalogue.
func MatchToolEntry(entry string, id ToolIdentity, prefix bool) bool {
	if entry == "" {
		return false
	}
	head, rest, scoped := SplitEntry(entry)
	if scoped && head != id.Slug {
		return false
	}
	if prefix {
		return strings.HasPrefix(id.Name, rest)
	}
	return rest == id.Name
}
