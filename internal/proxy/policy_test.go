package proxy

import (
	"encoding/json"
	"testing"

	"github.com/danjonesio/porymcp/internal/models"
)

// A rule is matched against the tool's identity (the upstream's slug and the
// tool's own name) and the endpoint decides how the name the client used
// becomes that pair. modeCompose is the shape where the two differ: the client
// sends the tool's own name and the endpoint already knows the slug, as a
// member endpoint and a single-upstream key both do. A scoped entry then has to
// name that slug, and one naming another member's must not reach this tool.
//
// prefixes are matched against the tool's own name whichever mode is in play,
// and the second half of this test says why.
func TestToolPolicyComposedIdentity(t *testing.T) {
	scoped := toolPolicy{
		tf:   models.ToolFilter{Mode: "deny", Tools: []string{"github__create_issue"}},
		mode: modeCompose, slug: "github",
	}
	if scoped.permits("create_issue") {
		t.Error(`deny ["github__create_issue"] on the member github permitted create_issue`)
	}
	if !scoped.permits("read_issue") {
		t.Error("a deny naming one tool refused another")
	}

	// The same entry on a different member. Its head is the whole of the
	// member check: without it, one member's rule would silently govern every
	// member advertising a tool of that name.
	elsewhere := toolPolicy{
		tf:   models.ToolFilter{Mode: "deny", Tools: []string{"github__create_issue"}},
		mode: modeCompose, slug: "docs",
	}
	if !elsewhere.permits("create_issue") {
		t.Error(`deny ["github__create_issue"] reached create_issue on docs`)
	}

	// An unscoped entry names a tool by its own name on every member, which is
	// what makes one deny enough for a group and all of its endpoints.
	unscoped := toolPolicy{
		tf:   models.ToolFilter{Mode: "deny", Tools: []string{"create_issue"}},
		mode: modeCompose, slug: "github",
	}
	if unscoped.permits("create_issue") {
		t.Error(`deny ["create_issue"] did not reach create_issue on a member endpoint`)
	}
	if !unscoped.permits("read_issue") {
		t.Error("an unscoped deny refused a tool it does not name")
	}

	// prefixes go against the tool's own name, and getting this backwards
	// inverts the rule rather than narrowing it. A prefixes entry names a shape
	// of tool name; matched against a composed "{slug}__{tool}" a deny prefix
	// would match nothing at all (the tool would be forwarded with the real
	// credential) and an allow prefix that happens to prefix "{slug}__" would
	// admit every tool on the member instead of the ones it names.
	denyPrefix := toolPolicy{
		tf:   models.ToolFilter{Mode: "deny", Prefixes: []string{"delete_"}},
		mode: modeCompose, slug: "github",
	}
	if denyPrefix.permits("delete_repo") {
		t.Error(`deny prefixes ["delete_"] permitted delete_repo on a member endpoint: the deny failed open and the real credential would be presented`)
	}
	if !denyPrefix.permits("read_issue") {
		t.Error("a deny prefix refused a tool it does not prefix")
	}

	// The aggregate endpoint's spelling of the same rule, parsed rather than
	// composed. The two lines below are the same tool asked about from the two
	// doors it can be called through, and one entry has to answer for both.
	denyPrefixAggregate := toolPolicy{
		tf:   models.ToolFilter{Mode: "deny", Prefixes: []string{"delete_"}},
		mode: modeParse,
	}
	if denyPrefixAggregate.permits("github__delete_repo") {
		t.Error(`deny prefixes ["delete_"] permitted github__delete_repo on a group endpoint`)
	}
	if !denyPrefixAggregate.permits("github__read_issue") {
		t.Error("a deny prefix refused a tool it does not prefix on a group endpoint")
	}

	// A scoped prefixes entry, which is what an allow rule on a group must
	// look like. The head picks the member and the rest is still measured
	// against the tool's own name.
	allowPrefix := toolPolicy{
		tf:   models.ToolFilter{Mode: "allow", Prefixes: []string{"gh__gh_"}},
		mode: modeCompose, slug: "gh", groupTarget: true,
	}
	if allowPrefix.permits("danger") {
		t.Error(`allow prefixes ["gh__gh_"] permitted danger: the rest is matched against the tool's own name, and "danger" does not start "gh_"`)
	}
	if !allowPrefix.permits("gh_read") {
		t.Error("an allow prefix refused the tool it names")
	}
}

// The one rule that reads an entry as saying nothing: an allow entry on a
// group that names no member. It cannot keep the promise an allow rule makes
// ("this one named thing is permitted") because on a group there is no one
// named thing, and reading it as "on every member" would widen the rule to the
// whole group. A deny is unaffected, and so is a key bound to one upstream.
func TestUnscopedAllowEntryIsSkippedOnAGroup(t *testing.T) {
	group := toolPolicy{
		tf:   models.ToolFilter{Mode: "allow", Tools: []string{"search", "docs__read"}},
		mode: modeParse, groupTarget: true,
	}
	if group.permits("alpha__search") {
		t.Error(`allow ["search"] admitted alpha__search on a group: an unscoped allow entry admits nothing`)
	}
	if !group.permits("docs__read") {
		t.Error("the scoped entry beside it stopped admitting the tool it names")
	}

	// The same list on a key bound to one upstream, where every tool belongs to
	// that upstream and a bare name is exactly right.
	single := toolPolicy{
		tf:   models.ToolFilter{Mode: "allow", Tools: []string{"search"}},
		mode: modeCompose, slug: "solo",
	}
	if !single.permits("search") {
		t.Error(`allow ["search"] refused search on a single-upstream key`)
	}

	// Deny is not skipped: "block this name wherever it appears" is exactly
	// what an operator writing an unscoped deny means.
	deny := toolPolicy{
		tf:   models.ToolFilter{Mode: "deny", Tools: []string{"search"}},
		mode: modeParse, groupTarget: true,
	}
	if deny.permits("alpha__search") {
		t.Error(`deny ["search"] was skipped for being unscoped`)
	}
}

// The zero value has to permit everything. Any field meaning "this policy was
// built properly" inverts that: a struct literal setting only the two fields a
// test cares about, or a policy nobody assigned, would refuse every tool and
// look exactly like a working denylist while doing it.
func TestToolPolicyZeroValueIsPermissive(t *testing.T) {
	var p toolPolicy
	if !p.permits("anything") {
		t.Error("the zero-value policy blocked a tool")
	}
	if by := p.blockedBy("anything"); by != "" {
		t.Errorf("the zero-value policy gave a reason to block: %q", by)
	}
	if p.active() {
		t.Error("the zero-value policy reports rules it does not have")
	}
}

// active is what lets a caller skip work it does not need, rewriting a
// tools/list response, in the commit that follows this one. The malformed row
// is the one that matters: a filter that fails validation refuses every call,
// so a policy that called itself inactive would leave the client holding a
// catalogue of tools none of which can be called.
func TestToolPolicyActive(t *testing.T) {
	group := func(filter string) *models.Group { return &models.Group{ToolFilter: json.RawMessage(filter)} }
	key := func(allow, deny []string) *models.VirtualKey {
		return &models.VirtualKey{ToolAllowlist: allow, ToolDenylist: deny}
	}
	cases := []struct {
		name  string
		group *models.Group
		vk    *models.VirtualKey
		want  bool
	}{
		{"nothing configured", nil, key(nil, nil), false},
		{"group with no filter", &models.Group{}, key(nil, nil), false},
		{"group filter of null", group(`null`), key(nil, nil), false},
		{"key allowlist", nil, key([]string{"a"}, nil), true},
		{"key denylist", nil, key(nil, []string{"a"}), true},
		{"group deny filter", group(`{"mode":"deny","tools":["a"]}`), key(nil, nil), true},
		{"group allow filter", group(`{"mode":"allow","prefixes":["a_"]}`), key(nil, nil), true},
		{"malformed group filter", group(`{"mode":"Deny","tools":["a"]}`), key(nil, nil), true},
		{"group filter that is not an object", group(`"nonsense"`), key(nil, nil), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := newToolPolicy(c.group, c.vk, modeParse, "").active(); got != c.want {
				t.Errorf("active()=%v want %v", got, c.want)
			}
		})
	}
}

// keyListsOnly is how a method that is not tools/call keeps the reach it has
// always had. It must drop the malformed flag with the filter: a typo in a
// group's tool_filter is a reason to refuse that group's tools, not a reason
// to take its prompts offline as collateral.
func TestToolPolicyKeyListsOnly(t *testing.T) {
	p := newToolPolicy(
		&models.Group{ToolFilter: json.RawMessage(`{"mode":"deny","tool":["x"]}`)},
		&models.VirtualKey{ToolDenylist: []string{"secret_prompt"}},
		modeParse, "",
	)
	if !p.malformed {
		t.Fatal("a filter with a misspelt key validated")
	}
	only := p.keyListsOnly()
	if only.malformed {
		t.Error("keyListsOnly kept the malformed flag; a group typo would block prompts too")
	}
	if only.mode != modeLiteral {
		t.Errorf("mode=%v want modeLiteral: a prompt name is not a tool identity", only.mode)
	}
	if !only.permits("some_prompt") {
		t.Error("keyListsOnly refused a name no key list names")
	}
	if by := only.blockedBy("secret_prompt"); by != reasonKeyDenylist {
		t.Errorf("blockedBy=%q want %q; the key's own lists must survive", by, reasonKeyDenylist)
	}

	// The identity grammar goes with the filter. {slug}__{tool} is a tool
	// identity; a prompt name is not one. If the grammar reached the key's
	// lists, a denylist entry that works on the key's other endpoints would be
	// inert on the member endpoint, the one shape of failure that looks like
	// success.
	member := newToolPolicy(nil, &models.VirtualKey{ToolDenylist: []string{"secret_prompt"}}, modeCompose, "gh").keyListsOnly()
	if member.mode != modeLiteral {
		t.Errorf("mode=%v want modeLiteral", member.mode)
	}
	if by := member.blockedBy("secret_prompt"); by != reasonKeyDenylist {
		t.Errorf("blockedBy=%q want %q; a prompt is judged by its own name on every path", by, reasonKeyDenylist)
	}

	// And the entry is matched whole, separator and all: an upstream may
	// advertise a prompt actually called "docs__search", and an operator has to
	// be able to deny it without the string being read as a slug and a name.
	literal := newToolPolicy(nil, &models.VirtualKey{ToolDenylist: []string{"docs__search"}}, modeParse, "").keyListsOnly()
	if by := literal.blockedBy("docs__search"); by != reasonKeyDenylist {
		t.Errorf("blockedBy=%q want %q for the prompt named docs__search", by, reasonKeyDenylist)
	}
	if !literal.permits("search") {
		t.Error(`the entry "docs__search" reached a prompt called "search"`)
	}
}
