package models

import (
	"strings"
	"testing"
)

// slugCorpus is the valid list from TestValidSlug: the shapes a stored slug can
// actually take, including one holding a single "_", one holding a "-" and one
// at MaxSlugLen. The round trip below is a property of ValidSlug rather than of
// any one slug, so it is worth crossing the whole corpus.
var slugCorpus = []string{
	"a", "ab", "github", "github_enterprise", "github-2", "a1_b-2",
	strings.Repeat("a", 40),
	"550e8400-e29b-41d4-a716-44665544000",
}

// toolNameCorpus is the awkward half. A tool name is opaque — MCP constrains
// nothing about it — so the interesting names are the ones that hold the
// separator themselves or lead with an underscore, which is exactly where a
// split at the last separator, or a trim, would recover the wrong pair.
var toolNameCorpus = []string{
	"create_issue",
	"search",
	"_search",           // "alpha" + "_search" composes to "alpha___search"
	"a__b",              // the separator inside the name
	"mcp__server__tool", // an upstream that is itself a proxy
	"__x",               // a name that is a separator plus a letter
	strings.Repeat("n", 200),
}

func TestSplitToolIDRoundTrips(t *testing.T) {
	seen := make(map[string]ToolIdentity)
	for _, slug := range slugCorpus {
		for _, name := range toolNameCorpus {
			id := ToolIdentity{Slug: slug, Name: name}
			c := id.Canonical()

			got, ok := ParseCanonical(c)
			if !ok {
				t.Fatalf("ParseCanonical(%q) = _, false; want %+v back", c, id)
			}
			if got != id {
				t.Errorf("ParseCanonical(%q) = %+v, want %+v", c, got, id)
			}
			// A name the proxy composes must survive the aggregate endpoint's
			// syntactic gate, or it could list a tool it would then refuse.
			if !ValidToolIdentity(c) {
				t.Errorf("ValidToolIdentity(%q) = false for a composed name", c)
			}
			// Injectivity, stated as the property that matters: no two
			// identities share a canonical string. Were that false the merged
			// catalogue would drop one of the two tools and route its calls to
			// the other member's credential.
			if prev, dup := seen[c]; dup {
				t.Fatalf("%q is the canonical form of both %+v and %+v", c, prev, id)
			}
			seen[c] = id
		}
	}
}

func TestParseCanonicalRejects(t *testing.T) {
	// Nothing here can name a tool on a member: there is no separator, nothing
	// before it, or nothing after it.
	for _, s := range []string{"", "search", "__search", "alpha__", "____", "__", "_"} {
		if id, ok := ParseCanonical(s); ok {
			t.Errorf("ParseCanonical(%q) = %+v, true; want false", s, id)
		}
	}
}

func TestValidToolIdentity(t *testing.T) {
	valid := []string{
		"alpha__search",
		"a__b",
		"github_enterprise__create_issue",
		"a1_b-2__x",
		"alpha___search", // the tool's own name is "_search"
		"gh__a__b",       // the tool's own name holds the separator
		// Syntax is not membership. This is true because "mcp" is a
		// well-formed slug, not because any upstream has it — no upstream may,
		// since "mcp" is reserved. The check reads no store on purpose, so a
		// caller cannot use it to learn which slugs a group holds.
		"mcp__server__tool",
		"stranger__whatever",
	}
	for _, s := range valid {
		if !ValidToolIdentity(s) {
			t.Errorf("ValidToolIdentity(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"search",   // no separator at all
		"alpha__",  // names no tool
		"__x",      // names no member
		"Alpha__x", // slugs are lower case
		"a--b__x",  // a separator run is not a slug
		"_gh__x",   // slugs start alphanumeric
		"gh enterprise__x",
		"550e8400-e29b-41d4-a716-446655440000__x", // UUID-shaped head
		strings.Repeat("a", 41) + "__x",           // over MaxSlugLen
	}
	for _, s := range invalid {
		if ValidToolIdentity(s) {
			t.Errorf("ValidToolIdentity(%q) = true, want false", s)
		}
	}
}

func TestSplitEntry(t *testing.T) {
	cases := []struct {
		entry      string
		head, rest string
		scoped     bool
	}{
		{"search", "", "search", false},
		// Unscoped: there is nothing before the separator, so this is not a
		// member's name but a tool whose own name begins with it. rest is the
		// whole entry, so a caller can match rest either way.
		{"__search", "", "__search", false},
		{"", "", "", false},
		{"docs__search", "docs", "search", true},
		// Scoped with an empty rest: every tool on docs, when matched as a
		// prefixes entry. Writes reject it anywhere it would be compared for
		// equality instead.
		{"docs__", "docs", "", true},
		{"docs__mcp__fetch", "docs", "mcp__fetch", true},
		{"docs___search", "docs", "_search", true},
		// Classification is shape only. Whether the head could be a real slug
		// is validateEntries' question, not this one's.
		{"Bad__x", "Bad", "x", true},
	}
	for _, c := range cases {
		head, rest, scoped := SplitEntry(c.entry)
		if head != c.head || rest != c.rest || scoped != c.scoped {
			t.Errorf("SplitEntry(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.entry, head, rest, scoped, c.head, c.rest, c.scoped)
		}
	}
}

func TestMatchToolEntry(t *testing.T) {
	docsSearch := ToolIdentity{Slug: "docs", Name: "search"}
	ghSearch := ToolIdentity{Slug: "gh", Name: "search"}
	docsSearchAll := ToolIdentity{Slug: "docs", Name: "search_all"}

	cases := []struct {
		name   string
		entry  string
		id     ToolIdentity
		prefix bool
		want   bool
	}{
		{"scoped hit", "docs__search", docsSearch, false, true},
		{"scoped miss on the member", "docs__search", ghSearch, false, false},
		{"scoped miss on the name", "docs__search", docsSearchAll, false, false},
		{"scoped prefix hits its member", "docs__search", docsSearchAll, true, true},
		{"scoped prefix stops at its member", "docs__search", ghSearch, true, false},
		// A scoped entry with an empty rest is every tool on that member, and
		// only as a prefixes entry: as an exact match it names a tool called "".
		{"scoped empty rest as a prefix", "docs__", docsSearchAll, true, true},
		{"scoped empty rest exactly", "docs__", docsSearch, false, false},
		{"scoped empty rest stops at its member", "docs__", ghSearch, true, false},

		// An unscoped entry is the tool's own name on every member, which is
		// what lets one entry cover the aggregate endpoint and each member
		// endpoint at once.
		{"unscoped hit on one member", "search", docsSearch, false, true},
		{"unscoped hit on another", "search", ghSearch, false, true},
		{"unscoped miss", "search", docsSearchAll, false, false},
		{"unscoped prefix", "search", docsSearchAll, true, true},
		{"unscoped name holding the separator", "__x", ToolIdentity{"docs", "__x"}, false, true},
		{"scoped name holding the separator", "gh__mcp__fetch", ToolIdentity{"gh", "mcp__fetch"}, false, true},

		// A ToolIdentity with no slug — the zero value, or a policy that never
		// learned which member it stands on — can satisfy no scoped entry.
		{"identity with no slug misses a scoped entry", "docs__search", ToolIdentity{"", "search"}, false, false},
		{"identity with no slug misses a scoped prefix", "docs__", ToolIdentity{"", "search"}, true, false},
		{"identity with no slug still matches unscoped", "search", ToolIdentity{"", "search"}, false, true},

		// An empty entry is rejected on write, but one stored before that check
		// existed must stay the no-op it has always been rather than become a
		// prefix matching every tool.
		{"empty entry as a prefix", "", docsSearch, true, false},
		{"empty entry exactly", "", docsSearch, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MatchToolEntry(c.entry, c.id, c.prefix); got != c.want {
				t.Errorf("MatchToolEntry(%q, %+v, prefix=%v) = %v, want %v",
					c.entry, c.id, c.prefix, got, c.want)
			}
		})
	}
}
