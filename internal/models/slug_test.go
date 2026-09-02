package models

import (
	"regexp"
	"strings"
	"testing"
)

func TestDeriveSlug(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"GitHub Enterprise", "github_enterprise"},
		{"GitHub", "github"},
		{"github", "github"},
		{"  GitHub  ", "github"},
		{"GitHub (prod)", "github_prod"},
		{"a---b", "a_b"},
		{"", "up"},
		{"   ", "up"},
		{"日本語", "up"},
		{"!!!", "up"},
		{"Größe", "gr_e"},
		{strings.Repeat("a", 60), strings.Repeat("a", 40)},
		{"550e8400-e29b-41d4-a716-446655440000", "550e8400_e29b_41d4_a716_446655440000"},
	}
	for _, c := range cases {
		if got := DeriveSlug(c.name); got != c.want {
			t.Errorf("DeriveSlug(%q) = %q, want %q", c.name, got, c.want)
		}
	}

	// Truncation must not leave a trailing separator.
	spaced := DeriveSlug(strings.Repeat("ab ", 20))
	if len(spaced) != MaxSlugLen {
		t.Errorf("DeriveSlug(%q) length = %d, want %d", "ab ×20", len(spaced), MaxSlugLen)
	}
	if last := spaced[len(spaced)-1]; last == '_' || last == '-' {
		t.Errorf("DeriveSlug(%q) = %q ends in a separator", "ab ×20", spaced)
	}

	// Property: every derived slug is valid, fits, and is never UUID-shaped.
	names := []string{"", "   ", "!!!", "日本語", "Größe", "GitHub Enterprise", "a---b",
		strings.Repeat("a", 60), strings.Repeat("ab ", 20),
		"550e8400-e29b-41d4-a716-446655440000", "MCP", "Health"}
	for _, n := range names {
		got := DeriveSlug(n)
		if !ValidSlug(got) {
			t.Errorf("DeriveSlug(%q) = %q is not ValidSlug", n, got)
		}
		if len(got) > MaxSlugLen {
			t.Errorf("DeriveSlug(%q) = %q is %d bytes, over MaxSlugLen", n, got, len(got))
		}
		if uuidLike.MatchString(got) {
			t.Errorf("DeriveSlug(%q) = %q is UUID-shaped", n, got)
		}
	}
}

func TestValidSlug(t *testing.T) {
	valid := []string{
		"a", "ab", "github", "github_enterprise", "github-2", "a1_b-2",
		strings.Repeat("a", 40),
		// 35 hex in the last group: the rejection is the exact UUID shape, not
		// "anything with dashes".
		"550e8400-e29b-41d4-a716-44665544000",
	}
	for _, s := range valid {
		if !ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"", "A", "Bad Slug!", "a b", "_x", "x_", "-x", "x-",
		"a__b", "a--b", "a-_b", "a_-b",
		"a/b", "a.b", "a%20b", "..", "../etc",
		strings.Repeat("a", 41),
		"gіthub",     // Cyrillic і (U+0456) — [a-z0-9] is the ASCII range over runes
		"ｇithub",     // fullwidth ｇ
		"git\x00hub", // NUL
		"github\n",   // RE2 "$" is end-of-TEXT, not end-of-line
		"550e8400-e29b-41d4-a716-446655440000",
		"a4f1c2de-0000-4000-8000-000000000000",
	}
	for _, s := range invalid {
		if ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = true, want false", s)
		}
	}

	// The newline case above is a unit-level assertion about ValidSlug only:
	// NormalizeSlug trims, so the API accepts a body of "github\n" as a 201.
	if got := NormalizeSlug("github\n"); got != "github" {
		t.Errorf("NormalizeSlug(%q) = %q, want %q", "github\n", got, "github")
	}
	if got := NormalizeSlug("  GitHub_Enterprise  "); got != "github_enterprise" {
		t.Errorf("NormalizeSlug case/trim = %q", got)
	}
}

func TestReservedSlug(t *testing.T) {
	for _, s := range []string{"mcp", "api", "health", "metrics"} {
		if !ReservedSlug(s) {
			t.Errorf("ReservedSlug(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"github", "mcp2", "my_mcp"} {
		if ReservedSlug(s) {
			t.Errorf("ReservedSlug(%q) = true, want false", s)
		}
	}

	// SlugCandidatesN is total only because at most ONE candidate per name is
	// skipped as reserved: every candidate after the first ends in "-<digits>".
	// Reserving a word of that shape (e.g. "mcp-2") would break the migration
	// walk, not merely narrow the namespace.
	suffixed := regexp.MustCompile(`-[0-9]+$`)
	for word := range reservedSlugs {
		if suffixed.MatchString(word) {
			t.Fatalf("reserved word %q ends in -<digits>; see models.SlugCandidatesN", word)
		}
	}
}

func TestSlugWithSuffix(t *testing.T) {
	if got := SlugWithSuffix("github", 2); got != "github-2" {
		t.Errorf("SlugWithSuffix(github, 2) = %q", got)
	}
	long := strings.Repeat("a", 40)
	if want, got := strings.Repeat("a", 38)+"-2", SlugWithSuffix(long, 2); got != want {
		t.Errorf("SlugWithSuffix(40a, 2) = %q, want %q", got, want)
	}
	if got := SlugWithSuffix(long, 10); len(got) != MaxSlugLen || !strings.HasSuffix(got, "-10") {
		t.Errorf("SlugWithSuffix(40a, 10) = %q (len %d)", got, len(got))
	}
	// Truncation landing on a separator must be trimmed, not left as "foo_-2".
	sepAt38 := strings.Repeat("a", 37) + "_" + strings.Repeat("b", 5)
	if want, got := strings.Repeat("a", 37)+"-2", SlugWithSuffix(sepAt38, 2); got != want {
		t.Errorf("SlugWithSuffix(sep at cut, 2) = %q, want %q", got, want)
	}

	for _, base := range []string{"a", "github", long, sepAt38} {
		for _, n := range []int{2, 3, 10, 99, 100, 12345} {
			got := SlugWithSuffix(base, n)
			if !ValidSlug(got) {
				t.Errorf("SlugWithSuffix(%q, %d) = %q is not ValidSlug", base, n, got)
			}
			if len(got) > MaxSlugLen {
				t.Errorf("SlugWithSuffix(%q, %d) = %q is %d bytes", base, n, got, len(got))
			}
		}
	}
}

func TestSlugCandidatesTotal(t *testing.T) {
	// SlugWithSuffix is injective in n on a worst-case 40-char base: 299 distinct
	// results for n = 2…300, every one valid and within MaxSlugLen. The migration
	// widens its walk to len(taken)+2 and relies on this.
	base := strings.Repeat("a", 40)
	seen := map[string]bool{}
	for n := 2; n <= 300; n++ {
		s := SlugWithSuffix(base, n)
		if seen[s] {
			t.Fatalf("SlugWithSuffix(40a, %d) = %q collides", n, s)
		}
		seen[s] = true
	}
	if len(seen) != 299 {
		t.Fatalf("SlugWithSuffix over n=2..300 gave %d distinct, want 299", len(seen))
	}

	// The candidate list is the base plus those suffixes, all distinct.
	got := SlugCandidatesN(base, 300)
	if len(got) != 300 {
		t.Fatalf("SlugCandidatesN(40a, 300) length = %d, want 300", len(got))
	}
	uniq := map[string]bool{}
	for _, c := range got {
		if uniq[c] {
			t.Fatalf("SlugCandidatesN repeated %q", c)
		}
		uniq[c] = true
		if !ValidSlug(c) {
			t.Errorf("candidate %q is not ValidSlug", c)
		}
		if len(c) > MaxSlugLen {
			t.Errorf("candidate %q is %d bytes", c, len(c))
		}
	}

	// At most one candidate per name is skipped as reserved, and the sequence
	// grows by extension: SlugCandidatesN(name, k) prefixes SlugCandidatesN(name, k+1).
	for _, name := range []string{"GitHub", "MCP", "日本語", strings.Repeat("a", 60)} {
		for k := 1; k <= 12; k++ {
			cur := SlugCandidatesN(name, k)
			if len(cur) != k && len(cur) != k-1 {
				t.Fatalf("SlugCandidatesN(%q, %d) length = %d, want %d or %d", name, k, len(cur), k, k-1)
			}
			next := SlugCandidatesN(name, k+1)
			for i, c := range cur {
				if next[i] != c {
					t.Fatalf("SlugCandidatesN(%q, %d) is not a prefix of (…, %d) at %d: %q vs %q",
						name, k, k+1, i, c, next[i])
				}
			}
		}
	}
}

func TestSlugCandidates(t *testing.T) {
	got := SlugCandidates("GitHub Enterprise")
	want := []string{"github_enterprise", "github_enterprise-2", "github_enterprise-3"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("SlugCandidates(GitHub Enterprise)[%d] = %q, want %q", i, got[i], w)
		}
	}
	if len(got) != MaxSlugAttempts {
		t.Errorf("SlugCandidates length = %d, want %d", len(got), MaxSlugAttempts)
	}

	// A reserved derived base is skipped, costing exactly one candidate.
	mcp := SlugCandidates("MCP")
	if mcp[0] != "mcp-2" {
		t.Errorf("SlugCandidates(MCP)[0] = %q, want mcp-2", mcp[0])
	}
	if len(mcp) != MaxSlugAttempts-1 {
		t.Errorf("SlugCandidates(MCP) length = %d, want %d", len(mcp), MaxSlugAttempts-1)
	}

	for _, name := range []string{"GitHub Enterprise", "MCP", "日本語", ""} {
		a := SlugCandidates(name)
		b := SlugCandidatesN(name, MaxSlugAttempts)
		if len(a) != len(b) {
			t.Fatalf("SlugCandidates(%q) != SlugCandidatesN(%q, MaxSlugAttempts)", name, name)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("SlugCandidates(%q)[%d] = %q, SlugCandidatesN = %q", name, i, a[i], b[i])
			}
		}
		for _, c := range a {
			if !ValidSlug(c) {
				t.Errorf("SlugCandidates(%q) yielded invalid %q", name, c)
			}
			if ReservedSlug(c) {
				t.Errorf("SlugCandidates(%q) yielded reserved %q", name, c)
			}
		}
	}
}
