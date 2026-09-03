package models

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	// MaxSlugLen is the longest a slug may be, in bytes. A slug is pure ASCII
	// after derivation, so bytes and characters agree.
	MaxSlugLen = 40
	// FallbackSlug is used when a name slugifies to nothing at all ("日本語").
	FallbackSlug = "up"
	// MaxSlugAttempts bounds the candidate walk on the create path, where a user
	// is present and can supply a slug explicitly.
	MaxSlugAttempts = 50
)

var nonSlugRun = regexp.MustCompile(`[^a-z0-9]+`)

var (
	// Starts and ends alphanumeric, 1 to 40 chars, "_" and "-" allowed
	// inside.
	slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,38}[a-z0-9])?$`)
	// A run of two separators would be ambiguous next to the "{slug}__{tool}"
	// tool identity. Forbidding it is the precondition for the split back to
	// (slug, name) being exact: it is what puts the first "__" of a composed
	// name at the join and nowhere earlier. See ParseCanonical.
	slugSepRun = regexp.MustCompile(`[_-]{2,}`)
	// A UUID is a strict subset of this charset. Upstream ids are UUIDs, so a
	// UUID-shaped slug would let upstream B shadow upstream A by identifier the
	// moment any lookup falls back between GetUpstream and GetUpstreamBySlug.
	uuidLike = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	reservedSlugs = map[string]bool{"mcp": true, "api": true, "health": true, "metrics": true}
)

// DeriveSlug turns a display name into a default slug: lowercased, every run of
// non-alphanumerics collapsed to a single "_", trimmed, truncated to MaxSlugLen.
// Names that slugify to nothing fall back to FallbackSlug.
func DeriveSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = nonSlugRun.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > MaxSlugLen {
		s = strings.TrimRight(s[:MaxSlugLen], "_-")
	}
	if s == "" {
		s = FallbackSlug
	}
	return s
}

// NormalizeSlug is what a user-supplied slug is compared and stored as.
func NormalizeSlug(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidSlug reports whether s is syntactically usable in a URL path segment and
// in a tool identity ("{slug}__{tool}"). It says nothing about availability.
//
// This is load-bearing for STORED data, not only for input: migrateUpstreamSlugs
// validates the slugs it finds already in the database and refuses to start if
// one fails, and the tool identity migration re-validates them with this same
// rule before it rewrites a single rule entry, a stored slug carrying a
// separator run would make every composed name on that member ambiguous, and an
// entry rewritten against it would name the wrong tool. Tightening this rule in
// a later release would therefore turn previously-valid stored slugs into a
// startup refusal, treat any narrowing as an upgrade-breaking change needing its
// own migration. (Widening is safe, and the reserved list is deliberately
// decoupled, see ReservedSlug.)
func ValidSlug(s string) bool {
	return slugPattern.MatchString(s) && !slugSepRun.MatchString(s) && !uuidLike.MatchString(s)
}

// ReservedSlug reports whether s is a word PoryMCP keeps for its own routes.
// Kept separate from ValidSlug so growing this list can never retroactively fail
// an existing stored row, and so the derivation walk can skip reserved
// candidates without invoking syntax rules.
func ReservedSlug(s string) bool { return reservedSlugs[s] }

// SlugWithSuffix returns base with a "-N" de-duplication suffix, trimming base
// so the whole slug still fits MaxSlugLen.
func SlugWithSuffix(base string, n int) string {
	suffix := "-" + strconv.Itoa(n)
	if MaxSlugLen-len(suffix) < 1 {
		// Only reachable for n with 39+ digits (n >= 1e38). Its job is to stop
		// the negative slice index below from panicking; the value it returns is
		// deliberately NOT itself ValidSlug, so do not mistake this for a live
		// fallback path.
		return FallbackSlug + suffix
	}
	if len(base)+len(suffix) > MaxSlugLen {
		base = strings.TrimRight(base[:MaxSlugLen-len(suffix)], "_-")
	}
	if base == "" {
		base = FallbackSlug
	}
	return base + suffix
}

// SlugCandidatesN returns the first n default slugs for a name, in order: the
// derived slug, then base-2, base-3, … Reserved words are skipped, so an
// upstream named "MCP" gets mcp-2.
//
// The sequence is TOTAL, which migrateUpstreamSlugs depends on:
//   - SlugWithSuffix is injective in n. A derived base contains no "-", so the
//     result is base + "-" + decimal(n) and the text after the single "-"
//     determines n.
//   - At most ONE candidate is ever skipped as reserved, because every candidate
//     for k > 1 ends in "-<digits>" and no reserved word matches -[0-9]+$.
//     TestReservedSlug pins that precondition: adding a reserved word of the form
//     "base-2" would break totality, not merely narrow the namespace.
//
// Therefore SlugCandidatesN(name, len(taken)+2) always contains a free slug.
func SlugCandidatesN(name string, n int) []string {
	base := DeriveSlug(name)
	out := make([]string, 0, n)
	for k := 1; k <= n; k++ {
		c := base
		if k > 1 {
			c = SlugWithSuffix(base, k)
		}
		if ReservedSlug(c) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// SlugCandidates is the bounded walk used on the create path.
func SlugCandidates(name string) []string { return SlugCandidatesN(name, MaxSlugAttempts) }
