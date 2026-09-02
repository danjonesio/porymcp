package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateToolFilter(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		// want is a substring of the expected error message; "" means the
		// filter is valid. For an invalid filter it names the offending field,
		// so a rewritten message that stops telling the operator *what* is
		// wrong fails the test.
		want string
	}{
		// Valid: no filter at all.
		{"nil", "", ""},
		{"whitespace only", "   ", ""},
		{"null", "null", ""},
		{"null padded", "  null\n", ""},
		{"empty object", "{}", ""},

		// Valid: enforceable filters.
		{"deny tools", `{"mode":"deny","tools":["delete_repo"]}`, ""},
		{"allow prefixes", `{"mode":"allow","prefixes":["gh_"]}`, ""},
		{"allow tools and prefixes", `{"mode":"allow","tools":["a"],"prefixes":["b_"]}`, ""},
		// A deny that lists nothing denies nothing. That is honest about being
		// a no-op, unlike an allow that lists nothing, so it is accepted.
		{"deny with nothing listed", `{"mode":"deny"}`, ""},
		// Go matches JSON field names case-insensitively and PoryMCP does not
		// change that. Only the mode's *value* is byte-exact, because only the
		// value is compared byte-exactly by the proxy.
		{"capitalised field name", `{"Mode":"deny","tools":["x"]}`, ""},

		// Invalid: a mode the proxy would never match, i.e. no filter at all.
		{"capitalised mode", `{"mode":"Deny","tools":["x"]}`, "mode"},
		{"upper-case mode", `{"mode":"DENY","tools":["x"]}`, "mode"},
		{"mode with trailing space", `{"mode":"deny ","tools":["x"]}`, "mode"},
		{"unknown mode", `{"mode":"block","tools":["x"]}`, "mode"},
		{"mode is not a string", `{"mode":123}`, "mode"},

		// Invalid: a key the decoder would otherwise drop on the floor.
		{"misspelt tools key", `{"mode":"deny","tool":["x"]}`, `unknown field "tool"`},
		{"unknown key", `{"mode":"deny","tools":["x"],"except":["y"]}`, `unknown field "except"`},
		{"tools is not an array", `{"mode":"deny","tools":"x"}`, "tools"},

		// Invalid: entries with no mode to apply them.
		{"tools without mode", `{"tools":["x"]}`, "mode is required"},
		{"prefixes without mode", `{"prefixes":["x_"]}`, "mode is required"},

		// Invalid: an allowlist of nothing permits everything.
		{"allow with nothing", `{"mode":"allow"}`, "allow"},
		{"allow with empty lists", `{"mode":"allow","tools":[],"prefixes":[]}`, "allow"},

		// Invalid: entries that cannot mean what they look like.
		{"empty tool entry", `{"mode":"deny","tools":[""]}`, "tools[0]"},
		{"empty prefix entry", `{"mode":"deny","prefixes":[""]}`, "prefixes[0]"},
		{"empty entry after a good one", `{"mode":"allow","tools":["a",""]}`, "tools[1]"},
		{"tool entry with a space", `{"mode":"deny","tools":["a b"]}`, "tools[0]"},
		{"tool entry with a trailing space", `{"mode":"deny","tools":["delete_repo "]}`, "tools[0]"},
		{"prefix entry with a control character", `{"mode":"deny","prefixes":["a\u0007"]}`, "prefixes[0]"},
		{"tool entry with a lone surrogate", `{"mode":"deny","tools":["a\ud800b"]}`, "tools[0]"},

		// Invalid: not an object, or more than one value.
		{"json string", `"nonsense"`, "JSON object"},
		{"json array", `[]`, "JSON object"},
		{"json array of filters", `[{"mode":"deny"}]`, "JSON object"},
		{"json number", `7`, "JSON object"},
		{"bare word", `nonsense`, "JSON object"},
		{"trailing object", `{"mode":"deny"} {"x":1}`, "trailing data"},
		{"trailing garbage", `{"mode":"deny"} nonsense`, "trailing data"},
		{"truncated object", `{"mode":"deny"`, "not valid JSON"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateToolFilter(json.RawMessage(c.raw))
			if c.want == "" {
				if err != nil {
					t.Fatalf("ValidateToolFilter(%s) = %v, want nil", c.raw, err)
				}
				// Anything this function accepts must be something the proxy's
				// byte-exact comparison can actually act on.
				assertEnforceableMode(t, c.raw)
				return
			}
			if err == nil {
				t.Fatalf("ValidateToolFilter(%s) = nil, want an error mentioning %q", c.raw, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ValidateToolFilter(%s) = %q, want it to mention %q", c.raw, err, c.want)
			}
		})
	}
}

// assertEnforceableMode pins the contract ValidateToolFilter exists to keep:
// every accepted filter decodes to a mode proxy.toolPolicy.blockedBy compares
// equal to, or to no mode at all (no filter). The proxy package cannot be
// imported here — it depends on models — so the invariant is asserted against
// the same literals blockedBy uses.
func assertEnforceableMode(t *testing.T, raw string) {
	t.Helper()
	var tf ToolFilter
	if err := json.Unmarshal([]byte(raw), &tf); err != nil {
		return // empty, whitespace or null: no filter to decode
	}
	switch tf.Mode {
	case "", "allow", "deny":
	default:
		t.Errorf("ValidateToolFilter accepted %s, which decodes to mode %q that the proxy never matches", raw, tf.Mode)
	}
}

func TestValidateToolFilterWrite(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		// want is a substring of the expected error; "" means the filter is
		// accepted on the way in.
		want string
	}{
		// Valid: no filter at all is still no filter.
		{"nil", "", ""},
		{"null", "null", ""},
		{"empty object", "{}", ""},
		{"deny with nothing listed", `{"mode":"deny"}`, ""},

		// Valid: a deny rule may name a tool either way. An unscoped entry is
		// the tool's own name on every member, which is a rule an operator can
		// mean, so it stays legal — only allow rules have to name a member.
		{"bare deny tools", `{"mode":"deny","tools":["delete_repo"]}`, ""},
		{"scoped deny tools", `{"mode":"deny","tools":["gh__delete_repo"]}`, ""},
		{"deny a name that leads with the separator", `{"mode":"deny","tools":["__x"]}`, ""},
		{"deny a scoped name holding the separator", `{"mode":"deny","tools":["github__mcp__fetch"]}`, ""},
		{"deny prefixes are free-form", `{"mode":"deny","prefixes":["delete_"]}`, ""},
		{"deny prefixes may end at the separator", `{"mode":"deny","prefixes":["docs__"]}`, ""},

		// Valid: an allow rule that names its member.
		{"scoped allow tools", `{"mode":"allow","tools":["gh__delete_repo"]}`, ""},
		{"scoped allow prefixes", `{"mode":"allow","prefixes":["docs__read_"]}`, ""},
		{"scoped allow prefixes ending at the separator", `{"mode":"allow","prefixes":["docs__"]}`, ""},
		{"scoped allow of a name holding the separator", `{"mode":"allow","tools":["github__mcp__fetch"]}`, ""},

		// Invalid: an allow rule on a group that names no member admits
		// nothing, so the key or group would be silently dead.
		{"unscoped allow tools", `{"mode":"allow","tools":["delete_repo"]}`, "must name a member"},
		{"unscoped allow prefixes", `{"mode":"allow","prefixes":["delete_"]}`, "must name a member"},
		{"allow entry leading with the separator", `{"mode":"allow","tools":["__x"]}`, "must name a member"},
		{"the offending allow entry is named", `{"mode":"allow","tools":["gh__a","b"]}`, "tools[1]"},
		{"an unscoped allow prefix is named", `{"mode":"allow","prefixes":["gh__a","b"]}`, "prefixes[1]"},

		// Invalid: a head that can never equal a member's slug. The entry would
		// sit in the filter matching nothing at all.
		{"head is not lower case", `{"mode":"deny","tools":["BadSlug__x"]}`, "must be an upstream slug"},
		{"head holds a separator run", `{"mode":"deny","tools":["a--b__x"]}`, "must be an upstream slug"},
		{"head is UUID-shaped", `{"mode":"deny","tools":["550e8400-e29b-41d4-a716-446655440000__x"]}`, "must be an upstream slug"},
		{"prefixes head is not a slug", `{"mode":"deny","prefixes":["Bad__"]}`, "must be an upstream slug"},
		// The whitespace check comes first, so this one never reaches the slug
		// rule — it is still rejected, and still names the entry.
		{"head with a space", `{"mode":"deny","tools":["Bad Slug__x"]}`, "tools[0]"},

		// Invalid: a tools entry is compared for equality, so one ending at the
		// separator names a tool with no name.
		{"tools entry ending at the separator", `{"mode":"deny","tools":["alpha__"]}`, "names no tool"},
		{"allow tools entry ending at the separator", `{"mode":"allow","tools":["alpha__"]}`, "names no tool"},

		// Invalid: everything the read side rejects, this rejects too.
		{"capitalised mode", `{"mode":"Deny","tools":["x"]}`, "mode"},
		{"misspelt tools key", `{"mode":"deny","tool":["x"]}`, `unknown field "tool"`},
		{"allow with nothing", `{"mode":"allow"}`, "allow"},
		{"empty entry", `{"mode":"deny","tools":[""]}`, "tools[0]"},
		{"entry with a trailing space", `{"mode":"deny","tools":["delete_repo "]}`, "tools[0]"},
		{"json array", `[]`, "JSON object"},
		{"trailing object", `{"mode":"deny"} {"x":1}`, "trailing data"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateToolFilterWrite(json.RawMessage(c.raw))
			if c.want == "" {
				if err != nil {
					t.Fatalf("ValidateToolFilterWrite(%s) = %v, want nil", c.raw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateToolFilterWrite(%s) = nil, want an error mentioning %q", c.raw, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ValidateToolFilterWrite(%s) = %q, want it to mention %q", c.raw, err, c.want)
			}
		})
	}

	// The message has to carry the spelling that works, not just the rule: an
	// operator who wrote a bare name needs to see the scoped one.
	err := ValidateToolFilterWrite(json.RawMessage(`{"mode":"allow","tools":["delete_repo"]}`))
	if err == nil || !strings.Contains(err.Error(), "github__delete_repo") {
		t.Errorf("unscoped allow error = %v, want an example spelling the entry as github__delete_repo", err)
	}
}

// TestWriteRulesStayOffTheReadSide pins the reason there are two validators.
// The proxy blocks every tool on a group whose filter fails to validate, so a
// rule that only ValidateToolFilterWrite enforces must never reach
// ValidateToolFilter: a filter stored before the identity grammar existed has
// to keep being enforceable until the migration rewrites it.
func TestWriteRulesStayOffTheReadSide(t *testing.T) {
	for _, raw := range []string{
		`{"mode":"allow","tools":["delete_repo"]}`, // unscoped allow entry
		`{"mode":"deny","tools":["BadSlug__x"]}`,   // head that is not a slug
		`{"mode":"deny","tools":["alpha__"]}`,      // scoped entry naming no tool
	} {
		if err := ValidateToolFilterWrite(json.RawMessage(raw)); err == nil {
			t.Fatalf("ValidateToolFilterWrite(%s) = nil; this case is here because it is rejected", raw)
		}
		if err := ValidateToolFilter(json.RawMessage(raw)); err != nil {
			t.Errorf("ValidateToolFilter(%s) = %v; the read side must stay permissive or stored groups fail closed", raw, err)
		}
	}
}

func TestValidateToolList(t *testing.T) {
	cases := []struct {
		name        string
		field       string
		entries     []string
		groupTarget bool
		want        string
	}{
		// Valid: nothing listed is no rule.
		{"nil allowlist", FieldToolAllowlist, nil, true, ""},
		{"nil denylist", FieldToolDenylist, nil, false, ""},
		{"empty allowlist", FieldToolAllowlist, []string{}, true, ""},

		// Valid: a denylist may name a tool either way, on either target.
		{"bare denylist on a group", FieldToolDenylist, []string{"delete_repo"}, true, ""},
		{"bare denylist on an upstream", FieldToolDenylist, []string{"delete_repo"}, false, ""},
		{"scoped denylist on a group", FieldToolDenylist, []string{"gh__delete_repo"}, true, ""},
		{"scoped denylist on an upstream", FieldToolDenylist, []string{"gh__delete_repo"}, false, ""},
		{"denylist name holding the separator", FieldToolDenylist, []string{"mcp__fetch", "__x"}, false, ""},

		// Valid: an allowlist that names its member, or one on a single
		// upstream where every tool is that upstream's anyway.
		{"scoped allowlist on a group", FieldToolAllowlist, []string{"gh__read", "docs__search"}, true, ""},
		{"bare allowlist on an upstream", FieldToolAllowlist, []string{"read"}, false, ""},
		{"scoped allowlist on an upstream", FieldToolAllowlist, []string{"gh__read"}, false, ""},

		// Invalid: an allow rule on a group that names no member admits
		// nothing, so the key would be silently dead.
		{"bare allowlist on a group", FieldToolAllowlist, []string{"read"}, true, "must name a member"},
		{"allowlist entry leading with the separator", FieldToolAllowlist, []string{"__x"}, true, "must name a member"},
		{"the offending allowlist entry is named", FieldToolAllowlist, []string{"gh__read", "search"}, true, "tool_allowlist[1]"},

		// Invalid: entries that can never equal a name the proxy sees. The
		// field and the index reach the operator in every one.
		{"empty entry", FieldToolDenylist, []string{""}, false, "tool_denylist[0] is empty"},
		{"whitespace", FieldToolDenylist, []string{"a b"}, false, "tool_denylist[0]"},
		{"trailing space", FieldToolAllowlist, []string{"gh__read "}, false, "tool_allowlist[0]"},
		{"control character", FieldToolDenylist, []string{"a\x07"}, false, "tool_denylist[0]"},
		// What a client's invalid UTF-8 or lone surrogate became when the API
		// decoded the key's JSON body; it can never equal the name that client
		// sends on a call.
		{"replacement rune", FieldToolDenylist, []string{"a\uFFFDb"}, false, "not valid UTF-8"},
		{"the offending denylist entry is named", FieldToolDenylist, []string{"ok", "bad entry"}, false, "tool_denylist[1]"},

		// Invalid: the {slug}__{tool} shape rules, on both fields and both
		// targets — a list is compared for equality wherever it is used.
		{"head is not a slug", FieldToolDenylist, []string{"BadSlug__x"}, false, "must be an upstream slug"},
		{"head holds a separator run", FieldToolAllowlist, []string{"a--b__x"}, true, "must be an upstream slug"},
		{"entry ending at the separator", FieldToolDenylist, []string{"docs__"}, false, "names no tool"},
		{"allowlist entry ending at the separator", FieldToolAllowlist, []string{"docs__"}, true, "names no tool"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateToolList(c.field, c.entries, c.groupTarget)
			if c.want == "" {
				if err != nil {
					t.Fatalf("ValidateToolList(%s, %q, group=%v) = %v, want nil", c.field, c.entries, c.groupTarget, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateToolList(%s, %q, group=%v) = nil, want an error mentioning %q", c.field, c.entries, c.groupTarget, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ValidateToolList(%s, %q, group=%v) = %q, want it to mention %q", c.field, c.entries, c.groupTarget, err, c.want)
			}
		})
	}

	// The "must name a member" rule keys off the exact field name, which is
	// why the two are constants. A caller that spells the allow side something
	// else still gets the text and shape checks — it just does not get this
	// rule, and would be widening a group key without noticing.
	if err := ValidateToolList("allowlist", []string{"read"}, true); err != nil {
		t.Errorf("ValidateToolList with an unrecognised field = %v, want the shape checks only", err)
	}
	if err := ValidateToolList("allowlist", []string{"a b"}, true); err == nil {
		t.Error("ValidateToolList with an unrecognised field skipped the text checks")
	}
}

// TestCleanToolEntryIsTheValidatorsVerdict pins what sharing the rule bought.
// CleanToolEntry and validateEntryText were separate code stating the same
// rules in two places, one for the store's migration and one for the management
// API, and a tightening of either would have left the two holding different
// opinions about which stored entries are clean: exactly the drift SplitEntry
// was centralised to prevent. They now answer as one, and this says so for the
// shapes that separate them, in both directions — an entry is clean exactly
// when no error names it, and the corpus below pins which entries those are.
func TestCleanToolEntryIsTheValidatorsVerdict(t *testing.T) {
	for _, tc := range []struct {
		clean   bool
		entries []string
	}{
		// The text rule has no opinion about shape, so a scoped entry, one
		// ending at the separator, one leading with it and one whose head no
		// upstream can hold are all clean: what they MEAN differs by list, and
		// that is validateEntries' question rather than this one.
		{true, []string{"delete_repo", "gh__delete_repo", "docs__", "__lead", "mcp__fetch"}},
		// One per rule: empty, an interior space, the trailing space that turns
		// a deny into a no-op, a leading tab, two control characters, and the
		// rune Go's JSON decoder substitutes for bytes that were not UTF-8.
		{false, []string{"", "delete repo", "delete_repo ", "\tlead", "a\x07b", "a\x00b", "a\uFFFDb"}},
		// Three models.UsableToolName allows and this does not, which
		// is why a tool named with one can be advertised and called but never
		// denied by name.
		{false, []string{"a\u00A0b", "a\u2028b", "a\u0085b"}},
	} {
		for _, e := range tc.entries {
			if got := CleanToolEntry(e); got != tc.clean {
				t.Errorf("CleanToolEntry(%q) = %v, want %v", e, got, tc.clean)
			}
			if err := validateEntryText(FieldToolDenylist, 0, e); (err == nil) != tc.clean {
				t.Errorf("validateEntryText(%q) = %v, but CleanToolEntry calls it clean=%v", e, err, tc.clean)
			}
		}
	}
}
