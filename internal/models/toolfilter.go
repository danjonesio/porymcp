package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// The two entry lists a virtual key carries. They are named here because
// ValidateToolList keys its allow-side rule off the exact string, so a caller
// that spells the field differently gets the text and shape checks but not the
// rule that an allow entry on a group must name a member.
const (
	FieldToolAllowlist = "tool_allowlist"
	FieldToolDenylist  = "tool_denylist"
)

// ValidateToolFilter reports whether raw is a tool_filter the proxy can
// enforce.
//
// The proxy matches a filter byte for byte: proxy.toolPolicy.blockedBy compares
// ToolFilter.Mode against the literals "allow" and "deny", and compares an entry
// against the tool's identity — the upstream's slug and the tool's own name —
// with no trimming, case folding or Unicode normalisation. Anything else decodes
// into a ToolFilter with no error at all and then matches nothing, which is
// indistinguishable from having no filter: {"mode":"Deny"}, {"mode":"deny "}
// with a trailing space and {"mode":"deny","tool":[...]} with the key misspelt
// are all silently permissive. While the filter was cosmetic that was
// invisible. PORM-19 makes it load-bearing, so the same typo becomes a silent
// authorization bypass.
//
// Both ends of a filter's life ask this one function the same question, so they
// cannot disagree about what is enforceable: the management API rejects a
// filter it could not enforce when a group is written, and the proxy fails
// closed — blocking every tool on the group — when a filter already in the
// database does not validate when it is read.
//
// The API asks ValidateToolFilterWrite, which is this plus the rules that only
// make sense against a filter a human is writing now. Everything this function
// rejects, that one rejects too.
//
// A missing, empty or null filter is valid and means "no filter". So does {},
// and so, deliberately, does {"mode":"deny"} with nothing listed: an operator
// who listed nothing to deny denied nothing. {"mode":"allow"} with nothing
// listed is rejected instead. It is just as permissive, but it is the exact
// opposite of what an operator writing "allow" meant.
func ValidateToolFilter(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil // no filter
	}
	if trimmed[0] != '{' {
		return errors.New(`tool_filter must be a JSON object, for example {"mode":"deny","tools":["delete_repo"]}`)
	}
	// json.Valid scans the whole input, so data after the object is rejected
	// here. The decoder below stops at the end of the first value and would
	// accept it.
	if !json.Valid(trimmed) {
		return errors.New("tool_filter is not valid JSON, or has trailing data after the object")
	}
	var tf ToolFilter
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	// Catches the misspelt key, which is otherwise dropped into a filter that
	// permits everything. Field matching stays case-insensitive, as it is
	// everywhere else in the API; only the mode's value is byte-exact, because
	// only its value is compared byte-exactly downstream.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return fmt.Errorf("tool_filter: %w", err)
	}
	switch tf.Mode {
	case "allow", "deny":
	case "":
		if len(tf.Tools) > 0 || len(tf.Prefixes) > 0 {
			return errors.New("tool_filter: mode is required when tools or prefixes are set")
		}
	default:
		return fmt.Errorf(`tool_filter: mode must be exactly "allow" or "deny", got %q`, tf.Mode)
	}
	if err := validateToolFilterEntries("tool_filter: tools", tf.Tools); err != nil {
		return err
	}
	if err := validateToolFilterEntries("tool_filter: prefixes", tf.Prefixes); err != nil {
		return err
	}
	if tf.Mode == "allow" && len(tf.Tools)+len(tf.Prefixes) == 0 {
		return errors.New(`tool_filter: mode "allow" needs at least one entry in tools or prefixes; an allowlist of nothing permits everything`)
	}
	return nil
}

// ValidateToolFilterWrite is ValidateToolFilter plus the rules that apply only
// when a filter is being written, not when the proxy reads one it already has.
//
// The two are separate because the read side fails closed. A rule added there
// would turn a filter already in the database into a group that blocks every
// tool — and would leave the store's migration with no valid filter to rewrite,
// since it refuses to marshal a filter the validator rejects. So new rules land
// here, where the operator is present, the entry can be quoted back, and the
// worst outcome is a 400.
//
// It adds three, all of them about the {slug}__{tool} identity:
//
//   - a scoped entry's head must be a syntactically valid slug, because nothing
//     else can ever equal a member's slug and the entry would otherwise sit in
//     the filter matching nothing at all;
//   - a scoped tools entry must name a tool after the separator, since tools
//     entries are matched for equality and only a prefixes entry says something
//     useful when it ends at the separator; and
//   - under mode "allow" every entry must be scoped — see requireScoped.
func ValidateToolFilterWrite(raw json.RawMessage) error {
	if err := ValidateToolFilter(raw); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil // no filter
	}
	var tf ToolFilter
	if err := json.Unmarshal(trimmed, &tf); err != nil {
		// Unreachable: ValidateToolFilter has already decoded these same bytes
		// with the stricter DisallowUnknownFields. Reported rather than
		// swallowed so that a future change to either function cannot quietly
		// skip the rules below.
		return fmt.Errorf("tool_filter: %w", err)
	}
	// A tools entry is matched for equality, so "docs__" would name no tool; a
	// prefixes entry is matched with HasPrefix, where the same empty rest is
	// the useful "every tool on docs".
	if err := validateEntries("tool_filter: tools", tf.Tools, false); err != nil {
		return err
	}
	if err := validateEntries("tool_filter: prefixes", tf.Prefixes, true); err != nil {
		return err
	}
	if tf.Mode == "allow" {
		if err := requireScoped("tool_filter: tools", tf.Tools); err != nil {
			return err
		}
		if err := requireScoped("tool_filter: prefixes", tf.Prefixes); err != nil {
			return err
		}
	}
	return nil
}

// ValidateToolList checks one of a virtual key's two entry lists. field is
// FieldToolAllowlist or FieldToolDenylist, and is named in every error along
// with the index, because a key may carry a long list and the operator needs to
// know which entry to fix.
//
// groupTarget says whether the key points at a group rather than at a single
// upstream. It matters only on the allow side: on a group an unscoped allow
// entry admits nothing whatsoever (requireScoped), while on a single upstream
// every tool belongs to that upstream and a bare tool name is exactly right.
func ValidateToolList(field string, entries []string, groupTarget bool) error {
	// Both lists are matched for equality, like tool_filter tools, so an entry
	// that ends at the separator names no tool on either side.
	if err := validateEntries(field, entries, false); err != nil {
		return err
	}
	if groupTarget && field == FieldToolAllowlist {
		return requireScoped(field, entries)
	}
	return nil
}

// validateToolFilterEntries is the read side's entry check: the text rules
// only, and deliberately not the {slug}__{tool} shape rules validateEntries
// adds. A filter written before the identity grammar existed can hold entries
// this accepts and ValidateToolFilterWrite would not — a head that is not a
// slug, say — and the proxy blocks every tool on a group whose filter fails to
// validate. Tightening this would take those groups offline rather than merely
// correct an operator: the store's migration rewrites such entries, and the
// management API refuses new ones.
func validateToolFilterEntries(field string, entries []string) error {
	for i, e := range entries {
		if err := validateEntryText(field, i, e); err != nil {
			return err
		}
	}
	return nil
}

// validateEntries is every check an entry must pass on the way in, for a
// group's filter and a virtual key's lists alike — one function, so the two
// cannot drift into accepting different things.
//
// allowEmptyRest is true only for tool_filter prefixes, the one list where a
// scoped entry ending at the separator means something: "docs__" is every tool
// on docs. Everywhere else entries are compared for equality, where it would
// name a tool with no name.
func validateEntries(field string, entries []string, allowEmptyRest bool) error {
	for i, e := range entries {
		if err := validateEntryText(field, i, e); err != nil {
			return err
		}
		head, rest, scoped := SplitEntry(e)
		if !scoped {
			// An unscoped entry is a bare tool name, matched on every member.
			// There is no shape to check: any name an upstream can advertise
			// is a legal entry, including one that starts with the separator.
			continue
		}
		if !ValidSlug(head) {
			return fmt.Errorf("%s[%d] %q: the text before %s must be an upstream slug", field, i, e, ToolSeparator)
		}
		if rest == "" && !allowEmptyRest {
			return fmt.Errorf("%s[%d] %q: nothing follows %s, so it names no tool", field, i, e, ToolSeparator)
		}
	}
	return nil
}

// requireScoped rejects the entries of an allow rule that name no member.
//
// On a group, an allow entry is a promise that one named thing is permitted,
// and an unscoped entry cannot keep it. The enforcement side skips it — reading
// it as "this tool name on every member" would widen the rule to the whole
// group, the opposite of what an operator narrowing access to one member's tool
// meant — so an allow rule holding nothing else admits nothing and the key or
// group is silently dead. Far better to say so while the operator is here, with
// the entry they sent and the spelling that works.
func requireScoped(field string, entries []string) error {
	for i, e := range entries {
		if _, _, scoped := SplitEntry(e); !scoped {
			return fmt.Errorf("%s[%d] %q: an allow rule on a group must name a member, for example github%s%s", field, i, e, ToolSeparator, e)
		}
	}
	return nil
}

// CleanToolEntry reports whether e could equal a tool name the proxy will ever
// see: not empty, and holding no whitespace, no control character and no
// U+FFFD, which Go's JSON decoder substitutes for bytes that were not valid
// UTF-8 while other clients keep the original.
//
// This is the text half of the entry rules and deliberately not the shape half.
// Whether an entry is scoped, whether its head is a slug and whether anything
// follows the separator are questions about what an entry means, and the
// answers differ by list: a prefixes entry ending at the separator is every tool
// on that member, where the same text in a tools list names a tool with no name.
// Callers that judge an entry an operator is writing want validateEntries and
// the errors it returns; callers reasoning about an entry already stored — the
// store's migration — want this.
func CleanToolEntry(e string) bool {
	if e == "" {
		return false
	}
	for _, r := range e {
		if r == utf8.RuneError || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validateEntryText rejects an entry that cannot match a tool name the proxy
// will ever see. field is the whole label ("tool_filter: tools",
// FieldToolAllowlist) and is named in the error with the index, so an operator
// can find the offending entry.
//
// The verdict is CleanToolEntry's alone, so this validator and the store's
// migration can never come to hold two different opinions about which entries
// are clean. Everything below only chooses which reason to name, and it ends in
// a catch-all: a rule added to CleanToolEntry that nothing here recognises must
// still come out of this function as an error, never as "valid".
func validateEntryText(field string, i int, e string) error {
	if CleanToolEntry(e) {
		return nil
	}
	if e == "" {
		return fmt.Errorf(`%s[%d] is empty; an empty entry denies nothing under mode "deny" and everything under mode "allow"`, field, i)
	}
	for _, r := range e {
		switch {
		case r == utf8.RuneError:
			// Go's JSON decoder substitutes U+FFFD for bytes that were not
			// valid UTF-8 and for lone surrogates, while JavaScript and
			// Python clients keep the original. An entry holding U+FFFD can
			// never equal the name such a client sends.
			return fmt.Errorf("%s[%d] %q is not valid UTF-8", field, i, e)
		case unicode.IsSpace(r), unicode.IsControl(r):
			// %q keeps a control character out of the operator's terminal
			// and makes a trailing space — the typo that turns a deny into a
			// no-op — visible.
			return fmt.Errorf("%s[%d] %q contains whitespace or a control character; entries are matched byte for byte against the tool identity", field, i, e)
		}
	}
	return fmt.Errorf("%s[%d] %q cannot match a tool name", field, i, e)
}
