package web

import (
	"regexp"
	"testing"
)

// dangerousHTMLPatterns are the ways dashboard code can turn a string into
// markup or script. Untrusted upstream text (error_message, params, tool
// descriptions, OAuth error text) must reach the page as React text children
// only. Biome's security.noDangerouslySetInnerHtml (raised to an error in
// web/biome.jsonc) and security.noGlobalEval (on through Biome's recommended
// set) are the precise checks for two of these, in make web-lint, and
// security.noScriptUrl covers a literal javascript: href. This table is the
// blunt check behind them: a match on the source text that runs in go test
// with no Node and covers the sinks Biome does not enable. It does not see an
// href or src bound to upstream text (oauth-connect.ts guards the one
// navigation with authorizationURLIsWeb), a string passed to setTimeout,
// DOMParser, or a sink reached through an alias. It reads comments too, so a
// comment names a pattern in words.
var dangerousHTMLPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"dangerouslySetInnerHTML", regexp.MustCompile(`\bdangerouslySetInnerHTML\b`)},
	{"srcDoc", regexp.MustCompile(`(?i)\bsrcdoc\b`)},
	{"Function(", regexp.MustCompile(`\bFunction\s*\(`)},
	{"eval(", regexp.MustCompile(`\beval\s*\(`)},
	{".innerHTML", regexp.MustCompile(`\.innerHTML\b`)},
	{".outerHTML", regexp.MustCompile(`\.outerHTML\b`)},
	{"insertAdjacentHTML", regexp.MustCompile(`\binsertAdjacentHTML\b`)},
	{"HTMLUnsafe", regexp.MustCompile(`\b(set|parse)HTMLUnsafe\b`)},
	{"createContextualFragment", regexp.MustCompile(`\bcreateContextualFragment\b`)},
	{"document.write", regexp.MustCompile(`\bdocument\.write`)},
}

// dangerousHTML returns the name of each pattern src contains, in table order.
func dangerousHTML(src []byte) []string {
	var found []string
	for _, p := range dangerousHTMLPatterns {
		if p.re.Match(src) {
			found = append(found, p.name)
		}
	}
	return found
}

// TestNoDangerousHTMLPatterns fails the Go suite when a file under web/src
// uses a pattern above, naming the file and the pattern (PORM-118).
func TestNoDangerousHTMLPatterns(t *testing.T) {
	forEachSource(t, "src", []string{".ts", ".tsx", ".js", ".jsx"}, nil, func(path string, b []byte) {
		for _, name := range dangerousHTML(b) {
			t.Errorf("%s uses %s", path, name)
		}
	})
}

// TestDangerousHTML_EachPattern runs dangerousHTML on one in-memory line per
// row, so each row is shown to fail without a file in the tree.
func TestDangerousHTML_EachPattern(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`<div dangerouslySetInnerHTML={{ __html: text }} />`, "dangerouslySetInnerHTML"},
		{`<iframe title="preview" srcDoc={text} />`, "srcDoc"},
		{`const f = new Function('a', text)`, "Function("},
		{`const g = Function (text)`, "Function("},
		{`const v = eval (text)`, "eval("},
		{`node.innerHTML = text`, ".innerHTML"},
		{`node.outerHTML = text`, ".outerHTML"},
		{`node.insertAdjacentHTML('beforeend', text)`, "insertAdjacentHTML"},
		{`node.setHTMLUnsafe(text)`, "HTMLUnsafe"},
		{`range.createContextualFragment(text)`, "createContextualFragment"},
		{`document.writeln(text)`, "document.write"},
	} {
		if got := dangerousHTML([]byte(c.src)); len(got) != 1 || got[0] != c.want {
			t.Errorf("%q: got %q, want [%q]", c.src, got, c.want)
		}
	}
}

// TestDangerousHTML_NearMisses: names that only contain a pattern's letters
// are not the pattern: a call whose name ends in eval, a Function type, text
// set as text, srcdoc inside a longer name.
func TestDangerousHTML_NearMisses(t *testing.T) {
	src := "const r = retrieval(x)\nconst g: Function = f\n(f as Function)(x)\nnode.textContent = text\n<p>{text}</p>\nconst evaluation = 1\nconst srcDocument = 1\n"
	if got := dangerousHTML([]byte(src)); len(got) != 0 {
		t.Fatalf("near misses reported %q", got)
	}
}
