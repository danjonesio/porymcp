package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestProseStyle is the gate behind docs/12-writing.md (PORM-130). It scans
// every tracked prose file (proseFile) and fails, naming file, line and
// column, on an em-dash, an en-dash, an arrow in prose, an emoji, or a word
// from bannedWords. The rules the test cannot check (question headings,
// bold-label bullets, contrast for emphasis, heading case, spelling) are in
// the guide and are checked at review.
func TestProseStyle(t *testing.T) {
	root := repoRoot(t)
	var all []violation
	for _, file := range trackedFiles(t, root) {
		if !proseFile(file) || notYetRewrittenPath(file) {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			// An index entry whose working-tree file is gone (mid git-rm, a
			// sparse checkout) is not a violation.
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		vs, err := checkFile(file, src)
		if err != nil {
			t.Errorf("%s: parse: %v", file, err)
			continue
		}
		all = append(all, vs...)
	}
	for _, v := range all {
		t.Errorf("%s", v)
	}
	if len(all) > 0 {
		t.Errorf("%d prose violations; the rules are in docs/12-writing.md", len(all))
	}
}

// violation is one rule broken at one position. Col counts runes from the
// start of the line, so an editor's column matches.
type violation struct {
	Path    string
	Line    int
	Col     int
	Rule    string
	Snippet string
}

func (v violation) String() string {
	return fmt.Sprintf("%s:%d:%d: %s: %s", v.Path, v.Line, v.Col, v.Rule, v.Snippet)
}

// bannedWords is the list from PORM-130: marketing adjectives, intensifiers,
// verbs borrowed from sales copy, and filler. Each entry is matched
// case-insensitively on ASCII word boundaries; an apostrophe matches both '
// and the curly U+2019. "just", "actually", "clean" and "modern" stay out
// because they have technical uses (path.Clean, "a clean start"); the guide
// covers them.
var bannedWords = []string{
	"seamless", "seamlessly", "robust", "powerful", "effortless", "effortlessly",
	"cutting-edge", "state-of-the-art", "world-class", "best-in-class",
	"battle-tested", "production-grade", "enterprise-grade", "blazing",
	"lightning-fast", "first-class", "beautiful", "gorgeous", "stunning",
	"polished", "sleek", "elegant", "delightful", "magical", "dead-simple",
	"dead simple", "super simple", "super clean", "extreme simplicity",
	"trivial", "trivially", "zero-config", "plug-and-play", "hassle-free",
	"out of the box", "game-changer", "supercharge", "unlock", "empower",
	"elevate", "streamline", "leverage", "delve", "journey", "landscape",
	"realm", "testament", "pivotal", "crucial", "vital", "paramount",
	"holistic", "synergy", "tailored", "meticulous", "nuanced", "intricate",
	"foster", "simply", "basically", "essentially", "ultimately",
	"importantly", "note that", "it's worth noting", "keep in mind",
	"in other words", "needless to say", "of course", "obviously",
	"feel free", "rest assured", "look no further", "say goodbye",
	"whether you're", "let's",
}

var bannedRes = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(bannedWords))
	for i, w := range bannedWords {
		q := strings.ReplaceAll(regexp.QuoteMeta(w), "'", `['\x{2019}]`)
		res[i] = regexp.MustCompile(`(?i)\b` + q + `\b`)
	}
	return res
}()

// quotations exempts single lines that quote another program's output
// verbatim from the emoji and word checks only. Dash and arrow rules are
// never exempt: reword around the quotation. Each entry carries a reason.
var quotations = []struct{ Path, Contains, Reason string }{
	{"docs/09-clients.md", "Failed to connect", "quotes Claude Code's own output, including its U+2718 glyph"},
}

// wordCheckExempt lists the two files that name the banned words on purpose.
// The code-point rules still apply to them.
var wordCheckExempt = map[string]bool{
	"docs/12-writing.md":       true,
	"cmd/server/prose_test.go": true,
}

// notYetRewritten lists the path prefixes PORM-130 has not rewritten yet.
// Each rewrite commit deletes its entry; the last one deletes this variable
// and notYetRewrittenPath, so the exemption cannot quietly regain an entry.
var notYetRewritten = []string{
	"docs/09-clients.md",
	"docs/11-deployment.md",
	"CHANGELOG.md",
	"NOTICE",
	"openapi.yaml",
	"web/src/",
	"web/fs.go",
	"web/sourceguard_test.go",
	"web/nodanger_test.go",
	"web/next.config.mjs",
	"web/eslint.config.mjs",
	"internal/api/",
	"internal/audit/",
	"internal/auth/",
	"internal/config/",
	"internal/credential/",
	"internal/crypto/",
	"internal/mcpclient/",
	"internal/models/",
	"internal/proxy/",
	"internal/store/",
	"internal/webutil/",
	"cmd/server/",
	"docker-compose.yml",
	"docker-compose.tls.yml",
	"Dockerfile",
	"Makefile",
	".env.example",
}

func notYetRewrittenPath(file string) bool {
	for _, prefix := range notYetRewritten {
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	return false
}

// proseFile reports whether the gate scans a tracked path: the text and
// source extensions, plus the extensionless files people read. web/out is
// the minified export, checked by hand in the PR instead. LICENSE has no
// matching extension or basename and is not scanned.
func proseFile(p string) bool {
	if strings.HasPrefix(p, "web/out/") {
		return false
	}
	switch path.Base(p) {
	case "NOTICE", "Dockerfile", "Makefile", ".env.example":
		return true
	}
	switch path.Ext(p) {
	case ".md", ".yaml", ".yml", ".go", ".ts", ".tsx", ".css", ".mjs":
		return true
	}
	return false
}

// checkFile scans src and returns every violation, sorted by line and
// column. U+2014 and U+2013 are reported everywhere. U+2192 is reported
// everywhere except inside a Markdown fence (a line whose trimmed text starts
// with three backticks toggles the state; only .md files have fences). Emoji
// are reported everywhere except on a quotations line. Banned words are
// reported everywhere except inside a fence, on a quotations line, in a
// wordCheckExempt file, and, for Go files, outside comments: Go comments
// come from go/parser, because identifiers such as Unlock are not prose. A
// Go file that fails to parse returns the error; it is never scanned as plain
// text and never skipped.
func checkFile(p string, src []byte) ([]violation, error) {
	var out []violation
	isMarkdown := path.Ext(p) == ".md"
	isGo := path.Ext(p) == ".go"
	wordsEverywhere := !isGo && !wordCheckExempt[p]
	lines := strings.Split(string(src), "\n")
	inFence := false
	for i, line := range lines {
		lineNo := i + 1
		if isMarkdown && strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		fenced := isMarkdown && inFence
		quoted := isQuotation(p, line)
		col := 0
		for _, r := range line {
			col++
			switch {
			case r == '\u2014':
				out = append(out, newViolation(p, lineNo, col, "em-dash", line))
			case r == '\u2013':
				out = append(out, newViolation(p, lineNo, col, "en-dash", line))
			case r == '\u2192' && !fenced:
				out = append(out, newViolation(p, lineNo, col, "arrow", line))
			case isEmoji(r) && !quoted:
				out = append(out, newViolation(p, lineNo, col, "emoji", line))
			}
		}
		if wordsEverywhere && !fenced && !quoted {
			out = append(out, bannedIn(p, lineNo, 1, line, line)...)
		}
	}
	if isGo && !wordCheckExempt[p] {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		for _, group := range f.Comments {
			for _, c := range group.List {
				pos := fset.Position(c.Slash)
				for j, text := range strings.Split(c.Text, "\n") {
					lineNo := pos.Line + j
					if lineNo < 1 || lineNo > len(lines) {
						break
					}
					full := lines[lineNo-1]
					if isQuotation(p, full) {
						continue
					}
					col := 1
					if j == 0 && pos.Column > 1 && pos.Column-1 <= len(full) {
						col = utf8.RuneCountInString(full[:pos.Column-1]) + 1
					}
					out = append(out, bannedIn(p, lineNo, col, text, full)...)
				}
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Line != out[b].Line {
			return out[a].Line < out[b].Line
		}
		return out[a].Col < out[b].Col
	})
	return out, nil
}

// bannedIn returns a violation for each banned word in text, whose first
// rune sits at column base of the line whose full text is shown as snippet.
func bannedIn(p string, lineNo, base int, text, full string) []violation {
	var out []violation
	for i, re := range bannedRes {
		for _, m := range re.FindAllStringIndex(text, -1) {
			col := base + utf8.RuneCountInString(text[:m[0]])
			out = append(out, newViolation(p, lineNo, col, fmt.Sprintf("word %q", bannedWords[i]), full))
		}
	}
	return out
}

func isQuotation(p, line string) bool {
	for _, q := range quotations {
		if q.Path == p && strings.Contains(line, q.Contains) {
			return true
		}
	}
	return false
}

// isEmoji covers the emoji and dingbat blocks the guide names.
func isEmoji(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF:
		return true
	case r >= 0x2600 && r <= 0x27BF:
		return true
	case r >= 0x2B00 && r <= 0x2BFF:
		return true
	case r == 0xFE0F:
		return true
	}
	return false
}

func newViolation(p string, line, col int, rule, snippet string) violation {
	snippet = strings.TrimSpace(snippet)
	if utf8.RuneCountInString(snippet) > 60 {
		runes := []rune(snippet)
		snippet = string(runes[:60])
	}
	return violation{Path: p, Line: line, Col: col, Rule: rule, Snippet: snippet}
}

// The unit tests below run checkFile on in-memory inputs, so they do not
// depend on the state of the rewrite. Every banned code point in an input is
// written as a Go escape, never as a live character.

func mustCheck(t *testing.T, p, src string) []violation {
	t.Helper()
	vs, err := checkFile(p, []byte(src))
	if err != nil {
		t.Fatalf("checkFile(%s): %v", p, err)
	}
	return vs
}

func rules(vs []violation) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d:%d %s", v.Line, v.Col, v.Rule)
	}
	return strings.Join(parts, "; ")
}

// Column is counted in runes, so a multibyte character before the dash does
// not shift it (no line and column precedent existed in the repository).
func TestCheckFile_EmDash(t *testing.T) {
	vs := mustCheck(t, "docs/x.md", "ok\né \u2014 x\n")
	if got, want := rules(vs), "2:3 em-dash"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if want := "docs/x.md:2:3: em-dash: é \u2014 x"; vs[0].String() != want {
		t.Fatalf("got %q, want %q", vs[0].String(), want)
	}
}

func TestCheckFile_EnDash(t *testing.T) {
	vs := mustCheck(t, "docs/x.md", "lines 30\u201340\n")
	if got, want := rules(vs), "1:9 en-dash"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Arrows inside a Markdown fence are a diagram; outside they are prose.
func TestCheckFile_ArrowOutsideFence(t *testing.T) {
	src := "a \u2192 b\n```\nc \u2192 d\n```\ne \u2192 f\n"
	vs := mustCheck(t, "docs/x.md", src)
	if got, want := rules(vs), "1:3 arrow; 5:3 arrow"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Fences exist only in Markdown: the same text under a YAML path reports all
// three arrows.
func TestCheckFile_ArrowInsideFence(t *testing.T) {
	src := "a \u2192 b\n```\nc \u2192 d\n```\ne \u2192 f\n"
	vs := mustCheck(t, "x.yaml", src)
	if got, want := rules(vs), "1:3 arrow; 3:3 arrow; 5:3 arrow"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Inside a fence only the arrow and word rules relax; a dash is still reported.
func TestCheckFile_EmDashInsideFence(t *testing.T) {
	vs := mustCheck(t, "docs/x.md", "```\na \u2014 b\n```\n")
	if got, want := rules(vs), "2:3 em-dash"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A quotations line is exempt from the emoji check and nothing else.
func TestCheckFile_Emoji(t *testing.T) {
	vs := mustCheck(t, "docs/x.md", "ok \u2718 bad\nface \U0001F600\n")
	if got, want := rules(vs), "1:4 emoji; 2:6 emoji"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	quoted := "the client prints \u2718 Failed to connect \u2014 then exits\n"
	vs = mustCheck(t, "docs/09-clients.md", quoted)
	if got, want := rules(vs), "1:39 em-dash"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Word boundaries, case, hyphens, spaces and the curly apostrophe.
func TestCheckFile_BannedWord(t *testing.T) {
	src := "Seamless setup\na dead-simple tool\nworks out of the box\nlet\u2019s go\nseamlessness\n"
	vs := mustCheck(t, "docs/x.md", src)
	want := `1:1 word "seamless"; 2:3 word "dead-simple"; 3:7 word "out of the box"; 4:1 word "let's"`
	if got := rules(vs); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Go identifiers are not prose: mu.Unlock() in code is ignored, the same
// word in a comment is reported at the comment's line and column.
func TestCheckFile_GoWordsOnlyInComments(t *testing.T) {
	src := "package x\n\nimport \"sync\"\n\nvar mu sync.Mutex\n\n// unlock the door\nfunc f() { mu.Unlock() } // and unlock again\n"
	vs := mustCheck(t, "internal/x/x.go", src)
	if got, want := rules(vs), `7:4 word "unlock"; 8:33 word "unlock"`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A Go file that does not parse is an error, never a silent pass and never
// a plain-text scan.
func TestCheckFile_GoParseError(t *testing.T) {
	vs, err := checkFile("internal/x/x.go", []byte("package x\nfunc {\n"))
	if err == nil {
		t.Fatalf("expected a parse error, got %d violations", len(vs))
	}
	if len(vs) != 0 {
		t.Fatalf("expected no violations on a parse error, got %v", vs)
	}
}

// The guide names the words and is exempt from the word check only.
func TestCheckFile_WordExemptFile(t *testing.T) {
	if vs := mustCheck(t, "docs/12-writing.md", "do not write seamless\n"); len(vs) != 0 {
		t.Fatalf("expected no violations, got %v", vs)
	}
	if got, want := rules(mustCheck(t, "docs/12-writing.md", "a \u2014 b\n")), "1:3 em-dash"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Extensionless files people read are scanned by basename; the export and
// the third-party licence are not.
func TestProseFile(t *testing.T) {
	for _, p := range []string{"README.md", "NOTICE", "Dockerfile", "web/next.config.mjs", "docs/x.md", "internal/a/b.go", "web/src/a.tsx", "openapi.yaml", ".env.example"} {
		if !proseFile(p) {
			t.Errorf("proseFile(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"LICENSE", "web/out/index.html", "web/out/_next/static/chunks/0.fyhs4wcwtf0.js", "web/package.json", "bin/porymcp"} {
		if proseFile(p) {
			t.Errorf("proseFile(%q) = true, want false", p)
		}
	}
}
