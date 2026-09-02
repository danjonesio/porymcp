package web

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// forEachSource walks root and calls fn with every regular file whose
// extension is in exts (every file when exts is empty), skipping the
// root-relative paths and directory names in skip. It fails the test outright
// when root is missing, so a wrong working directory cannot pass silently.
// nodanger_test.go and the two guards below share this one walk.
func forEachSource(t *testing.T, root string, exts []string, skip []string, fn func(path string, src []byte)) {
	t.Helper()
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("%s missing from the test working directory: %v", root, err)
	}
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}
	extSet := make(map[string]bool, len(exts))
	for _, e := range exts {
		extSet[e] = true
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Skips are root-relative paths, so "bin" skips only the top-level
			// build directory, never a nested one of the same name.
			if skipSet[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if skipSet[rel] {
			return nil
		}
		if len(extSet) > 0 && !extSet[filepath.Ext(path)] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fn(path, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestNoKitReferences is the standing guard behind PORM-61: no file in the
// repository may name the commercial UI kit the dashboard was once built on,
// in a comment, a doc or a copied file. The needles are assembled at runtime
// so that neither this file nor the tree carries the literal — the repo-wide
// grep in the verification must find nothing, and this guard must not trip on
// itself.
func TestNoKitReferences(t *testing.T) {
	kit := "cata" + "lyst"
	needles := [][]byte{[]byte(kit), []byte("tailwind " + "plus"), []byte(kit + "-ui-kit")}
	// The tracked export web/out is walked on purpose: it is the build product
	// that ships in the binary and the image. bin/ holds compiled binaries.
	// docs/plans/, .agents/ and .claude/ are git-ignored working directories
	// that are not part of the published tree; they are skipped so the guard
	// still passes in a working copy that has them.
	skip := []string{".git", "bin", "docs/plans", ".agents", ".claude", "web/node_modules", "web/.next", "web/sourceguard_test.go"}
	forEachSource(t, "..", nil, skip, func(path string, src []byte) {
		rel, _ := filepath.Rel("..", path)
		rel = filepath.ToSlash(rel)
		lower := bytes.ToLower(src)
		for _, n := range needles {
			if bytes.Contains(lower, n) {
				t.Errorf("%s names the kit (%q)", rel, n)
				return
			}
		}
	})
}

// remoteCSS matches an off-origin @import or font source in a stylesheet,
// absolute (https://) or protocol-relative (//).
var remoteCSS = regexp.MustCompile(`(@import\s+(url\()?\s*["']?(https?:)?//|src:\s*url\(\s*["']?(https?:)?//)`)

// remoteMarkup matches a stylesheet link or a script tag with a src in
// TSX/JSX, in any quoting or casing (<Script> is next/script).
var remoteMarkup = regexp.MustCompile(`(?i)(rel\s*=\s*["'{]?\s*["']?stylesheet|<script\s[^>]*\bsrc\s*=)`)

// TestNoRemoteResources keeps the dashboard's CSP honest
// (internal/webutil/headers.go): nothing under web/src may pull a stylesheet,
// script or font from another origin. Markup files are checked for stylesheet
// and script tags; stylesheets for remote @import and src: url(...) lines. The
// one allowed line is the Inter import in tailwind.css, which PORM-43 removes
// when it vendors the font — a second remote import fails the suite.
func TestNoRemoteResources(t *testing.T) {
	allowCSS := map[string]string{
		"src/styles/tailwind.css": "@import url('https://rsms.me/inter/inter.css');", // TODO(PORM-43)
	}
	forEachSource(t, "src", []string{".ts", ".tsx", ".js", ".jsx", ".css"}, nil, func(path string, src []byte) {
		rel := filepath.ToSlash(path)
		if filepath.Ext(path) == ".css" {
			for _, line := range bytes.Split(src, []byte("\n")) {
				l := bytes.TrimSpace(line)
				if allowed, ok := allowCSS[rel]; ok && string(l) == allowed {
					continue
				}
				if remoteCSS.Match(l) {
					t.Errorf("%s pulls a remote resource: %s", rel, l)
				}
			}
			return
		}
		if m := remoteMarkup.Find(src); m != nil {
			t.Errorf("%s embeds a stylesheet link or script tag: %s", rel, m)
		}
	})
}
