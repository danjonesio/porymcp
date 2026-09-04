package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestOwnerConsistent keeps the module path, the image path the README tells
// an operator to pull, and the repository this tree is checked out from on
// one owner. The workflow publishes to ghcr.io/<repository>, so the check on
// it is that it still derives the path from github.repository; the remote
// check is what ties that derivation to the owner in go.mod. The workflow
// check is a substring match on one line, so reformatting that line is a
// deliberate change to this test. LICENSE names a person, not the slug, and
// is checked by reading.
func TestOwnerConsistent(t *testing.T) {
	root := repoRoot(t)
	m := regexp.MustCompile(`(?m)^module github\.com/([^/\s]+)/porymcp$`).FindSubmatch(readRepoFile(t, root, "go.mod"))
	if m == nil {
		t.Fatal("go.mod does not declare module github.com/<owner>/porymcp")
	}
	owner := string(m[1])
	if want := "ghcr.io/" + owner + "/porymcp"; !bytes.Contains(readRepoFile(t, root, "README.md"), []byte(want)) {
		t.Errorf("README.md does not name %s", want)
	}
	workflow := readRepoFile(t, root, filepath.Join(".github", "workflows", "ci.yml"))
	if want := "images: ghcr.io/${{ github.repository }}"; !bytes.Contains(workflow, []byte(want)) {
		t.Errorf("ci.yml does not derive the image path from the repository (%q)", want)
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Log("not a git checkout; the remote check does not apply")
		return
	}
	out, err := exec.Command("git", "-C", root, "config", "--get", "remote.origin.url").Output()
	if err != nil {
		t.Logf("no origin remote; the remote check does not apply: %v", err)
		return
	}
	remote := strings.ReplaceAll(strings.TrimSpace(string(out)), ":", "/")
	if want := "github.com/" + owner + "/porymcp"; !strings.Contains(remote, want) {
		t.Errorf("remote origin %q does not contain %s", strings.TrimSpace(string(out)), want)
	}
}

// TestNodeMajorConsistent keeps web/.nvmrc, which nvm and the web job read,
// on the Node major the Dockerfile's web stage builds with.
func TestNodeMajorConsistent(t *testing.T) {
	root := repoRoot(t)
	nvmrc := strings.TrimSpace(string(readRepoFile(t, root, filepath.Join("web", ".nvmrc"))))
	m := regexp.MustCompile(`(?m)^FROM .*\bnode:(\d+)-alpine\b`).FindSubmatch(readRepoFile(t, root, "Dockerfile"))
	if m == nil {
		t.Fatal("Dockerfile has no node:<major>-alpine stage")
	}
	if got := string(m[1]); got != nvmrc {
		t.Errorf("web/.nvmrc says Node %s; Dockerfile says node:%s-alpine", nvmrc, got)
	}
}

func readRepoFile(t *testing.T, root, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
