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

// TestOwnerConsistent keeps the module path, every image path the tree names,
// and the repository this tree is checked out from on one owner. The workflow
// publishes to ghcr.io/<repository>, so the check on it is that it still
// derives the path from github.repository; the repository checks are what tie
// that derivation to the owner in go.mod. Under GitHub Actions the repository
// is GITHUB_REPOSITORY and a mismatch fails, which is why the workflow greps
// this test's PASS line. On a workstation the origin remote is compared and a
// mismatch is only logged, because a fork's clone names the fork's owner and
// is not wrong. The workflow check is a substring match on one line, so
// reformatting that line is a deliberate change to this test. LICENSE names a
// person, not the slug, and is checked by reading.
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
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		// Every tracked file that names an image path names this owner. This
		// file is excluded because its own expression below matches the pattern.
		out, err := exec.Command("git", "-C", root, "grep", "-n", "-E", `ghcr\.io/[^/[:space:]]+/porymcp`, "--", ".", ":!cmd/server/pins_test.go").Output()
		if err != nil {
			t.Fatalf("git grep for image paths: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" || strings.Contains(line, "ghcr.io/"+owner+"/porymcp") {
				continue
			}
			t.Errorf("image path with another owner: %s", line)
		}
	}
	if os.Getenv("GITHUB_ACTIONS") != "" {
		if repo, want := os.Getenv("GITHUB_REPOSITORY"), owner+"/porymcp"; repo != want {
			t.Errorf("GITHUB_REPOSITORY is %q; the module owner wants %s", repo, want)
		}
		return
	}
	out, err := exec.Command("git", "-C", root, "config", "--get", "remote.origin.url").Output()
	if err != nil {
		t.Logf("no origin remote; the remote check does not apply: %v", err)
		return
	}
	remote := strings.ReplaceAll(strings.TrimSpace(string(out)), ":", "/")
	if !regexp.MustCompile(`(^|/)github\.com/` + regexp.QuoteMeta(owner) + `/porymcp(\.git)?$`).MatchString(remote) {
		t.Logf("origin %q is not github.com/%s/porymcp; a fork's clone is expected to differ", strings.TrimSpace(string(out)), owner)
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
