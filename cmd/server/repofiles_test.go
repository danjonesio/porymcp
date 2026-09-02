package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the repository root, two directories above this package,
// and fails the test when go.mod is not there.
func repoRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not at ../.. from the test working directory: %v", err)
	}
	return root
}

// trackedFiles lists every path git tracks under root, repo-relative with
// forward slashes, minus the localOnly paths. Untracked local state (a
// developer's .env, a scratch file) never appears, so it cannot fail a clean
// checkout. The calling test is skipped on a source tree that is not a git
// checkout (a downloaded archive).
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("not a git checkout; the guard scans tracked files")
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files (the guard scans tracked files only): %v", err)
	}
	var files []string
	for _, file := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if file == "" || localOnly(file) {
			continue
		}
		files = append(files, file)
	}
	return files
}

// localOnly reports the working files that are git-ignored on the public
// tree and tracked only on the pre-cut archive: the agent workflow, the plan
// records and the issue template. They are never part of the published tree.
func localOnly(file string) bool {
	for _, prefix := range []string{"docs/plans/", ".agents/", ".claude/"} {
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	switch file {
	case "AGENTS.md", "CLAUDE.md", "docs/10-linear-issues.md":
		return true
	}
	return false
}
