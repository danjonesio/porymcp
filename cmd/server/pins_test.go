package main

import (
	"bytes"
	"fmt"
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
// README must also name `github.com/<owner>/porymcp`, the repository line in
// its title block.
func TestOwnerConsistent(t *testing.T) {
	root := repoRoot(t)
	m := regexp.MustCompile(`(?m)^module github\.com/([^/\s]+)/porymcp$`).FindSubmatch(readRepoFile(t, root, "go.mod"))
	if m == nil {
		t.Fatal("go.mod does not declare module github.com/<owner>/porymcp")
	}
	owner := string(m[1])
	readme := readRepoFile(t, root, "README.md")
	if want := "ghcr.io/" + owner + "/porymcp"; !bytes.Contains(readme, []byte(want)) {
		t.Errorf("README.md does not name %s", want)
	}
	if want := "github.com/" + owner + "/porymcp"; !bytes.Contains(readme, []byte(want)) {
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

var (
	dockerfileFrom   = regexp.MustCompile(`(?m)^FROM .*$`)
	dockerfileRun    = regexp.MustCompile(`(?m)^RUN\b.*$`)
	dockerfileNpmCi  = regexp.MustCompile(`(?m)^RUN npm ci\b`)
	dockerfileSyntax = regexp.MustCompile(`(?m)^# syntax=.*$`)
	dockerfileDigest = regexp.MustCompile(`@sha256:[0-9a-f]{64}\b`)
)

// dockerfileProblems lists what is wrong with a Dockerfile's pins and its
// dashboard install, one message per problem. Only FROM and RUN lines and a
// syntax directive are read, so a comment that names npm install is ignored.
func dockerfileProblems(src []byte) []string {
	var problems []string
	froms := dockerfileFrom.FindAll(src, -1)
	if len(froms) < 3 {
		problems = append(problems, fmt.Sprintf("%d FROM lines; the build has three stages", len(froms)))
	}
	for _, line := range froms {
		if !dockerfileDigest.Match(line) {
			problems = append(problems, fmt.Sprintf("base image without an @sha256 digest: %s", line))
		}
	}
	if n := len(dockerfileNpmCi.FindAll(src, -1)); n != 1 {
		problems = append(problems, fmt.Sprintf("%d RUN npm ci lines; want 1", n))
	}
	for _, line := range dockerfileRun.FindAll(src, -1) {
		for _, banned := range []string{"npm install", "npm audit"} {
			if bytes.Contains(line, []byte(banned)) {
				problems = append(problems, fmt.Sprintf("%s in the image build: %s", banned, line))
			}
		}
	}
	for _, line := range dockerfileSyntax.FindAll(src, -1) {
		if !dockerfileDigest.Match(line) {
			problems = append(problems, fmt.Sprintf("frontend without an @sha256 digest: %s", line))
		}
	}
	return problems
}

// TestDockerfilePinned keeps every base image in the Dockerfile on a digest
// and the dashboard install on npm ci, which PORM-42's first two acceptance
// criteria asked for and which were checked by hand until now. npm install
// would resolve ranges afresh, and an npm audit step would fail a rebuild of a
// published commit on the day an advisory lands; make web-audit is the gate.
// The check is on the digest's shape only: telling an index digest from one
// platform's manifest needs a registry call, and is settled when the pin is
// taken (docs/08-docker.md).
func TestDockerfilePinned(t *testing.T) {
	for _, p := range dockerfileProblems(readRepoFile(t, repoRoot(t), "Dockerfile")) {
		t.Error(p)
	}
}

// The tests below run dockerfileProblems on in-memory inputs, so the guard is
// shown to fail without touching the tracked Dockerfile. The fixture's digest
// is built at run time to keep the inputs short.

func pinnedDockerfile() string {
	d := "@sha256:" + strings.Repeat("a", 64)
	return "FROM --platform=$BUILDPLATFORM node:22-alpine" + d + " AS web\n" +
		"RUN npm ci --no-audit --no-fund\n" +
		"FROM --platform=$BUILDPLATFORM golang:1.26-alpine" + d + " AS build\n" +
		"RUN go build ./cmd/server\n" +
		"FROM gcr.io/distroless/static-debian12:nonroot" + d + "\n"
}

func wantProblem(t *testing.T, src, fragment string) {
	t.Helper()
	got := dockerfileProblems([]byte(src))
	for _, p := range got {
		if strings.Contains(p, fragment) {
			return
		}
	}
	t.Fatalf("no problem containing %q; got %q", fragment, got)
}

func TestDockerfileProblems_Pinned(t *testing.T) {
	if got := dockerfileProblems([]byte(pinnedDockerfile())); len(got) != 0 {
		t.Fatalf("a pinned Dockerfile reported %q", got)
	}
}

func TestDockerfileProblems_NoDigest(t *testing.T) {
	src := strings.Replace(pinnedDockerfile(), "golang:1.26-alpine@sha256:"+strings.Repeat("a", 64), "golang:1.26-alpine", 1)
	wantProblem(t, src, "base image without an @sha256 digest: FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build")
}

// A digest cut short is a tag with a suffix, so it is not a pin.
func TestDockerfileProblems_ShortDigest(t *testing.T) {
	src := strings.Replace(pinnedDockerfile(), strings.Repeat("a", 64)+" AS web", strings.Repeat("a", 12)+" AS web", 1)
	wantProblem(t, src, "base image without an @sha256 digest: FROM --platform=$BUILDPLATFORM node:22-alpine")
}

func TestDockerfileProblems_TwoFroms(t *testing.T) {
	src := pinnedDockerfile()
	src = src[:strings.LastIndex(src, "FROM ")]
	wantProblem(t, src, "2 FROM lines")
}

// npm install beside a valid npm ci line is still reported.
func TestDockerfileProblems_NpmInstall(t *testing.T) {
	wantProblem(t, pinnedDockerfile()+"RUN npm install --no-fund\n", "npm install in the image build")
	src := strings.Replace(pinnedDockerfile(), "RUN npm ci --no-audit --no-fund", "RUN npm install", 1)
	wantProblem(t, src, "0 RUN npm ci lines")
}

// Security requirement 2 of the PORM-42 plan: no vulnerability check of its
// own in the image build.
func TestDockerfileProblems_NpmAudit(t *testing.T) {
	wantProblem(t, pinnedDockerfile()+"RUN npm audit --audit-level=high\n", "npm audit in the image build")
}

// Security requirement 10 of the PORM-42 plan: a frontend line that returns
// must carry a digest.
func TestDockerfileProblems_UnpinnedSyntax(t *testing.T) {
	wantProblem(t, "# syntax=docker/dockerfile:1\n"+pinnedDockerfile(), "frontend without an @sha256 digest")
	pinned := "# syntax=docker/dockerfile:1@sha256:" + strings.Repeat("a", 64) + "\n" + pinnedDockerfile()
	if got := dockerfileProblems([]byte(pinned)); len(got) != 0 {
		t.Fatalf("a pinned frontend reported %q", got)
	}
}

// A comment is prose about the build, and the repository's own docs name npm
// install, so a comment that names it is not a problem.
func TestDockerfileProblems_CommentIgnored(t *testing.T) {
	src := "# Use npm install to change dependencies, never in a RUN line.\n" + pinnedDockerfile()
	if got := dockerfileProblems([]byte(src)); len(got) != 0 {
		t.Fatalf("a comment reported %q", got)
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
