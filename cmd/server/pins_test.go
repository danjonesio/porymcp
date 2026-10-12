package main

import (
	"bytes"
	"fmt"
	"go/version"
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

// goToolchainProblems lists what puts a golang build image in the Dockerfile
// below the Go release go.mod asks for, one message per problem. Each image
// tag names a minor (golang:1.27-alpine), and that minor has to be at least
// the minor of go.mod's go line and of its toolchain line. The image sets
// GOTOOLCHAIN=local, so a newer go line fails the image build, but a newer
// toolchain line is ignored and the image compiles with its own older
// release; that second comparison is the one no build makes. An image a
// minor ahead passes, as the tree stands since the docker lane moved the tag
// (aac1934) and PORM-215 kept it; the go job and make vuln then run on the
// toolchain line's release, not the image's. The patch is not compared: the
// tag carries none, and the release inside the image is fixed by its digest,
// which is read by running the image when the pin moves (docs/08-docker.md).
// No golang tag with a minor (golang:alpine), a garbled line or a missing go
// line is a problem, never a pass. A go.mod with no toolchain line, or with
// toolchain default, is checked on its go line alone, which is Go's own rule.
func goToolchainProblems(gomod, dockerfile []byte) []string {
	src := dockerfileContinuation.ReplaceAll(dockerfileComment.ReplaceAll(dockerfile, nil), []byte(" "))
	froms := dockerfileGolang.FindAllSubmatch(src, -1)
	if len(froms) == 0 {
		return []string{"Dockerfile has no FROM line with a golang:<major>.<minor> tag, so there is no minor to compare with go.mod"}
	}
	var problems []string
	g := gomodGo.FindSubmatch(gomod)
	tc := gomodToolchain.FindSubmatch(gomod)
	switch {
	case g == nil:
		problems = append(problems, "go.mod has no go line")
	case !version.IsValid("go" + string(g[1])):
		problems = append(problems, fmt.Sprintf("go.mod's go line %q is not a Go version", g[1]))
	}
	if tc != nil && string(tc[1]) != "default" && !version.IsValid(string(tc[1])) {
		problems = append(problems, fmt.Sprintf("go.mod's toolchain line %q is not a Go toolchain name", tc[1]))
	}
	if len(problems) > 0 {
		return problems
	}
	for _, m := range froms {
		tag := string(m[1])
		image := version.Lang("go" + tag)
		if version.Compare(image, version.Lang("go"+string(g[1]))) < 0 {
			problems = append(problems, fmt.Sprintf("go.mod says go %s and the Dockerfile builds on golang:%s; under GOTOOLCHAIN=local the image build fails with go.mod requires go >= %s", g[1], tag, g[1]))
		}
		if tc != nil && string(tc[1]) != "default" && version.Compare(image, version.Lang(string(tc[1]))) < 0 {
			problems = append(problems, fmt.Sprintf("go.mod pins toolchain %s, a newer minor than the Dockerfile's golang:%s build image; under GOTOOLCHAIN=local the image ignores the line and compiles with Go %s", tc[1], tag, tag))
		}
	}
	return problems
}

// TestGoToolchainConsistent keeps every golang build image in the Dockerfile
// at or above the minor release go.mod names (PORM-185), as
// TestNodeMajorConsistent keeps web/.nvmrc on the image's Node major. The
// workflow greps its PASS line.
func TestGoToolchainConsistent(t *testing.T) {
	root := repoRoot(t)
	for _, p := range goToolchainProblems(readRepoFile(t, root, "go.mod"), readRepoFile(t, root, "Dockerfile")) {
		t.Error(p)
	}
}

var (
	dockerfileComment      = regexp.MustCompile(`(?m)^[ \t]*#.*$`)
	dockerfileContinuation = regexp.MustCompile(`\\[ \t]*\r?\n`)
	dockerfileFrom         = regexp.MustCompile(`(?m)^FROM .*$`)
	// dockerfileGolang reads the minor from a golang build stage's tag, after
	// comment lines are stripped and continuations joined. Instructions are
	// case-insensitive and may be indented. The digest after the tag is not
	// read: TestDockerfilePinned checks its shape.
	dockerfileGolang       = regexp.MustCompile(`(?mi)^[ \t]*FROM\b.*\bgolang:(\d+\.\d+)\b`)
	dockerfilePinnedFrom   = regexp.MustCompile(`^FROM\s+(?:--\S+\s+)*\S+@sha256:[0-9a-f]{64}(?:\s|$)`)
	dockerfileRun          = regexp.MustCompile(`(?m)^RUN\b.*$`)
	dockerfileNpmCi        = regexp.MustCompile(`(?m)^RUN npm ci\b`)
	dockerfileSyntax       = regexp.MustCompile(`(?mi)^#\s*syntax\s*=.*$`)
	dockerfilePinnedSyntax = regexp.MustCompile(`@sha256:[0-9a-f]{64}\s*$`)
	// gomodGo and gomodToolchain read the two version lines. \S+ stops before
	// a carriage return, so a CRLF file reads the same.
	gomodGo            = regexp.MustCompile(`(?m)^go[ \t]+(\S+)`)
	gomodToolVuln      = regexp.MustCompile(`(?m)^(?:tool[ \t]+|\t)golang\.org/x/vuln/cmd/govulncheck[ \t]*\r?$`)
	gomodToolchain     = regexp.MustCompile(`(?m)^toolchain[ \t]+(\S+)`)
	makefileComment    = regexp.MustCompile(`^[ \t]*#`)
	makefileVulnRecipe = regexp.MustCompile(`(?m)^vuln:[ \t]*\r?\n\tgo tool govulncheck `)
)

// dockerfileProblems lists what is wrong with a Dockerfile's pins and its
// dashboard install, one message per problem. Only FROM and RUN instructions
// and a syntax directive are read, so a comment that names npm install is
// ignored. Comment lines are dropped and then backslash continuations are
// joined, the order BuildKit uses, so an instruction is read whole and a
// comment ending in a backslash cannot hide the line after it. The digest has
// to sit on the image reference, and the directive is matched the way BuildKit
// reads one: any case, optional spaces.
func dockerfileProblems(src []byte) []string {
	var problems []string
	directives := dockerfileSyntax.FindAll(src, -1)
	src = dockerfileComment.ReplaceAll(src, nil)
	src = dockerfileContinuation.ReplaceAll(src, []byte(" "))
	froms := dockerfileFrom.FindAll(src, -1)
	if len(froms) < 3 {
		problems = append(problems, fmt.Sprintf("%d FROM lines; the build has three stages", len(froms)))
	}
	for _, line := range froms {
		if !dockerfilePinnedFrom.Match(line) {
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
	for _, line := range directives {
		if !dockerfilePinnedSyntax.Match(line) {
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

// A digest in a trailing comment is not on the image reference.
func TestDockerfileProblems_DigestInComment(t *testing.T) {
	d := "@sha256:" + strings.Repeat("a", 64)
	src := strings.Replace(pinnedDockerfile(), "golang:1.26-alpine"+d+" AS build", "golang:1.26-alpine AS build # was "+d, 1)
	wantProblem(t, src, "base image without an @sha256 digest: FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build")
}

func TestDockerfileProblems_TwoFroms(t *testing.T) {
	src := pinnedDockerfile()
	src = src[:strings.LastIndex(src, "FROM ")]
	wantProblem(t, src, "2 FROM lines")
}

// The install is one npm ci line: none and two are both reported.
func TestDockerfileProblems_NpmCiCount(t *testing.T) {
	none := strings.Replace(pinnedDockerfile(), "RUN npm ci --no-audit --no-fund\n", "", 1)
	wantProblem(t, none, "0 RUN npm ci lines")
	wantProblem(t, pinnedDockerfile()+"RUN npm ci\n", "2 RUN npm ci lines")
}

// npm install beside a valid npm ci line is still reported, and so is one on
// the continuation of an instruction, which is how a RUN line usually grows.
func TestDockerfileProblems_NpmInstall(t *testing.T) {
	wantProblem(t, pinnedDockerfile()+"RUN npm install --no-fund\n", "npm install in the image build")
	continued := strings.Replace(pinnedDockerfile(), "RUN npm ci --no-audit --no-fund\n", "RUN npm ci --no-audit --no-fund \\\n  && npm install left-pad\n", 1)
	wantProblem(t, continued, "npm install in the image build")
	wantProblem(t, pinnedDockerfile()+"# a comment ending in a backslash \\\nRUN npm install left-pad\n", "npm install in the image build")
}

// The image build carries no vulnerability check of its own: an advisory
// against frozen code would fail a rebuild of a published commit, and
// make web-audit is the gate.
func TestDockerfileProblems_NpmAudit(t *testing.T) {
	wantProblem(t, pinnedDockerfile()+"RUN npm audit --audit-level=high\n", "npm audit in the image build")
}

// A frontend line that returns must carry a digest, in every spelling BuildKit
// reads as the directive: the key is case-insensitive and spaces are optional.
func TestDockerfileProblems_UnpinnedSyntax(t *testing.T) {
	for _, line := range []string{
		"# syntax=docker/dockerfile:1",
		"#syntax=docker/dockerfile:1",
		"# SYNTAX = docker/dockerfile:1",
	} {
		wantProblem(t, line+"\n"+pinnedDockerfile(), "frontend without an @sha256 digest")
	}
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

// vulnPinProblems lists what is wrong with how the vulnerability scanner is
// pinned, one message per problem: go.mod must name govulncheck in a tool
// directive (a single tool line or an entry in a tool block, the two shapes
// go get -tool writes), the Makefile's vuln target must run it through go
// tool, and no Makefile line may pin it by version, which is what a go run
// argument does. A Makefile comment that names the old pin is prose about
// the build, not a pin, and is ignored the way dockerfileProblems ignores
// comments.
func vulnPinProblems(gomod, makefile []byte) []string {
	var problems []string
	if !gomodToolVuln.Match(gomod) {
		problems = append(problems, "go.mod has no tool line for golang.org/x/vuln/cmd/govulncheck")
	}
	if !makefileVulnRecipe.Match(makefile) {
		problems = append(problems, "Makefile has no vuln target whose recipe starts with go tool govulncheck")
	}
	for _, line := range bytes.Split(makefile, []byte("\n")) {
		if !makefileComment.Match(line) && bytes.Contains(line, []byte("govulncheck@")) {
			problems = append(problems, fmt.Sprintf("govulncheck pinned by version in the Makefile: %s", bytes.TrimSpace(line)))
		}
	}
	return problems
}

// TestVulnPinned keeps the vulnerability scanner's version in go.mod, where
// PORM-183 moved it so that Dependabot's gomod lane can raise the bump. The
// version sat in a go run argument in the Makefile before that, where no
// lane reads it, and drifted seven releases. This fails if that pin returns
// or the tool line goes.
func TestVulnPinned(t *testing.T) {
	root := repoRoot(t)
	for _, p := range vulnPinProblems(readRepoFile(t, root, "go.mod"), readRepoFile(t, root, "Makefile")) {
		t.Error(p)
	}
}

// The tests below run vulnPinProblems on in-memory inputs, so the guard is
// shown to fail without touching the tracked files.

const (
	pinnedGoMod = "module example.com/m\n\ngo 1.26.0\n\nrequire golang.org/x/vuln v1.8.0 // indirect\n\n" +
		"tool golang.org/x/vuln/cmd/govulncheck\n"
	pinnedMakefile = "vet:\n\tgo vet ./cmd/... ./internal/... ./web\n\n" +
		"vuln:\n\tgo tool govulncheck ./cmd/... ./internal/... ./web\n"
)

func wantVulnProblem(t *testing.T, gomod, makefile, fragment string) {
	t.Helper()
	got := vulnPinProblems([]byte(gomod), []byte(makefile))
	for _, p := range got {
		if strings.Contains(p, fragment) {
			return
		}
	}
	t.Fatalf("no problem containing %q; got %q", fragment, got)
}

// Both shapes go get -tool writes are accepted: a single tool line, and an
// entry in a tool block once a second tool exists.
func TestVulnPinProblems_Pinned(t *testing.T) {
	block := strings.Replace(pinnedGoMod, "tool golang.org/x/vuln/cmd/govulncheck\n",
		"tool (\n\tgolang.org/x/tools/cmd/stringer\n\tgolang.org/x/vuln/cmd/govulncheck\n)\n", 1)
	for _, gomod := range []string{pinnedGoMod, block} {
		if got := vulnPinProblems([]byte(gomod), []byte(pinnedMakefile)); len(got) != 0 {
			t.Fatalf("a pinned tree reported %q", got)
		}
	}
}

func TestVulnPinProblems_NoToolLine(t *testing.T) {
	gomod := strings.Replace(pinnedGoMod, "tool golang.org/x/vuln/cmd/govulncheck\n", "", 1)
	wantVulnProblem(t, gomod, pinnedMakefile, "no tool line")
	if got := vulnPinProblems([]byte(gomod), []byte(pinnedMakefile)); len(got) != 1 {
		t.Fatalf("want 1 problem, got %q", got)
	}
}

// The old recipe is reported twice: no go tool recipe, and the version pin.
func TestVulnPinProblems_GoRunPin(t *testing.T) {
	makefile := strings.Replace(pinnedMakefile, "go tool govulncheck ./cmd/... ./internal/... ./web",
		"go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./cmd/... ./internal/... ./web", 1)
	wantVulnProblem(t, pinnedGoMod, makefile, "no vuln target whose recipe starts with go tool govulncheck")
	wantVulnProblem(t, pinnedGoMod, makefile, "pinned by version in the Makefile: go run golang.org/x/vuln/cmd/govulncheck@v1.8.0")
	if got := vulnPinProblems([]byte(pinnedGoMod), []byte(makefile)); len(got) != 2 {
		t.Fatalf("want 2 problems, got %q", got)
	}
}

func TestVulnPinProblems_NoVulnTarget(t *testing.T) {
	makefile := pinnedMakefile[:strings.Index(pinnedMakefile, "vuln:")]
	wantVulnProblem(t, pinnedGoMod, makefile, "no vuln target")
	if got := vulnPinProblems([]byte(pinnedGoMod), []byte(makefile)); len(got) != 1 {
		t.Fatalf("want 1 problem, got %q", got)
	}
}

// A Makefile comment naming the old pin is not a pin, and a go.mod written
// with CRLF line endings still carries its tool line.
func TestVulnPinProblems_CommentAndCRLF(t *testing.T) {
	commented := "# was: go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./cmd/...\n" + pinnedMakefile
	if got := vulnPinProblems([]byte(pinnedGoMod), []byte(commented)); len(got) != 0 {
		t.Fatalf("a comment reported %q", got)
	}
	crlf := strings.ReplaceAll(pinnedGoMod, "\n", "\r\n")
	if got := vulnPinProblems([]byte(crlf), []byte(pinnedMakefile)); len(got) != 0 {
		t.Fatalf("a CRLF go.mod reported %q", got)
	}
}

// The tests below run goToolchainProblems on in-memory inputs, so the guard
// is shown to fail without touching the tracked files. The Dockerfile fixture
// builds on golang:1.26-alpine and the go.mod fixture says go 1.26.0.

// toolchainGoMod is pinnedGoMod with a toolchain line.
func toolchainGoMod(tc string) string {
	return strings.Replace(pinnedGoMod, "go 1.26.0\n", "go 1.26.0\n\ntoolchain "+tc+"\n", 1)
}

func wantToolchainProblem(t *testing.T, gomod, dockerfile, fragment string) {
	t.Helper()
	got := goToolchainProblems([]byte(gomod), []byte(dockerfile))
	for _, p := range got {
		if strings.Contains(p, fragment) {
			return
		}
	}
	t.Fatalf("no problem containing %q; got %q", fragment, got)
}

// A go.mod with no toolchain line, with toolchain default, or with a
// toolchain at the image's minor passes, as does an image a minor ahead (how
// the tree stands), a tag that carries a patch, and an indented lower-case
// from instruction.
func TestGoToolchainProblems_Consistent(t *testing.T) {
	ahead := strings.Replace(pinnedDockerfile(), "golang:1.26-alpine", "golang:1.27-alpine", 1)
	patch := strings.Replace(pinnedDockerfile(), "golang:1.26-alpine", "golang:1.26.9-alpine", 1)
	lower := strings.Replace(pinnedDockerfile(), "FROM --platform=$BUILDPLATFORM golang:1.26-alpine",
		"  from --platform=$BUILDPLATFORM golang:1.26-alpine", 1)
	for _, c := range []struct{ name, gomod, dockerfile string }{
		{"no toolchain line", pinnedGoMod, pinnedDockerfile()},
		{"equal minor", toolchainGoMod("go1.26.9"), pinnedDockerfile()},
		{"toolchain default", toolchainGoMod("default"), pinnedDockerfile()},
		{"image a minor ahead", toolchainGoMod("go1.26.9"), ahead},
		{"tag with a patch", toolchainGoMod("go1.26.9"), patch},
		{"indented lower-case from", toolchainGoMod("go1.26.9"), lower},
	} {
		if got := goToolchainProblems([]byte(c.gomod), []byte(c.dockerfile)); len(got) != 0 {
			t.Fatalf("%s reported %q", c.name, got)
		}
	}
}

// A toolchain line a minor past the image is the case no build catches.
func TestGoToolchainProblems_ToolchainAhead(t *testing.T) {
	gomod := toolchainGoMod("go1.27.0")
	wantToolchainProblem(t, gomod, pinnedDockerfile(),
		"go.mod pins toolchain go1.27.0, a newer minor than the Dockerfile's golang:1.26 build image")
	if got := goToolchainProblems([]byte(gomod), []byte(pinnedDockerfile())); len(got) != 1 {
		t.Fatalf("want 1 problem, got %q", got)
	}
}

// A go line past the image is reported as well, beside the toolchain line.
func TestGoToolchainProblems_GoLineAhead(t *testing.T) {
	gomod := strings.Replace(toolchainGoMod("go1.27.0"), "go 1.26.0\n", "go 1.27.0\n", 1)
	wantToolchainProblem(t, gomod, pinnedDockerfile(), "go.mod says go 1.27.0 and the Dockerfile builds on golang:1.26")
	wantToolchainProblem(t, gomod, pinnedDockerfile(), "go.mod pins toolchain go1.27.0")
	if got := goToolchainProblems([]byte(gomod), []byte(pinnedDockerfile())); len(got) != 2 {
		t.Fatalf("want 2 problems, got %q", got)
	}
}

// A tag without a minor, and a golang stage that is only a comment, leave
// nothing to compare and fail closed.
func TestGoToolchainProblems_NoMinorTag(t *testing.T) {
	const fragment = "no FROM line with a golang:<major>.<minor> tag"
	for _, tag := range []string{"golang:alpine", "golang:1-alpine", "golang:latest"} {
		src := strings.Replace(pinnedDockerfile(), "golang:1.26-alpine", tag, 1)
		wantToolchainProblem(t, toolchainGoMod("go1.26.9"), src, fragment)
		if got := goToolchainProblems([]byte(toolchainGoMod("go1.26.9")), []byte(src)); len(got) != 1 {
			t.Fatalf("%s: want 1 problem, got %q", tag, got)
		}
	}
	commented := strings.Replace(pinnedDockerfile(), "FROM --platform=$BUILDPLATFORM golang:1.26-alpine",
		"# FROM --platform=$BUILDPLATFORM golang:1.26-alpine", 1)
	wantToolchainProblem(t, toolchainGoMod("go1.26.9"), commented, fragment)
	if got := goToolchainProblems([]byte(toolchainGoMod("go1.26.9")), []byte(commented)); len(got) != 1 {
		t.Fatalf("commented stage: want 1 problem, got %q", got)
	}
}

// A go.mod the guard cannot read fails closed rather than passing: version
// ranks an invalid name below every valid one, so the IsValid checks are what
// keep a garbled line from passing.
func TestGoToolchainProblems_Garbled(t *testing.T) {
	for _, c := range []struct{ name, gomod, fragment string }{
		{"no go line", strings.Replace(pinnedGoMod, "go 1.26.0\n", "", 1), "has no go line"},
		{"go 1.x", strings.Replace(pinnedGoMod, "go 1.26.0\n", "go 1.x\n", 1), "is not a Go version"},
		{"toolchain without the go prefix", toolchainGoMod("1.27.0"), "is not a Go toolchain name"},
	} {
		wantToolchainProblem(t, c.gomod, pinnedDockerfile(), c.fragment)
		if got := goToolchainProblems([]byte(c.gomod), []byte(pinnedDockerfile())); len(got) != 1 {
			t.Fatalf("%s: want 1 problem, got %q", c.name, got)
		}
	}
}

// Files written with CRLF line endings read the same.
func TestGoToolchainProblems_CRLF(t *testing.T) {
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	if got := goToolchainProblems([]byte(crlf(toolchainGoMod("go1.26.9"))), []byte(crlf(pinnedDockerfile()))); len(got) != 0 {
		t.Fatalf("a CRLF pair reported %q", got)
	}
	gomod := crlf(toolchainGoMod("go1.27.0"))
	wantToolchainProblem(t, gomod, crlf(pinnedDockerfile()), "go.mod pins toolchain go1.27.0")
	if got := goToolchainProblems([]byte(gomod), []byte(crlf(pinnedDockerfile()))); len(got) != 1 {
		t.Fatalf("want 1 problem, got %q", got)
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

// ciJobBlock returns the text of one job in a workflow: from the line that
// names it at two spaces of indent to the next key at that indent, or to the
// end of the file. The whole line is matched, so docker does not find
// docker-arm64. It returns "" when the job is absent.
func ciJobBlock(src, name string) string {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	head := "\n  " + name + ":\n"
	i := strings.Index(src, head)
	if i < 0 {
		return ""
	}
	rest := src[i+1:]
	lines := strings.SplitAfter(rest, "\n")
	n := len(lines[0])
	for _, line := range lines[1:] {
		if len(line) > 2 && line[0] == ' ' && line[1] == ' ' && line[2] >= 'a' && line[2] <= 'z' {
			break
		}
		n += len(line)
	}
	return rest[:n]
}

// withoutComments drops every line whose first non-space character is #, so
// a comment that names a thing is not read as the thing.
func withoutComments(block string) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

var publishNeedsArm64 = regexp.MustCompile(`(?m)^    needs: \[[^\]]*\bdocker-arm64\b[^\]]*\]`)

// ciGateProblems reports what would let publish run without the arm64 image
// having run, or let verify pull with a credential (PORM-156).
func ciGateProblems(src string) []string {
	var problems []string
	publish := withoutComments(ciJobBlock(src, "publish"))
	if publish == "" {
		problems = append(problems, "ci.yml has no publish job")
	} else if !publishNeedsArm64.MatchString(publish) {
		problems = append(problems, "publish does not need docker-arm64")
	}
	verify := withoutComments(ciJobBlock(src, "verify"))
	if verify == "" {
		problems = append(problems, "ci.yml has no verify job")
		return problems
	}
	if strings.Contains(verify, "login-action") {
		problems = append(problems, "verify logs in to a registry")
	}
	if strings.Contains(verify, "secrets.") || strings.Contains(verify, "github.token") {
		problems = append(problems, "verify reads a secret")
	}
	if strings.Contains(verify, "docker login") {
		problems = append(problems, "verify runs docker login")
	}
	if strings.Contains(verify, "packages:") {
		problems = append(problems, "verify asks for a packages permission")
	}
	return problems
}

// TestImageJobsGated keeps publish behind the arm64 image check, and keeps
// the verify job free of a login, a secret, the job token and a packages
// permission, so its pull stays anonymous (PORM-156). The red proof on the issue's
// branch showed the gate once; this keeps it.
func TestImageJobsGated(t *testing.T) {
	root := repoRoot(t)
	for _, p := range ciGateProblems(string(readRepoFile(t, root, ".github/workflows/ci.yml"))) {
		t.Error(p)
	}
}

// The tests below run ciGateProblems on an in-memory workflow, so the guard
// is shown to fail without touching ci.yml.

const gatedWorkflow = "name: ci\n\njobs:\n" +
	"  docker:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo docker\n\n" +
	"  docker-arm64:\n    runs-on: ubuntu-24.04-arm\n    steps:\n      - run: echo arm\n\n" +
	"  publish:\n    needs: [go, web, docker, docker-arm64]\n    steps:\n" +
	"      - uses: docker/login-action@0000000000000000000000000000000000000000 # v1.0.0\n" +
	"        with:\n          password: ${{ secrets.GITHUB_TOKEN }}\n\n" +
	"  verify:\n    needs: publish\n    steps:\n      - run: docker pull \"$REPO@$DIGEST\"\n"

func wantGateProblem(t *testing.T, src, fragment string) {
	t.Helper()
	got := ciGateProblems(src)
	for _, p := range got {
		if strings.Contains(p, fragment) {
			return
		}
	}
	t.Fatalf("no problem containing %q; got %q", fragment, got)
}

// publish's own login and secret are not verify's.
func TestCIGateProblems_Gated(t *testing.T) {
	if got := ciGateProblems(gatedWorkflow); len(got) != 0 {
		t.Fatalf("a gated workflow reported %q", got)
	}
	crlf := strings.ReplaceAll(gatedWorkflow, "\n", "\r\n")
	if got := ciGateProblems(crlf); len(got) != 0 {
		t.Fatalf("a CRLF workflow reported %q", got)
	}
}

func TestCIGateProblems_PublishNotGated(t *testing.T) {
	src := strings.Replace(gatedWorkflow, "[go, web, docker, docker-arm64]", "[go, web, docker]", 1)
	wantGateProblem(t, src, "publish does not need docker-arm64")
}

// The docker job's block ends where docker-arm64 starts, a name is matched as
// the whole key, and a needs line naming docker alone is not read as naming
// docker-arm64.
func TestCIGateProblems_DockerIsNotDockerArm64(t *testing.T) {
	if got := ciJobBlock(gatedWorkflow, "docker-arm"); got != "" {
		t.Fatalf("a prefix of a job name found a block: %q", got)
	}
	if got := ciJobBlock(gatedWorkflow, "docker"); strings.Contains(got, "ubuntu-24.04-arm") {
		t.Fatalf("the docker block ran into docker-arm64: %q", got)
	}
	src := strings.Replace(gatedWorkflow, "[go, web, docker, docker-arm64]", "[go, web, docker] # docker-arm64", 1)
	wantGateProblem(t, src, "publish does not need docker-arm64")
}

func TestCIGateProblems_NoVerify(t *testing.T) {
	src := gatedWorkflow[:strings.Index(gatedWorkflow, "  verify:")]
	wantGateProblem(t, src, "no verify job")
}

func TestCIGateProblems_VerifyLogsIn(t *testing.T) {
	src := gatedWorkflow + "      - uses: docker/login-action@0000000000000000000000000000000000000000 # v1.0.0\n"
	wantGateProblem(t, src, "verify logs in")
}

func TestCIGateProblems_VerifyReadsSecret(t *testing.T) {
	src := gatedWorkflow + "        env:\n          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
	wantGateProblem(t, src, "verify reads a secret")
}

func TestCIGateProblems_VerifyReadsToken(t *testing.T) {
	src := gatedWorkflow + "        env:\n          TOKEN: ${{ github.token }}\n"
	wantGateProblem(t, src, "verify reads a secret")
}

func TestCIGateProblems_VerifyRunsDockerLogin(t *testing.T) {
	src := gatedWorkflow + "      - run: docker login ghcr.io -u x --password-stdin\n"
	wantGateProblem(t, src, "verify runs docker login")
}

func TestCIGateProblems_VerifyPackagesPermission(t *testing.T) {
	src := strings.Replace(gatedWorkflow, "  verify:\n    needs: publish\n",
		"  verify:\n    needs: publish\n    permissions:\n      contents: read\n      packages: read\n", 1)
	wantGateProblem(t, src, "verify asks for a packages permission")
}

// A comment in verify that names secrets. or the login action is not a use.
func TestCIGateProblems_CommentIgnored(t *testing.T) {
	src := gatedWorkflow + "      # no secrets. reference and no docker/login-action here\n"
	if got := ciGateProblems(src); len(got) != 0 {
		t.Fatalf("a comment reported %q", got)
	}
}
