//go:build unix

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The tests below run scripts/edge-deploy.sh (PORM-220) with bash against a
// stub of the deploy platform's two routes. Every value the script must never
// print is a canary: the token, the app uuid in the webhook query, the whole
// webhook URL and the status record's logs field.
const (
	edTokenCanary = "edTokenCanaryQz9"
	edAppCanary   = "edAppCanaryXv7"
	edLogsCanary  = "edLogsCanaryWk4"
	edID          = "dep-Ab12_cd"
	edFixedError  = "::error title=edge-deploy::the deploy failed; see the step log"
)

type stubAnswer struct {
	code int
	body string
}

type stubHit struct {
	method, path, query, auth string
}

// deployStub answers POST /api/v1/deploy with webhook and each
// GET /api/v1/deployments/{id} with the next entry of statuses; the last
// entry repeats.
type deployStub struct {
	srv      *httptest.Server
	webhook  stubAnswer
	location string
	statuses []stubAnswer

	mu   sync.Mutex
	hits []stubHit
	poll int
}

func newDeployStub(t *testing.T, webhook stubAnswer, statuses ...stubAnswer) *deployStub {
	t.Helper()
	s := &deployStub{webhook: webhook, statuses: statuses}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *deployStub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, stubHit{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/deploy":
		if s.location != "" {
			w.Header().Set("Location", s.location)
		}
		w.WriteHeader(s.webhook.code)
		fmt.Fprint(w, s.webhook.body)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/deployments/") && len(s.statuses) > 0:
		a := s.statuses[min(s.poll, len(s.statuses)-1)]
		s.poll++
		w.WriteHeader(a.code)
		fmt.Fprint(w, a.body)
	default:
		w.WriteHeader(http.StatusTeapot)
	}
}

func (s *deployStub) recorded() []stubHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubHit(nil), s.hits...)
}

// webhookURL is the stub's deploy route with the app canary in its query.
func (s *deployStub) webhookURL() string {
	return s.srv.URL + "/api/v1/deploy?uuid=" + edAppCanary
}

func queued(id, msg string) stubAnswer {
	return stubAnswer{200, fmt.Sprintf(`{"deployments":[{"message":%q,"resource_uuid":"r1","deployment_uuid":%q}]}`, msg, id)}
}

func status(s string) stubAnswer {
	return stubAnswer{200, fmt.Sprintf(`{"status":%q,"logs":%q}`, s, edLogsCanary)}
}

// edgeEnv is the environment of one run: PATH and HOME and nothing else
// inherited, so a developer's own DEPLOY_* never reaches the script.
func edgeEnv(t *testing.T, stub *deployStub) map[string]string {
	env := map[string]string{
		"PATH":                 os.Getenv("PATH"),
		"HOME":                 t.TempDir(),
		"EDGE_DEPLOY_INTERVAL": "0.05",
		// $SECONDS counts whole seconds, so a budget of 1 can end before the
		// first poll. Only the Budget case shortens it further.
		"EDGE_DEPLOY_BUDGET": "10",
		"DEPLOY_TOKEN":       edTokenCanary,
	}
	if stub != nil {
		env["DEPLOY_WEBHOOK_URL"] = stub.webhookURL()
	}
	return env
}

// runEdgeDeploy runs the script with exactly env, bash flags first, and
// returns both streams, the exit code and the step summary it wrote.
func runEdgeDeploy(t *testing.T, env map[string]string, bashArgs ...string) (stdout, stderr string, code int, summary string) {
	t.Helper()
	sum := filepath.Join(t.TempDir(), "summary.md")
	if err := os.WriteFile(sum, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// repoRoot is relative and the run's directory is a temporary one.
	script, err := filepath.Abs(filepath.Join(repoRoot(t), "scripts", "edge-deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	args := append(append([]string(nil), bashArgs...), script)
	cmd := exec.Command("bash", args...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"GITHUB_STEP_SUMMARY=" + sum}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("running the script: %v", err)
	}
	b, rerr := os.ReadFile(sum)
	if rerr != nil {
		t.Fatal(rerr)
	}
	return out.String(), errb.String(), code, string(b)
}

// assertNoSecret fails when any canary appears in any stream, in the wording
// of the process tests' hygiene check (binary_test.go).
func assertNoSecret(t *testing.T, canaries, streams map[string]string) {
	t.Helper()
	for sname, s := range streams {
		for cname, c := range canaries {
			if c == "" {
				continue
			}
			if i := strings.Index(s, c); i >= 0 {
				t.Errorf("captured %s line %d contains the %s", sname, lineOf(s, i), cname)
			}
		}
	}
}

func TestEdgeDeploy(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("GITHUB_ACTIONS") == "true" {
				t.Fatalf("%s is not on PATH; the deploy job needs it", tool)
			}
			t.Skipf("%s is not on PATH", tool)
		}
	}

	type result struct {
		stdout, stderr, summary string
		code                    int
		stub                    *deployStub
	}
	// run drives one case and applies the checks every case shares: no
	// canary in any output, and every request carried the token.
	run := func(t *testing.T, stub *deployStub, env map[string]string, bashArgs ...string) result {
		t.Helper()
		stdout, stderr, code, summary := runEdgeDeploy(t, env, bashArgs...)
		canaries := map[string]string{"token": edTokenCanary, "app uuid": edAppCanary, "logs field": edLogsCanary}
		if stub != nil {
			canaries["webhook URL"] = stub.webhookURL()
			for _, h := range stub.recorded() {
				if h.auth != "Bearer "+edTokenCanary {
					t.Errorf("%s %s reached the stub with Authorization %q", h.method, h.path, h.auth)
				}
			}
		}
		assertNoSecret(t, canaries, map[string]string{"stdout": stdout, "stderr": stderr, "summary": summary})
		return result{stdout, stderr, summary, code, stub}
	}
	wantCode := func(t *testing.T, r result, want int) {
		t.Helper()
		if r.code != want {
			t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, want, r.stdout, r.stderr)
		}
	}
	wantOut := func(t *testing.T, r result, subs ...string) {
		t.Helper()
		all := r.stdout + r.stderr
		for _, s := range subs {
			if !strings.Contains(all, s) {
				t.Errorf("output lacks %q\nstdout:\n%s\nstderr:\n%s", s, r.stdout, r.stderr)
			}
		}
	}
	noHits := func(t *testing.T, stub *deployStub) {
		t.Helper()
		if hits := stub.recorded(); len(hits) != 0 {
			t.Errorf("the stub saw %d requests, want none: %v", len(hits), hits)
		}
	}
	gets := func(stub *deployStub) int {
		n := 0
		for _, h := range stub.recorded() {
			if h.method == http.MethodGet {
				n++
			}
		}
		return n
	}

	// Acceptance criterion 1: finished exits 0, the summary names the id and
	// the status, and the webhook is called once with no force.
	t.Run("Finished", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "Deployment request queued."), status("queued"), status("in_progress"), status("finished"))
		r := run(t, stub, edgeEnv(t, stub))
		wantCode(t, r, 0)
		wantOut(t, r, "PASS deploy: "+edID+" finished", "deploy: requested "+edID+": Deployment request queued.")
		if want := "Deployment `" + edID + "`: finished"; !strings.Contains(r.summary, want) {
			t.Errorf("summary %q lacks %q", r.summary, want)
		}
		posts := 0
		for _, h := range stub.recorded() {
			if h.method == http.MethodPost {
				posts++
				if strings.Contains(h.query, "force") {
					t.Errorf("the webhook query carries force: %q", h.query)
				}
			}
		}
		if posts != 1 {
			t.Errorf("%d webhook calls, want 1", posts)
		}
	})

	// Acceptance criterion 1: failed and cancelled-by-user exit 1.
	for _, s := range []string{"failed", "cancelled-by-user"} {
		name := map[string]string{"failed": "Failed", "cancelled-by-user": "CancelledByUser"}[s]
		t.Run(name, func(t *testing.T) {
			stub := newDeployStub(t, queued(edID, "queued"), status("in_progress"), status(s))
			r := run(t, stub, edgeEnv(t, stub))
			wantCode(t, r, 1)
			wantOut(t, r, "FAIL deploy: "+edID+" "+s)
			if want := "Deployment `" + edID + "`: " + s; !strings.Contains(r.summary, want) {
				t.Errorf("summary %q lacks %q", r.summary, want)
			}
		})
	}

	// Acceptance criterion 1: an answer with no deployment id exits 1 and
	// prints the platform's message.
	t.Run("NoDeploymentID", func(t *testing.T) {
		stub := newDeployStub(t, stubAnswer{200, `{"deployments":[{"message":"No resources found."}]}`})
		r := run(t, stub, edgeEnv(t, stub))
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL deploy: the answer has no valid deployment id: No resources found.")
		if gets(stub) != 0 {
			t.Error("the script polled with no id")
		}
	})

	// Acceptance criterion 1 (401) and the queue-full answer (429): exit 1,
	// printing the code and the message.
	for _, c := range []int{401, 429} {
		t.Run(fmt.Sprintf("WebhookError/%d", c), func(t *testing.T) {
			stub := newDeployStub(t, stubAnswer{c, `{"message":"Unauthenticated."}`})
			r := run(t, stub, edgeEnv(t, stub))
			wantCode(t, r, 1)
			wantOut(t, r, fmt.Sprintf("FAIL deploy: HTTP %d: Unauthenticated.", c))
			if !strings.Contains(r.summary, "Deploy not started") {
				t.Errorf("summary %q does not say the deploy was not started", r.summary)
			}
		})
	}

	// A request while one is in flight answers with the existing id; the run
	// follows it and prints the message (plan, platform answers).
	t.Run("AlreadyQueued", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "Deployment already queued for this commit."), status("finished"))
		r := run(t, stub, edgeEnv(t, stub))
		wantCode(t, r, 0)
		wantOut(t, r, "Deployment already queued for this commit.")
	})

	// Acceptance criterion 1 and security requirement 8: a status that never
	// finishes fails at the budget with the last status printed clean, and
	// an unknown status reaches the summary as unknown only.
	t.Run("Budget", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), status("in_progress"), status("weird`x`[a](b)"))
		env := edgeEnv(t, stub)
		env["EDGE_DEPLOY_BUDGET"] = "2"
		r := run(t, stub, env)
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL deploy: "+edID+" did not finish in 2s; last status weird`x`[a](b)")
		if !strings.Contains(r.summary, "Deployment `"+edID+"`: unknown") || strings.Contains(r.summary, "[a](b)") {
			t.Errorf("summary %q is not the enum-only form", r.summary)
		}
	})

	// The poll rule: a 5xx and a 2xx with no status keep waiting; 404 fails
	// at once.
	t.Run("PollErrors/502ThenFinished", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), stubAnswer{502, `bad gateway`}, stubAnswer{200, `{}`}, status("finished"))
		r := run(t, stub, edgeEnv(t, stub))
		wantCode(t, r, 0)
	})
	t.Run("PollErrors/404", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), stubAnswer{404, `{"message":"Deployment not found."}`}, status("finished"))
		r := run(t, stub, edgeEnv(t, stub))
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL deploy: "+edID+": HTTP 404: Deployment not found.")
		if n := gets(stub); n != 1 {
			t.Errorf("%d polls after a 404, want 1", n)
		}
	})

	// Acceptance criterion 1: no secrets exits 0 with the notice.
	t.Run("NoSecrets", func(t *testing.T) {
		env := edgeEnv(t, nil)
		delete(env, "DEPLOY_TOKEN")
		env["GITHUB_ACTIONS"] = "true"
		r := run(t, nil, env)
		wantCode(t, r, 0)
		wantOut(t, r, "edge-deploy: no deployment is configured; nothing requested", "::notice title=edge-deploy::no deployment is configured")
		if !strings.Contains(r.summary, "No deployment is configured; nothing was requested") {
			t.Errorf("summary %q lacks the notice", r.summary)
		}
	})

	// Acceptance criterion 1: one secret set exits 1.
	t.Run("OneSecret/url", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), status("finished"))
		env := edgeEnv(t, stub)
		delete(env, "DEPLOY_TOKEN")
		r := run(t, stub, env)
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL input: DEPLOY_WEBHOOK_URL is set and DEPLOY_TOKEN is not")
		noHits(t, stub)
	})
	t.Run("OneSecret/token", func(t *testing.T) {
		r := run(t, nil, edgeEnv(t, nil))
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL input: DEPLOY_TOKEN is set and DEPLOY_WEBHOOK_URL is not")
	})

	// Security requirement 5: a trace would print the secrets, so both ways
	// of turning it on are refused before any request.
	t.Run("Xtrace/flag", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), status("finished"))
		r := run(t, stub, edgeEnv(t, stub), "-x")
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL input: xtrace is on")
		noHits(t, stub)
	})
	t.Run("Xtrace/shellopts", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), status("finished"))
		env := edgeEnv(t, stub)
		env["SHELLOPTS"] = "xtrace"
		r := run(t, stub, env)
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL input: xtrace is on")
		noHits(t, stub)
	})

	// Security requirement 6: input that could break the curl config, send
	// the token in clear or to another host, or busy-loop is refused, naming
	// the variable and never its value.
	t.Run("RejectsInput", func(t *testing.T) {
		stub := newDeployStub(t, queued(edID, "queued"), status("finished"))
		cases := []struct{ name, key, value, want string }{
			{"token quote", "DEPLOY_TOKEN", `ab"cd`, "DEPLOY_TOKEN"},
			{"token newline", "DEPLOY_TOKEN", "ab\nurl = \"http://127.0.0.1:1/\"", "DEPLOY_TOKEN"},
			{"token space", "DEPLOY_TOKEN", "ab cd", "DEPLOY_TOKEN"},
			{"plain http", "DEPLOY_WEBHOOK_URL", "http://deploy.invalid/api/v1/deploy?uuid=" + edAppCanary, "DEPLOY_WEBHOOK_URL"},
			{"userinfo", "DEPLOY_WEBHOOK_URL", "http://127.0.0.1:80@deploy.invalid/api/v1/deploy?uuid=" + edAppCanary, "DEPLOY_WEBHOOK_URL"},
			{"lookalike host", "DEPLOY_WEBHOOK_URL", "http://127.0.0.1.deploy.invalid/api/v1/deploy?uuid=" + edAppCanary, "DEPLOY_WEBHOOK_URL"},
			{"url quote", "DEPLOY_WEBHOOK_URL", stub.webhookURL() + `"`, "DEPLOY_WEBHOOK_URL"},
			{"interval zero", "EDGE_DEPLOY_INTERVAL", "0", "EDGE_DEPLOY_INTERVAL"},
			{"interval injection", "EDGE_DEPLOY_INTERVAL", "1;x", "EDGE_DEPLOY_INTERVAL"},
			{"budget too long", "EDGE_DEPLOY_BUDGET", "9999", "EDGE_DEPLOY_BUDGET"},
		}
		for _, c := range cases {
			env := edgeEnv(t, stub)
			env[c.key] = c.value
			stdout, stderr, code, _ := runEdgeDeploy(t, env)
			all := stdout + stderr
			if code != 1 || !strings.Contains(all, "FAIL input: "+c.want) {
				t.Errorf("%s: exit %d, output %q; want exit 1 naming %s", c.name, code, all, c.want)
			}
			// A value as short as "0" is part of the message's own wording.
			if (len(c.value) > 3 && strings.Contains(all, c.value)) || strings.Contains(all, edAppCanary) {
				t.Errorf("%s: the output holds the rejected value: %q", c.name, all)
			}
		}
		noHits(t, stub)
	})

	// Security requirement 7: a redirect is never followed, so the token
	// never reaches a second host.
	t.Run("Redirect", func(t *testing.T) {
		other := newDeployStub(t, queued(edID, "queued"), status("finished"))
		stub := newDeployStub(t, stubAnswer{302, ``})
		stub.location = other.webhookURL()
		r := run(t, stub, edgeEnv(t, stub))
		wantCode(t, r, 1)
		wantOut(t, r, "FAIL deploy: HTTP 302")
		noHits(t, other)
	})

	// Security requirement 8: platform text reaches the public log as
	// printable ASCII with no %, cut to 200 bytes, behind a fixed prefix, and
	// the only workflow command is the fixed annotation.
	t.Run("HostileAnswer", func(t *testing.T) {
		msg := "::error::x\x1b[31m%0A::warning::y\nnext " + strings.Repeat("A", 5000)
		stub := newDeployStub(t, stubAnswer{401, fmt.Sprintf(`{"message":%q}`, msg)})
		env := edgeEnv(t, stub)
		env["GITHUB_ACTIONS"] = "true"
		r := run(t, stub, env)
		wantCode(t, r, 1)
		all := r.stdout + r.stderr
		const prefix = "FAIL deploy: HTTP 401: "
		for _, line := range strings.Split(all, "\n") {
			if strings.HasPrefix(line, "::") && line != edFixedError {
				t.Errorf("a workflow command reached the log: %q", line)
			}
			if strings.HasPrefix(line, prefix) && len(line) > len(prefix)+200 {
				t.Errorf("the message is %d bytes, want at most 200", len(line)-len(prefix))
			}
		}
		if strings.ContainsAny(all, "\x1b%") {
			t.Errorf("an escape or a %% reached the log: %q", all)
		}
		if !strings.Contains(all, edFixedError) {
			t.Errorf("no fixed annotation in %q", all)
		}
	})

	// Security requirement 8: an id that is not an id never reaches a URL.
	for _, id := range []string{"../x", "a?b"} {
		t.Run("BadID/"+id, func(t *testing.T) {
			stub := newDeployStub(t, queued(id, "queued"), status("finished"))
			r := run(t, stub, edgeEnv(t, stub))
			wantCode(t, r, 1)
			wantOut(t, r, "FAIL deploy: the answer has no valid deployment id")
			if gets(stub) != 0 {
				t.Error("the script polled with an invalid id")
			}
		})
	}
}
