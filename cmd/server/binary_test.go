//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/danjonesio/porymcp/internal/models"
)

// PORM-158: the binary as an operator runs it. Every TestBinary* case builds
// ./cmd/server once, starts it as a child process with an environment of its
// own, a temporary data directory and port 0, and reads its JSON log, its
// exit code and its HTTP answers. The in-process tests in this package pin
// the router and the handlers; these pin the joins between them: config,
// store, encryption check, listener, signal handler, exit code.
//
// The child never inherits os.Environ(): a developer's DATABASE_URL,
// PUBLIC_URL, TLS_*, HTTP_PROXY or WEB_ROOT would change what is tested or
// write to a real database. Keys travel in the environment, never argv.

const (
	listenDeadline   = 10 * time.Second
	badStartDeadline = 5 * time.Second
	requestTimeout   = 5 * time.Second
	rowsDeadline     = 5 * time.Second
	// cleanupStop sits above Shutdown's 10 s plus the auditor's 5 s drain,
	// so a slow drain fails as slow rather than as killed.
	cleanupStop = 16 * time.Second
	// listeningMsg is the record startBinary waits for.
	listeningMsg = "porymcp listening"
)

var (
	binOnce sync.Once
	binDir  string
	binPath string
	binErr  error
	binLog  []byte
)

// TestMain only removes the build directory after the run. The build itself
// is lazy (binaryPath), so a -run filter that selects no binary test, the CI
// guard step included, never pays for a link.
func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// skipUnlessBinary skips under -short. testing.Short is read inside a test,
// where the flags are parsed.
func skipUnlessBinary(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts the built binary; skipped under -short")
	}
}

// binaryPath builds ./cmd/server once per test binary run, on first use,
// into a private temporary directory. The build inherits the environment
// (GOCACHE, HOME, GOFLAGS; go build ignores -count=1) plus GOTOOLCHAIN=local
// and GOPROXY=off, so a missing module or toolchain fails loudly instead of
// downloading. Under the race detector the child is built with -race too.
func binaryPath(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		t.Log("building the server binary")
		dir, err := os.MkdirTemp("", "porymcp-binary-")
		if err != nil {
			binErr = err
			return
		}
		binDir = dir
		binPath = filepath.Join(dir, "porymcp")
		args := []string{"build", "-o", binPath}
		if raceBuild {
			args = append(args, "-race")
		}
		args = append(args, ".")
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
		binLog, binErr = cmd.CombinedOutput()
	})
	if binErr != nil {
		t.Fatalf("building the server binary: %v\n%s", binErr, binLog)
	}
	return binPath
}

// childEnv is the one place the race runtime setting is added: vars plus
// GORACE=atexit_sleep_ms=0 when raceBuild, so an exit with status 0 does not
// sleep for a second. baseEnv and runHealthcheck both call it.
func childEnv(vars ...string) []string {
	env := append([]string(nil), vars...)
	if raceBuild {
		env = append(env, "GORACE=atexit_sleep_ms=0")
	}
	return env
}

// baseEnv is the server child's whole environment. kv pairs override the
// defaults; an empty value removes the variable.
func baseEnv(t *testing.T, kv ...string) []string {
	t.Helper()
	if len(kv)%2 != 0 {
		t.Fatalf("baseEnv: %d values, want pairs", len(kv))
	}
	vars := map[string]string{
		"ADMIN_API_KEY":  hex.EncodeToString(mustKey(t)),
		"ENCRYPTION_KEY": hex.EncodeToString(mustKey(t)),
		"DATA_DIR":       t.TempDir(),
		"LISTEN_ADDR":    "127.0.0.1:0",
		"LOG_LEVEL":      "info",
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(vars, kv[i])
			continue
		}
		vars[kv[i]] = kv[i+1]
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	list := make([]string, 0, len(names))
	for _, k := range names {
		list = append(list, k+"="+vars[k])
	}
	return childEnv(list...)
}

// envValue returns the value of name in env, or "".
func envValue(env []string, name string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}

// secret is one value the hygiene check scans for. onceIn names the one
// stdout record (by msg) that may carry it exactly once; "" means never.
// windowed also scans the two streams for every 8-byte window of the value,
// for a non-hex token where a window cannot collide with a request id.
type secret struct {
	label    string
	value    string
	onceIn   string
	windowed bool
}

// phase is one point in a case, measured from the spawn.
type phase struct {
	name string
	at   time.Duration
}

// proc is one started child. Everything the test asserts on is read from here.
type proc struct {
	t        *testing.T
	cmd      *exec.Cmd
	tr       *http.Transport
	stdout   *lockedLog
	stderr   *lockedLog
	done     chan struct{}
	code     int
	addr     string
	dataDir  string
	adminKey string
	secrets  []secret
	phases   []phase
	started  time.Time
}

// newProc starts the binary with env and nothing else. Plain exec.Command,
// never CommandContext: t.Context is cancelled before Cleanup runs and the
// default Cancel is Kill, which would end the SIGTERM case with a signal
// exit. cmd.Dir is a fresh temporary directory, so ./data and web/out never
// resolve into the repository and the embedded dashboard serves. Two
// cleanups are registered in this order: checkHygiene, then stop; LIFO means
// stop runs first.
func newProc(t *testing.T, env []string, extra ...secret) *proc {
	t.Helper()
	p := &proc{
		t:      t,
		tr:     &http.Transport{},
		stdout: &lockedLog{},
		stderr: &lockedLog{},
		done:   make(chan struct{}),
	}
	p.registerSecrets(env)
	p.secrets = append(p.secrets, extra...)
	cmd := exec.Command(binaryPath(t))
	cmd.Env = env
	cmd.Dir = t.TempDir()
	cmd.Stdout = p.stdout
	cmd.Stderr = p.stderr
	cmd.WaitDelay = 2 * time.Second
	p.cmd = cmd
	t.Cleanup(func() { p.checkHygiene(t) })
	t.Cleanup(func() { p.stop(t, cleanupStop) })
	p.started = time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	p.mark("spawn")
	go func() {
		err := cmd.Wait()
		p.code = -1
		if cmd.ProcessState != nil {
			p.code = cmd.ProcessState.ExitCode()
		}
		if err != nil && cmd.ProcessState == nil {
			p.stderr.Write([]byte("wait: " + err.Error() + "\n"))
		}
		close(p.done)
	}()
	return p
}

// registerSecrets reads the final env slice and records every key value in
// it: the value verbatim and, only when it is 64 hex characters, its
// upper-case hex and the standard base64 of the raw bytes. It also takes
// dataDir and adminKey from the same slice.
func (p *proc) registerSecrets(env []string) {
	p.dataDir = envValue(env, "DATA_DIR")
	p.adminKey = envValue(env, "ADMIN_API_KEY")
	add := func(label, v string) {
		if v == "" {
			return
		}
		p.secret(label, v)
		raw, err := hex.DecodeString(v)
		if err != nil || len(raw) != 32 {
			return
		}
		p.secret(label+" (upper-case hex)", strings.ToUpper(v))
		p.secret(label+" (base64)", base64.StdEncoding.EncodeToString(raw))
	}
	add("admin key", p.adminKey)
	add("encryption key", envValue(env, "ENCRYPTION_KEY"))
	for _, prev := range strings.Split(envValue(env, "ENCRYPTION_KEY_PREVIOUS"), ",") {
		add("previous encryption key", strings.TrimSpace(prev))
	}
}

// startBinary starts the server and waits for the listening record. The
// bound address must be on 127.0.0.1 and must not be port 0, which is the
// check that proves the tests read the log rather than guess.
func startBinary(t *testing.T, env []string, extra ...secret) *proc {
	t.Helper()
	p := newProc(t, env, extra...)
	rec := p.waitFor(t, listeningMsg, func(r map[string]any) bool { return r["msg"] == listeningMsg }, listenDeadline)
	addr, _ := rec["addr"].(string)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listening line carries an unexpected host: %q", addr)
	}
	if strings.HasSuffix(addr, ":0") {
		t.Fatalf("listening line carries port 0: %q", addr)
	}
	p.addr = addr
	return p
}

// startExpectExit starts the server and waits for it to exit on its own
// within badStartDeadline. It asserts no listening record was written and
// returns the exit code.
func startExpectExit(t *testing.T, env []string, extra ...secret) (*proc, int) {
	t.Helper()
	p := newProc(t, env, extra...)
	select {
	case <-p.done:
	case <-time.After(badStartDeadline):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Fatalf("process still running after %v; killed\n%s", badStartDeadline, p.dump())
	}
	p.mark("exit")
	if recs := p.find(t, listeningMsg); len(recs) > 0 {
		t.Errorf("a start that must fail logged %q\n%s", listeningMsg, p.dump())
	}
	return p, p.code
}

// stop is idempotent and safe after a bad start. It sends SIGTERM and waits
// up to within; on overrun it kills, waits, and fails. It returns the exit
// code.
func (p *proc) stop(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case <-p.done:
		return p.code
	default:
	}
	if p.cmd.Process == nil {
		return -1
	}
	p.tr.CloseIdleConnections()
	p.mark("SIGTERM sent")
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("SIGTERM: %v", err)
	}
	select {
	case <-p.done:
		p.mark("exit")
		return p.code
	case <-time.After(within):
		_ = p.cmd.Process.Kill()
		<-p.done
		p.mark("killed")
		t.Errorf("process did not exit within %v of SIGTERM; killed\n%s", within, p.dump())
		return p.code
	}
}

// exited reports whether the child has exited.
func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// records decodes stdout only. While the child runs, the text is the buffer
// up to its last newline, so a record the copy goroutine has half-written is
// never decoded; after it exits, the whole buffer. stderr is never decoded:
// a panic or a race report is not JSON.
func (p *proc) records(t *testing.T) []map[string]any {
	t.Helper()
	text := p.stdout.String()
	if !p.exited() {
		i := strings.LastIndex(text, "\n")
		if i < 0 {
			return nil
		}
		text = text[:i+1]
	}
	return decodeLogRecords(t, bytes.NewBufferString(text))
}

// find returns the records whose msg equals msg.
func (p *proc) find(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range p.records(t) {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// requireLine returns the one record with msg, or fails.
func (p *proc) requireLine(t *testing.T, msg string) map[string]any {
	t.Helper()
	recs := p.find(t, msg)
	if len(recs) == 0 {
		t.Fatalf("no record with msg %q\n%s", msg, p.dump())
	}
	return recs[0]
}

// waitFor polls the records every 10 ms until pred matches, the child
// exits, or d passes.
func (p *proc) waitFor(t *testing.T, what string, pred func(map[string]any) bool, d time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		for _, r := range p.records(t) {
			if pred(r) {
				p.mark(what)
				return r
			}
		}
		select {
		case <-p.done:
			for _, r := range p.records(t) {
				if pred(r) {
					p.mark(what)
					return r
				}
			}
			t.Fatalf("process exited (code %d) before %s\n%s", p.code, what, p.dump())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not seen within %v\n%s", what, d, p.dump())
		}
	}
}

// request sends one HTTP request to the child through a bare Transport: a
// client literal, http.DefaultClient or http.Get here would fail
// TestNoSecondCredentialCarryingHTTPClient, and a Transport follows no
// redirect and reads no proxy variable. The body is read whole and scanned
// for every registered secret.
func (p *proc) request(t *testing.T, method, path string, hdr http.Header, body string) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://"+p.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := p.tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", method, path, err, p.dump())
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body: %v", method, path, err)
	}
	p.mark(method + " " + path)
	for _, s := range p.secrets {
		if bytes.Contains(b, []byte(s.value)) {
			t.Errorf("response body for %s %s contains the %s", method, path, s.label)
		}
	}
	return resp.StatusCode, b
}

// admin sends a management request with the admin key and requires want.
// A JSON object body is decoded and returned; any other body gives nil.
func (p *proc) admin(t *testing.T, method, path, body string, want int) map[string]any {
	t.Helper()
	hdr := http.Header{"Authorization": {"Bearer " + p.adminKey}}
	if body != "" {
		hdr.Set("Content-Type", "application/json")
	}
	status, b := p.request(t, method, path, hdr, body)
	if status != want {
		t.Fatalf("%s %s: status %d, want %d; body %s", method, path, status, want, p.redact(string(b)))
	}
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s %s: body is not a JSON object: %v", method, path, err)
	}
	return out
}

// mcp sends one JSON-RPC request through the proxy door, with the plaintext
// in both Authorization and X-Api-Key so the strip of both headers is
// exercised (auth reads Authorization first).
func (p *proc) mcp(t *testing.T, keyID, plaintext, rpc string) (int, []byte) {
	t.Helper()
	hdr := http.Header{
		"Authorization": {"Bearer " + plaintext},
		"X-Api-Key":     {plaintext},
		"Content-Type":  {"application/json"},
		"Accept":        {"application/json, text/event-stream"},
	}
	return p.request(t, http.MethodPost, "/"+keyID+"/mcp", hdr, rpc)
}

// waitRows polls GET /api/v1/logs?query every 20 ms until it returns want
// rows or rowsDeadline passes. The audit writer runs on its own goroutine,
// so the row a request produced is not readable the instant its answer
// comes back.
func (p *proc) waitRows(t *testing.T, query string, want int) []models.AuditLog {
	t.Helper()
	deadline := time.Now().Add(rowsDeadline)
	hdr := http.Header{"Authorization": {"Bearer " + p.adminKey}}
	for {
		status, b := p.request(t, http.MethodGet, "/api/v1/logs?"+query, hdr, "")
		rows := decodeLogsBytes(t, status, b)
		if len(rows) >= want {
			p.mark("rows seen")
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /api/v1/logs?%s: %d rows after %v, want %d\n%s", query, len(rows), rowsDeadline, want, p.dump())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// secret adds a value the hygiene check scans for.
func (p *proc) secret(label, value string) {
	p.secrets = append(p.secrets, secret{label: label, value: value})
}

// secretWindowed adds a non-hex value scanned whole and by 8-byte windows.
func (p *proc) secretWindowed(label, value string) {
	p.secrets = append(p.secrets, secret{label: label, value: value, windowed: true})
}

// secretOnce adds a value that may appear exactly once, on the stdout record
// whose msg is onceIn, and nowhere else.
func (p *proc) secretOnce(label, value, onceIn string) {
	p.secrets = append(p.secrets, secret{label: label, value: value, onceIn: onceIn})
}

// redact replaces every registered secret in s with its label.
func (p *proc) redact(s string) string {
	for _, sec := range p.secrets {
		s = strings.ReplaceAll(s, sec.value, "<"+sec.label+">")
	}
	return s
}

func (p *proc) mark(name string) {
	p.phases = append(p.phases, phase{name: name, at: time.Since(p.started)})
}

// phaseTable is the harness's own timeline plus the deltas between the
// child's startup records, so a slow start names its phase.
func (p *proc) phaseTable() string {
	var b strings.Builder
	for _, ph := range p.phases {
		fmt.Fprintf(&b, "  %-24s %v\n", ph.name, ph.at.Round(time.Millisecond))
	}
	var last time.Time
	for _, line := range strings.Split(p.stdout.String(), "\n") {
		var rec struct {
			Time time.Time `json:"time"`
			Msg  string    `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		switch rec.Msg {
		case "upstream guard", "schema migrated", "encryption key verified", listeningMsg:
			if !last.IsZero() {
				fmt.Fprintf(&b, "  child: %-28s +%v\n", rec.Msg, rec.Time.Sub(last).Round(time.Millisecond))
			} else {
				fmt.Fprintf(&b, "  child: %-28s\n", rec.Msg)
			}
			last = rec.Time
		}
	}
	return b.String()
}

// dump is the failure text: the phase table and the last 20 lines of each
// stream, every line redacted. CI logs on a public repository are public.
func (p *proc) dump() string {
	tail := func(name, s string) string {
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		return name + ":\n  " + p.redact(strings.Join(lines, "\n  "))
	}
	return "phases:\n" + p.phaseTable() + tail("stdout", p.stdout.String()) + "\n" + tail("stderr", p.stderr.String())
}

// lineOf returns the 1-based line number of byte offset i in s.
func lineOf(s string, i int) int {
	return strings.Count(s[:i], "\n") + 1
}

// checkHygiene runs after stop. No registered secret may appear on either
// stream (a once-secret exactly once, on its named record), the field name
// admin_api_key may not appear when the key was supplied, a stopped child
// wrote no panic or race report, and no data file holds a secret.
func (p *proc) checkHygiene(t *testing.T) {
	t.Helper()
	t.Logf("phases:\n%s", p.phaseTable())
	streams := []struct{ name, text string }{
		{"stdout", p.stdout.String()},
		{"stderr", p.stderr.String()},
	}
	for _, s := range p.secrets {
		if s.onceIn != "" {
			p.checkOnce(t, s, streams[0].text, streams[1].text)
			continue
		}
		for _, st := range streams {
			if i := strings.Index(st.text, s.value); i >= 0 {
				t.Errorf("captured %s line %d contains the %s", st.name, lineOf(st.text, i), s.label)
			}
			if !s.windowed {
				continue
			}
			for _, w := range fragments(s.value) {
				if i := strings.Index(st.text, w); i >= 0 {
					t.Errorf("captured %s line %d contains a fragment of the %s", st.name, lineOf(st.text, i), s.label)
					break
				}
			}
		}
	}
	if p.adminKey != "" {
		for _, st := range streams {
			if i := strings.Index(st.text, "admin_api_key"); i >= 0 {
				t.Errorf("captured %s line %d names admin_api_key", st.name, lineOf(st.text, i))
			}
		}
	}
	if p.exited() {
		for _, st := range streams {
			for _, marker := range []string{"panic:", "goroutine ", "DATA RACE"} {
				if i := strings.Index(st.text, marker); i >= 0 {
					t.Errorf("captured %s line %d contains %q\n%s", st.name, lineOf(st.text, i), marker, p.dump())
				}
			}
		}
	}
	p.checkAtRest(t)
}

// checkOnce enforces a once-secret: one hit in stdout, on the record whose
// msg is onceIn, and none in stderr.
func (p *proc) checkOnce(t *testing.T, s secret, out, errs string) {
	t.Helper()
	if n := strings.Count(out, s.value); n != 1 {
		t.Errorf("the %s appears %d times in stdout, want exactly once", s.label, n)
		return
	}
	if strings.Contains(errs, s.value) {
		t.Errorf("the %s appears in stderr", s.label)
	}
	i := strings.Index(out, s.value)
	start := strings.LastIndex(out[:i], "\n") + 1
	end := strings.Index(out[i:], "\n")
	line := out[start:]
	if end >= 0 {
		line = out[start : i+end]
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Errorf("the line carrying the %s is not a JSON record", s.label)
		return
	}
	if rec["msg"] != s.onceIn || rec["admin_api_key"] != s.value {
		t.Errorf("the %s is on record %q under the wrong key, want %q under admin_api_key", s.label, rec["msg"], s.onceIn)
	}
}

// checkAtRest walks the data directory and fails on any registered secret
// in any file, the hashed-at-rest and encrypted-at-rest invariants at
// process level. A child that served must have written porymcp.db there, so
// an ignored DATA_DIR cannot pass as an empty scan.
func (p *proc) checkAtRest(t *testing.T) {
	t.Helper()
	if p.dataDir == "" {
		return
	}
	files := 0
	err := filepath.WalkDir(p.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == p.dataDir && errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		files++
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, s := range p.secrets {
			if bytes.Contains(b, []byte(s.value)) {
				t.Errorf("data file %s contains the %s", filepath.Base(path), s.label)
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("walking DATA_DIR: %v", err)
	}
	if p.addr != "" {
		if _, err := os.Stat(filepath.Join(p.dataDir, "porymcp.db")); err != nil {
			t.Errorf("DATA_DIR was not used: %v (%d files scanned)", err, files)
		}
	}
}

// runHealthcheck runs "<binary> healthcheck" with LISTEN_ADDR alone (the
// subcommand needs no key), scans both of its streams with p's secrets, and
// returns the exit code.
func (p *proc) runHealthcheck(t *testing.T, addr string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath(t), "healthcheck")
	cmd.Env = childEnv("LISTEN_ADDR=" + addr)
	cmd.Dir = t.TempDir()
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	for _, s := range p.secrets {
		for _, st := range []struct {
			name string
			b    []byte
		}{{"stdout", out.Bytes()}, {"stderr", errs.Bytes()}} {
			if bytes.Contains(st.b, []byte(s.value)) {
				t.Errorf("healthcheck %s contains the %s", st.name, s.label)
			}
		}
	}
	p.mark("healthcheck exit " + fmt.Sprint(code))
	return code
}
