package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/danjonesio/porymcp/internal/api"
	"github.com/danjonesio/porymcp/internal/audit"
	"github.com/danjonesio/porymcp/internal/config"
	"github.com/danjonesio/porymcp/internal/mcpclient"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/proxy"
	"github.com/danjonesio/porymcp/internal/store"
	"github.com/danjonesio/porymcp/internal/webutil"
	"github.com/danjonesio/porymcp/web"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	if code, handled := dispatch(os.Args, os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(os.Getenv("LOG_LEVEL"))}))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	cfg.LogWarnings(log)

	st, err := store.Open(cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	// Counts only, never names or urls: url is stored in plaintext and MCP
	// endpoints commonly carry a key in the query string. Zeroes are logged as
	// they are, a fresh install and a Postgres replica that waited on the
	// advisory lock both report 0, which is true: the step ran and found nothing.
	if m := st.LastMigration(); m.Applied {
		log.Info("schema migrated", "version", m.Version,
			"slugs_derived", m.SlugsDerived, "slugs_deduplicated", m.SlugsDeduplicated,
			"tool_entries_rewritten", m.ToolEntriesRewritten, "tool_entries_left", m.ToolEntriesLeft,
			"tool_filters_left_invalid", m.ToolFiltersLeftInvalid,
			"groups_rewritten", m.GroupsRewritten, "virtual_keys_rewritten", m.VirtualKeysRewritten)
	}

	// The encryption verdict is a boot fact: computed once here, handed to the
	// two /health routes as a value, and never recomputed per request. A
	// mismatch never aborts (the operator needs the dashboard to fix it) only
	// the ephemeral-key guard does.
	encryption, err := checkEncryption(context.Background(), st, cfg, log)
	if err != nil {
		log.Error("encryption", "err", err)
		os.Exit(1)
	}

	reportToolPolicyProblems(context.Background(), st, log)

	auditor := audit.New(st, log)
	defer auditor.Close()

	r := newRouter(cfg, st, auditor, log, dashboard(log), encryption)
	srv := newHTTPServer(cfg, r)

	go func() {
		// tls is a boolean on purpose, cert paths must not appear in logs.
		log.Info("porymcp listening", "addr", cfg.ListenAddr, "public_url", cfg.PublicURL, "tls", cfg.TLSEnabled())
		if err := serve(srv, cfg); err != nil && err != http.ErrServerClosed {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// reportToolPolicyProblems names every group and every virtual key whose tool
// rules do not do what they look like they do. It runs once, before the
// listener opens, because none of what it finds is visible from inside a
// client: a rule that matches nothing and a rule nobody wrote produce exactly
// the same traffic, and a call no rule stopped is indistinguishable from a call
// no rule was written for.
//
// It reports five things.
//
// An upstream whose stored slug is not a valid slug is an ERROR. The store
// validates every stored slug once, at the migration step that introduced the
// {slug}__{tool} identity, and never again, so a slug edited by hand in the
// database afterwards arrives here unchallenged. A group's aggregate endpoint
// composes its catalogue from that slug unconditionally, while the proxy parses
// the name it is called with and refuses anything whose head is not a slug, so
// every tool this upstream advertises there is listed under a name no call can
// use. Nothing else on the deployment is affected, which is why it is an error
// about one upstream rather than a refusal to start.
//
// A group whose tool_filter does not validate is an ERROR. The proxy fails
// closed on one (PORM-19 D4), so every tool call on that group is blocked, and
// a filter that was silently permissive before the upgrade takes the group
// offline the moment it is read. Its entries are not judged any further: which
// member an entry would have named is not the operator's problem while nothing
// on the group runs at all.
//
// An entry scoped to a member the target does not have ("docs__search" on a
// group holding only github) is a WARN. models.MatchToolEntry compares a scoped
// entry's head against the identity's slug, and no tool on this target carries
// that slug, so the entry matches nothing anywhere: on the deny side it is a
// rule the operator believes is stopping something and which stops nothing, on
// the allow side one that admits nothing. Membership counts the group's
// upstreams including the disabled ones, because disabling an upstream is
// reversible and a rule written for it is dormant rather than wrong.
//
// An unscoped entry in an allow rule on a group (a bare "search" in a
// tool_filter in mode "allow", or in a group key's tool_allowlist) is a WARN
// too. The proxy skips it outright (proxy.toolPolicy.matchesAny owns the
// reasoning), so an allow rule holding nothing else admits nothing and the
// group or key is silently dead. The management API refuses to write one and
// the store's migration leaves the ones already stored alone (widening an
// allowlist is not a migration's decision to make) so this is the only place
// an operator hears about them.
//
// A virtual key whose tool_allowlist or tool_denylist did not decode out of
// storage is a WARN, and it blocks every call on that key for the same reason a
// malformed filter blocks a group. The line names the only edit that clears it,
// a PATCH carrying both lists, because the store leaves both columns exactly as
// it finds them while they are unreadable: a rotation or a revocation of such a
// key preserves the corruption rather than replacing it with no rule at all.
//
// What it deliberately does NOT report is a bare deny entry, whatever shape it
// has. "delete_repo" and "github_search" alike are matched against each
// member's own tool name on every endpoint the key is served through, which is
// exactly what an operator writing "block this name wherever it appears" means.
// The store's migration keeps such entries for that reason, and a warning about
// them would be a warning about working configuration.
//
// Nor does it report the rest of what that migration writes: a deny entry whose
// head is not a member, standing beside "{member}__{entry}" for every member of
// the target. That is the schema-3 rewrite's own output for a pre-v0.1 entry like
// "mcp__fetch", the scoped forms do the blocking, and the original is kept
// because dropping an entry from a deny rule widens it, and because on a key's
// lists it still matches a prompt or a resource literally called "mcp__fetch". A
// warning there would fire on a perfectly migrated deployment on every restart,
// and the only way to silence it would be to delete the entry: an operator
// breaking working configuration to quieten a report, and then filtering out the
// report anyway, taking the five findings above with it. An entry covering only
// some of the members is a different thing and still counted (it does nothing on
// the rest, which is a gap worth closing) and so is a stranger's scope nothing
// else in the list mentions.
//
// Ids, names and counts reach the log and nothing else. Entries are
// operator-written text about someone's private deployment, and the id is
// enough to find them.
//
// It never aborts startup. A group with a broken filter is a broken group, not
// a broken server, and every other group, key and endpoint must keep serving
// while the operator fixes it. A store failure is logged for the same reason
// and then costs only the part of the report that needed that table; the store
// has already been opened and migrated, so a failure at this point is not the
// signal that the database is unusable.
func reportToolPolicyProblems(ctx context.Context, st store.Store, log *slog.Logger) {
	groups, groupsErr := st.ListGroups(ctx)
	if groupsErr != nil {
		log.Error("could not check group tool_filters at startup", "err", groupsErr)
	}
	upstreams, upstreamsErr := st.ListUpstreams(ctx)
	if upstreamsErr != nil {
		log.Error("could not check upstream slugs at startup", "err", upstreamsErr)
	}
	keys, keysErr := st.ListVirtualKeys(ctx)
	if keysErr != nil {
		log.Error("could not check virtual key tool lists at startup", "err", keysErr)
	}

	slugOf := make(map[string]string, len(upstreams))
	for _, u := range upstreams {
		if !models.ValidSlug(u.Slug) {
			// The slug itself is never logged, for the same reason a filter's
			// entries are not: it is operator-written text about someone's
			// private deployment, this line is going to a log, and the id is
			// enough to find the row.
			log.Error("upstream slug is not valid; every tool it advertises on a group's aggregate endpoint is listed under a name no call can use",
				"upstream_id", u.ID, "upstream_name", u.Name)
		}
		// The row still goes into the index. Its slug is what the catalogue
		// composes with and what a rule scoped to this upstream names, so
		// dropping it would turn one true error into a pile of warnings that
		// are not: every rule written for this upstream would look like it
		// named a member the target has not got.
		slugOf[u.ID] = u.Slug
	}
	membersOf := make(map[string]map[string]bool, len(groups))
	for _, g := range groups {
		// A group may list the same upstream twice, and may hold an id whose
		// upstream has since been deleted. A set of slugs handles both without
		// a special case for either.
		members := make(map[string]bool, len(g.UpstreamIDs))
		for _, id := range g.UpstreamIDs {
			if slug, ok := slugOf[id]; ok {
				members[slug] = true
			}
		}
		membersOf[g.ID] = members
	}
	// targetMembers answers the slugs a rule on this target may name, and false
	// when there is nothing to compare an entry against: the upstreams could not
	// be read, or the target itself is gone. Both mean the entries cannot be
	// judged at all (without the slugs every scoped entry in the deployment
	// would look like it named a member that does not exist) and a warning built
	// on a guess is worse than no warning. The rules that need no membership are
	// still reported in that case.
	targetMembers := func(targetType, targetID string) (map[string]bool, bool) {
		if upstreamsErr != nil {
			return nil, false
		}
		switch targetType {
		case models.TargetUpstream:
			slug, ok := slugOf[targetID]
			if !ok {
				return nil, false
			}
			return map[string]bool{slug: true}, true
		case models.TargetGroup:
			members, ok := membersOf[targetID]
			return members, ok
		}
		return nil, false
	}

	for _, g := range groups {
		if err := models.ValidateToolFilter(g.ToolFilter); err != nil {
			// The filter itself is never logged: it is operator-written and the
			// group id is enough to find it. err already names the bad field.
			log.Error("group tool_filter is invalid; every tool call on this group is blocked until it is fixed",
				"group_id", g.ID, "group_name", g.Name, "err", err)
			continue
		}
		var tf models.ToolFilter
		// A missing, empty or null filter has nothing to say: the first two fail
		// to decode, and "null" decodes to the zero value with no entries.
		// Anything else has just been validated, so an error here is unreachable.
		if err := json.Unmarshal(g.ToolFilter, &tf); err != nil {
			continue
		}
		// tools and prefixes are counted together. They are matched differently
		// (equality against HasPrefix) but a head naming no member is the same
		// mistake in both, and two counts for one filter would read as two
		// separate problems to chase.
		entries := append(append([]string(nil), tf.Tools...), tf.Prefixes...)
		var unmatched, unscopedAllow int
		if members, ok := targetMembers(models.TargetGroup, g.ID); ok {
			unmatched = unmatchedEntries(entries, members, tf.Mode == "deny")
		}
		if tf.Mode == "allow" {
			unscopedAllow = unscopedEntries(entries)
		}
		if unmatched == 0 && unscopedAllow == 0 {
			continue
		}
		// One line per group, whichever of the two it tripped, for the same
		// reason the two counts share a line.
		log.Warn("group tool_filter has entries that can match no tool on this group",
			policyArgs([]any{"group_id", g.ID, "group_name", g.Name}, unmatched, unscopedAllow)...)
	}

	for _, k := range keys {
		if k.ListsMalformed {
			// The message names the one edit that fixes it. Rotating or
			// revoking the key does not: the store leaves both columns exactly
			// as they are while they are unreadable, so those two land without
			// changing anything an operator was told to fix.
			log.Warn("virtual key tool lists could not be decoded; every call on this key is blocked until a PATCH supplies both tool_allowlist and tool_denylist",
				"virtual_key_id", k.ID, "virtual_key_name", k.Name)
			// Neither list survived the decode, so there is nothing left to
			// judge: anything else said about this key would be a statement
			// about the empty lists the scan fell back to.
			continue
		}
		var unmatched, unscopedAllow int
		if members, ok := targetMembers(k.TargetType, k.TargetID); ok {
			unmatched = unmatchedEntries(k.ToolAllowlist, members, false) + unmatchedEntries(k.ToolDenylist, members, true)
		}
		// Only on a group, and only on the allow side. A key bound to a single
		// upstream has exactly one member, so a bare allow entry there names the
		// only tool it could name and is the ordinary way to write the rule; the
		// proxy admits it, and this report must not call it a problem.
		if k.TargetType == models.TargetGroup {
			unscopedAllow = unscopedEntries(k.ToolAllowlist)
		}
		if unmatched == 0 && unscopedAllow == 0 {
			continue
		}
		log.Warn("virtual key tool list has entries that can match no tool on its target",
			policyArgs([]any{"virtual_key_id", k.ID, "virtual_key_name", k.Name}, unmatched, unscopedAllow)...)
	}
}

// policyArgs finishes one WARN record: the two counts, and the spelling that
// works when an allow rule named no member. The hint is attached only when
// there is an unscoped allow entry to explain, because a hint about a mistake
// the operator did not make is how a report becomes noise they learn to skip.
func policyArgs(args []any, unmatched, unscopedAllow int) []any {
	args = append(args, "unmatched_entries", unmatched, "unscoped_allow_entries", unscopedAllow)
	if unscopedAllow > 0 {
		args = append(args, "hint", "an allow rule on a group must name a member: write {slug}__{tool}")
	}
	return args
}

// unmatchedEntries counts the entries scoped to a member that is not there.
// members holds the slugs the target actually carries. models.SplitEntry is the
// same split the proxy, the management API and the store's migration use, so an
// entry cannot be scoped here and unscoped where it is enforced.
//
// deny says these entries come from a deny rule, where one such entry is not a
// mistake but this report's own migration talking back. The store's schema-3
// rewrite takes a pre-v0.1 entry whose head no upstream can hold ("mcp__fetch",
// where mcp is a reserved word) adds "{member}__mcp__fetch" for every member,
// and keeps the original, because removing an entry from a deny rule widens it
// and on a key's lists the original still matches a prompt or a resource
// literally called "mcp__fetch". The kept entry looks scoped to a stranger for
// ever after, so counting it would warn about a deployment that migrated
// perfectly, on every restart, and the only way to silence it would be to delete
// the entry, breaking working configuration to quieten a report. An entry whose
// scoped form is present for every member is therefore not counted on the deny
// side. An operator's typo, "zzz__delete_repo", has no such siblings and is
// counted as it always was.
func unmatchedEntries(entries []string, members map[string]bool, deny bool) int {
	n := 0
	for _, e := range entries {
		head, _, scoped := models.SplitEntry(e)
		if !scoped || members[head] {
			continue
		}
		if deny && scopedForEveryMember(entries, e, members) {
			continue
		}
		n++
	}
	return n
}

// scopedForEveryMember reports whether entries holds "{slug}__{e}" for every
// slug the target carries, the migration's own output for e, and only that.
// Covering some members and not others leaves the entry doing nothing on the
// rest, which is a gap the operator wants told about; it is what the migration's
// output becomes when the group gains a member afterwards.
//
// A target with no members matches nothing at all, so there is no migration
// output to recognise there and the guard keeps that vacuous truth from
// suppressing every count on it.
func scopedForEveryMember(entries []string, e string, members map[string]bool) bool {
	if len(members) == 0 {
		return false
	}
	for slug := range members {
		if !slices.Contains(entries, slug+models.ToolSeparator+e) {
			return false
		}
	}
	return true
}

// unscopedEntries counts the entries that name no member. Callers ask this only
// of an allow rule on a group, where the proxy skips such an entry. On the deny
// side an unscoped entry is the useful "this tool name on every member", and
// counting it would report working configuration as a fault.
func unscopedEntries(entries []string) int {
	n := 0
	for _, e := range entries {
		if _, _, scoped := models.SplitEntry(e); !scoped {
			n++
		}
	}
	return n
}

func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.TLSEnabled() {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return srv
}

func serve(srv *http.Server, cfg *config.Config) error {
	if cfg.TLSEnabled() {
		return srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

// newRouter assembles the router that ships: middleware, the management API
// under /api/v1, the proxy's shared door and per-key route, and the dashboard
// as the fallback for everything else (spa may be nil when no dashboard is
// built). It is a function rather than inline in main so tests can exercise
// the real route table, the API mount, the proxy routes and the dashboard
// fallback all compete for the same paths, and only the assembled router
// shows who wins.
func newRouter(cfg *config.Config, st store.Store, auditor *audit.Logger, log *slog.Logger, spa *webutil.SPA, encryption string) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(webutil.SecurityHeaders(webutil.ContentSecurityPolicy(fsOf(spa))))
	r.Use(requestLogger(log, cfg))
	// Scheme check sits ahead of dashboardCORS so an OPTIONS /api/* preflight
	// cannot 204 past EnforceHTTPS when PUBLIC_URL is https.
	r.Use(webutil.EnforceHTTPS(cfg.SchemeEnforced(), cfg.TrustedProxies, log))
	r.Use(dashboardCORS)

	r.Get("/health", healthAlias(st, cfg, encryption, log))

	// One construction for every outbound call PoryMCP makes with a real
	// credential. The management API's discoveries go out on it; the proxy
	// builds its own from the same construction, and mcpclient is where that
	// policy (refuse every redirect, wrap rather than replace the default
	// transport) lives so there is one place to forget it rather than two
	// (PORM-94).
	r.Mount("/api/v1", api.New(cfg, st, log, mcpclient.New(), encryption).Routes())
	px := proxy.New(cfg, st, auditor, log)
	r.HandleFunc("/mcp", px.ServeHTTP)
	r.HandleFunc(proxy.KeyRoute, px.ServeHTTP)
	// Three segments, so it is unambiguous against /mcp and KeyRoute; and
	// /api/v1/** is a Mount, whose static node chi prefers over {keyID} with
	// no backtracking, so everything under the API keeps its own 404.
	r.HandleFunc(proxy.MemberRoute, px.ServeMember)

	if spa != nil {
		r.NotFound(spa.ServeHTTP)
	}
	return r
}

func healthAlias(st store.Store, cfg *config.Config, encryption string, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pingErr := st.Ping(r.Context())
		webutil.LogPingFailure(log, pingErr)
		webutil.WriteHealth(w, pingErr, cfg.SchemeEnforced(), cfg.TrustedProxyCount(), encryption)
	}
}

// dispatch runs the subcommand args[1] names and reports whether there was
// one. Every first argument is a command or a refusal: a mistyped `rekey`
// must not fall through and start a second server on the live database. out
// is where a command writes its result; errOut gets the usage line.
func dispatch(args []string, out, errOut io.Writer) (code int, handled bool) {
	if len(args) < 2 {
		return 0, false
	}
	switch args[1] {
	case "healthcheck":
		return healthcheck(out), true
	case "rekey":
		return rekey(out), true
	default:
		fmt.Fprintf(errOut, "porymcp: unknown command %q\nusage: porymcp [healthcheck|rekey]\n", args[1])
		return 2, true
	}
}

// healthcheckURL always probes 127.0.0.1. Concatenating LISTEN_ADDR onto
// "http://127.0.0.1" produced "http://127.0.0.10.0.0.0:8080" when the
// process bound 0.0.0.0:8080, the container healthcheck then failed even
// though the process was up.
func healthcheckURL(listenAddr, scheme string) string {
	port := "8080"
	if listenAddr != "" {
		if _, p, err := net.SplitHostPort(listenAddr); err == nil {
			port = p
		} else {
			port = strings.TrimPrefix(listenAddr, ":")
		}
	}
	return scheme + "://127.0.0.1:" + port + "/health"
}

// healthcheckResult is the container-liveness decision, apart from the probe
// so it can be tested. 200 is alive. A 503 whose body says "degraded" is alive
// too (PORM-52): the process is serving, the dashboard the operator needs is
// reachable, and a restart cannot change an environment variable, restarting
// it would only take working upstreams offline and, behind
// docker-compose.tls.yml, keep Caddy from ever starting. The message is
// printed so `docker inspect` (.State.Health.Log) says why. A 503 that says
// "unhealthy" (the store ping failed) stays what it always was: exit 1.
// Anything else, or a body that does not parse, is exit 1. An HTTP monitor on
// GET /health still sees the 503; the tolerance lives here only.
func healthcheckResult(status int, body webutil.HealthBody) (code int, msg string) {
	switch {
	case status == http.StatusOK:
		return 0, ""
	case status == http.StatusServiceUnavailable && body.Status == "degraded":
		return 0, "porymcp is degraded (encryption mismatch); see GET /health"
	default:
		return 1, ""
	}
}

func healthcheck(out io.Writer) int {
	scheme := "http"
	client := &http.Client{Timeout: 2 * time.Second}
	if os.Getenv("TLS_CERT_FILE") != "" {
		// Distroless has no CA bundle; this is localhost liveness, not
		// identity verification of the process's own cert.
		scheme = "https"
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	resp, err := client.Get(healthcheckURL(os.Getenv("LISTEN_ADDR"), scheme))
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	var body webutil.HealthBody
	if resp.StatusCode == http.StatusServiceUnavailable {
		// A body that does not decode leaves Status empty, which is exit 1.
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
	}
	code, msg := healthcheckResult(resp.StatusCode, body)
	if msg != "" {
		fmt.Fprintln(out, msg)
	}
	return code
}

func dashboardCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:3000" || origin == "http://127.0.0.1:3000" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions && strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestLogger(log *slog.Logger, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
				"ip", webutil.ClientIP(r, cfg.TrustedProxies),
			)
		})
	}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func dashboard(log *slog.Logger) *webutil.SPA {
	if root := env("WEB_ROOT", "web/out"); root != "" {
		if spa := webutil.NewSPA(root); spa != nil {
			log.Info("serving dashboard", "root", spa.Root)
			return spa
		}
	}
	dist, err := web.Dist()
	if err != nil {
		log.Warn("dashboard assets missing; / will 404 until you run: cd web && npm run build")
		return nil
	}
	log.Info("serving dashboard", "root", "embedded")
	return webutil.FromFS(dist)
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func fsOf(spa *webutil.SPA) fs.FS {
	if spa == nil {
		return nil
	}
	return spa.FS
}
