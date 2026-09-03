package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/netcasklabs/porymcp/internal/auth"
	"github.com/netcasklabs/porymcp/internal/config"
	"github.com/netcasklabs/porymcp/internal/crypto"
	"github.com/netcasklabs/porymcp/internal/mcpclient"
	"github.com/netcasklabs/porymcp/internal/store"
	"github.com/netcasklabs/porymcp/internal/webutil"
)

// adminAuthFailRPM is the per-IP budget for failed admin-auth attempts.
// Successful requests never consume it, so a busy dashboard is not throttled.
const adminAuthFailRPM = 10

// discoverRPM is the budget for the two discovery routes together. It is one
// bucket for the deployment and not one per client IP: there is a single admin
// key, so per-IP keying would only let its holder rotate source addresses, and
// what this bounds is authenticated outbound calls to an operator-supplied
// host, a property of the deployment, not of the caller. 30/min is a burst of
// 30 and then one every two seconds; the dashboard's heaviest real flow is one
// discovery per dialog and one per Refresh click.
const discoverRPM = 30

// discoverBucket is that single key. The constant is the point, see
// discoverRPM. One permanent bucket is never swept: auth.Limiter evicts only
// when it admits a key it has not seen before.
const discoverBucket = "discover"

// maxInFlightDiscoveries bounds how many upstream handshakes run at once. The
// rate limit does not: a full bucket admits 30 immediately, and each of those
// holds a socket open to an operator-supplied host for up to ten seconds.
const maxInFlightDiscoveries = 4

// errNameEmpty is the single source of the PATCH message for a name sent as
// null, empty or whitespace, shared by the three PATCH handlers. Create keeps
// its own "… are required" texts: a create names the whole required set, a
// PATCH names the one field that was sent.
const errNameEmpty = "name cannot be empty"

type Server struct {
	cfg *config.Config
	// keys is the process keyring, ENCRYPTION_KEY plus any previous keys.
	// Every credential this package writes is sealed with it, and every one
	// it reads is opened through internal/credential (PORM-52).
	keys crypto.Keyring
	// encryption is the boot integrity verdict /health reports: a fact
	// cmd/server computed once, passed in, and never recomputed per request.
	encryption string
	store      store.Store
	log        *slog.Logger
	adminFails *auth.Limiter
	// mcp is the one client every credential-carrying request goes out on,
	// shared rather than constructed here so the redirect policy has a single
	// home (PORM-94).
	mcp *mcpclient.Client
	// discoverLimit and discovering are the two budgets on the discovery
	// routes: tokens per minute, and how many may be in flight at once.
	discoverLimit *auth.Limiter
	discovering   chan struct{}
}

func New(cfg *config.Config, st store.Store, log *slog.Logger, mcp *mcpclient.Client, encryption string) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg:           cfg,
		keys:          cfg.Keyring(),
		encryption:    encryption,
		store:         st,
		log:           log,
		adminFails:    auth.NewLimiter(),
		mcp:           mcp,
		discoverLimit: auth.NewLimiter(),
		discovering:   make(chan struct{}, maxInFlightDiscoveries),
	}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	// An unknown path under /api/v1 must be a JSON 404, not the dashboard.
	// chi hands a mounted sub-router the parent's NotFound handler unless the
	// sub-router sets its own (Mux.NotFound to updateSubRoutes, and again at
	// Mount time), and cmd/server/main.go makes the dashboard SPA that parent
	// handler, which answers 200 with index.html. This runs before
	// requireAdmin, as an unknown path never reaches the group below.
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	r.Get("/health", s.health)
	r.Group(func(r chi.Router) {
		r.Use(s.requireAdmin)
		r.Get("/stats", s.stats)

		r.Get("/upstreams", s.listUpstreams)
		r.Post("/upstreams", s.createUpstream)
		// Both discovery routes are POST: a GET would be prefetched by a
		// browser, and this is the one management call that reaches out to a
		// third party with a real credential. chi prefers the static
		// "discover" child for POST and backtracks into {id} for every other
		// verb, so GET /upstreams/discover is the ordinary unknown-upstream
		// 404 rather than a 405, pinned in discover_test.go.
		r.Post("/upstreams/discover", s.discoverUnsaved)
		r.Post("/upstreams/{id}/discover", s.discoverUpstream)
		r.Get("/upstreams/{id}", s.getUpstream)
		r.Patch("/upstreams/{id}", s.patchUpstream)
		r.Delete("/upstreams/{id}", s.deleteUpstream)

		r.Get("/groups", s.listGroups)
		r.Post("/groups", s.createGroup)
		r.Get("/groups/{id}", s.getGroup)
		r.Patch("/groups/{id}", s.patchGroup)
		r.Delete("/groups/{id}", s.deleteGroup)

		r.Get("/virtual-keys", s.listVirtualKeys)
		r.Post("/virtual-keys", s.createVirtualKey)
		r.Get("/virtual-keys/{id}", s.getVirtualKey)
		r.Patch("/virtual-keys/{id}", s.patchVirtualKey)
		r.Post("/virtual-keys/{id}/rotate", s.rotateVirtualKey)
		r.Post("/virtual-keys/{id}/revoke", s.revokeVirtualKey)
		r.Delete("/virtual-keys/{id}", s.deleteVirtualKey)

		r.Get("/logs", s.listLogs)
		r.Get("/logs/{id}", s.getLog)
	})
	return r
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.AdminAuthorized(r, s.cfg.AdminAPIKey) {
			next.ServeHTTP(w, r)
			return
		}
		ip := webutil.ClientIP(r, s.cfg.TrustedProxies)
		if ok, retry := s.adminFails.Consume(ip, adminAuthFailRPM); !ok {
			tooManyRequests(w, retry, "too many requests")
			return
		}
		s.log.Warn("admin auth failed",
			"ip", ip,
			"path", r.URL.Path,
			"request_id", middleware.GetReqID(r.Context()),
		)
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
}

// encryptAuth seals a credential under the current key; every write is the
// v1 form. An empty value stores nothing.
func (s *Server) encryptAuth(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	enc, err := s.keys.Seal(raw)
	if err != nil {
		return nil, err
	}
	return []byte(enc), nil
}
