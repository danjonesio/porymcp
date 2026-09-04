package api

import (
	"net/http"

	"github.com/danjonesio/porymcp/internal/credential"
	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/webutil"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	pingErr := s.store.Ping(r.Context())
	webutil.LogPingFailure(s.log, pingErr)
	webutil.WriteHealth(w, pingErr, s.cfg.SchemeEnforced(), s.cfg.TrustedProxyCount(), s.encryption)
}

// statsPublic is models.Stats plus the three credential counts (PORM-52),
// computed live from one credential.Sweep (the same definition the boot
// report uses) so the Overview banner, the Upstreams badges and the boot
// line cannot disagree. Admin-authenticated, on page load: the same work the
// unauthenticated /health deliberately does not do per hit.
type statsPublic struct {
	models.Stats
	UndecryptableUpstreams    int `json:"undecryptable_upstreams"`
	UnreadableUpstreams       int `json:"unreadable_upstreams"`
	UpstreamsUnderPreviousKey int `json:"upstreams_under_previous_key"`
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	items, err := s.store.ListUpstreams(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	rep := credential.Sweep(s.keys, items)
	writeJSON(w, http.StatusOK, statsPublic{
		Stats:                     *st,
		UndecryptableUpstreams:    rep.Undecryptable,
		UnreadableUpstreams:       rep.Unreadable,
		UpstreamsUnderPreviousKey: rep.UnderPrevious,
	})
}
