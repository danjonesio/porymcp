package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/danjonesio/porymcp/internal/netguard"
	"github.com/danjonesio/porymcp/internal/proxy"
)

// The policy view (PORM-209) answers one question for one key: which rules
// apply to it, and how many calls each refused in a period. It is read-only
// and built field by field from presentVirtualKey's output, so its lists and
// flags cannot disagree with GET /virtual-keys/{id}, and nothing that carries
// a credential (models.Upstream, the config) is ever serialised.

const (
	policyDefaultPeriod = 7 * 24 * time.Hour
	// policyMaxPeriod bounds the scan: the count reads every row the key
	// wrote in the period, and on SQLite that holds the one connection the
	// proxy also uses.
	policyMaxPeriod = 90 * 24 * time.Hour
	// policyCountTimeout stops a count on a very busy key from holding that
	// connection for longer than an operator would wait for a dialog.
	policyCountTimeout = 5 * time.Second
)

type policyView struct {
	VirtualKeyID string   `json:"virtual_key_id"`
	Status       string   `json:"status"`
	TargetType   string   `json:"target_type"`
	TargetSlug   string   `json:"target_slug"`
	TargetKinds  []string `json:"target_kinds"`
	Order        []string `json:"order"`
	// Absent when empty and when unreadable, as on GET /virtual-keys/{id};
	// lists_malformed says which.
	KeyDenylist          []string      `json:"key_denylist,omitempty"`
	KeyAllowlist         []string      `json:"key_allowlist,omitempty"`
	ListsMalformed       bool          `json:"lists_malformed"`
	GroupToolFilter      *policyGroup  `json:"group_tool_filter"`
	HTTPMethods          []string      `json:"http_methods"`
	HTTPMethodsMalformed bool          `json:"http_methods_malformed"`
	Egress               policyEgress  `json:"egress"`
	Blocked              policyBlocked `json:"blocked"`
}

type policyGroup struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	// The stored filter, raw, as GET /groups/{id} returns it. Absent when the
	// group has none, and when the stored bytes are not JSON at all, so the
	// encoder can never fail halfway through the answer.
	ToolFilter json.RawMessage `json:"tool_filter,omitempty"`
	// Malformed is the proxy's own verdict (models.ValidateToolFilter): the
	// gate refuses every tool on the group, whatever ToolFilter reads as.
	Malformed bool `json:"malformed"`
}

// policyEgress is the two switches and nothing else from the config.
type policyEgress struct {
	AllowLoopback bool `json:"allow_loopback"`
	DenyPrivate   bool `json:"deny_private"`
}

type policyBlocked struct {
	Since                        string         `json:"since"`
	Until                        string         `json:"until"`
	ByRule                       map[string]int `json:"by_rule"`
	UpstreamAddressDenied        int            `json:"upstream_address_denied"`
	UpstreamAddressDeniedByClass map[string]int `json:"upstream_address_denied_by_class"`
}

func (s *Server) getVirtualKeyPolicy(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sinceP, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid since")
		return
	}
	untilP, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid until")
		return
	}
	until := time.Now().UTC()
	if untilP != nil {
		until = untilP.UTC()
	}
	since := until.Add(-policyDefaultPeriod)
	if sinceP != nil {
		since = sinceP.UTC()
	}
	if until.Sub(since) > policyMaxPeriod {
		writeError(w, http.StatusBadRequest, "period longer than 90 days")
		return
	}

	ctx := r.Context()
	vk, err := s.store.GetVirtualKey(ctx, chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	ix := &endpointIndex{store: s.store}
	pub, err := s.presentVirtualKey(ctx, ix, vk, "")
	if err != nil {
		presentError(w)
		return
	}
	view := policyView{
		VirtualKeyID:         vk.ID,
		Status:               pub.Status,
		TargetType:           vk.TargetType,
		TargetKinds:          []string{},
		Order:                proxy.PolicyOrder(),
		KeyDenylist:          pub.ToolDenylist,
		KeyAllowlist:         pub.ToolAllowlist,
		ListsMalformed:       pub.ListsUnreadable,
		HTTPMethodsMalformed: pub.MethodsUnreadable,
		Egress: policyEgress{
			AllowLoopback: s.cfg.UpstreamGuard.AllowLoopback,
			DenyPrivate:   s.cfg.UpstreamGuard.DenyPrivate,
		},
	}
	if err := s.policyTarget(ctx, ix, vk, &view); err != nil {
		presentError(w)
		return
	}
	if hasKind(view.TargetKinds, models.KindHTTP) {
		view.HTTPMethods = pub.HTTPMethods
	}

	view.Blocked = policyBlocked{
		Since:                        since.Format(time.RFC3339Nano),
		Until:                        until.Format(time.RFC3339Nano),
		ByRule:                       map[string]int{},
		UpstreamAddressDeniedByClass: map[string]int{},
	}
	for _, rule := range proxy.PolicyRules() {
		view.Blocked.ByRule[rule.ID] = 0
	}
	classes, sentences := netguard.DeniedClasses(), netguard.DeniedSentences()
	for _, c := range classes {
		view.Blocked.UpstreamAddressDeniedByClass[c] = 0
	}
	// since after until is an empty period, as GET /logs answers it: zeros.
	if !since.After(until) {
		cctx, cancel := context.WithTimeout(ctx, policyCountTimeout)
		counts, err := s.store.CountBlockedByReason(cctx, vk.ID, since, until, proxy.PolicyReasons(), sentences)
		timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
		cancel()
		if err != nil {
			// Checked on the context, not the error: the SQLite and pgx
			// drivers report an interrupted query differently.
			if timedOut {
				writeError(w, http.StatusServiceUnavailable, "policy counts took too long")
				return
			}
			storeError(w, err)
			return
		}
		for _, rule := range proxy.PolicyRules() {
			view.Blocked.ByRule[rule.ID] += counts.Blocked[rule.Reason]
		}
		for i, c := range classes {
			n := counts.Errored[sentences[i]]
			view.Blocked.UpstreamAddressDeniedByClass[c] = n
			view.Blocked.UpstreamAddressDenied += n
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// policyTarget fills the target's slug, its member kinds and the group's
// filter. Kinds count every member, enabled or not, as the Edit dialog does
// (virtual-keys/page.tsx targetKinds): a rule on a disabled member still
// applies the moment it is enabled. A target row that is gone leaves the kinds
// empty and the group null.
func (s *Server) policyTarget(ctx context.Context, ix *endpointIndex, vk *models.VirtualKey, view *policyView) error {
	ups, err := ix.upstreams(ctx)
	if err != nil {
		return err
	}
	kinds := map[string]bool{}
	switch vk.TargetType {
	case models.TargetUpstream:
		if u, ok := ups[vk.TargetID]; ok {
			view.TargetSlug = u.Slug
			kinds[upstreamKind(u)] = true
		}
	case models.TargetGroup:
		grps, err := ix.groups(ctx)
		if err != nil {
			return err
		}
		g, ok := grps[vk.TargetID]
		if !ok {
			return nil
		}
		for _, id := range g.UpstreamIDs {
			if u, ok := ups[id]; ok {
				kinds[upstreamKind(u)] = true
			}
		}
		pg := &policyGroup{GroupID: g.ID, GroupName: g.Name}
		if len(g.ToolFilter) > 0 {
			pg.Malformed = models.ValidateToolFilter(g.ToolFilter) != nil
			if json.Valid(g.ToolFilter) {
				pg.ToolFilter = g.ToolFilter
			}
		}
		view.GroupToolFilter = pg
	}
	for _, k := range []string{models.KindMCP, models.KindHTTP} {
		if kinds[k] {
			view.TargetKinds = append(view.TargetKinds, k)
		}
	}
	return nil
}

// upstreamKind reads an empty stored kind as mcp, as the store does on write.
func upstreamKind(u *models.Upstream) string {
	if u.Kind == models.KindHTTP {
		return models.KindHTTP
	}
	return models.KindMCP
}

func hasKind(kinds []string, k string) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}
