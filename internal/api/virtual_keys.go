package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/netcasklabs/porymcp/internal/auth"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
)

// virtualKeyEndpoint is one 1:1 endpoint this virtual key can connect to: it
// speaks exactly one upstream, with that upstream's own tool names and its own
// initialize, capabilities, prompts, resources and sessions. A group target has
// one entry per ENABLED member; a single-upstream target has exactly one entry
// and its URL is proxy_url itself, because that endpoint is already 1:1 (the
// /{slug}/mcp form is a group-only route and answers 404 there).
type virtualKeyEndpoint struct {
	UpstreamID string `json:"upstream_id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	// URL is the PROXY url a client configures. It is never
	// models.Upstream.URL, which addresses the real MCP server and must never
	// be handed to a client.
	URL string `json:"url"`
}

type virtualKeyPublic struct {
	models.VirtualKey
	Status   string `json:"status"`
	APIKey   string `json:"api_key,omitempty"`
	ProxyURL string `json:"proxy_url,omitempty"`
	// Endpoints is never omitempty and never nil: an empty array means
	// "nothing is reachable through this key right now", which the dashboard
	// renders and an installer must see. A nil slice would marshal as null and
	// every consumer would then need a guard before iterating.
	Endpoints []virtualKeyEndpoint `json:"endpoints"`
}

// proxyURL joins PUBLIC_URL with the path segments of a proxy endpoint. Plain
// concatenation is correct: PUBLIC_URL is trailing-slash-trimmed at load
// (config.Load) and every segment is a uuid or a models.ValidSlug, so nothing
// needs escaping. Both proxy_url and every member URL go through it, so the two
// can never drift.
func (s *Server) proxyURL(seg ...string) string {
	return s.cfg.PublicURL + "/" + strings.Join(seg, "/")
}

// endpointIndex is a per-request, lazily loaded view of the upstreams and
// groups a response needs. It costs at most two queries however many keys the
// response carries; the obvious alternative (GetGroup plus one GetUpstream per
// member, per key) is an unbounded N+1 on GET /virtual-keys over the single
// SQLite connection the proxy data plane also shares.
type endpointIndex struct {
	store store.Store
	ups   map[string]*models.Upstream // nil until first use
	grps  map[string]*models.Group    // nil until first use
}

func (ix *endpointIndex) upstreams(ctx context.Context) (map[string]*models.Upstream, error) {
	if ix.ups != nil {
		return ix.ups, nil
	}
	list, err := ix.store.ListUpstreams(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*models.Upstream, len(list))
	for i := range list {
		m[list[i].ID] = &list[i]
	}
	ix.ups = m
	return m, nil
}

func (ix *endpointIndex) groups(ctx context.Context) (map[string]*models.Group, error) {
	if ix.grps != nil {
		return ix.grps, nil
	}
	list, err := ix.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*models.Group, len(list))
	for i := range list {
		m[list[i].ID] = &list[i]
	}
	ix.grps = m
	return m, nil
}

// endpointsFor resolves the usable endpoints of one virtual key.
//
// A missing group id, a missing member id and a disabled upstream are all
// skipped in silence, exactly as the proxy's resolveTargets does: the API must
// never advertise a URL the proxy would refuse, and it must not fail a whole
// list page because one key's group lost a member. Each of those is a map miss
// here, not an error. A ListUpstreams/ListGroups failure is different (the
// answer would be silently incomplete) so only that propagates.
//
// The resolver reads only ID, Slug and Name; a models.Upstream carries the
// encrypted auth_config and must never escape into a response.
func (s *Server) endpointsFor(ctx context.Context, ix *endpointIndex, vk *models.VirtualKey) ([]virtualKeyEndpoint, error) {
	switch vk.TargetType {
	case models.TargetUpstream:
		ups, err := ix.upstreams(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]virtualKeyEndpoint, 0, 1)
		u, ok := ups[vk.TargetID]
		if !ok || !u.Enabled {
			// The proxy answers errUpstreamDisabled on this key, so there is
			// no usable endpoint to advertise.
			return out, nil
		}
		// Deliberately mirrors proxy_url: a single-upstream key has no
		// /{slug}/mcp route (that 404s), and its aggregate endpoint is already
		// a 1:1 pass-through to this one upstream.
		return append(out, virtualKeyEndpoint{
			UpstreamID: u.ID,
			Slug:       u.Slug,
			Name:       u.Name,
			URL:        s.proxyURL(vk.ID, "mcp"),
		}), nil

	case models.TargetGroup:
		grps, err := ix.groups(ctx)
		if err != nil {
			return nil, err
		}
		g, ok := grps[vk.TargetID]
		if !ok {
			// The group was deleted out from under the key. Reachable only by
			// editing the database (DeleteGroup returns ErrInUse while a key
			// references the group) but the key row is still real and must still
			// be listed.
			return make([]virtualKeyEndpoint, 0), nil
		}
		ups, err := ix.upstreams(ctx)
		if err != nil {
			return nil, err
		}
		// Stored membership order, not ListUpstreams' created_at DESC, so the
		// API, the proxy and the Groups page all agree and the dashboard
		// render is stable across refreshes.
		out := make([]virtualKeyEndpoint, 0, len(g.UpstreamIDs))
		seen := make(map[string]bool, len(g.UpstreamIDs))
		for _, id := range g.UpstreamIDs {
			u, ok := ups[id]
			// Duplicate ids are storable (the groups API does not de-dupe them)
			// and would otherwise register one server twice in a client under
			// the same name.
			if !ok || !u.Enabled || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, virtualKeyEndpoint{
				UpstreamID: u.ID,
				Slug:       u.Slug,
				Name:       u.Name,
				URL:        s.proxyURL(vk.ID, u.Slug, "mcp"),
			})
		}
		return out, nil
	}
	// Unknown target_type: the proxy refuses every call, so nothing is usable.
	return make([]virtualKeyEndpoint, 0), nil
}

// presentVirtualKey resolves the key's endpoints and builds the response. It
// returns an error only when the store failed; every data condition (missing
// group, missing or disabled member) yields an empty endpoints array.
func (s *Server) presentVirtualKey(ctx context.Context, ix *endpointIndex, a *models.VirtualKey, plaintext string) (virtualKeyPublic, error) {
	eps, err := s.endpointsFor(ctx, ix, a)
	if err != nil {
		return virtualKeyPublic{}, err
	}
	return s.presentVirtualKeyWithEndpoints(a, plaintext, eps), nil
}

// presentVirtualKeyWithEndpoints builds the response from endpoints that have
// already been resolved. create and rotate use it because they resolve BEFORE
// their mutating write: the plaintext key exists only in that one response, so
// a store failure while presenting must cost nothing, rather than strand a
// minted key nobody can ever read again.
func (s *Server) presentVirtualKeyWithEndpoints(a *models.VirtualKey, plaintext string, eps []virtualKeyEndpoint) virtualKeyPublic {
	out := virtualKeyPublic{
		VirtualKey: *a,
		Status:     a.Status(),
		ProxyURL:   s.proxyURL(a.ID, "mcp"),
		Endpoints:  eps,
	}
	if plaintext != "" {
		out.APIKey = plaintext
	}
	return out
}

// presentError answers a presenter failure. It is deliberately not storeError:
// that maps store.ErrNotFound to 404, which would report a virtual key that
// plainly exists as missing, and would 404 a whole list page because one key's
// target could not be read.
func presentError(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "internal error")
}

// upsertVirtualKey is the write shape for create and patch. Every field is an
// Optional (see optional.go) so patchVirtualKey can tell a key the body did not
// carry from one sent as null or empty; revoked_at, last_used_at, key_prefix
// and created_at are deliberately absent, so a client that round-trips a key
// object cannot un-revoke it or claim a use that never happened.
type upsertVirtualKey struct {
	Name          Optional[string]          `json:"name"`
	TargetType    Optional[string]          `json:"target_type"`
	TargetID      Optional[string]          `json:"target_id"`
	RateLimit     Optional[int]             `json:"rate_limit"`
	ExpiresAt     Optional[time.Time]       `json:"expires_at"`
	ToolAllowlist Optional[[]string]        `json:"tool_allowlist"`
	ToolDenylist  Optional[[]string]        `json:"tool_denylist"`
	Metadata      Optional[json.RawMessage] `json:"metadata"`
}

func (s *Server) listVirtualKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListVirtualKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	// One index for the whole loop: two queries for the page, not two per key.
	ix := &endpointIndex{store: s.store}
	pub := make([]virtualKeyPublic, 0, len(items))
	for i := range items {
		p, err := s.presentVirtualKey(r.Context(), ix, &items[i], "")
		if err != nil {
			presentError(w)
			return
		}
		pub = append(pub, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"virtual_keys": pub})
}

func (s *Server) getVirtualKey(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetVirtualKey(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	pub, err := s.presentVirtualKey(r.Context(), &endpointIndex{store: s.store}, a, "")
	if err != nil {
		presentError(w)
		return
	}
	writeJSON(w, http.StatusOK, pub)
}

func (s *Server) createVirtualKey(w http.ResponseWriter, r *http.Request) {
	var in upsertVirtualKey
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(in.Name.Value) == "" || in.TargetID.Value == "" {
		writeError(w, http.StatusBadRequest, "name and target_id are required")
		return
	}
	// The default lives in a local rather than being written back into in:
	// see createUpstream. "" and null both take it here; PATCH refuses them.
	targetType := in.TargetType.Value
	if targetType == "" {
		targetType = models.TargetUpstream
	}
	if err := s.validateTarget(r, targetType, in.TargetID.Value); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A key's own two lists outrank the group's filter (the denylist outranks
	// everything) and the proxy matches them byte for byte, yet until now
	// nothing checked either of them on the way in. That made them the one rule
	// in the system that failed OPEN on a typo: a denylist entry with a
	// trailing space is a deny that denies nothing, and it looks right in the
	// dashboard. Everything the validator rejects is quoted back to the caller,
	// which costs nothing, they sent it in this request.
	//
	// Before auth.GenerateKey, not after. The plaintext key exists only in the
	// 201 response, so a key minted for a request that then 400s is a row
	// nobody will ever be able to authenticate with and a secret drawn for
	// nothing; the same instinct puts endpoint resolution before the insert
	// below.
	//
	// targetType is the target this key will have (defaulted and confirmed just
	// above) and it is what decides the allow-side rule: on one upstream an
	// unscoped entry is a bare tool name and exactly right, while on a group it
	// names nothing the proxy will ever match.
	groupTarget := targetType == models.TargetGroup
	if err := models.ValidateToolList(models.FieldToolAllowlist, in.ToolAllowlist.Value, groupTarget); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := models.ValidateToolList(models.FieldToolDenylist, in.ToolDenylist.Value, groupTarget); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The two nullable columns take a pointer only when a value was sent.
	// Never &in.X.Value: that is always non-nil, and a zero expires_at would
	// mint every key already expired.
	var rateLimit *int
	if in.RateLimit.Has() {
		v := in.RateLimit.Value
		rateLimit = &v
	}
	var expiresAt *time.Time
	if in.ExpiresAt.Has() {
		v := in.ExpiresAt.Value
		expiresAt = &v
	}
	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint key")
		return
	}
	now := time.Now().UTC()
	a := &models.VirtualKey{
		ID:            uuid.NewString(),
		Name:          strings.TrimSpace(in.Name.Value),
		KeyHash:       hash,
		KeyLookup:     lookup,
		KeyPrefix:     prefix,
		TargetType:    targetType,
		TargetID:      in.TargetID.Value,
		RateLimit:     rateLimit,
		ExpiresAt:     expiresAt,
		ToolAllowlist: in.ToolAllowlist.Value,
		ToolDenylist:  in.ToolDenylist.Value,
		CreatedAt:     now,
		Metadata:      in.Metadata.Value,
	}
	// Resolve the endpoints BEFORE the insert. The plaintext key lives only in
	// this response, so a store failure while presenting must cost nothing: a
	// 500 here mints no key at all, where a 500 after the insert would leave a
	// key in the database whose plaintext is gone forever.
	eps, err := s.endpointsFor(r.Context(), &endpointIndex{store: s.store}, a)
	if err != nil {
		presentError(w)
		return
	}
	if err := s.store.CreateVirtualKey(r.Context(), a); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.presentVirtualKeyWithEndpoints(a, plain, eps))
}

func (s *Server) patchVirtualKey(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetVirtualKey(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	var in upsertVirtualKey
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Every field is an Optional (see optional.go): absent keeps, a value sets
	// under create's checks, null clears where there is a cleared state and is
	// refused on name, target_type and target_id, which have none.
	if in.Name.Set {
		name := strings.TrimSpace(in.Name.Value)
		if name == "" {
			writeError(w, http.StatusBadRequest, errNameEmpty)
			return
		}
		a.Name = name
	}
	// retargeted is remembered because a move is the one edit that changes what
	// a list the operator did NOT send means. See checkRetargetedAllowlist.
	// A null or "" target_type falls to validateTarget's own 400 and an empty
	// target_id names no row, so neither needs a check of its own.
	retargeted := false
	if in.TargetType.Set || in.TargetID.Set {
		tt, tid := a.TargetType, a.TargetID
		if in.TargetType.Set {
			tt = in.TargetType.Value
		}
		if in.TargetID.Set {
			tid = in.TargetID.Value
		}
		if err := s.validateTarget(r, tt, tid); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		retargeted = tt != a.TargetType || tid != a.TargetID
		a.TargetType, a.TargetID = tt, tid
	}
	// null clears a limit or an expiry: the store writes SQL NULL for a nil
	// pointer. Clearing expires_at makes a key that had expired active again.
	if in.RateLimit.Set {
		if in.RateLimit.Null {
			a.RateLimit = nil
		} else {
			v := in.RateLimit.Value
			a.RateLimit = &v
		}
	}
	if in.ExpiresAt.Set {
		if in.ExpiresAt.Null {
			a.ExpiresAt = nil
		} else {
			v := in.ExpiresAt.Value
			a.ExpiresAt = &v
		}
	}
	// Only a list this request actually sends is validated, and it is validated
	// as in.*, never as the merged key. A key written before these checks
	// existed may hold an entry they reject, and re-checking an untouched list
	// would make that key unrenamable, unexpirable and unrevokable through the
	// API, a validation rule that locks operators out of their own keys is
	// worse than the entry it objects to. An operator answers for what they
	// send.
	//
	// The target the lists are judged against is the one the key will have when
	// this patch lands, which is why this sits after the block above has
	// already applied in.TargetType to a: a request that moves the key to a
	// group and sends a new allowlist in the same body must be judged as the
	// group key it is about to become, not the single-upstream key it was.
	if in.ToolAllowlist.Set {
		// null and [] both clear; the column always holds an array.
		list := in.ToolAllowlist.Value
		if list == nil {
			list = []string{}
		}
		if err := models.ValidateToolList(models.FieldToolAllowlist, list, a.TargetType == models.TargetGroup); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.ToolAllowlist = list
	}
	if in.ToolDenylist.Set {
		list := in.ToolDenylist.Value
		if list == nil {
			list = []string{}
		}
		if err := models.ValidateToolList(models.FieldToolDenylist, list, a.TargetType == models.TargetGroup); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.ToolDenylist = list
	}
	// A key whose stored lists did not decode is the one case where a patch of
	// a single list cannot do what it says. The scan answers nil for BOTH lists
	// on such a key, so the merged key here carries the sent list beside a nil
	// the operator never wrote, and the store refuses to touch either column
	// while the flag is set, which would make this request a silent no-op
	// answered 200 with the new list echoed back. Saying so is better than
	// either half-truth, and it names the request that works.
	//
	// "Sent" is presence: a null counts, because null now clears a list. One
	// side alone must still refuse, if it cleared the flag, the store would
	// write both columns and an unreadable allowlist, which fails closed, would
	// become [], which permits everything.
	sentAllow, sentDeny := in.ToolAllowlist.Set, in.ToolDenylist.Set
	if a.ListsMalformed && sentAllow != sentDeny {
		writeError(w, http.StatusBadRequest, "this key's stored tool_allowlist and tool_denylist could not be decoded; send both fields to replace them")
		return
	}
	if sentAllow && sentDeny {
		// Both columns are being replaced by lists that have just been
		// validated, so nothing unreadable survives this write and the store
		// must store them. This is the only edit that clears the flag: rotate
		// and revoke leave it set, and so preserve the columns.
		a.ListsMalformed = false
	}
	if in.Metadata.Set {
		a.Metadata = in.Metadata.Value // null clears; the store writes ''
	}
	// The one exception to "an operator answers for what they send", checked
	// last so that a is the key exactly as it is about to be stored, and still
	// before UpdateVirtualKey so a refusal leaves the stored key untouched.
	if retargeted {
		if err := s.checkRetargetedAllowlist(r, a); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// A clear that widens what this key may do leaves a record: field names
	// only, never a value.
	var cleared []string
	// 0 and a negative value mean unlimited to the limiter (auth.Limiter's
	// Consume), so they are the same widening as null and are logged as one.
	if in.RateLimit.Set && (in.RateLimit.Null || in.RateLimit.Value <= 0) {
		cleared = append(cleared, "rate_limit")
	}
	if in.ExpiresAt.Set && in.ExpiresAt.Null {
		cleared = append(cleared, "expires_at")
	}
	if in.ToolAllowlist.Set && len(a.ToolAllowlist) == 0 {
		cleared = append(cleared, "tool_allowlist")
	}
	if in.ToolDenylist.Set && len(a.ToolDenylist) == 0 {
		cleared = append(cleared, "tool_denylist")
	}
	if err := s.store.UpdateVirtualKey(r.Context(), a); err != nil {
		storeError(w, err)
		return
	}
	if len(cleared) > 0 {
		s.log.Info("virtual key policy fields cleared", "virtual_key_id", a.ID, "fields", cleared)
	}
	// After the write: a patch can change target_type/target_id, so the
	// endpoints must be resolved from the updated key. A presenter failure
	// here therefore reports 500 for a patch that has already been applied;
	// unlike create and rotate there is no one-time secret at stake, and the
	// patch is idempotent on retry.
	pub, err := s.presentVirtualKey(r.Context(), &endpointIndex{store: s.store}, a, "")
	if err != nil {
		presentError(w)
		return
	}
	writeJSON(w, http.StatusOK, pub)
}

func (s *Server) rotateVirtualKey(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetVirtualKey(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	plain, hash, lookup, prefix, err := auth.GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint key")
		return
	}
	a.KeyHash = hash
	a.KeyLookup = lookup
	a.KeyPrefix = prefix
	a.RevokedAt = nil
	// Resolve the endpoints BEFORE the rotation, for the same reason as create:
	// the new plaintext key is only in this response, so a store failure while
	// presenting must leave the old key working rather than rotate to a key
	// nobody can read. Rotation cannot change the target, so the endpoints
	// resolved here are the ones the rotated key has.
	eps, err := s.endpointsFor(r.Context(), &endpointIndex{store: s.store}, a)
	if err != nil {
		presentError(w)
		return
	}
	if err := s.store.UpdateVirtualKey(r.Context(), a); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.presentVirtualKeyWithEndpoints(a, plain, eps))
}

func (s *Server) revokeVirtualKey(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetVirtualKey(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	now := time.Now().UTC()
	a.RevokedAt = &now
	if err := s.store.UpdateVirtualKey(r.Context(), a); err != nil {
		storeError(w, err)
		return
	}
	// A revoked key keeps its endpoints: they are a property of the target, not
	// of the key's status, exactly as proxy_url is. The URLs stop
	// authenticating. Presented after the write, so a presenter failure reports
	// 500 for a revocation that has already happened, which is the safe
	// direction, and revoking again is a no-op.
	pub, err := s.presentVirtualKey(r.Context(), &endpointIndex{store: s.store}, a, "")
	if err != nil {
		presentError(w)
		return
	}
	writeJSON(w, http.StatusOK, pub)
}

func (s *Server) deleteVirtualKey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteVirtualKey(r.Context(), chi.URLParam(r, "id")); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validateTarget(r *http.Request, targetType, targetID string) error {
	switch targetType {
	case models.TargetUpstream:
		if _, err := s.store.GetUpstream(r.Context(), targetID); err != nil {
			if err == store.ErrNotFound {
				return errInvalid("unknown upstream target")
			}
			return err
		}
	case models.TargetGroup:
		if _, err := s.store.GetGroup(r.Context(), targetID); err != nil {
			if err == store.ErrNotFound {
				return errInvalid("unknown group target")
			}
			return err
		}
	default:
		return errInvalid("target_type must be upstream or group")
	}
	return nil
}

// checkRetargetedAllowlist re-reads a key's tool_allowlist against the target it
// is being moved to. vk is the key as it is about to be stored, so the list
// checked is the resulting one: whatever the same request sent, or the stored
// list when it sent none.
//
// Every other check in this package judges what the operator wrote. This one
// judges what they left behind, because a move is the only edit that changes
// the meaning of an entry nobody touched: the text is unchanged and the set of
// tools it can name is not. The allow side is where that goes wrong quietly. A
// stranded allow entry is a permission the operator believes they granted and
// the proxy will never grant, and when the whole list is stranded the key is
// useless: it authenticates, it lists tools, and it blocks every one of
// them, with nothing in the request that said so.
//
// Only the allow side. A deny entry that stops matching after a move stops
// denying, which is a genuine widening, but refusing the move cannot be the
// answer there: an operator who writes "never delete_repo, anywhere" wants
// precisely the unscoped entry that survives every move, and forcing a rewrite
// of the deny side on each retarget would only teach them to empty it.
func (s *Server) checkRetargetedAllowlist(r *http.Request, vk *models.VirtualKey) error {
	if len(vk.ToolAllowlist) == 0 {
		return nil // nothing to strand
	}
	var stranded []string
	switch vk.TargetType {
	case models.TargetGroup:
		// On a group the proxy skips an unscoped allow entry rather than read
		// it as "this name on every member", which would widen the rule to the
		// whole group, the opposite of what an allowlist is for. So the entry
		// admits nothing at all once the key lands here.
		for _, e := range vk.ToolAllowlist {
			if _, _, scoped := models.SplitEntry(e); !scoped {
				stranded = append(stranded, e)
			}
		}
		if len(stranded) > 0 {
			return errInvalid(fmt.Sprintf("%s %q: an allow rule on a group must name a member, so these entries would admit nothing on the new target; rewrite each as {slug}%s{tool}, or send a new %s with this request",
				models.FieldToolAllowlist, stranded, models.ToolSeparator, models.FieldToolAllowlist))
		}
	case models.TargetUpstream:
		// A single-upstream key only ever sees one upstream's tools, so a
		// scoped entry whose head names anything else can never match. The
		// models validators deliberately read no store and so cannot know a
		// slug; the comparison belongs here, and costs one extra read on the
		// only path that needs it.
		u, err := s.store.GetUpstream(r.Context(), vk.TargetID)
		if err != nil {
			return err
		}
		for _, e := range vk.ToolAllowlist {
			if head, _, scoped := models.SplitEntry(e); scoped && head != u.Slug {
				stranded = append(stranded, e)
			}
		}
		if len(stranded) > 0 {
			return errInvalid(fmt.Sprintf("%s %q: scoped to an upstream other than %q, so these entries can never admit a tool on the new target; rewrite each as %s%s{tool}, drop the scope, or send a new %s with this request",
				models.FieldToolAllowlist, stranded, u.Slug, u.Slug, models.ToolSeparator, models.FieldToolAllowlist))
		}
	}
	return nil
}
