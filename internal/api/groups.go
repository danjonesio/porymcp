package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/netcasklabs/porymcp/internal/models"
	"github.com/netcasklabs/porymcp/internal/store"
)

// upsertGroup is the write shape for create and patch. Every field is an
// Optional (see optional.go) so patchGroup can tell a key the body did not
// carry from one sent as null or empty.
type upsertGroup struct {
	Name        Optional[string]          `json:"name"`
	Description Optional[string]          `json:"description"`
	UpstreamIDs Optional[[]string]        `json:"upstream_ids"`
	ToolFilter  Optional[json.RawMessage] `json:"tool_filter"`
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListGroups(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": items})
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetGroup(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in upsertGroup
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(in.Name.Value) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// The proxy now fails closed on a filter it cannot enforce (PORM-19 D4),
	// so a filter such as {"mode":"Deny"} that used to be silently permissive
	// blocks every tool call on the group instead. Refuse to store one: the
	// operator hears about the typo at the keystroke that caused it rather
	// than from inside a client. The validator's message names the offending
	// field and quotes the offending entry, which the caller sent us in this
	// request, so it is safe to return verbatim. Checked before the upstream
	// ids because it is pure, while each id costs a store round trip.
	//
	// ValidateToolFilterWrite rather than ValidateToolFilter: the write side
	// adds the rules that only make sense while the operator is still here to
	// be told, above all that an allow rule on a group must name a member.
	// Those rules cannot live on the read side, because a filter already in the
	// database that fails them would take the whole group offline; here the
	// worst outcome is this 400.
	if in.ToolFilter.Has() {
		if err := models.ValidateToolFilterWrite(in.ToolFilter.Value); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Absent, null and [] are all "no members" here; the model always carries
	// an array so the response and the column both say [] rather than null.
	ids := in.UpstreamIDs.Value
	if ids == nil {
		ids = []string{}
	}
	if err := s.validateUpstreamIDs(r, ids); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	g := &models.Group{
		ID:          uuid.NewString(),
		Name:        strings.TrimSpace(in.Name.Value),
		Description: in.Description.Value,
		UpstreamIDs: ids,
		ToolFilter:  in.ToolFilter.Value,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.CreateGroup(r.Context(), g); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetGroup(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	var in upsertGroup
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Every field is an Optional (see optional.go): absent keeps, a value sets
	// under create's checks, null clears where there is a cleared state and is
	// refused on name, which has none.
	if in.Name.Set {
		name := strings.TrimSpace(in.Name.Value)
		if name == "" {
			writeError(w, http.StatusBadRequest, errNameEmpty)
			return
		}
		g.Name = name
	}
	if in.Description.Set {
		g.Description = in.Description.Value // "" and null both clear
	}
	if in.UpstreamIDs.Set {
		// null and [] both empty the group; the model always carries an array.
		ids := in.UpstreamIDs.Value
		if ids == nil {
			ids = []string{}
		}
		if err := s.validateUpstreamIDs(r, ids); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		g.UpstreamIDs = ids
	}
	// Same reasoning as createGroup, and the same write-side validator: this
	// guards the replacement, and a rejected filter leaves the group untouched
	// because nothing is written until UpdateGroup below. Only a filter this
	// request actually sends is judged, a group whose stored filter predates
	// the identity rules keeps it, and can still be renamed or have members
	// added, until someone rewrites the filter itself. A null clears the
	// filter: Value is nil, which the validator accepts as "no filter" and the
	// store writes as ''.
	if in.ToolFilter.Set {
		if err := models.ValidateToolFilterWrite(in.ToolFilter.Value); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		g.ToolFilter = in.ToolFilter.Value
	}
	// A clear that widens what every key on this group may call leaves a
	// record: field names only, never a value. {} is a filter that filters
	// nothing, so it counts as a clear here even though it is stored as sent.
	var cleared []string
	if tf := strings.TrimSpace(string(in.ToolFilter.Value)); in.ToolFilter.Set && (tf == "" || tf == "{}") {
		cleared = append(cleared, "tool_filter")
	}
	if in.UpstreamIDs.Set && len(g.UpstreamIDs) == 0 {
		cleared = append(cleared, "upstream_ids")
	}
	g.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateGroup(r.Context(), g); err != nil {
		storeError(w, err)
		return
	}
	if len(cleared) > 0 {
		s.log.Info("group policy fields cleared", "group_id", g.ID, "fields", cleared)
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteGroup(r.Context(), chi.URLParam(r, "id")); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validateUpstreamIDs(r *http.Request, ids []string) error {
	for _, id := range ids {
		if _, err := s.store.GetUpstream(r.Context(), id); err != nil {
			if err == store.ErrNotFound {
				return errInvalid("unknown upstream_id: " + id)
			}
			return err
		}
	}
	return nil
}

type errInvalid string

func (e errInvalid) Error() string { return string(e) }
