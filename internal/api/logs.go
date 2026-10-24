package api

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/danjonesio/porymcp/internal/models"
	"github.com/go-chi/chi/v5"
)

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := models.LogFilter{
		VirtualKeyID: q.Get("virtual_key_id"),
		Method:       q.Get("method"),
		Tool:         q.Get("tool"),
		Status:       q.Get("status"),
		Cursor:       q.Get("cursor"),
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = n
	}
	// has_tool is the only way to ask for the calls that named no tool: tool=
	// with no value is no filter, and any word in tool could be a real tool's
	// name. Exactly "true" or "false"; empty is no filter.
	switch v := q.Get("has_tool"); v {
	case "":
	case "true", "false":
		b := v == "true"
		f.HasTool = &b
	default:
		writeError(w, http.StatusBadRequest, "invalid has_tool")
		return
	}
	if f.HasTool != nil && f.Tool != "" {
		writeError(w, http.StatusBadRequest, "has_tool cannot be set with tool")
		return
	}
	if !parseLogWindow(w, q, &f) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), logReadTimeout)
	defer cancel()
	logs, next, err := s.store.ListAuditLogs(ctx, f)
	if err != nil {
		s.readFailed(ctx, w, r, err, errLogReadTimeout)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "next_cursor": next})
}

// listLogFacets answers GET /logs/facets: the methods, tools and statuses the
// rows GET /logs would list carry, with a count each, under logReadTimeout.
// method, tool and has_tool are refused: a list filtered by its own value is
// one entry, and the method and tool lists do not narrow each other. limit and
// cursor are not read. Every error string is fixed; nothing echoes the query.
func (s *Server) listLogFacets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, name := range []string{"method", "tool", "has_tool"} {
		if q.Get(name) != "" {
			writeError(w, http.StatusBadRequest, name+" cannot be set on facets")
			return
		}
	}
	f := models.LogFilter{VirtualKeyID: q.Get("virtual_key_id")}
	if v := q.Get("status"); v != "" {
		switch v {
		case models.StatusSuccess, models.StatusError, models.StatusBlocked:
			f.Status = v
		default:
			writeError(w, http.StatusBadRequest, "invalid status")
			return
		}
	}
	if !parseLogWindow(w, q, &f) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), logReadTimeout)
	defer cancel()
	facets, err := s.store.ListAuditFacets(ctx, f)
	if err != nil {
		s.readFailed(ctx, w, r, err, errLogReadTimeout)
		return
	}
	writeJSON(w, http.StatusOK, facets)
}

// parseLogWindow reads since and until into f. On a malformed one it writes
// the 400 ("invalid since" or "invalid until") and reports false.
func parseLogWindow(w http.ResponseWriter, q url.Values, f *models.LogFilter) bool {
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid since")
		return false
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid until")
		return false
	}
	f.Since, f.Until = since, until
	return true
}

func (s *Server) getLog(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.GetAuditLog(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}
