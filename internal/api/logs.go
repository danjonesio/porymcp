package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/netcasklabs/porymcp/internal/models"
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
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid since")
		return
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid until")
		return
	}
	f.Since, f.Until = since, until

	logs, next, err := s.store.ListAuditLogs(r.Context(), f)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "next_cursor": next})
}

func (s *Server) getLog(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.GetAuditLog(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}
