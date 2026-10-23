// STATUS: DIAMANT VGT SUPREME
package server

import "net/http"

func (s *Server) evidenceSnapshot(w http.ResponseWriter, _ *http.Request) {
	records, err := s.ledger.Snapshot(100)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "evidence unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, records)
}
func (s *Server) evidencePage(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 20, 1, 100)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid evidence page limit")
		return
	}
	offset, err := parseBoundedInteger(r.URL.Query().Get("offset"), 0, 0, 10_000_000)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid evidence page offset")
		return
	}
	items, total, err := s.ledger.Page(limit, offset)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "evidence unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "limit": limit, "offset": offset,
	})
}

func (s *Server) verifyEvidence(w http.ResponseWriter, _ *http.Request) {
	if err := s.ledger.Verify(); err != nil {
		s.writeError(w, http.StatusConflict, "evidence verification failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}
