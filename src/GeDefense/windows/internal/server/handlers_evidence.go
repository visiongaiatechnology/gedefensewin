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
func (s *Server) verifyEvidence(w http.ResponseWriter, _ *http.Request) {
	if err := s.ledger.Verify(); err != nil {
		s.writeError(w, http.StatusConflict, "evidence verification failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}
