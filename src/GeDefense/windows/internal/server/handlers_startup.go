// STATUS: PLATIN
package server

import "net/http"

func (s *Server) startupStatus(w http.ResponseWriter, _ *http.Request) {
	if s.startupGate == nil {
		s.writeError(w, http.StatusServiceUnavailable, "startup state unavailable")
		return
	}
	result, err := s.startupGate.Required(s.version)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "startup state unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// startupAck persists that the operator has completed the readiness review.
// The server, not the browser, decides whether a check is required.
func (s *Server) startupAcknowledge(w http.ResponseWriter, _ *http.Request) {
	if s.startupGate == nil {
		s.writeError(w, http.StatusServiceUnavailable, "startup state unavailable")
		return
	}
	result, err := s.startupGate.Acknowledge(s.version)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "startup acknowledgement failed")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
