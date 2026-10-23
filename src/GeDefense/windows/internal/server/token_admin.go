// STATUS: PLATIN
package server

import (
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/visiongaiatechnology/gedefense/windows/internal/security"
)

// dashboardTokenPath resolves the same credential file the service itself is
// started with. The path is derived from ProgramData, never from client input.
func dashboardTokenPath() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is unavailable")
	}
	return filepath.Join(filepath.Clean(programData), "VGT", "GeDefense", "dashboard.token"), nil
}

// reloadMasterToken replaces the in-memory master credential with the current
// on-disk content and revokes every session that was authorized by the old
// credential. This is the lifecycle operation a stolen file token needs
// (AN-FIND-003): the installer keeps the file read-only for the operator group,
// but a delegate can rotate it and invalidate copied credentials immediately.
func (s *Server) reloadMasterToken(w http.ResponseWriter, r *http.Request) {
	path, err := dashboardTokenPath()
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "master credential store unavailable")
		return
	}
	token, err := security.ReadToken(path)
	if err != nil {
		log.Printf("master credential reload rejected: %v", err)
		s.writeError(w, http.StatusConflict, "master credential reload rejected")
		return
	}
	previous := s.masterToken()
	s.setMasterToken(token)
	s.revokeAllSessionsForCredentialChange()
	s.auditSession("master-token:reloaded", "master", scopeAll, "")
	s.writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "changed": previous != token})
}

// rotateMasterToken atomically writes a new 256-bit master credential to the
// installer-owned token file, swaps the in-memory authority and revokes all
// sessions. The new secret is never returned to the HTTP caller; local clients
// read the file through their existing read authority.
func (s *Server) rotateMasterToken(w http.ResponseWriter, r *http.Request) {
	path, err := dashboardTokenPath()
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "master credential store unavailable")
		return
	}
	token, err := security.RotateToken(path)
	if err != nil {
		log.Printf("master credential rotation failed: %v", err)
		s.writeError(w, http.StatusInternalServerError, "master credential rotation failed")
		return
	}
	s.setMasterToken(token)
	s.revokeAllSessionsForCredentialChange()
	s.auditSession("master-token:rotated", "master", scopeAll, "")
	s.writeJSON(w, http.StatusOK, map[string]any{"rotated": true, "sessionsRevoked": true})
}

func (s *Server) revokeAllSessionsForCredentialChange() {
	s.sessionMu.Lock()
	for key := range s.sessions {
		delete(s.sessions, key)
	}
	s.bootstrapCodes = make(map[string]bootstrapCode)
	s.browserRegistrations = nil
	s.sessionMu.Unlock()
}
