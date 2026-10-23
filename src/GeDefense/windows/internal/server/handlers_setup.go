package server

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// setupStatus is read-only: it tells the Center whether the first-run wizard
// must still be shown. It is server-authoritative and survives browser changes.
func (s *Server) setupStatus(w http.ResponseWriter, _ *http.Request) {
	if s.startupGate == nil {
		s.writeError(w, http.StatusServiceUnavailable, "setup state unavailable")
		return
	}
	result, err := s.startupGate.SetupStatus(s.version)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "setup state unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// setupComplete records the operator's first-run profile only after the
// measured protection posture is real. A UI cannot mark setup complete while
// Defender, ASR/CFA, firewall or the integrity monitor are still inactive.
func (s *Server) setupComplete(w http.ResponseWriter, r *http.Request) {
	if s.startupGate == nil || s.engine == nil || s.mhx == nil || s.integrity == nil {
		s.writeError(w, http.StatusServiceUnavailable, "setup verification unavailable")
		return
	}
	var input struct {
		Profile      string `json:"profile"`
		Reason       string `json:"reason"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(w, r, &input); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid setup request")
		return
	}
	if input.Confirmation != setupConfirmation {
		s.writeError(w, http.StatusConflict, "explicit confirmation required")
		return
	}
	profile := strings.ToLower(strings.TrimSpace(input.Profile))
	switch profile {
	case "personal", "business", "server", "developer":
	default:
		s.writeError(w, http.StatusBadRequest, "invalid setup profile")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	posture, err := s.engine.Posture(ctx)
	if err != nil {
		s.writeError(w, http.StatusConflict, "hardening posture unavailable")
		return
	}
	if !posture.Defender || !posture.DefenderService || !posture.RealTimeProtection ||
		!posture.ControlledFolderAccess || posture.ASRRules < 11 || posture.ASRBlockRules < 11 {
		s.writeError(w, http.StatusConflict, "protection posture is not fully enforced")
		return
	}
	if s.mhx.Status().ProtectionHealth != "VERIFIED" {
		s.writeError(w, http.StatusConflict, "policy is not verified")
		return
	}
	integrityStatus := s.integrity.Status()
	if !integrityStatus.Enabled || integrityStatus.State == "DEGRADED" {
		s.writeError(w, http.StatusConflict, "integrity monitoring is not operational")
		return
	}
	result, err := s.startupGate.CompleteSetup(profile, s.version)
	if err != nil {
		s.writeError(w, http.StatusConflict, "setup state rejected")
		return
	}
	if s.ledger != nil {
		_ = s.ledger.Append("setup.complete", profile, "verified")
	}
	s.writeJSON(w, http.StatusOK, result)
}
