// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

func (s *Server) mhxStatus(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.mhx.Status())
}
func (s *Server) mhxAnalyses(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 100, 1, 500)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid window")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.Analyses(limit))
}
func (s *Server) mhxNetwork(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 100, 1, 500)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid window")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.NetworkFindings(limit))
}
func (s *Server) mhxStories(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInteger(r.URL.Query().Get("limit"), 100, 1, 500)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid window")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.AttackStories(limit))
}
func (s *Server) mhxSyncFeeds(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Minute)
	defer cancel()
	if err := s.mhx.SyncFeeds(ctx); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "threat intelligence synchronization failed")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.Status().ThreatIntelligence)
}

func (s *Server) mhxSetMode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Mode         string `json:"mode"`
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	input.Mode = strings.ToLower(strings.TrimSpace(input.Mode))
	expected := map[string]string{"monitor": "RETURN TO MONITOR", "guarded": "ACTIVATE GUARDED", "sovereign": "SOVEREIGN DEFAULT DENY"}[input.Mode]
	if expected == "" || input.Confirmation != expected {
		s.writeError(w, http.StatusConflict, "explicit protection confirmation required")
		return
	}
	if err := validateReason(input.Reason); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ready := s.modeReady(input.Mode)
	if !ready.Ready {
		s.writeError(w, http.StatusConflict, "protection target is not ready")
		return
	}
	reason := strings.TrimSpace(input.Reason)
	digest := sha256.Sum256([]byte(reason))
	if err := s.ledger.Append("protection.request", input.Mode, "operator-confirmed; reason-sha256="+hex.EncodeToString(digest[:])); err != nil {
		s.writeError(w, http.StatusInternalServerError, "protection evidence preflight failed")
		return
	}
	if err := s.mhx.SetMode(r.Context(), input.Mode); err != nil {
		s.writeError(w, http.StatusConflict, "protection mode rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.Status())
}

func (s *Server) modeReady(target string) readiness {
	status := s.mhx.Status()
	result := readiness{Target: target, CurrentMode: status.ProtectionMode, Ready: true, Blockers: []string{}}
	if target != "monitor" && !status.Realtime {
		result.Ready = false
		result.Blockers = append(result.Blockers, "Realtime process telemetry is not healthy")
	}
	if target != "monitor" && status.ProtectionHealth != "VERIFIED" {
		result.Ready = false
		result.Blockers = append(result.Blockers, "Protection policy verification is not healthy")
	}
	if target == "sovereign" {
		if status.ProtectionMode == "monitor" {
			result.Ready = false
			result.Blockers = append(result.Blockers, "Guarded protection must be active before Sovereign mode")
		}
		if status.ThreatIntelligence.Indicators == 0 || (status.ThreatIntelligence.State != "CURRENT" && status.ThreatIntelligence.State != "CACHED") {
			result.Ready = false
			result.Blockers = append(result.Blockers, "Threat-intelligence snapshot is not ready")
		}
	}
	return result
}

func (s *Server) mhxApplications(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.mhx.Applications(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "application allow policy unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
func (s *Server) mhxSetApplication(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Action string `json:"action"`
		Path   string `json:"path"`
	}
	if err := decodeJSON(w, r, &input); err != nil || (input.Action != "Add" && input.Action != "Remove") || len(input.Path) < 3 || len(input.Path) > 1024 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := s.mhx.SetApplication(ctx, input.Action, input.Path)
	if err != nil {
		s.writeError(w, http.StatusConflict, "application allow transaction rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
