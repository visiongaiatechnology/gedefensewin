// STATUS: DIAMANT VGT SUPREME
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
)

type mhxSymbiosisProvider interface {
	SymbiosisStatus() mhx.DefenderSymbiosisStatus
	Containments() []mhx.ContainmentRecord
	ResumeContainment(string, string) (mhx.ContainmentRecord, error)
	TerminateContainment(string, string) (mhx.ContainmentRecord, error)
	ScanFileWithDefender(context.Context, string) (mhx.DefenderScanResult, error)
	ReconcileDefenderSymbiosis(context.Context, bool, string) error
}

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
		log.Printf("threat intelligence synchronization: %v", err)
		s.writeError(w, http.StatusServiceUnavailable, "Threat Intelligence konnte nicht synchronisiert werden. Verbindung und Installationsdiagnose prüfen.")
		return
	}
	s.writeJSON(w, http.StatusOK, s.mhx.Status().ThreatIntelligence)
}

func (s *Server) mhxProtectedNetworks(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.mhx.ProtectedNetworkPolicy())
}

func (s *Server) mhxSetProtectedNetworks(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Prefixes     []string `json:"prefixes"`
		Confirmation string   `json:"confirmation"`
		Reason       string   `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 32<<10); err != nil || input.Confirmation != "UPDATE PROTECTED NETWORKS" || validateReason(input.Reason) != nil || len(input.Prefixes) > 256 {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	reason := strings.TrimSpace(input.Reason)
	digest := sha256.Sum256([]byte(reason))
	if err := s.ledger.Append("threat-intelligence.policy", "protected-networks", "operator-confirmed; count="+fmt.Sprintf("%d", len(input.Prefixes))+"; reason-sha256="+hex.EncodeToString(digest[:])); err != nil {
		s.writeError(w, http.StatusInternalServerError, "protected network evidence preflight failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Minute)
	defer cancel()
	policy, err := s.mhx.SetProtectedNetworkPolicy(ctx, input.Prefixes)
	if err != nil {
		s.writeError(w, http.StatusConflict, "protected network policy rejected")
		return
	}
	s.writeJSON(w, http.StatusOK, policy)
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
		ti := status.ThreatIntelligence
		if ti.BlockingIndicators == 0 || ti.BlockingFeedsTotal == 0 || ti.BlockingFeedsReady != ti.BlockingFeedsTotal || (ti.State != "CURRENT" && ti.State != "CACHED" && ti.State != "DEGRADED") {
			result.Ready = false
			result.Blockers = append(result.Blockers, "Threat-intelligence blocking coverage is not ready")
		}
		enforcement := status.ThreatEnforcement
		if (enforcement.State != "VERIFIED" && enforcement.State != "VERIFIED_CLEANUP_PENDING") || enforcement.ActiveGeneration == "" || enforcement.ActiveGeneration != ti.EnforcementGeneration {
			result.Ready = false
			result.Blockers = append(result.Blockers, "Threat-intelligence firewall generation is not verified")
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
		Action       string `json:"action"`
		Path         string `json:"path"`
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
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

func (s *Server) mhxReconcilePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	if err := s.mhx.ReconcilePolicy(ctx); err != nil {
		log.Printf("policy reconciliation: %v", err)
		s.writeError(w, http.StatusConflict, "Policy konnte nicht verifiziert werden. Installationsdiagnose prüfen.")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":  "verified",
		"mhx":     s.mhx.Status(),
		"message": "Protection policy reconciled and verified",
	})
}

func (s *Server) mhxSymbiosisStatus(w http.ResponseWriter, _ *http.Request) {
	provider, ok := s.mhx.(mhxSymbiosisProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Defender Symbiosis is not available in this build")
		return
	}
	s.writeJSON(w, http.StatusOK, provider.SymbiosisStatus())
}

func (s *Server) mhxContainments(w http.ResponseWriter, _ *http.Request) {
	provider, ok := s.mhx.(mhxSymbiosisProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Process containment is not available in this build")
		return
	}
	s.writeJSON(w, http.StatusOK, provider.Containments())
}

func (s *Server) mhxDefenderScanFile(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxSymbiosisProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Defender scan oracle is not available in this build")
		return
	}
	var input struct {
		Path string `json:"path"`
	}
	if err := decodeJSONBounded(w, r, &input, 4<<10); err != nil || len(strings.TrimSpace(input.Path)) < 3 || len(input.Path) > 1024 {
		s.writeError(w, http.StatusBadRequest, "invalid file path")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	result, err := provider.ScanFileWithDefender(ctx, strings.TrimSpace(input.Path))
	if err != nil {
		s.writeInternalError(w, http.StatusConflict, "Defender scan could not be completed", "defender scan-file", err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) mhxDefenderReconcile(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxSymbiosisProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Defender Symbiosis is not available in this build")
		return
	}
	var input struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 4<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid operator reason")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	if err := provider.ReconcileDefenderSymbiosis(ctx, true, "operator-reconcile"); err != nil {
		s.writeInternalError(w, http.StatusConflict, "Defender baseline reconcile failed", "defender reconcile", err)
		return
	}
	s.writeJSON(w, http.StatusOK, provider.SymbiosisStatus())
}

func (s *Server) mhxResumeContainment(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxSymbiosisProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Process containment is not available in this build")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var input struct {
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 4<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	record, err := provider.ResumeContainment(id, input.Reason)
	if err != nil {
		s.writeInternalError(w, http.StatusConflict, "Containment release rejected", "containment resume", err)
		return
	}
	s.writeJSON(w, http.StatusOK, record)
}

func (s *Server) mhxTerminateContainment(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.mhx.(mhxSymbiosisProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "Process containment is not available in this build")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var input struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONBounded(w, r, &input, 4<<10); err != nil || validateReason(input.Reason) != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	record, err := provider.TerminateContainment(id, input.Reason)
	if err != nil {
		s.writeInternalError(w, http.StatusConflict, "Containment termination rejected", "containment terminate", err)
		return
	}
	s.writeJSON(w, http.StatusOK, record)
}
