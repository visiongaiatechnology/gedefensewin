// STATUS: DIAMANT VGT SUPREME
package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
)

// confirmationSentinelPosture is the typed confirmation phrase required for
// every change that reduces the active protection posture (turning Killerdom,
// Paranoia, Ghost Mode or the Titan fusion off, disabling a signature or
// isolating a curated system app). Enabling protection never asks for it.
const confirmationSentinelPosture = "CHANGE SENTINEL POSTURE"

type sentinelConfigUpdateRequest struct {
	ParanoiaMode           *bool  `json:"paranoiaMode"`
	KillerdomEnabled       *bool  `json:"killerdomEnabled"`
	GhostModeTelemetryKill *bool  `json:"ghostModeTelemetryKill"`
	CorrelateWithTitan     *bool  `json:"correlateWithTitan"`
	Reason                 string `json:"reason"`
	Confirmation           string `json:"confirmation"`
}

type sentinelSignatureToggleRequest struct {
	SigID        string `json:"sigId"`
	Enabled      bool   `json:"enabled"`
	Reason       string `json:"reason"`
	Confirmation string `json:"confirmation"`
}

type sentinelItemToggleRequest struct {
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Reason       string `json:"reason"`
	Confirmation string `json:"confirmation"`
}

type sentinelAddWhitelistRequest struct {
	Name        string `json:"name"`
	PathPattern string `json:"pathPattern"`
	SHA256      string `json:"sha256"`
	SignerMatch string `json:"signerMatch"`
}

type sentinelRemoveWhitelistRequest struct {
	ID           string `json:"id"`
	Reason       string `json:"reason"`
	Confirmation string `json:"confirmation"`
}

// requireSentinelReduceIntent enforces typed confirmation plus an operator
// reason for every security-reducing mutation. Without it a single mis-click
// could switch off Killerdom or isolate lsass/svchost in Paranoia mode.
func (s *Server) requireSentinelReduceIntent(w http.ResponseWriter, confirmation, reason string) bool {
	trimmed := strings.TrimSpace(reason)
	if confirmation == confirmationSentinelPosture && len(trimmed) >= 8 && len(trimmed) <= 512 {
		return true
	}
	s.writeError(w, http.StatusConflict, "explicit confirmation and operator reason required for reducing protection posture")
	return false
}

func (s *Server) sentinelAvailable(w http.ResponseWriter) bool {
	if s.mhx == nil || s.mhx.SentinelStore() == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Sentinel / Killerdom is not available in this build")
		return false
	}
	return true
}

func (s *Server) sentinelStatus(w http.ResponseWriter, _ *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	store := s.mhx.SentinelStore()
	cfg := store.Config()

	sigs := mhx.DefaultKillerdomSignatures()
	type sigStatus struct {
		mhx.SignatureDef
		Enabled bool `json:"enabled"`
	}
	sigList := make([]sigStatus, len(sigs))
	for i, sig := range sigs {
		enabled := true
		if val, exists := cfg.ActiveSignatures[sig.ID]; exists {
			enabled = val
		}
		sigList[i] = sigStatus{SignatureDef: sig, Enabled: enabled}
	}

	sysApps := make([]mhx.SystemAppEntry, 0, len(cfg.SystemApps))
	for _, app := range cfg.SystemApps {
		sysApps = append(sysApps, app)
	}

	whitelist := make([]mhx.WhitelistEntry, 0, len(cfg.Whitelist))
	for _, wl := range cfg.Whitelist {
		whitelist = append(whitelist, wl)
	}
	// Deterministic ordering: map iteration order must never make the UI tables
	// jump between live refreshes.
	sort.Slice(sigList, func(i, j int) bool { return sigList[i].ID < sigList[j].ID })
	sort.Slice(sysApps, func(i, j int) bool { return sysApps[i].ID < sysApps[j].ID })
	sort.Slice(whitelist, func(i, j int) bool {
		if whitelist[i].Name == whitelist[j].Name {
			return whitelist[i].ID < whitelist[j].ID
		}
		return whitelist[i].Name < whitelist[j].Name
	})

	titanLinked := false
	titanMode := "OFFLINE"
	// The Sentinel switch must reflect the effective Titan policy, not only the
	// stored Sentinel preference. Otherwise the UI can show "TITAN BRIDGE
	// ENTKOPPELT" while the toggle is on (or vice versa).
	correlateWithTitan := cfg.CorrelateWithTitan
	if s.titan != nil {
		tp := s.titan.Policy()
		titanLinked = tp.CorrelateWithKillerdom
		titanMode = tp.Mode
		correlateWithTitan = titanLinked
	}

	ghostApplied, ghostLastError := store.GhostRuntime()
	response := map[string]any{
		"killerdomEnabled":       cfg.KillerdomEnabled,
		"paranoiaMode":           cfg.ParanoiaMode,
		"correlateWithTitan":     correlateWithTitan,
		"ghostModeTelemetryKill": cfg.GhostModeTelemetryKill,
		"ghostModeApplied":       ghostApplied,
		"ghostModeLastError":     ghostLastError,
		"strictLineageEnforced":  cfg.StrictLineageEnforced,
		"amsiShieldEnforced":     cfg.AmsiShieldEnforced,
		"signatures":             sigList,
		"systemApps":             sysApps,
		"whitelist":              whitelist,
		"titanMode":              titanMode,
		"titanLinked":            titanLinked,
		"updatedUtc":             cfg.UpdatedUTC,
		"reason":                 cfg.Reason,
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) sentinelUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	var req sentinelConfigUpdateRequest
	if err := decodeJSONBounded(w, r, &req, 8<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) < 4 {
		reason = "Sentinel Konfigurations-Update durch Operator"
	}

	store := s.mhx.SentinelStore()
	current := store.Config()
	reducing := false
	if req.ParanoiaMode != nil && current.ParanoiaMode && !*req.ParanoiaMode {
		reducing = true
	}
	if req.KillerdomEnabled != nil && current.KillerdomEnabled && !*req.KillerdomEnabled {
		reducing = true
	}
	if req.GhostModeTelemetryKill != nil && current.GhostModeTelemetryKill && !*req.GhostModeTelemetryKill {
		reducing = true
	}
	if req.GhostModeTelemetryKill != nil && current.GhostModeTelemetryKill != *req.GhostModeTelemetryKill {
		// Ghost Mode mutates the OS hosts file. Require an explicit operator
		// confirmation for BOTH directions, not only for the downgrade.
		reducing = true
	}
	if req.CorrelateWithTitan != nil {
		effective := current.CorrelateWithTitan
		if s.titan != nil {
			effective = s.titan.Policy().CorrelateWithKillerdom
		}
		if effective && !*req.CorrelateWithTitan {
			reducing = true
		}
	}
	if reducing && !s.requireSentinelReduceIntent(w, req.Confirmation, req.Reason) {
		return
	}

	if req.ParanoiaMode != nil {
		if err := store.SetParanoiaMode(*req.ParanoiaMode, reason); err != nil {
			s.writeInternalError(w, http.StatusInternalServerError, "Paranoia-Modus konnte nicht gespeichert werden", "sentinel.paranoia", err)
			return
		}
	}
	if req.KillerdomEnabled != nil {
		if err := store.SetKillerdomEnabled(*req.KillerdomEnabled, reason); err != nil {
			s.writeInternalError(w, http.StatusInternalServerError, "Killerdom-Konfiguration konnte nicht gespeichert werden", "sentinel.killerdom", err)
			return
		}
	}
	if req.GhostModeTelemetryKill != nil && current.GhostModeTelemetryKill != *req.GhostModeTelemetryKill {
		if err := store.SetGhostMode(*req.GhostModeTelemetryKill, reason); err != nil {
			// The OS-level sinkhole is the source of truth. If it cannot be
			// applied, the switch must not report success to the operator.
			if s.ledger != nil {
				_ = s.ledger.Append("sentinel.ghostmode", "apply-failed", err.Error())
			}
			s.writeError(w, http.StatusInternalServerError, "Ghost Mode konnte nicht auf das System angewendet werden")
			return
		}
	}
	if req.CorrelateWithTitan != nil {
		previousCorrelation := false
		if s.titan != nil {
			previousCorrelation = s.titan.Policy().CorrelateWithKillerdom
			if _, err := s.titan.SetCorrelationWithKillerdom(*req.CorrelateWithTitan, reason); err != nil {
				s.writeError(w, http.StatusInternalServerError, "Titan-Kopplung konnte nicht aktualisiert werden")
				return
			}
		}
		if err := store.SetTitanCorrelation(*req.CorrelateWithTitan, reason); err != nil {
			// Never leave Titan and the Sentinel store with divergent states.
			if s.titan != nil {
				_, _ = s.titan.SetCorrelationWithKillerdom(previousCorrelation, "Rollback nach fehlgeschlagener Sentinel-Persistenz")
			}
			s.writeError(w, http.StatusInternalServerError, "Sentinel-Konfiguration konnte nicht gespeichert werden")
			return
		}
	}

	if s.ledger != nil {
		_ = s.ledger.Append("sentinel.config", "updated", reason)
	}
	s.sentinelStatus(w, r)
}

func (s *Server) sentinelToggleSignature(w http.ResponseWriter, r *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	var req sentinelSignatureToggleRequest
	if err := decodeJSONBounded(w, r, &req, 8<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Enabled && !s.requireSentinelReduceIntent(w, req.Confirmation, req.Reason) {
		return
	}
	store := s.mhx.SentinelStore()
	if err := store.ToggleSignature(req.SigID, req.Enabled); err != nil {
		s.writeInternalError(w, http.StatusBadRequest, "Signatur konnte nicht aktualisiert werden", "sentinel.signature", err)
		return
	}
	if s.ledger != nil {
		_ = s.ledger.Append("sentinel.signature", fmt.Sprintf("%s=%t", req.SigID, req.Enabled), strings.TrimSpace(req.Reason))
	}
	s.sentinelStatus(w, r)
}

func (s *Server) sentinelToggleSystemApp(w http.ResponseWriter, r *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	var req sentinelItemToggleRequest
	if err := decodeJSONBounded(w, r, &req, 8<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !req.Enabled && !s.requireSentinelReduceIntent(w, req.Confirmation, req.Reason) {
		return
	}
	store := s.mhx.SentinelStore()
	if err := store.ToggleSystemApp(req.ID, req.Enabled); err != nil {
		s.writeInternalError(w, http.StatusBadRequest, "System-App konnte nicht aktualisiert werden", "sentinel.systemapp", err)
		return
	}
	if s.ledger != nil {
		_ = s.ledger.Append("sentinel.systemapp", fmt.Sprintf("%s=%t", req.ID, req.Enabled), strings.TrimSpace(req.Reason))
	}
	s.sentinelStatus(w, r)
}

func (s *Server) sentinelToggleWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	var req sentinelItemToggleRequest
	if err := decodeJSONBounded(w, r, &req, 8<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	store := s.mhx.SentinelStore()
	if err := store.ToggleWhitelistApp(req.ID, req.Enabled); err != nil {
		s.writeInternalError(w, http.StatusBadRequest, "Whitelist-Eintrag konnte nicht aktualisiert werden", "sentinel.whitelist", err)
		return
	}
	if s.ledger != nil {
		_ = s.ledger.Append("sentinel.whitelist", fmt.Sprintf("%s=%t", req.ID, req.Enabled), strings.TrimSpace(req.Reason))
	}
	s.sentinelStatus(w, r)
}

func (s *Server) sentinelAddWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	var req sentinelAddWhitelistRequest
	if err := decodeJSONBounded(w, r, &req, 8<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	store := s.mhx.SentinelStore()
	entry, err := store.AddWhitelistAppPinned(req.Name, req.PathPattern, req.SHA256, req.SignerMatch)
	if err != nil {
		s.writeInternalError(w, http.StatusBadRequest, "Whitelist-Eintrag konnte nicht angelegt werden", "sentinel.whitelist.add", err)
		return
	}
	s.writeJSON(w, http.StatusOK, entry)
}

func (s *Server) sentinelRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.sentinelAvailable(w) {
		return
	}
	var req sentinelRemoveWhitelistRequest
	if err := decodeJSONBounded(w, r, &req, 8<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	store := s.mhx.SentinelStore()
	if err := store.RemoveWhitelistApp(req.ID); err != nil {
		s.writeInternalError(w, http.StatusBadRequest, "Whitelist-Eintrag konnte nicht entfernt werden", "sentinel.whitelist.remove", err)
		return
	}
	if s.ledger != nil {
		_ = s.ledger.Append("sentinel.whitelist", "removed "+req.ID, strings.TrimSpace(req.Reason))
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "id": req.ID})
}
