// STATUS: PLATIN VGT SUPREME
package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/spyware"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/witness"
)

const (
	v6DefaultLimit = 50
	v6MaxLimit     = 100
)

type v6WitnessProjection struct {
	Status              witness.Status             `json:"status"`
	Enabled             bool                       `json:"enabled"`
	Wired               bool                       `json:"wired"`
	LastCheckpoint      *witness.CheckpointSummary `json:"lastCheckpoint,omitempty"`
	LastReceiptSequence uint64                     `json:"lastReceiptSequence"`
	OutboxDepth         int                        `json:"outboxDepth"`
	OutboxBytes         int64                      `json:"outboxBytes"`
	OutboxFull          bool                       `json:"outboxFull"`
	ConsecutiveFailures int                        `json:"consecutiveFailures"`
	LastError           string                     `json:"lastError,omitempty"`
	SettingsState       string                     `json:"settingsState"`
	SettingsReason      string                     `json:"settingsReason,omitempty"`
}

type v6StatusResponse struct {
	Spyware         spyware.Status          `json:"spyware"`
	SpywareFindings []spyware.Finding       `json:"spywareFindings"`
	LockState       string                  `json:"lockState"`
	BootPosture     winapi.BootPosture      `json:"bootPosture"`
	Witness         v6WitnessProjection     `json:"witness"`
	Styx            mhx.StyxStatus          `json:"styx"`
	StyxCollector   mhx.StyxCollectorStatus `json:"styxCollector"`
	StyxIncidents   []mhx.StyxIncident      `json:"styxIncidents"`
}

func (s *Server) v6Status(w http.ResponseWriter, r *http.Request) {
	limit := parseV6Limit(r, v6DefaultLimit)

	spyStatus := spyware.Status{}
	spyFindings := []spyware.Finding{}
	lockState := "UNAVAILABLE"
	bootPosture := winapi.BootPosture{QuoteKind: "none"}
	witProj := v6WitnessProjection{
		Status:        witness.StatusDisabled,
		SettingsState: "DISABLED",
	}

	if s.v6 != nil {
		spyStatus = s.v6.SpywareStatus()
		if rawFindings := s.v6.SpywareFindings(limit); len(rawFindings) > 0 {
			spyFindings = rawFindings
		}
		if ls := strings.TrimSpace(s.v6.SpywareLockState()); ls != "" {
			lockState = ls
		}
		bootPosture = s.v6.BootPosture()
		witReport := s.v6.WitnessStatus()
		cfgState, cfgReason := s.v6.WitnessSettingsState()
		if cfgState == "" {
			cfgState = string(witReport.Status)
		}
		witProj = v6WitnessProjection{
			Status:              witReport.Status,
			Enabled:             witReport.Enabled,
			Wired:               witReport.Wired,
			LastCheckpoint:      witReport.LastCheckpoint,
			LastReceiptSequence: witReport.LastReceiptSequence,
			OutboxDepth:         witReport.OutboxDepth,
			OutboxBytes:         witReport.OutboxBytes,
			OutboxFull:          witReport.OutboxFull,
			ConsecutiveFailures: witReport.ConsecutiveFailures,
			LastError:           witReport.LastError,
			SettingsState:       cfgState,
			SettingsReason:      cfgReason,
		}
	}

	styxStatus := mhx.StyxStatus{
		Mode:        mhx.StyxModeOff,
		SensorState: "unavailable",
		Capability:  "missing",
		Top:         []mhx.StyxFlowSnapshot{},
	}
	styxCollector := mhx.StyxCollectorStatus{}
	styxIncidents := []mhx.StyxIncident{}
	if s.mhx != nil {
		styxStatus = s.mhx.StyxStatus()
		if styxStatus.Top == nil {
			styxStatus.Top = []mhx.StyxFlowSnapshot{}
		}
		styxCollector = s.mhx.StyxCollectorStatus()
		if rawIncidents := s.mhx.StyxIncidents(limit); len(rawIncidents) > 0 {
			styxIncidents = rawIncidents
		}
	}

	s.writeJSON(w, http.StatusOK, v6StatusResponse{
		Spyware:         spyStatus,
		SpywareFindings: spyFindings,
		LockState:       lockState,
		BootPosture:     bootPosture,
		Witness:         witProj,
		Styx:            styxStatus,
		StyxCollector:   styxCollector,
		StyxIncidents:   styxIncidents,
	})
}

func (s *Server) v6SpywareFindings(w http.ResponseWriter, r *http.Request) {
	limit := parseV6Limit(r, v6DefaultLimit)
	findings := []spyware.Finding{}
	if s.v6 != nil {
		if raw := s.v6.SpywareFindings(limit); len(raw) > 0 {
			findings = raw
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
	})
}

func (s *Server) v6StyxIncidents(w http.ResponseWriter, r *http.Request) {
	limit := parseV6Limit(r, v6DefaultLimit)
	incidents := []mhx.StyxIncident{}
	if s.mhx != nil {
		if raw := s.mhx.StyxIncidents(limit); len(raw) > 0 {
			incidents = raw
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"incidents": incidents,
	})
}

func parseV6Limit(r *http.Request, fallback int) int {
	if r == nil || r.URL == nil {
		return fallback
	}
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	if n > v6MaxLimit {
		return v6MaxLimit
	}
	return n
}
