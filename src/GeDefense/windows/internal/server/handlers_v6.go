// STATUS: PLATIN VGT SUPREME
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/geoip"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/settings"
	"github.com/visiongaiatechnology/gedefense/windows/internal/spyware"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/witness"
)

const confirmationV6Posture = "CHANGE V6 POSTURE"

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

type styxControlProvider interface {
	StyxWhitelist() []string
	SetStyxWhitelist(context.Context, []string) ([]string, error)
	StyxBlockedTargets() []string
	StyxProgramTraffic() []mhx.StyxProgramTrafficSummary
}

type v6StyxIncidentView struct {
	mhx.StyxIncident
	RemoteIP    string `json:"remoteIp,omitempty"`
	RemotePort  uint16 `json:"remotePort,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	Country     string `json:"country,omitempty"`
	ASN         string `json:"asn,omitempty"`
	ASName      string `json:"asName,omitempty"`
}

type v6StatusResponse struct {
	Spyware            spyware.Status          `json:"spyware"`
	SpywareFindings    []spyware.Finding       `json:"spywareFindings"`
	LockState          string                  `json:"lockState"`
	BootPosture        winapi.BootPosture      `json:"bootPosture"`
	Witness            v6WitnessProjection     `json:"witness"`
	Styx               mhx.StyxStatus          `json:"styx"`
	StyxCollector      mhx.StyxCollectorStatus `json:"styxCollector"`
	StyxIncidents      []v6StyxIncidentView    `json:"styxIncidents"`
	StyxWhitelist      []string                `json:"styxWhitelist"`
	StyxBlockedTargets []string                `json:"styxBlockedTargets"`
}

func (s *Server) v6Status(w http.ResponseWriter, r *http.Request) {
	limit := parseV6Limit(r, v6DefaultLimit)
	s.writeJSON(w, http.StatusOK, s.buildV6StatusResponse(limit))
}

func (s *Server) buildV6StatusResponse(limit int) v6StatusResponse {
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

	s.initGeo()
	styxStatus := mhx.StyxStatus{
		Mode:        mhx.StyxModeOff,
		SensorState: "unavailable",
		Capability:  "missing",
		Top:         []mhx.StyxFlowSnapshot{},
	}
	styxCollector := mhx.StyxCollectorStatus{}
	styxIncidents := []v6StyxIncidentView{}
	styxWhitelist := []string{}
	styxBlocked := []string{}
	if s.mhx != nil {
		styxStatus = s.mhx.StyxStatus()
		if styxStatus.Top == nil {
			styxStatus.Top = []mhx.StyxFlowSnapshot{}
		}
		styxCollector = s.mhx.StyxCollectorStatus()
		if rawIncidents := s.mhx.StyxIncidents(limit); len(rawIncidents) > 0 {
			styxIncidents = s.enrichStyxIncidents(rawIncidents)
		}
		if ctrl, ok := s.mhx.(styxControlProvider); ok {
			if wl := ctrl.StyxWhitelist(); len(wl) > 0 {
				styxWhitelist = wl
			}
			if bt := ctrl.StyxBlockedTargets(); len(bt) > 0 {
				styxBlocked = bt
			}
		}
	}

	return v6StatusResponse{
		Spyware:            spyStatus,
		SpywareFindings:    spyFindings,
		LockState:          lockState,
		BootPosture:        bootPosture,
		Witness:            witProj,
		Styx:               styxStatus,
		StyxCollector:      styxCollector,
		StyxIncidents:      styxIncidents,
		StyxWhitelist:      styxWhitelist,
		StyxBlockedTargets: styxBlocked,
	}
}

func splitRemoteEndpoint(raw string) (string, uint16) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", 0
	}
	if ap, err := netip.ParseAddrPort(trimmed); err == nil {
		return ap.Addr().Unmap().String(), ap.Port()
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.Unmap().String(), 0
	}
	return trimmed, 0
}

func (s *Server) enrichStyxIncidents(raw []mhx.StyxIncident) []v6StyxIncidentView {
	out := make([]v6StyxIncidentView, 0, len(raw))
	for _, inc := range raw {
		remoteIP, remotePort := splitRemoteEndpoint(inc.Remote)
		view := v6StyxIncidentView{
			StyxIncident: inc,
			RemoteIP:     remoteIP,
			RemotePort:   remotePort,
		}
		if parsed := net.ParseIP(remoteIP); parsed != nil && s.geo != nil {
			if geo, ok := s.geo.Lookup(parsed); ok {
				view.CountryCode = geo.CountryCode
				view.Country = geo.Country
				view.ASN = geo.ASN
				view.ASName = geo.ASName
			} else if special, isSpecial := geoip.ClassifySpecial(parsed); isSpecial {
				view.CountryCode = special.CountryCode
				view.Country = special.Country
				view.ASN = special.ASN
				view.ASName = special.ASName
			}
		}
		out = append(out, view)
	}
	return out
}

type v6ModeRequest struct {
	SpywareMode  string `json:"spywareMode,omitempty"`
	StyxMode     string `json:"styxMode,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Confirmation string `json:"confirmation,omitempty"`
}

func v6RankSpyware(mode string) int {
	if strings.EqualFold(strings.TrimSpace(mode), "active") {
		return 2
	}
	return 1
}

func v6RankStyx(mode string) int {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case mhx.StyxModeEnforce:
		return 3
	case mhx.StyxModeObserve, "monitor":
		return 2
	default:
		return 1
	}
}

func (s *Server) v6SetMode(w http.ResponseWriter, r *http.Request) {
	var input v6ModeRequest
	if err := decodeJSONBounded(w, r, &input, 16<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	spyMode := strings.ToLower(strings.TrimSpace(input.SpywareMode))
	styxMode := strings.ToLower(strings.TrimSpace(input.StyxMode))
	if styxMode == "monitor" {
		styxMode = mhx.StyxModeObserve
	}
	if spyMode == "" && styxMode == "" {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if spyMode != "" && spyMode != "observe" && spyMode != "active" {
		s.writeError(w, http.StatusBadRequest, "invalid spywareMode")
		return
	}
	if styxMode != "" && styxMode != mhx.StyxModeOff && styxMode != mhx.StyxModeObserve && styxMode != mhx.StyxModeEnforce {
		s.writeError(w, http.StatusBadRequest, "invalid styxMode")
		return
	}

	weakening := false
	if spyMode != "" && s.v6 != nil {
		cur := s.v6.SpywareStatus().Mode
		if v6RankSpyware(spyMode) < v6RankSpyware(cur) {
			weakening = true
		}
	}
	if styxMode != "" && s.mhx != nil {
		cur := s.mhx.StyxStatus().Mode
		if styxMode == mhx.StyxModeOff || v6RankStyx(styxMode) < v6RankStyx(cur) {
			weakening = true
		}
	}

	reason := strings.TrimSpace(input.Reason)
	if weakening {
		if input.Confirmation != confirmationV6Posture || validateReason(reason) != nil {
			s.writeError(w, http.StatusConflict, "explicit confirmation and operator reason required for reducing V6 posture")
			return
		}
	} else {
		if reason == "" {
			reason = "Operator activated V6 Sovereign protection"
		} else if err := validateReason(reason); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid operator reason")
			return
		}
	}

	digest := sha256.Sum256([]byte(reason))
	if s.ledger != nil {
		detail := fmt.Sprintf("spyware=%s styx=%s", spyMode, styxMode)
		if err := s.ledger.Append("v6.mode.request", detail, "operator-authorized; reason-sha256="+hex.EncodeToString(digest[:])); err != nil {
			s.writeError(w, http.StatusInternalServerError, "V6 mode evidence preflight failed")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if s.settings != nil {
		snap := s.settings.Snapshot()
		nextValues := make(map[string]any, len(snap.Values[settings.SectionV6])+2)
		for k, v := range snap.Values[settings.SectionV6] {
			nextValues[k] = v
		}
		if spyMode != "" {
			nextValues["spywareMode"] = spyMode
		}
		if styxMode != "" {
			nextValues["styxMode"] = styxMode
		}
		if _, err := s.settings.Apply(ctx, settings.SectionV6, nextValues, reason, settings.ConfirmationApplySettings); err != nil {
			log.Printf("v6 settings apply failed: %v", err)
			s.writeError(w, http.StatusConflict, "V6 Modus konnte nicht angewendet werden: "+err.Error())
			return
		}
	} else {
		if spyMode != "" {
			if s.v6 == nil {
				s.writeError(w, http.StatusServiceUnavailable, "V6 Sovereign runtime unavailable")
				return
			}
			if err := s.v6.SetSpywareMode(ctx, spyMode); err != nil {
				s.writeError(w, http.StatusConflict, "V6 Anti-Spyware Modus abgelehnt: "+err.Error())
				return
			}
		}
		if styxMode != "" {
			if s.mhx == nil {
				s.writeError(w, http.StatusServiceUnavailable, "StyX runtime unavailable")
				return
			}
			if _, err := s.mhx.SetStyxMode(ctx, styxMode); err != nil {
				s.writeError(w, http.StatusConflict, "StyX Kernel-WFP Durchsetzung fehlgeschlagen: "+err.Error())
				return
			}
		}
	}

	s.writeJSON(w, http.StatusOK, s.buildV6StatusResponse(v6DefaultLimit))
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
	s.initGeo()
	limit := parseV6Limit(r, v6DefaultLimit)
	incidents := []v6StyxIncidentView{}
	if s.mhx != nil {
		if raw := s.mhx.StyxIncidents(limit); len(raw) > 0 {
			incidents = s.enrichStyxIncidents(raw)
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"incidents": incidents,
	})
}

func (s *Server) v6StyxWhitelist(w http.ResponseWriter, _ *http.Request) {
	entries := []string{}
	blocked := []string{}
	if ctrl, ok := s.mhx.(styxControlProvider); ok {
		if wl := ctrl.StyxWhitelist(); len(wl) > 0 {
			entries = wl
		}
		if bt := ctrl.StyxBlockedTargets(); len(bt) > 0 {
			blocked = bt
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"entries":        entries,
		"blockedTargets": blocked,
	})
}

type v6StyxWhitelistRequest struct {
	Action  string   `json:"action"`
	Entry   string   `json:"entry,omitempty"`
	Entries []string `json:"entries,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

func (s *Server) v6SetStyxWhitelist(w http.ResponseWriter, r *http.Request) {
	var input v6StyxWhitelistRequest
	if err := decodeJSONBounded(w, r, &input, 32<<10); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	reason := strings.TrimSpace(input.Reason)
	if err := validateReason(reason); err != nil {
		s.writeError(w, http.StatusBadRequest, "operator reason (8..512 chars) required")
		return
	}
	ctrl, ok := s.mhx.(styxControlProvider)
	if !ok {
		s.writeError(w, http.StatusServiceUnavailable, "StyX whitelist runtime unavailable")
		return
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	current := ctrl.StyxWhitelist()
	var next []string
	switch action {
	case "add":
		entry := strings.TrimSpace(input.Entry)
		if entry == "" {
			s.writeError(w, http.StatusBadRequest, "whitelist entry required")
			return
		}
		next = append(append([]string(nil), current...), entry)
	case "remove":
		target := strings.TrimSpace(input.Entry)
		if target == "" {
			s.writeError(w, http.StatusBadRequest, "whitelist entry required")
			return
		}
		for _, item := range current {
			if !strings.EqualFold(item, target) {
				next = append(next, item)
			}
		}
	case "set":
		next = append([]string(nil), input.Entries...)
	default:
		s.writeError(w, http.StatusBadRequest, "action must be add, remove, or set")
		return
	}

	normalized, normErr := mhx.NormalizeStyxWhitelist(next)
	if normErr != nil {
		s.writeError(w, http.StatusBadRequest, normErr.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if s.settings != nil {
		snap := s.settings.Snapshot()
		nextValues := make(map[string]any, len(snap.Values[settings.SectionV6])+1)
		for k, v := range snap.Values[settings.SectionV6] {
			nextValues[k] = v
		}
		nextValues["styxWhitelist"] = normalized
		if _, err := s.settings.Apply(ctx, settings.SectionV6, nextValues, reason, settings.ConfirmationApplySettings); err != nil {
			s.writeError(w, http.StatusConflict, "StyX Whitelist konnte nicht gespeichert werden: "+err.Error())
			return
		}
	} else {
		if _, err := ctrl.SetStyxWhitelist(ctx, normalized); err != nil {
			s.writeError(w, http.StatusConflict, "StyX Whitelist abgelehnt: "+err.Error())
			return
		}
	}

	digest := sha256.Sum256([]byte(reason))
	if s.ledger != nil {
		_ = s.ledger.Append("v6.styx.whitelist", fmt.Sprintf("action=%s entries=%d", action, len(normalized)), "reason-sha256="+hex.EncodeToString(digest[:]))
	}
	s.writeJSON(w, http.StatusOK, s.buildV6StatusResponse(v6DefaultLimit))
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
