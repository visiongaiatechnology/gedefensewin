// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// styxPollInterval is the flow-statistics cadence of the passive egress
	// detector. It matches the network watcher cadence so window deltas line up.
	styxPollInterval = 2 * time.Second
	// maximumStyxIncidents bounds the in-memory incident projection.
	maximumStyxIncidents = 256
	// maximumStyxWFPBlocks caps dynamically installed remote host block filters.
	maximumStyxWFPBlocks = 64
	// maximumStyxWhitelist caps persisted StyX program/path/IP whitelist rules.
	maximumStyxWhitelist = 512
)

// startStyxRuntime constructs the StyX egress/beacon detector. It starts in
// observe mode by default; RestoreStyxMode / SetStyxMode can switch to off,
// observe, or enforce (activating dynamic GeDefense-V6-Sovereign-WFP filters).
func (e *Engine) startStyxRuntime() {
	if e == nil {
		return
	}
	settings := DefaultStyxSettings()
	settings.Enabled = true
	settings.Mode = StyxModeObserve
	beacon, err := NewStyxBeaconEngine(StyxBeaconConfig{
		Settings: settings,
		// The iphlpapi TCP table is available on Windows; data-estats and DNS
		// attribution are proven only after real observations, so they start
		// false and are upgraded dynamically by the collection loop.
		FlowCapabilityKnown:     true,
		RxObservationAvailable:  false,
		DNSObservationAvailable: false,
	})
	if err != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("styx.unavailable", "STYX egress/beacon detector could not be constructed; beacon detection is DISABLED", err.Error())
		}
		return
	}
	e.mu.Lock()
	e.styx = beacon
	e.styxCollector = NewStyxCollector(StyxCollectorConfig{Now: func() time.Time { return time.Now().UTC() }})
	e.styxDesiredMode = StyxModeObserve
	e.mu.Unlock()

	e.styxEnforceMu.Lock()
	if e.styxWFP == nil {
		e.styxWFP = newStyxEnforcer()
	}
	e.styxEnforceMu.Unlock()
}

// RestoreStyxMode applies a persisted StyX mode during engine composition. If
// enforce was persisted, Run reconciles kernel WFP filters once the service starts.
func (e *Engine) RestoreStyxMode(mode string) error {
	if e == nil {
		return errors.New("mhx engine unavailable")
	}
	normalized, err := styxNormalizeMode(mode)
	if err != nil {
		return err
	}
	e.mu.Lock()
	styx := e.styx
	e.styxDesiredMode = normalized
	e.mu.Unlock()
	if styx == nil {
		return errors.New("styX detector unavailable")
	}
	return styx.SetMode(normalized)
}

// SetStyxMode switches StyX between off, observe, and enforce. Switching to
// enforce synchronizes dynamic kernel WFP filters immediately and fails closed
// (rolling back to the previous detector mode) when kernel WFP cannot open.
func (e *Engine) SetStyxMode(ctx context.Context, mode string) (StyxStatus, error) {
	if e == nil {
		return StyxStatus{Mode: StyxModeOff, SensorState: "unavailable", Capability: "missing"}, errors.New("mhx engine unavailable")
	}
	if ctx != nil && ctx.Err() != nil {
		return e.StyxStatus(), ctx.Err()
	}
	normalized, err := styxNormalizeMode(mode)
	if err != nil {
		return e.StyxStatus(), err
	}
	e.mu.Lock()
	styx := e.styx
	prevDesired := e.styxDesiredMode
	e.mu.Unlock()
	if styx == nil {
		return e.StyxStatus(), errors.New("styX detector unavailable")
	}
	prevMode := styx.Settings().EffectiveMode()
	if err := styx.SetMode(normalized); err != nil {
		return e.StyxStatus(), err
	}

	var wfpState styxEnforceState
	e.styxEnforceMu.Lock()
	if e.styxWFP == nil {
		e.styxWFP = newStyxEnforcer()
	}
	enforcer := e.styxWFP
	if normalized == StyxModeEnforce {
		wfpState, err = enforcer.Sync(ctx, e.buildStyxWFPConfig())
		if err != nil {
			e.styxEnforceMu.Unlock()
			_ = styx.SetMode(prevMode)
			return e.StyxStatus(), fmt.Errorf("styX kernel WFP enforcement failed: %w", err)
		}
	} else {
		_ = enforcer.Close()
		wfpState = enforcer.State()
	}
	e.styxEnforceMu.Unlock()

	e.mu.Lock()
	e.styxDesiredMode = normalized
	e.mu.Unlock()

	if e.ledger != nil && (prevDesired != normalized || normalized == StyxModeEnforce) {
		_ = e.ledger.Append("styx.mode", normalized, fmt.Sprintf("wfp_active=%t filters=%d", wfpState.Active, wfpState.FilterCount))
	}
	return e.StyxStatus(), nil
}

func (e *Engine) closeStyxWFP() {
	if e == nil {
		return
	}
	e.styxEnforceMu.Lock()
	enforcer := e.styxWFP
	e.styxEnforceMu.Unlock()
	if enforcer != nil {
		_ = enforcer.Close()
	}
}

func (e *Engine) reconcileStyxWFP(ctx context.Context) {
	if e == nil {
		return
	}
	e.mu.Lock()
	desired := e.styxDesiredMode
	styx := e.styx
	e.mu.Unlock()
	if desired != StyxModeEnforce || styx == nil {
		return
	}
	if _, err := e.SetStyxMode(ctx, StyxModeEnforce); err != nil && e.ledger != nil {
		_ = e.ledger.Append("styx.wfp", "reconcile-failed", err.Error())
	}
}

// styxLoop polls flow statistics until the engine context is cancelled. Every
// poll either yields evidence-backed samples or an error; a failed poll never
// produces synthetic zero samples.
func (e *Engine) styxLoop(ctx context.Context) {
	if e == nil || e.styx == nil || e.styxCollector == nil {
		return
	}
	e.reconcileStyxWFP(ctx)
	ticker := time.NewTicker(styxPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !e.styx.Settings().Enabled {
				// Keep live per-program destination telemetry fresh in Overview even
				// when StyX anomaly detection is switched off.
				_, _ = e.styxCollector.Poll(ctx)
				continue
			}
			incidents, err := e.styxCollector.PollInto(ctx, e.styx)
			if err != nil {
				if ctx.Err() == nil {
					e.logSentinelThrottled("styx.collector", "TCP flow statistics unavailable", err.Error())
				}
			}
			if collectorStatus := e.styxCollector.Status(); collectorStatus.DataObservationAvailable {
				// Receive bytes are provable only after a successful estats read;
				// the detector upgrades its signal 2 capability from this fact.
				e.styx.SetRxObservationAvailable(true)
			}
			for _, incident := range incidents {
				e.enrichStyxIncidentIdentity(&incident)
				if isStyxSelfIncident(incident) {
					continue
				}
				if e.isStyxIncidentWhitelisted(incident) {
					incident.Whitelisted = true
					incident.Action = "whitelisted"
					incident.Outcome = "freigegeben durch StyX-Whitelist; keine WFP-Sperre"
					e.recordStyxIncident(incident)
					continue
				}
				e.enforceStyxIncident(ctx, &incident)
				e.recordStyxIncident(incident)
			}
		}
	}
}

func (e *Engine) enrichStyxIncidentIdentity(incident *StyxIncident) {
	if e == nil || incident == nil {
		return
	}
	if (incident.Process == "" || incident.Process == "unknown" || incident.ProcessPath == "") && e.styxCollector != nil && incident.PID > 0 {
		name, path := e.styxCollector.resolveProcess(incident.PID)
		if name != "" && (incident.Process == "" || incident.Process == "unknown") {
			incident.Process = name
		}
		if path != "" && incident.ProcessPath == "" {
			incident.ProcessPath = path
		}
	}
	if incident.ProcessPath == "" && incident.PID > 0 {
		e.mu.RLock()
		recent, ok := e.recentProcesses[uint32(incident.PID)]
		e.mu.RUnlock()
		if ok {
			if recent.event.Image != "" && (incident.Process == "" || incident.Process == "unknown") {
				incident.Process = recent.event.Image
			}
			if recent.event.ImagePath != "" {
				incident.ProcessPath = recent.event.ImagePath
			}
		}
	}
}

func isStyxSelfIncident(incident StyxIncident) bool {
	if incident.PID > 0 && incident.PID == os.Getpid() {
		return true
	}
	exe, err := os.Executable()
	if err == nil && exe != "" && incident.ProcessPath != "" {
		exeDir := filepath.Clean(filepath.Dir(exe))
		procDir := filepath.Clean(filepath.Dir(incident.ProcessPath))
		if strings.EqualFold(exeDir, procDir) {
			return true
		}
	}
	return false
}

// NormalizeStyxWhitelist validates and canonicalizes StyX whitelist entries.
// Supported entries are CIDR/IP prefixes, absolute executable paths, or exact
// executable filenames ending with .exe.
func NormalizeStyxWhitelist(entries []string) ([]string, error) {
	if len(entries) > maximumStyxWhitelist {
		return nil, fmt.Errorf("styX whitelist exceeds maximum of %d entries", maximumStyxWhitelist)
	}
	seen := make(map[string]struct{}, len(entries))
	normalized := make([]string, 0, len(entries))
	for _, raw := range entries {
		cleaned := strings.TrimSpace(raw)
		if cleaned == "" {
			continue
		}
		if len(cleaned) > 512 || strings.ContainsAny(cleaned, "\r\n\x00") {
			return nil, fmt.Errorf("styX whitelist entry rejected: %q", cleaned)
		}
		var canonical string
		if prefix, err := StyxCanonicalAllowPrefix(cleaned); err == nil {
			canonical = prefix.String()
		} else if filepath.IsAbs(cleaned) && !strings.Contains(cleaned, "..") {
			canonical = filepath.Clean(cleaned)
		} else if !strings.ContainsAny(cleaned, `/\:`) && strings.HasSuffix(strings.ToLower(cleaned), ".exe") {
			canonical = cleaned
		} else {
			return nil, fmt.Errorf("styX whitelist entry must be an IP/CIDR, absolute executable path, or .exe filename: %q", cleaned)
		}
		key := strings.ToLower(canonical)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

// StyxWhitelist returns a copy of active StyX whitelist entries.
func (e *Engine) StyxWhitelist() []string {
	if e == nil {
		return []string{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, len(e.styxWhitelist))
	copy(out, e.styxWhitelist)
	return out
}

// RestoreStyxWhitelist applies a persisted whitelist snapshot on startup.
func (e *Engine) RestoreStyxWhitelist(entries []string) error {
	if e == nil {
		return nil
	}
	normalized, err := NormalizeStyxWhitelist(entries)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.styxWhitelist = normalized
	e.mu.Unlock()
	return nil
}

// SetStyxWhitelist validates, applies and reconciles kernel WFP filters when
// StyX is enforcing so newly whitelisted paths/IPs are unblocked immediately.
func (e *Engine) SetStyxWhitelist(ctx context.Context, entries []string) ([]string, error) {
	if e == nil {
		return nil, errors.New("mhx engine unavailable")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	normalized, err := NormalizeStyxWhitelist(entries)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.styxWhitelist = normalized
	for idx := range e.styxIncidents {
		inc := &e.styxIncidents[idx]
		if styxEntryMatchesList(normalized, *inc) {
			inc.Whitelisted = true
			if inc.Action == "wfp-blocked" || inc.Action == "none" {
				inc.Action = "whitelisted"
				inc.Outcome = "freigegeben durch StyX-Whitelist; WFP-Sperre aufgehoben"
			}
		} else if inc.Action == "whitelisted" {
			inc.Whitelisted = false
		}
	}
	styx := e.styx
	e.mu.Unlock()

	if styx != nil && styx.Settings().IsEnforcing() {
		e.styxEnforceMu.Lock()
		if e.styxWFP == nil {
			e.styxWFP = newStyxEnforcer()
		}
		_, syncErr := e.styxWFP.Sync(ctx, e.buildStyxWFPConfig())
		e.styxEnforceMu.Unlock()
		if syncErr != nil {
			return normalized, fmt.Errorf("styX WFP whitelist sync failed: %w", syncErr)
		}
	}
	if e.ledger != nil {
		_ = e.ledger.Append("styx.whitelist", fmt.Sprintf("entries=%d", len(normalized)), "updated")
	}
	return append([]string(nil), normalized...), nil
}

func (e *Engine) isStyxIncidentWhitelisted(incident StyxIncident) bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	list := append([]string(nil), e.styxWhitelist...)
	e.mu.RUnlock()
	return styxEntryMatchesList(list, incident)
}

func styxEntryMatchesList(entries []string, incident StyxIncident) bool {
	if len(entries) == 0 {
		return false
	}
	var remoteIP netip.Addr
	if raw := strings.TrimSpace(incident.Remote); raw != "" {
		if ap, err := netip.ParseAddrPort(raw); err == nil {
			remoteIP = ap.Addr().Unmap()
		} else if parsed, err := netip.ParseAddr(raw); err == nil {
			remoteIP = parsed.Unmap()
		}
	}
	cleanProcPath := strings.ToLower(strings.TrimSpace(filepath.Clean(incident.ProcessPath)))
	if incident.ProcessPath == "" {
		cleanProcPath = ""
	}
	cleanProcName := strings.ToLower(strings.TrimSpace(incident.Process))
	for _, entry := range entries {
		if prefix, err := StyxCanonicalAllowPrefix(entry); err == nil {
			if remoteIP.IsValid() && prefix.Contains(remoteIP) {
				return true
			}
			continue
		}
		if filepath.IsAbs(entry) {
			if cleanProcPath != "" && strings.EqualFold(cleanProcPath, filepath.Clean(entry)) {
				return true
			}
			continue
		}
		if cleanProcName != "" && strings.EqualFold(cleanProcName, entry) {
			return true
		}
		if cleanProcPath != "" && strings.EqualFold(filepath.Base(cleanProcPath), entry) {
			return true
		}
	}
	return false
}

func (e *Engine) buildStyxWFPConfig() styxEnforceConfig {
	prefixes := e.collectEnforceBlockPrefixes()
	e.mu.RLock()
	whitelist := append([]string(nil), e.styxWhitelist...)
	e.mu.RUnlock()
	permitPaths := make([]string, 0, len(whitelist))
	for _, entry := range whitelist {
		if !filepath.IsAbs(entry) {
			continue
		}
		info, err := os.Stat(entry)
		if err != nil || info.IsDir() {
			continue
		}
		permitPaths = append(permitPaths, filepath.Clean(entry))
		if len(permitPaths) >= 64 {
			break
		}
	}
	return styxEnforceConfig{
		BlockPrefixes:  prefixes,
		PermitAppPaths: permitPaths,
	}
}

func (e *Engine) StyxBlockedTargets() []string {
	if e == nil || e.styx == nil || !e.styx.Settings().IsEnforcing() {
		return []string{}
	}
	prefixes := e.collectEnforceBlockPrefixes()
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

func (e *Engine) StyxProgramTraffic() []StyxProgramTrafficSummary {
	if e == nil || e.styxCollector == nil {
		return []StyxProgramTrafficSummary{}
	}
	return e.styxCollector.ProgramSnapshots()
}

func (e *Engine) enforceStyxIncident(ctx context.Context, incident *StyxIncident) {
	if e == nil || incident == nil || e.styx == nil || !e.styx.Settings().IsEnforcing() {
		return
	}
	if e.isStyxIncidentWhitelisted(*incident) {
		incident.Whitelisted = true
		incident.Action = "whitelisted"
		incident.Outcome = "freigegeben durch StyX-Whitelist; keine WFP-Sperre"
		return
	}
	prefix, ok := styxIncidentBlockPrefix(*incident)
	if !ok {
		return
	}
	if incident.Decision != StyxDecisionContain && incident.Score < 200 {
		return
	}

	cfg := e.buildStyxWFPConfig()
	already := false
	for _, existing := range cfg.BlockPrefixes {
		if existing == prefix {
			already = true
			break
		}
	}
	if !already && len(cfg.BlockPrefixes) < maximumStyxWFPBlocks {
		cfg.BlockPrefixes = append(cfg.BlockPrefixes, prefix)
	}

	e.styxEnforceMu.Lock()
	if e.styxWFP == nil {
		e.styxWFP = newStyxEnforcer()
	}
	_, err := e.styxWFP.Sync(ctx, cfg)
	e.styxEnforceMu.Unlock()

	if err != nil {
		incident.Action = "wfp-failed"
		incident.Outcome = truncate("kernel WFP enforcement failed: "+err.Error(), 240)
		return
	}
	incident.Action = "wfp-blocked"
	incident.Outcome = "blocked outgoing beacon target in kernel WFP (GeDefense-V6-Sovereign-WFP)"
}

func (e *Engine) collectEnforceBlockPrefixes() []netip.Prefix {
	e.mu.RLock()
	incidents := append([]StyxIncident(nil), e.styxIncidents...)
	whitelist := append([]string(nil), e.styxWhitelist...)
	e.mu.RUnlock()

	seen := make(map[netip.Prefix]struct{}, 16)
	prefixes := make([]netip.Prefix, 0, 16)
	for index := len(incidents) - 1; index >= 0 && len(prefixes) < maximumStyxWFPBlocks; index-- {
		inc := incidents[index]
		if inc.Whitelisted || styxEntryMatchesList(whitelist, inc) || isStyxSelfIncident(inc) {
			continue
		}
		if inc.Decision != StyxDecisionContain && inc.Action != "wfp-blocked" {
			continue
		}
		prefix, ok := styxIncidentBlockPrefix(inc)
		if !ok {
			continue
		}
		if _, dup := seen[prefix]; dup {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func styxIncidentBlockPrefix(incident StyxIncident) (netip.Prefix, bool) {
	raw := strings.TrimSpace(incident.Remote)
	if raw == "" {
		return netip.Prefix{}, false
	}
	var addr netip.Addr
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		addr = ap.Addr()
	} else if parsed, err := netip.ParseAddr(raw); err == nil {
		addr = parsed
	} else {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() {
		return netip.Prefix{}, false
	}
	prefix, err := StyxBlockableHostPrefix(addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// recordStyxIncident stores a bounded incident projection and writes the
// evidence record.
func (e *Engine) recordStyxIncident(incident StyxIncident) {
	if e == nil || incident.ID == "" {
		return
	}
	e.mu.Lock()
	e.styxIncidents = append(e.styxIncidents, incident)
	if len(e.styxIncidents) > maximumStyxIncidents {
		copy(e.styxIncidents, e.styxIncidents[len(e.styxIncidents)-maximumStyxIncidents:])
		e.styxIncidents = e.styxIncidents[:maximumStyxIncidents]
	}
	e.mu.Unlock()

	if e.ledger != nil {
		detail := fmt.Sprintf("styX %s score=%d signals=%v action=%s", incident.Category, incident.Score, incident.Signals, incident.Action)
		_ = e.ledger.Append("styx.incident", truncate(detail, 512), incident.ID)
	}
	e.notifyEvent(notificationKindThreatIntel, incident.Severity, "STYX Egress-/Beacon-Evidenz", truncate(incident.Summary, 512))
}

// StyxStatus returns the bounded detector status. A missing detector is reported
// honestly as unavailable instead of inventing health.
func (e *Engine) StyxStatus() StyxStatus {
	if e == nil || e.styx == nil {
		return StyxStatus{Mode: StyxModeOff, SensorState: "unavailable", Capability: "missing", Top: []StyxFlowSnapshot{}}
	}
	status := e.styx.Status()
	e.styxEnforceMu.Lock()
	enforcer := e.styxWFP
	e.styxEnforceMu.Unlock()
	if enforcer != nil {
		wfp := enforcer.State()
		status.WFPActive = wfp.Active
		status.WFPFilterCount = wfp.FilterCount
		status.WFPLastError = wfp.LastError
	}
	return status
}

// StyxCollectorStatus returns the bounded flow-collector projection.
func (e *Engine) StyxCollectorStatus() StyxCollectorStatus {
	if e == nil || e.styxCollector == nil {
		return StyxCollectorStatus{}
	}
	return e.styxCollector.Status()
}

// StyxIncidents returns the newest incidents first, bounded by limit.
func (e *Engine) StyxIncidents(limit int) []StyxIncident {
	if limit <= 0 || limit > maximumStyxIncidents {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.styxIncidents) - limit
	if start < 0 {
		start = 0
	}
	result := make([]StyxIncident, 0, len(e.styxIncidents)-start)
	for index := len(e.styxIncidents) - 1; index >= start; index-- {
		result = append(result, e.styxIncidents[index])
	}
	return result
}
