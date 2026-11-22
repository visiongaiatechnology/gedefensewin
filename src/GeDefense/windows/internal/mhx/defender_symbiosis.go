// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	defenderTamperHealCooldown = 60 * time.Second
)

// DefenderScanResult captures the outcome of a targeted MpCmdRun.exe scan.
type DefenderScanResult struct {
	TargetPath   string    `json:"targetPath"`
	ScannerPath  string    `json:"scannerPath,omitempty"`
	TimestampUTC time.Time `json:"timestampUtc"`
	DurationMS   int64     `json:"durationMs"`
	ExitCode     int       `json:"exitCode"`
	Status       string    `json:"status"` // CLEAN, THREAT_FOUND, ERROR, TIMEOUT
	ThreatFound  bool      `json:"threatFound"`
	ThreatName   string    `json:"threatName,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

// DefenderSymbiosisStatus exposes the live bi-directional integration state
// between GeDefense (MHX/Titan/Containments) and Microsoft Defender.
type DefenderSymbiosisStatus struct {
	Enabled                     bool                `json:"enabled"`
	SubscribedEventIDs          []int               `json:"subscribedEventIds"`
	OracleAvailable             bool                `json:"oracleAvailable"`
	OraclePath                  string              `json:"oraclePath,omitempty"`
	OracleScansTotal            uint64              `json:"oracleScansTotal"`
	OracleThreatsFound          uint64              `json:"oracleThreatsFound"`
	LastOracleScan              *DefenderScanResult `json:"lastOracleScan,omitempty"`
	DetectionsObserved          uint64              `json:"detectionsObserved"`
	RemediationFailuresObserved uint64              `json:"remediationFailuresObserved"`
	ASRBlocksObserved           uint64              `json:"asrBlocksObserved"`
	CFABlocksObserved           uint64              `json:"cfaBlocksObserved"`
	NetworkBlocksObserved       uint64              `json:"networkBlocksObserved"`
	TamperEventsObserved        uint64              `json:"tamperEventsObserved"`
	AutoHealsTriggered          uint64              `json:"autoHealsTriggered"`
	ActiveContainments          int                 `json:"activeContainments"`
	TotalContainments           int                 `json:"totalContainments"`
	LastSymbiosisActionUTC      time.Time           `json:"lastSymbiosisActionUtc,omitempty"`
	LastSymbiosisDetail         string              `json:"lastSymbiosisDetail,omitempty"`
}

type defenderOracleFunc func(context.Context, string) (DefenderScanResult, error)

// parseMpCmdRunThreat extracts a bounded threat identifier from MpCmdRun stdout.
func parseMpCmdRunThreat(output string) string {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "threat") || strings.HasPrefix(lower, "bedrohung") {
			if idx := strings.IndexByte(line, ':'); idx >= 0 && idx+1 < len(line) {
				candidate := trimSentinelText(strings.TrimSpace(line[idx+1:]))
				if len(candidate) > 0 {
					return candidate
				}
			}
		}
	}
	return ""
}

// ScanFileWithDefender executes a bounded, read-only custom scan through the
// Authenticode-verified MpCmdRun.exe binary and records the finding.
func (e *Engine) ScanFileWithDefender(ctx context.Context, path string) (DefenderScanResult, error) {
	if strings.TrimSpace(path) == "" {
		return DefenderScanResult{}, errors.New("scan file path is required")
	}
	oracle := e.defenderOracleFn()
	result, err := oracle(ctx, path)
	e.mu.Lock()
	e.symbiosis.OracleScansTotal++
	if result.ThreatFound {
		e.symbiosis.OracleThreatsFound++
		e.symbiosis.LastSymbiosisActionUTC = result.TimestampUTC
		e.symbiosis.LastSymbiosisDetail = fmt.Sprintf("Defender Oracle Fund: %s (%s)", result.ThreatName, filepath.Base(result.TargetPath))
	}
	copyResult := result
	e.symbiosis.LastOracleScan = &copyResult
	e.mu.Unlock()

	if result.ThreatFound {
		_ = e.ledger.Append("defender.oracle", result.TargetPath, "threat-found: "+result.ThreatName)
		e.notifyEvent(notificationKindDefender, SeverityCritical, "Microsoft Defender Scan-Treffer", fmt.Sprintf("%s in %s", result.ThreatName, filepath.Base(result.TargetPath)))
	} else if err == nil {
		_ = e.ledger.Append("defender.oracle", result.TargetPath, "clean")
	} else {
		_ = e.ledger.Append("defender.oracle", path, "scan-error: "+trimSentinelText(err.Error()))
	}
	return result, err
}

// ReconcileDefenderSymbiosis re-enforces the signed MHX/Defender baseline (e.g.
// after Event 5001/5007/5010/5012 or manual operator request).
func (e *Engine) ReconcileDefenderSymbiosis(ctx context.Context, force bool, trigger string) error {
	now := time.Now().UTC()
	e.mu.Lock()
	if !force && !e.lastTamperHealUTC.IsZero() && now.Sub(e.lastTamperHealUTC) < defenderTamperHealCooldown {
		e.mu.Unlock()
		return nil
	}
	e.lastTamperHealUTC = now
	e.mu.Unlock()

	if err := e.acquirePolicy(ctx); err != nil {
		return err
	}
	defer e.releasePolicy()

	mode := e.Mode()
	verified, err := e.protection.Apply(ctx, mode)
	if err != nil {
		_ = e.ledger.Append("defender.tamper_heal", trigger, "failed: "+trimSentinelText(err.Error()))
		return err
	}
	e.defenderMu.Lock()
	e.defenderCacheAt = time.Time{}
	e.defenderMu.Unlock()

	e.mu.Lock()
	e.symbiosis.AutoHealsTriggered++
	e.symbiosis.LastSymbiosisActionUTC = time.Now().UTC()
	e.symbiosis.LastSymbiosisDetail = fmt.Sprintf("Defender/MHX Baseline wiederhergestellt (%s, mode=%s)", trimSentinelText(trigger), verified.Mode)
	e.mu.Unlock()

	_ = e.ledger.Append("defender.tamper_heal", trigger, fmt.Sprintf("restored-mode=%s; realtime=%v", verified.Mode, verified.DefenderRealtime))
	return nil
}

// RecordTitanCompromise closes the cross-engine correlation gap in MHX so a
// Titan TrustCompromised attribution contributes to FairScorer immediately.
func (e *Engine) RecordTitanCompromise(target TerminationTarget) {
	if target.PID <= 4 {
		return
	}
	now := time.Now().UTC()
	e.mu.Lock()
	recordBoundedPIDHit(&e.titanHits, target.PID, now)
	e.symbiosis.LastSymbiosisActionUTC = now
	e.symbiosis.LastSymbiosisDetail = fmt.Sprintf("Titan-Korrelation verknüpft: %s (PID %d)", filepath.Base(target.ImagePath), target.PID)
	e.mu.Unlock()
	_ = e.ledger.Append("titan.correlation", fmt.Sprintf("pid=%d; image=%s", target.PID, filepath.Base(target.ImagePath)), trimSentinelText(target.Reason))
}

func (e *Engine) pidHasRecentTitanHit(pid uint32) bool {
	return e.pidHasRecentHitLocked(&e.titanHits, pid)
}

func (e *Engine) pidHasRecentDefenderHit(pid uint32) bool {
	return e.pidHasRecentHitLocked(&e.defenderHits, pid)
}

func (e *Engine) pidHasRecentHitLocked(store *map[uint32]time.Time, pid uint32) bool {
	if pid <= 4 {
		return false
	}
	e.mu.RLock()
	if *store == nil {
		e.mu.RUnlock()
		return false
	}
	seen, found := (*store)[pid]
	e.mu.RUnlock()
	if !found {
		return false
	}
	return time.Since(seen) <= threatHitTTL
}

func recordBoundedPIDHit(store *map[uint32]time.Time, pid uint32, at time.Time) {
	if pid <= 4 {
		return
	}
	if *store == nil {
		*store = make(map[uint32]time.Time, 64)
	}
	(*store)[pid] = at
	if len(*store) > maxThreatHits {
		cutoff := at.Add(-threatHitTTL)
		for key, seen := range *store {
			if seen.Before(cutoff) {
				delete(*store, key)
			}
		}
		if len(*store) > maxThreatHits {
			*store = make(map[uint32]time.Time, 64)
		}
	}
}

// SymbiosisStatus returns a consistent snapshot of Defender Symbiosis and
// active process-tree containments.
func (e *Engine) SymbiosisStatus() DefenderSymbiosisStatus {
	cliPath, cliErr := locateDefenderCLI()
	e.mu.RLock()
	status := e.symbiosis
	status.Enabled = true
	status.SubscribedEventIDs = append([]int(nil), defenderEventIDs...)
	status.OracleAvailable = cliErr == nil && cliPath != ""
	if status.OracleAvailable {
		status.OraclePath = cliPath
	}
	if e.symbiosis.LastOracleScan != nil {
		copyScan := *e.symbiosis.LastOracleScan
		status.LastOracleScan = &copyScan
	}
	active := 0
	for _, item := range e.containments {
		if item.State == ContainmentFrozen {
			active++
		}
	}
	status.ActiveContainments = active
	status.TotalContainments = len(e.containments)
	e.mu.RUnlock()
	return status
}

func (e *Engine) defenderOracleFn() defenderOracleFunc {
	if e != nil && e.defenderOracle != nil {
		return e.defenderOracle
	}
	return runDefenderFileOracle
}

func firstNonEmptyDefenderField(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

// findUniqueRecentProcessByPath resolves an unambiguous recently observed
// process for an image path reported in a Defender operational event. If zero or
// multiple distinct active processes share that image path without a PID match,
// it refuses to guess (anti-false-positive boundary).
func (e *Engine) findUniqueRecentProcessByPath(processPath string) (ProcessEvent, bool) {
	cleaned := strings.TrimSpace(processPath)
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return ProcessEvent{}, false
	}
	now := time.Now().UTC()
	e.mu.RLock()
	defer e.mu.RUnlock()
	var matched ProcessEvent
	matches := 0
	for _, item := range e.recentProcesses {
		if now.After(item.expires) {
			continue
		}
		if winapi.SameImagePath(item.event.ImagePath, cleaned) {
			matched = item.event
			matches++
		}
	}
	if matches != 1 {
		return ProcessEvent{}, false
	}
	return matched, true
}

func (e *Engine) applyDefenderSymbiosis(event defenderEvent, severity Severity, detection string, timestamp time.Time) {
	processPath := firstNonEmptyDefenderField(event.Fields, "process name", "process", "targetprocessname")
	targetPath := firstNonEmptyDefenderField(event.Fields, "path", "target", "targetfile", "destination", "uri")
	threatName := firstNonEmptyDefenderField(event.Fields, "threat name", "id", "rule id")

	// 1. Update structured symbiosis metrics cleanly inside e.mu.
	e.mu.Lock()
	switch event.EventID {
	case 1116:
		e.symbiosis.DetectionsObserved++
	case 1118, 1119:
		e.symbiosis.RemediationFailuresObserved++
	case 1121, 1122:
		e.symbiosis.ASRBlocksObserved++
	case 1123, 1124:
		e.symbiosis.CFABlocksObserved++
	case 1125, 1126:
		e.symbiosis.NetworkBlocksObserved++
	case 5001, 5007, 5010, 5012, 5013:
		e.symbiosis.TamperEventsObserved++
	}
	e.mu.Unlock()

	mode := e.Mode()
	settings := e.currentPolicySettings()

	// 2. Tamper / Disable events (5001, 5010, 5012, 5007) -> invalidate cache
	// and reconcile signed baseline in Guarded/Sovereign mode.
	if event.EventID == 5001 || event.EventID == 5010 || event.EventID == 5012 || event.EventID == 5007 {
		e.defenderMu.Lock()
		e.defenderCacheAt = time.Time{}
		e.defenderMu.Unlock()
		if mode != "monitor" {
			trigger := fmt.Sprintf("defender-event-%d", event.EventID)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				_ = e.ReconcileDefenderSymbiosis(ctx, false, trigger)
			}()
		}
		return
	}

	// 3. Process correlation & containment for active enforcement events.
	isActionableBlock := event.EventID == 1116 || event.EventID == 1118 || event.EventID == 1119 || event.EventID == 1121 || event.EventID == 1123
	if !isActionableBlock {
		return
	}

	matchedProc, hasProc := e.findUniqueRecentProcessByPath(processPath)
	if hasProc {
		e.mu.Lock()
		recordBoundedPIDHit(&e.defenderHits, matchedProc.PID, timestamp)
		if threatName != "" {
			e.symbiosis.LastSymbiosisActionUTC = timestamp
			e.symbiosis.LastSymbiosisDetail = fmt.Sprintf("Defender Event %d korreliert mit %s (PID %d): %s", event.EventID, matchedProc.Image, matchedProc.PID, threatName)
		}
		// Record an enriched AttackStory linking the process and Defender signal.
		story := AttackStory{
			ID:         fmt.Sprintf("def-%d-%d", event.EventID, event.RecordID),
			StartedUTC: timestamp,
			UpdatedUTC: timestamp,
			PID:        matchedProc.PID,
			Image:      matchedProc.Image,
			Severity:   severity,
			Signals:    []string{fmt.Sprintf("defender.event.%d", event.EventID), "defender.symbiosis"},
			Response:   "DEFENDER_CORRELATED",
		}
		if threatName != "" {
			story.ThreatSources = []string{threatName}
		}
		e.attackStories = append(e.attackStories, story)
		if len(e.attackStories) > maximumAttackStories {
			e.attackStories = append([]AttackStory(nil), e.attackStories[len(e.attackStories)-maximumAttackStories:]...)
		}
		e.mu.Unlock()

		// Automatic reversible tree freeze on CFA ransomware attempts (1123),
		// remediation failures (1118/1119), or active malware detections (1116)
		// when Guarded/Sovereign mode and AutoResponse are armed.
		shouldFreeze := (event.EventID == 1123 || event.EventID == 1118 || event.EventID == 1119 || event.EventID == 1116) &&
			mode != "monitor" && settings.AutoResponse.TerminateProcess
		if shouldFreeze {
			target := TerminationTarget{
				PID:              matchedProc.PID,
				CreationUnixNano: matchedProc.CreationUTC.UnixNano(),
				ImagePath:        matchedProc.ImagePath,
				Reason:           fmt.Sprintf("Defender Symbiose Event %d: %s", event.EventID, firstNonEmptyString(threatName, detection)),
			}
			sourceTag := fmt.Sprintf("defender.%d", event.EventID)
			go func() {
				_, _ = e.FreezeProcessTree(target, sourceTag)
			}()
		}
	} else if (event.EventID == 1118 || event.EventID == 1119) && targetPath != "" && e.defenderOracle != nil {
		// When remediation failed on an artifact without an active correlated
		// process, re-verify the artifact with the targeted Defender oracle.
		go func(path string) {
			ctx, cancel := context.WithTimeout(context.Background(), defenderOracleTimeout)
			defer cancel()
			_, _ = e.ScanFileWithDefender(ctx, path)
		}(targetPath)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
