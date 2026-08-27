// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

const maximumAnalyses = 500

type Engine struct {
	root              string
	ledger            *evidence.Ledger
	feeds             *FeedManager
	protection        *protectionManager
	evaluator         Evaluator
	mu                sync.RWMutex
	analyses          []Analysis
	mode              string
	realtime          bool
	telemetry         string
	lastTelemetryUTC  time.Time
	lastFault         string
	evaluated         atomic.Uint64
	blocked           atomic.Uint64
	knownBenign       atomic.Uint64
	kernelEnforcement atomic.Bool
}

func NewEngine(root, protectionScript, firewallScript, allowScript, appControlScript, operationRoot string, ledger *evidence.Ledger) (*Engine, error) {
	if ledger == nil || !filepath.IsAbs(root) {
		return nil, errors.New("invalid MHX engine configuration")
	}
	feeds, err := NewFeedManager(filepath.Join(root, "intelligence"))
	if err != nil {
		return nil, err
	}
	protection, err := newProtectionManager(protectionScript, firewallScript, allowScript, appControlScript, operationRoot)
	if err != nil {
		return nil, err
	}
	engine := &Engine{root: root, ledger: ledger, feeds: feeds, protection: protection, evaluator: Evaluator{}, analyses: make([]Analysis, 0, maximumAnalyses), mode: "guarded", telemetry: "STARTING"}
	_ = engine.loadMode()
	return engine, nil
}

func (e *Engine) Run(stop <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-stop; cancel() }()
	go e.intelligenceLoop(stop)
	go e.allowVerificationLoop(stop)
	go e.policyReconciliationLoop(stop)
	go e.initializeAppControlStatus(ctx)
	events := make(chan ProcessEvent, 64)
	health := make(chan time.Time, 8)
	defenderEvents := make(chan defenderEvent, 32)
	faults := make(chan error, 8)
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()
	go (processWatcher{}).Run(ctx, events, health, faults)
	go (defenderWatcher{}).Run(ctx, defenderEvents, faults)
	_ = e.ledger.Append("mhx.realtime", "process-telemetry", "started")
	for {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			e.realtime = false
			e.telemetry = "STOPPED"
			e.mu.Unlock()
			return
		case err := <-faults:
			e.mu.Lock()
			e.lastFault = err.Error()
			e.telemetry = "DEGRADED"
			e.mu.Unlock()
			_ = e.ledger.Append("mhx.realtime", "telemetry", "degraded")
		case timestamp := <-health:
			e.mu.Lock()
			e.lastTelemetryUTC = timestamp
			e.realtime = true
			e.telemetry = "WIN32_PROCESS_START_TRACE"
			e.mu.Unlock()
		case <-healthTicker.C:
			e.mu.Lock()
			if e.lastTelemetryUTC.IsZero() || time.Since(e.lastTelemetryUTC) > 7*time.Second {
				e.realtime = false
				e.telemetry = "DEGRADED"
			}
			e.mu.Unlock()
		case event := <-events:
			e.evaluate(event)
		case event := <-defenderEvents:
			e.evaluateDefender(event)
		}
	}
}

func (e *Engine) initializeAppControlStatus(ctx context.Context) {
	probe, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	result, err := e.protection.ApplyAppControl(probe, "Status")
	if err != nil {
		_ = e.ledger.Append("mhx.appcontrol", "status", "unavailable")
		return
	}
	e.kernelEnforcement.Store(result.KernelEnforcement)
}

func (e *Engine) evaluateDefender(event defenderEvent) {
	timestamp, _ := time.Parse(time.RFC3339Nano, event.TimestampUTC)
	severity, disposition, classification := SeverityMedium, DispositionAudit, "DEFENDER CONFIGURATION"
	detection := "Microsoft Defender security configuration changed"
	if event.EventID == 1116 {
		severity, disposition, classification, detection = SeverityCritical, DispositionBlock, "DEFENDER DETECTION", "Microsoft Defender detected malware or unwanted software"
	}
	if event.EventID == 1117 {
		severity, disposition, classification, detection = SeverityInformational, DispositionAllow, "DEFENDER REMEDIATION", "Microsoft Defender completed a protection action"
	}
	if event.EventID == 5001 || event.EventID == 5010 || event.EventID == 5012 {
		severity, disposition, classification, detection = SeverityCritical, DispositionBlock, "DEFENDER PROTECTION DISABLED", "Microsoft Defender protection control was disabled"
	}
	analysis := Analysis{ID: analysisID(ProcessEvent{ImagePath: "Microsoft Defender", CommandLine: event.Message}, timestamp), TimestampUTC: timestamp, InitialSeverity: severity, EffectiveSeverity: severity, Disposition: disposition, Detection: detection, Classification: classification, Identified: "Microsoft Defender Antivirus", Purpose: "AMSI, antivirus and platform protection coordination", ConfidenceBasis: 10000, Image: "MsMpEng.exe", Signals: []string{fmt.Sprintf("defender.event.%d", event.EventID)}}
	e.evaluated.Add(1)
	e.mu.Lock()
	e.analyses = append(e.analyses, analysis)
	if len(e.analyses) > maximumAnalyses {
		e.analyses = append([]Analysis(nil), e.analyses[len(e.analyses)-maximumAnalyses:]...)
	}
	e.mu.Unlock()
	_ = e.ledger.Append("defender.event", detection, fmt.Sprintf("event-%d", event.EventID))
}

func (e *Engine) evaluate(event ProcessEvent) {
	result := e.evaluator.Analyze(event)
	e.evaluated.Add(1)
	mode := e.Mode()
	if result.Classification == "KNOWN BENIGN" {
		e.knownBenign.Add(1)
	}
	if result.Disposition == DispositionBlock && mode != "monitor" {
		if err := terminateProcess(event.PID); err == nil {
			e.blocked.Add(1)
			_ = e.ledger.Append("mhx.block", result.Detection, "terminated")
		} else {
			_ = e.ledger.Append("mhx.block", result.Detection, "process-exited-or-denied")
		}
	}
	e.mu.Lock()
	e.analyses = append(e.analyses, result)
	if len(e.analyses) > maximumAnalyses {
		copy(e.analyses, e.analyses[len(e.analyses)-maximumAnalyses:])
		e.analyses = e.analyses[:maximumAnalyses]
	}
	e.mu.Unlock()
}

func (e *Engine) Analyses(limit int) []Analysis {
	if limit <= 0 || limit > maximumAnalyses {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.analyses) - limit
	if start < 0 {
		start = 0
	}
	result := append(make([]Analysis, 0, len(e.analyses)-start), e.analyses[start:]...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func (e *Engine) Status() Status {
	e.mu.RLock()
	realtime, telemetry, mode, lastTelemetryUTC := e.realtime, e.telemetry, e.mode, e.lastTelemetryUTC
	e.mu.RUnlock()
	enforcement := "AUDIT"
	if mode == "guarded" {
		enforcement = "ENRICH_THEN_TERMINATE"
	} else if mode == "sovereign" {
		enforcement = "DEFAULT_DENY"
	}
	appControl := "AUDIT"
	if e.kernelEnforcement.Load() {
		appControl = "ENFORCED"
	}
	return Status{Engine: "VGT MHX 6.0", Realtime: realtime, Telemetry: telemetry, TelemetryHeartbeatUTC: lastTelemetryUTC, Enforcement: enforcement, DefenderBridge: "AMSI + ASR + OPERATIONAL EVENT STREAM", AppControl: appControl, KernelEnforcement: e.kernelEnforcement.Load(), ProtectionMode: mode, EventsEvaluated: e.evaluated.Load(), EventsBlocked: e.blocked.Load(), KnownBenign: e.knownBenign.Load(), ThreatIntelligence: e.feeds.Status()}
}

func (e *Engine) Mode() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.mode }

func (e *Engine) SetMode(mode string) error {
	if mode != "monitor" && mode != "guarded" && mode != "sovereign" {
		return errors.New("unsupported MHX protection mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if mode == "sovereign" {
		appControl, appErr := e.protection.ApplyAppControl(ctx, "Enforce")
		if appErr != nil {
			return appErr
		}
		if !appControl.KernelEnforcement {
			return errors.New("App Control kernel enforcement verification failed")
		}
		e.kernelEnforcement.Store(true)
	}
	verified, err := e.protection.Apply(ctx, mode)
	if err != nil {
		return err
	}
	if verified.Mode != mode || !verified.DefenderRealtime || !verified.ProcessTelemetry || (mode == "sovereign" && !verified.NetworkDefaultDeny) {
		return errors.New("MHX protection verification failed")
	}
	if mode != "sovereign" {
		appControl, appErr := e.protection.ApplyAppControl(ctx, "Audit")
		if appErr != nil {
			return appErr
		}
		if appControl.Enforced {
			return errors.New("App Control audit verification failed")
		}
		e.kernelEnforcement.Store(false)
	}
	payload, err := json.Marshal(struct {
		Mode       string    `json:"mode"`
		UpdatedUTC time.Time `json:"updatedUtc"`
	}{mode, time.Now().UTC()})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(e.root, "mode.json"), append(payload, '\n')); err != nil {
		return err
	}
	e.mu.Lock()
	e.mode = mode
	e.mu.Unlock()
	return e.ledger.Append("mhx.mode", "protection-mode", mode)
}

func (e *Engine) SyncFeeds(ctx context.Context) error {
	if err := e.feeds.Sync(ctx); err != nil {
		_ = e.ledger.Append("mhx.intelligence", "12h-sync", "failed")
		return err
	}
	result, err := e.protection.ApplyThreatIntelligence(ctx, e.feeds.SnapshotPath())
	if err != nil || result.Indicators != e.feeds.Status().Indicators {
		_ = e.ledger.Append("mhx.intelligence", "firewall-enforcement", "failed")
		if err != nil {
			return err
		}
		return errors.New("threat intelligence firewall verification failed")
	}
	return e.ledger.Append("mhx.intelligence", "12h-sync", "verified")
}

func (e *Engine) intelligenceLoop(stop <-chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	_ = e.SyncFeeds(ctx)
	cancel()
	timer := time.NewTimer(feedInterval)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
			_ = e.SyncFeeds(ctx)
			cancel()
			timer.Reset(feedInterval)
		}
	}
}

func (e *Engine) loadMode() error {
	payload, err := os.ReadFile(filepath.Join(e.root, "mode.json"))
	if err != nil {
		return err
	}
	var state struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return err
	}
	if state.Mode != "monitor" && state.Mode != "guarded" && state.Mode != "sovereign" {
		return errors.New("persisted MHX mode is invalid")
	}
	e.mode = state.Mode
	return nil
}

func (e *Engine) Applications(ctx context.Context) ([]ApplicationAllow, error) {
	result, err := e.protection.Applications(ctx, "List", "")
	return result.Entries, err
}

func (e *Engine) SetApplication(ctx context.Context, action, path string) ([]ApplicationAllow, error) {
	if action != "Add" && action != "Remove" {
		return nil, errors.New("application allow action rejected")
	}
	result, err := e.protection.Applications(ctx, action, path)
	if err != nil {
		_ = e.ledger.Append("mhx.sovereign", "application-allow", "failed")
		return nil, err
	}
	appAction := "Audit"
	if e.Mode() == "sovereign" {
		appAction = "Enforce"
	}
	appControl, appErr := e.protection.ApplyAppControl(ctx, appAction)
	if appErr != nil {
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "failed")
		return nil, appErr
	}
	e.kernelEnforcement.Store(appControl.KernelEnforcement)
	_ = e.ledger.Append("mhx.sovereign", "application-allow", strings.ToLower(action))
	return result.Entries, nil
}

func (e *Engine) allowVerificationLoop(stop <-chan struct{}) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			_, err := e.protection.Applications(ctx, "Verify", "")
			cancel()
			if err != nil {
				_ = e.ledger.Append("mhx.sovereign", "application-integrity", "failed")
			}
			timer.Reset(time.Minute)
		}
	}
}

func (e *Engine) policyReconciliationLoop(stop <-chan struct{}) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			_, err := e.protection.Apply(ctx, e.Mode())
			cancel()
			if err != nil {
				_ = e.ledger.Append("mhx.enforcement", "policy-reconciliation", "degraded")
			}
			timer.Reset(10 * time.Minute)
		}
	}
}
