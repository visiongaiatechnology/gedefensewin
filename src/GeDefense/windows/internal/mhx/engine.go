// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

const (
	maximumAnalyses        = 500
	maximumNetworkFindings = 500
	maximumAttackStories   = 500
	maximumRecentProcesses = 2048
)

type recentProcess struct {
	event    ProcessEvent
	analysis Analysis
	expires  time.Time
}

type Engine struct {
	root                  string
	ledger                *evidence.Ledger
	feeds                 *FeedManager
	protection            protectionController
	evaluator             Evaluator
	mu                    sync.RWMutex
	analyses              []Analysis
	networkFindings       []NetworkFinding
	attackStories         []AttackStory
	recentProcesses       map[uint32]recentProcess
	mode                  string
	realtime              bool
	telemetry             string
	lastTelemetryUTC      time.Time
	lastFault             string
	networkRealtime       bool
	networkLastUTC        time.Time
	networkLastFault      string
	evaluated             atomic.Uint64
	blocked               atomic.Uint64
	knownBenign           atomic.Uint64
	networkObserved       atomic.Uint64
	networkThreatHits     atomic.Uint64
	kernelEnforcement     atomic.Bool
	policyOnce            sync.Once
	policyGate            chan struct{}
	protectionHealth      string
	protectionVerifiedUTC time.Time
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
	engine := &Engine{root: root, ledger: ledger, feeds: feeds, protection: protection, evaluator: Evaluator{}, analyses: make([]Analysis, 0, maximumAnalyses), networkFindings: make([]NetworkFinding, 0, maximumNetworkFindings), attackStories: make([]AttackStory, 0, maximumAttackStories), recentProcesses: make(map[uint32]recentProcess, 256), mode: "guarded", telemetry: "STARTING", protectionHealth: "STARTING"}
	_ = engine.loadMode()
	return engine, nil
}

func (e *Engine) Run(stop <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	go func() { <-stop; cancel() }()
	launch := func(run func()) { workers.Add(1); go func() { defer workers.Done(); run() }() }
	launch(func() { e.intelligenceLoop(stop) })
	launch(func() { e.allowVerificationLoop(stop) })
	launch(func() { e.policyReconciliationLoop(stop) })
	launch(func() { e.initializeAppControlStatus(ctx) })
	events := make(chan ProcessEvent, 64)
	health := make(chan time.Time, 8)
	defenderEvents := make(chan defenderEvent, 32)
	networkEvents := make(chan networkEvent, 128)
	networkHealth := make(chan time.Time, 8)
	faults := make(chan error, 8)
	networkFaults := make(chan error, 8)
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()
	launch(func() { (processWatcher{}).Run(ctx, events, health, faults) })
	launch(func() { (defenderWatcher{}).Run(ctx, defenderEvents, faults) })
	launch(func() { (networkWatcher{}).Run(ctx, networkEvents, networkHealth, networkFaults) })
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
			if e.networkLastUTC.IsZero() || time.Since(e.networkLastUTC) > 8*time.Second {
				e.networkRealtime = false
			}
			e.mu.Unlock()
		case event := <-events:
			e.evaluate(event)
		case event := <-defenderEvents:
			e.evaluateDefender(event)
		case event := <-networkEvents:
			e.evaluateNetwork(event)
		case timestamp := <-networkHealth:
			e.mu.Lock()
			e.networkRealtime = true
			e.networkLastUTC = timestamp
			e.networkLastFault = ""
			e.mu.Unlock()
		case err := <-networkFaults:
			e.mu.Lock()
			e.networkRealtime = false
			e.networkLastFault = err.Error()
			e.mu.Unlock()
			_ = e.ledger.Append("mhx.network", "native-tcp-telemetry", "degraded")
		}
	}
}

func (e *Engine) initializeAppControlStatus(ctx context.Context) {
	probe, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := e.acquirePolicy(probe); err != nil {
		_ = e.ledger.Append("mhx.appcontrol", "status", "unavailable")
		return
	}
	defer e.releasePolicy()
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
	if result.ResponseAuthority && mode != "monitor" {
		if err := terminateProcess(event); err == nil {
			e.blocked.Add(1)
			_ = e.ledger.Append("mhx.block", result.Detection, "terminated")
		} else {
			_ = e.ledger.Append("mhx.block", result.Detection, "process-exited-or-denied")
		}
	}
	e.mu.Lock()
	e.purgeRecentProcessesLocked(time.Now().UTC())
	if len(e.recentProcesses) < maximumRecentProcesses {
		e.recentProcesses[event.PID] = recentProcess{event: event, analysis: result, expires: time.Now().UTC().Add(5 * time.Minute)}
	}
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
	networkRealtime := e.networkRealtime
	protectionHealth, protectionVerifiedUTC := e.protectionHealth, e.protectionVerifiedUTC
	attackStoryCount := len(e.attackStories)
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
	return Status{Engine: "VGT MHX 7.0", Realtime: realtime, Telemetry: telemetry, TelemetryHeartbeatUTC: lastTelemetryUTC, Enforcement: enforcement, DefenderBridge: "AMSI + ASR + OPERATIONAL EVENT STREAM", AppControl: appControl, KernelEnforcement: e.kernelEnforcement.Load(), ProtectionMode: mode, ProtectionHealth: protectionHealth, ProtectionVerifiedUTC: protectionVerifiedUTC, EventsEvaluated: e.evaluated.Load(), EventsBlocked: e.blocked.Load(), KnownBenign: e.knownBenign.Load(), ThreatIntelligence: e.feeds.Status(), NetworkTelemetry: map[bool]string{true: "NATIVE_TCP_OWNER_PID", false: "DEGRADED"}[networkRealtime], NetworkConnections: e.networkObserved.Load(), ThreatNetworkHits: e.networkThreatHits.Load(), AttackStories: uint64(attackStoryCount)}
}

func (e *Engine) Mode() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.mode }

func (e *Engine) SetMode(parent context.Context, mode string) error {
	if mode != "monitor" && mode != "guarded" && mode != "sovereign" {
		return errors.New("unsupported MHX protection mode")
	}
	if parent == nil {
		return errors.New("MHX mode transition requires context")
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	if err := e.acquirePolicy(ctx); err != nil {
		return fmt.Errorf("MHX policy gate unavailable: %w", err)
	}
	defer e.releasePolicy()

	if err := e.ledger.Verify(); err != nil {
		e.setProtectionHealth("DEGRADED")
		return fmt.Errorf("evidence ledger verification failed: %w", err)
	}
	previous := e.Mode()
	if mode == previous {
		return nil
	}

	if err := e.applyVerifiedMode(ctx, mode); err != nil {
		rollbackErr := e.rollbackMode(previous)
		if rollbackErr != nil {
			e.setProtectionHealth("DEGRADED")
			_ = e.ledger.Append("mhx.mode", "protection-mode", "transition-failed-rollback-failed")
			return fmt.Errorf("MHX mode transition failed: %w; rollback failed: %v", err, rollbackErr)
		}
		e.setProtectionHealth("VERIFIED")
		_ = e.ledger.Append("mhx.mode", "protection-mode", "transition-failed-rolled-back")
		return err
	}

	if err := e.persistMode(mode); err != nil {
		rollbackErr := e.rollbackMode(previous)
		if rollbackErr != nil {
			e.setProtectionHealth("DEGRADED")
			_ = e.ledger.Append("mhx.mode", "protection-mode", "persist-failed-rollback-failed")
			return fmt.Errorf("MHX mode persistence failed: %w; rollback failed: %v", err, rollbackErr)
		}
		e.setProtectionHealth("VERIFIED")
		_ = e.ledger.Append("mhx.mode", "protection-mode", "persist-failed-rolled-back")
		return err
	}

	if err := e.ledger.Append("mhx.mode", "protection-mode", mode); err != nil {
		rollbackErr := e.rollbackMode(previous)
		if rollbackErr != nil {
			e.setProtectionHealth("DEGRADED")
			return fmt.Errorf("evidence commit failed: %w; rollback failed: %v", err, rollbackErr)
		}
		e.setProtectionHealth("VERIFIED")
		return fmt.Errorf("evidence commit failed; protection rolled back: %w", err)
	}

	e.mu.Lock()
	e.mode = mode
	e.mu.Unlock()
	e.refreshKernelEnforcement(ctx)
	e.setProtectionHealth("VERIFIED")
	return nil
}

func (e *Engine) persistMode(mode string) error {
	payload, err := json.Marshal(struct {
		Mode       string    `json:"mode"`
		UpdatedUTC time.Time `json:"updatedUtc"`
	}{mode, time.Now().UTC()})
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(e.root, "mode.json"), append(payload, '\n'))
}

func (e *Engine) rollbackMode(previous string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var rollbackErrors []error
	if err := e.applyVerifiedMode(ctx, previous); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("protection rollback: %w", err))
	}
	if err := e.persistMode(previous); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("mode-state rollback: %w", err))
	}
	e.refreshKernelEnforcement(ctx)
	return errors.Join(rollbackErrors...)
}

func (e *Engine) applyVerifiedMode(ctx context.Context, mode string) error {
	if mode == "sovereign" {
		appControl, err := e.protection.ApplyAppControl(ctx, "Enforce")
		if err != nil {
			return err
		}
		if !appControl.Enforced || !appControl.KernelEnforcement {
			return errors.New("App Control kernel enforcement verification failed")
		}
		e.kernelEnforcement.Store(appControl.KernelEnforcement)
	}

	verified, err := e.protection.Apply(ctx, mode)
	if err != nil {
		return err
	}
	if verified.Mode != mode || !verified.DefenderRealtime || !verified.ProcessTelemetry || (mode == "sovereign" && !verified.NetworkDefaultDeny) {
		return errors.New("MHX protection verification failed")
	}

	if mode != "sovereign" {
		appControl, err := e.protection.ApplyAppControl(ctx, "Audit")
		if err != nil {
			return err
		}
		if appControl.Enforced || appControl.KernelEnforcement {
			return errors.New("App Control audit verification failed")
		}
		e.kernelEnforcement.Store(false)
	}
	return nil
}

func (e *Engine) refreshKernelEnforcement(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	result, err := e.protection.ApplyAppControl(ctx, "Status")
	if err != nil {
		_ = e.ledger.Append("mhx.appcontrol", "status", "unavailable")
		return
	}
	e.kernelEnforcement.Store(result.KernelEnforcement)
}

func (e *Engine) acquirePolicy(ctx context.Context) error {
	if ctx == nil {
		return errors.New("policy operation requires context")
	}
	e.policyOnce.Do(func() { e.policyGate = make(chan struct{}, 1) })
	select {
	case e.policyGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) releasePolicy() {
	<-e.policyGate
}

func (e *Engine) setProtectionHealth(state string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.protectionHealth = state
	if state == "VERIFIED" {
		e.protectionVerifiedUTC = time.Now().UTC()
		return
	}
	e.protectionVerifiedUTC = time.Time{}
}

func (e *Engine) SyncFeeds(ctx context.Context) error {
	if err := e.feeds.Sync(ctx); err != nil {
		_ = e.ledger.Append("mhx.intelligence", "12h-sync", "failed")
		return err
	}
	if err := e.acquirePolicy(ctx); err != nil {
		return fmt.Errorf("threat-intelligence policy gate unavailable: %w", err)
	}
	defer e.releasePolicy()
	result, err := e.protection.ApplyThreatIntelligence(ctx, e.feeds.SnapshotPath())
	if err != nil || result.Indicators != e.feeds.Status().Indicators {
		verificationErr := err
		if verificationErr == nil {
			verificationErr = errors.New("threat intelligence firewall verification failed")
		}
		e.feeds.fail(time.Now().UTC(), verificationErr)
		_ = e.ledger.Append("mhx.intelligence", "firewall-enforcement", "failed")
		return verificationErr
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
	if err := e.acquirePolicy(ctx); err != nil {
		return nil, err
	}
	defer e.releasePolicy()
	result, err := e.protection.Applications(ctx, "List", "")
	return result.Entries, err
}

func (e *Engine) SetApplication(ctx context.Context, action, path string) ([]ApplicationAllow, error) {
	if action != "Add" && action != "Remove" {
		return nil, errors.New("application allow action rejected")
	}
	if err := e.acquirePolicy(ctx); err != nil {
		return nil, err
	}
	defer e.releasePolicy()
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
		e.setProtectionHealth("DEGRADED")
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "failed")
		return nil, appErr
	}
	if appAction == "Enforce" && (!appControl.Enforced || !appControl.KernelEnforcement) {
		e.setProtectionHealth("DEGRADED")
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "verification-failed")
		return nil, errors.New("App Control kernel enforcement verification failed")
	}
	if appAction == "Audit" && (appControl.Enforced || appControl.KernelEnforcement) {
		e.setProtectionHealth("DEGRADED")
		_ = e.ledger.Append("mhx.sovereign", "appcontrol-refresh", "verification-failed")
		return nil, errors.New("App Control audit verification failed")
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
			if err := e.acquirePolicy(ctx); err == nil {
				_, verifyErr := e.protection.Applications(ctx, "Verify", "")
				e.releasePolicy()
				if verifyErr != nil {
					if e.Mode() == "sovereign" {
						e.setProtectionHealth("DEGRADED")
					}
					_ = e.ledger.Append("mhx.sovereign", "application-integrity", "failed")
				}
			} else if e.Mode() == "sovereign" {
				e.setProtectionHealth("DEGRADED")
				_ = e.ledger.Append("mhx.sovereign", "application-integrity", "policy-gate-unavailable")
			}
			cancel()
			timer.Reset(time.Minute)
		}
	}
}

func (e *Engine) policyReconciliationLoop(stop <-chan struct{}) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			if err := e.acquirePolicy(ctx); err != nil {
				e.setProtectionHealth("DEGRADED")
				_ = e.ledger.Append("mhx.enforcement", "policy-gate", "degraded")
			} else {
				err = e.applyVerifiedMode(ctx, e.Mode())
				e.releasePolicy()
				if err != nil {
					e.setProtectionHealth("DEGRADED")
					_ = e.ledger.Append("mhx.enforcement", "policy-reconciliation", "degraded")
				} else {
					e.setProtectionHealth("VERIFIED")
				}
			}
			cancel()
			timer.Reset(10 * time.Minute)
		}
	}
}

func (e *Engine) evaluateNetwork(event networkEvent) {
	e.networkObserved.Add(1)
	address, err := netip.ParseAddr(event.RemoteIP)
	if err != nil || !e.feeds.Contains(address) {
		return
	}
	e.networkThreatHits.Add(1)
	now := event.TimestampUTC
	finding := NetworkFinding{
		ID:           networkFindingID(event),
		TimestampUTC: now,
		PID:          event.PID,
		RemoteIP:     event.RemoteIP,
		RemotePort:   event.RemotePort,
		LocalPort:    event.LocalPort,
		ThreatIntel:  true,
		Severity:     SeverityHigh,
		Response:     "FIREWALL_INTELLIGENCE_MATCH",
	}

	e.mu.Lock()
	e.purgeRecentProcessesLocked(now)
	recent, correlated := e.recentProcesses[event.PID]
	if correlated && validateObservedProcess(recent.event) != nil {
		delete(e.recentProcesses, event.PID)
		correlated = false
	}
	if correlated {
		finding.Image = recent.event.Image
		finding.CorrelationID = recent.analysis.ID
		story := AttackStory{
			ID:                attackStoryID(recent.analysis.ID, event),
			StartedUTC:        recent.analysis.TimestampUTC,
			UpdatedUTC:        now,
			PID:               event.PID,
			Image:             recent.event.Image,
			ProcessAnalysisID: recent.analysis.ID,
			Severity:          SeverityHigh,
			Signals:           appendUniqueCopy(recent.analysis.Signals, "network.threat-intelligence"),
			RemoteIP:          event.RemoteIP,
			RemotePort:        event.RemotePort,
			Response:          "CORRELATED",
		}
		if recent.analysis.ResponseAuthority {
			story.Severity = SeverityCritical
			story.Response = "HOST_RESPONSE_ELIGIBLE"
		}
		e.attackStories = append(e.attackStories, story)
		if len(e.attackStories) > maximumAttackStories {
			copy(e.attackStories, e.attackStories[len(e.attackStories)-maximumAttackStories:])
			e.attackStories = e.attackStories[:maximumAttackStories]
		}
	}
	e.networkFindings = append(e.networkFindings, finding)
	if len(e.networkFindings) > maximumNetworkFindings {
		copy(e.networkFindings, e.networkFindings[len(e.networkFindings)-maximumNetworkFindings:])
		e.networkFindings = e.networkFindings[:maximumNetworkFindings]
	}
	e.mu.Unlock()

	_ = e.ledger.Append("mhx.network", event.RemoteIP, "threat-intelligence-match")
	if !correlated || !recent.analysis.ResponseAuthority || e.Mode() == "monitor" {
		return
	}
	// A network IOC alone never grants process-kill authority. The process must
	// already have an independent blocking verdict and its identity is revalidated.
	if err := terminateProcess(recent.event); err == nil {
		e.blocked.Add(1)
		_ = e.ledger.Append("mhx.correlated-response", recent.analysis.Detection, "terminated-after-network-correlation")
	}
}

func (e *Engine) purgeRecentProcessesLocked(now time.Time) {
	if len(e.recentProcesses) == 0 {
		return
	}
	for pid, record := range e.recentProcesses {
		if now.After(record.expires) {
			delete(e.recentProcesses, pid)
		}
	}
}

func (e *Engine) NetworkFindings(limit int) []NetworkFinding {
	if limit <= 0 || limit > maximumNetworkFindings {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.networkFindings) - limit
	if start < 0 {
		start = 0
	}
	result := append([]NetworkFinding(nil), e.networkFindings[start:]...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func (e *Engine) AttackStories(limit int) []AttackStory {
	if limit <= 0 || limit > maximumAttackStories {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.attackStories) - limit
	if start < 0 {
		start = 0
	}
	result := make([]AttackStory, 0, len(e.attackStories)-start)
	for _, story := range e.attackStories[start:] {
		copyStory := story
		copyStory.Signals = append([]string(nil), story.Signals...)
		result = append(result, copyStory)
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func appendUniqueCopy(values []string, value string) []string {
	result := append([]string(nil), values...)
	for _, existing := range result {
		if existing == value {
			return result
		}
	}
	return append(result, value)
}

func networkFindingID(event networkEvent) string {
	payload := fmt.Sprintf("%d\x00%s\x00%d\x00%s", event.PID, event.RemoteIP, event.RemotePort, event.TimestampUTC.Format(time.RFC3339Nano))
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}

func attackStoryID(analysisID string, event networkEvent) string {
	payload := fmt.Sprintf("%s\x00%s\x00%d", analysisID, event.RemoteIP, event.RemotePort)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}
