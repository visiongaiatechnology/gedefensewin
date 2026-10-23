// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
	"github.com/visiongaiatechnology/gedefense/windows/internal/traffic"
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
	root                       string
	ledger                     *evidence.Ledger
	feeds                      *threatintel.Manager
	protection                 protectionController
	evaluator                  Evaluator
	mu                         sync.RWMutex
	analyses                   []Analysis
	networkFindings            []NetworkFinding
	attackStories              []AttackStory
	recentProcesses            map[uint32]recentProcess
	mode                       string
	realtime                   bool
	telemetry                  string
	lastTelemetryUTC           time.Time
	lastFault                  string
	networkRealtime            bool
	networkLastUTC             time.Time
	networkLastFault           string
	wfpRealtime                bool
	wfpLastUTC                 time.Time
	wfpLastFault               string
	evaluated                  atomic.Uint64
	blocked                    atomic.Uint64
	knownBenign                atomic.Uint64
	networkObserved            atomic.Uint64
	wfpBlockedObserved         atomic.Uint64
	networkThreatHits          atomic.Uint64
	networkUncorrelated        atomic.Uint64
	kineticMonitor             *kinetic.Monitor
	trafficMonitor             *traffic.Sampler
	kineticArmed               bool
	kineticIncidents           []KineticIncident
	kineticThreatCorrelations  atomic.Uint64
	kineticBlockedCorrelations atomic.Uint64
	kernelEnforcement          atomic.Bool
	policyOnce                 sync.Once
	policyGate                 chan struct{}
	protectionHealth           string
	protectionVerifiedUTC      time.Time
	threatEnforcement          ThreatEnforcementStatus
	kineticRuntime             kineticRuntimeState
	intelligenceWake           chan struct{}
	policySettings             atomic.Pointer[PolicySettings]
	policySettingsSource       string
	policySettingsWarning      string
	policySettingsUpdatedUTC   time.Time
	policySettingsPersisted    bool
	notifications              []Notification
	defenderMu                 sync.Mutex
	defenderCache              DefenderTelemetry
	defenderCacheAt            time.Time
	defenderProbe              defenderProbeFunc
	terminate                  func(ProcessEvent) error
}

func NewEngine(root, protectionScript, firewallScript, allowScript, denyScript, appControlScript, operationRoot string, ledger *evidence.Ledger) (*Engine, error) {
	if ledger == nil || !filepath.IsAbs(root) {
		return nil, errors.New("invalid MHX engine configuration")
	}
	feeds, err := threatintel.NewManager(filepath.Join(root, "intelligence"))
	if err != nil {
		return nil, err
	}
	protection, err := newProtectionManager(protectionScript, firewallScript, allowScript, denyScript, appControlScript, operationRoot)
	if err != nil {
		return nil, err
	}
	engine := &Engine{root: root, ledger: ledger, feeds: feeds, protection: protection, evaluator: Evaluator{}, kineticMonitor: kinetic.NewMonitor(), trafficMonitor: traffic.NewSampler(), analyses: make([]Analysis, 0, maximumAnalyses), networkFindings: make([]NetworkFinding, 0, maximumNetworkFindings), attackStories: make([]AttackStory, 0, maximumAttackStories), recentProcesses: make(map[uint32]recentProcess, 256), mode: "guarded", telemetry: "STARTING", protectionHealth: "STARTING", threatEnforcement: ThreatEnforcementStatus{State: "UNVERIFIED"}, intelligenceWake: make(chan struct{}, 1)}
	_ = engine.loadMode()
	engine.loadKineticState()
	engine.loadPolicySettings()
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
	wfpEvents := make(chan wfpBlockEvent, 128)
	wfpHealth := make(chan time.Time, 8)
	faults := make(chan error, 8)
	networkFaults := make(chan error, 8)
	wfpFaults := make(chan error, 8)
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()
	launch(func() { (processWatcher{}).Run(ctx, events, health, faults) })
	launch(func() { (defenderWatcher{}).Run(ctx, defenderEvents, faults) })
	launch(func() { (networkWatcher{}).Run(ctx, networkEvents, networkHealth, networkFaults) })
	launch(func() { (wfpBlockWatcher{}).Run(ctx, wfpEvents, wfpHealth, wfpFaults) })
	launch(func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				data, err := traffic.ReadInterfaces()
				e.trafficMonitor.Record(data, now.UTC(), err)
			}
		}
	})
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
			if e.lastTelemetryUTC.IsZero() || time.Since(e.lastTelemetryUTC) > 45*time.Second {
				e.realtime = false
				e.telemetry = "DEGRADED"
			}
			if e.networkLastUTC.IsZero() || time.Since(e.networkLastUTC) > 8*time.Second {
				e.networkRealtime = false
			}
			if e.wfpLastUTC.IsZero() || time.Since(e.wfpLastUTC) > 8*time.Second {
				e.wfpRealtime = false
			}
			e.mu.Unlock()
			// Kinetic never trusts a persisted armed flag. This loop is the only
			// promotion path for a persisted arming intent and the only automatic
			// disarm path for sustained verification loss or an elapsed window.
			e.reconcileKinetic(time.Now().UTC())
		case event := <-events:
			e.evaluate(event)
		case event := <-defenderEvents:
			e.evaluateDefender(event)
		case event := <-networkEvents:
			e.evaluateNetwork(event)
		case event := <-wfpEvents:
			e.wfpBlockedObserved.Add(1)
			e.evaluateWFPBlock(event)
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
		case timestamp := <-wfpHealth:
			e.mu.Lock()
			e.wfpRealtime = true
			e.wfpLastUTC = timestamp
			e.wfpLastFault = ""
			e.mu.Unlock()
		case err := <-wfpFaults:
			e.mu.Lock()
			e.wfpRealtime = false
			e.wfpLastFault = err.Error()
			e.mu.Unlock()
			_ = e.ledger.Append("mhx.network", "wfp-5157-telemetry", "degraded")
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
	if disposition == DispositionBlock {
		e.notifyEvent(notificationKindDefender, severity, detection, fmt.Sprintf("Defender event %d", event.EventID))
	}
}

func (e *Engine) evaluate(event ProcessEvent) {
	result := e.evaluator.Analyze(event)
	e.evaluated.Add(1)
	mode := e.Mode()
	settings := e.currentPolicySettings()
	if result.Classification == "KNOWN BENIGN" {
		e.knownBenign.Add(1)
	}
	if result.ResponseAuthority && mode != "monitor" && responsePolicyAllows(settings, result.EffectiveSeverity) {
		if err := e.terminateObserved(event); err == nil {
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
	if result.Disposition == DispositionBlock {
		e.notifyBlockingAnalysis(result)
	}
}

// terminateObserved is the single process-termination seam. Tests can replace
// it to verify the auto-response policy gates without terminating a real
// process; production engines always use the PID-reuse protected terminator.
func (e *Engine) terminateObserved(event ProcessEvent) error {
	if e.terminate != nil {
		return e.terminate(event)
	}
	return terminateProcess(event)
}

// responsePolicyAllows applies the operator auto-response policy on top of the
// evaluator's independent response authority. The default policy preserves the
// historical behaviour exactly.
func responsePolicyAllows(settings PolicySettings, severity Severity) bool {
	if !settings.AutoResponse.TerminateProcess {
		return false
	}
	return severityAtLeast(severity, settings.AutoResponse.MinimumSeverity)
}

func severityAtLeast(severity, floor Severity) bool {
	return severityRank(severity) >= severityRank(floor)
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
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
	wfpRealtime := e.wfpRealtime
	protectionHealth, protectionVerifiedUTC := e.protectionHealth, e.protectionVerifiedUTC
	attackStoryCount := len(e.attackStories)
	threatEnforcement := e.threatEnforcement
	kineticArmed := e.kineticArmed
	kineticIncidents := append([]KineticIncident(nil), e.kineticIncidents...)
	e.mu.RUnlock()
	enforcement := "AUDIT"
	switch mode {
	case "guarded":
		enforcement = "ENRICH_THEN_TERMINATE"
	case "sovereign":
		enforcement = "DEFAULT_DENY"
	}
	appControl := "AUDIT"
	if e.kernelEnforcement.Load() {
		appControl = "ENFORCED"
	}
	kineticSnap := e.kineticMonitor.Snapshot()
	readiness := kinetic.EvaluateReadiness(networkRealtime, wfpRealtime, e.wfpBlockedObserved.Load(), threatEnforcement.State, e.feeds.Status().EnforcementGeneration, threatEnforcement.ActiveGeneration)
	kineticSnap.Mode = "OBSERVE_ONLY"
	if kineticArmed {
		kineticSnap.Mode = "ARMED_TI_CORRELATION"
		readiness.Mode = "ARMED_TI_CORRELATION"
	}
	kineticSettings := e.KineticSettings()
	policySettings := e.PolicySettings()
	var threatIntelPolling threatintel.PollingConfig
	var threatIntelligence threatintel.Status
	if e.feeds != nil {
		threatIntelPolling = e.feeds.PollingConfig()
		threatIntelligence = e.feeds.Status()
	}
	defenderTelemetry := e.cachedDefenderTelemetry()
	e.mu.RLock()
	notificationCount := len(e.notifications)
	e.mu.RUnlock()
	return Status{KineticSources: e.kineticMonitor.SourceSnapshot(250), Traffic: e.trafficMonitor.Snapshot(), KineticArmed: kineticArmed, KineticIncidents: kineticIncidents, KineticThreatCorrelations: e.kineticThreatCorrelations.Load(), KineticBlockedCorrelations: e.kineticBlockedCorrelations.Load(), Kinetic: kineticSnap, KineticReadiness: readiness, UncorrelatedThreatHits: e.networkUncorrelated.Load(), Engine: "VGT MHX 7.1", Realtime: realtime, Telemetry: telemetry, TelemetryHeartbeatUTC: lastTelemetryUTC, Enforcement: enforcement, DefenderBridge: "AMSI + ASR + OPERATIONAL EVENT STREAM", AppControl: appControl, KernelEnforcement: e.kernelEnforcement.Load(), ProtectionMode: mode, ProtectionHealth: protectionHealth, ProtectionVerifiedUTC: protectionVerifiedUTC, EventsEvaluated: e.evaluated.Load(), EventsBlocked: e.blocked.Load(), KnownBenign: e.knownBenign.Load(), ThreatIntelligence: threatIntelligence, ThreatEnforcement: threatEnforcement, NetworkTelemetry: map[bool]string{true: "NATIVE_TCP_OWNER_PID", false: "DEGRADED"}[networkRealtime], NetworkConnections: e.networkObserved.Load(), WFPBlockTelemetry: map[bool]string{true: "POLLING_5157_AUDIT_UNVERIFIED", false: "DEGRADED"}[wfpRealtime], WFPBlockedEvents: e.wfpBlockedObserved.Load(), ThreatNetworkHits: e.networkThreatHits.Load(), AttackStories: uint64(attackStoryCount), KineticSettings: kineticSettings, PolicySettings: policySettings, ThreatIntelPolling: threatIntelPolling, DefenderTelemetry: defenderTelemetry, NotificationCount: notificationCount}
}
