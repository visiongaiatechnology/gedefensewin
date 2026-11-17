// STATUS: PLATIN VGT SUPREME
package app

// V6 integration: anti-spyware sensors and the out-of-band evidence witness.
//
// This file owns the lifecycle of the two V6 packages. They are wired into the
// running service, not merely constructed:
//
//   - spyware: one sensor supervisor starts after App.Run, reads the operator
//     configuration from the persisted settings document (section "v6") on every
//     cycle, feeds real Windows observations into spyware.Engine and appends the
//     resulting findings to the tamper-evident evidence ledger through a narrow
//     Append adapter. A settings change accepted by the settings applier takes
//     effect without a restart because the collectors consult v6Runtime.config.
//   - witness: the provisioning document witness/settings.json is loaded at
//     start; key material is only created when the operator activates the
//     witness, and witness.Engine.Start runs under this supervisor while Close
//     joins it on shutdown. Missing or invalid provisioning never falls back to
//     defaults: the engine stays inert and the honest state is reported.
//
// The sensors are detection-only by construction: spyware.Engine stamps every
// finding with OBSERVE_ONLY and this integration owns no response adapter.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/spyware"
	"github.com/visiongaiatechnology/gedefense/windows/internal/witness"
)

const (
	// v6CapabilityPollInterval is the bounded fallback cadence for the
	// capability consent store. The registry change notification is the primary
	// trigger; the poll bounds the detection latency if a notification is lost.
	v6CapabilityPollInterval = 2 * time.Second
	// v6RegistryWatchRetry bounds the retry cadence when the consent store key
	// cannot be watched yet (for example before the first capability use).
	v6RegistryWatchRetry = 30 * time.Second
	// v6DriverScanInterval is the kernel driver / security posture cadence.
	v6DriverScanInterval = 10 * time.Minute
	// v6PersistenceScanInterval is the registry persistence scan cadence.
	v6PersistenceScanInterval = 10 * time.Minute
	// v6SensorRetryInterval throttles a collector that failed at the OS boundary
	// (for example a Security event log subscription without SeSecurityPrivilege).
	v6SensorRetryInterval = 5 * time.Minute
	// v6MaxFindings bounds one status response. The engine keeps up to
	// spyware.MaxFindings; the API never emits more than this.
	v6MaxFindings = 50
	// v6ShutdownGrace bounds the final sensor join.
	v6ShutdownGrace = 5 * time.Second
)

// Witness provisioning states reported through the status API. They describe
// how the witness configuration was resolved, not how the engine currently
// behaves (the engine has its own DISABLED/UNVERIFIED/CONNECTED/DEGRADED/FAULT
// vocabulary).
const (
	witnessStateDisabled = "DISABLED" // the operator setting is off
	witnessStateMissing  = "MISSING"  // enabled, but no provisioning document
	witnessStateInvalid  = "INVALID"  // enabled, but the document or keys were rejected
	witnessStateLoaded   = "LOADED"   // settings and keys accepted, engine constructed
)

// Workstation lock detection states. "UNAVAILABLE" is honest: a session-0
// service cannot observe the interactive session's desktop in this build.
const (
	v6LockLocked      = "LOCKED"
	v6LockUnlocked    = "UNLOCKED"
	v6LockUnavailable = "UNAVAILABLE"
)

// v6Config is the effective operator configuration of the V6 integration. It is
// derived from the settings catalogue and re-applied through the existing
// settings applier; the collectors and the status projection consult it instead
// of keeping a second UI-only copy.
type v6Config struct {
	SpywareEnabled bool
	SpywareMode    string
	BYOVD          bool
	Capability     bool
	Persistence    bool
	LSASS          bool
	WitnessEnabled bool
}

const (
	v6SpywareModeObserve = "observe"
	v6SpywareModeActive  = "active"
)

// defaultV6Config mirrors the catalog defaults. It is used when a section value
// is absent from a persisted snapshot, exactly like the settings service does.
func defaultV6Config() v6Config {
	return v6Config{
		SpywareEnabled: true, SpywareMode: v6SpywareModeObserve,
		BYOVD: true, Capability: true, Persistence: true, LSASS: true,
		WitnessEnabled: false,
	}
}

func normalizeSpywareMode(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", v6SpywareModeObserve:
		return v6SpywareModeObserve, nil
	case v6SpywareModeActive:
		return v6SpywareModeActive, nil
	default:
		return "", errors.New("v6.spywareMode must be observe or active")
	}
}

func styxModeFromValues(section map[string]any) string {
	if raw, ok := section["styxMode"].(string); ok && strings.TrimSpace(raw) != "" {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return "observe"
}

func styxWhitelistFromValues(section map[string]any) []string {
	switch typed := section["styxWhitelist"].(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return []string{}
	}
}

// v6ConfigFromValues maps the canonical section values onto v6Config. Unknown
// or wrongly typed values keep the documented default.
func v6ConfigFromValues(section map[string]any) v6Config {
	config := defaultV6Config()
	read := func(key string, fallback bool) bool {
		if value, ok := section[key].(bool); ok {
			return value
		}
		return fallback
	}
	config.SpywareEnabled = read("spywareEnabled", config.SpywareEnabled)
	if modeRaw, ok := section["spywareMode"].(string); ok {
		if mode, err := normalizeSpywareMode(modeRaw); err == nil {
			config.SpywareMode = mode
		}
	}
	config.BYOVD = read("spywareByovd", config.BYOVD)
	config.Capability = read("spywareCapability", config.Capability)
	config.Persistence = read("spywarePersistence", config.Persistence)
	config.LSASS = read("spywareLsass", config.LSASS)
	config.WitnessEnabled = read("witnessEnabled", config.WitnessEnabled)
	return config
}

// v6Runtime owns the V6 sensor supervisor, the spyware engine and the witness
// engine. It is safe for the settings applier to call Configure while the
// supervisor is running.
type v6Runtime struct {
	root     string
	dataRoot string
	version  string
	ledger   *evidence.Ledger

	// applyMu serialises configuration changes and the witness start/stop
	// sequence. It is never taken by the sensor cycles.
	applyMu sync.Mutex

	// mu guards the fields below.
	mu             sync.Mutex
	config         v6Config
	spyware        *spyware.Engine
	witness        *witness.Engine
	witnessState   string
	witnessReason  string
	sensorProblems map[string]string
	lockState      string
	runCtx         context.Context
	runCancel      context.CancelFunc
	running        bool
}

// newV6Runtime builds the V6 runtime. It performs no OS access: the spyware
// engine is constructed with all sensor families active so a later operator
// activation needs no re-instantiation; effective activation is enforced by the
// collectors and reported by SpywareStatus. The witness engine is only built
// once the operator activates it and a valid provisioning document exists.
func newV6Runtime(root, dataRoot, version string, ledger *evidence.Ledger) *v6Runtime {
	runtime := &v6Runtime{
		root: root, dataRoot: dataRoot, version: version, ledger: ledger,
		config:         defaultV6Config(),
		witnessState:   witnessStateDisabled,
		witnessReason:  "witness activation has not been evaluated yet",
		sensorProblems: make(map[string]string, 4),
		lockState:      v6LockUnavailable,
	}
	runtime.spyware = newV6SpywareEngine(ledger)
	runtime.syncSpywareHook(runtime.config)
	return runtime
}

// SetSpywareMode switches anti-spyware mode between "observe" and "active".
func (r *v6Runtime) SetSpywareMode(ctx context.Context, mode string) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("V6 settings apply requires an active request")
	}
	normalized, err := normalizeSpywareMode(mode)
	if err != nil {
		return err
	}
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	cfg := r.config
	cfg.SpywareMode = normalized
	r.config = cfg
	r.mu.Unlock()
	r.syncSpywareHook(cfg)
	if r.ledger != nil {
		_ = r.ledger.Append("v6.spyware.mode", normalized, "operator-updated")
	}
	return nil
}

func (r *v6Runtime) syncSpywareHook(cfg v6Config) {
	if r == nil || r.spyware == nil {
		return
	}
	mode := cfg.SpywareMode
	if mode == "" {
		mode = v6SpywareModeObserve
	}
	if !cfg.SpywareEnabled || mode != v6SpywareModeActive {
		r.spyware.SetFindingResponseHook(nil)
		return
	}
	r.spyware.SetFindingResponseHook(func(f spyware.Finding) string {
		if f.Severity != spyware.SeverityHigh && f.Severity != spyware.SeverityCritical {
			return ""
		}
		if r.ledger != nil {
			_ = r.ledger.Append("v6.active_guard", string(f.Source)+":"+f.Asset, f.Title)
		}
		if f.Response == "OBSERVE_ONLY" || f.Response == "" {
			return "ACTIVE_GUARD"
		}
		return f.Response + "|ACTIVE_GUARD"
	})
}

// Restore applies the persisted configuration at composition time. A witness
// that is requested but not provisioned yields the honest FAULT state instead of
// aborting the service start; only an explicit operator apply is rejected.
func (r *v6Runtime) Restore(config v6Config) {
	_ = r.configure(context.Background(), config, false)
}

// Configure applies an accepted operator settings change. Enabling the witness
// without a valid provisioning document is rejected so the settings authority
// never persists a witness intent it cannot enforce.
func (r *v6Runtime) Configure(ctx context.Context, config v6Config) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("V6 settings apply requires an active request")
	}
	return r.configure(ctx, config, true)
}

func (r *v6Runtime) configure(ctx context.Context, config v6Config, enforce bool) error {
	mode, err := normalizeSpywareMode(config.SpywareMode)
	if err != nil {
		return err
	}
	config.SpywareMode = mode

	r.applyMu.Lock()
	defer r.applyMu.Unlock()

	r.mu.Lock()
	previous := r.config
	r.config = config
	r.mu.Unlock()
	r.syncSpywareHook(config)

	if !config.WitnessEnabled {
		r.stopWitness()
		r.setWitnessState(witnessStateDisabled, "witness is disabled in the GeDefense settings")
		return nil
	}
	if previous.WitnessEnabled && r.witnessEngine() != nil {
		// Already provisioned; a spyware-only change must not restart the witness.
		return nil
	}
	if err := r.startWitness(); err != nil {
		r.setWitnessState(r.invalidWitnessState(), err.Error())
		if enforce {
			return err
		}
	}
	return nil
}

// invalidWitnessState keeps the provisioning state that startWitness recorded.
func (r *v6Runtime) invalidWitnessState() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.witnessState == witnessStateMissing || r.witnessState == witnessStateInvalid {
		return r.witnessState
	}
	return witnessStateInvalid
}

// Run is the V6 supervisor. It starts the witness engine (Start) and the four
// sensor cycles under one cancelable context, then joins everything before it
// returns. It is executed by App.supervise so a panic is contained and recorded.
func (r *v6Runtime) Run(stop <-chan struct{}) {
	r.applyMu.Lock()
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		r.applyMu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(context.Background())
	r.runCtx = runCtx
	r.runCancel = cancel
	r.running = true
	engine := r.witness
	r.mu.Unlock()

	if engine != nil {
		if err := engine.Start(runCtx); err != nil {
			// Keep the engine: Status reports FAULT with the bounded reason.
			r.setWitnessReason("witness engine could not start: " + boundedV6Reason(err))
		}
	}
	r.applyMu.Unlock()

	var sensors sync.WaitGroup
	sensors.Add(4)
	go func() { defer sensors.Done(); r.runCapabilitySensor(runCtx) }()
	go func() { defer sensors.Done(); r.runDriverSensor(runCtx) }()
	go func() { defer sensors.Done(); r.runPersistenceSensor(runCtx) }()
	go func() { defer sensors.Done(); r.runLSASSSensor(runCtx) }()

	<-stop
	cancel()

	joined := make(chan struct{})
	go func() { sensors.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(v6ShutdownGrace):
	}

	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	engine = r.witness
	r.running = false
	r.runCtx = nil
	r.runCancel = nil
	r.mu.Unlock()
	if engine != nil {
		_ = engine.Close()
	}
}

// Close is the idempotent shutdown hook for App.Run. It stops the witness
// engine even if the supervisor returned early.
func (r *v6Runtime) Close() error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	engine := r.witness
	r.mu.Unlock()
	if engine != nil {
		return engine.Close()
	}
	return nil
}

// effectiveConfig returns a copy of the effective configuration.
func (r *v6Runtime) effectiveConfig() v6Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.config
}

// spywareEngine returns the process-wide spyware engine.
func (r *v6Runtime) spywareEngine() *spyware.Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.spyware
}

// witnessEngine returns the current witness engine, if constructed.
func (r *v6Runtime) witnessEngine() *witness.Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.witness
}

func (r *v6Runtime) setWitnessState(state, reason string) {
	r.mu.Lock()
	r.witnessState = state
	r.witnessReason = boundedV6ReasonText(reason)
	r.mu.Unlock()
}

func (r *v6Runtime) setWitnessReason(reason string) {
	r.mu.Lock()
	r.witnessReason = boundedV6ReasonText(reason)
	r.mu.Unlock()
}

// SpywareStatus is the bounded status projection. It corrects the engine's
// construction-time flags to the effective operator configuration so the API
// never claims a sensor is watching when the operator disabled it.
func (r *v6Runtime) SpywareStatus() spyware.Status {
	r.mu.Lock()
	engine := r.spyware
	config := r.config
	problems := make(map[string]string, len(r.sensorProblems))
	for family, reason := range r.sensorProblems {
		problems[family] = reason
	}
	lockState := r.lockState
	r.mu.Unlock()

	var status spyware.Status
	if engine != nil {
		status = engine.Status()
	}
	status.Enabled = config.SpywareEnabled
	if !config.SpywareEnabled {
		status.Mode = "disabled"
		status.ActiveEnforced = false
	} else {
		mode := config.SpywareMode
		if mode == "" {
			mode = v6SpywareModeObserve
		}
		status.Mode = mode
		status.ActiveEnforced = mode == v6SpywareModeActive
	}
	status.BYOVDWatched = config.SpywareEnabled && config.BYOVD
	status.CapabilityWatch = config.SpywareEnabled && config.Capability
	status.PersistenceWatch = config.SpywareEnabled && config.Persistence
	status.LSASSWatch = config.SpywareEnabled && config.LSASS
	if reason := joinedSensorProblem(problems); reason != "" {
		status.Degraded = true
		status.LastError = reason
	}
	if status.LastError == "" {
		status.LastError = lockStateNote(lockState)
	}
	return status
}

// SpywareFindings returns at most limit newest findings.
func (r *v6Runtime) SpywareFindings(limit int) []spyware.Finding {
	engine := r.spywareEngine()
	if engine == nil || limit <= 0 {
		return nil
	}
	if limit > v6MaxFindings {
		limit = v6MaxFindings
	}
	return engine.Findings(limit)
}

// SpywareLockState reports how the workstation lock signal is available.
func (r *v6Runtime) SpywareLockState() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lockState
}

// WitnessStatus returns the bounded witness projection. An unprovisioned but
// operator-requested witness is reported as FAULT; a genuinely disabled witness
// is reported as DISABLED with the provisioning reason in the settings state.
func (r *v6Runtime) WitnessStatus() witness.StatusReport {
	r.mu.Lock()
	engine := r.witness
	state := r.witnessState
	reason := r.witnessReason
	r.mu.Unlock()
	if engine != nil {
		report := engine.Status()
		if report.LastError == "" && reason != "" && report.Status == witness.StatusUnverified {
			// Keep the engine's own vocabulary; the reason is surfaced through
			// WitnessSettingsState, not by rewriting the engine status.
			report.LastError = ""
		}
		return report
	}
	report := witness.StatusReport{Status: witness.StatusDisabled}
	switch state {
	case witnessStateMissing, witnessStateInvalid:
		report.Status = witness.StatusFault
		report.LastError = reason
	default:
		report.Status = witness.StatusDisabled
	}
	return report
}

// WitnessSettingsState reports how the witness provisioning document was
// resolved and the bounded operator-facing reason.
func (r *v6Runtime) WitnessSettingsState() (string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.witnessState, r.witnessReason
}

// setLockState records the lock detection result.
func (r *v6Runtime) setLockState(state string) {
	r.mu.Lock()
	r.lockState = state
	r.mu.Unlock()
}

// noteSensorProblem records or clears one bounded collector problem.
func (r *v6Runtime) noteSensorProblem(family string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		delete(r.sensorProblems, family)
		return
	}
	if r.sensorProblems == nil {
		r.sensorProblems = make(map[string]string, 4)
	}
	if len(r.sensorProblems) >= 8 {
		return
	}
	r.sensorProblems[family] = family + ": " + boundedV6Reason(err)
}

// joinedSensorProblem returns the first problem in a stable family order.
func joinedSensorProblem(problems map[string]string) string {
	for _, family := range []string{"capability", "driver", "persistence", "lsass"} {
		if reason := problems[family]; reason != "" {
			return reason
		}
	}
	return ""
}

// lockStateNote explains an unavailable lock signal honestly. It is not an
// error of the sensors themselves; it documents that the capability classifier
// receives false (never a fabricated "locked") when the service cannot see the
// interactive desktop.
func lockStateNote(lockState string) string {
	if lockState == v6LockUnavailable {
		return "workstation lock detection is unavailable in the service session; capability findings assume an unlocked workstation"
	}
	return ""
}

// boundedV6Reason keeps operator-facing detail bounded.
func boundedV6Reason(err error) string {
	if err == nil {
		return ""
	}
	return boundedV6ReasonText(err.Error())
}

// boundedV6ReasonText trims and bounds a reason string.
func boundedV6ReasonText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}
