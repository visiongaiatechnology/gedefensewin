// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/kinetic"
)

const (
	kineticStateSchemaVersion = 1
	kineticStateFileName      = "kinetic-settings.json"
	// maximumKineticStateBytes bounds the persisted operator state before any
	// JSON decoding occurs.
	maximumKineticStateBytes = 16 << 10
	// kineticRearmRetryInterval is the minimum delay between automatic re-arm
	// evaluations while the verified Threat-IP/WFP requirements are missing.
	kineticRearmRetryInterval = 30 * time.Second
	// kineticRequirementLostGrace avoids flapping when a healthy WFP bridge has
	// a single missed heartbeat. Arming is only dropped after sustained loss.
	kineticRequirementLostGrace = 20 * time.Second
)

const (
	kineticConfigSourceDefault = "DEFAULT"
	kineticConfigSourceStored  = "PERSISTED"
	kineticConfigSourceInvalid = "INVALID_DEFAULT"

	kineticRearmIdle     = "IDLE"
	kineticRearmPending  = "PENDING"
	kineticRearmReArmed  = "REARMED"
	kineticArmOperator   = "OPERATOR"
	kineticArmPersisted  = "PERSISTED_REARM"
	kineticArmFailSecure = "FAIL_SAFE_OBSERVE"
)

// kineticRuntimeState is the engine-owned Kinetic state. It is protected by
// Engine.mu and is never serialized directly; kineticPersistedState is the
// on-disk projection.
type kineticRuntimeState struct {
	config               kinetic.Config
	configSource         string
	configWarning        string
	persisted            bool
	settingsUpdatedUTC   time.Time
	desiredArmed         bool
	armedUTC             time.Time
	armReason            string
	requirementLostSince time.Time
	rearmState           string
	rearmReason          string
	rearmAttempts        uint64
	rearmLastAttemptUTC  time.Time
	rearmNextAttemptUTC  time.Time
	rearmLastError       string
}

type kineticPersistedState struct {
	SchemaVersion int            `json:"schemaVersion"`
	Armed         bool           `json:"armed"`
	Config        kinetic.Config `json:"config"`
	UpdatedUTC    time.Time      `json:"updatedUtc"`
}

// KineticAutoRearmStatus explains the automatic promotion of a persisted
// arming intent. It is derived from live verification, not from the file.
type KineticAutoRearmStatus struct {
	State          string    `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	Attempts       uint64    `json:"attempts"`
	LastAttemptUTC time.Time `json:"lastAttemptUtc,omitempty"`
	NextAttemptUTC time.Time `json:"nextAttemptUtc,omitempty"`
	LastError      string    `json:"lastError,omitempty"`
}

// KineticSettingsSnapshot is the complete Kinetic settings/status contract.
// Armed is the effective, runtime-verified correlation state. DesiredArmed is
// the persisted operator intent which may legitimately be waiting for verified
// Threat-IP/WFP generation requirements.
type KineticSettingsSnapshot struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Armed         bool                       `json:"armed"`
	Observe       bool                       `json:"observe"`
	DesiredArmed  bool                       `json:"desiredArmed"`
	Mode          string                     `json:"mode"`
	Config        kinetic.Config             `json:"config"`
	Defaults      kinetic.Config             `json:"defaults"`
	Limits        kinetic.Limits             `json:"limits"`
	ConfigSource  string                     `json:"configSource"`
	ConfigWarning string                     `json:"configWarning,omitempty"`
	ArmingSource  string                     `json:"armingSource"`
	Reason        string                     `json:"reason,omitempty"`
	Requirements  kinetic.ArmingRequirements `json:"requirements"`
	AutoRearm     KineticAutoRearmStatus     `json:"autoRearm"`
	Persisted     bool                       `json:"persisted"`
	UpdatedUTC    time.Time                  `json:"updatedUtc,omitempty"`
	ArmedUTC      time.Time                  `json:"armedUtc,omitempty"`
}

func (e *Engine) kineticStatePath() string {
	return filepath.Join(e.root, kineticStateFileName)
}

// loadKineticState restores the persisted observation policy and the operator
// arming intent. Persisted arming is never trusted as verification: the engine
// always restarts effectively disarmed and only re-arms once the live
// Threat-IP/WFP generation checks pass again.
func (e *Engine) loadKineticState() {
	defaults := kinetic.DefaultConfig()
	e.mu.Lock()
	e.kineticRuntime = kineticRuntimeState{config: defaults, configSource: kineticConfigSourceDefault, rearmState: kineticRearmIdle}
	e.mu.Unlock()

	raw, err := os.ReadFile(e.kineticStatePath())
	if errors.Is(err, os.ErrNotExist) {
		e.applyKineticMonitorConfig(defaults)
		return
	}
	markInvalid := func(warning string) {
		e.mu.Lock()
		e.kineticRuntime.config = defaults
		e.kineticRuntime.configSource = kineticConfigSourceInvalid
		e.kineticRuntime.configWarning = warning
		e.kineticRuntime.persisted = false
		e.kineticRuntime.desiredArmed = false
		e.mu.Unlock()
		e.applyKineticMonitorConfig(defaults)
	}
	if err != nil {
		markInvalid("persisted kinetic state unreadable; default observe policy active")
		return
	}
	if len(raw) == 0 || len(raw) > maximumKineticStateBytes {
		markInvalid("persisted kinetic state size rejected; default observe policy active")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state kineticPersistedState
	if err := decoder.Decode(&state); err != nil {
		markInvalid("persisted kinetic state rejected; default observe policy active")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		markInvalid("persisted kinetic state trailing data rejected; default observe policy active")
		return
	}
	if state.SchemaVersion != kineticStateSchemaVersion {
		markInvalid("persisted kinetic state schema rejected; default observe policy active")
		return
	}
	if err := state.Config.Validate(); err != nil {
		markInvalid("persisted kinetic policy rejected; default observe policy active")
		return
	}
	e.mu.Lock()
	e.kineticRuntime.config = state.Config
	e.kineticRuntime.configSource = kineticConfigSourceStored
	e.kineticRuntime.configWarning = ""
	e.kineticRuntime.persisted = true
	e.kineticRuntime.settingsUpdatedUTC = state.UpdatedUTC
	e.kineticRuntime.desiredArmed = state.Armed
	if state.Armed {
		e.kineticRuntime.rearmState = kineticRearmPending
		e.kineticRuntime.rearmReason = "persisted arming intent requires verified Threat-IP/WFP requirements"
	}
	e.mu.Unlock()
	e.applyKineticMonitorConfig(state.Config)
}

func (e *Engine) applyKineticMonitorConfig(config kinetic.Config) {
	if e.kineticMonitor == nil {
		return
	}
	_ = e.kineticMonitor.Configure(config)
}

// writeKineticState atomically persists the desired arming intent and the
// active observation policy. It intentionally does not persist the effective
// armed flag: verification state is never restored from disk.
func (e *Engine) writeKineticState(desiredArmed bool) error {
	e.mu.RLock()
	config := e.kineticRuntime.config
	if config == (kinetic.Config{}) {
		config = kinetic.DefaultConfig()
	}
	e.mu.RUnlock()
	if err := config.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(kineticPersistedState{SchemaVersion: kineticStateSchemaVersion, Armed: desiredArmed, Config: config, UpdatedUTC: time.Now().UTC()})
	if err != nil {
		return err
	}
	return atomicWrite(e.kineticStatePath(), append(payload, '\n'))
}

func (e *Engine) ledgerAppend(kind, action, result string) {
	if e == nil || e.ledger == nil {
		return
	}
	_ = e.ledger.Append(kind, action, result)
}

// kineticRequirements evaluates the existing verified Threat-IP/WFP generation
// requirements against live telemetry. It never mutates state.
func (e *Engine) kineticRequirements() kinetic.ArmingRequirements {
	if e == nil {
		return kinetic.EvaluateArmingRequirements(kinetic.ArmingInputs{})
	}
	e.mu.RLock()
	wfpRealtime, networkRealtime := e.wfpRealtime, e.networkRealtime
	enforcement := e.threatEnforcement
	e.mu.RUnlock()
	var feedFeedGeneration string
	var blockingIndicators int
	if e.feeds != nil {
		status := e.feeds.Status()
		feedFeedGeneration = status.EnforcementGeneration
		blockingIndicators = status.BlockingIndicators
	}
	return kinetic.EvaluateArmingRequirements(kinetic.ArmingInputs{
		WFPRealtime:               wfpRealtime,
		NetworkRealtime:           networkRealtime,
		EnforcementState:          enforcement.State,
		DesiredGeneration:         enforcement.DesiredGeneration,
		ActiveGeneration:          enforcement.ActiveGeneration,
		FeedEnforcementGeneration: feedFeedGeneration,
		BlockingIndicators:        blockingIndicators,
	})
}

// KineticSettings returns a detached snapshot of the persisted policy and the
// live arming/verification state.
func (e *Engine) KineticSettings() KineticSettingsSnapshot {
	if e == nil {
		defaults := kinetic.DefaultConfig()
		return KineticSettingsSnapshot{SchemaVersion: kineticStateSchemaVersion, Observe: true, Mode: "OBSERVE_ONLY", Config: defaults, Defaults: defaults, Limits: defaults.Limits(), ConfigSource: kineticConfigSourceDefault, ArmingSource: kineticArmFailSecure}
	}
	requirements := e.kineticRequirements()
	e.mu.RLock()
	rt := e.kineticRuntime
	armed := e.kineticArmed
	e.mu.RUnlock()
	config := rt.config
	configSource := rt.configSource
	if config == (kinetic.Config{}) {
		config = kinetic.DefaultConfig()
		if configSource == "" {
			configSource = kineticConfigSourceDefault
		}
	}
	if configSource == "" {
		configSource = kineticConfigSourceDefault
	}
	reason := rt.armReason
	armingSource := rt.armReason
	if !armed {
		armingSource = kineticArmFailSecure
		if rt.desiredArmed {
			armingSource = kineticRearmPending
			reason = rt.rearmReason
		}
	}
	if armed && armingSource == "" {
		armingSource = kineticArmFailSecure
	}
	rearmState := rt.rearmState
	if rearmState == "" {
		rearmState = kineticRearmIdle
	}
	autoRearm := KineticAutoRearmStatus{State: rearmState, Reason: rt.rearmReason, Attempts: rt.rearmAttempts, LastAttemptUTC: rt.rearmLastAttemptUTC, NextAttemptUTC: rt.rearmNextAttemptUTC, LastError: rt.rearmLastError}
	if armed && rearmState == kineticRearmPending && requirements.Ready {
		// Defensive: a pending state with satisfied requirements is stale; the
		// next reconciliation promotes it.
		autoRearm.Reason = "verified requirements satisfied; automatic re-arm pending"
	}
	mode := "OBSERVE_ONLY"
	if armed {
		mode = "ARMED_TI_CORRELATION"
	}
	return KineticSettingsSnapshot{
		SchemaVersion: kineticStateSchemaVersion,
		Armed:         armed,
		Observe:       !armed,
		DesiredArmed:  rt.desiredArmed,
		Mode:          mode,
		Config:        config,
		Defaults:      kinetic.DefaultConfig(),
		Limits:        config.Limits(),
		ConfigSource:  configSource,
		ConfigWarning: rt.configWarning,
		ArmingSource:  armingSource,
		Reason:        reason,
		Requirements:  requirements,
		AutoRearm:     autoRearm,
		Persisted:     rt.persisted,
		UpdatedUTC:    rt.settingsUpdatedUTC,
		ArmedUTC:      rt.armedUTC,
	}
}

// SetKineticConfig validates, applies and atomically persists a new observation
// policy. The previous verified policy stays active when validation, monitor
// application or persistence fails.
func (e *Engine) SetKineticConfig(ctx context.Context, config kinetic.Config) (KineticSettingsSnapshot, error) {
	if e == nil {
		return KineticSettingsSnapshot{}, errors.New("kinetic controller unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return e.KineticSettings(), errors.New("kinetic configuration requires an active request")
	}
	if e.kineticMonitor == nil {
		return e.KineticSettings(), errors.New("kinetic observation monitor unavailable")
	}
	if err := config.Validate(); err != nil {
		e.ledgerAppend("kinetic.config", "observation-policy", "rejected")
		return e.KineticSettings(), err
	}
	e.mu.RLock()
	previous := e.kineticRuntime.config
	if previous == (kinetic.Config{}) {
		previous = kinetic.DefaultConfig()
	}
	desiredArmed := e.kineticRuntime.desiredArmed
	e.mu.RUnlock()
	if previous == config {
		return e.KineticSettings(), nil
	}
	if err := e.kineticMonitor.Configure(config); err != nil {
		e.ledgerAppend("kinetic.config", "observation-policy", "rejected")
		return e.KineticSettings(), err
	}
	e.mu.Lock()
	e.kineticRuntime.config = config
	e.kineticRuntime.configSource = kineticConfigSourceStored
	e.kineticRuntime.configWarning = ""
	e.kineticRuntime.settingsUpdatedUTC = time.Now().UTC()
	e.mu.Unlock()
	if err := e.writeKineticState(desiredArmed); err != nil {
		if rollbackErr := e.kineticMonitor.Configure(previous); rollbackErr == nil {
			e.mu.Lock()
			e.kineticRuntime.config = previous
			e.mu.Unlock()
		}
		e.ledgerAppend("kinetic.config", "observation-policy", "persistence-failed")
		return e.KineticSettings(), fmt.Errorf("kinetic configuration persistence failed: %w", err)
	}
	e.mu.Lock()
	e.kineticRuntime.persisted = true
	e.kineticRuntime.settingsUpdatedUTC = time.Now().UTC()
	e.mu.Unlock()
	e.ledgerAppend("kinetic.config", "observation-policy", fmt.Sprintf("window=%d;events=%d;ports=%d;autoDisarm=%d", config.BurstWindowSeconds, config.MinEvents, config.MinDistinctPorts, config.AutoDisarmSeconds))
	// A shortened auto-disarm window can expire immediately; let the regular
	// reconciliation path evaluate it instead of leaving a stale armed state.
	e.reconcileKinetic(time.Now().UTC())
	return e.KineticSettings(), nil
}

// recordArmingIntent persists an effective arming decision. The evidence entry
// is written before the persisted state so a failed commit never claims arming.
func (e *Engine) recordArmingIntent(source string) error {
	now := time.Now().UTC()
	e.ledgerAppend("kinetic.mode", "threat-ip-correlation", "ARMED")
	if err := e.writeKineticState(true); err != nil {
		e.ledgerAppend("kinetic.mode", "arming-persistence", "failed")
		return fmt.Errorf("kinetic arming persistence failed: %w", err)
	}
	e.mu.Lock()
	e.kineticArmed = true
	e.kineticRuntime.desiredArmed = true
	e.kineticRuntime.persisted = true
	e.kineticRuntime.armedUTC = now
	e.kineticRuntime.armReason = source
	e.kineticRuntime.requirementLostSince = time.Time{}
	e.kineticRuntime.rearmLastError = ""
	e.kineticRuntime.rearmNextAttemptUTC = time.Time{}
	if source == kineticArmPersisted {
		e.kineticRuntime.rearmState = kineticRearmReArmed
		e.kineticRuntime.rearmReason = "persisted arming intent promoted after verified Threat-IP/WFP requirements"
		e.kineticRuntime.rearmAttempts++
		e.kineticRuntime.rearmLastAttemptUTC = now
	} else {
		e.kineticRuntime.rearmState = kineticRearmIdle
		e.kineticRuntime.rearmReason = ""
	}
	e.mu.Unlock()
	return nil
}

// disarmWithReason records and applies an operator-requested disarm. A failed
// persistence write still leaves the engine disarmed in memory (fail-secure);
// the caller receives the persistence error.
func (e *Engine) disarmWithReason(reason string) error {
	e.ledgerAppend("kinetic.mode", "threat-ip-correlation", reason)
	persistErr := e.writeKineticState(false)
	e.mu.Lock()
	e.kineticArmed = false
	e.kineticRuntime.desiredArmed = false
	e.kineticRuntime.armedUTC = time.Time{}
	e.kineticRuntime.armReason = "OBSERVE"
	e.kineticRuntime.requirementLostSince = time.Time{}
	e.kineticRuntime.rearmState = kineticRearmIdle
	e.kineticRuntime.rearmReason = "operator disarm"
	e.kineticRuntime.rearmNextAttemptUTC = time.Time{}
	e.mu.Unlock()
	if persistErr != nil {
		e.ledgerAppend("kinetic.mode", "disarm-persistence", "failed")
		return fmt.Errorf("kinetic disarm persistence failed: %w", persistErr)
	}
	e.mu.Lock()
	e.kineticRuntime.persisted = true
	e.mu.Unlock()
	return nil
}

// dropEffectiveArming is the fail-secure reaction to sustained loss of the
// verified Threat-IP/WFP requirements. The persisted operator intent is kept so
// the engine can re-arm automatically once verification succeeds again.
func (e *Engine) dropEffectiveArming(requirements kinetic.ArmingRequirements) {
	e.ledgerAppend("kinetic.mode", "threat-ip-correlation", "OBSERVE_REQUIREMENTS_LOST")
	e.mu.Lock()
	e.kineticArmed = false
	e.kineticRuntime.requirementLostSince = time.Time{}
	e.kineticRuntime.rearmState = kineticRearmPending
	e.kineticRuntime.rearmReason = "verified Threat-IP/WFP requirements were lost; automatic re-arm pending"
	e.kineticRuntime.rearmLastError = strings.Join(requirements.Blockers, "; ")
	e.mu.Unlock()
}

// reconcileKinetic is called from the engine health loop. It is the only place
// that promotes a persisted arming intent or drops effective arming after a
// sustained verification loss; both decisions require live evidence.
func (e *Engine) reconcileKinetic(now time.Time) {
	if e == nil {
		return
	}
	e.mu.RLock()
	desired := e.kineticRuntime.desiredArmed
	armed := e.kineticArmed
	config := e.kineticRuntime.config
	armedUTC := e.kineticRuntime.armedUTC
	lostSince := e.kineticRuntime.requirementLostSince
	nextAttempt := e.kineticRuntime.rearmNextAttemptUTC
	rearmState := e.kineticRuntime.rearmState
	e.mu.RUnlock()
	if config == (kinetic.Config{}) {
		config = kinetic.DefaultConfig()
	}
	requirements := e.kineticRequirements()

	if armed {
		// Auto-disarm is an operator-configured safety window, not a response
		// to a failed verification. It always returns the engine to observe.
		if config.AutoDisarmSeconds > 0 && !armedUTC.IsZero() && now.Sub(armedUTC) >= config.AutoDisarm() {
			if err := e.disarmWithReason("AUTO_DISARM_ELAPSED"); err != nil {
				e.ledgerAppend("kinetic.mode", "auto-disarm", "persistence-failed")
			}
			return
		}
		if requirements.Ready {
			e.mu.Lock()
			e.kineticRuntime.requirementLostSince = time.Time{}
			e.mu.Unlock()
			return
		}
		if lostSince.IsZero() {
			e.mu.Lock()
			e.kineticRuntime.requirementLostSince = now
			e.mu.Unlock()
			return
		}
		if now.Sub(lostSince) < kineticRequirementLostGrace {
			return
		}
		e.dropEffectiveArming(requirements)
		return
	}
	if !desired {
		return
	}
	if !nextAttempt.IsZero() && now.Before(nextAttempt) {
		return
	}
	if !requirements.Ready {
		previousState := rearmState
		e.mu.Lock()
		if e.kineticRuntime.rearmState != kineticRearmPending || e.kineticRuntime.rearmLastAttemptUTC.IsZero() {
			e.kineticRuntime.rearmAttempts++
			e.kineticRuntime.rearmLastAttemptUTC = now
		}
		e.kineticRuntime.rearmState = kineticRearmPending
		e.kineticRuntime.rearmReason = "persisted arming intent waiting for verified Threat-IP/WFP requirements"
		e.kineticRuntime.rearmLastError = strings.Join(requirements.Blockers, "; ")
		e.kineticRuntime.rearmNextAttemptUTC = now.Add(kineticRearmRetryInterval)
		e.mu.Unlock()
		if previousState != kineticRearmPending {
			e.ledgerAppend("kinetic.rearm", "persisted-intent", "waiting-for-verified-requirements")
		}
		return
	}
	if err := e.recordArmingIntent(kineticArmPersisted); err != nil {
		e.mu.Lock()
		e.kineticRuntime.rearmState = kineticRearmPending
		e.kineticRuntime.rearmAttempts++
		e.kineticRuntime.rearmLastAttemptUTC = now
		e.kineticRuntime.rearmLastError = err.Error()
		e.kineticRuntime.rearmNextAttemptUTC = now.Add(kineticRearmRetryInterval)
		e.mu.Unlock()
		e.ledgerAppend("kinetic.rearm", "persisted-intent", "failed")
	}
}

// SetKineticDesiredState persists the operator's arming intent across service
// restarts without ever promoting it without live verification. It is the
// explicit "arm after restart" contract:
//
//   - armedAfterRestart=false disarms immediately and persists OBSERVE;
//   - armedAfterRestart=true records the intent. When the existing verified
//     Threat-IP/WFP generation requirements are currently satisfied the engine
//     arms immediately; otherwise it remains effectively OBSERVE and the health
//     loop promotes the intent only once all requirements verify.
//
// It never returns an error for a persisted-but-not-yet-verified intent: the
// intent is accepted and the effective state is reported honestly.
func (e *Engine) SetKineticDesiredState(ctx context.Context, armedAfterRestart bool) (KineticSettingsSnapshot, error) {
	if e == nil {
		return KineticSettingsSnapshot{}, errors.New("kinetic controller unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return e.KineticSettings(), errors.New("kinetic state update requires an active request")
	}
	if !armedAfterRestart {
		if err := e.disarmWithReason("DISARMED"); err != nil {
			return e.KineticSettings(), err
		}
		return e.KineticSettings(), nil
	}
	requirements := e.kineticRequirements()
	e.mu.RLock()
	alreadyArmed := e.kineticArmed
	e.mu.RUnlock()
	if alreadyArmed {
		return e.KineticSettings(), nil
	}
	if requirements.Ready {
		if err := e.recordArmingIntent(kineticArmOperator); err != nil {
			return e.KineticSettings(), err
		}
		return e.KineticSettings(), nil
	}
	if e.kineticMonitor == nil {
		return e.KineticSettings(), errors.New("kinetic observation monitor unavailable")
	}
	if err := e.writeKineticState(true); err != nil {
		e.ledgerAppend("kinetic.intent", "armed-after-restart", "persistence-failed")
		return e.KineticSettings(), fmt.Errorf("kinetic arming intent persistence failed: %w", err)
	}
	now := time.Now().UTC()
	e.mu.Lock()
	e.kineticRuntime.desiredArmed = true
	e.kineticRuntime.persisted = true
	e.kineticRuntime.rearmState = kineticRearmPending
	e.kineticRuntime.rearmReason = "operator requested arming after restart; waiting for verified Threat-IP/WFP requirements"
	e.kineticRuntime.rearmLastError = strings.Join(requirements.Blockers, "; ")
	e.kineticRuntime.rearmNextAttemptUTC = now
	e.mu.Unlock()
	e.ledgerAppend("kinetic.intent", "armed-after-restart", "persisted-pending-verification")
	e.reconcileKinetic(now)
	return e.KineticSettings(), nil
}

// SetKineticArmed is the existing operator entry point. It keeps its signature
// and fail-closed verification semantics, now with atomic persistence and an
// automatic re-arm ladder for a verified restart.
func (e *Engine) SetKineticArmed(ctx context.Context, armed bool) error {
	if e == nil {
		return errors.New("kinetic controller unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("kinetic control requires an active request")
	}
	if !armed {
		e.mu.RLock()
		desired, effective := e.kineticRuntime.desiredArmed, e.kineticArmed
		e.mu.RUnlock()
		if !desired && !effective {
			return nil
		}
		return e.disarmWithReason("DISARMED")
	}
	if e.kineticMonitor == nil {
		return errors.New("kinetic: observation monitor unavailable")
	}
	requirements := e.kineticRequirements()
	if !requirements.Ready {
		e.ledgerAppend("kinetic.mode", "threat-ip-correlation", "REQUIREMENTS_UNMET")
		return fmt.Errorf("kinetic: verified Threat-IP WFP generation required: %s", strings.Join(requirements.Blockers, "; "))
	}
	e.mu.RLock()
	alreadyArmed := e.kineticArmed
	e.mu.RUnlock()
	if alreadyArmed {
		return nil
	}
	return e.recordArmingIntent(kineticArmOperator)
}
