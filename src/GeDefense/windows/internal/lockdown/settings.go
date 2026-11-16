// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"fmt"
	"strings"
	"time"
)

// Settings bounds. They are enforced as rejection bounds, never repaired
// silently: a clamped safety setting would look applied while doing something
// else.
const (
	// DefaultCooldown is the shipped automatic-trigger cooldown (5 minutes).
	DefaultCooldown = 5 * time.Minute
	// DefaultDedupe is the shipped trigger-identity dedupe window (5 minutes).
	DefaultDedupe = 5 * time.Minute
	// MaxCooldown is the documented upper cooldown bound.
	MaxCooldown = 24 * time.Hour
	// MaxDedupe is the documented upper dedupe bound.
	MaxDedupe = 24 * time.Hour
	// DefaultPhaseTimeout is the per-phase timeout used by the standard phases.
	DefaultPhaseTimeout = 20 * time.Second
	// MaxPhaseTimeout is the hard per-phase timeout bound.
	MaxPhaseTimeout = 2 * time.Minute
	// MaxReasonBytes bounds one operator-visible reason string.
	MaxReasonBytes = 240
	// MaxDetailBytes bounds one operator-visible phase detail string. It is the
	// same 160-byte bound as the Linux engine (lockdownMaxPhaseDetailBytes).
	MaxDetailBytes = 160
	// MaxTriggerIDBytes bounds one trigger identity.
	MaxTriggerIDBytes = 128
	// MaxPhaseTargets bounds every per-phase target list.
	MaxPhaseTargets = 256
)

// PhaseName is the closed vocabulary of lockdown phase names. The order and the
// spellings are the Linux V6 phase order, restricted to the phases that exist on
// Windows.
type PhaseName string

const (
	// PhaseNetwork blocks outbound network traffic.
	PhaseNetwork PhaseName = "NET"
	// PhaseUSB applies the composite-BadUSB USB policy.
	PhaseUSB PhaseName = "USB"
	// PhaseThunderbolt applies the Thunderbolt DMA policy.
	PhaseThunderbolt PhaseName = "TB"
	// PhaseHardening applies the allowlisted reversible hardening profile.
	PhaseHardening PhaseName = "HARDENING"
	// PhaseBrokers freezes the fixed key-broker/remote-desktop process set.
	PhaseBrokers PhaseName = "BROKERS"
	// PhaseParsers is the Linux parser-cell phase; it has no Windows substrate.
	PhaseParsers PhaseName = "PARSERS"
	// PhaseSessions disconnects remote sessions and locks the workstation.
	PhaseSessions PhaseName = "SESSIONS"
	// PhaseDeviceMapper is the optional BitLocker ForceRecovery phase.
	PhaseDeviceMapper PhaseName = "DM"
)

// phaseSequence is the fixed engage order (the Linux order, Windows subset).
// The array is unexported and never mutated; PhaseSequence returns a copy so no
// caller can install a global mutation.
var phaseSequence = [...]PhaseName{
	PhaseNetwork, PhaseUSB, PhaseThunderbolt, PhaseHardening,
	PhaseBrokers, PhaseParsers, PhaseSessions, PhaseDeviceMapper,
}

// PhaseSequence returns a copy of the fixed phase order.
func PhaseSequence() []PhaseName {
	out := make([]PhaseName, len(phaseSequence))
	copy(out, phaseSequence[:])
	return out
}

// phaseNameValid reports whether name is in the closed phase vocabulary.
func phaseNameValid(name PhaseName) bool {
	for _, candidate := range phaseSequence {
		if candidate == name {
			return true
		}
	}
	return false
}

// PhaseSelection is the operator-facing phase switch set. DM is special: it
// additionally requires Settings.DMEnabled because BitLocker ForceRecovery is
// destructive and off by default.
type PhaseSelection struct {
	Network      bool `json:"network"`
	USB          bool `json:"usb"`
	Thunderbolt  bool `json:"thunderbolt"`
	Hardening    bool `json:"hardening"`
	Brokers      bool `json:"brokers"`
	Parsers      bool `json:"parsers"`
	Sessions     bool `json:"sessions"`
	DeviceMapper bool `json:"device_mapper"`
}

// DefaultPhaseSelection is the shipped selection: the reversible response
// phases are on, the destructive/administrative phases are off.
func DefaultPhaseSelection() PhaseSelection {
	return PhaseSelection{
		Network: true, USB: true, Thunderbolt: true, Hardening: false,
		Brokers: true, Parsers: true, Sessions: true, DeviceMapper: false,
	}
}

// For reports the switch of one phase.
func (s PhaseSelection) For(name PhaseName) bool {
	switch name {
	case PhaseNetwork:
		return s.Network
	case PhaseUSB:
		return s.USB
	case PhaseThunderbolt:
		return s.Thunderbolt
	case PhaseHardening:
		return s.Hardening
	case PhaseBrokers:
		return s.Brokers
	case PhaseParsers:
		return s.Parsers
	case PhaseSessions:
		return s.Sessions
	case PhaseDeviceMapper:
		return s.DeviceMapper
	}
	return false
}

// Any reports whether at least one phase is selected.
func (s PhaseSelection) Any() bool {
	return s.Network || s.USB || s.Thunderbolt || s.Hardening ||
		s.Brokers || s.Parsers || s.Sessions || s.DeviceMapper
}

// Enabled returns the selected phase names in the fixed engage order.
func (s PhaseSelection) Enabled() []PhaseName {
	out := make([]PhaseName, 0, len(phaseSequence))
	for _, name := range phaseSequence {
		if s.For(name) {
			out = append(out, name)
		}
	}
	return out
}

// Settings is the validated, immutable engine configuration. Construct it with
// DefaultSettings (or an explicit literal) and call Validate; the engine copies
// it at construction and never mutates it, so a caller that keeps the value
// cannot change a running engine.
type Settings struct {
	// Enabled arms the namespace. The shipped default is false: an upgrade must
	// not arm anything by itself.
	Enabled bool `json:"enabled"`
	// ClearRequiresExplicitEpoch requires Clear to carry the epoch the caller
	// observed. Disabling it is a documented weakening and is reported as
	// degraded.
	ClearRequiresExplicitEpoch bool `json:"clear_requires_explicit_epoch"`
	// Cooldown is the minimum interval between two automatic triggers.
	Cooldown time.Duration `json:"cooldown"`
	// Dedupe is the window in which the same trigger identity is suppressed.
	Dedupe time.Duration `json:"dedupe"`
	// Phases selects which phases run.
	Phases PhaseSelection `json:"phases"`
	// DMEnabled activates BitLocker ForceRecovery. It must match
	// Phases.DeviceMapper and is off by default.
	DMEnabled bool `json:"dm_enabled"`
}

// DefaultSettings returns the shipped, inert configuration: disabled, five
// minute cooldown and dedupe, every reversible phase selected, DM off.
func DefaultSettings() Settings {
	return Settings{
		Enabled:                    false,
		ClearRequiresExplicitEpoch: true,
		Cooldown:                   DefaultCooldown,
		Dedupe:                     DefaultDedupe,
		Phases:                     DefaultPhaseSelection(),
		DMEnabled:                  false,
	}
}

// Clone returns a value copy. Settings has only value fields, so the copy is the
// clone; it exists so callers express the intent explicitly.
func (s Settings) Clone() Settings { return s }

// Validate is reject-not-repair. Every out-of-bounds value is refused with its
// own error; no value is clamped.
func (s Settings) Validate() error {
	if s.Cooldown < 0 || s.Cooldown > MaxCooldown {
		return fmt.Errorf("%w: cooldown must be between 0 and %s", ErrInvalidSettings, MaxCooldown)
	}
	if s.Dedupe < 0 || s.Dedupe > MaxDedupe {
		return fmt.Errorf("%w: dedupe must be between 0 and %s", ErrInvalidSettings, MaxDedupe)
	}
	// DM is a two-key arming: the phase switch and the explicit activation must
	// agree. A half-configured destructive phase is a configuration error, not a
	// silent no-op.
	if s.Phases.DeviceMapper != s.DMEnabled {
		return fmt.Errorf("%w: the DM phase switch and DM activation must be configured together", ErrInvalidSettings)
	}
	if s.Enabled && !s.Phases.Any() {
		return fmt.Errorf("%w: lockdown is enabled but no phase is selected; enable at least one phase or disable lockdown", ErrInvalidSettings)
	}
	return nil
}

// selectedPhases returns the engage order of the configured phase set.
func (s Settings) selectedPhases() []PhaseName { return s.Phases.Enabled() }

// phaseSelected reports whether one phase is selected.
func (s Settings) phaseSelected(name PhaseName) bool { return s.Phases.For(name) }

func validateReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("%w: a reason is required", ErrInvalidReason)
	}
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("%w: reason exceeds %d bytes", ErrInvalidReason, MaxReasonBytes)
	}
	for _, char := range reason {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%w: reason contains a control character", ErrInvalidReason)
		}
	}
	return nil
}

// truncateText bounds one operator-visible string, flattens control line breaks
// and trims surrounding space. It never cuts in the middle of a UTF-8 sequence.
func truncateText(value string, max int) string {
	text := strings.TrimSpace(controlFlattener.Replace(value))
	if len(text) <= max {
		return text
	}
	cut := max
	for cut > 0 && (text[cut]&0xc0) == 0x80 {
		cut--
	}
	return text[:cut]
}

var controlFlattener = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")
