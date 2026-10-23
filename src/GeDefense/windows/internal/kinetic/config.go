// STATUS: DIAMANT VGT SUPREME
package kinetic

import (
	"errors"
	"fmt"
	"time"
)

// Default burst classification parameters. They intentionally match the
// previously hard-coded observation thresholds, so an engine that never had a
// persisted configuration keeps its exact historical behaviour.
const (
	DefaultBurstWindowSeconds = 10
	DefaultMinEvents          = 12
	DefaultMinDistinctPorts   = 3
	DefaultAutoDisarmSeconds  = 0

	// MinBurstWindowSeconds is the smallest accepted aggregation window.
	MinBurstWindowSeconds = 2
	// MaxBurstWindowSeconds bounds the aggregation window so a misconfigured
	// observer cannot accumulate unbounded evidence for an ancient burst.
	MaxBurstWindowSeconds = 300
	// MinEvents is the smallest accepted event count. Fewer than three blocked
	// inbound events cannot describe port-diverse scanning behaviour.
	MinEvents = 3
	// MaxEvents is capped at the bounded per-source sample capacity. Accepting
	// more events would require retaining more samples per remote IP and would
	// turn an operator knob into a memory amplification vector.
	MaxEvents = maxSamplesPerSource
	// MinDistinctPorts is the smallest accepted port diversity.
	MinDistinctPorts = 2
	// MaxDistinctPorts keeps the diversity set bounded.
	MaxDistinctPorts = 16
	// MinAutoDisarmSeconds is the smallest accepted automatic disarm window
	// (five minutes). Shorter windows would disarm faster than an operator can
	// understand the state.
	MinAutoDisarmSeconds = 5 * 60
	// MaxAutoDisarmSeconds bounds an automatic disarm window to seven days.
	MaxAutoDisarmSeconds = 7 * 24 * 60 * 60
	// AutoDisarmDisabled is the explicit "never auto-disarm" value.
	AutoDisarmDisabled = 0
)

// Config is the operator-configurable Kinetic observation policy. Every field
// is expressed in whole seconds or counts so it can be validated, persisted and
// rendered without ambiguity.
type Config struct {
	BurstWindowSeconds int `json:"burstWindowSeconds"`
	MinEvents          int `json:"minEvents"`
	MinDistinctPorts   int `json:"minDistinctPorts"`
	AutoDisarmSeconds  int `json:"autoDisarmSeconds"`
}

// DefaultConfig returns the historical, conservative observation policy.
func DefaultConfig() Config {
	return Config{
		BurstWindowSeconds: DefaultBurstWindowSeconds,
		MinEvents:          DefaultMinEvents,
		MinDistinctPorts:   DefaultMinDistinctPorts,
		AutoDisarmSeconds:  DefaultAutoDisarmSeconds,
	}
}

// Range is an inclusive integer validation range.
type Range struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Limits is the published, machine-readable validation envelope. The UI must
// render controls from these bounds instead of guessing.
type Limits struct {
	BurstWindowSeconds      Range `json:"burstWindowSeconds"`
	MinEvents               Range `json:"minEvents"`
	MinDistinctPorts        Range `json:"minDistinctPorts"`
	AutoDisarmSeconds       Range `json:"autoDisarmSeconds"`
	AutoDisarmDisabledValue int   `json:"autoDisarmDisabledValue"`
}

// Limits returns the static validation envelope for Config.
func (Config) Limits() Limits {
	return Limits{
		BurstWindowSeconds:      Range{Min: MinBurstWindowSeconds, Max: MaxBurstWindowSeconds},
		MinEvents:               Range{Min: MinEvents, Max: MaxEvents},
		MinDistinctPorts:        Range{Min: MinDistinctPorts, Max: MaxDistinctPorts},
		AutoDisarmSeconds:       Range{Min: MinAutoDisarmSeconds, Max: MaxAutoDisarmSeconds},
		AutoDisarmDisabledValue: AutoDisarmDisabled,
	}
}

// Validate rejects every configuration that cannot be evaluated honestly. A
// rejected configuration is never partially applied; callers keep the previous
// verified policy.
func (c Config) Validate() error {
	if c.BurstWindowSeconds < MinBurstWindowSeconds || c.BurstWindowSeconds > MaxBurstWindowSeconds {
		return fmt.Errorf("kinetic config: burstWindowSeconds %d outside [%d,%d]", c.BurstWindowSeconds, MinBurstWindowSeconds, MaxBurstWindowSeconds)
	}
	if c.MinEvents < MinEvents || c.MinEvents > MaxEvents {
		return fmt.Errorf("kinetic config: minEvents %d outside [%d,%d]", c.MinEvents, MinEvents, MaxEvents)
	}
	if c.MinDistinctPorts < MinDistinctPorts || c.MinDistinctPorts > MaxDistinctPorts {
		return fmt.Errorf("kinetic config: minDistinctPorts %d outside [%d,%d]", c.MinDistinctPorts, MinDistinctPorts, MaxDistinctPorts)
	}
	if c.MinDistinctPorts > c.MinEvents {
		// A burst candidate requires at least MinDistinctPorts events, so a
		// smaller MinEvents can never be reached. Reject instead of silently
		// creating an observer that can never classify anything.
		return errors.New("kinetic config: minDistinctPorts must not exceed minEvents")
	}
	if c.AutoDisarmSeconds != AutoDisarmDisabled && (c.AutoDisarmSeconds < MinAutoDisarmSeconds || c.AutoDisarmSeconds > MaxAutoDisarmSeconds) {
		return fmt.Errorf("kinetic config: autoDisarmSeconds %d outside [%d,%d] or disabled value %d", c.AutoDisarmSeconds, MinAutoDisarmSeconds, MaxAutoDisarmSeconds, AutoDisarmDisabled)
	}
	return nil
}

// BurstWindow returns the validated aggregation window.
func (c Config) BurstWindow() time.Duration {
	return time.Duration(c.BurstWindowSeconds) * time.Second
}

// AutoDisarm returns the validated automatic disarm window. Zero means the
// operator deliberately disabled automatic disarming.
func (c Config) AutoDisarm() time.Duration {
	return time.Duration(c.AutoDisarmSeconds) * time.Second
}

// ArmingInputs are the live runtime facts that gate Kinetic arming. They are
// passed explicitly so the decision is testable and never inferred from an
// in-memory boolean alone.
type ArmingInputs struct {
	WFPRealtime               bool
	NetworkRealtime           bool
	EnforcementState          string
	DesiredGeneration         string
	ActiveGeneration          string
	FeedEnforcementGeneration string
	BlockingIndicators        int
}

// ArmingRequirements is the fail-closed evaluation of the existing verified
// Threat-IP/WFP generation requirements. It never enables enforcement; it only
// states whether an operator request (or a persisted re-arm intent) may be
// promoted to effective armed correlation.
type ArmingRequirements struct {
	WFPRealtime               bool     `json:"wfpRealtime"`
	NetworkRealtime           bool     `json:"networkRealtime"`
	EnforcementState          string   `json:"enforcementState"`
	DesiredGeneration         string   `json:"desiredGenerationSha256,omitempty"`
	ActiveGeneration          string   `json:"activeGenerationSha256,omitempty"`
	FeedEnforcementGeneration string   `json:"feedEnforcementGenerationSha256,omitempty"`
	BlockingIndicators        int      `json:"blockingIndicators"`
	EnforcementVerified       bool     `json:"enforcementVerified"`
	Ready                     bool     `json:"ready"`
	Blockers                  []string `json:"blockers"`
}

// EvaluateArmingRequirements applies the same checks the original
// SetKineticArmed implementation enforced inline. Persistent state is never
// trusted as proof: only live verified generation equality arms Kinetic.
func EvaluateArmingRequirements(input ArmingInputs) ArmingRequirements {
	result := ArmingRequirements{
		WFPRealtime:               input.WFPRealtime,
		NetworkRealtime:           input.NetworkRealtime,
		EnforcementState:          input.EnforcementState,
		DesiredGeneration:         input.DesiredGeneration,
		ActiveGeneration:          input.ActiveGeneration,
		FeedEnforcementGeneration: input.FeedEnforcementGeneration,
		BlockingIndicators:        input.BlockingIndicators,
		Blockers:                  make([]string, 0, 5),
	}
	stateVerified := input.EnforcementState == "VERIFIED" || input.EnforcementState == "VERIFIED_CLEANUP_PENDING"
	result.EnforcementVerified = stateVerified
	if !input.WFPRealtime {
		result.Blockers = append(result.Blockers, "WFP 5157 block telemetry unavailable")
	}
	if !input.NetworkRealtime {
		result.Blockers = append(result.Blockers, "native TCP owner/PID telemetry unavailable")
	}
	if !stateVerified {
		result.Blockers = append(result.Blockers, "Threat-IP WFP enforcement generation is not verified")
	}
	if input.ActiveGeneration == "" {
		result.Blockers = append(result.Blockers, "no active Threat-IP WFP generation hash")
	}
	if input.DesiredGeneration != "" && input.ActiveGeneration != "" && input.ActiveGeneration != input.DesiredGeneration {
		result.Blockers = append(result.Blockers, "active WFP generation does not match the desired generation")
	}
	if input.ActiveGeneration != "" && input.ActiveGeneration != input.FeedEnforcementGeneration {
		result.Blockers = append(result.Blockers, "active WFP generation does not match the current threat feed generation")
	}
	if input.BlockingIndicators <= 0 {
		result.Blockers = append(result.Blockers, "no blocking threat intelligence indicators available")
	}
	result.Ready = len(result.Blockers) == 0
	return result
}
