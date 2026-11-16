// STATUS: PLATIN VGT SUPREME

package lockdown

// Trigger correlation of the Emergency Lockdown engine.
//
// The five documented automatic sources (MHX critical, Titan BootTrust drift,
// canary alarm, witness equivocation, duress file) arrive as closed trigger
// kinds. EvaluateTrigger is pure: it takes the immutable policy, the previous
// correlation state, the candidate and the clock value and returns the decision
// plus the next state. It never touches the engine, so the whole guard matrix is
// testable without a latch.
//
// Guards, in order:
//  1. closed vocabulary and bounded identity (an invalid candidate is refused),
//  2. TriggerID dedupe inside the dedupe window,
//  3. cooldown inside the cooldown window, with priority escalation allowed: a
//     higher-priority source may shorten the cooldown, a lower one never
//     downgrades an ongoing response.
//
// Explicit operator intent (manual arm, an operator-flagged trigger or the
// duress token) bypasses the automatic guards. That is the same contract as the
// Linux API path.

import (
	"fmt"
	"time"
)

// TriggerKind is the closed vocabulary of trigger sources.
type TriggerKind string

const (
	// TriggerManual is explicit operator intent.
	TriggerManual TriggerKind = "manual"
	// TriggerMHXCritical is a critical MHX (RASP) incident.
	TriggerMHXCritical TriggerKind = "mhx-critical"
	// TriggerTitanBootTrustDrift is a boot-trust degradation to OBSERVE.
	TriggerTitanBootTrustDrift TriggerKind = "titan-boottrust-drift"
	// TriggerCanaryAlarm is an unauthorized canary access.
	TriggerCanaryAlarm TriggerKind = "canary-alarm"
	// TriggerWitnessEquivocation is an out-of-band witness ledger
	// equivocation/rollback report.
	TriggerWitnessEquivocation TriggerKind = "witness-equivocation"
	// TriggerDuressFile is an operator duress token.
	TriggerDuressFile TriggerKind = "duress-file"
)

// Valid reports whether kind is in the closed vocabulary.
func (k TriggerKind) Valid() bool {
	switch k {
	case TriggerManual, TriggerMHXCritical, TriggerTitanBootTrustDrift,
		TriggerCanaryAlarm, TriggerWitnessEquivocation, TriggerDuressFile:
		return true
	}
	return false
}

// Priority returns the documented escalation rank. A higher rank may shorten the
// automatic cooldown; a lower one never does.
func (k TriggerKind) Priority() int {
	switch k {
	case TriggerManual:
		return 100
	case TriggerDuressFile:
		return 90
	case TriggerMHXCritical:
		return 80
	case TriggerWitnessEquivocation:
		return 70
	case TriggerCanaryAlarm:
		return 60
	case TriggerTitanBootTrustDrift:
		return 50
	}
	return 0
}

// Trigger is one evaluated trigger candidate. It carries closed tokens and a
// bounded identity, never free text on the wire.
type Trigger struct {
	// ID is the bounded dedupe identity of the candidate.
	ID string `json:"id"`
	// Kind is the trigger source.
	Kind TriggerKind `json:"kind"`
	// Severity is the severity token reported by the source (for example
	// "critical"). It is bounded and never parsed as free text.
	Severity string `json:"severity,omitempty"`
	// Reason is a bounded operator-visible reason.
	Reason string `json:"reason,omitempty"`
	// DetectedAt is the source timestamp. The engine fills it when zero.
	DetectedAt time.Time `json:"detected_at,omitempty"`
	// Operator marks explicit operator intent.
	Operator bool `json:"operator,omitempty"`
}

// Validate rejects a trigger outside the closed vocabulary and the identity
// bounds.
func (t Trigger) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("%w: a trigger identity is required", ErrInvalidTrigger)
	}
	if len(t.ID) > MaxTriggerIDBytes {
		return fmt.Errorf("%w: the trigger identity exceeds %d bytes", ErrInvalidTrigger, MaxTriggerIDBytes)
	}
	for _, char := range t.ID {
		if char < 0x20 || char == 0x7f || char == ' ' {
			return fmt.Errorf("%w: the trigger identity contains a rejected character", ErrInvalidTrigger)
		}
	}
	if !t.Kind.Valid() {
		return fmt.Errorf("%w: the trigger kind %q is unknown", ErrInvalidTrigger, t.Kind)
	}
	if len(t.Severity) > 64 {
		return fmt.Errorf("%w: the severity exceeds its bound", ErrInvalidTrigger)
	}
	if len(t.Reason) > MaxReasonBytes {
		return fmt.Errorf("%w: the reason exceeds %d bytes", ErrInvalidTrigger, MaxReasonBytes)
	}
	for _, char := range t.Reason {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%w: the reason contains a control character", ErrInvalidTrigger)
		}
	}
	return nil
}

// explicit reports whether the trigger is explicit operator intent and therefore
// bypasses the automatic correlation guards.
func (t Trigger) explicit() bool {
	return t.Operator || t.Kind == TriggerManual || t.Kind == TriggerDuressFile
}

// CorrelationPolicy is the immutable dedupe/cooldown policy.
type CorrelationPolicy struct {
	Cooldown time.Duration
	Dedupe   time.Duration
}

// CorrelationState is the bounded state the engine carries between candidates.
type CorrelationState struct {
	AutomaticAt   time.Time
	AutomaticKind TriggerKind
	TriggerID     string
	TriggerIDAt   time.Time
	Guards        uint64
}

// CorrelationDecision is the closed decision vocabulary.
type CorrelationDecision string

const (
	// DecisionAccepted marks a candidate that may engage the latch.
	DecisionAccepted CorrelationDecision = "accepted"
	// DecisionDuplicate marks a candidate whose identity is already being
	// handled inside the dedupe window.
	DecisionDuplicate CorrelationDecision = "suppressed-duplicate"
	// DecisionCooldown marks an automatic candidate inside the cooldown window.
	DecisionCooldown CorrelationDecision = "suppressed-cooldown"
	// DecisionInvalid marks a candidate outside the closed vocabulary.
	DecisionInvalid CorrelationDecision = "invalid"
	// DecisionEscalated marks an accepted higher-priority candidate that
	// shortened the running cooldown.
	DecisionEscalated CorrelationDecision = "accepted-escalation"
)

// CorrelationOutcome is the decision plus the next correlation state and a
// bounded operator-visible detail.
type CorrelationOutcome struct {
	Accepted bool
	Decision CorrelationDecision
	Detail   string
	Priority int
	State    CorrelationState
}

// EvaluateTrigger applies the dedupe/cooldown/priority correlation. It is pure.
func EvaluateTrigger(policy CorrelationPolicy, state CorrelationState, trigger Trigger, now time.Time) CorrelationOutcome {
	outcome := CorrelationOutcome{State: state, Decision: DecisionInvalid, Priority: trigger.Kind.Priority()}
	if err := trigger.Validate(); err != nil {
		outcome.Detail = err.Error()
		return outcome
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if trigger.explicit() {
		outcome.Accepted = true
		outcome.Decision = DecisionAccepted
		outcome.Detail = "explicit operator intent; automatic correlation guards bypassed"
		outcome.State.TriggerID = trigger.ID
		outcome.State.TriggerIDAt = now
		return outcome
	}
	if policy.Dedupe > 0 && state.TriggerID == trigger.ID &&
		!state.TriggerIDAt.IsZero() && now.Sub(state.TriggerIDAt) < policy.Dedupe {
		outcome.State.Guards++
		outcome.Decision = DecisionDuplicate
		outcome.Detail = "the same trigger identity is already being handled inside the dedupe window"
		return outcome
	}
	if policy.Cooldown > 0 && !state.AutomaticAt.IsZero() && now.Sub(state.AutomaticAt) < policy.Cooldown {
		if trigger.Kind.Priority() > state.AutomaticKind.Priority() {
			outcome.Accepted = true
			outcome.Decision = DecisionEscalated
			outcome.Detail = "higher-priority trigger escalated and shortened the running cooldown"
		} else {
			outcome.State.Guards++
			outcome.Decision = DecisionCooldown
			outcome.Detail = "the automatic trigger cooldown is still active"
			return outcome
		}
	}
	if outcome.Decision == DecisionAccepted || outcome.Decision == DecisionEscalated {
		outcome.State.AutomaticAt = now
		outcome.State.AutomaticKind = trigger.Kind
		outcome.State.TriggerID = trigger.ID
		outcome.State.TriggerIDAt = now
		return outcome
	}
	outcome.Accepted = true
	outcome.Decision = DecisionAccepted
	outcome.Detail = "trigger accepted"
	outcome.State.AutomaticAt = now
	outcome.State.AutomaticKind = trigger.Kind
	outcome.State.TriggerID = trigger.ID
	outcome.State.TriggerIDAt = now
	return outcome
}
