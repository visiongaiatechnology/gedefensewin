// STATUS: PLATIN VGT SUPREME

package lockdown

// Phase abstraction of the Emergency Lockdown.
//
// Every phase reports the acknowledgement of its dedicated Windows subsystem; it
// never reports an assumption. Engage and Release are error-isolating: the
// orchestration runs every selected phase even when one of them fails, and the
// aggregate status is PARTIAL or FAILED instead of a fake "locked".
//
// Read-back is mandatory for a claimed isolation: after a phase reports
// PhaseApplied or PhasePartial the engine calls its Verify method. A failed
// read-back downgrades the result to PhaseFailed; a subsystem without a
// documented read-back must return ErrVerificationUnavailable, which keeps the
// status honest but explicitly unverified.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PhaseAction marks whether a result describes the engage or the release side.
type PhaseAction string

const (
	// ActionEngage marks an engage result.
	ActionEngage PhaseAction = "engage"
	// ActionRelease marks a release result.
	ActionRelease PhaseAction = "release"
)

// PhaseStatus is the closed per-phase outcome vocabulary.
type PhaseStatus string

const (
	// PhaseApplied means the subsystem acknowledged and the read-back confirmed
	// the isolation.
	PhaseApplied PhaseStatus = "applied"
	// PhasePartial means the phase isolated a subset of its targets or could not
	// confirm a subset.
	PhasePartial PhaseStatus = "partial"
	// PhaseUnavailable means the subsystem exists but could not be reached or
	// answered with an error. It is not a success.
	PhaseUnavailable PhaseStatus = "unavailable"
	// PhaseUnsupported means the phase does not apply on this host or is
	// disabled by settings. It is not a success.
	PhaseUnsupported PhaseStatus = "unsupported"
	// PhaseFailed means the phase tried and failed.
	PhaseFailed PhaseStatus = "failed"
	// StatusNone is the computed aggregate of an empty result list.
	StatusNone PhaseStatus = "none"
)

// Valid reports whether s is a per-phase outcome.
func (s PhaseStatus) Valid() bool {
	switch s {
	case PhaseApplied, PhasePartial, PhaseUnavailable, PhaseUnsupported, PhaseFailed:
		return true
	}
	return false
}

// protects reports whether the outcome is an isolation claim.
func (s PhaseStatus) protects() bool {
	return s == PhaseApplied || s == PhasePartial
}

// PhaseResult is one bounded, operator-visible phase outcome.
type PhaseResult struct {
	Action    PhaseAction   `json:"action,omitempty"`
	Phase     PhaseName     `json:"phase"`
	Status    PhaseStatus   `json:"status"`
	Detail    string        `json:"detail,omitempty"`
	Targets   int           `json:"targets,omitempty"`
	StartedAt time.Time     `json:"started_at,omitempty"`
	Duration  time.Duration `json:"duration_ns,omitempty"`
	Verified  bool          `json:"verified,omitempty"`
	// Err carries the machine-readable error of the result. It is never
	// persisted; the bounded Detail is.
	Err error `json:"-"`
}

// Phase is one lockdown phase. Implementations must honour the context deadline
// of the engine (the engine runs them synchronously with a per-phase timeout) and
// must never panic.
type Phase interface {
	// Name returns the closed phase name.
	Name() PhaseName
	// Timeout returns the per-phase timeout. It must be in (0, MaxPhaseTimeout].
	Timeout() time.Duration
	// Engage applies the isolation and reports what the subsystem acknowledged.
	Engage(ctx context.Context) PhaseResult
	// Release reverses the isolation.
	Release(ctx context.Context) PhaseResult
	// Verify reads the isolation back. A subsystem without a documented read-back
	// returns ErrVerificationUnavailable.
	Verify(ctx context.Context) error
}

// effectiveTimeout bounds one phase timeout defensively.
func effectiveTimeout(phase Phase) time.Duration {
	timeout := phase.Timeout()
	if timeout <= 0 {
		return DefaultPhaseTimeout
	}
	if timeout > MaxPhaseTimeout {
		return MaxPhaseTimeout
	}
	return timeout
}

// runEngage executes one phase with its timeout and the mandatory read-back.
func runEngage(ctx context.Context, phase Phase, clock Clock) PhaseResult {
	if ctx == nil {
		ctx = context.Background()
	}
	started := clock.Now()
	phaseContext, cancel := context.WithTimeout(ctx, effectiveTimeout(phase))
	defer cancel()
	result := safeEngage(phaseContext, phase)
	result = normalizePhaseResult(result, phase.Name(), ActionEngage)
	result.StartedAt = started
	result.Duration = clock.Now().Sub(started)
	if result.Status.protects() {
		if err := safeVerify(phaseContext, phase); err != nil {
			if errors.Is(err, ErrVerificationUnavailable) {
				result.Verified = false
				result.Detail = appendDetail(result.Detail, "read-back not available: "+err.Error())
				return result
			}
			result.Status = PhaseFailed
			result.Verified = false
			result.Detail = truncateText("read-back verification failed: "+err.Error(), MaxDetailBytes)
		} else {
			result.Verified = true
		}
	}
	return result
}

// runRelease executes one phase release with its timeout.
func runRelease(ctx context.Context, phase Phase, clock Clock) PhaseResult {
	if ctx == nil {
		ctx = context.Background()
	}
	started := clock.Now()
	phaseContext, cancel := context.WithTimeout(ctx, effectiveTimeout(phase))
	defer cancel()
	result := safeRelease(phaseContext, phase)
	result = normalizePhaseResult(result, phase.Name(), ActionRelease)
	result.StartedAt = started
	result.Duration = clock.Now().Sub(started)
	return result
}

// safeEngage isolates a misbehaving phase implementation.
func safeEngage(ctx context.Context, phase Phase) (result PhaseResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = PhaseResult{
				Phase: phase.Name(), Status: PhaseFailed,
				Detail: truncateText(fmt.Sprintf("phase panicked: %v", recovered), MaxDetailBytes),
			}
		}
	}()
	return phase.Engage(ctx)
}

// safeRelease isolates a misbehaving phase implementation.
func safeRelease(ctx context.Context, phase Phase) (result PhaseResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = PhaseResult{
				Phase: phase.Name(), Status: PhaseFailed,
				Detail: truncateText(fmt.Sprintf("phase panicked: %v", recovered), MaxDetailBytes),
			}
		}
	}()
	return phase.Release(ctx)
}

// safeVerify isolates a misbehaving verification implementation.
func safeVerify(ctx context.Context, phase Phase) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("phase verification panicked: %v", recovered)
		}
	}()
	return phase.Verify(ctx)
}

// normalizePhaseResult fills the closed name/action and downgrades anything
// outside the vocabulary instead of trusting it.
func normalizePhaseResult(result PhaseResult, name PhaseName, action PhaseAction) PhaseResult {
	result.Phase = name
	result.Action = action
	result.Err = nil
	if result.Targets < 0 {
		result.Targets = 0
	}
	if !result.Status.Valid() {
		status := result.Status
		// The invalid-outcome marker takes precedence over the phase detail: an
		// untrusted status must never be visible as a bounded detail only.
		result.Status = PhaseFailed
		result.Detail = truncateText(fmt.Sprintf("phase returned an invalid outcome %q; %s", status, result.Detail), MaxDetailBytes)
		return result
	}
	result.Detail = truncateText(result.Detail, MaxDetailBytes)
	if result.Status == PhaseUnavailable && result.Detail == "" {
		result.Detail = "phase subsystem is unavailable"
	}
	return result
}

// validatePhaseResult rejects an invalid persisted phase result.
func validatePhaseResult(result PhaseResult) error {
	if !phaseNameValid(result.Phase) {
		return fmt.Errorf("%w: unknown phase name %q", ErrInvalidPhase, result.Phase)
	}
	if result.Action != ActionEngage && result.Action != ActionRelease {
		return fmt.Errorf("%w: unknown action %q", ErrInvalidPhase, result.Action)
	}
	if !result.Status.Valid() {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidPhase, result.Status)
	}
	if len(result.Detail) > MaxDetailBytes*2 {
		return fmt.Errorf("%w: the detail exceeds its bound", ErrInvalidPhase)
	}
	if result.Targets < 0 || result.Targets > MaxPhaseTargets {
		return fmt.Errorf("%w: the target count is outside its bound", ErrInvalidPhase)
	}
	if result.Duration < 0 || result.Duration > 2*MaxPhaseTimeout {
		return fmt.Errorf("%w: the duration is outside its bound", ErrInvalidPhase)
	}
	return nil
}

// Aggregate computes the overall status of one phase run. A run without any
// applied or partial isolation is FAILED, never "locked": unsupported and
// unavailable phases do not protect anything.
func Aggregate(results []PhaseResult) (PhaseStatus, string) {
	var applied, partial, unavailable, unsupported, failed int
	for _, result := range results {
		switch result.Status {
		case PhaseApplied:
			applied++
		case PhasePartial:
			partial++
		case PhaseUnavailable:
			unavailable++
		case PhaseUnsupported:
			unsupported++
		case PhaseFailed:
			failed++
		}
	}
	var overall PhaseStatus
	switch {
	case applied > 0 && partial == 0 && failed == 0 && unavailable == 0:
		overall = PhaseApplied
	case applied+partial > 0:
		overall = PhasePartial
	default:
		overall = PhaseFailed
	}
	summary := fmt.Sprintf("applied=%d partial=%d unavailable=%d unsupported=%d failed=%d",
		applied, partial, unavailable, unsupported, failed)
	return overall, summary
}

// phaseSummary returns a deterministic, bounded one-line outcome.
func phaseSummary(results []PhaseResult) string {
	_, summary := Aggregate(results)
	parts := make([]string, 0, len(results))
	for _, name := range phaseSequence {
		for _, result := range results {
			if result.Phase != name {
				continue
			}
			if result.Status == PhaseUnsupported || result.Status == PhaseUnavailable {
				parts = append(parts, string(name)+"="+string(result.Status))
			}
			break
		}
	}
	if len(parts) == 0 {
		return summary
	}
	return truncateText(summary+" ("+joinStrings(parts, ", ")+")", MaxDetailBytes*3)
}

// joinStrings is a small allocation-bounded join for the summary.
func joinStrings(values []string, separator string) string {
	total := 0
	for _, value := range values {
		total += len(value) + len(separator)
	}
	builder := make([]byte, 0, total)
	for index, value := range values {
		if index > 0 {
			builder = append(builder, separator...)
		}
		builder = append(builder, value...)
	}
	return string(builder)
}

// unsupportedPhase is the honest phase implementation for actions that are not
// implemented or not applicable on Windows in V6 phase 1. It never fakes success.
type unsupportedPhase struct {
	name    PhaseName
	detail  string
	timeout time.Duration
}

// NewUnsupportedPhase returns a phase that reports PhaseUnsupported with the
// documented reason and has nothing to release.
func NewUnsupportedPhase(name PhaseName, reason string) Phase {
	detail := "NOT_IMPLEMENTED: " + strings.TrimSpace(reason)
	return &unsupportedPhase{name: name, detail: truncateText(detail, MaxDetailBytes), timeout: DefaultPhaseTimeout}
}

func (p *unsupportedPhase) Name() PhaseName        { return p.name }
func (p *unsupportedPhase) Timeout() time.Duration { return p.timeout }
func (p *unsupportedPhase) Engage(context.Context) PhaseResult {
	return PhaseResult{Phase: p.name, Status: PhaseUnsupported, Detail: p.detail}
}
func (p *unsupportedPhase) Release(context.Context) PhaseResult {
	return PhaseResult{Phase: p.name, Status: PhaseApplied, Detail: "nothing to release"}
}
func (p *unsupportedPhase) Verify(context.Context) error {
	return fmt.Errorf("%w: %s", ErrPhaseUnsupported, p.name)
}
