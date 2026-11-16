// STATUS: PLATIN VGT SUPREME

package lockdown

// Clear and Reconcile.
//
// Clear is the only way out of a latch. It requires the compare-set epoch the
// caller observed: a mismatch leaves the engine latched (the Linux §7/§9
// contract). The release runs every selected phase in reverse engage order; a
// release that does not confirm keeps the latch so the operator can retry
// without leaving a suspended broker process behind (documented Windows
// deviation from the Linux engine, which releases the latch and only reports the
// failure).
//
// Reconcile re-verifies an engaged isolation and is also the body of the
// maintenance tick.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Clear releases the latch with expected_epoch compare-set semantics.
func (e *Engine) Clear(ctx context.Context, expectedEpoch, reason string) (Status, error) {
	if e == nil {
		return Status{}, ErrNilEngine
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateReason(reason); err != nil {
		return e.Status(), err
	}
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	e.stateMu.RLock()
	latched := e.doc.Latched
	currentEpoch := e.doc.Epoch
	e.stateMu.RUnlock()
	if !latched {
		return e.Status(), ErrNotLatched
	}
	if err := e.checkEpoch(expectedEpoch, currentEpoch); err != nil {
		return e.Status(), err
	}
	if err := ctx.Err(); err != nil {
		return e.Status(), fmt.Errorf("lockdown clear aborted: %w", err)
	}
	now := e.clock.Now()
	e.stateMu.Lock()
	e.doc.Transition = transitionClearing
	e.doc.UpdatedAt = now
	_ = e.saveUnlocked()
	e.stateMu.Unlock()

	releaseResults := make([]PhaseResult, 0, len(e.order))
	for index := len(e.order) - 1; index >= 0; index-- {
		name := e.order[index]
		phase, present := e.phases[name]
		if !present {
			releaseResults = append(releaseResults, PhaseResult{
				Action: ActionRelease, Phase: name, Status: PhaseFailed,
				Detail: "phase implementation is missing",
			})
			continue
		}
		releaseResults = append(releaseResults, runRelease(ctx, phase, e.clock))
	}
	releaseOverall, summary := Aggregate(releaseResults)
	if releaseOverall == PhaseFailed {
		e.stateMu.Lock()
		e.doc.Transition = ""
		e.doc.Phases = releaseResults
		e.doc.Action = ActionRelease
		e.doc.NeedsVerification = true
		e.doc.LastError = truncateText("clear incomplete: "+summary, MaxDetailBytes*2)
		e.doc.Degraded = truncateText("the release did not confirm; the latch was kept so the clear can be retried", MaxDetailBytes*2)
		if e.doc.State != StateFailed {
			e.doc.State = StateEngaged
		}
		_ = e.saveUnlocked()
		status := e.statusLocked()
		e.stateMu.Unlock()
		return status, fmt.Errorf("%w: %s", ErrReleaseIncomplete, summary)
	}
	degraded := ""
	if releaseOverall == PhasePartial {
		degraded = truncateText("clear completed with an incomplete release: "+summary, MaxDetailBytes*2)
	}
	e.stateMu.Lock()
	e.doc.Latched = false
	e.doc.State = StateClear
	e.doc.Epoch = ""
	e.doc.Trigger = Trigger{}
	// The released phase results are not a protection claim and are not kept on
	// the document; the bounded LastClear/Degraded fields carry the outcome.
	e.doc.Phases = nil
	e.doc.Action = ""
	e.doc.Transition = ""
	e.doc.NeedsVerification = false
	e.doc.VerifiedAt = time.Time{}
	e.doc.EngagedAt = time.Time{}
	e.doc.ClearedAt = now
	e.doc.LastClear = &ClearRecord{At: now, Reason: truncateText(reason, MaxReasonBytes), Epoch: currentEpoch}
	e.doc.Degraded = degraded
	e.doc.LastError = ""
	_ = e.saveUnlocked()
	status := e.statusLocked()
	e.stateMu.Unlock()
	return status, nil
}

// checkEpoch applies the compare-set gate. With ClearRequiresExplicitEpoch the
// caller must name the exact epoch; without it an empty epoch is accepted as
// "the current one" (documented weakening, reported as degraded by Status).
func (e *Engine) checkEpoch(expected, current string) error {
	if e.settings.ClearRequiresExplicitEpoch {
		if !validEpoch(expected) || !epochEqual(expected, current) {
			return ErrEpochMismatch
		}
		return nil
	}
	if expected == "" {
		return nil
	}
	if !validEpoch(expected) || !epochEqual(expected, current) {
		return ErrEpochMismatch
	}
	return nil
}

// Reconcile re-verifies the engaged phases (read-back) and updates the status.
func (e *Engine) Reconcile(ctx context.Context) (Status, error) {
	if e == nil {
		return Status{}, ErrNilEngine
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e.closed.Load() {
		return e.Status(), ErrClosed
	}
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	return e.reconcileLocked(ctx)
}

// reconcileLocked is the body of Reconcile and of the maintenance tick. The
// caller holds opsMu.
func (e *Engine) reconcileLocked(ctx context.Context) (Status, error) {
	e.stateMu.RLock()
	latched := e.doc.Latched
	results := append([]PhaseResult(nil), e.doc.Phases...)
	e.stateMu.RUnlock()
	if !latched {
		return e.Status(), ErrNotLatched
	}
	if err := ctx.Err(); err != nil {
		return e.Status(), fmt.Errorf("lockdown reconcile aborted: %w", err)
	}
	changed := false
	for index := range results {
		result := results[index]
		if result.Action != ActionEngage || !result.Status.protects() {
			continue
		}
		phase, present := e.phases[result.Phase]
		if !present {
			result.Status = PhaseFailed
			result.Verified = false
			result.Detail = "phase implementation is missing during re-verification"
			results[index] = result
			changed = true
			continue
		}
		verifyContext, cancel := context.WithTimeout(ctx, effectiveTimeout(phase))
		err := safeVerify(verifyContext, phase)
		cancel()
		switch {
		case err == nil:
			if !result.Verified {
				result.Verified = true
				changed = true
			}
		case errors.Is(err, ErrVerificationUnavailable):
			// Honest but not a failure: the subsystem has no read-back.
			if result.Verified {
				result.Verified = false
				changed = true
			}
		default:
			result.Status = PhaseFailed
			result.Verified = false
			result.Detail = truncateText("re-verification failed: "+err.Error(), MaxDetailBytes)
			results[index] = result
			changed = true
			continue
		}
		results[index] = result
	}
	e.stateMu.Lock()
	e.doc.NeedsVerification = false
	e.doc.VerifiedAt = e.clock.Now()
	if changed {
		e.doc.Phases = results
		overall, summary := Aggregate(results)
		switch overall {
		case PhaseApplied:
			e.doc.State = StateEngaged
			e.doc.Degraded = ""
			e.doc.LastError = ""
		case PhasePartial:
			e.doc.State = StateEngaged
			e.doc.Degraded = truncateText("re-verification degraded the isolation: "+summary, MaxDetailBytes*2)
		default:
			e.doc.State = StateFailed
			e.doc.Degraded = truncateText("re-verification could not confirm any isolation: "+summary, MaxDetailBytes*2)
			e.doc.LastError = "re-verification could not confirm any isolation"
		}
	}
	_ = e.saveUnlocked()
	status := e.statusLocked()
	e.stateMu.Unlock()
	return status, nil
}
