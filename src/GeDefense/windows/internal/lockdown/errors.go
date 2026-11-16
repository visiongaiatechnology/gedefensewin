// STATUS: PLATIN VGT SUPREME

package lockdown

import "errors"

// Sentinel errors. Callers must use errors.Is; none of these is widened by a
// wrapper that changes its meaning.
var (
	// ErrDisabled marks every entry point that is refused because the operator
	// has not enabled the lockdown namespace (the shipped default).
	ErrDisabled = errors.New("lockdown is disabled by settings")
	// ErrLatched marks an engage attempt while a latch is already held.
	ErrLatched = errors.New("lockdown is already engaged and requires an explicit clear")
	// ErrNotLatched marks a clear or reconcile without an engaged lockdown.
	ErrNotLatched = errors.New("no lockdown is engaged")
	// ErrEpochMismatch marks a clear whose expected epoch is not the epoch in
	// force. A mismatch never releases the latch.
	ErrEpochMismatch = errors.New("lockdown epoch mismatch")
	// ErrTriggerSuppressed marks an automatic trigger rejected by the
	// dedupe/cooldown/priority correlation.
	ErrTriggerSuppressed = errors.New("lockdown trigger suppressed by correlation")
	// ErrInvalidTrigger marks a trigger outside the closed kind/identity
	// vocabulary.
	ErrInvalidTrigger = errors.New("lockdown trigger is invalid")
	// ErrInvalidReason marks a clear reason outside its bound.
	ErrInvalidReason = errors.New("lockdown clear reason is invalid")
	// ErrReleaseIncomplete marks a clear whose release phases did not confirm.
	// The latch stays engaged so the clear can be retried.
	ErrReleaseIncomplete = errors.New("lockdown release is incomplete; the latch was kept")
	// ErrClosed marks use of an engine whose maintenance lifecycle was closed.
	ErrClosed = errors.New("lockdown engine is closed")
	// ErrAlreadyStarted marks a second Start of the maintenance lifecycle.
	ErrAlreadyStarted = errors.New("lockdown engine maintenance is already running")
	// ErrInvalidSettings marks an out-of-bounds setting. Values are rejected, not
	// clamped.
	ErrInvalidSettings = errors.New("lockdown settings are invalid")
	// ErrNilEngine marks a method call on a nil engine.
	ErrNilEngine = errors.New("lockdown engine is nil")
	// ErrMissingStateStore marks New without a state store.
	ErrMissingStateStore = errors.New("lockdown engine requires a state store")
	// ErrMissingClock marks New without an injected clock.
	ErrMissingClock = errors.New("lockdown engine requires an injected clock")
	// ErrPhaseSetMismatch marks an enabled engine whose injected phase set does
	// not exactly match the selected phases. A silently missing phase would
	// pretend protection that never ran.
	ErrPhaseSetMismatch = errors.New("lockdown phase set does not match the selected settings")
	// ErrInvalidPhase marks a phase with an unknown name, a duplicate name or a
	// timeout outside its bound.
	ErrInvalidPhase = errors.New("lockdown phase definition is invalid")
	// ErrPhaseUnsupported marks a verification of a phase that never claims
	// isolation.
	ErrPhaseUnsupported = errors.New("lockdown phase is unsupported")
	// ErrVerificationUnavailable marks a phase whose subsystem exposes no
	// documented read-back. The phase result stays honest: applied but
	// explicitly unverified.
	ErrVerificationUnavailable = errors.New("phase read-back verification is not available")
	// ErrNotImplemented marks an action that is not implemented in V6 phase 1.
	// It is returned instead of a fake success.
	ErrNotImplemented = errors.New("action is not implemented on Windows in this phase")
	// ErrProcessProtected marks a PID/name that the broker freezer must never
	// touch (PID<=4, lsass.exe, the engine's own process).
	ErrProcessProtected = errors.New("process is protected from lockdown freezing")
	// ErrProcessIdentityMismatch marks a PID whose creation time no longer
	// matches the recorded identity: the PID was reused and must not be
	// signalled.
	ErrProcessIdentityMismatch = errors.New("process identity mismatch (pid reused)")
	// ErrProcessControllerUnavailable marks the broker phase without an injected
	// process controller.
	ErrProcessControllerUnavailable = errors.New("process controller is unavailable")
	// ErrKeyInvalid marks a key provider that did not return exactly 32 bytes.
	ErrKeyInvalid = errors.New("lockdown key provider returned an invalid key")
	// ErrStateNotFound marks the documented first start without a state
	// document.
	ErrStateNotFound = errors.New("lockdown state document does not exist")
	// ErrStateCorrupt marks a state document that does not authenticate or does
	// not validate. The engine latches fail-closed.
	ErrStateCorrupt = errors.New("lockdown state document is corrupt")
	// ErrStateTooLarge marks a document (or its plaintext) beyond its bound.
	ErrStateTooLarge = errors.New("lockdown state document exceeds its bound")
	// ErrStatePathInvalid marks a relative or malformed state path.
	ErrStatePathInvalid = errors.New("lockdown state path is invalid")
)
