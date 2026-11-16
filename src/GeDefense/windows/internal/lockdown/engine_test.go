// STATUS: PLATIN VGT SUPREME

package lockdown

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// engineHarness keeps one state document across engine restarts.
type engineHarness struct {
	t     *testing.T
	clock *fakeClock
	store *StateStore
	path  string
}

func newEngineHarness(t *testing.T) *engineHarness {
	t.Helper()
	clock := newFakeClock()
	store, path := newTestStore(t)
	return &engineHarness{t: t, clock: clock, store: store, path: path}
}

func (h *engineHarness) engine(settings Settings, phases ...Phase) *Engine {
	h.t.Helper()
	engine, err := New(settings, h.store, phases, h.clock)
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	return engine
}

func manualTrigger(id string) Trigger {
	return Trigger{ID: id, Kind: TriggerManual, Operator: true, Reason: "operator engage"}
}

func TestEngineDisabledIsInert(t *testing.T) {
	harness := newEngineHarness(t)
	engine := harness.engine(DefaultSettings())
	status := engine.Status()
	if status.Enabled || status.State != StateDisabled || status.Latched || status.Corrupt {
		t.Fatalf("unexpected disabled status: %+v", status)
	}
	if _, err := engine.Arm(context.Background(), manualTrigger("t-1")); !errors.Is(err, ErrDisabled) {
		t.Fatalf("a disabled engine engaged: %v", err)
	}
	if _, err := engine.Clear(context.Background(), testEpoch, "operator clear"); !errors.Is(err, ErrNotLatched) {
		t.Fatalf("a disabled engine cleared: %v", err)
	}
	if _, err := os.Stat(harness.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a disabled engine wrote a latch document")
	}
}

func TestEngineArmClearAndStatusRoundTrip(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB, PhaseBrokers))
	usb := appliedPhase(PhaseUSB)
	brokers := appliedPhase(PhaseBrokers)
	engine := harness.engine(settings, usb, brokers)

	status, err := engine.Arm(context.Background(), manualTrigger("trig-1"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !status.Latched || status.State != StateEngaged || status.Overall != PhaseApplied {
		t.Fatalf("the arm did not latch: %+v", status)
	}
	if !validEpoch(status.Epoch) {
		t.Fatalf("the epoch is invalid: %q", status.Epoch)
	}
	if status.Trigger.ID != "trig-1" || status.Trigger.Kind != TriggerManual {
		t.Fatalf("the trigger was not recorded: %+v", status.Trigger)
	}
	if len(status.Phases) != 2 {
		t.Fatalf("unexpected phase result count: %+v", status.Phases)
	}
	for _, result := range status.Phases {
		if result.Status != PhaseApplied || !result.Verified {
			t.Fatalf("a phase was not applied and verified: %+v", result)
		}
	}
	if _, err := os.Stat(harness.path); err != nil {
		t.Fatalf("the latch was not persisted: %v", err)
	}
	// The status snapshot is a copy: mutating it cannot change the engine.
	status.Phases[0].Detail = "mutated"
	if fresh := engine.Status(); fresh.Phases[0].Detail == "mutated" {
		t.Fatal("Status exposed the engine's internal slice")
	}
	// A second arm never re-runs the phases.
	if _, err := engine.Arm(context.Background(), manualTrigger("trig-2")); !errors.Is(err, ErrLatched) {
		t.Fatalf("a second arm was accepted: %v", err)
	}
	// Wrong epoch leaves the engine latched.
	if _, err := engine.Clear(context.Background(), "deadbeef", "operator clear"); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("a wrong expected epoch was accepted: %v", err)
	}
	if !engine.Status().Latched {
		t.Fatal("a wrong expected epoch released the latch")
	}
	cleared, err := engine.Clear(context.Background(), status.Epoch, "operator clear after review")
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cleared.Latched || cleared.State != StateClear || cleared.Epoch != "" {
		t.Fatalf("the clear did not release the latch: %+v", cleared)
	}
	if cleared.LastClear == nil || cleared.LastClear.Epoch != status.Epoch {
		t.Fatalf("the clear record is missing: %+v", cleared.LastClear)
	}
	if _, err := engine.Clear(context.Background(), status.Epoch, "operator clear again"); !errors.Is(err, ErrNotLatched) {
		t.Fatalf("a second clear was accepted: %v", err)
	}
	// The cleared state survives a restart and a disabled engine never latches.
	restarted := harness.engine(DefaultSettings())
	if status := restarted.Status(); status.Latched || status.State != StateDisabled {
		t.Fatalf("the cleared state did not survive the restart: %+v", status)
	}
}

func TestEngineRestartRecoversLatch(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	status, err := engine.Arm(context.Background(), manualTrigger("trig-restart"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	restarted := harness.engine(settings, appliedPhase(PhaseUSB))
	recovered := restarted.Status()
	if !recovered.Latched || recovered.State != StateEngaged {
		t.Fatalf("the restart released the latch: %+v", recovered)
	}
	if recovered.Epoch != status.Epoch {
		t.Fatalf("the epoch did not survive the restart: got %q want %q", recovered.Epoch, status.Epoch)
	}
	if recovered.Trigger.ID != "trig-restart" {
		t.Fatalf("the trigger identity did not survive the restart: %+v", recovered.Trigger)
	}
}

func TestEngineCorruptStateFailsClosedAndIsClearable(t *testing.T) {
	harness := newEngineHarness(t)
	if err := os.WriteFile(harness.path, []byte("tampered-not-a-seal"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	settings := testSettings(selectionOf(PhaseUSB))
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	status := engine.Status()
	if !status.Latched || status.State != StateEngaged {
		t.Fatalf("a corrupt document did not fail closed: %+v", status)
	}
	if !status.Corrupt || !validEpoch(status.Epoch) {
		t.Fatalf("the degraded recovery is not reported: %+v", status)
	}
	if !strings.Contains(status.Degraded, "could not be trusted") {
		t.Fatalf("the degraded reason is not named: %q", status.Degraded)
	}
	// The recovery is persisted: a second start stays latched with the same epoch.
	reopened := harness.engine(settings, appliedPhase(PhaseUSB))
	if again := reopened.Status(); again.Epoch != status.Epoch || !again.Latched {
		t.Fatalf("the recovered latch was not persisted: %+v", again)
	}
	cleared, err := reopened.Clear(context.Background(), status.Epoch, "operator clear after recovery")
	if err != nil {
		t.Fatalf("clear after recovery: %v", err)
	}
	if cleared.Latched || cleared.State != StateClear {
		t.Fatalf("the recovered latch was not clearable: %+v", cleared)
	}
}

func TestEngineCrashWindowNeedsVerification(t *testing.T) {
	harness := newEngineHarness(t)
	document := sampleLatchedDocument(harness.clock)
	document.Transition = transitionEngaging
	if err := harness.store.Save(document); err != nil {
		t.Fatalf("save crash document: %v", err)
	}
	settings := testSettings(selectionOf(PhaseUSB))
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	status := engine.Status()
	if !status.Latched || !status.NeedsVerification {
		t.Fatalf("the crash window was not recovered fail-closed: %+v", status)
	}
	if !strings.Contains(status.LastError, "interrupted engage") {
		t.Fatalf("the crash window is not named: %q", status.LastError)
	}
	reconciled, err := engine.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if reconciled.NeedsVerification || reconciled.VerifiedAt.IsZero() {
		t.Fatalf("the reconcile did not record the verification: %+v", reconciled)
	}
	if reconciled.Phases[0].Status != PhaseApplied || !reconciled.Phases[0].Verified {
		t.Fatalf("the reconcile did not verify the isolation: %+v", reconciled.Phases[0])
	}
}

func TestEnginePhaseErrorIsolation(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB, PhaseBrokers, PhaseSessions))
	usb := appliedPhase(PhaseUSB)
	brokers := failedPhase(PhaseBrokers)
	sessions := appliedPhase(PhaseSessions)
	engine := harness.engine(settings, usb, brokers, sessions)
	status, err := engine.Arm(context.Background(), manualTrigger("trig-isolation"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if status.Overall != PhasePartial || status.State != StateEngaged {
		t.Fatalf("unexpected aggregate status: %+v", status)
	}
	if len(status.Phases) != 3 {
		t.Fatalf("a failed phase prevented the remaining phases: %+v", status.Phases)
	}
	if engages, _, _ := sessions.counts(); engages != 1 {
		t.Fatalf("the phase after the failure did not run: %d", engages)
	}
	if status.Phases[1].Status != PhaseFailed {
		t.Fatalf("the failing phase was not reported: %+v", status.Phases[1])
	}
	if status.Phases[2].Status != PhaseApplied {
		t.Fatalf("the phase after the failure was not applied: %+v", status.Phases[2])
	}
}

func TestEngineVerificationDowngradesToFailed(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	usb := appliedPhase(PhaseUSB)
	usb.setVerify(func(context.Context) error { return errors.New("device still enabled") })
	engine := harness.engine(settings, usb)
	status, err := engine.Arm(context.Background(), manualTrigger("trig-verify"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if status.Overall != PhaseFailed || status.State != StateFailed {
		t.Fatalf("a failed read-back was reported as locked: %+v", status)
	}
	if status.Phases[0].Status != PhaseFailed || status.Phases[0].Verified {
		t.Fatalf("the read-back failure was not downgraded: %+v", status.Phases[0])
	}
	if !status.Latched {
		t.Fatal("a failed isolation must stay latched fail-closed")
	}
}

func TestEngineUnsupportedOnlyIsFailedNotLocked(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseParsers))
	engine := harness.engine(settings, NewUnsupportedPhase(PhaseParsers, "not applicable"))
	status, err := engine.Arm(context.Background(), manualTrigger("trig-unsupported"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if status.State != StateFailed || status.Overall != PhaseFailed || !status.Latched {
		t.Fatalf("the engine pretended a protection that never ran: %+v", status)
	}
	if status.Phases[0].Status != PhaseUnsupported {
		t.Fatalf("the unsupported phase was not reported verbatim: %+v", status.Phases[0])
	}
}

func TestEngineReleaseFailureKeepsLatchAndIsRetryable(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseBrokers))
	brokers := appliedPhase(PhaseBrokers)
	brokers.setRelease(func(context.Context) PhaseResult {
		return PhaseResult{Phase: PhaseBrokers, Status: PhaseFailed, Detail: "resume refused"}
	})
	engine := harness.engine(settings, brokers)
	status, err := engine.Arm(context.Background(), manualTrigger("trig-release"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, err := engine.Clear(context.Background(), status.Epoch, "operator clear"); !errors.Is(err, ErrReleaseIncomplete) {
		t.Fatalf("an incomplete release was accepted: %v", err)
	}
	kept := engine.Status()
	if !kept.Latched || kept.State != StateEngaged {
		t.Fatalf("an incomplete release released the latch: %+v", kept)
	}
	brokers.setRelease(nil)
	retried, err := engine.Clear(context.Background(), status.Epoch, "operator clear retry")
	if err != nil {
		t.Fatalf("retried clear: %v", err)
	}
	if retried.Latched || retried.State != StateClear {
		t.Fatalf("the retried clear did not release the latch: %+v", retried)
	}
}

func TestEngineTriggerCorrelation(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	first := Trigger{ID: "mhx-1", Kind: TriggerMHXCritical, Reason: "critical RASP"}
	status, err := engine.Arm(context.Background(), first)
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, err := engine.Clear(context.Background(), status.Epoch, "operator clear"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	// Same identity inside the dedupe window.
	if _, err := engine.Arm(context.Background(), first); !errors.Is(err, ErrTriggerSuppressed) {
		t.Fatalf("a duplicate trigger was accepted: %v", err)
	}
	if engine.Status().FalsePositiveGuards == 0 {
		t.Fatal("the suppressed candidate was not counted")
	}
	// A different identity is still inside the cooldown.
	if _, err := engine.Arm(context.Background(), Trigger{ID: "mhx-2", Kind: TriggerMHXCritical}); !errors.Is(err, ErrTriggerSuppressed) {
		t.Fatalf("the cooldown was not enforced: %v", err)
	}
	// After the windows a new automatic candidate is accepted.
	harness.clock.Advance(DefaultCooldown + DefaultDedupe + time.Second)
	status, err = engine.Arm(context.Background(), Trigger{ID: "mhx-3", Kind: TriggerMHXCritical})
	if err != nil {
		t.Fatalf("the trigger after the windows was refused: %v", err)
	}
	if !status.Latched {
		t.Fatal("the trigger after the windows did not latch")
	}
}

func TestEngineClearWithoutExplicitEpochSetting(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	settings.ClearRequiresExplicitEpoch = false
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	status, err := engine.Arm(context.Background(), manualTrigger("trig-no-epoch"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !strings.Contains(status.Degraded, "explicit epoch comparison is disabled") {
		t.Fatalf("the weakened clear gate is not reported: %q", status.Degraded)
	}
	cleared, err := engine.Clear(context.Background(), "", "operator clear without epoch")
	if err != nil {
		t.Fatalf("clear without epoch: %v", err)
	}
	if cleared.Latched || cleared.State != StateClear {
		t.Fatalf("the clear without epoch did not release the latch: %+v", cleared)
	}
}

func TestEngineReconcileDowngradesWhenReadbackFails(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	usb := appliedPhase(PhaseUSB)
	engine := harness.engine(settings, usb)
	if _, err := engine.Arm(context.Background(), manualTrigger("trig-reconcile")); err != nil {
		t.Fatalf("arm: %v", err)
	}
	usb.setVerify(func(context.Context) error { return errors.New("device re-enabled by the operator") })
	status, err := engine.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status.State != StateFailed || status.Overall != PhaseFailed {
		t.Fatalf("a failed re-verification was not downgraded: %+v", status)
	}
	if !strings.Contains(status.Degraded, "re-verification") {
		t.Fatalf("the re-verification failure is not named: %q", status.Degraded)
	}
}

func TestEngineMaintenanceLifecycleJoins(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := engine.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("a second start was accepted: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = engine.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join the maintenance goroutine")
	}
	if !engine.Status().Closed {
		t.Fatal("the closed lifecycle is not reported")
	}
	if err := engine.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed engine restarted: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if _, err := engine.Reconcile(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed engine reconciled: %v", err)
	}
}

func TestEngineReportsEngagingDuringTransition(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	started := make(chan struct{})
	release := make(chan struct{})
	usb := &scriptedPhase{
		name: PhaseUSB, timeout: 5 * time.Second,
		engageFn: func(context.Context) PhaseResult {
			close(started)
			<-release
			return PhaseResult{Phase: PhaseUSB, Status: PhaseApplied, Detail: "applied"}
		},
	}
	engine := harness.engine(settings, usb)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if _, err := engine.Arm(context.Background(), manualTrigger("trig-engaging")); err != nil {
			t.Errorf("arm: %v", err)
		}
	}()
	<-started
	during := engine.Status()
	if during.State != StateEngaging || !during.Latched {
		t.Fatalf("the running engage is not reported as ENGAGING: %+v", during)
	}
	close(release)
	<-finished
	after := engine.Status()
	if after.State != StateEngaged || after.Overall != PhaseApplied {
		t.Fatalf("the settled engage is not reported as ENGAGED: %+v", after)
	}
}

func TestEngineNewValidation(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	if _, err := New(settings, nil, nil, harness.clock); !errors.Is(err, ErrMissingStateStore) {
		t.Fatalf("a missing state store was accepted: %v", err)
	}
	if _, err := New(settings, harness.store, nil, nil); !errors.Is(err, ErrMissingClock) {
		t.Fatalf("a missing clock was accepted: %v", err)
	}
	if _, err := New(settings, harness.store, []Phase{appliedPhase(PhaseBrokers)}, harness.clock); !errors.Is(err, ErrPhaseSetMismatch) {
		t.Fatalf("a mismatched phase set was accepted: %v", err)
	}
	if _, err := New(settings, harness.store, nil, harness.clock); !errors.Is(err, ErrPhaseSetMismatch) {
		t.Fatalf("a missing selected phase was accepted: %v", err)
	}
	duplicate := appliedPhase(PhaseUSB)
	if _, err := New(settings, harness.store, []Phase{duplicate, duplicate}, harness.clock); !errors.Is(err, ErrPhaseSetMismatch) && !errors.Is(err, ErrInvalidPhase) {
		t.Fatalf("a duplicate phase was accepted: %v", err)
	}
	badTimeout := appliedPhase(PhaseUSB)
	badTimeout.timeout = 0
	if _, err := New(settings, harness.store, []Phase{badTimeout}, harness.clock); !errors.Is(err, ErrInvalidPhase) {
		t.Fatalf("a zero phase timeout was accepted: %v", err)
	}
	invalidSettings := settings
	invalidSettings.Cooldown = -time.Second
	if _, err := New(invalidSettings, harness.store, []Phase{appliedPhase(PhaseUSB)}, harness.clock); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("invalid settings were accepted: %v", err)
	}
}

func TestEngineArmWithCancelledContext(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(selectionOf(PhaseUSB))
	engine := harness.engine(settings, appliedPhase(PhaseUSB))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Arm(ctx, manualTrigger("trig-cancelled")); err == nil {
		t.Fatal("an engage with a cancelled context was accepted")
	}
	if engine.Status().Latched {
		t.Fatal("a cancelled engage latched the engine")
	}
}

func TestEngineStandardPhasesFactoryIsHonest(t *testing.T) {
	harness := newEngineHarness(t)
	settings := testSettings(DefaultPhaseSelection())
	phases := NewStandardPhases(Dependencies{Clock: harness.clock}, settings)
	if len(phases) != len(settings.selectedPhases()) {
		t.Fatalf("the factory did not honour the selection: %d", len(phases))
	}
	engine := harness.engine(settings, phases...)
	status, err := engine.Arm(context.Background(), manualTrigger("trig-standard"))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	// No production adapter is wired: every action must be honestly unavailable or
	// unsupported and the engine must not claim an isolation.
	if status.Overall != PhaseFailed || status.State != StateFailed {
		t.Fatalf("an unwired standard engine pretended an isolation: %+v", status)
	}
	for _, result := range status.Phases {
		if result.Status == PhaseApplied || result.Status == PhasePartial {
			t.Fatalf("a phase faked an isolation: %+v", result)
		}
	}
	if !status.Latched {
		t.Fatal("even a failed isolation must stay latched fail-closed")
	}
}
