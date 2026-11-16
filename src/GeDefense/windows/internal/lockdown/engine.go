// STATUS: PLATIN VGT SUPREME

package lockdown

// Engine lifecycle of the Emergency Lockdown.
//
// New loads the persisted latch and is already fail-closed when the document
// cannot be trusted. Arm latches the engine, runs the ordered phase set and
// persists the result; Clear releases the latch with the compare-set epoch; the
// optional maintenance goroutine re-verifies an engaged isolation and is joined
// by Close. There is no global mutable state: every engine owns its document,
// its correlation state and its lifecycle.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MaintenanceInterval is the re-verification cadence of an engaged engine.
const MaintenanceInterval = 10 * time.Second

// Clock is the injected time source. The engine never reads the wall clock
// directly, so every transition and timeout is testable.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production clock.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// nowFrom returns the injected clock value, or the system clock when the phase
// was constructed without one.
func nowFrom(clock Clock) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock.Now()
}

// Engine owns the latch, the correlation state and the phase orchestration.
type Engine struct {
	settings Settings
	store    *StateStore
	phases   map[PhaseName]Phase
	order    []PhaseName
	clock    Clock

	// opsMu serialises every latch transition and the reconcile pass.
	opsMu sync.Mutex
	// stateMu guards doc, correlation, corrupt and persistErr.
	stateMu     sync.RWMutex
	doc         stateDocument
	correlation CorrelationState
	corrupt     bool
	persistErr  string
	closed      atomic.Bool

	startMu sync.Mutex
	started bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// New validates the settings and the phase set, loads the persisted latch and
// returns the engine. A corrupt or untrusted document does not fail the
// constructor: it latches the engine fail-closed and reports the degraded
// recovery in Status.
func New(settings Settings, store *StateStore, phases []Phase, clock Clock) (*Engine, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrMissingStateStore
	}
	if clock == nil {
		return nil, ErrMissingClock
	}
	phaseMap, order, err := validatePhaseSet(settings, phases)
	if err != nil {
		return nil, err
	}
	engine := &Engine{
		settings: settings.Clone(), store: store, phases: phaseMap,
		order: order, clock: clock,
	}
	document, loadErr := store.Load()
	switch {
	case errors.Is(loadErr, ErrStateNotFound):
		// The documented first start: disarmed and inert.
		engine.doc = freshDocument(clock)
	case loadErr != nil:
		engine.failClosed("state document could not be trusted: " + loadErr.Error())
	default:
		recovered, changed := recoverStateDocument(document)
		engine.doc = recovered
		if changed {
			if saveErr := engine.saveUnlocked(); saveErr != nil {
				engine.persistErr = truncateText(saveErr.Error(), MaxDetailBytes)
			}
		}
	}
	return engine, nil
}

// Settings returns a copy of the engine configuration.
func (e *Engine) Settings() Settings {
	if e == nil {
		return Settings{}
	}
	return e.settings.Clone()
}

// validatePhaseSet checks names, bounds, duplicates and the exact match with the
// selected settings. An enabled engine with a missing phase never starts: a
// silently absent phase would pretend protection that never ran.
func validatePhaseSet(settings Settings, phases []Phase) (map[PhaseName]Phase, []PhaseName, error) {
	phaseMap := make(map[PhaseName]Phase, len(phases))
	for _, phase := range phases {
		if phase == nil {
			return nil, nil, fmt.Errorf("%w: a nil phase was provided", ErrInvalidPhase)
		}
		name := phase.Name()
		if !phaseNameValid(name) {
			return nil, nil, fmt.Errorf("%w: unknown phase name %q", ErrInvalidPhase, name)
		}
		if _, duplicate := phaseMap[name]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate phase %q", ErrInvalidPhase, name)
		}
		timeout := phase.Timeout()
		if timeout <= 0 || timeout > MaxPhaseTimeout {
			return nil, nil, fmt.Errorf("%w: phase %q timeout %s is outside (0, %s]", ErrInvalidPhase, name, timeout, MaxPhaseTimeout)
		}
		phaseMap[name] = phase
	}
	order := settings.selectedPhases()
	if settings.Enabled {
		for _, name := range order {
			if _, present := phaseMap[name]; !present {
				return nil, nil, fmt.Errorf("%w: selected phase %q has no implementation", ErrPhaseSetMismatch, name)
			}
		}
		for name := range phaseMap {
			if !settings.phaseSelected(name) {
				return nil, nil, fmt.Errorf("%w: phase %q is injected but not selected", ErrPhaseSetMismatch, name)
			}
		}
	}
	return phaseMap, order, nil
}

// freshDocument returns the documented first-start document.
func freshDocument(clock Clock) stateDocument {
	return stateDocument{
		Schema: stateSchema, Revision: 1, State: StateClear,
		UpdatedAt: nowFrom(clock),
	}
}

// failClosed installs the latched recovery document and persists it best-effort.
func (e *Engine) failClosed(reason string) {
	now := nowFrom(e.clock)
	e.doc = stateDocument{
		Schema: stateSchema, Revision: 1, State: StateEngaged, Latched: true,
		Epoch: newEpoch(e.clock), EngagedAt: now, UpdatedAt: now,
		NeedsVerification: true,
		Trigger: Trigger{
			ID: "state-recovery", Kind: TriggerManual, Operator: true,
			Reason:     "state recovery: " + truncateText(reason, MaxDetailBytes),
			DetectedAt: now,
		},
		LastError: truncateText("state recovery: "+reason, MaxDetailBytes*2),
		Degraded:  "the persisted latch document could not be trusted; the engine latched fail-closed",
	}
	e.corrupt = true
	if err := e.saveUnlocked(); err != nil {
		e.persistErr = truncateText(err.Error(), MaxDetailBytes)
	}
}

// saveUnlocked persists the current document. The caller holds stateMu for
// writing, or is the constructor before the engine is published.
func (e *Engine) saveUnlocked() error {
	e.doc.Revision++
	e.doc.UpdatedAt = nowFrom(e.clock)
	if err := e.store.Save(e.doc); err != nil {
		e.persistErr = truncateText(err.Error(), MaxDetailBytes)
		return err
	}
	e.persistErr = ""
	return nil
}

// normalizeTrigger fills the detection time when the source left it zero.
func normalizeTrigger(trigger Trigger, now time.Time) Trigger {
	if trigger.DetectedAt.IsZero() {
		trigger.DetectedAt = now
	}
	return trigger
}

// Arm latches the engine and runs the ordered phase set. It is idempotent-safe:
// a second Arm while latched is refused with ErrLatched and never re-runs a
// phase. A failed phase does not prevent the remaining phases from running.
func (e *Engine) Arm(ctx context.Context, trigger Trigger) (Status, error) {
	if e == nil {
		return Status{}, ErrNilEngine
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e.closed.Load() {
		return e.Status(), ErrClosed
	}
	if !e.settings.Enabled {
		return e.Status(), ErrDisabled
	}
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	if err := ctx.Err(); err != nil {
		return e.Status(), fmt.Errorf("lockdown engage aborted: %w", err)
	}
	now := e.clock.Now()
	trigger = normalizeTrigger(trigger, now)
	if err := trigger.Validate(); err != nil {
		return e.Status(), err
	}
	e.stateMu.RLock()
	latched := e.doc.Latched
	correlation := e.correlation
	e.stateMu.RUnlock()
	if latched {
		return e.Status(), ErrLatched
	}
	outcome := EvaluateTrigger(
		CorrelationPolicy{Cooldown: e.settings.Cooldown, Dedupe: e.settings.Dedupe},
		correlation, trigger, now,
	)
	if !outcome.Accepted {
		e.stateMu.Lock()
		e.correlation = outcome.State
		e.stateMu.Unlock()
		return e.Status(), fmt.Errorf("%w: %s", ErrTriggerSuppressed, outcome.Detail)
	}
	epoch := newEpoch(e.clock)
	e.stateMu.Lock()
	e.correlation = outcome.State
	e.doc = stateDocument{
		Schema: stateSchema, Revision: e.doc.Revision + 1,
		// The latch is persisted as ENGAGED before any phase runs: a crash during
		// the engage window recovers fail-closed instead of starting disarmed.
		State: StateEngaged, Latched: true, Epoch: epoch,
		EngagedAt: now, Trigger: trigger, Transition: transitionEngaging,
		LastError: "engage in progress", UpdatedAt: now,
	}
	_ = e.saveUnlocked()
	e.stateMu.Unlock()

	results := make([]PhaseResult, 0, len(e.order))
	for _, name := range e.order {
		phase, present := e.phases[name]
		if !present {
			// New guarantees the phase set; this is a defensive fail-closed record.
			results = append(results, PhaseResult{
				Action: ActionEngage, Phase: name, Status: PhaseFailed,
				Detail: "phase implementation is missing",
			})
			continue
		}
		results = append(results, runEngage(ctx, phase, e.clock))
	}
	overall, summary := Aggregate(results)
	state := StateEngaged
	if overall == PhaseFailed {
		state = StateFailed
	}
	e.stateMu.Lock()
	e.doc.State = state
	e.doc.Latched = true
	e.doc.Phases = results
	e.doc.Action = ActionEngage
	e.doc.Transition = ""
	e.doc.NeedsVerification = overall != PhaseApplied
	e.doc.VerifiedAt = time.Time{}
	switch overall {
	case PhaseApplied:
		e.doc.Degraded = ""
		e.doc.LastError = ""
	case PhasePartial:
		e.doc.Degraded = truncateText("partial isolation: "+phaseSummary(results), MaxDetailBytes*2)
		e.doc.LastError = ""
	default:
		e.doc.Degraded = truncateText("no isolation phase reported an applied or partial result: "+summary, MaxDetailBytes*2)
		e.doc.LastError = "no phase reported an applied or partial isolation"
	}
	_ = e.saveUnlocked()
	status := e.statusLocked()
	e.stateMu.Unlock()
	return status, nil
}

// Start launches the single maintenance goroutine. It re-verifies an engaged
// isolation and is joined by Close.
func (e *Engine) Start(ctx context.Context) error {
	if e == nil {
		return ErrNilEngine
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.closed.Load() {
		return ErrClosed
	}
	if e.started {
		return ErrAlreadyStarted
	}
	stop := make(chan struct{})
	e.stopCh = stop
	e.started = true
	e.wg.Add(1)
	go e.maintenanceLoop(ctx, stop)
	return nil
}

// Close stops the maintenance goroutine and waits for it. It is idempotent. It
// never releases an engaged latch: the latch survives the process by design.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.startMu.Lock()
	if e.closed.Load() {
		e.startMu.Unlock()
		e.wg.Wait()
		return nil
	}
	e.closed.Store(true)
	if e.stopCh != nil {
		close(e.stopCh)
		e.stopCh = nil
	}
	e.startMu.Unlock()
	e.wg.Wait()
	return nil
}

// maintenanceLoop is the only goroutine the engine owns.
func (e *Engine) maintenanceLoop(ctx context.Context, stop <-chan struct{}) {
	defer e.wg.Done()
	ticker := time.NewTicker(MaintenanceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			e.maintenanceTick(ctx)
		}
	}
}

// maintenanceTick re-verifies an engaged isolation when it is due.
func (e *Engine) maintenanceTick(ctx context.Context) {
	if e == nil || e.closed.Load() {
		return
	}
	e.stateMu.RLock()
	latched := e.doc.Latched
	needs := e.doc.NeedsVerification
	verifiedAt := e.doc.VerifiedAt
	e.stateMu.RUnlock()
	if !latched {
		return
	}
	if !needs && !verifiedAt.IsZero() && e.clock.Now().Sub(verifiedAt) < MaintenanceInterval {
		return
	}
	if !e.opsMu.TryLock() {
		return
	}
	defer e.opsMu.Unlock()
	_, _ = e.reconcileLocked(ctx)
}
