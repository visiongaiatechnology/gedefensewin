// STATUS: PLATIN VGT SUPREME

package lockdown

// Status is the bounded, secret-free snapshot of the engine. It is computed from
// memory only: a Status call never performs disk, device or process I/O, so a
// slow phase can never block the operator's status read.
//
// The state vocabulary is ENGAGED, CLEAR, ENGAGING, FAILED and DISABLED. FAILED
// is a latched state (fail-closed) in which no phase reported an applied or
// partial isolation: the status never claims "locked" in that case.

import "time"

// Status is the operator-visible engine snapshot.
type Status struct {
	Enabled             bool          `json:"enabled"`
	State               EngineState   `json:"state"`
	Latched             bool          `json:"latched"`
	Epoch               string        `json:"epoch,omitempty"`
	EngagedAt           time.Time     `json:"engaged_at,omitempty"`
	ClearedAt           time.Time     `json:"cleared_at,omitempty"`
	Trigger             Trigger       `json:"trigger"`
	Action              PhaseAction   `json:"action,omitempty"`
	Overall             PhaseStatus   `json:"overall,omitempty"`
	Phases              []PhaseResult `json:"phases"`
	LastClear           *ClearRecord  `json:"last_clear,omitempty"`
	CooldownRemaining   time.Duration `json:"cooldown_remaining_ns,omitempty"`
	FalsePositiveGuards uint64        `json:"false_positive_guards"`
	NeedsVerification   bool          `json:"needs_verification,omitempty"`
	VerifiedAt          time.Time     `json:"verified_at,omitempty"`
	Degraded            string        `json:"degraded,omitempty"`
	LastError           string        `json:"last_error,omitempty"`
	PersistError        string        `json:"persist_error,omitempty"`
	Corrupt             bool          `json:"corrupt,omitempty"`
	Closed              bool          `json:"closed,omitempty"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

// Status returns a snapshotted copy. The caller may mutate the returned slice and
// the trigger without affecting the engine.
func (e *Engine) Status() Status {
	if e == nil {
		return Status{State: StateDisabled}
	}
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.statusLocked()
}

// statusLocked builds the snapshot. The caller holds stateMu for reading.
func (e *Engine) statusLocked() Status {
	now := e.clock.Now()
	state := e.doc.State
	if !e.doc.Latched {
		if e.settings.Enabled {
			state = StateClear
		} else {
			state = StateDisabled
		}
	} else if e.doc.Transition != "" {
		// A latched transition (engage or clear) is reported as ENGAGING: the
		// status never claims a settled isolation while a phase set is running.
		state = StateEngaging
	}
	overall, _ := Aggregate(e.doc.Phases)
	if len(e.doc.Phases) == 0 {
		overall = StatusNone
	}
	phases := make([]PhaseResult, len(e.doc.Phases))
	copy(phases, e.doc.Phases)
	status := Status{
		Enabled:             e.settings.Enabled,
		State:               state,
		Latched:             e.doc.Latched,
		Epoch:               e.doc.Epoch,
		EngagedAt:           e.doc.EngagedAt,
		ClearedAt:           e.doc.ClearedAt,
		Trigger:             e.doc.Trigger,
		Action:              e.doc.Action,
		Overall:             overall,
		Phases:              phases,
		FalsePositiveGuards: e.correlation.Guards,
		NeedsVerification:   e.doc.NeedsVerification,
		VerifiedAt:          e.doc.VerifiedAt,
		Degraded:            e.doc.Degraded,
		LastError:           e.doc.LastError,
		PersistError:        e.persistErr,
		Corrupt:             e.corrupt,
		Closed:              e.closed.Load(),
		UpdatedAt:           e.doc.UpdatedAt,
	}
	if e.doc.LastClear != nil {
		clear := *e.doc.LastClear
		status.LastClear = &clear
	}
	if e.settings.Cooldown > 0 && !e.correlation.AutomaticAt.IsZero() {
		remaining := e.settings.Cooldown - now.Sub(e.correlation.AutomaticAt)
		if remaining > 0 {
			status.CooldownRemaining = remaining
		}
	}
	if !e.settings.ClearRequiresExplicitEpoch && e.doc.Latched {
		status.Degraded = appendDetail(status.Degraded, "explicit epoch comparison is disabled by settings; an operator clear does not need to name the observed epoch")
	}
	if e.corrupt {
		status.Degraded = appendDetail(status.Degraded, "the persisted latch document could not be trusted; the engine latched fail-closed")
	}
	if e.persistErr != "" {
		status.Degraded = appendDetail(status.Degraded, "state persistence degraded: "+e.persistErr)
	}
	return status
}
