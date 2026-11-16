// STATUS: DIAMANT VGT SUPREME
package userlaunch

import (
	"errors"
	"fmt"
)

// MarkerEnv is set in the environment block of a UI process that was
// deliberately handed over to the unprivileged desktop shell user. It breaks a
// relaunch loop if an elevated process ever inherits the marker.
const MarkerEnv = "VGT_UI_LAUNCHED_UNELEVATED"

// ErrDeElevationUnavailable classifies "the UI is running elevated and cannot
// be continued as an unprivileged process". Callers MUST treat it as fatal for
// the elevated process: there is no elevated browser/Chromium fallback.
var ErrDeElevationUnavailable = errors.New("userlaunch: unprivileged UI start is not safely possible")

// DeElevationError is the typed, fail-closed outcome of the de-elevation
// decision. The process is elevated, so it must not continue as the UI and must
// not start a browser with the administrator token; instead the caller reports
// the error and exits.
type DeElevationError struct {
	// Reason is a short, operator-readable cause category.
	Reason string
	// Err keeps the underlying launch failure available for diagnostics.
	Err error
}

// Error implements error.
func (e *DeElevationError) Error() string {
	if e == nil {
		return ErrDeElevationUnavailable.Error()
	}
	if e.Err != nil {
		return fmt.Sprintf("userlaunch: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("userlaunch: %s", e.Reason)
}

// Unwrap exposes the underlying cause to errors.Is/errors.As while keeping the
// classifiable sentinel reachable.
func (e *DeElevationError) Unwrap() error {
	if e == nil {
		return ErrDeElevationUnavailable
	}
	if e.Err != nil {
		return errors.Join(ErrDeElevationUnavailable, e.Err)
	}
	return ErrDeElevationUnavailable
}

// StartPolicy is the pure outcome of the de-elevation decision. It never means
// "run the UI elevated": an elevated process either hands over or stops.
type StartPolicy int

const (
	// StartPolicyProceed means the process is unprivileged and may start the UI.
	StartPolicyProceed StartPolicy = iota
	// StartPolicyRelaunch means the process is elevated and must hand itself
	// over to the unprivileged desktop shell user before starting the UI.
	StartPolicyRelaunch
	// StartPolicyRefuse means the process is elevated even though the marker
	// says it was already handed over. The state is inconsistent, so no UI and
	// no browser may be started (fail-closed).
	StartPolicyRefuse
)

// DecideStartPolicy is the fail-closed de-elevation decision. It is pure so it
// can be unit-tested without touching the desktop:
//
//   - unprivileged: the UI may run in this process, never relaunch (the marker
//     is irrelevant for a standard user).
//   - elevated without marker: hand over exactly once.
//   - elevated with marker: refuse. A process that carries the "already
//     unprivileged" marker but runs elevated is an inheritance anomaly; running
//     the UI here would put a Chromium browser under the administrator token.
func DecideStartPolicy(elevated bool, marker string) StartPolicy {
	if !elevated {
		return StartPolicyProceed
	}
	if marker == "1" {
		return StartPolicyRefuse
	}
	return StartPolicyRelaunch
}

// ShouldRelaunchUnelevated reports whether an elevated UI process must hand
// itself over to the unprivileged shell user. It is intentionally pure so the
// decision stays unit-testable without touching the desktop.
//
// Deprecated: prefer DecideStartPolicy. A false result only means "do not
// relaunch"; it does not prove that starting the UI in this process is safe.
func ShouldRelaunchUnelevated(elevated bool, marker string) bool {
	return DecideStartPolicy(elevated, marker) == StartPolicyRelaunch
}

// relaunchUnelevated is RelaunchUnelevatedIfNeeded with explicit inputs, so the
// complete fail-closed decision is testable without an elevated desktop process.
// The launch relay is injected: when the policy refuses, it must never be
// called (a test asserts exactly that).
func relaunchUnelevated(elevated bool, marker, executable string, args []string, launch func(string, []string) error) (bool, error) {
	switch DecideStartPolicy(elevated, marker) {
	case StartPolicyProceed:
		return false, nil
	case StartPolicyRefuse:
		return false, &DeElevationError{Reason: "elevated process carries the unprivileged hand-over marker"}
	}
	if launch == nil {
		return false, &DeElevationError{Reason: "no unprivileged launch relay configured"}
	}
	if launchErr := launch(executable, args); launchErr != nil {
		return false, &DeElevationError{Reason: "hand-over to the unprivileged desktop shell failed", Err: launchErr}
	}
	return true, nil
}
