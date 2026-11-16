// STATUS: PLATIN VGT SUPREME

package witness

// Honest status projection.
//
// Status is a bounded, secret-free view of the engine: enums, counters, the last
// checkpoint id/digest and a fixed-vocabulary reason. It never carries an
// endpoint, a path, a header, a token or key material, so it is safe to render in
// an operator API. The state machine is:
//
//	DISABLED   settings.Enabled is false; the package is inert.
//	UNVERIFIED enabled and wired, no verified receipt yet, no failure.
//	CONNECTED  the last operation produced a verified witness receipt.
//	DEGRADED   a push failed (not a trust failure) or the outbox is at its bound.
//	FAULT      fail-closed stop: rollback/fork, corrupt outbox, signing failure or
//	           a rejected pin/receipt; no further checkpoint is created.

import "errors"

// Status is the honest lifecycle state of the engine.
type Status string

// The five states of the witness engine. There is no "OK": CONNECTED is only
// reported after a verified receipt.
const (
	StatusDisabled   Status = "DISABLED"
	StatusUnverified Status = "UNVERIFIED"
	StatusConnected  Status = "CONNECTED"
	StatusDegraded   Status = "DEGRADED"
	StatusFault      Status = "FAULT"
)

// CheckpointSummary is the bounded checkpoint projection of Status.
type CheckpointSummary struct {
	CheckpointID     string
	CheckpointSHA256 string
	LedgerEpoch      uint64
	Sequence         uint64
	WindowEndUTC     string
}

// StatusReport is the bounded status projection. It never carries an endpoint, a
// path, a header, a token or key material.
type StatusReport struct {
	Status              Status
	Enabled             bool
	Wired               bool
	LastCheckpoint      *CheckpointSummary
	LastReceiptSequence uint64
	OutboxDepth         int
	OutboxBytes         int64
	OutboxFull          bool
	ConsecutiveFailures int
	LastError           string
}

// Status returns the bounded, honest engine status.
func (e *Engine) Status() StatusReport {
	if e == nil {
		return StatusReport{Status: StatusDisabled}
	}
	e.mu.Lock()
	enabled := e.settings.Enabled
	fault := e.faultReason
	failures := e.failures
	lastReceipt := e.lastReceiptSequence
	lastError := e.lastError
	var summary *CheckpointSummary
	if e.lastCheckpoint != nil {
		checkpoint := e.lastCheckpoint
		summary = &CheckpointSummary{
			CheckpointID: checkpoint.CheckpointID, CheckpointSHA256: checkpoint.CheckpointSHA256,
			LedgerEpoch: checkpoint.LedgerEpoch, Sequence: checkpoint.Sequence,
			WindowEndUTC: checkpoint.WindowEndUTC,
		}
	}
	wired := enabled && fault == "" && e.outbox != nil && e.transport != nil
	e.mu.Unlock()
	report := StatusReport{
		Enabled: enabled, Wired: wired, LastCheckpoint: summary,
		LastReceiptSequence: lastReceipt, ConsecutiveFailures: failures, LastError: lastError,
	}
	if e.outbox != nil {
		report.OutboxDepth = e.outbox.Depth()
		report.OutboxBytes = e.outbox.Bytes()
		report.OutboxFull = e.outbox.Full()
	}
	switch {
	case !enabled:
		report.Status = StatusDisabled
	case fault != "":
		report.Status = StatusFault
		report.LastError = fault
	case e.outbox != nil && e.outbox.Corrupt():
		report.Status = StatusFault
		report.LastError = "witness outbox is corrupt"
	case e.outbox != nil && e.outbox.Full():
		report.Status = StatusDegraded
	case failures > 0:
		report.Status = StatusDegraded
	case lastReceipt > 0:
		report.Status = StatusConnected
	default:
		report.Status = StatusUnverified
	}
	return report
}

// boundedPushReason maps a push failure onto a bounded, secret-free status text.
func boundedPushReason(err error) string {
	switch {
	case errors.Is(err, ErrSPKIPinMismatch):
		return "witness server pin was rejected"
	case errors.Is(err, ErrCertificateInvalid):
		return "witness server certificate was rejected"
	case errors.Is(err, ErrDestinationRefused):
		return "witness destination was refused"
	case errors.Is(err, ErrReceiptInvalid):
		return "witness receipt was rejected"
	case errors.Is(err, ErrReplayDetected):
		return "witness receipt did not advance its sequence"
	case errors.Is(err, ErrRedirectRefused):
		return "witness redirect was refused"
	case errors.Is(err, ErrResponseInvalid):
		return "witness response was invalid"
	case errors.Is(err, ErrTransport):
		return "witness is unreachable"
	default:
		return "witness push failed"
	}
}
