// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	// processSensorHeartbeat is the receipt-time health cadence. It is well
	// below the engine's 45s stale-heartbeat threshold and satisfies the
	// ">= every 2s" contract even on an idle Security log.
	processSensorHeartbeat = time.Second
	// processSensorInitialBackoff/processSensorMaximumBackoff bound the
	// supervisor retry loop for a failing Security 4688 subscription.
	processSensorInitialBackoff = time.Second
	processSensorMaximumBackoff = 30 * time.Second
)

// processEventLogStream is the injectable wevtapi seam. Production uses
// winapi.StreamEventLog; tests substitute a deterministic record stream to
// prove cursor resume and restart handling without touching the live Security
// log.
type processEventLogStream func(ctx context.Context, channel, xpath string, startAfterRecordID int64) (<-chan winapi.EventLogRecord, <-chan error, error)

type processWatcher struct{}

// Run owns the native process-creation sensor. It spawns no child process: the
// sensor subscribes to Security event ID 4688 (process creation with command
// line) through wevtapi and recovers from stream failures through the shared
// supervisor. The cursor lives in this closure, so a restarted attempt resumes
// after the last handled record instead of replaying history.
func (processWatcher) Run(ctx context.Context, output chan<- ProcessEvent, health chan<- time.Time, faults chan<- error) {
	probe := &processImageProbe{}
	var cursor int64
	superviseSensor(ctx, "process telemetry", func(attempt context.Context) error {
		return runProcessEventLog(attempt, &cursor, probe, output, health, faults, processAuditAvailability, winapi.StreamEventLog)
	}, faults, processSensorInitialBackoff, processSensorMaximumBackoff)
}

// runProcessEventLog opens one 4688 subscription attempt and drains it until a
// fatal stream error, a context cancellation or a closed stream. Health
// heartbeats carry the receipt time (never the historical event time) and are
// emitted at least once per processSensorHeartbeat even when no record arrives.
func runProcessEventLog(
	ctx context.Context,
	cursor *int64,
	probe *processImageProbe,
	output chan<- ProcessEvent,
	health chan<- time.Time,
	faults chan<- error,
	auditCheck func() error,
	stream processEventLogStream,
) error {
	if ctx == nil || cursor == nil || probe == nil || output == nil || health == nil || auditCheck == nil || stream == nil {
		return errors.New("process telemetry configuration rejected")
	}
	// Fail honestly when command-line process auditing is not configured: a
	// name-only 4688 stream would silently lose the evidence this sensor exists
	// for, so each attempt reports the configuration fault to the supervisor.
	if err := auditCheck(); err != nil {
		return err
	}
	startAfter := *cursor
	xpath, err := winapi.EventLogXPath([]int{securityProcessCreationEventID}, startAfter)
	if err != nil {
		return fmt.Errorf("process telemetry query rejected: %w", err)
	}
	records, failures, err := stream(ctx, securityChannelName, xpath, startAfter)
	if err != nil {
		return fmt.Errorf("process telemetry subscription unavailable: %w", err)
	}
	if records == nil {
		return errors.New("process telemetry subscription returned no records")
	}
	deliverHealth(health, time.Now().UTC())
	heartbeat := time.NewTicker(processSensorHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			deliverHealth(health, time.Now().UTC())
		case streamErr, ok := <-failures:
			if !ok {
				failures = nil
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if streamErr == nil {
				streamErr = errors.New("process telemetry stream failed")
			}
			return streamErr
		case record, ok := <-records:
			if !ok {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Records are closed before the error channel, so the fatal
				// reason (if any) is already buffered.
				if streamErr := drainProcessStreamFailure(failures); streamErr != nil {
					return streamErr
				}
				return errors.New("process telemetry event stream ended unexpectedly")
			}
			handleErr := handleProcessCreationRecord(ctx, record, probe, output)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if handleErr != nil {
				deliverFault(faults, handleErr)
			}
			// Cursor advances only after a record was handled - either delivered
			// or explicitly rejected. A malformed record must be skipped instead
			// of being replayed forever by the restarting supervisor.
			if record.RecordID > *cursor {
				*cursor = record.RecordID
			}
			deliverHealth(health, time.Now().UTC())
		}
	}
}

// handleProcessCreationRecord validates one stream record, triages it and
// forwards an observed event. Delivery is the commit point: the caller only
// advances the cursor after this function returns, so an event interrupted by
// cancellation is replayed after a restart.
func handleProcessCreationRecord(ctx context.Context, record winapi.EventLogRecord, probe *processImageProbe, output chan<- ProcessEvent) error {
	if record.RecordID <= 0 {
		return errors.New("process telemetry record id rejected")
	}
	if record.Channel != "" && !equalFoldASCII(record.Channel, securityChannelName) {
		return errors.New("process telemetry channel rejected")
	}
	event, parsedRecordID, err := parseProcessCreationEvent(record.XML)
	if err != nil {
		return fmt.Errorf("process telemetry record rejected: %w", err)
	}
	if parsedRecordID != record.RecordID {
		return errors.New("process telemetry record cursor mismatch")
	}
	if !probe.triageProcessCreation(&event) {
		return nil
	}
	select {
	case output <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drainProcessStreamFailure performs the final non-blocking read of the stream
// error channel after the records channel closed.
func drainProcessStreamFailure(failures <-chan error) error {
	if failures == nil {
		return nil
	}
	select {
	case streamErr, ok := <-failures:
		if !ok || streamErr == nil {
			return nil
		}
		return streamErr
	default:
		return nil
	}
}

// equalFoldASCII compares two short ASCII tokens without allocating.
func equalFoldASCII(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := 0; index < len(left); index++ {
		character := left[index]
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		expected := right[index]
		if expected >= 'A' && expected <= 'Z' {
			expected += 'a' - 'A'
		}
		if character != expected {
			return false
		}
	}
	return true
}

// deliverHealth publishes a receipt-time heartbeat without ever blocking the
// stream loop.
func deliverHealth(health chan<- time.Time, timestamp time.Time) {
	select {
	case health <- timestamp:
	default:
	}
}

// deliverFault publishes a bounded fault without ever blocking the stream loop.
func deliverFault(faults chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case faults <- err:
	default:
	}
}
