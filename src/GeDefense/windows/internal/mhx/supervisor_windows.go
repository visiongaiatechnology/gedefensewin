// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// superviseSensor owns the recovery loop of one independent telemetry sensor.
// A failed attempt is reported exactly once on the faults channel and retried
// with exponential backoff; a plain context cancellation stops the loop without
// an additional fault. Cursor or dedupe state that must survive restarts stays
// in the caller's closure, never in the supervisor itself.
func superviseSensor(ctx context.Context, name string, run func(context.Context) error, faults chan<- error, initial, maximum time.Duration) {
	if ctx == nil {
		return
	}
	if run == nil || initial <= 0 || maximum < initial {
		deliverFault(faults, errors.New("sensor supervisor configuration rejected"))
		return
	}
	if name == "" {
		name = "sensor"
	}
	delay := initial
	for ctx.Err() == nil {
		started := time.Now()
		err := run(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("ended unexpectedly")
		}
		deliverFault(faults, fmt.Errorf("%s: %w", name, err))
		delay = nextSensorDelay(time.Since(started), delay, initial, maximum)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// nextSensorDelay applies the VGT sensor backoff contract: an attempt that
// stayed healthy for at least maximum resets the delay to initial, otherwise
// the delay doubles until it reaches maximum.
func nextSensorDelay(elapsed, delay, initial, maximum time.Duration) time.Duration {
	if elapsed >= maximum {
		return initial
	}
	if delay < maximum/2 {
		return delay * 2
	}
	return maximum
}
