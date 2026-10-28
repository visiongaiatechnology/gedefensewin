// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSuperviseSensorRetriesThenJoinsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	faults := make(chan error, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseSensor(ctx, "fixture sensor", func(context.Context) error {
			if attempts.Add(1) == 3 {
				cancel()
			}
			return errors.New("fixture sensor exited")
		}, faults, time.Millisecond, 4*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not stop")
	}
	if attempts.Load() != 3 || len(faults) != 2 {
		t.Fatalf("unexpected attempts/faults: %d/%d", attempts.Load(), len(faults))
	}
	for len(faults) > 0 {
		fault := <-faults
		if !strings.HasPrefix(fault.Error(), "fixture sensor: ") {
			t.Fatalf("fault does not name its sensor: %v", fault)
		}
	}
}

func TestSuperviseSensorCancelInterruptsLongBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	faults := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseSensor(ctx, "fixture sensor", func(context.Context) error {
			return errors.New("fixture sensor exited")
		}, faults, time.Hour, time.Hour)
	}()
	select {
	case <-faults:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not report the first fault")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backoff blocked cancellation")
	}
}

func TestSuperviseSensorResetsBackoffAfterHealthyAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mutex sync.Mutex
	var starts []time.Time
	var attempt atomic.Int32
	var healthyEnd time.Time
	faults := make(chan error, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseSensor(ctx, "fixture sensor", func(context.Context) error {
			mutex.Lock()
			starts = append(starts, time.Now())
			mutex.Unlock()
			switch attempt.Add(1) {
			case 1, 2:
				return errors.New("fast failure")
			case 3:
				time.Sleep(120 * time.Millisecond)
				mutex.Lock()
				healthyEnd = time.Now()
				mutex.Unlock()
				return errors.New("slow failure")
			default:
				cancel()
				return errors.New("stopped")
			}
		}, faults, 20*time.Millisecond, 100*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not stop")
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(starts) != 4 {
		t.Fatalf("unexpected attempt count: %d", len(starts))
	}
	// The healthy attempt (>= maximum) must reset the next delay to initial
	// (20ms), not continue the escalated delay (80ms after two fast failures).
	if gap := starts[3].Sub(healthyEnd); gap > 60*time.Millisecond {
		t.Fatalf("backoff did not reset after a healthy attempt: %v", gap)
	}
	if gap := starts[3].Sub(healthyEnd); gap < 10*time.Millisecond {
		t.Fatalf("backoff reset delay is implausibly small: %v", gap)
	}
}

func TestNextSensorDelayContract(t *testing.T) {
	const initial, maximum = time.Second, 30 * time.Second
	cases := []struct {
		name     string
		elapsed  time.Duration
		delay    time.Duration
		expected time.Duration
	}{
		{name: "initial-doubles", delay: initial, expected: 2 * time.Second},
		{name: "four-doubles", delay: 4 * time.Second, expected: 8 * time.Second},
		{name: "caps-at-maximum", delay: 16 * time.Second, expected: maximum},
		{name: "stays-at-maximum", delay: maximum, expected: maximum},
		{name: "healthy-resets", elapsed: maximum, delay: 16 * time.Second, expected: initial},
		{name: "longer-than-maximum-resets", elapsed: time.Hour, delay: maximum, expected: initial},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := nextSensorDelay(testCase.elapsed, testCase.delay, initial, maximum); got != testCase.expected {
				t.Fatalf("nextSensorDelay(%v, %v) = %v, want %v", testCase.elapsed, testCase.delay, got, testCase.expected)
			}
		})
	}
	if got := nextSensorDelay(0, maximum/2, initial, maximum); got != maximum {
		t.Fatalf("half maximum must escalate to maximum, got %v", got)
	}
}

func TestSuperviseSensorRejectsInvalidConfiguration(t *testing.T) {
	faults := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseSensor(context.Background(), "fixture sensor", nil, faults, time.Second, time.Second)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("invalid configuration blocked the supervisor")
	}
	if len(faults) != 1 {
		t.Fatalf("invalid configuration was not reported: %d", len(faults))
	}
}
