// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// styxFakeSource is an empty flow source; the wiring tests never touch real
// sockets or connection statistics.
type styxFakeSource struct{}

func (styxFakeSource) TCPConnections() ([]winapi.TCPConnection, error) { return nil, nil }
func (styxFakeSource) EnableDataEstats(winapi.TCPConnection) error     { return nil }
func (styxFakeSource) ConnectionDataEstats(winapi.TCPConnection) (winapi.TCPConnDataStats, error) {
	return winapi.TCPConnDataStats{}, nil
}

func newWiredStyxEngine(t *testing.T) *Engine {
	t.Helper()
	settings := DefaultStyxSettings()
	settings.Enabled = true
	settings.Mode = StyxModeObserve
	beacon, err := NewStyxBeaconEngine(StyxBeaconConfig{
		Settings:            settings,
		FlowCapabilityKnown: true,
	})
	if err != nil {
		t.Fatalf("construct styX beacon: %v", err)
	}
	return &Engine{
		styx:          beacon,
		styxCollector: NewStyxCollector(StyxCollectorConfig{Source: styxFakeSource{}}),
	}
}

// TestStyxRuntimeExposesHonestStatus proves the collector is reachable through
// the engine status instead of being a dead module.
func TestStyxRuntimeExposesHonestStatus(t *testing.T) {
	engine := newWiredStyxEngine(t)
	status := engine.StyxStatus()
	if !status.Enabled {
		t.Fatal("styX detector must be enabled in observe mode")
	}
	if status.Mode != StyxModeObserve {
		t.Fatalf("mode = %q, want observe", status.Mode)
	}
	if status.SensorState != "active" {
		t.Fatalf("sensor state = %q, want active", status.SensorState)
	}
	if status.RxObservationAvailable {
		t.Fatal("receive observation must start unproven, not optimistic")
	}
	if status.DNSObservationAvailable {
		t.Fatal("DNS observation is not available in phase 1 and must not be claimed")
	}
	collector := engine.StyxCollectorStatus()
	_ = collector // bounded projection; values are measured, not asserted here

	full := engine.Status()
	if full.Styx == nil || full.StyxCollector == nil {
		t.Fatal("engine status does not expose the styX runtime")
	}
	if full.Styx.SensorState != "active" {
		t.Fatalf("engine status styX state = %q", full.Styx.SensorState)
	}

	var empty Engine
	if got := empty.StyxStatus(); got.SensorState != "unavailable" || got.Capability != "missing" {
		t.Fatalf("missing detector must be reported unavailable, got %+v", got)
	}
}

// TestStyxIncidentProjectionIsBoundedAndNewestFirst proves the evidence
// projection cannot grow without bound and exposes the newest findings first.
func TestStyxIncidentProjectionIsBoundedAndNewestFirst(t *testing.T) {
	engine := newWiredStyxEngine(t)
	for index := 0; index < maximumStyxIncidents+16; index++ {
		engine.recordStyxIncident(StyxIncident{
			ID:       fmt.Sprintf("styx-%03d", index),
			Severity: SeverityHigh,
			Score:    200,
			Summary:  "test incident",
			Category: "BEACON",
		})
	}
	incidents := engine.StyxIncidents(maximumStyxIncidents)
	if len(incidents) != maximumStyxIncidents {
		t.Fatalf("incident projection = %d entries, want bounded %d", len(incidents), maximumStyxIncidents)
	}
	wantNewest := fmt.Sprintf("styx-%03d", maximumStyxIncidents+15)
	if incidents[0].ID != wantNewest {
		t.Fatalf("newest incident = %q, want %q", incidents[0].ID, wantNewest)
	}
	if got := engine.Status().StyxIncidents; got != maximumStyxIncidents {
		t.Fatalf("status incident count = %d, want %d", got, maximumStyxIncidents)
	}
	// Empty IDs are rejected instead of polluting evidence.
	engine.recordStyxIncident(StyxIncident{})
	if len(engine.StyxIncidents(maximumStyxIncidents)) != maximumStyxIncidents {
		t.Fatal("empty incident id must be ignored")
	}
}

// TestStyxLoopStopsOnCancellation proves the polling goroutine has a lifecycle
// and does not leak after the engine context is cancelled.
func TestStyxLoopStopsOnCancellation(t *testing.T) {
	engine := newWiredStyxEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		engine.styxLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("styX loop did not stop after cancellation")
	}
	// A nil detector must not panic or block.
	var empty Engine
	empty.styxLoop(context.Background())
}
