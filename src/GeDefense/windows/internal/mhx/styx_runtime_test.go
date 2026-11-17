// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
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

type fakeStyxEnforcer struct {
	syncErr    error
	syncCalls  int
	closeCalls int
	lastCfg    styxEnforceConfig
	state      styxEnforceState
}

func (f *fakeStyxEnforcer) Sync(_ context.Context, cfg styxEnforceConfig) (styxEnforceState, error) {
	f.syncCalls++
	f.lastCfg = cfg
	if f.syncErr != nil {
		f.state = styxEnforceState{LastError: f.syncErr.Error()}
		return f.state, f.syncErr
	}
	f.state = styxEnforceState{Active: true, FilterCount: 4 + len(cfg.BlockPrefixes)}
	return f.state, nil
}

func (f *fakeStyxEnforcer) Close() error {
	f.closeCalls++
	f.state = styxEnforceState{}
	return nil
}

func (f *fakeStyxEnforcer) State() styxEnforceState { return f.state }

func TestStyxModeTransitionsAndFailClosedWFP(t *testing.T) {
	engine := newWiredStyxEngine(t)
	enforcer := &fakeStyxEnforcer{}
	engine.styxWFP = enforcer
	engine.styxIncidents = []StyxIncident{
		{ID: "inc-1", Decision: StyxDecisionContain, Remote: "198.51.100.42:443", Score: 250},
		{ID: "inc-lan", Decision: StyxDecisionContain, Remote: "192.168.1.10:443", Score: 250},
	}

	status, err := engine.SetStyxMode(context.Background(), StyxModeEnforce)
	if err != nil {
		t.Fatalf("SetStyxMode enforce: %v", err)
	}
	if !status.Enforcing || !status.WFPActive || status.WFPFilterCount != 5 || enforcer.syncCalls != 1 {
		t.Fatalf("expected active WFP enforce with 1 public prefix, got status=%+v syncCalls=%d", status, enforcer.syncCalls)
	}
	if len(enforcer.lastCfg.BlockPrefixes) != 1 || enforcer.lastCfg.BlockPrefixes[0].String() != "198.51.100.42/32" {
		t.Fatalf("expected only public IP blocked, got %v", enforcer.lastCfg.BlockPrefixes)
	}

	// Switching to observe releases dynamic WFP filters cleanly.
	status, err = engine.SetStyxMode(context.Background(), StyxModeObserve)
	if err != nil {
		t.Fatalf("SetStyxMode observe: %v", err)
	}
	if status.Enforcing || status.WFPActive || enforcer.closeCalls != 1 {
		t.Fatalf("expected WFP closed in observe, got %+v closeCalls=%d", status, enforcer.closeCalls)
	}

	// Failed WFP sync rolls back detector mode fail-closed.
	enforcer.syncErr = errors.New("BFE access denied")
	status, err = engine.SetStyxMode(context.Background(), StyxModeEnforce)
	if err == nil {
		t.Fatal("expected failed WFP sync to error")
	}
	if status.Mode != StyxModeObserve || status.Enforcing {
		t.Fatalf("expected rollback to observe, got %+v", status)
	}
}

func TestStyxWhitelistReleasesWFPBlockAndUnblocksApp(t *testing.T) {
	engine := newWiredStyxEngine(t)
	enforcer := &fakeStyxEnforcer{}
	engine.styxEnforceMu.Lock()
	engine.styxWFP = enforcer
	engine.styxEnforceMu.Unlock()

	if _, err := engine.SetStyxMode(context.Background(), StyxModeEnforce); err != nil {
		t.Fatalf("SetStyxMode enforce: %v", err)
	}
	inc := StyxIncident{
		ID:          "INC-STYX-WL-1",
		PID:         9120,
		Process:     "tool.exe",
		ProcessPath: `C:\Tools\tool.exe`,
		Remote:      "198.51.100.44:443",
		Score:       250,
		Decision:    StyxDecisionContain,
	}
	engine.enforceStyxIncident(context.Background(), &inc)
	engine.recordStyxIncident(inc)
	if inc.Action != "wfp-blocked" || len(engine.StyxBlockedTargets()) != 1 {
		t.Fatalf("expected active WFP block before whitelist, action=%s blocked=%v", inc.Action, engine.StyxBlockedTargets())
	}

	syncBefore := enforcer.syncCalls
	wl, err := engine.SetStyxWhitelist(context.Background(), []string{`C:\Tools\tool.exe`})
	if err != nil {
		t.Fatalf("SetStyxWhitelist: %v", err)
	}
	if len(wl) != 1 || enforcer.syncCalls != syncBefore+1 {
		t.Fatalf("expected immediate WFP resync on whitelist, wl=%v syncCalls=%d", wl, enforcer.syncCalls)
	}
	if len(engine.StyxBlockedTargets()) != 0 {
		t.Fatalf("expected WFP block released after whitelisting process path, still blocked: %v", engine.StyxBlockedTargets())
	}
	latest := engine.StyxIncidents(5)
	if len(latest) != 1 || !latest[0].Whitelisted || latest[0].Action != "whitelisted" {
		t.Fatalf("expected stored incident marked whitelisted, got %+v", latest)
	}
}
