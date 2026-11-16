// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func newStatusTestEngine(t *testing.T, rxObservation, dnsObservation bool, thresholdMutation func(*StyxBeaconThresholds)) (*StyxBeaconEngine, *styxTestClock) {
	t.Helper()
	settings := enabledStyxSettings()
	settings.Mode = StyxModeObserve
	thresholds := DefaultStyxBeaconThresholds()
	if thresholdMutation != nil {
		thresholdMutation(&thresholds)
	}
	settings.Thresholds = thresholds
	clock := newStyxTestClock()
	engine, err := NewStyxBeaconEngine(StyxBeaconConfig{
		Settings:                settings,
		FlowCapabilityKnown:     true,
		RxObservationAvailable:  rxObservation,
		DNSObservationAvailable: dnsObservation,
		Now:                     clock.Now,
	})
	if err != nil {
		t.Fatalf("NewStyxBeaconEngine: %v", err)
	}
	return engine, clock
}

func TestStyxStatusJSONSafe(t *testing.T) {
	engine, clock := newStatusTestEngine(t, false, true, nil)
	for index := 0; index < 14; index++ {
		clock.Advance(60 * time.Second)
		sample := periodicSample(300, 1024)
		sample.Timestamp = clock.Now()
		engine.Observe(sample)
	}
	status := engine.Status()
	if status.IncidentTotal != 1 {
		t.Fatalf("incident total = %d, want 1", status.IncidentTotal)
	}
	if len(status.Top) != 1 {
		t.Fatalf("top length = %d, want 1", len(status.Top))
	}
	if status.Top[0].CV != 0 {
		t.Fatalf("perfectly periodic CV = %v, want 0", status.Top[0].CV)
	}
	if status.Top[0].Remote != "203.0.113.9:443" || status.Top[0].Score != 120 {
		t.Fatalf("top projection = %+v", status.Top[0])
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("status is not JSON-safe: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "Inf") || strings.Contains(text, "NaN") {
		t.Fatalf("status JSON contains a non-finite float: %s", text)
	}
	if !strings.Contains(text, `"rxObservationAvailable":false`) || !strings.Contains(text, `"dnsObservationAvailable":true`) {
		t.Fatalf("status JSON hides the capability truth: %s", text)
	}
	// Unmeasured flows must also marshal cleanly (CV would be +Inf internally).
	fresh, _ := newStatusTestEngine(t, false, false, nil)
	clock.Advance(time.Second)
	sample := periodicSample(301, 512)
	sample.Timestamp = clock.Now()
	fresh.Observe(sample)
	if _, err := json.Marshal(fresh.Status()); err != nil {
		t.Fatalf("fresh status is not JSON-safe: %v", err)
	}
}

func TestStyxStatusTopBoundAndOrder(t *testing.T) {
	engine, clock := newStatusTestEngine(t, false, true, func(thresholds *StyxBeaconThresholds) {
		thresholds.MaxIncidentsPerMinute = 100
	})
	clock.Advance(time.Second)
	for index := 0; index < 20; index++ {
		sample := periodicSample(1000+index, uint64(1<<16)+uint64(index)*1024)
		sample.Remote = netip.AddrFrom4([4]byte{198, 51, 100, byte(index)})
		sample.Timestamp = clock.Now()
		if _, emitted := engine.Observe(sample); !emitted {
			t.Fatalf("flow %d did not emit a direct-IP finding", index)
		}
	}
	status := engine.Status()
	if len(status.Top) != styxStatusTopFlows {
		t.Fatalf("top length = %d, want %d", len(status.Top), styxStatusTopFlows)
	}
	for index := 1; index < len(status.Top); index++ {
		if status.Top[index-1].TxBytes < status.Top[index].TxBytes {
			t.Fatalf("top list is not ordered by tx volume: %d then %d", status.Top[index-1].TxBytes, status.Top[index].TxBytes)
		}
	}
	if status.FlowsTracked != 20 || status.IncidentTotal != 20 {
		t.Fatalf("status counters = %+v", status)
	}
	if _, err := json.Marshal(status); err != nil {
		t.Fatalf("bounded status marshal: %v", err)
	}
}

func TestStyxStatusCountersAndSnapshot(t *testing.T) {
	engine, clock := newStatusTestEngine(t, true, true, nil)
	clock.Advance(time.Second)
	engine.Observe(periodicSample(7, 1024)) // valid
	invalid := periodicSample(8, 10)
	invalid.Remote = netip.Addr{}
	engine.Observe(invalid) // dropped
	engine.RecordFlowPoll(3)
	engine.RecordFlowPoll(4)
	engine.RecordFlowPoll(5)
	status := engine.Status()
	if status.EventsTotal != 2 {
		t.Fatalf("events total = %d, want 2", status.EventsTotal)
	}
	if status.DroppedTotal != 1 {
		t.Fatalf("dropped total = %d, want 1", status.DroppedTotal)
	}
	if status.OverflowTotal != 12 {
		t.Fatalf("overflow total = %d, want 12", status.OverflowTotal)
	}
	if !status.Degraded || status.SensorState != "degraded" || status.Capability != "known" {
		t.Fatalf("degraded status = %+v", status)
	}
	if !status.RxObservationAvailable || !status.DNSObservationAvailable || status.CanaryCorrelationAvailable {
		t.Fatalf("capability projection = %+v", status)
	}
	snapshot := engine.Snapshot()
	if snapshot.SensorState != "degraded" || snapshot.RxObservation != "known" || snapshot.DNSObservation != "known" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Overflows != 12 || snapshot.Dropped != 1 || snapshot.Events != 2 {
		t.Fatalf("snapshot counters = %+v", snapshot)
	}
	if snapshot.Top == nil {
		t.Fatal("snapshot top must be a non-nil list")
	}
	if _, err := json.Marshal(snapshot); err != nil {
		t.Fatalf("snapshot marshal: %v", err)
	}
}

func TestStyxStatusCapabilityMissing(t *testing.T) {
	settings := enabledStyxSettings()
	engine, err := NewStyxBeaconEngine(StyxBeaconConfig{Settings: settings})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	status := engine.Status()
	if status.Capability != "missing" || status.SensorState != "unavailable" {
		t.Fatalf("capability-missing status = %+v", status)
	}
	if status.FlowsTracked != 0 || status.Top == nil {
		t.Fatalf("empty status = %+v", status)
	}
	if _, err := json.Marshal(status); err != nil {
		t.Fatalf("empty status marshal: %v", err)
	}
}

func TestStyxStatusNilEngineJSON(t *testing.T) {
	var engine *StyxBeaconEngine
	for _, value := range []any{engine.Status(), engine.Snapshot()} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("nil engine projection is not JSON-safe: %v", err)
		}
		if !strings.Contains(string(encoded), `"top":[]`) {
			t.Fatalf("nil engine projection must carry an empty top list: %s", encoded)
		}
	}
}
