// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type styxTestClock struct {
	now time.Time
}

func newStyxTestClock() *styxTestClock {
	return &styxTestClock{now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
}

func (c *styxTestClock) Now() time.Time {
	return c.now
}

func (c *styxTestClock) Advance(delta time.Duration) time.Time {
	c.now = c.now.Add(delta)
	return c.now
}

func newBeaconTestEngine(t *testing.T, mode string, rxObservation, dnsObservation, capability bool) (*StyxBeaconEngine, *styxTestClock) {
	t.Helper()
	settings := enabledStyxSettings()
	settings.Mode = mode
	clock := newStyxTestClock()
	engine, err := NewStyxBeaconEngine(StyxBeaconConfig{
		Settings:                settings,
		FlowCapabilityKnown:     capability,
		RxObservationAvailable:  rxObservation,
		DNSObservationAvailable: dnsObservation,
		Now:                     clock.Now,
	})
	if err != nil {
		t.Fatalf("NewStyxBeaconEngine: %v", err)
	}
	return engine, clock
}

// feedStyle feeds one sample after advancing the test clock; the sample carries
// the same timestamp so inter-arrival statistics are deterministic.
func feedStyle(t *testing.T, engine *StyxBeaconEngine, clock *styxTestClock, advance time.Duration, sample StyxFlowSample) (StyxIncident, bool) {
	t.Helper()
	clock.Advance(advance)
	sample.Timestamp = clock.Now()
	return engine.Observe(sample)
}

func periodicSample(pid int, txBytes uint64) StyxFlowSample {
	return StyxFlowSample{
		PID:                    pid,
		Remote:                 netip.MustParseAddr("203.0.113.9"),
		RemotePort:             443,
		Proto:                  styxProtoTCP,
		TxBytes:                txBytes,
		TxObservationAvailable: true,
	}
}

func TestNewStyxBeaconEngineValidation(t *testing.T) {
	if engine, err := NewStyxBeaconEngine(StyxBeaconConfig{Settings: StyxSettings{Enabled: true, Mode: "nonsense"}}); err == nil || engine != nil {
		t.Fatalf("invalid settings produced an engine: %+v, %v", engine, err)
	}
	engine, err := NewStyxBeaconEngine(StyxBeaconConfig{Settings: DefaultStyxSettings()})
	if err != nil {
		t.Fatalf("default settings rejected: %v", err)
	}
	if engine.SensorState() != "unavailable" {
		t.Fatalf("disabled engine sensor state = %q, want unavailable", engine.SensorState())
	}
}

func TestSensorStateHonesty(t *testing.T) {
	engine, _ := newBeaconTestEngine(t, StyxModeObserve, false, false, false)
	if state := engine.SensorState(); state != "unavailable" {
		t.Fatalf("missing capability sensor state = %q, want unavailable", state)
	}
	engine.SetFlowCapabilityKnown(true)
	if state := engine.SensorState(); state != "active" {
		t.Fatalf("active sensor state = %q, want active", state)
	}
	engine.RecordFlowPoll(0)
	if state := engine.SensorState(); state != "active" {
		t.Fatalf("clean poll changed sensor state to %q", state)
	}
	for index := 0; index < 3; index++ {
		engine.RecordFlowPoll(7)
	}
	if state := engine.SensorState(); state != "degraded" {
		t.Fatalf("3-strike overflow sensor state = %q, want degraded", state)
	}
	for index := 0; index < 3; index++ {
		engine.RecordFlowPoll(0)
	}
	if state := engine.SensorState(); state != "active" {
		t.Fatalf("recovered sensor state = %q, want active", state)
	}

	offSettings := enabledStyxSettings()
	offSettings.Mode = StyxModeOff
	offSettings.Enabled = false
	offEngine, err := NewStyxBeaconEngine(StyxBeaconConfig{Settings: offSettings, FlowCapabilityKnown: true})
	if err != nil {
		t.Fatalf("off engine: %v", err)
	}
	if state := offEngine.SensorState(); state != "unavailable" {
		t.Fatalf("disabled sensor state = %q, want unavailable", state)
	}
}

func TestBeaconPeriodicityDetection(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, false, true)
	var incidents []StyxIncident
	for index := 0; index < 14; index++ {
		incident, emitted := feedStyle(t, engine, clock, 60*time.Second, periodicSample(4242, 512))
		if emitted {
			incidents = append(incidents, incident)
		}
	}
	if len(incidents) != 1 {
		t.Fatalf("periodic beacon emitted %d incidents, want exactly 1", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 120 || incident.Severity != SeverityHigh || incident.Decision != StyxDecisionAlert {
		t.Fatalf("periodicity incident = %+v", incident)
	}
	if incident.EventType != StyxBeaconEventPeriodicity || incident.Category != StyxCategoryCommandAndControl {
		t.Fatalf("periodicity classification = %+v", incident)
	}
	if len(incident.RuleIDs) != 1 || incident.RuleIDs[0] != StyxBeaconRulePeriodicity {
		t.Fatalf("periodicity rules = %v", incident.RuleIDs)
	}
	if incident.PID != 4242 || incident.Remote != "203.0.113.9:443" {
		t.Fatalf("incident identity = %+v", incident)
	}
	if incident.IntervalSamples != 12 {
		t.Fatalf("interval samples = %d, want 12", incident.IntervalSamples)
	}
	if incident.Action != "none" || incident.Outcome == "" {
		t.Fatalf("passive incident must not carry an active action: %+v", incident)
	}
	if !strings.HasPrefix(incident.ID, "INC-STYX-BEACON-") {
		t.Fatalf("incident id = %q", incident.ID)
	}
}

func TestBeaconPeriodicityRequiresTxObservation(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, false, true)
	for index := 0; index < 20; index++ {
		sample := periodicSample(1, 0)
		sample.TxObservationAvailable = false // the source cannot prove transmit bytes
		if _, emitted := feedStyle(t, engine, clock, 60*time.Second, sample); emitted {
			t.Fatal("periodicity fired without proven transmit observation")
		}
	}
	if status := engine.Status(); status.EventsTotal != 20 || status.IncidentTotal != 0 {
		t.Fatalf("status after unobserved samples = %+v", status)
	}
}

func TestBeaconExfilVolumeWithoutRxStaysUnknown(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, false, true)
	for index := 0; index < 10; index++ {
		if _, emitted := feedStyle(t, engine, clock, 60*time.Second, periodicSample(77, 131072)); emitted {
			t.Fatal("volume-only exfiltration fired without canary evidence or rx telemetry")
		}
	}
	// With a canary correlation the same volume becomes a HIGH finding, but it
	// must never claim a tx/rx ratio.
	engine.SetCanaryCorrelation(func(pid int, since time.Time) bool { return pid == 77 })
	var incidents []StyxIncident
	for index := 0; index < 10; index++ {
		if incident, emitted := feedStyle(t, engine, clock, 60*time.Second, periodicSample(77, 131072)); emitted {
			incidents = append(incidents, incident)
		}
	}
	if len(incidents) == 0 {
		t.Fatal("canary-correlated volume did not emit an incident")
	}
	incident := incidents[0]
	if incident.Score != 200 || incident.Severity != SeverityHigh || incident.Decision != StyxDecisionAlert {
		t.Fatalf("phase-1 volume incident = %+v", incident)
	}
	if !incident.CanaryCorrelated {
		t.Fatal("incident does not record the canary correlation")
	}
	if !strings.Contains(incident.Summary, "no ratio claim") {
		t.Fatalf("summary claims more than it can prove: %q", incident.Summary)
	}
}

func TestBeaconExfilRatioWithRxObservation(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, true, false, true)
	sample := periodicSample(88, 1<<20)
	sample.RxBytes = 1024
	sample.RxObservationAvailable = true
	incident, emitted := feedStyle(t, engine, clock, 60*time.Second, sample)
	if !emitted {
		t.Fatal("provable tx/rx asymmetry did not emit an incident")
	}
	if incident.Score != 200 || incident.Severity != SeverityHigh || incident.RuleIDs[0] != StyxBeaconRuleAsymmetry {
		t.Fatalf("asymmetry incident = %+v", incident)
	}
	if incident.Category != StyxCategoryExfiltration {
		t.Fatalf("asymmetry category = %q", incident.Category)
	}
	// A canary correlation raises the same finding to CRITICAL 250 once the
	// dedupe window has passed. The first observation is remembered for the
	// ratio, so the second feed keeps the same flow identity.
	engine.SetCanaryCorrelation(func(pid int, since time.Time) bool { return pid == 88 })
	clock.Advance(400 * time.Second)
	sample.Timestamp = clock.Now()
	sample.TxBytes = 1 << 20
	incident, emitted = engine.Observe(sample)
	if !emitted {
		t.Fatal("canary-correlated asymmetry did not emit after the dedupe window")
	}
	if incident.Score != 250 || incident.Severity != SeverityCritical || !incident.CanaryCorrelated {
		t.Fatalf("canary asymmetry incident = %+v", incident)
	}
	if incident.RuleIDs[0] != StyxBeaconRuleAsymmetry || len(incident.RuleIDs) != 1 {
		t.Fatalf("canary asymmetry rules = %v", incident.RuleIDs)
	}
}

func TestBeaconAsymmetryBelowRatioThreshold(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, true, false, true)
	sample := periodicSample(55, 1<<20)
	sample.RxBytes = 1 << 19 // ratio 2, far below the documented 8
	sample.RxObservationAvailable = true
	if _, emitted := feedStyle(t, engine, clock, 60*time.Second, sample); emitted {
		t.Fatal("asymmetry fired below the documented ratio threshold")
	}
}

func TestBeaconDirectIPRequiresDNSObservation(t *testing.T) {
	// Phase 1: no DNS attribution => signal 3 is unknown and never fires.
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, false, true)
	sample := periodicSample(12, 128<<10)
	if _, emitted := feedStyle(t, engine, clock, 60*time.Second, sample); emitted {
		t.Fatal("DIRECT_IP_NO_DNS fired while DNS observation is unavailable")
	}
	dnsEngine, dnsClock := newBeaconTestEngine(t, StyxModeObserve, false, true, true)
	incident, emitted := feedStyle(t, dnsEngine, dnsClock, 60*time.Second, sample)
	if !emitted {
		t.Fatal("DIRECT_IP_NO_DNS did not fire with DNS observation available")
	}
	if incident.Score != 80 || incident.EventType != StyxBeaconEventDirectIP || incident.RuleIDs[0] != StyxBeaconRuleDirectIP {
		t.Fatalf("direct-IP incident = %+v", incident)
	}
}

func TestBeaconSignalCombinationContain(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeEnforce, false, true, true)
	var incidents []StyxIncident
	for index := 0; index < 14; index++ {
		if incident, emitted := feedStyle(t, engine, clock, 60*time.Second, periodicSample(31, 8192)); emitted {
			incidents = append(incidents, incident)
		}
	}
	if len(incidents) < 2 {
		t.Fatalf("expected a direct-IP and a combined incident, got %d", len(incidents))
	}
	combined := incidents[len(incidents)-1]
	if combined.Score != 250 || combined.Decision != StyxDecisionContain || combined.Severity != SeverityCritical {
		t.Fatalf("combined incident = %+v", combined)
	}
	if len(combined.Signals) != 2 || len(combined.RuleIDs) != 2 {
		t.Fatalf("combined signals/rules = %v / %v", combined.Signals, combined.RuleIDs)
	}
}

func TestBeaconDedupe(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, true, true)
	var emitted int
	for index := 0; index < 14; index++ {
		if _, ok := feedStyle(t, engine, clock, 60*time.Second, periodicSample(500, 1024)); ok {
			emitted++
		}
	}
	if emitted != 1 {
		t.Fatalf("dedupe emitted %d incidents within the window, want 1", emitted)
	}
	status := engine.Status()
	if status.IncidentTotal != 1 || status.SuppressedTotal == 0 {
		t.Fatalf("dedupe status = %+v", status)
	}
}

func TestBeaconIncidentRateLimit(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, true, true)
	clock.Advance(time.Second)
	emitted := 0
	for index := 0; index < 10; index++ {
		sample := periodicSample(700+index, 128<<10)
		sample.Timestamp = clock.Now()
		if _, ok := engine.Observe(sample); ok {
			emitted++
		}
	}
	if emitted != MaxIncidentsPerMinute {
		t.Fatalf("emitted %d incidents, want the documented limit %d", emitted, MaxIncidentsPerMinute)
	}
	status := engine.Status()
	if status.IncidentTotal != uint64(MaxIncidentsPerMinute) || status.SuppressedTotal == 0 {
		t.Fatalf("rate-limit status = %+v", status)
	}
}

func TestBeaconDegradedSuppressesFindings(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, true, true)
	for index := 0; index < 3; index++ {
		engine.RecordFlowPoll(4)
	}
	for index := 0; index < 14; index++ {
		if _, emitted := feedStyle(t, engine, clock, 60*time.Second, periodicSample(41, 128<<10)); emitted {
			t.Fatal("degraded sensor emitted an incident")
		}
	}
	status := engine.Status()
	if !status.Degraded || status.SuppressedTotal == 0 || status.IncidentTotal != 0 {
		t.Fatalf("degraded status = %+v", status)
	}
	if status.OverflowTotal == 0 {
		t.Fatal("overflow records were not retained")
	}
}

func TestBeaconCapabilitySettersAndSettings(t *testing.T) {
	engine, _ := newBeaconTestEngine(t, StyxModeObserve, false, false, false)
	engine.SetRxObservationAvailable(true)
	engine.SetDNSObservationAvailable(true)
	engine.SetCanaryCorrelation(func(pid int, since time.Time) bool { return false })
	status := engine.Status()
	if !status.RxObservationAvailable || !status.DNSObservationAvailable || !status.CanaryCorrelationAvailable {
		t.Fatalf("capability projection = %+v", status)
	}
	engine.SetCanaryCorrelation(nil)
	if engine.Status().CanaryCorrelationAvailable {
		t.Fatal("cleared canary hook is still reported as available")
	}
	if err := engine.SetSettings(StyxSettings{Enabled: true, Mode: "broken"}); err == nil {
		t.Fatal("invalid settings revision accepted")
	}
	off := DefaultStyxSettings()
	if err := engine.SetSettings(off); err != nil {
		t.Fatalf("SetSettings(off): %v", err)
	}
	if state := engine.SensorState(); state != "unavailable" {
		t.Fatalf("disabled engine sensor state = %q", state)
	}
}

func TestBeaconSettingsModeApplies(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, false, true)
	off := enabledStyxSettings()
	off.Mode = StyxModeOff
	off.Enabled = false
	if err := engine.SetSettings(off); err != nil {
		t.Fatalf("SetSettings(off): %v", err)
	}
	if state := engine.SensorState(); state != "unavailable" {
		t.Fatalf("off sensor state = %q, want unavailable", state)
	}
	if _, emitted := feedStyle(t, engine, clock, 60*time.Second, periodicSample(1, 512)); emitted {
		t.Fatal("off engine emitted an incident")
	}
}

func TestBeaconPruneExpiresFlows(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, false, true)
	feedStyle(t, engine, clock, time.Second, periodicSample(9, 128))
	if engine.Status().FlowsTracked != 1 {
		t.Fatalf("flows tracked = %d, want 1", engine.Status().FlowsTracked)
	}
	clock.Advance(FlowTTL + time.Second)
	engine.Prune(clock.Now())
	if flows := engine.Status().FlowsTracked; flows != 0 {
		t.Fatalf("flows tracked after TTL prune = %d, want 0", flows)
	}
}

func TestBeaconObserveBatch(t *testing.T) {
	engine, clock := newBeaconTestEngine(t, StyxModeObserve, false, true, true)
	clock.Advance(time.Second)
	samples := make([]StyxFlowSample, 0, 3)
	for index := 0; index < 3; index++ {
		sample := periodicSample(800+index, 128<<10)
		sample.Timestamp = clock.Now()
		samples = append(samples, sample)
	}
	incidents := engine.ObserveBatch(samples)
	if len(incidents) != 3 {
		t.Fatalf("ObserveBatch emitted %d incidents, want 3", len(incidents))
	}
	if incidents := engine.ObserveBatch(nil); incidents != nil {
		t.Fatalf("ObserveBatch(nil) = %v", incidents)
	}
}

func TestBeaconNilSafety(t *testing.T) {
	var engine *StyxBeaconEngine
	if engine.SensorState() != "unavailable" {
		t.Fatal("nil engine sensor state")
	}
	if _, emitted := engine.Observe(periodicSample(1, 10)); emitted {
		t.Fatal("nil engine emitted an incident")
	}
	if incidents := engine.ObserveBatch([]StyxFlowSample{periodicSample(1, 10)}); incidents != nil {
		t.Fatal("nil engine ObserveBatch returned incidents")
	}
	engine.SetCanaryCorrelation(nil)
	engine.SetFlowCapabilityKnown(true)
	engine.SetRxObservationAvailable(true)
	engine.SetDNSObservationAvailable(true)
	engine.RecordFlowPoll(0)
	engine.Prune(time.Time{})
	snapshot := engine.Snapshot()
	if snapshot.SensorState != "unavailable" || snapshot.Top == nil {
		t.Fatalf("nil engine snapshot = %+v", snapshot)
	}
	status := engine.Status()
	if status.SensorState != "unavailable" || status.Capability != "missing" || status.Top == nil {
		t.Fatalf("nil engine status = %+v", status)
	}
	if err := engine.SetSettings(DefaultStyxSettings()); err == nil {
		t.Fatal("nil engine accepted settings")
	}
}

func TestBeaconConcurrentObserve(t *testing.T) {
	engine, _ := newBeaconTestEngine(t, StyxModeObserve, true, true, true)
	engine.SetCanaryCorrelation(func(pid int, since time.Time) bool { return pid%3 == 0 })
	var waitGroup sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			start := time.Now().UTC()
			for sampleIndex := 0; sampleIndex < 200; sampleIndex++ {
				sample := periodicSample(900+worker, 4096)
				sample.Timestamp = start.Add(time.Duration(sampleIndex) * time.Minute)
				engine.Observe(sample)
				if sampleIndex%50 == 0 {
					_ = engine.Status()
					_ = engine.Snapshot()
				}
			}
		}(worker)
	}
	waitGroup.Wait()
	status := engine.Status()
	if status.FlowsTracked != 8 {
		t.Fatalf("concurrent status flows = %d, want 8", status.FlowsTracked)
	}
	if status.EventsTotal != 1600 {
		t.Fatalf("concurrent events total = %d, want 1600", status.EventsTotal)
	}
}
