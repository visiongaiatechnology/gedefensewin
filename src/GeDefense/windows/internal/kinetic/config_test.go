// STATUS: DIAMANT VGT SUPREME
package kinetic

import (
	"testing"
	"time"
)

func TestDefaultConfigPreservesHistoricalThresholds(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.BurstWindowSeconds != 10 || cfg.MinEvents != 12 || cfg.MinDistinctPorts != 3 || cfg.AutoDisarmSeconds != 0 {
		t.Fatalf("default kinetic config changed: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default kinetic config rejected: %v", err)
	}
	if cfg.BurstWindow() != 10*time.Second || cfg.AutoDisarm() != 0 {
		t.Fatalf("duration projection changed: %+v", cfg)
	}
}

func TestConfigValidationRejectsOutOfBoundsAndUnreachablePolicies(t *testing.T) {
	valid := []Config{
		DefaultConfig(),
		{BurstWindowSeconds: MinBurstWindowSeconds, MinEvents: MinEvents, MinDistinctPorts: MinDistinctPorts, AutoDisarmSeconds: AutoDisarmDisabled},
		{BurstWindowSeconds: MaxBurstWindowSeconds, MinEvents: MaxEvents, MinDistinctPorts: MaxDistinctPorts, AutoDisarmSeconds: MaxAutoDisarmSeconds},
	}
	for _, cfg := range valid {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid kinetic config rejected: %+v: %v", cfg, err)
		}
	}
	invalid := []Config{
		{BurstWindowSeconds: MinBurstWindowSeconds - 1, MinEvents: 12, MinDistinctPorts: 3},
		{BurstWindowSeconds: MaxBurstWindowSeconds + 1, MinEvents: 12, MinDistinctPorts: 3},
		{BurstWindowSeconds: 10, MinEvents: MinEvents - 1, MinDistinctPorts: 2},
		{BurstWindowSeconds: 10, MinEvents: MaxEvents + 1, MinDistinctPorts: 3},
		{BurstWindowSeconds: 10, MinEvents: 12, MinDistinctPorts: MinDistinctPorts - 1},
		{BurstWindowSeconds: 10, MinEvents: 12, MinDistinctPorts: MaxDistinctPorts + 1},
		// Port diversity above the event threshold can never be reached.
		{BurstWindowSeconds: 10, MinEvents: 4, MinDistinctPorts: 8},
		// A non-zero auto-disarm window below the enforced minimum.
		{BurstWindowSeconds: 10, MinEvents: 12, MinDistinctPorts: 3, AutoDisarmSeconds: MinAutoDisarmSeconds - 1},
		{BurstWindowSeconds: 10, MinEvents: 12, MinDistinctPorts: 3, AutoDisarmSeconds: MaxAutoDisarmSeconds + 1},
	}
	for _, cfg := range invalid {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe kinetic config accepted: %+v", cfg)
		}
	}
}

func TestLimitsEnvelopeContainsDefaultsAndDisabledValue(t *testing.T) {
	limits := DefaultConfig().Limits()
	cfg := DefaultConfig()
	if cfg.BurstWindowSeconds < limits.BurstWindowSeconds.Min || cfg.BurstWindowSeconds > limits.BurstWindowSeconds.Max {
		t.Fatalf("default burst window outside published limits: %+v", limits)
	}
	if cfg.MinEvents < limits.MinEvents.Min || cfg.MinEvents > limits.MinEvents.Max {
		t.Fatalf("default min events outside published limits: %+v", limits)
	}
	if cfg.MinDistinctPorts < limits.MinDistinctPorts.Min || cfg.MinDistinctPorts > limits.MinDistinctPorts.Max {
		t.Fatalf("default port diversity outside published limits: %+v", limits)
	}
	if limits.AutoDisarmDisabledValue != AutoDisarmDisabled || limits.AutoDisarmSeconds.Min >= limits.AutoDisarmSeconds.Max {
		t.Fatalf("published auto-disarm limits invalid: %+v", limits)
	}
}

func TestMonitorConfigureControlsClassification(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	monitor := NewMonitor()
	if monitor.Config() != DefaultConfig() {
		t.Fatalf("new monitor did not start with default config: %+v", monitor.Config())
	}
	// The historical threshold needs 12 events; three port-diverse blocks must
	// not classify under the default policy.
	for i := 0; i < 3; i++ {
		if monitor.ObserveBlockedInbound("203.0.113.9", uint16(1000+i*10), now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatal("default policy classified a three-event burst")
		}
	}
	strict := Config{BurstWindowSeconds: 5, MinEvents: 3, MinDistinctPorts: 2, AutoDisarmSeconds: 0}
	if err := monitor.Configure(strict); err != nil {
		t.Fatal(err)
	}
	if monitor.Config() != strict {
		t.Fatalf("configured policy not retained: %+v", monitor.Config())
	}
	// Configure discards samples from the previous policy, so classification
	// has to be rebuilt from fresh verified observations.
	if monitor.ObserveBlockedInbound("203.0.113.9", 2000, now.Add(100*time.Millisecond)) {
		t.Fatal("previous-policy samples were reused after reconfiguration")
	}
	if monitor.ObserveBlockedInbound("203.0.113.9", 2001, now.Add(101*time.Millisecond)) {
		t.Fatal("candidate classified before the configured event count")
	}
	if !monitor.ObserveBlockedInbound("203.0.113.9", 2002, now.Add(102*time.Millisecond)) {
		t.Fatal("configured burst threshold was not honoured after reset")
	}
}

func TestMonitorConfigureRejectsInvalidPolicyAndKeepsPrevious(t *testing.T) {
	monitor := NewMonitor()
	previous := monitor.Config()
	if err := monitor.Configure(Config{BurstWindowSeconds: 0}); err == nil {
		t.Fatal("invalid kinetic policy accepted")
	}
	if monitor.Config() != previous {
		t.Fatal("invalid policy replaced the active policy")
	}
	var unavailable *Monitor
	if err := unavailable.Configure(DefaultConfig()); err == nil {
		t.Fatal("nil monitor accepted a policy")
	}
	if unavailable.Config() != DefaultConfig() || unavailable.Snapshot().Config != DefaultConfig() {
		t.Fatal("nil monitor did not expose fail-safe defaults")
	}
}

func TestMonitorSnapshotCarriesEffectiveConfig(t *testing.T) {
	monitor := NewMonitor()
	configured := Config{BurstWindowSeconds: 20, MinEvents: 8, MinDistinctPorts: 4, AutoDisarmSeconds: 600}
	if err := monitor.Configure(configured); err != nil {
		t.Fatal(err)
	}
	if snapshot := monitor.Snapshot(); snapshot.Config != configured || snapshot.Mode != "OBSERVE_ONLY" {
		t.Fatalf("snapshot did not carry the effective observation policy: %+v", snapshot)
	}
}

func TestEvaluateArmingRequirementsFailsClosed(t *testing.T) {
	generation := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ready := ArmingInputs{WFPRealtime: true, NetworkRealtime: true, EnforcementState: "VERIFIED", ActiveGeneration: generation, DesiredGeneration: generation, FeedEnforcementGeneration: generation, BlockingIndicators: 42}
	if result := EvaluateArmingRequirements(ready); !result.Ready || len(result.Blockers) != 0 || !result.EnforcementVerified {
		t.Fatalf("verified generation did not satisfy arming requirements: %+v", result)
	}
	cleanupPending := ready
	cleanupPending.EnforcementState = "VERIFIED_CLEANUP_PENDING"
	if result := EvaluateArmingRequirements(cleanupPending); !result.Ready {
		t.Fatalf("cleanup-pending verified generation rejected: %+v", result)
	}
	cases := map[string]func(*ArmingInputs){
		"wfp telemetry":     func(in *ArmingInputs) { in.WFPRealtime = false },
		"network telemetry": func(in *ArmingInputs) { in.NetworkRealtime = false },
		"unverified state":  func(in *ArmingInputs) { in.EnforcementState = "UNVERIFIED" },
		"missing active":    func(in *ArmingInputs) { in.ActiveGeneration = "" },
		"generation mismatch": func(in *ArmingInputs) {
			in.ActiveGeneration = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"feed mismatch": func(in *ArmingInputs) { in.FeedEnforcementGeneration = "" },
		"no indicators": func(in *ArmingInputs) { in.BlockingIndicators = 0 },
	}
	for name, mutate := range cases {
		input := ready
		mutate(&input)
		result := EvaluateArmingRequirements(input)
		if result.Ready || len(result.Blockers) == 0 {
			t.Fatalf("%s case incorrectly satisfied arming requirements: %+v", name, result)
		}
	}
}
