package kinetic

import (
	"fmt"
	"testing"
	"time"
)

func TestCandidatesNeedBurstAndPortDiversity(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	m := NewMonitor()
	for i := 0; i < 11; i++ {
		if m.ObserveBlockedInbound("203.0.113.5", uint16(1000+i%3), now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatal("premature candidate")
		}
	}
	if !m.ObserveBlockedInbound("203.0.113.5", 1002, now.Add(11*time.Millisecond)) {
		t.Fatal("candidate missing")
	}
	if m.ObserveBlockedInbound("203.0.113.5", 1003, now.Add(12*time.Millisecond)) {
		t.Fatal("duplicate")
	}
	snap := m.Snapshot()
	if snap.BlocksObserved != 13 || snap.BurstCandidates != 1 || snap.Mode != "OBSERVE_ONLY" {
		t.Fatal(snap)
	}
}
func TestSinglePortAndQuietPeriod(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	m := NewMonitor()
	for i := 0; i < 30; i++ {
		if m.ObserveBlockedInbound("203.0.113.8", 443, now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatal("single port not diverse")
		}
	}
	for i := 0; i < 12; i++ {
		got := m.ObserveBlockedInbound("203.0.113.8", uint16(2000+i%3), now.Add(12*time.Second+time.Duration(i)*time.Millisecond))
		if i == 11 && !got {
			t.Fatal("quiet window did not reset")
		}
	}
}

func TestPortlessBlocksRemainVisibleWithoutInventingBursts(t *testing.T) {
	m := NewMonitor()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		if m.ObserveBlockedInbound("8.8.8.8", 0, now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatal("a portless block cannot prove a port-diverse burst")
		}
	}
	snapshot := m.Snapshot()
	if snapshot.BlocksObserved != 20 || snapshot.TrackedSources != 1 || snapshot.BurstCandidates != 0 {
		t.Fatalf("portless WFP observations disappeared: %+v", snapshot)
	}
	rows := m.SourceSnapshot(250)
	if len(rows) != 1 || rows[0].IP != "8.8.8.8" || rows[0].Hits != 20 || rows[0].PortlessBlocks != 20 || rows[0].LastPort != 0 {
		t.Fatalf("incorrect portless source detail: %+v", rows)
	}
}

func TestSourceSnapshotIsBoundedSortedAndDetached(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	m.ObserveBlockedInbound("8.8.8.8", 443, now)
	m.ObserveBlockedInbound("1.1.1.1", 0, now.Add(time.Second))
	rows := m.SourceSnapshot(1)
	if len(rows) != 1 || rows[0].IP != "1.1.1.1" {
		t.Fatal(rows)
	}
	rows[0].Hits = 900
	if m.SourceSnapshot(1)[0].Hits != 1 {
		t.Fatal("snapshot mutates monitor state")
	}
	m.ObserveBlockedInbound("1.1.1.1", 80, now)
	if m.SourceSnapshot(1)[0].Hits != 1 {
		t.Fatal("old observation replaced the current source")
	}
}
func TestSourceCountIsBounded(t *testing.T) {
	m := NewMonitor()
	now := time.Now().UTC()
	for i := 0; i < maxSources+5; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65025, (i/255)%255, i%255+1)
		m.ObserveBlockedInbound(ip, 80, now.Add(time.Duration(i)*time.Millisecond))
	}
	got := m.Snapshot()
	if got.TrackedSources > maxSources || got.DroppedSamples == 0 {
		t.Fatal(got)
	}
}
func TestInvalidInputAndReadiness(t *testing.T) {
	m := NewMonitor()
	for _, v := range []string{"not-ip", "::1", "0.0.0.0", "224.0.0.1"} {
		if m.ObserveBlockedInbound(v, 443, time.Now()) {
			t.Fatal(v)
		}
	}
	if m.Snapshot().BlocksObserved != 0 {
		t.Fatal("invalid input counted")
	}
	r := EvaluateReadiness(true, true, 0, "VERIFIED", "a", "a")
	if r.ThreatRules != "UNVERIFIED" || r.WFPAudit != "POLLING_AUDIT_NOT_VERIFIED" || r.Ingress != "UNVERIFIED_NO_RAW_INGRESS_SENSOR" {
		t.Fatal(r)
	}
	h := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	r = EvaluateReadiness(true, true, 4, "VERIFIED", h, h)
	if r.ThreatRules != "GENERATION_VERIFIED" || r.WFPAudit != "BLOCK_EVENTS_OBSERVED" {
		t.Fatal(r)
	}
}
