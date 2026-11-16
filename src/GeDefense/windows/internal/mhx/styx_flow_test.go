// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"math"
	"net/netip"
	"testing"
	"time"
)

func TestFlowAggregateWelford(t *testing.T) {
	aggregate := &FlowAggregate{}
	for _, interval := range []float64{10, 20, 30} {
		aggregate.ObserveInterval(interval)
	}
	if aggregate.Samples != 3 {
		t.Fatalf("samples = %d, want 3", aggregate.Samples)
	}
	if mean := aggregate.IntervalMean(); math.Abs(mean-20) > 1e-9 {
		t.Fatalf("mean = %v, want 20", mean)
	}
	// Population variance of {10,20,30} = 200/3.
	wantStddev := math.Sqrt(200.0 / 3.0)
	if stddev := aggregate.IntervalStddev(); math.Abs(stddev-wantStddev) > 1e-9 {
		t.Fatalf("stddev = %v, want %v", stddev, wantStddev)
	}
	wantCV := wantStddev / 20
	if cv := aggregate.IntervalCV(); math.Abs(cv-wantCV) > 1e-9 {
		t.Fatalf("CV = %v, want %v", cv, wantCV)
	}
}

func TestFlowAggregateCVHonesty(t *testing.T) {
	aggregate := &FlowAggregate{}
	if cv := aggregate.IntervalCV(); !math.IsInf(cv, 1) {
		t.Fatalf("CV with no samples = %v, want +Inf", cv)
	}
	aggregate.ObserveInterval(15)
	if cv := aggregate.IntervalCV(); !math.IsInf(cv, 1) {
		t.Fatalf("CV with one sample = %v, want +Inf", cv)
	}
	if stddev := aggregate.IntervalStddev(); stddev != 0 {
		t.Fatalf("stddev with one sample = %v, want 0", stddev)
	}
	// Perfectly periodic traffic has CV 0.
	periodic := &FlowAggregate{}
	for index := 0; index < 10; index++ {
		periodic.ObserveInterval(60)
	}
	if cv := periodic.IntervalCV(); cv != 0 {
		t.Fatalf("perfectly periodic CV = %v, want 0", cv)
	}
}

func TestFlowAggregateRejectsInvalidIntervals(t *testing.T) {
	aggregate := &FlowAggregate{}
	aggregate.ObserveInterval(0)
	aggregate.ObserveInterval(-5)
	aggregate.ObserveInterval(math.NaN())
	aggregate.ObserveInterval(math.Inf(1))
	if aggregate.Samples != 0 {
		t.Fatalf("invalid intervals were counted: samples=%d", aggregate.Samples)
	}
}

func TestSaturatingAddAndByteAccounting(t *testing.T) {
	if got := saturatingAdd(1, 2); got != 3 {
		t.Fatalf("saturatingAdd(1,2)=%d", got)
	}
	if got := saturatingAdd(^uint64(0), 1); got != ^uint64(0) {
		t.Fatalf("saturatingAdd overflow = %d, want saturated", got)
	}
	var aggregate FlowAggregate
	aggregate.AddTxBytes(100)
	aggregate.AddRxBytes(0)
	if !aggregate.TxObservationAvailable || !aggregate.RxObservationAvailable {
		t.Fatal("byte accounting did not mark observation as available")
	}
	if aggregate.TxBytes != 100 || aggregate.RxBytes != 0 {
		t.Fatalf("byte counters = tx %d rx %d", aggregate.TxBytes, aggregate.RxBytes)
	}
	aggregate.AddTxBytes(^uint64(0))
	if aggregate.TxBytes != ^uint64(0) {
		t.Fatalf("tx counter wrapped: %d", aggregate.TxBytes)
	}
}

func TestFlowKey(t *testing.T) {
	key := FlowKey{PID: 42, RemoteIP: netip.MustParseAddr("203.0.113.7"), RemotePort: 443, Proto: styxProtoTCP}
	if !key.Valid() {
		t.Fatal("valid TCP key rejected")
	}
	if key.Remote() != "203.0.113.7:443" {
		t.Fatalf("Remote()=%q", key.Remote())
	}
	if key.String() != "pid=42|203.0.113.7:443|proto=6" {
		t.Fatalf("String()=%q", key.String())
	}
	neutral := FlowKey{PID: 42, RemoteIP: netip.MustParseAddr("203.0.113.7"), Proto: styxProtoUnknown}
	if !neutral.Valid() || neutral.Remote() != "203.0.113.7" {
		t.Fatalf("neutral key invalid: %v", neutral)
	}
	if (FlowKey{PID: -1, RemoteIP: netip.MustParseAddr("203.0.113.7"), Proto: styxProtoTCP}).Valid() {
		t.Fatal("negative pid accepted")
	}
	if (FlowKey{PID: 1, Proto: styxProtoTCP}).Valid() {
		t.Fatal("invalid address accepted")
	}
	if (FlowKey{PID: 1, RemoteIP: netip.MustParseAddr("203.0.113.7"), RemotePort: 443, Proto: 99}).Valid() {
		t.Fatal("unknown protocol accepted")
	}
	if (FlowKey{PID: 1, RemoteIP: netip.MustParseAddr("203.0.113.7"), RemotePort: 443, Proto: styxProtoUnknown}).Valid() {
		t.Fatal("neutral key with a port accepted")
	}
}

func TestStyxFlowSampleFlowKey(t *testing.T) {
	sample := StyxFlowSample{PID: 7, Remote: netip.MustParseAddr("::ffff:203.0.113.7"), RemotePort: 8443, Proto: styxProtoTCP}
	key, err := sample.FlowKey()
	if err != nil {
		t.Fatalf("FlowKey: %v", err)
	}
	if !key.RemoteIP.Is4() || key.RemoteIP.String() != "203.0.113.7" {
		t.Fatalf("mapped remote was not unmapped: %s", key.RemoteIP)
	}
	invalid := []StyxFlowSample{
		{PID: -1, Remote: netip.MustParseAddr("203.0.113.7"), RemotePort: 443, Proto: styxProtoTCP},
		{PID: 1, Remote: netip.MustParseAddr("0.0.0.0"), RemotePort: 443, Proto: styxProtoTCP},
		{PID: 1, Remote: netip.MustParseAddr("203.0.113.7"), RemotePort: 443, Proto: styxProtoUnknown},
		{PID: 1, Remote: netip.MustParseAddr("203.0.113.7"), RemotePort: 443, Proto: 99},
		{PID: 1, Remote: netip.Addr{}, RemotePort: 443, Proto: styxProtoTCP},
	}
	for index, candidate := range invalid {
		if _, err := candidate.FlowKey(); err == nil {
			t.Fatalf("invalid sample %d was accepted", index)
		}
	}
}

func TestStyxFlowTablePerPIDCap(t *testing.T) {
	table := newStyxFlowTable()
	now := time.Unix(1_700_000_000, 0).UTC()
	for index := 0; index < MaxFlowsPerPID; index++ {
		key := FlowKey{PID: 1234, RemoteIP: netip.AddrFrom4([4]byte{203, 0, 113, byte(index)}), RemotePort: uint16(1000 + index), Proto: styxProtoTCP}
		if _, ok := table.acquire(key, now); !ok {
			t.Fatalf("flow %d rejected below the per-PID cap", index)
		}
	}
	overflow := FlowKey{PID: 1234, RemoteIP: netip.MustParseAddr("198.51.100.1"), RemotePort: 443, Proto: styxProtoTCP}
	if _, ok := table.acquire(overflow, now); ok {
		t.Fatal("per-PID flow cap was not enforced")
	}
	otherPID := FlowKey{PID: 5678, RemoteIP: netip.MustParseAddr("198.51.100.1"), RemotePort: 443, Proto: styxProtoTCP}
	if _, ok := table.acquire(otherPID, now); !ok {
		t.Fatal("another identity must not be limited by the first PID cap")
	}
	if table.len() != MaxFlowsPerPID+1 {
		t.Fatalf("table length = %d, want %d", table.len(), MaxFlowsPerPID+1)
	}
}

func TestStyxFlowTableGlobalEviction(t *testing.T) {
	table := newStyxFlowTable()
	now := time.Unix(1_700_000_000, 0).UTC()
	total := MaxTrackedBeaconFlows + 5
	for index := 0; index < total; index++ {
		key := FlowKey{
			PID:        index,
			RemoteIP:   netip.AddrFrom4([4]byte{203, 0, byte(index / 256), byte(index % 256)}),
			RemotePort: 443,
			Proto:      styxProtoTCP,
		}
		if _, ok := table.acquire(key, now); !ok {
			t.Fatalf("flow %d rejected below the global cap", index)
		}
	}
	if table.len() != MaxTrackedBeaconFlows {
		t.Fatalf("table length = %d, want the global cap %d", table.len(), MaxTrackedBeaconFlows)
	}
	if table.evicted != 5 {
		t.Fatalf("evicted = %d, want 5", table.evicted)
	}
}

func TestStyxFlowTableTTLPrune(t *testing.T) {
	table := newStyxFlowTable()
	start := time.Unix(1_700_000_000, 0).UTC()
	oldKey := FlowKey{PID: 1, RemoteIP: netip.MustParseAddr("203.0.113.1"), RemotePort: 443, Proto: styxProtoTCP}
	freshKey := FlowKey{PID: 2, RemoteIP: netip.MustParseAddr("203.0.113.2"), RemotePort: 443, Proto: styxProtoTCP}
	aggregate, ok := table.acquire(oldKey, start)
	if !ok {
		t.Fatal("old flow rejected")
	}
	aggregate.LastSeen = start
	aggregate, ok = table.acquire(freshKey, start.Add(FlowTTL))
	if !ok {
		t.Fatal("fresh flow rejected")
	}
	aggregate.LastSeen = start.Add(FlowTTL)
	removed := table.prune(start.Add(FlowTTL + time.Second))
	if removed != 1 {
		t.Fatalf("prune removed %d flows, want 1", removed)
	}
	if table.len() != 1 {
		t.Fatalf("table length after prune = %d, want 1", table.len())
	}
	if _, ok := table.flows[oldKey]; ok {
		t.Fatal("expired flow survived the TTL prune")
	}
}

func TestStyxFlowTableTop(t *testing.T) {
	table := newStyxFlowTable()
	now := time.Unix(1_700_000_000, 0).UTC()
	for index := 0; index < 12; index++ {
		key := FlowKey{PID: index, RemoteIP: netip.AddrFrom4([4]byte{203, 0, 113, byte(index)}), RemotePort: 443, Proto: styxProtoTCP}
		aggregate, ok := table.acquire(key, now)
		if !ok {
			t.Fatalf("flow %d rejected", index)
		}
		aggregate.LastScore = 80 + index
		aggregate.TxBytes = uint64(index) * 100
	}
	top := table.top(styxStatusTopFlows)
	if len(top) != styxStatusTopFlows {
		t.Fatalf("top length = %d, want %d", len(top), styxStatusTopFlows)
	}
	for index := 1; index < len(top); index++ {
		if top[index-1].Score < top[index].Score {
			t.Fatalf("top list is not sorted by score: %d then %d", top[index-1].Score, top[index].Score)
		}
	}
	if top[0].Score != 91 {
		t.Fatalf("top[0].Score = %d, want 91", top[0].Score)
	}
	if table.top(0) == nil {
		t.Fatal("top(0) must return an empty, non-nil slice")
	}
}

func TestStyxFlowSnapshotJSONSafe(t *testing.T) {
	aggregate := &FlowAggregate{Key: FlowKey{PID: 5, RemoteIP: netip.MustParseAddr("203.0.113.5"), RemotePort: 443, Proto: styxProtoTCP}}
	snapshot := aggregate.snapshot()
	if snapshot.CV != 0 || snapshot.MeanInterval != 0 || snapshot.Stddev != 0 {
		t.Fatalf("unmeasured intervals must project finite zeroes: %+v", snapshot)
	}
	aggregate.ObserveInterval(30)
	aggregate.ObserveInterval(30)
	snapshot = aggregate.snapshot()
	if snapshot.CV != 0 || snapshot.MeanInterval != 30 || snapshot.Samples != 2 {
		t.Fatalf("measured interval projection = %+v", snapshot)
	}
	if snapshot.Remote != "203.0.113.5:443" || snapshot.PID != 5 {
		t.Fatalf("snapshot identity = %+v", snapshot)
	}
}
