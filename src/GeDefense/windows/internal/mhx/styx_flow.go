// STATUS: PLATIN VGT SUPREME
package mhx

// Windows V6 Phase 1: the bounded StyX flow model.
//
// It is the 1:1 semantic port of the Linux V6 detector's flow aggregate
// (control/styx_beacon.go, docs/POINT3-EGRESS-BEACON.md §8.2):
//
//   - Welford online mean/variance over inter-arrival times (no history slices),
//   - population variance and CV = stddev/mean exactly like Linux,
//   - saturating tx/rx byte counters over window deltas,
//   - the same hard bounds: 8192 flows total, 64 flows per identity, TTL 900 s.
//
// Windows has no cgroups; the "per cgroup" cap of the Linux contract is applied
// per process identity (PID), which is the Windows analogue. The exported
// constant names are kept for source parity and documented accordingly.

import (
	"container/list"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"
)

const (
	// MaxTrackedBeaconFlows is the hard ceiling of the detector flow table.
	MaxTrackedBeaconFlows = 8192
	// MaxFlowsPerCgroup is the Linux V6 per-cell cap. On Windows the identity is
	// the process, so it is applied as MaxFlowsPerPID; the name is kept for the
	// 1:1 port and both constants are identical.
	MaxFlowsPerCgroup = 64
	// MaxFlowsPerPID is the Windows per-process flow cap.
	MaxFlowsPerPID = MaxFlowsPerCgroup
	// FlowTTLSeconds is the flow idle eviction TTL (900 s).
	FlowTTLSeconds = 900
	// FlowTTL is FlowTTLSeconds as a duration.
	FlowTTL = FlowTTLSeconds * time.Second
	// MaxIncidentsPerMinute is the detector emission rate limit.
	MaxIncidentsPerMinute = 6
	// DedupeSeconds is the per-fingerprint incident dedupe window (300 s).
	DedupeSeconds = 300

	styxProtoUnknown = 0
	styxProtoTCP     = 6
	styxProtoUDP     = 17
)

// FlowKey identifies one observed egress peer. RemoteIP is always unmapped
// (IPv4-mapped IPv6 is normalised to IPv4), so the same peer can never produce
// two distinct tracked flows.
type FlowKey struct {
	PID        int        `json:"pid"`
	RemoteIP   netip.Addr `json:"remoteIp"`
	RemotePort uint16     `json:"remotePort"`
	Proto      uint8      `json:"proto"`
}

// Valid reports whether the key is a usable flow identity.
func (k FlowKey) Valid() bool {
	if k.PID < 0 || !k.RemoteIP.IsValid() {
		return false
	}
	if k.RemoteIP.Is4In6() || k.RemoteIP.IsUnspecified() {
		return false
	}
	switch k.Proto {
	case styxProtoUnknown:
		return k.RemotePort == 0
	case styxProtoTCP, styxProtoUDP:
		return true
	default:
		return false
	}
}

// Remote renders the peer as ip:port (or bare IP for the neutral protocol).
func (k FlowKey) Remote() string {
	if k.Proto == styxProtoUnknown {
		return k.RemoteIP.String()
	}
	return netip.AddrPortFrom(k.RemoteIP, k.RemotePort).String()
}

// String renders one stable, log-safe flow identity.
func (k FlowKey) String() string {
	return fmt.Sprintf("pid=%d|%s|proto=%d", k.PID, k.Remote(), k.Proto)
}

// StyxFlowSample is one observed window delta for one flow. TxObservationAvailable and
// RxObservationAvailable are honesty flags: a source that cannot prove transmit or receive
// bytes must set them to false instead of reporting guessed zeroes. Timestamp is
// the observation instant; a zero timestamp means "use the detector clock".
type StyxFlowSample struct {
	PID                    int        `json:"pid"`
	Remote                 netip.Addr `json:"remote"`
	RemotePort             uint16     `json:"remotePort"`
	LocalPort              uint16     `json:"localPort,omitempty"`
	Proto                  uint8      `json:"proto"`
	TxBytes                uint64     `json:"txBytes"`
	RxBytes                uint64     `json:"rxBytes"`
	TxObservationAvailable bool       `json:"txObservationAvailable"`
	RxObservationAvailable bool       `json:"rxObservationAvailable"`
	Timestamp              time.Time  `json:"timestamp"`
	Comm                   string     `json:"comm,omitempty"`
	ProcessPath            string     `json:"processPath,omitempty"`
}

// FlowKey validates the sample and returns its canonical flow identity. It is
// the only path from a sample into the detector flow table.
func (s StyxFlowSample) FlowKey() (FlowKey, error) {
	if s.PID < 0 {
		return FlowKey{}, fmt.Errorf("styX flow sample has a negative pid %d", s.PID)
	}
	remote, err := StyxNormalizeDestination(s.Remote)
	if err != nil {
		return FlowKey{}, fmt.Errorf("styX flow sample: %w", err)
	}
	switch s.Proto {
	case styxProtoUnknown:
		if s.RemotePort != 0 {
			return FlowKey{}, errors.New("styX neutral protocol sample must not carry a remote port")
		}
	case styxProtoTCP, styxProtoUDP:
	default:
		return FlowKey{}, fmt.Errorf("styX flow sample protocol %d is not TCP, UDP or neutral", s.Proto)
	}
	key := FlowKey{PID: s.PID, RemoteIP: remote, RemotePort: s.RemotePort, Proto: s.Proto}
	if !key.Valid() {
		return FlowKey{}, errors.New("styX flow sample does not form a valid flow key")
	}
	return key, nil
}

// FlowAggregate is the bounded state of one tracked flow. It stores only
// O(1) statistics: Welford's running mean and M2, the saturating byte counters
// and the last finding. There is no per-packet or per-interval history.
type FlowAggregate struct {
	Key                    FlowKey   `json:"key"`
	Comm                   string    `json:"comm,omitempty"`
	ProcessPath            string    `json:"processPath,omitempty"`
	LocalPort              uint16    `json:"localPort,omitempty"`
	FirstSeen              time.Time `json:"firstSeen"`
	LastSeen               time.Time `json:"lastSeen"`
	Samples                int64     `json:"samples"`
	TxBytes                uint64    `json:"txBytes"`
	RxBytes                uint64    `json:"rxBytes"`
	TxObservationAvailable bool      `json:"txObservationAvailable"`
	RxObservationAvailable bool      `json:"rxObservationAvailable"`
	DNSSeen                bool      `json:"dnsSeen"`
	LastScore              int       `json:"lastScore"`
	LastSignals            []string  `json:"lastSignals,omitempty"`

	intervalMean float64
	intervalM2   float64
	lastRules    []string
	lastEvent    string
	lastCategory string
	lastDecision string
}

// ObserveInterval feeds one positive inter-arrival time in seconds into the
// Welford accumulator. Non-positive, NaN and infinite values are ignored.
func (a *FlowAggregate) ObserveInterval(seconds float64) {
	if a == nil || seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return
	}
	a.Samples++
	delta := seconds - a.intervalMean
	a.intervalMean += delta / float64(a.Samples)
	a.intervalM2 += delta * (seconds - a.intervalMean)
}

// IntervalMean is the running mean inter-arrival time in seconds.
func (a *FlowAggregate) IntervalMean() float64 {
	if a == nil {
		return 0
	}
	return a.intervalMean
}

// IntervalStddev is the population standard deviation (M2/n), matching the
// Linux V6 detector; it is 0 while fewer than two intervals exist.
func (a *FlowAggregate) IntervalStddev() float64 {
	if a == nil || a.Samples < 2 {
		return 0
	}
	variance := a.intervalM2 / float64(a.Samples)
	if variance <= 0 || math.IsNaN(variance) || math.IsInf(variance, 0) {
		return 0
	}
	return math.Sqrt(variance)
}

// IntervalCV is the coefficient of variation stddev/mean. It returns +Inf when
// fewer than two intervals exist or the mean is not positive, exactly like the
// Linux V6 detector (callers must compare with a threshold, never print it).
func (a *FlowAggregate) IntervalCV() float64 {
	if a == nil || a.Samples < 2 || a.intervalMean <= 0 {
		return math.Inf(1)
	}
	stddev := a.IntervalStddev()
	if stddev == 0 {
		return 0
	}
	cv := stddev / a.intervalMean
	if math.IsNaN(cv) || math.IsInf(cv, 0) {
		return math.Inf(1)
	}
	return cv
}

// AddTxBytes accumulates one observed tx window delta (saturating) and marks
// transmit observation as available for this flow.
func (a *FlowAggregate) AddTxBytes(bytes uint64) {
	if a == nil {
		return
	}
	a.TxObservationAvailable = true
	a.TxBytes = saturatingAdd(a.TxBytes, bytes)
}

// AddRxBytes accumulates one observed rx window delta (saturating) and marks
// receive observation as available for this flow. A source that cannot read rx
// bytes must not call it.
func (a *FlowAggregate) AddRxBytes(bytes uint64) {
	if a == nil {
		return
	}
	a.RxObservationAvailable = true
	a.RxBytes = saturatingAdd(a.RxBytes, bytes)
}

// saturatingAdd adds two byte counters without wrapping.
func saturatingAdd(left, right uint64) uint64 {
	if sum := left + right; sum >= left {
		return sum
	}
	return ^uint64(0)
}

// StyxFlowSnapshot is the bounded per-flow projection used by the status view.
// It is a copy: no pointer into the detector state leaves the engine.
type StyxFlowSnapshot struct {
	PID                    int      `json:"pid"`
	Remote                 string   `json:"remote"`
	Proto                  uint8    `json:"proto"`
	TxBytes                uint64   `json:"txBytes"`
	RxBytes                uint64   `json:"rxBytes"`
	TxObservationAvailable bool     `json:"txObservationAvailable"`
	RxObservationAvailable bool     `json:"rxObservationAvailable"`
	Samples                int64    `json:"samples"`
	MeanInterval           float64  `json:"meanIntervalSeconds"`
	Stddev                 float64  `json:"stddevIntervalSeconds"`
	CV                     float64  `json:"intervalCv"`
	Score                  int      `json:"score"`
	Signals                []string `json:"signals,omitempty"`
	Process                string   `json:"process,omitempty"`
	ProcessPath            string   `json:"processPath,omitempty"`
	LocalPort              uint16   `json:"localPort,omitempty"`
}

func (a *FlowAggregate) snapshot() StyxFlowSnapshot {
	if a == nil {
		return StyxFlowSnapshot{}
	}
	out := StyxFlowSnapshot{
		PID:                    a.Key.PID,
		Remote:                 a.Key.Remote(),
		Proto:                  a.Key.Proto,
		TxBytes:                a.TxBytes,
		RxBytes:                a.RxBytes,
		TxObservationAvailable: a.TxObservationAvailable,
		RxObservationAvailable: a.RxObservationAvailable,
		Samples:                a.Samples,
		MeanInterval:           finiteOrZero(a.IntervalMean()),
		Stddev:                 finiteOrZero(a.IntervalStddev()),
		Score:                  a.LastScore,
		Signals:                append([]string(nil), a.LastSignals...),
		Process:                a.Comm,
		ProcessPath:            a.ProcessPath,
		LocalPort:              a.LocalPort,
	}
	out.CV = finiteOrZero(a.IntervalCV())
	return out
}

// finiteOrZero makes a float JSON-safe: +Inf/-Inf/NaN become 0. The accompanying
// sample counter tells the operator whether the value was measured at all.
func finiteOrZero(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

// styxFlowTable is the bounded FIFO/LRU table of tracked flows. The list order
// is access order (front = most recent) and therefore doubles as the TTL order:
// pruning walks the back while entries are expired.
type styxFlowTable struct {
	flows   map[FlowKey]*list.Element
	order   *list.List
	perPID  map[int]int
	evicted uint64
}

func newStyxFlowTable() *styxFlowTable {
	return &styxFlowTable{
		flows:  make(map[FlowKey]*list.Element, 64),
		order:  list.New(),
		perPID: make(map[int]int, 64),
	}
}

// acquire returns the aggregate for key, creating it when capacity allows. The
// second return value is false when the per-PID cap rejects a new flow; the
// global cap evicts the least recently used flow instead.
func (t *styxFlowTable) acquire(key FlowKey, now time.Time) (*FlowAggregate, bool) {
	if element, exists := t.flows[key]; exists {
		t.order.MoveToFront(element)
		return element.Value.(*FlowAggregate), true
	}
	if t.perPID[key.PID] >= MaxFlowsPerPID {
		return nil, false
	}
	if t.order.Len() >= MaxTrackedBeaconFlows {
		if victim := t.order.Back(); victim != nil {
			t.remove(victim)
			t.evicted++
		}
	}
	aggregate := &FlowAggregate{Key: key, FirstSeen: now, LastSeen: now}
	element := t.order.PushFront(aggregate)
	t.flows[key] = element
	t.perPID[key.PID]++
	return aggregate, true
}

func (t *styxFlowTable) remove(element *list.Element) {
	aggregate, ok := element.Value.(*FlowAggregate)
	if !ok {
		return
	}
	t.order.Remove(element)
	delete(t.flows, aggregate.Key)
	if count := t.perPID[aggregate.Key.PID]; count > 1 {
		t.perPID[aggregate.Key.PID] = count - 1
	} else {
		delete(t.perPID, aggregate.Key.PID)
	}
}

// prune expires every flow whose last activity is older than the TTL.
func (t *styxFlowTable) prune(now time.Time) int {
	cutoff := now.Add(-FlowTTL)
	removed := 0
	for element := t.order.Back(); element != nil; {
		previous := element.Prev()
		aggregate, ok := element.Value.(*FlowAggregate)
		if !ok || !aggregate.LastSeen.Before(cutoff) {
			break
		}
		t.remove(element)
		removed++
		element = previous
	}
	return removed
}

func (t *styxFlowTable) len() int {
	if t == nil {
		return 0
	}
	return t.order.Len()
}

// top returns the bounded score projection of the table, highest score first.
func (t *styxFlowTable) top(limit int) []StyxFlowSnapshot {
	snapshots := make([]StyxFlowSnapshot, 0, limit)
	if t == nil || limit <= 0 {
		return snapshots
	}
	for element := t.order.Front(); element != nil; element = element.Next() {
		aggregate, ok := element.Value.(*FlowAggregate)
		if !ok || aggregate.LastScore <= 0 {
			continue
		}
		snapshots = append(snapshots, aggregate.snapshot())
	}
	sortStyxFlowSnapshots(snapshots)
	if len(snapshots) > limit {
		snapshots = snapshots[:limit]
	}
	return snapshots
}

// sortStyxFlowSnapshots orders by score, then tx volume, then identity.
func sortStyxFlowSnapshots(snapshots []StyxFlowSnapshot) {
	for i := 1; i < len(snapshots); i++ {
		current := snapshots[i]
		j := i - 1
		for j >= 0 && styxFlowSnapshotLess(current, snapshots[j]) {
			snapshots[j+1] = snapshots[j]
			j--
		}
		snapshots[j+1] = current
	}
}

// styxFlowSnapshotLess orders by score, then tx volume, then identity.
func styxFlowSnapshotLess(left, right StyxFlowSnapshot) bool {
	if left.Score != right.Score {
		return left.Score > right.Score
	}
	if left.TxBytes != right.TxBytes {
		return left.TxBytes > right.TxBytes
	}
	if left.PID != right.PID {
		return left.PID < right.PID
	}
	return left.Remote < right.Remote
}
