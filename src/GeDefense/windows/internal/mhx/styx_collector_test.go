// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

type fakeStyxSource struct {
	mu            sync.Mutex
	connections   []winapi.TCPConnection
	connectionErr error
	enableErrs    map[uint16]error
	statsErrs     map[uint16]error
	stats         map[uint16]winapi.TCPConnDataStats
	enableCalls   int
}

func (f *fakeStyxSource) TCPConnections() ([]winapi.TCPConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connectionErr != nil {
		return nil, f.connectionErr
	}
	return append([]winapi.TCPConnection(nil), f.connections...), nil
}

func (f *fakeStyxSource) EnableDataEstats(connection winapi.TCPConnection) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableCalls++
	if err := f.enableErrs[connection.RemotePort]; err != nil {
		return err
	}
	return nil
}

func (f *fakeStyxSource) ConnectionDataEstats(connection winapi.TCPConnection) (winapi.TCPConnDataStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.statsErrs[connection.RemotePort]; err != nil {
		return winapi.TCPConnDataStats{}, err
	}
	return f.stats[connection.RemotePort], nil
}

func (f *fakeStyxSource) setStats(remotePort uint16, tx, rx uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stats == nil {
		f.stats = make(map[uint16]winapi.TCPConnDataStats)
	}
	f.stats[remotePort] = winapi.TCPConnDataStats{DataBytesOut: tx, DataBytesIn: rx}
}

func fakeTCPConnection(pid uint32, remote string, remotePort uint16) winapi.TCPConnection {
	return winapi.TCPConnection{
		PID:        pid,
		State:      winapi.TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("10.0.0.5"),
		LocalPort:  50000,
		RemoteAddr: netip.MustParseAddr(remote),
		RemotePort: remotePort,
	}
}

func fakeTCP6Connection(pid uint32, remote string, remotePort uint16) winapi.TCPConnection {
	return winapi.TCPConnection{
		PID:        pid,
		State:      winapi.TCPStateEstablished,
		LocalAddr:  netip.MustParseAddr("2001:db8::5"),
		LocalPort:  50000,
		RemoteAddr: netip.MustParseAddr(remote),
		RemotePort: remotePort,
	}
}

func TestNewStyxCollectorDefaults(t *testing.T) {
	collector := NewStyxCollector(StyxCollectorConfig{})
	if collector == nil {
		t.Fatal("NewStyxCollector returned nil")
	}
	if status := collector.Status(); status.Polls != 0 || status.Samples != 0 || status.DataObservationAvailable {
		t.Fatalf("fresh collector status = %+v", status)
	}
}

func TestStyxCollectorPollMapsDeltas(t *testing.T) {
	source := &fakeStyxSource{connections: []winapi.TCPConnection{fakeTCPConnection(4321, "203.0.113.7", 443)}}
	source.setStats(443, 1000, 100)
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})

	samples, err := collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("first poll samples = %d, want 1", len(samples))
	}
	first := samples[0]
	if first.PID != 4321 || first.Remote.String() != "203.0.113.7" || first.RemotePort != 443 {
		t.Fatalf("sample identity = %+v", first)
	}
	if !first.TxObservationAvailable || !first.RxObservationAvailable || first.TxBytes != 1000 || first.RxBytes != 100 {
		t.Fatalf("first poll deltas = %+v", first)
	}
	if first.Timestamp.IsZero() {
		t.Fatal("sample carries no observation timestamp")
	}

	source.setStats(443, 1500, 180)
	samples, err = collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if len(samples) != 1 || samples[0].TxBytes != 500 || samples[0].RxBytes != 80 {
		t.Fatalf("second poll deltas = %+v", samples)
	}

	// Unchanged cumulative counters are not an activity window: no sample.
	if samples, err = collector.Poll(context.Background()); err != nil || len(samples) != 0 {
		t.Fatalf("idle poll = %v, %v, want no samples", samples, err)
	}
	status := collector.Status()
	if status.Polls != 3 || status.Samples != 2 || status.EstatsEnabled != 1 || status.EstatsFailed != 0 {
		t.Fatalf("collector counters = %+v", status)
	}
	if !status.DataObservationAvailable || status.TrackedFlows != 1 {
		t.Fatalf("collector capability projection = %+v", status)
	}
	if source.enableCalls != 1 {
		t.Fatalf("estats collection enabled %d times, want once per connection", source.enableCalls)
	}
}

func TestStyxCollectorCounterReset(t *testing.T) {
	source := &fakeStyxSource{connections: []winapi.TCPConnection{fakeTCPConnection(11, "203.0.113.7", 443)}}
	source.setStats(443, 1000, 100)
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	if _, err := collector.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	source.setStats(443, 100, 5) // counters went backwards: collection restarted
	samples, err := collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if len(samples) != 1 || samples[0].TxBytes != 100 || samples[0].RxBytes != 5 {
		t.Fatalf("counter reset deltas = %+v", samples)
	}
}

func TestStyxCollectorUnavailableEstatsStaysHonest(t *testing.T) {
	source := &fakeStyxSource{
		connections: []winapi.TCPConnection{fakeTCPConnection(21, "203.0.113.7", 443)},
		statsErrs:   map[uint16]error{443: errors.New("stats unavailable")},
	}
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	for poll := 0; poll < 2; poll++ {
		samples, err := collector.Poll(context.Background())
		if err != nil {
			t.Fatalf("poll %d: %v", poll, err)
		}
		if len(samples) != 0 {
			t.Fatalf("poll %d emitted guessed samples: %+v", poll, samples)
		}
	}
	status := collector.Status()
	if status.DataObservationAvailable {
		t.Fatal("missing estats must never report data observation as available")
	}
	if status.EstatsFailed != 2 || status.Samples != 0 {
		t.Fatalf("failed-estats counters = %+v", status)
	}
}

func TestStyxCollectorEnableFailureIsReported(t *testing.T) {
	source := &fakeStyxSource{
		connections: []winapi.TCPConnection{fakeTCPConnection(22, "203.0.113.7", 443)},
		enableErrs:  map[uint16]error{443: errors.New("denied")},
	}
	source.setStats(443, 500, 50)
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	samples, err := collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(samples) != 0 {
		t.Fatalf("enable failure still produced samples: %+v", samples)
	}
	if status := collector.Status(); status.EstatsFailed != 1 || status.DataObservationAvailable {
		t.Fatalf("enable failure status = %+v", status)
	}
}

func TestStyxCollectorFiltersRows(t *testing.T) {
	invalid := []winapi.TCPConnection{
		fakeTCPConnection(0, "203.0.113.7", 443),
		func() winapi.TCPConnection {
			connection := fakeTCPConnection(31, "203.0.113.7", 443)
			connection.State = 1 // closed
			return connection
		}(),
		fakeTCPConnection(32, "127.0.0.1", 8080),
		func() winapi.TCPConnection {
			connection := fakeTCPConnection(33, "203.0.113.7", 0)
			return connection
		}(),
		func() winapi.TCPConnection {
			connection := fakeTCPConnection(34, "203.0.113.7", 443)
			connection.RemoteAddr = netip.Addr{}
			return connection
		}(),
		func() winapi.TCPConnection {
			connection := fakeTCPConnection(35, "2001:db8::1", 443) // v6 remote, v4 local
			return connection
		}(),
	}
	source := &fakeStyxSource{connections: append(invalid, fakeTCPConnection(36, "203.0.113.8", 443))}
	source.setStats(443, 10, 1)
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	samples, err := collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(samples) != 1 || samples[0].PID != 36 {
		t.Fatalf("filtered samples = %+v", samples)
	}
	if status := collector.Status(); status.Skipped != uint64(len(invalid)) {
		t.Fatalf("skipped rows = %d, want %d", status.Skipped, len(invalid))
	}
}

func TestStyxCollectorTruncates(t *testing.T) {
	connections := make([]winapi.TCPConnection, 0, 5)
	for index := 0; index < 5; index++ {
		connections = append(connections, fakeTCPConnection(uint32(100+index), "203.0.113.7", uint16(4000+index)))
	}
	source := &fakeStyxSource{connections: connections}
	collector := NewStyxCollector(StyxCollectorConfig{Source: source, MaxConnections: 2})
	for index := 0; index < 5; index++ {
		source.setStats(uint16(4000+index), 50, 5)
	}
	samples, err := collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("truncated samples = %d, want 2", len(samples))
	}
	if status := collector.Status(); status.Truncated != 3 {
		t.Fatalf("truncated counter = %d, want 3", status.Truncated)
	}
}

func TestStyxCollectorIPv6(t *testing.T) {
	source := &fakeStyxSource{connections: []winapi.TCPConnection{fakeTCP6Connection(77, "2001:db8::42", 8443)}}
	source.setStats(8443, 2048, 256)
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	samples, err := collector.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(samples) != 1 || samples[0].Remote.String() != "2001:db8::42" {
		t.Fatalf("IPv6 sample = %+v", samples)
	}
}

func TestStyxCollectorSourceError(t *testing.T) {
	source := &fakeStyxSource{connectionErr: errors.New("iphlpapi unavailable")}
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	if samples, err := collector.Poll(context.Background()); err == nil || samples != nil {
		t.Fatalf("source error = %v, %v", samples, err)
	}
	if status := collector.Status(); !strings.Contains(status.LastError, "iphlpapi unavailable") {
		t.Fatalf("last error not reported: %+v", status)
	}
	source.connectionErr = nil
	source.connections = nil
	if _, err := collector.Poll(context.Background()); err != nil {
		t.Fatalf("recovered poll: %v", err)
	}
	if status := collector.Status(); status.LastError != "" {
		t.Fatalf("stale error retained after recovery: %+v", status)
	}
}

func TestStyxCollectorContextCancellation(t *testing.T) {
	source := &fakeStyxSource{connections: []winapi.TCPConnection{fakeTCPConnection(1, "203.0.113.7", 443)}}
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := collector.Poll(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled poll error = %v, want context.Canceled", err)
	}
	if _, err := collector.Poll(nil); err != nil {
		t.Fatalf("nil context poll: %v", err)
	}
}

func TestStyxCollectorPollInto(t *testing.T) {
	source := &fakeStyxSource{connections: []winapi.TCPConnection{fakeTCPConnection(9, "203.0.113.7", 443)}}
	source.setStats(443, 1<<20, 1<<20) // balanced rx/tx: no ratio claim possible
	collector := NewStyxCollector(StyxCollectorConfig{Source: source})
	settings := enabledStyxSettings()
	settings.Mode = StyxModeObserve
	engine, err := NewStyxBeaconEngine(StyxBeaconConfig{Settings: settings, DNSObservationAvailable: true})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	incidents, err := collector.PollInto(context.Background(), engine)
	if err != nil {
		t.Fatalf("PollInto: %v", err)
	}
	if len(incidents) != 1 || incidents[0].EventType != StyxBeaconEventDirectIP {
		t.Fatalf("PollInto incidents = %+v", incidents)
	}
	status := engine.Status()
	if status.Capability != "known" || !status.RxObservationAvailable {
		t.Fatalf("PollInto did not project capabilities honestly: %+v", status)
	}
	if status.DNSObservationAvailable != true {
		t.Fatalf("DNS capability projection = %+v", status)
	}
	if _, err := collector.PollInto(context.Background(), nil); err == nil {
		t.Fatal("PollInto accepted a nil engine")
	}
}

func TestStyxCollectorNilSafety(t *testing.T) {
	var collector *StyxCollector
	if samples, err := collector.Poll(context.Background()); err == nil || samples != nil {
		t.Fatalf("nil collector poll = %v, %v", samples, err)
	}
	if status := collector.Status(); status.Polls != 0 {
		t.Fatalf("nil collector status = %+v", status)
	}
	if _, err := collector.PollInto(context.Background(), nil); err == nil {
		t.Fatal("nil collector PollInto accepted")
	}
}

func TestStyxCounterDeltaAndBoundedText(t *testing.T) {
	cases := []struct {
		previous, current, want uint64
	}{
		{10, 20, 10},
		{20, 10, 10},
		{5, 5, 0},
		{0, 7, 7},
	}
	for _, testCase := range cases {
		if got := styxCounterDelta(testCase.previous, testCase.current); got != testCase.want {
			t.Fatalf("styxCounterDelta(%d,%d)=%d, want %d", testCase.previous, testCase.current, got, testCase.want)
		}
	}
	long := errors.New(strings.Repeat("x", styxCollectorMaxErrorBytes*2))
	if text := styxBoundedText(long); len(text) != styxCollectorMaxErrorBytes {
		t.Fatalf("bounded text length = %d, want %d", len(text), styxCollectorMaxErrorBytes)
	}
	if text := styxBoundedText(nil); text != "" {
		t.Fatalf("bounded text of nil = %q", text)
	}
}

func TestStyxCollectorUsesInjectedClock(t *testing.T) {
	source := &fakeStyxSource{connections: []winapi.TCPConnection{fakeTCPConnection(3, "203.0.113.7", 443)}}
	source.setStats(443, 10, 1)
	fixed := time.Date(2026, 11, 16, 21, 0, 0, 0, time.UTC)
	collector := NewStyxCollector(StyxCollectorConfig{Source: source, Now: func() time.Time { return fixed }})
	samples, err := collector.Poll(context.Background())
	if err != nil || len(samples) != 1 {
		t.Fatalf("poll = %v, %v", samples, err)
	}
	if !samples[0].Timestamp.Equal(fixed) {
		t.Fatalf("sample timestamp = %v, want %v", samples[0].Timestamp, fixed)
	}
	if status := collector.Status(); !status.LastPollUTC.Equal(fixed) {
		t.Fatalf("status last poll = %v, want %v", status.LastPollUTC, fixed)
	}
}
