// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

// Windows V6 Phase 1: the real (optional) StyX flow collector.
//
// It is the only place that touches Win32: it polls the TCP connection table
// (winapi.TCPConnections) and, per connection, enables and reads the TCP
// per-connection data statistics (GetPerTcpConnectionEStats). The collector
// turns cumulative byte counters into window deltas and keeps the honesty flags
// of the samples strict: when a statistics read fails, the sample is not
// emitted at all instead of reporting guessed zeroes.
//
// No sockets are opened and no service/registry state is written. Every source
// call is injectable (StyxFlowSource) so the mapping is testable without a
// network, exactly like the rest of the Windows V6 port.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	// styxCollectorMaxErrorBytes bounds the retained last-error text.
	styxCollectorMaxErrorBytes = 240
)

// StyxFlowSource abstracts the Win32 connection/estats source for tests.
type StyxFlowSource interface {
	TCPConnections() ([]winapi.TCPConnection, error)
	EnableDataEstats(connection winapi.TCPConnection) error
	ConnectionDataEstats(connection winapi.TCPConnection) (winapi.TCPConnDataStats, error)
}

// win32StyxFlowSource is the real iphlpapi implementation.
type win32StyxFlowSource struct{}

func (win32StyxFlowSource) TCPConnections() ([]winapi.TCPConnection, error) {
	return winapi.TCPConnections()
}

func (win32StyxFlowSource) EnableDataEstats(connection winapi.TCPConnection) error {
	return winapi.EnableTCPConnectionDataEstats(connection)
}

func (win32StyxFlowSource) ConnectionDataEstats(connection winapi.TCPConnection) (winapi.TCPConnDataStats, error) {
	return winapi.TCPConnectionDataEstats(connection)
}

// StyxCollectorConfig configures the collector. Source defaults to iphlpapi,
// MaxConnections defaults to MaxTrackedBeaconFlows.
type StyxCollectorConfig struct {
	Source         StyxFlowSource
	Now            func() time.Time
	MaxConnections int
}

// StyxCollectorStatus is the honest collector projection. DataObservationAvailable
// becomes true only after at least one successful statistics read; it is never
// set optimistically.
type StyxCollectorStatus struct {
	Polls                    uint64    `json:"polls"`
	Connections              uint64    `json:"connections"`
	Samples                  uint64    `json:"samples"`
	EstatsEnabled            uint64    `json:"estatsEnabled"`
	EstatsFailed             uint64    `json:"estatsFailed"`
	Truncated                uint64    `json:"truncated"`
	Skipped                  uint64    `json:"skipped"`
	TrackedFlows             int       `json:"trackedFlows"`
	DataObservationAvailable bool      `json:"dataObservationAvailable"`
	LastPollUTC              time.Time `json:"lastPollUtc"`
	LastError                string    `json:"lastError,omitempty"`
}

type styxFlowCounters struct {
	tx uint64
	rx uint64
}

// StyxCollector is the bounded, thread-safe Win32 flow source.
type StyxCollector struct {
	mu             sync.Mutex
	source         StyxFlowSource
	now            func() time.Time
	maxConnections int
	previous       map[FlowKey]styxFlowCounters
	enabled        map[FlowKey]struct{}
	counters       StyxCollectorStatus
}

// NewStyxCollector builds a collector; a nil Source means the real iphlpapi
// implementation. It never panics and never starts a goroutine.
func NewStyxCollector(cfg StyxCollectorConfig) *StyxCollector {
	source := cfg.Source
	if source == nil {
		source = win32StyxFlowSource{}
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxConnections := cfg.MaxConnections
	if maxConnections <= 0 || maxConnections > MaxTrackedBeaconFlows {
		maxConnections = MaxTrackedBeaconFlows
	}
	return &StyxCollector{
		source:         source,
		now:            now,
		maxConnections: maxConnections,
		previous:       make(map[FlowKey]styxFlowCounters, 64),
		enabled:        make(map[FlowKey]struct{}, 64),
	}
}

// Poll reads one batch of flow window deltas. A connection whose statistics
// cannot be read contributes no sample (never a zero-value guess). A cancelled
// context stops the loop and is returned with the partial batch.
func (c *StyxCollector) Poll(ctx context.Context) ([]StyxFlowSample, error) {
	if c == nil {
		return nil, errors.New("styX collector is nil")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	connections, err := c.source.TCPConnections()
	if err != nil {
		c.counters.Polls++
		c.counters.LastError = styxBoundedText(fmt.Errorf("styX TCP connection table unavailable: %w", err))
		return nil, fmt.Errorf("styX collector: %w", err)
	}
	now := c.now().UTC()
	samples := make([]StyxFlowSample, 0, 16)
	previous := make(map[FlowKey]styxFlowCounters, len(c.previous))
	enabled := make(map[FlowKey]struct{}, len(c.enabled))
	c.counters.Connections += uint64(len(connections))
	for index := range connections {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		if len(samples) >= c.maxConnections {
			c.counters.Truncated++
			continue
		}
		connection := connections[index]
		key, ok := styxCollectorKey(connection)
		if !ok {
			c.counters.Skipped++
			continue
		}
		if _, alreadyEnabled := c.enabled[key]; !alreadyEnabled {
			if enableErr := c.source.EnableDataEstats(connection); enableErr != nil {
				// Estats is opt-in per connection; a failure is reported and the
				// flow stays unobserved instead of being reported with zeroes.
				c.counters.EstatsFailed++
				continue
			}
			c.counters.EstatsEnabled++
		}
		enabled[key] = struct{}{}
		stats, statsErr := c.source.ConnectionDataEstats(connection)
		if statsErr != nil {
			c.counters.EstatsFailed++
			continue
		}
		c.counters.DataObservationAvailable = true
		previousCounters, observedBefore := c.previous[key]
		txDelta := stats.DataBytesOut
		rxDelta := stats.DataBytesIn
		if observedBefore {
			txDelta = styxCounterDelta(previousCounters.tx, stats.DataBytesOut)
			rxDelta = styxCounterDelta(previousCounters.rx, stats.DataBytesIn)
		}
		previous[key] = styxFlowCounters{tx: stats.DataBytesOut, rx: stats.DataBytesIn}
		if observedBefore && txDelta == 0 && rxDelta == 0 {
			// No new bytes since the last poll: not an activity window, so it
			// must not feed the inter-arrival statistics.
			continue
		}
		remote := connection.RemoteAddr.Unmap()
		samples = append(samples, StyxFlowSample{
			PID:                    int(connection.PID),
			Remote:                 remote,
			RemotePort:             connection.RemotePort,
			Proto:                  styxProtoTCP,
			TxBytes:                txDelta,
			RxBytes:                rxDelta,
			TxObservationAvailable: true,
			RxObservationAvailable: true,
			Timestamp:              now,
		})
	}
	c.previous = previous
	c.enabled = enabled
	c.counters.Polls++
	c.counters.Samples += uint64(len(samples))
	c.counters.TrackedFlows = len(previous)
	c.counters.LastPollUTC = now
	c.counters.LastError = ""
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return samples, err
		}
	}
	return samples, nil
}

// Status returns a copy of the bounded collector counters.
func (c *StyxCollector) Status() StyxCollectorStatus {
	if c == nil {
		return StyxCollectorStatus{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counters
}

// PollInto polls one batch, projects the observed capability honestly onto the
// engine and feeds every sample into the detector. Rx observation is raised
// only after a successful statistics read; DNS attribution is never claimed.
func (c *StyxCollector) PollInto(ctx context.Context, engine *StyxBeaconEngine) ([]StyxIncident, error) {
	if c == nil {
		return nil, errors.New("styX collector is nil")
	}
	if engine == nil {
		return nil, errors.New("styX collector: engine is nil")
	}
	samples, err := c.Poll(ctx)
	if err == nil || len(samples) > 0 {
		engine.SetFlowCapabilityKnown(true)
		engine.SetRxObservationAvailable(c.Status().DataObservationAvailable)
	}
	return engine.ObserveBatch(samples), err
}

// styxCollectorKey maps one connection table row onto a flow key. Loopback is
// skipped (it is exempt from StyX policy and not beacon-relevant), as are rows
// without an established peer.
func styxCollectorKey(connection winapi.TCPConnection) (FlowKey, bool) {
	if connection.PID == 0 || connection.State != winapi.TCPStateEstablished || connection.RemotePort == 0 {
		return FlowKey{}, false
	}
	remote, err := StyxNormalizeDestination(connection.RemoteAddr)
	if err != nil || remote.IsLoopback() {
		return FlowKey{}, false
	}
	if connection.LocalAddr.IsValid() && connection.LocalAddr.Is4() != remote.Is4() {
		return FlowKey{}, false
	}
	key := FlowKey{PID: int(connection.PID), RemoteIP: remote, RemotePort: connection.RemotePort, Proto: styxProtoTCP}
	if !key.Valid() {
		return FlowKey{}, false
	}
	return key, true
}

// styxCounterDelta computes a cumulative-counter delta. A counter that went
// backwards means the connection or its collection was recreated, so the new
// value is the delta since the last observation.
func styxCounterDelta(previous, current uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func styxBoundedText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > styxCollectorMaxErrorBytes {
		return text[:styxCollectorMaxErrorBytes]
	}
	return text
}
