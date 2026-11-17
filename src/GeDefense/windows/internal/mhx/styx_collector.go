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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	// styxCollectorMaxErrorBytes bounds the retained last-error text.
	styxCollectorMaxErrorBytes = 240
	// styxMaxTrackedPrograms caps retained per-program traffic summaries.
	styxMaxTrackedPrograms = 256
	// styxMaxProgramDestinations caps destinations retained per program.
	styxMaxProgramDestinations = 48
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
	Source          StyxFlowSource
	ProcessResolver func(pid int) (string, string)
	Now             func() time.Time
	MaxConnections  int
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

type styxTrackedDest struct {
	IP          string
	Port        uint16
	LocalPort   uint16
	TxBytes     uint64
	RxBytes     uint64
	Connections int
	LastSeen    time.Time
}

type styxTrackedProgram struct {
	Process      string
	ProcessPath  string
	PIDs         map[int]struct{}
	Connections  int
	TxBytes      uint64
	RxBytes      uint64
	LastSeen     time.Time
	Destinations map[string]*styxTrackedDest
}

// StyxCollector is the bounded, thread-safe Win32 flow source.
type StyxCollector struct {
	mu              sync.Mutex
	source          StyxFlowSource
	processResolver func(pid int) (string, string)
	cacheResolver   *styxProcessResolver
	now             func() time.Time
	maxConnections  int
	previous        map[FlowKey]styxFlowCounters
	enabled         map[FlowKey]struct{}
	programs        map[string]*styxTrackedProgram
	counters        StyxCollectorStatus
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
		source:          source,
		processResolver: cfg.ProcessResolver,
		cacheResolver:   newStyxProcessResolver(now),
		now:             now,
		maxConnections:  maxConnections,
		previous:        make(map[FlowKey]styxFlowCounters, 64),
		enabled:         make(map[FlowKey]struct{}, 64),
		programs:        make(map[string]*styxTrackedProgram, 32),
	}
}

func (c *StyxCollector) resolveProcess(pid int) (string, string) {
	if c.processResolver != nil {
		return c.processResolver(pid)
	}
	if c.cacheResolver != nil {
		return c.cacheResolver.Resolve(pid)
	}
	return "", ""
}

func (c *StyxCollector) recordProgramLocked(procName, procPath string, key FlowKey, localPort uint16, txAdd, rxAdd uint64, seenFlowKeys map[string]map[FlowKey]struct{}, now time.Time) {
	progKey := strings.ToLower(strings.TrimSpace(procPath))
	if progKey == "" {
		progKey = strings.ToLower(strings.TrimSpace(procName))
	}
	if progKey == "" {
		progKey = fmt.Sprintf("pid:%d", key.PID)
	}
	prog := c.programs[progKey]
	if prog == nil {
		if len(c.programs) >= styxMaxTrackedPrograms {
			var oldestKey string
			var oldestTime time.Time
			for k, candidate := range c.programs {
				if oldestKey == "" || candidate.LastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = candidate.LastSeen
				}
			}
			if oldestKey != "" {
				delete(c.programs, oldestKey)
			}
		}
		displayName := procName
		if displayName == "" {
			displayName = fmt.Sprintf("pid-%d", key.PID)
		}
		prog = &styxTrackedProgram{
			Process:      displayName,
			ProcessPath:  procPath,
			PIDs:         make(map[int]struct{}, 2),
			Destinations: make(map[string]*styxTrackedDest, 8),
		}
		c.programs[progKey] = prog
	}
	if procName != "" && strings.HasPrefix(prog.Process, "pid-") {
		prog.Process = procName
	}
	if procPath != "" && prog.ProcessPath == "" {
		prog.ProcessPath = procPath
	}
	prog.PIDs[key.PID] = struct{}{}
	prog.LastSeen = now
	prog.TxBytes = saturatingAdd(prog.TxBytes, txAdd)
	prog.RxBytes = saturatingAdd(prog.RxBytes, rxAdd)

	destKey := fmt.Sprintf("%s:%d", key.RemoteIP.String(), key.RemotePort)
	dest := prog.Destinations[destKey]
	if dest == nil {
		if len(prog.Destinations) >= styxMaxProgramDestinations {
			var oldestDest string
			var oldestDestTime time.Time
			for k, d := range prog.Destinations {
				if oldestDest == "" || d.LastSeen.Before(oldestDestTime) {
					oldestDest = k
					oldestDestTime = d.LastSeen
				}
			}
			if oldestDest != "" {
				delete(prog.Destinations, oldestDest)
			}
		}
		dest = &styxTrackedDest{
			IP:        key.RemoteIP.String(),
			Port:      key.RemotePort,
			LocalPort: localPort,
		}
		prog.Destinations[destKey] = dest
	}
	if dest.LocalPort == 0 && localPort != 0 {
		dest.LocalPort = localPort
	}
	dest.TxBytes = saturatingAdd(dest.TxBytes, txAdd)
	dest.RxBytes = saturatingAdd(dest.RxBytes, rxAdd)
	dest.LastSeen = now

	if perProg := seenFlowKeys[progKey]; perProg == nil {
		seenFlowKeys[progKey] = map[FlowKey]struct{}{key: {}}
		prog.Connections++
		dest.Connections++
	} else if _, dup := perProg[key]; !dup {
		perProg[key] = struct{}{}
		dest.Connections++
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
	activeProgFlows := make(map[string]map[FlowKey]struct{}, 32)
	for _, prog := range c.programs {
		prog.Connections = 0
		for _, dest := range prog.Destinations {
			dest.Connections = 0
		}
	}
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
		procName, procPath := c.resolveProcess(key.PID)
		if _, alreadyEnabled := c.enabled[key]; !alreadyEnabled {
			if enableErr := c.source.EnableDataEstats(connection); enableErr != nil {
				// Estats is opt-in per connection; a failure is reported and the
				// flow stays unobserved for beacon scoring, while the connection
				// identity stays visible in per-program overview telemetry.
				c.counters.EstatsFailed++
				c.recordProgramLocked(procName, procPath, key, connection.LocalPort, 0, 0, activeProgFlows, now)
				continue
			}
			c.counters.EstatsEnabled++
		}
		enabled[key] = struct{}{}
		stats, statsErr := c.source.ConnectionDataEstats(connection)
		if statsErr != nil {
			c.counters.EstatsFailed++
			c.recordProgramLocked(procName, procPath, key, connection.LocalPort, 0, 0, activeProgFlows, now)
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
		c.recordProgramLocked(procName, procPath, key, connection.LocalPort, txDelta, rxDelta, activeProgFlows, now)
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
			LocalPort:              connection.LocalPort,
			Proto:                  styxProtoTCP,
			TxBytes:                txDelta,
			RxBytes:                rxDelta,
			TxObservationAvailable: true,
			RxObservationAvailable: true,
			Timestamp:              now,
			Comm:                   procName,
			ProcessPath:            procPath,
		})
	}
	c.previous = previous
	c.enabled = enabled
	for progKey, flowsMap := range activeProgFlows {
		if prog := c.programs[progKey]; prog != nil {
			prog.Connections = len(flowsMap)
		}
	}
	// Prune idle program entries older than 15 minutes with zero active connections.
	cutoff := now.Add(-15 * time.Minute)
	for progKey, prog := range c.programs {
		if prog.Connections == 0 && prog.LastSeen.Before(cutoff) {
			delete(c.programs, progKey)
		}
	}
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

// ProgramSnapshots returns a bounded, sorted copy of per-program outbound TCP
// traffic summaries collected across active polls.
func (c *StyxCollector) ProgramSnapshots() []StyxProgramTrafficSummary {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]StyxProgramTrafficSummary, 0, len(c.programs))
	for _, prog := range c.programs {
		pids := make([]int, 0, len(prog.PIDs))
		for pid := range prog.PIDs {
			pids = append(pids, pid)
		}
		sort.Ints(pids)
		dests := make([]StyxProgramDestination, 0, len(prog.Destinations))
		for _, dest := range prog.Destinations {
			dests = append(dests, StyxProgramDestination{
				IP:          dest.IP,
				Port:        dest.Port,
				LocalPort:   dest.LocalPort,
				TxBytes:     dest.TxBytes,
				RxBytes:     dest.RxBytes,
				Connections: dest.Connections,
				LastSeen:    dest.LastSeen,
			})
		}
		sort.Slice(dests, func(i, j int) bool {
			ti := dests[i].TxBytes + dests[i].RxBytes
			tj := dests[j].TxBytes + dests[j].RxBytes
			if ti != tj {
				return ti > tj
			}
			if dests[i].Connections != dests[j].Connections {
				return dests[i].Connections > dests[j].Connections
			}
			if dests[i].IP != dests[j].IP {
				return dests[i].IP < dests[j].IP
			}
			return dests[i].Port < dests[j].Port
		})
		if len(dests) > 24 {
			dests = dests[:24]
		}
		out = append(out, StyxProgramTrafficSummary{
			Process:      prog.Process,
			ProcessPath:  prog.ProcessPath,
			PIDs:         pids,
			Connections:  prog.Connections,
			TxBytes:      prog.TxBytes,
			RxBytes:      prog.RxBytes,
			TotalBytes:   saturatingAdd(prog.TxBytes, prog.RxBytes),
			LastSeen:     prog.LastSeen,
			Destinations: dests,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalBytes != out[j].TotalBytes {
			return out[i].TotalBytes > out[j].TotalBytes
		}
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		return strings.ToLower(out[i].Process) < strings.ToLower(out[j].Process)
	})
	return out
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
