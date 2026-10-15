// Package kinetic provides Windows-safe, observe-only Kinetic telemetry.
// It never installs WFP rules or authorizes a process termination.
package kinetic

import (
	"net/netip"
	"sync"
	"time"
)

const (
	maxSources          = 2048
	maxSamplesPerSource = 32
	burstWindow         = 10 * time.Second
	burstThreshold      = 12
	diversityThreshold  = 3
)

type sample struct {
	at        time.Time
	localPort uint16
}
type source struct {
	samples     [maxSamplesPerSource]sample
	next, count int
	last        time.Time
	reported    bool
}

// Snapshot counts verified input events. A candidate is not an established attack.
type Snapshot struct {
	Mode            string `json:"mode"`
	Input           string `json:"input"`
	BlocksObserved  uint64 `json:"blocksObserved"`
	BurstCandidates uint64 `json:"burstCandidates"`
	TrackedSources  int    `json:"trackedSources"`
	Capacity        int    `json:"capacity"`
	DroppedSamples  uint64 `json:"droppedSamples"`
}

type Monitor struct {
	mu                          sync.Mutex
	sources                     map[netip.Addr]*source
	order                       []netip.Addr
	nextEvict                   int
	blocks, candidates, dropped uint64
}

func NewMonitor() *Monitor { return &Monitor{sources: make(map[netip.Addr]*source)} }

// ObserveBlockedInbound ingests only WFP Security 5157 inbound BLOCK observations.
// It must not be called with TCP-ESTABLISHED snapshots or synthesized traffic.
// The monitor never enforces or asserts SYN flood detection: 5157 contains no
// reliable packet-level SYN rate or full ingress coverage.
func (m *Monitor) ObserveBlockedInbound(ip string, port uint16, now time.Time) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.IsValid() || addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() || now.IsZero() {
		return false
	}
	addr = addr.Unmap()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks++
	if port == 0 {
		return false
	}
	s := m.sources[addr]
	if s == nil {
		if len(m.sources) >= maxSources {
			// O(1) round-robin eviction. Unbounded scans on new remote IPs
			// would let high-cardinality block logs burn CPU.
			victim := m.order[m.nextEvict]
			delete(m.sources, victim)
			m.order[m.nextEvict] = addr
			m.nextEvict = (m.nextEvict + 1) % maxSources
			m.dropped++
		} else {
			m.order = append(m.order, addr)
		}
		s = &source{}
		m.sources[addr] = s
	}
	if now.Before(s.last) {
		m.dropped++
		return false
	}
	if now.Sub(s.last) > burstWindow {
		s.count = 0
		s.next = 0
		s.reported = false
	}
	if now.After(s.last) {
		s.last = now
	}
	s.samples[s.next] = sample{now, port}
	s.next = (s.next + 1) % maxSamplesPerSource
	if s.count < maxSamplesPerSource {
		s.count++
	} else {
		m.dropped++
	}
	seenPorts := make(map[uint16]struct{}, diversityThreshold)
	hits := 0
	for j := 0; j < s.count; j++ {
		event := s.samples[j]
		if !event.at.After(now) && now.Sub(event.at) <= burstWindow {
			hits++
			seenPorts[event.localPort] = struct{}{}
		}
	}
	if !s.reported && hits >= burstThreshold && len(seenPorts) >= diversityThreshold {
		s.reported = true
		m.candidates++
		return true
	}
	return false
}
func (m *Monitor) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{Mode: "OBSERVE_ONLY", Input: "WFP_SECURITY_5157_BLOCKED_INBOUND_ONLY"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{Mode: "OBSERVE_ONLY", Input: "WFP_SECURITY_5157_BLOCKED_INBOUND_ONLY", BlocksObserved: m.blocks, BurstCandidates: m.candidates, TrackedSources: len(m.sources), Capacity: maxSources, DroppedSamples: m.dropped}
}

// Readiness is a deliberately conservative representation of sensor coverage.
// A live polling loop does not prove that 5157 audit policy is enabled.
type Readiness struct {
	Mode        string `json:"mode"`
	Ingress     string `json:"ingress"`
	WFPAudit    string `json:"wfpAudit"`
	ThreatRules string `json:"threatRules"`
	Note        string `json:"note"`
}

func EvaluateReadiness(tcpPolling, wfpPolling bool, wfpBlocks uint64, rulesState, desired, active string) Readiness {
	r := Readiness{Mode: "OBSERVE_ONLY", Ingress: "UNVERIFIED_NO_RAW_INGRESS_SENSOR", WFPAudit: "OFFLINE", ThreatRules: "UNVERIFIED", Note: "TCP table snapshots and WFP 5157 blocks do not prove full ingress coverage"}
	if wfpPolling {
		r.WFPAudit = "POLLING_AUDIT_NOT_VERIFIED"
	}
	if wfpPolling && wfpBlocks > 0 {
		r.WFPAudit = "BLOCK_EVENTS_OBSERVED"
	}
	if rulesState == "VERIFIED" || rulesState == "VERIFIED_CLEANUP_PENDING" {
		if len(desired) == 64 && desired == active {
			r.ThreatRules = "GENERATION_VERIFIED"
		}
	}
	if !tcpPolling {
		r.Note += "; TCP owner-PID sampling unavailable"
	}
	return r
}
