// Package kinetic provides Windows-safe, observe-only Kinetic telemetry.
// It never installs WFP rules or authorizes a process termination.
package kinetic

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	maxSources          = 2048
	maxSamplesPerSource = 32
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
	hits        uint64
	portless    uint64
	lastSeen    time.Time
	lastPort    uint16
}

// Source records real WFP observations independently of the stricter burst threshold.
type Source struct {
	IP             string    `json:"ip"`
	Hits           uint64    `json:"hits"`
	PortlessBlocks uint64    `json:"portlessBlocks"`
	LastSeen       time.Time `json:"lastSeen"`
	LastPort       uint16    `json:"lastPort"`
}

// Snapshot counts verified input events. A candidate is not an established attack.
type Snapshot struct {
	Mode            string `json:"mode"`
	Input           string `json:"input"`
	Config          Config `json:"config"`
	BlocksObserved  uint64 `json:"blocksObserved"`
	BurstCandidates uint64 `json:"burstCandidates"`
	TrackedSources  int    `json:"trackedSources"`
	Capacity        int    `json:"capacity"`
	DroppedSamples  uint64 `json:"droppedSamples"`
}

type Monitor struct {
	mu                          sync.Mutex
	cfg                         Config
	sources                     map[netip.Addr]*source
	order                       []netip.Addr
	nextEvict                   int
	blocks, candidates, dropped uint64
}

// NewMonitor creates an observer with the default (historically hard-coded)
// thresholds. Explicit configuration goes through Configure.
func NewMonitor() *Monitor {
	return &Monitor{cfg: DefaultConfig(), sources: make(map[netip.Addr]*source)}
}

// Configure validates and applies an observation policy. Already retained
// samples are discarded because they were measured against the previous
// thresholds; mixing two policies would make the burst counters unauditable.
// The previous configuration always remains in place when validation fails.
func (m *Monitor) Configure(cfg Config) error {
	if m == nil {
		return errors.New("kinetic monitor unavailable")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == cfg {
		return nil
	}
	m.cfg = cfg
	for _, tracked := range m.sources {
		tracked.samples = [maxSamplesPerSource]sample{}
		tracked.next, tracked.count, tracked.reported = 0, 0, false
		tracked.last = time.Time{}
	}
	return nil
}

// Config returns a copy of the active observation policy.
func (m *Monitor) Config() Config {
	if m == nil {
		return DefaultConfig()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

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
	window := m.cfg.BurstWindow()
	minEvents := m.cfg.MinEvents
	minPorts := m.cfg.MinDistinctPorts
	m.blocks++
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
	if now.Before(s.lastSeen) {
		m.dropped++
		return false
	}
	s.hits++
	s.lastSeen, s.lastPort = now, port
	if port == 0 {
		s.portless++
		return false
	}
	if now.Before(s.last) {
		m.dropped++
		return false
	}
	if now.Sub(s.last) > window {
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
	seenPorts := make(map[uint16]struct{}, minPorts)
	hits := 0
	for j := 0; j < s.count; j++ {
		event := s.samples[j]
		if !event.at.After(now) && now.Sub(event.at) <= window {
			hits++
			seenPorts[event.localPort] = struct{}{}
		}
	}
	if !s.reported && hits >= minEvents && len(seenPorts) >= minPorts {
		s.reported = true
		m.candidates++
		return true
	}
	return false
}

// SourceSnapshot copies bounded state under the lock and sorts outside the hot path.
func (m *Monitor) SourceSnapshot(limit int) []Source {
	if m == nil {
		return []Source{}
	}
	if limit < 1 || limit > 500 {
		limit = 250
	}
	m.mu.Lock()
	rows := make([]Source, 0, len(m.sources))
	for ip, item := range m.sources {
		rows = append(rows, Source{IP: ip.String(), Hits: item.hits, PortlessBlocks: item.portless, LastSeen: item.lastSeen, LastPort: item.lastPort})
	}
	m.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LastSeen.Equal(rows[j].LastSeen) {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].LastSeen.After(rows[j].LastSeen)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func (m *Monitor) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{Mode: "OBSERVE_ONLY", Input: "WFP_SECURITY_5157_BLOCKED_INBOUND_ONLY", Config: DefaultConfig()}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{Mode: "OBSERVE_ONLY", Input: "WFP_SECURITY_5157_BLOCKED_INBOUND_ONLY", Config: m.cfg, BlocksObserved: m.blocks, BurstCandidates: m.candidates, TrackedSources: len(m.sources), Capacity: maxSources, DroppedSamples: m.dropped}
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
