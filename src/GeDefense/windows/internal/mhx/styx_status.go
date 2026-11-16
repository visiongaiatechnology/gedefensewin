// STATUS: PLATIN VGT SUPREME
package mhx

// Windows V6 Phase 1: the honest, bounded StyX status projection.
//
// The projection is JSON-safe by construction: every list is capped, every
// float is finite and every capability is reported as it is
// (rxObservationAvailable=false when the source cannot prove receive bytes,
// dnsObservationAvailable=false while DNS attribution does not exist).
// "unavailable" and "off" are never presented as "active/OK".

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// styxStatusTopFlows is the hard cap of the status flow list (Linux V6 Top 10).
	styxStatusTopFlows = 10
)

// StyxBeaconSnapshot is the bounded detector view returned by Snapshot.
type StyxBeaconSnapshot struct {
	SensorState    string             `json:"sensorState"`
	Mode           string             `json:"mode"`
	DNSObservation string             `json:"dnsObservation"`
	RxObservation  string             `json:"rxObservation"`
	Flows          int                `json:"flowsTracked"`
	Events         uint64             `json:"eventsTotal"`
	Incidents      uint64             `json:"incidentTotal"`
	Suppressed     uint64             `json:"suppressedTotal"`
	Dropped        uint64             `json:"droppedTotal"`
	Evicted        uint64             `json:"evictedTotal"`
	Overflows      uint64             `json:"overflowTotal"`
	Degraded       bool               `json:"degraded"`
	Top            []StyxFlowSnapshot `json:"top"`
}

// StyxStatus is the operator-facing detector status: the snapshot plus the
// capability projection and the enabled/mode state.
type StyxStatus struct {
	Enabled                    bool               `json:"enabled"`
	Mode                       string             `json:"mode"`
	SensorState                string             `json:"sensorState"`
	Capability                 string             `json:"capability"`
	FlowsTracked               int                `json:"flowsTracked"`
	FlowsEvicted               uint64             `json:"flowsEvicted"`
	EventsTotal                uint64             `json:"eventsTotal"`
	IncidentTotal              uint64             `json:"incidentTotal"`
	SuppressedTotal            uint64             `json:"suppressedTotal"`
	DroppedTotal               uint64             `json:"droppedTotal"`
	OverflowTotal              uint64             `json:"overflowTotal"`
	Degraded                   bool               `json:"degraded"`
	RxObservationAvailable     bool               `json:"rxObservationAvailable"`
	DNSObservationAvailable    bool               `json:"dnsObservationAvailable"`
	CanaryCorrelationAvailable bool               `json:"canaryCorrelationAvailable"`
	Top                        []StyxFlowSnapshot `json:"top"`
}

// Snapshot returns the bounded detector view. A nil receiver reports an honest
// unavailable state with empty lists instead of panicking.
func (e *StyxBeaconEngine) Snapshot() StyxBeaconSnapshot {
	if e == nil {
		return StyxBeaconSnapshot{
			SensorState:    "unavailable",
			Mode:           StyxModeOff,
			DNSObservation: "unknown",
			RxObservation:  "unknown",
			Top:            []StyxFlowSnapshot{},
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := StyxBeaconSnapshot{
		SensorState:    e.sensorStateLocked(),
		Mode:           e.settings.EffectiveMode(),
		DNSObservation: "unknown",
		RxObservation:  "unknown",
		Flows:          e.flows.len(),
		Events:         e.events,
		Incidents:      e.emittedIncidents,
		Suppressed:     e.suppressed,
		Dropped:        e.dropped,
		Evicted:        e.flows.evicted,
		Overflows:      e.overflowRecords,
		Degraded:       e.degraded,
		Top:            e.flows.top(styxStatusTopFlows),
	}
	if e.dnsObservation {
		snapshot.DNSObservation = "known"
	}
	if e.rxObservation {
		snapshot.RxObservation = "known"
	}
	return snapshot
}

// Status returns the full bounded status projection.
func (e *StyxBeaconEngine) Status() StyxStatus {
	if e == nil {
		return StyxStatus{
			Mode:        StyxModeOff,
			SensorState: "unavailable",
			Capability:  "missing",
			Top:         []StyxFlowSnapshot{},
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	status := StyxStatus{
		Enabled:                    e.settings.Enabled,
		Mode:                       e.settings.EffectiveMode(),
		SensorState:                e.sensorStateLocked(),
		Capability:                 "missing",
		FlowsTracked:               e.flows.len(),
		FlowsEvicted:               e.flows.evicted,
		EventsTotal:                e.events,
		IncidentTotal:              e.emittedIncidents,
		SuppressedTotal:            e.suppressed,
		DroppedTotal:               e.dropped,
		OverflowTotal:              e.overflowRecords,
		Degraded:                   e.degraded,
		RxObservationAvailable:     e.rxObservation,
		DNSObservationAvailable:    e.dnsObservation,
		CanaryCorrelationAvailable: e.canary != nil,
		Top:                        e.flows.top(styxStatusTopFlows),
	}
	if e.flowCapability {
		status.Capability = "known"
	}
	return status
}

// StyxIncident is one detector finding. It is evidence only: Action is always
// "none" because the Go side never enforces egress policy by itself. It lives
// next to the status projection because findings and status are the only data
// that leave the detector.
type StyxIncident struct {
	ID               string    `json:"id"`
	TimestampUTC     time.Time `json:"timestampUtc"`
	Severity         Severity  `json:"severity"`
	Score            int       `json:"score"`
	ResponseScore    int       `json:"responseScore"`
	PID              int       `json:"pid"`
	Process          string    `json:"process"`
	Remote           string    `json:"remote"`
	EventType        string    `json:"eventType"`
	Category         string    `json:"category"`
	Signals          []string  `json:"signals"`
	RuleIDs          []string  `json:"ruleIds"`
	Decision         string    `json:"decision"`
	Action           string    `json:"action"`
	Outcome          string    `json:"outcome"`
	Summary          string    `json:"summary"`
	TxBytes          uint64    `json:"txBytes"`
	RxBytes          uint64    `json:"rxBytes"`
	IntervalSamples  int64     `json:"intervalSamples"`
	CanaryCorrelated bool      `json:"canaryCorrelated"`
}

// buildIncidentLocked renders one finding from a flow aggregate. It never
// includes command lines, credentials or payload bytes; the summary is bounded
// to counters, rule identifiers and the peer tuple.
func (e *StyxBeaconEngine) buildIncidentLocked(aggregate *FlowAggregate, now time.Time, canaryCorrelated bool) StyxIncident {
	key := aggregate.Key
	process := aggregate.Comm
	if process == "" {
		process = "unknown"
	}
	signals := append([]string(nil), aggregate.LastSignals...)
	rules := append([]string(nil), aggregate.lastRules...)
	severity := SeverityHigh
	if aggregate.LastScore >= 250 {
		severity = SeverityCritical
	}
	summary := fmt.Sprintf("Styx beacon/exfiltration evidence: pid=%d comm=%s remote=%s signals=%s tx=%d rx=%d samples=%d score=%d",
		key.PID, process, key.Remote(), strings.Join(signals, "+"), aggregate.TxBytes, aggregate.RxBytes, aggregate.Samples, aggregate.LastScore)
	if !e.rxObservation && slices.Contains(rules, StyxBeaconRuleAsymmetry) {
		summary += " (rx telemetry unavailable; volume+canary correlation, no ratio claim)"
	}
	return StyxIncident{
		ID:               fmt.Sprintf("INC-STYX-BEACON-%d-%d", now.UnixNano(), aggregate.LastScore),
		TimestampUTC:     now,
		Severity:         severity,
		Score:            aggregate.LastScore,
		ResponseScore:    aggregate.LastScore,
		PID:              key.PID,
		Process:          sanitizeStyxProcess(process),
		Remote:           key.Remote(),
		EventType:        aggregate.lastEvent,
		Category:         aggregate.lastCategory,
		Signals:          signals,
		RuleIDs:          rules,
		Decision:         aggregate.lastDecision,
		Action:           "none",
		Outcome:          "recorded by the StyX beacon detector; no active response from this sensor",
		Summary:          summary,
		TxBytes:          aggregate.TxBytes,
		RxBytes:          aggregate.RxBytes,
		IntervalSamples:  aggregate.Samples,
		CanaryCorrelated: canaryCorrelated,
	}
}
