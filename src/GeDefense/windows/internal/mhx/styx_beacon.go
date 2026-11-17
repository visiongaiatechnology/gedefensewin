// STATUS: PLATIN VGT SUPREME
package mhx

// Windows V6 Phase 1: the STYX_BEACON detector.
//
// 1:1 port of control/styx_beacon.go (docs/POINT3-EGRESS-BEACON.md §8.2). It is
// a passive sensor: it never reacts, never invents DNS or rx telemetry and
// reports mode=off as off. Three signals are evaluated per flow:
//
//  1. BEACON_PERIODICITY  - low CV of inter-arrival times over enough samples.
//  2. EXFIL_ASYMMETRY     - provable tx/rx asymmetry, or (without rx telemetry)
//     a volume threshold that only counts together with a canary correlation.
//  3. DIRECT_IP_NO_DNS    - direct-IP egress; dead while DNS attribution is
//     unavailable (DNSObservationAvailable=false), never a fake signal.
//
// Combination, score mapping (120/200/250/80, >=2 signals => 250 "contain"),
// severity (HIGH/CRITICAL), dedupe (300 s), rate limit (6/min), the 3-strike
// ring-overflow degradation and the canary lookback (900 s) mirror Linux V6.
// All state is behind one mutex; no goroutine is started here.

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// StyxBeaconEventPeriodicity / Asymmetry / DirectIP are the incident event
	// types (Linux V6 wire vocabulary).
	StyxBeaconEventPeriodicity = "BEACON_PERIODICITY"
	StyxBeaconEventAsymmetry   = "EXFIL_ASYMMETRY"
	StyxBeaconEventDirectIP    = "DIRECT_IP_NO_DNS"
	// StyxBeaconRulePeriodicity / Asymmetry / DirectIP are the rule identifiers.
	StyxBeaconRulePeriodicity = "STYX.BEACON.PERIODIC"
	StyxBeaconRuleAsymmetry   = "STYX.EXFIL.ASYMMETRY"
	StyxBeaconRuleDirectIP    = "STYX.EGRESS.DIRECT_IP"

	// StyxCategoryCommandAndControl / StyxCategoryExfiltration are the XDR
	// categories the Linux V6 detector reports.
	StyxCategoryCommandAndControl = "COMMAND_AND_CONTROL"
	StyxCategoryExfiltration      = "EXFILTRATION"
	// StyxDecisionAlert / StyxDecisionContain are the Linux V6 decision strings.
	StyxDecisionAlert   = "alert"
	StyxDecisionContain = "contain"

	styxBeaconSensorName = "STYX_BEACON"
	styMaxProcessName    = 32
)

// StyxBeaconConfig is the immutable construction configuration of the detector.
// Capability flags describe what the source can prove, not what it hopes to see:
// leaving DNSObservationAvailable/RxObservationAvailable false keeps the
// corresponding signals honest (they stay unknown instead of firing).
type StyxBeaconConfig struct {
	// Settings is validated with NormalizeStyxSettings by the constructor.
	Settings StyxSettings
	// FlowCapabilityKnown states that flow telemetry is actually available. A
	// false value makes the sensor report "unavailable" and disables ingestion.
	FlowCapabilityKnown bool
	// RxObservationAvailable states that the source can prove receive bytes.
	RxObservationAvailable bool
	// DNSObservationAvailable states that DNS attribution exists. Phase 1 on
	// Windows has no DNS attribution, so this must stay false.
	DNSObservationAvailable bool
	// CanaryCorrelation is the contextual hook for signal 2. It must not call
	// back into the engine (it runs under the detector lock).
	CanaryCorrelation func(pid int, since time.Time) bool
	// Now, when set, is the detector clock (tests); UTC is applied.
	Now func() time.Time
	// PruneInterval is the minimum interval between TTL/dedupe sweeps.
	PruneInterval time.Duration
}

// StyxBeaconEngine is the bounded, thread-safe passive STYX detector.
type StyxBeaconEngine struct {
	mu               sync.Mutex
	settings         StyxSettings
	thresholds       StyxBeaconThresholds
	resolverPrefixes []netip.Prefix
	flowCapability   bool
	rxObservation    bool
	dnsObservation   bool
	canary           func(pid int, since time.Time) bool
	now              func() time.Time
	pruneInterval    time.Duration

	flows     *styxFlowTable
	dedupe    map[string]time.Time
	incidents []time.Time
	degraded  bool

	overflowPolls int
	cleanPolls    int

	events           uint64
	emittedIncidents uint64
	suppressed       uint64
	dropped          uint64
	overflowRecords  uint64

	lastPrune time.Time
}

// StyxIncident is declared in styx_status.go together with the bounded status
// projection: both are the only data that leaves the detector.

// NewStyxBeaconEngine validates the settings and builds a detector. It never
// panics: invalid settings are returned as an error and no engine is created.
func NewStyxBeaconEngine(cfg StyxBeaconConfig) (*StyxBeaconEngine, error) {
	settings, err := NormalizeStyxSettings(cfg.Settings)
	if err != nil {
		return nil, fmt.Errorf("styX beacon settings: %w", err)
	}
	resolvers, err := settings.DNSResolverPrefixes()
	if err != nil {
		return nil, fmt.Errorf("styX beacon resolver prefixes: %w", err)
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.PruneInterval <= 0 {
		cfg.PruneInterval = 5 * time.Second
	}
	return &StyxBeaconEngine{
		settings:         settings,
		thresholds:       settings.Thresholds,
		resolverPrefixes: resolvers,
		flowCapability:   cfg.FlowCapabilityKnown,
		rxObservation:    cfg.RxObservationAvailable,
		dnsObservation:   cfg.DNSObservationAvailable,
		canary:           cfg.CanaryCorrelation,
		now:              cfg.Now,
		pruneInterval:    cfg.PruneInterval,
		flows:            newStyxFlowTable(),
		dedupe:           make(map[string]time.Time, 16),
	}, nil
}

// SensorState reports the honest detector state: unavailable without capability,
// off in mode=off, degraded after an overflow series, active otherwise.
func (e *StyxBeaconEngine) SensorState() string {
	if e == nil {
		return "unavailable"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sensorStateLocked()
}

func (e *StyxBeaconEngine) sensorStateLocked() string {
	if e == nil || !e.settings.Enabled || !e.flowCapability {
		return "unavailable"
	}
	mode := e.settings.EffectiveMode()
	if mode != StyxModeObserve && mode != StyxModeEnforce {
		return "off"
	}
	if e.degraded {
		return "degraded"
	}
	return "active"
}

func (e *StyxBeaconEngine) activeLocked() bool {
	if e == nil || !e.settings.Enabled || !e.flowCapability {
		return false
	}
	mode := e.settings.EffectiveMode()
	return mode == StyxModeObserve || mode == StyxModeEnforce
}

// SetFlowCapabilityKnown updates the flow-capability projection honestly.
func (e *StyxBeaconEngine) SetFlowCapabilityKnown(known bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.flowCapability = known
	e.mu.Unlock()
}

// SetRxObservationAvailable updates the receive-byte capability. Setting it to
// false always wins: any later volume-only finding keeps the "no ratio claim"
// wording and cannot raise the ratio score.
func (e *StyxBeaconEngine) SetRxObservationAvailable(available bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.rxObservation = available
	e.mu.Unlock()
}

// SetDNSObservationAvailable updates the DNS attribution capability. Phase 1 on
// Windows has none; false keeps signal 3 dead instead of firing on a guess.
func (e *StyxBeaconEngine) SetDNSObservationAvailable(available bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.dnsObservation = available
	e.mu.Unlock()
}

// SetCanaryCorrelation installs or clears the canary-correlation hook. The hook
// runs under the detector lock and must not call back into the engine.
func (e *StyxBeaconEngine) SetCanaryCorrelation(hook func(pid int, since time.Time) bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.canary = hook
	e.mu.Unlock()
}

// Settings returns a deep copy of the active StyX detector settings.
func (e *StyxBeaconEngine) Settings() StyxSettings {
	if e == nil {
		return DefaultStyxSettings()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings.Clone()
}

// SetMode switches the StyX detector mode atomically between off, observe and
// enforce without dropping tracked flows.
func (e *StyxBeaconEngine) SetMode(mode string) error {
	if e == nil {
		return fmt.Errorf("styX beacon engine is nil")
	}
	normalized, err := styxNormalizeMode(mode)
	if err != nil {
		return err
	}
	e.mu.Lock()
	next := e.settings.Clone()
	e.mu.Unlock()
	if normalized == StyxModeOff {
		next.Enabled = false
		next.Mode = StyxModeOff
	} else {
		next.Enabled = true
		next.Mode = normalized
	}
	return e.SetSettings(next)
}

// SetSettings applies a validated settings revision. Tracked flows are kept (the
// TTL bounds them); the capability flags are not changed by this call.
func (e *StyxBeaconEngine) SetSettings(settings StyxSettings) error {
	if e == nil {
		return fmt.Errorf("styX beacon engine is nil")
	}
	normalized, err := NormalizeStyxSettings(settings)
	if err != nil {
		return err
	}
	resolvers, err := normalized.DNSResolverPrefixes()
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.settings = normalized
	e.thresholds = normalized.Thresholds
	e.resolverPrefixes = resolvers
	e.mu.Unlock()
	return nil
}

// Observe ingests one flow window sample and reports a finding when one is
// warranted. Invalid samples are counted as dropped, never guessed.
func (e *StyxBeaconEngine) Observe(sample StyxFlowSample) (StyxIncident, bool) {
	if e == nil {
		return StyxIncident{}, false
	}
	now := e.now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.activeLocked() {
		return StyxIncident{}, false
	}
	e.events++
	incident, emitted := e.observeLocked(sample, now)
	if emitted {
		e.emittedIncidents++
	}
	if e.lastPrune.IsZero() || now.Sub(e.lastPrune) >= e.pruneInterval {
		e.pruneLocked(now)
	}
	return incident, emitted
}

// ObserveBatch ingests samples in order and returns the emitted findings.
func (e *StyxBeaconEngine) ObserveBatch(samples []StyxFlowSample) []StyxIncident {
	if e == nil || len(samples) == 0 {
		return nil
	}
	incidents := make([]StyxIncident, 0, 1)
	for index := range samples {
		if incident, ok := e.Observe(samples[index]); ok {
			incidents = append(incidents, incident)
		}
	}
	return incidents
}

func (e *StyxBeaconEngine) observeLocked(sample StyxFlowSample, now time.Time) (StyxIncident, bool) {
	key, err := sample.FlowKey()
	if err != nil {
		e.dropped++
		return StyxIncident{}, false
	}
	aggregate, ok := e.flows.acquire(key, now)
	if !ok {
		// Per-identity cardinality pressure: drop the new flow, never the old
		// evidence, and report it instead of silently widening the table.
		e.dropped++
		return StyxIncident{}, false
	}
	if aggregate.Comm == "" {
		aggregate.Comm = sanitizeStyxProcess(sample.Comm)
	}
	if aggregate.ProcessPath == "" {
		aggregate.ProcessPath = sanitizeStyxProcessPath(sample.ProcessPath)
	}
	if aggregate.LocalPort == 0 && sample.LocalPort != 0 {
		aggregate.LocalPort = sample.LocalPort
	}
	activity := sample.TxObservationAvailable && (sample.TxBytes > 0 || (sample.RxObservationAvailable && sample.RxBytes > 0))
	observedAt := sample.Timestamp
	if observedAt.IsZero() {
		observedAt = now
	} else {
		observedAt = observedAt.UTC()
	}
	// Only windows with proven activity count as inter-arrival samples. Without
	// this, a polled source would feed its own poll cadence into the periodicity
	// signal and manufacture beacons out of ordinary TCP keepalives.
	if activity && !aggregate.LastSeen.IsZero() && observedAt.After(aggregate.LastSeen) {
		aggregate.ObserveInterval(observedAt.Sub(aggregate.LastSeen).Seconds())
	}
	if sample.TxObservationAvailable {
		aggregate.AddTxBytes(sample.TxBytes)
	}
	if sample.RxObservationAvailable {
		aggregate.AddRxBytes(sample.RxBytes)
	}
	aggregate.LastSeen = now
	if e.dnsObservation && e.resolverMatchesLocked(aggregate.Key.RemoteIP) {
		aggregate.DNSSeen = true
	}
	return e.evaluateLocked(aggregate, now)
}

// evaluateLocked runs the three Linux V6 signals and the score mapping.
func (e *StyxBeaconEngine) evaluateLocked(aggregate *FlowAggregate, now time.Time) (StyxIncident, bool) {
	thresholds := e.thresholds
	signals := make([]string, 0, 3)
	rules := make([]string, 0, 3)
	category, eventType := StyxCategoryCommandAndControl, ""
	bestScore := 0
	canaryCorrelated := false

	if aggregate.Samples >= int64(thresholds.PeriodicityMinSamples) &&
		aggregate.TxObservationAvailable && aggregate.TxBytes >= thresholds.PeriodicityMinTxBytes &&
		aggregate.IntervalCV() <= thresholds.PeriodicityMaxCV &&
		aggregate.IntervalMean() >= thresholds.PeriodicityMinIntervalSeconds &&
		aggregate.IntervalMean() <= thresholds.PeriodicityMaxIntervalSeconds {
		signals = append(signals, StyxBeaconEventPeriodicity)
		rules = append(rules, StyxBeaconRulePeriodicity)
		bestScore, eventType = 120, StyxBeaconEventPeriodicity
	}

	asymmetry, asymmetryScore := false, 200
	canaryWindow := now.Add(-time.Duration(thresholds.FlowTTLSeconds) * time.Second)
	if e.rxObservation && aggregate.RxObservationAvailable {
		if aggregate.TxBytes >= thresholds.ExfilMinTxBytes {
			if aggregate.RxBytes == 0 {
				asymmetry = aggregate.Samples >= int64(thresholds.ExfilZeroRxMinSamples) &&
					aggregate.TxBytes >= thresholds.ExfilZeroRxMinTxBytes
			} else {
				asymmetry = float64(aggregate.TxBytes)/float64(aggregate.RxBytes) >= thresholds.ExfilRatio
			}
		}
		if asymmetry && e.canaryLocked(aggregate.Key.PID, canaryWindow) {
			asymmetryScore = 250
			canaryCorrelated = true
		}
	} else if aggregate.TxObservationAvailable && aggregate.TxBytes >= thresholds.CanaryVolumeMinTxBytes &&
		aggregate.Samples >= int64(thresholds.ExfilZeroRxMinSamples) &&
		e.canaryLocked(aggregate.Key.PID, canaryWindow) {
		// Phase-1 honesty: without rx telemetry there is no ratio claim. Only a
		// canary correlation can turn volume into an exfiltration finding.
		asymmetry = true
		canaryCorrelated = true
	}
	if asymmetry {
		signals = append(signals, StyxBeaconEventAsymmetry)
		rules = append(rules, StyxBeaconRuleAsymmetry)
		category = StyxCategoryExfiltration
		if asymmetryScore > bestScore {
			bestScore, eventType = asymmetryScore, StyxBeaconEventAsymmetry
		}
	}

	// Signal 3 is dead in Phase 1 (no DNS attribution). It may only fire when the
	// source truly proves DNS observation and the destination is not a resolver.
	if e.dnsObservation && !aggregate.DNSSeen && !e.resolverMatchesLocked(aggregate.Key.RemoteIP) &&
		aggregate.TxBytes >= thresholds.DirectIPMinTxBytes {
		signals = append(signals, StyxBeaconEventDirectIP)
		rules = append(rules, StyxBeaconRuleDirectIP)
		if 80 > bestScore {
			bestScore, eventType = 80, StyxBeaconEventDirectIP
		}
	}

	aggregate.LastSignals = append(aggregate.LastSignals[:0], signals...)
	aggregate.LastScore = 0
	if len(signals) == 0 {
		return StyxIncident{}, false
	}
	score, decision := bestScore, StyxDecisionAlert
	if len(signals) >= 2 {
		score, decision = 250, StyxDecisionContain
	}
	aggregate.LastScore = score
	aggregate.lastRules = rules
	aggregate.lastEvent = eventType
	aggregate.lastCategory = category
	aggregate.lastDecision = decision
	if e.degraded {
		e.suppressed++
		return StyxIncident{}, false
	}
	if !e.claimIncidentLocked(now, aggregate.Key, rules) {
		e.suppressed++
		return StyxIncident{}, false
	}
	return e.buildIncidentLocked(aggregate, now, canaryCorrelated), true
}

// claimIncidentLocked applies the per-fingerprint dedupe and the global incident
// rate limit. It reports whether this finding may be emitted.
func (e *StyxBeaconEngine) claimIncidentLocked(now time.Time, key FlowKey, rules []string) bool {
	fingerprint := fmt.Sprintf("styx-beacon:%d:%s:%d:%s", key.PID, key.RemoteIP.String(), key.RemotePort, strings.Join(rules, ","))
	if until, exists := e.dedupe[fingerprint]; exists && now.Before(until) {
		return false
	}
	kept := e.incidents[:0]
	for _, stamp := range e.incidents {
		if stamp.After(now.Add(-time.Minute)) {
			kept = append(kept, stamp)
		}
	}
	e.incidents = kept
	if len(e.incidents) >= e.thresholds.MaxIncidentsPerMinute {
		return false
	}
	e.incidents = append(e.incidents, now)
	e.dedupe[fingerprint] = now.Add(time.Duration(e.thresholds.DedupeSeconds) * time.Second)
	return true
}

func (e *StyxBeaconEngine) canaryLocked(pid int, since time.Time) bool {
	hook := e.canary
	if hook == nil {
		return false
	}
	return hook(pid, since)
}

func (e *StyxBeaconEngine) resolverMatchesLocked(destination netip.Addr) bool {
	for _, prefix := range e.resolverPrefixes {
		if prefix.IsValid() && prefix.Contains(destination) {
			return true
		}
	}
	return false
}

// RecordFlowPoll records one source poll's dropped-record delta and applies the
// 3-strike degradation/recovery contract. Degraded suppresses findings and says
// so; it never claims that no beacons exist.
func (e *StyxBeaconEngine) RecordFlowPoll(dropped uint64) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.overflowRecords = saturatingAdd(e.overflowRecords, dropped)
	if dropped == 0 {
		e.overflowPolls = 0
		e.cleanPolls++
		if e.degraded && e.cleanPolls >= 3 {
			e.degraded = false
		}
		return
	}
	e.cleanPolls = 0
	e.overflowPolls++
	if e.overflowPolls >= 3 {
		e.degraded = true
	}
}

// Prune drops expired flows, dedupe fingerprints and rate-limit stamps.
func (e *StyxBeaconEngine) Prune(now time.Time) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if now.IsZero() {
		now = e.now().UTC()
	}
	e.pruneLocked(now.UTC())
}

func (e *StyxBeaconEngine) pruneLocked(now time.Time) {
	e.flows.prune(now)
	for fingerprint, until := range e.dedupe {
		if !now.Before(until) {
			delete(e.dedupe, fingerprint)
		}
	}
	kept := e.incidents[:0]
	for _, stamp := range e.incidents {
		if stamp.After(now.Add(-time.Minute)) {
			kept = append(kept, stamp)
		}
	}
	e.incidents = kept
	e.lastPrune = now
}

// sanitizeStyxProcess keeps a process name log-safe: bounded length, no control
// characters and no spaces. Anything suspicious degrades to the empty string.
func sanitizeStyxProcess(name string) string {
	if name == "" || len(name) > styMaxProcessName {
		return ""
	}
	if strings.IndexFunc(name, func(character rune) bool {
		return character < 0x20 || character == 0x7f || character == ' '
	}) >= 0 {
		return ""
	}
	return name
}

func sanitizeStyxProcessPath(path string) string {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" || len(cleaned) > 512 {
		return ""
	}
	if strings.IndexFunc(cleaned, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return ""
	}
	return cleaned
}
