// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"context"
	"fmt"
	"time"
)

const (
	// styxPollInterval is the flow-statistics cadence of the passive egress
	// detector. It matches the network watcher cadence so window deltas line up.
	styxPollInterval = 2 * time.Second
	// maximumStyxAIncidents bounds the in-memory incident projection.
	maximumStyxIncidents = 256
)

// startStyxRuntime constructs the passive StyX egress/beacon detector. It runs
// in observe mode by default: the detector never enforces anything (Action is
// always "none"), so enabling passive detection is safe and its findings are
// evidence. Enforce mode requires an explicit operator decision and is not
// activated here.
func (e *Engine) startStyxRuntime() {
	if e == nil {
		return
	}
	settings := DefaultStyxSettings()
	settings.Enabled = true
	settings.Mode = StyxModeObserve
	beacon, err := NewStyxBeaconEngine(StyxBeaconConfig{
		Settings: settings,
		// The iphlpapi TCP table is available on Windows; data-estats and DNS
		// attribution are proven only after real observations, so they start
		// false and are upgraded dynamically by the collection loop.
		FlowCapabilityKnown:     true,
		RxObservationAvailable:  false,
		DNSObservationAvailable: false,
	})
	if err != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("styx.unavailable", "STYX egress/beacon detector could not be constructed; passive beacon detection is DISABLED", err.Error())
		}
		return
	}
	e.styx = beacon
	e.styxCollector = NewStyxCollector(StyxCollectorConfig{Now: func() time.Time { return time.Now().UTC() }})
}

// styxLoop polls flow statistics until the engine context is cancelled. Every
// poll either yields evidence-backed samples or an error; a failed poll never
// produces synthetic zero samples.
func (e *Engine) styxLoop(ctx context.Context) {
	if e == nil || e.styx == nil || e.styxCollector == nil {
		return
	}
	ticker := time.NewTicker(styxPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			incidents, err := e.styxCollector.PollInto(ctx, e.styx)
			if err != nil {
				if ctx.Err() == nil {
					e.logSentinelThrottled("styx.collector", "TCP flow statistics unavailable", err.Error())
				}
			}
			if collectorStatus := e.styxCollector.Status(); collectorStatus.DataObservationAvailable {
				// Receive bytes are provable only after a successful estats read;
				// the detector upgrades its signal 2 capability from this fact.
				e.styx.SetRxObservationAvailable(true)
			}
			for _, incident := range incidents {
				e.recordStyxIncident(incident)
			}
		}
	}
}

// recordStyxIncident stores a bounded incident projection and writes the
// evidence record. StyX incidents are evidence only; no process is terminated
// and no egress policy is changed by this path.
func (e *Engine) recordStyxIncident(incident StyxIncident) {
	if e == nil || incident.ID == "" {
		return
	}
	e.mu.Lock()
	e.styxIncidents = append(e.styxIncidents, incident)
	if len(e.styxIncidents) > maximumStyxIncidents {
		copy(e.styxIncidents, e.styxIncidents[len(e.styxIncidents)-maximumStyxIncidents:])
		e.styxIncidents = e.styxIncidents[:maximumStyxIncidents]
	}
	e.mu.Unlock()

	if e.ledger != nil {
		detail := fmt.Sprintf("styX %s score=%d signals=%v", incident.Category, incident.Score, incident.Signals)
		_ = e.ledger.Append("styx.incident", truncate(detail, 512), incident.ID)
	}
	e.notifyEvent(notificationKindThreatIntel, incident.Severity, "STYX Egress-/Beacon-Evidenz", truncate(incident.Summary, 512))
}

// StyxStatus returns the bounded detector status. A missing detector is reported
// honestly as unavailable instead of inventing health.
func (e *Engine) StyxStatus() StyxStatus {
	if e == nil || e.styx == nil {
		return StyxStatus{Mode: StyxModeOff, SensorState: "unavailable", Capability: "missing", Top: []StyxFlowSnapshot{}}
	}
	return e.styx.Status()
}

// StyxCollectorStatus returns the bounded flow-collector projection.
func (e *Engine) StyxCollectorStatus() StyxCollectorStatus {
	if e == nil || e.styxCollector == nil {
		return StyxCollectorStatus{}
	}
	return e.styxCollector.Status()
}

// StyxIncidents returns the newest incidents first, bounded by limit.
func (e *Engine) StyxIncidents(limit int) []StyxIncident {
	if limit <= 0 || limit > maximumStyxIncidents {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.styxIncidents) - limit
	if start < 0 {
		start = 0
	}
	result := make([]StyxIncident, 0, len(e.styxIncidents)-start)
	for index := len(e.styxIncidents) - 1; index >= start; index-- {
		result = append(result, e.styxIncidents[index])
	}
	return result
}
