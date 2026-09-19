// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/threatintel"
)

func (e *Engine) evaluateNetwork(event networkEvent) {
	e.networkObserved.Add(1)
	address, err := netip.ParseAddr(event.RemoteIP)
	if err != nil {
		return
	}
	match := e.feeds.Lookup(address)
	if !match.Found {
		return
	}
	e.networkThreatHits.Add(1)
	now := event.TimestampUTC
	finding := NetworkFinding{
		ID:               networkFindingID(event),
		TimestampUTC:     now,
		PID:              event.PID,
		RemoteIP:         event.RemoteIP,
		RemotePort:       event.RemotePort,
		LocalPort:        event.LocalPort,
		ThreatIntel:      true,
		ProtectedNetwork: match.Protected,
		ThreatAction:     match.Action,
		ThreatSources:    append([]string(nil), match.Sources...),
		Severity:         severityForThreatAction(match.Action),
		Response:         responseForThreatAction(match.Action, false, match.Protected),
	}

	e.mu.Lock()
	e.purgeRecentProcessesLocked(now)
	recent, correlated := e.recentProcesses[event.PID]
	if correlated && validateObservedProcess(recent.event) != nil {
		delete(e.recentProcesses, event.PID)
		correlated = false
	}
	if correlated {
		finding.Image = recent.event.Image
		finding.CorrelationID = recent.analysis.ID
		storySignals := appendUniqueCopy(recent.analysis.Signals, "network.threat-intelligence."+strings.ToLower(string(match.Action)))
		if match.Protected {
			storySignals = appendUniqueCopy(storySignals, "network.protected-management-prefix")
		}
		story := AttackStory{
			ID:                attackStoryID(recent.analysis.ID, event),
			StartedUTC:        recent.analysis.TimestampUTC,
			UpdatedUTC:        now,
			PID:               event.PID,
			Image:             recent.event.Image,
			ProcessAnalysisID: recent.analysis.ID,
			Severity:          severityForCorrelatedThreat(match.Action),
			Signals:           storySignals,
			ThreatAction:      match.Action,
			ProtectedNetwork:  match.Protected,
			ThreatSources:     append([]string(nil), match.Sources...),
			RemoteIP:          event.RemoteIP,
			RemotePort:        event.RemotePort,
			Response:          "CORRELATED",
		}
		if match.Protected {
			story.Response = "PROTECTED_NETWORK_CORRELATED"
		} else if recent.analysis.ResponseAuthority && match.Action != threatintel.ActionAnnotateOnly {
			story.Severity = SeverityCritical
			story.Response = "HOST_RESPONSE_ELIGIBLE"
		}
		e.attackStories = append(e.attackStories, story)
		if len(e.attackStories) > maximumAttackStories {
			copy(e.attackStories, e.attackStories[len(e.attackStories)-maximumAttackStories:])
			e.attackStories = e.attackStories[:maximumAttackStories]
		}
	}
	e.networkFindings = append(e.networkFindings, finding)
	if len(e.networkFindings) > maximumNetworkFindings {
		copy(e.networkFindings, e.networkFindings[len(e.networkFindings)-maximumNetworkFindings:])
		e.networkFindings = e.networkFindings[:maximumNetworkFindings]
	}
	e.mu.Unlock()

	ledgerResult := "threat-intelligence-" + strings.ToLower(string(match.Action))
	if match.Protected {
		ledgerResult += "-protected-network"
	}
	_ = e.ledger.Append("mhx.network", event.RemoteIP, ledgerResult)
	if !correlated || !recent.analysis.ResponseAuthority || match.Protected || match.Action == threatintel.ActionAnnotateOnly || e.Mode() == "monitor" {
		return
	}
	// A threat-intelligence match never grants process-kill authority by itself.
	// The process must already carry independent response authority and its
	// identity is revalidated immediately before termination.
	if err := terminateProcess(recent.event); err == nil {
		e.blocked.Add(1)
		_ = e.ledger.Append("mhx.correlated-response", recent.analysis.Detection, "terminated-after-network-correlation")
	}
}

func severityForThreatAction(action threatintel.Action) Severity {
	switch action {
	case threatintel.ActionBlock:
		return SeverityHigh
	case threatintel.ActionCorrelateOnly:
		return SeverityMedium
	case threatintel.ActionAnnotateOnly:
		return SeverityInformational
	default:
		return SeverityLow
	}
}

func severityForCorrelatedThreat(action threatintel.Action) Severity {
	switch action {
	case threatintel.ActionBlock:
		return SeverityHigh
	case threatintel.ActionCorrelateOnly:
		return SeverityHigh
	case threatintel.ActionAnnotateOnly:
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func responseForThreatAction(action threatintel.Action, blocked, protected bool) string {
	if protected {
		if blocked {
			return "PROTECTED_NETWORK_WFP_BLOCK_OBSERVED"
		}
		return "PROTECTED_NETWORK_OBSERVED"
	}
	if blocked {
		return "WFP_BLOCK_OBSERVED"
	}
	switch action {
	case threatintel.ActionBlock:
		return "BLOCK_DESTINATION_OBSERVED"
	case threatintel.ActionCorrelateOnly:
		return "CORRELATED_ONLY"
	case threatintel.ActionAnnotateOnly:
		return "ANNOTATED_ONLY"
	default:
		return "THREAT_INTELLIGENCE_MATCH"
	}
}

func (e *Engine) evaluateWFPBlock(event wfpBlockEvent) {
	e.networkObserved.Add(1)
	address, err := netip.ParseAddr(event.RemoteIP)
	if err != nil {
		return
	}
	match := e.feeds.Lookup(address)
	if !match.Found {
		return
	}
	e.networkThreatHits.Add(1)
	finding := NetworkFinding{
		ID:               wfpNetworkFindingID(event),
		TimestampUTC:     event.TimestampUTC,
		PID:              event.PID,
		Image:            filepath.Base(event.Application),
		RemoteIP:         event.RemoteIP,
		RemotePort:       event.RemotePort,
		LocalPort:        event.LocalPort,
		ThreatIntel:      true,
		ProtectedNetwork: match.Protected,
		ThreatAction:     match.Action,
		ThreatSources:    append([]string(nil), match.Sources...),
		Severity:         severityForThreatAction(match.Action),
		Response:         responseForThreatAction(match.Action, true, match.Protected),
		FilterOrigin:     event.FilterOrigin,
	}
	if event.GeDefenseOrigin {
		if match.Protected {
			finding.Response = "GEDEFENSE_STALE_PROTECTED_NETWORK_BLOCK"
		} else {
			finding.Response = "GEDEFENSE_WFP_BLOCK"
		}
	}

	e.mu.Lock()
	e.purgeRecentProcessesLocked(event.TimestampUTC)
	recent, correlated := e.recentProcesses[event.PID]
	if correlated && validateObservedProcess(recent.event) != nil {
		delete(e.recentProcesses, event.PID)
		correlated = false
	}
	if correlated {
		finding.Image = recent.event.Image
		finding.CorrelationID = recent.analysis.ID
		storySignals := appendUniqueCopy(recent.analysis.Signals, "network.wfp-block."+strings.ToLower(string(match.Action)))
		if match.Protected {
			storySignals = appendUniqueCopy(storySignals, "network.protected-management-prefix")
		}
		story := AttackStory{
			ID:                wfpAttackStoryID(recent.analysis.ID, event),
			StartedUTC:        recent.analysis.TimestampUTC,
			UpdatedUTC:        event.TimestampUTC,
			PID:               event.PID,
			Image:             recent.event.Image,
			ProcessAnalysisID: recent.analysis.ID,
			Severity:          severityForCorrelatedThreat(match.Action),
			Signals:           storySignals,
			ThreatAction:      match.Action,
			ProtectedNetwork:  match.Protected,
			ThreatSources:     append([]string(nil), match.Sources...),
			RemoteIP:          event.RemoteIP,
			RemotePort:        event.RemotePort,
			Response:          "NETWORK_BLOCKED",
		}
		if match.Protected {
			story.Response = "PROTECTED_NETWORK_BLOCK_OBSERVED"
		} else if event.GeDefenseOrigin {
			story.Response = "GEDEFENSE_NETWORK_BLOCKED"
		}
		if !match.Protected && recent.analysis.ResponseAuthority && match.Action != threatintel.ActionAnnotateOnly {
			story.Severity = SeverityCritical
			story.Response = "NETWORK_BLOCKED_HOST_RESPONSE_AUTHORITY_PRESENT"
		}
		e.attackStories = append(e.attackStories, story)
		if len(e.attackStories) > maximumAttackStories {
			copy(e.attackStories, e.attackStories[len(e.attackStories)-maximumAttackStories:])
			e.attackStories = e.attackStories[:maximumAttackStories]
		}
	}
	e.networkFindings = append(e.networkFindings, finding)
	if len(e.networkFindings) > maximumNetworkFindings {
		copy(e.networkFindings, e.networkFindings[len(e.networkFindings)-maximumNetworkFindings:])
		e.networkFindings = e.networkFindings[:maximumNetworkFindings]
	}
	e.mu.Unlock()
	result := "wfp-block-threat-intelligence-" + strings.ToLower(string(match.Action))
	if match.Protected {
		result += "-protected-network"
	}
	if event.GeDefenseOrigin {
		result = "gedefense-wfp-block-" + strings.ToLower(string(match.Action))
		if match.Protected {
			result += "-stale-protected-network"
		}
	}
	_ = e.ledger.Append("mhx.network", event.RemoteIP, result)
}

func wfpNetworkFindingID(event wfpBlockEvent) string {
	payload := fmt.Sprintf("wfp\x00%d\x00%d\x00%s\x00%d", event.RecordID, event.PID, event.RemoteIP, event.RemotePort)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}

func wfpAttackStoryID(analysisID string, event wfpBlockEvent) string {
	payload := fmt.Sprintf("%s\x00wfp\x00%d", analysisID, event.RecordID)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}

func (e *Engine) purgeRecentProcessesLocked(now time.Time) {
	if len(e.recentProcesses) == 0 {
		return
	}
	for pid, record := range e.recentProcesses {
		if now.After(record.expires) {
			delete(e.recentProcesses, pid)
		}
	}
}

func (e *Engine) NetworkFindings(limit int) []NetworkFinding {
	if limit <= 0 || limit > maximumNetworkFindings {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.networkFindings) - limit
	if start < 0 {
		start = 0
	}
	result := append([]NetworkFinding(nil), e.networkFindings[start:]...)
	for index := range result {
		result[index].ThreatSources = append([]string(nil), result[index].ThreatSources...)
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func (e *Engine) AttackStories(limit int) []AttackStory {
	if limit <= 0 || limit > maximumAttackStories {
		limit = 100
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	start := len(e.attackStories) - limit
	if start < 0 {
		start = 0
	}
	result := make([]AttackStory, 0, len(e.attackStories)-start)
	for _, story := range e.attackStories[start:] {
		copyStory := story
		copyStory.Signals = append([]string(nil), story.Signals...)
		copyStory.ThreatSources = append([]string(nil), story.ThreatSources...)
		result = append(result, copyStory)
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func appendUniqueCopy(values []string, value string) []string {
	result := append([]string(nil), values...)
	for _, existing := range result {
		if existing == value {
			return result
		}
	}
	return append(result, value)
}

func networkFindingID(event networkEvent) string {
	payload := fmt.Sprintf("%d\x00%s\x00%d\x00%s", event.PID, event.RemoteIP, event.RemotePort, event.TimestampUTC.Format(time.RFC3339Nano))
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}

func attackStoryID(analysisID string, event networkEvent) string {
	payload := fmt.Sprintf("%s\x00%s\x00%d", analysisID, event.RemoteIP, event.RemotePort)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:16])
}
