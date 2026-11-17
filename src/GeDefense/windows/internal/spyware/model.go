// STATUS: PLATIN VGT SUPREME

// Package spyware implements Windows-specific anti-spyware sensors that target
// state-level and commercial surveillance tooling rather than generic malware:
// vulnerable-driver (BYOVD) loading, capability access to webcam / microphone /
// screen capture / location, hidden persistence (WMI, BITS, IFEO, COM, LSA,
// AppCertDlls) and LSASS credential dumping.
//
// The package separates classification (pure, unit-tested, no OS access) from
// the Win32 adapters (registry, event log) and from the engine lifecycle. That
// separation keeps every detection decision reproducible in tests and lets the
// control plane expose exactly the evidence that was observed.
package spyware

import (
	"strings"
	"time"
)

// Severity mirrors the rest of the product so findings can flow into the
// existing evidence and notification paths without a second severity scale.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Source identifies the sensor family that produced a finding.
type Source string

const (
	SourceBYOVD       Source = "byovd"
	SourceCapability  Source = "capability-access"
	SourcePersistence Source = "persistence"
	SourceLSASS       Source = "lsass-access"
)

// Finding is one bounded, evidence-carrying observation. It never claims more
// than the sensor actually read.
type Finding struct {
	ID          string    `json:"id"`
	Source      Source    `json:"source"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Asset       string    `json:"asset,omitempty"`
	ObservedUTC time.Time `json:"observedUtc"`
	Evidence    []string  `json:"evidence,omitempty"`
	// Response is what the engine actually did or recommends doing. It is
	// "OBSERVE_ONLY" until an enforcement adapter accepted the action.
	Response string `json:"response"`
	// DedupeKey groups repeated observations of the same asset/family.
	DedupeKey string `json:"dedupeKey"`
}

// Status is the honest engine state for the control plane.
type Status struct {
	Enabled          bool      `json:"enabled"`
	Mode             string    `json:"mode,omitempty"`
	ActiveEnforced   bool      `json:"activeEnforced"`
	BYOVDWatched     bool      `json:"byovdWatched"`
	CapabilityWatch  bool      `json:"capabilityWatch"`
	PersistenceWatch bool      `json:"persistenceWatch"`
	LSASSWatch       bool      `json:"lsassWatch"`
	Degraded         bool      `json:"degraded"`
	LastError        string    `json:"lastError,omitempty"`
	LastScanUTC      time.Time `json:"lastScanUtc"`
	Findings         int       `json:"findings"`
}

// Ledger is the evidence sink. It is an interface so the engine cannot depend
// on the concrete ledger implementation and stays testable.
type Ledger interface {
	Append(kind, detail, result string) error
}

// Bounded list limits. Untrusted or noisy inputs must never grow memory.
const (
	MaxFindings        = 512
	MaxEvidence        = 16
	maxDedupeEntries   = 2048
	maxDetailBytes     = 4096
	findingDedupeTTL   = 5 * time.Minute
	severityRankInfo   = 1
	severityRankMedium = 2
	severityRankHigh   = 3
	severityRankRank   = 4
)

func severityRank(value Severity) int {
	switch value {
	case SeverityCritical:
		return severityRankRank
	case SeverityHigh:
		return severityRankHigh
	case SeverityMedium:
		return severityRankMedium
	default:
		return severityRankInfo
	}
}

// sanitizeText bounds and normalizes text that originates from the operating
// system (registry values, image paths, command lines) before it is stored or
// rendered.
func sanitizeText(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxDetailBytes {
		value = value[:maxDetailBytes]
	}
	return value
}

// boundedEvidence copies at most MaxEvidence entries, dropping empty ones.
func boundedEvidence(values ...string) []string {
	result := make([]string, 0, MaxEvidence)
	for _, value := range values {
		if len(result) >= MaxEvidence {
			break
		}
		if trimmed := sanitizeText(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
