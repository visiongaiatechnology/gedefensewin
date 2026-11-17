// STATUS: PLATIN VGT SUPREME
package spyware

import (
	"strings"
	"sync"
	"time"
)

// Settings configure which anti-spyware sensors are active. CapabilityAllowed is
// the operator allowlist for capability access; a nil function denies everything
// (which is the safe default: an active camera nobody authorised is a finding).
// VerifyDriverSignature returns nil only for a driver image with a valid
// Authenticode chain. When it is nil the engine reports a driver signature as
// unverified instead of pretending it is unsigned.
type Settings struct {
	Enabled               bool
	BYOVD                 bool
	Capability            bool
	Persistence           bool
	LSASS                 bool
	CapabilityAllowed     func(path string) bool
	VerifyDriverSignature func(path string) error
	// OnFindingRecorded is an optional active-response adapter evaluated right
	// before a finding is stored and written to the ledger. Returning a non-empty
	// response replaces finding.Response only when enforcement actually ran.
	OnFindingRecorded func(finding Finding) string
}

// Engine classifies sensor observations into bounded, deduplicated findings and
// records them in the evidence ledger. It owns no OS resources itself; the
// adapters push observations in, which keeps the detector unit-testable and the
// lifecycle free of hidden goroutines.
type Engine struct {
	mu       sync.Mutex
	settings Settings
	ledger   Ledger
	findings []Finding
	dedupe   map[string]time.Time
	sigCache map[string]signatureEntry
	status   Status
	now      func() time.Time
}

type signatureEntry struct {
	status  string
	expires time.Time
}

const (
	signatureCacheTTL = 10 * time.Minute
	maxSignatureCache = 4096
)

// New builds an engine. A nil ledger is tolerated for tests and read-only
// diagnostic use; the engine then keeps findings in memory only.
func New(settings Settings, ledger Ledger) *Engine {
	engine := &Engine{
		settings: settings,
		ledger:   ledger,
		findings: make([]Finding, 0, MaxFindings),
		dedupe:   make(map[string]time.Time, 64),
		sigCache: make(map[string]signatureEntry, 64),
		now:      time.Now,
	}
	engine.status.Enabled = settings.Enabled
	engine.status.BYOVDWatched = settings.Enabled && settings.BYOVD
	engine.status.CapabilityWatch = settings.Enabled && settings.Capability
	engine.status.PersistenceWatch = settings.Enabled && settings.Persistence
	engine.status.LSASSWatch = settings.Enabled && settings.LSASS
	return engine
}

// HandleDriverService classifies one kernel service and records the finding. The
// signature status is measured through the configured verifier (cached), never
// assumed: an unverified driver is reported as unverified, not as unsigned.
func (e *Engine) HandleDriverService(service DriverService, posture SecurityPosture) *Finding {
	if !e.Enabled(SourceBYOVD) {
		return nil
	}
	service.Signature = e.driverSignatureStatus(service.ImagePath)
	return e.record(ClassifyDriverService(service, posture, e.now()))
}

// driverSignatureStatus verifies a driver image at most once per cache TTL.
func (e *Engine) driverSignatureStatus(path string) string {
	if strings.TrimSpace(path) == "" {
		return "unverified"
	}
	key := strings.ToLower(strings.TrimSpace(path))
	now := e.now()
	e.mu.Lock()
	if entry, cached := e.sigCache[key]; cached && now.Before(entry.expires) {
		e.mu.Unlock()
		return entry.status
	}
	verifier := e.settings.VerifyDriverSignature
	e.mu.Unlock()
	status := "unverified"
	if verifier != nil {
		if err := verifier(path); err == nil {
			status = "valid"
		} else {
			status = "invalid"
		}
	}
	e.mu.Lock()
	if len(e.sigCache) >= maxSignatureCache {
		e.sigCache = make(map[string]signatureEntry, 64)
	}
	e.sigCache[key] = signatureEntry{status: status, expires: now.Add(signatureCacheTTL)}
	e.mu.Unlock()
	return status
}

// HandleCapabilityStates classifies the current capability-consent state set.
func (e *Engine) HandleCapabilityStates(states []CapabilityState, workstationLocked bool) []Finding {
	if !e.Enabled(SourceCapability) {
		return nil
	}
	classifier := CapabilityClassifier{IsAllowed: e.settings.CapabilityAllowed, WorkstationLocked: workstationLocked}
	now := e.now()
	var recorded []Finding
	for _, state := range states {
		if finding := classifier.Classify(state, now); finding != nil {
			if stored := e.record(finding); stored != nil {
				recorded = append(recorded, *stored)
			}
		}
	}
	return recorded
}

// HandlePersistence classifies one persistence observation.
func (e *Engine) HandlePersistence(observation PersistenceObservation) *Finding {
	if !e.Enabled(SourcePersistence) {
		return nil
	}
	if observation.ObservedUTC.IsZero() {
		observation.ObservedUTC = e.now()
	}
	return e.record(ClassifyPersistence(observation))
}

// HandleLSASSAccess classifies one LSASS access-audit event.
func (e *Engine) HandleLSASSAccess(accessMask uint32, callerImage, callerSignature string) *Finding {
	if !e.Enabled(SourceLSASS) {
		return nil
	}
	return e.record(ClassifyLSASSAccess(accessMask, callerImage, callerSignature, e.now()))
}

// Enabled reports whether the sensor family is active.
func (e *Engine) Enabled(source Source) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.settings.Enabled {
		return false
	}
	switch source {
	case SourceBYOVD:
		return e.settings.BYOVD
	case SourceCapability:
		return e.settings.Capability
	case SourcePersistence:
		return e.settings.Persistence
	case SourceLSASS:
		return e.settings.LSASS
	default:
		return false
	}
}

// SetFindingResponseHook installs an optional post-classification active response
// hook. The callback runs outside the engine lock and must only return a new
// Response label when an actual enforcement action ran.
func (e *Engine) SetFindingResponseHook(hook func(Finding) string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.settings.OnFindingRecorded = hook
	e.mu.Unlock()
}

// record deduplicates and stores a finding. Repeated identical observations
// inside the dedupe window are suppressed but still count as observed, so a
// sustained capture attempt cannot hide behind deduplication.
func (e *Engine) record(finding *Finding) *Finding {
	if finding == nil {
		return nil
	}
	finding.ID = findingID(finding)
	finding.ObservedUTC = finding.ObservedUTC.UTC()

	e.mu.Lock()
	key := finding.DedupeKey
	if key == "" {
		key = finding.ID
	}
	if last, seen := e.dedupe[key]; seen && e.now().Sub(last) < findingDedupeTTL {
		e.mu.Unlock()
		return nil
	}
	if len(e.dedupe) >= maxDedupeEntries {
		cutoff := e.now().Add(-findingDedupeTTL)
		for dedupeKey, seen := range e.dedupe {
			if seen.Before(cutoff) {
				delete(e.dedupe, dedupeKey)
			}
		}
		if len(e.dedupe) >= maxDedupeEntries {
			e.dedupe = make(map[string]time.Time, 64)
		}
	}
	e.dedupe[key] = e.now()
	hook := e.settings.OnFindingRecorded
	copied := *finding
	copied.Evidence = append([]string(nil), finding.Evidence...)
	e.mu.Unlock()

	if hook != nil {
		if response := strings.TrimSpace(hook(copied)); response != "" {
			copied.Response = response
			finding.Response = response
		}
	}

	e.mu.Lock()
	e.findings = append(e.findings, copied)
	if len(e.findings) > MaxFindings {
		copy(e.findings, e.findings[len(e.findings)-MaxFindings:])
		e.findings = e.findings[:MaxFindings]
	}
	e.status.Findings = len(e.findings)
	ledger := e.ledger
	e.mu.Unlock()

	if ledger != nil {
		result := string(finding.Severity) + "|" + finding.Response
		if err := ledger.Append("spyware."+string(finding.Source), finding.Title, result); err != nil {
			e.mu.Lock()
			e.status.Degraded = true
			e.status.LastError = sanitizeText(err.Error())
			e.mu.Unlock()
		}
	}
	return &copied
}

// Findings returns the newest findings first, bounded by limit.
func (e *Engine) Findings(limit int) []Finding {
	if limit <= 0 || limit > MaxFindings {
		limit = 100
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	start := len(e.findings) - limit
	if start < 0 {
		start = 0
	}
	result := make([]Finding, 0, len(e.findings)-start)
	for index := len(e.findings) - 1; index >= start; index-- {
		result = append(result, e.findings[index])
	}
	return result
}

// Status returns the honest engine state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.status
	status.Findings = len(e.findings)
	return status
}

// MarkScan records that a collector completed a scan cycle.
func (e *Engine) MarkScan(at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if at.IsZero() {
		at = e.now()
	}
	e.status.LastScanUTC = at.UTC()
}

// findingID derives a stable, bounded identifier from source and dedupe key.
func findingID(finding *Finding) string {
	key := strings.ToLower(strings.TrimSpace(finding.DedupeKey))
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(finding.Asset + "|" + finding.Title))
	}
	// FNV-1a: stable, dependency-free, and only used as a display/correlation id.
	var hash uint64 = 14695981039346656037
	for index := 0; index < len(key) && index < 512; index++ {
		hash ^= uint64(key[index])
		hash *= 1099511628211
	}
	const hexDigits = "0123456789abcdef"
	buffer := make([]byte, 16)
	for index := 15; index >= 0; index-- {
		buffer[index] = hexDigits[hash&0xF]
		hash >>= 4
	}
	return string(finding.Source) + "-" + string(buffer)
}
