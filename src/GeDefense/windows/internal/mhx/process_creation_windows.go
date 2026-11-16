// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// Native Security 4688 process-creation telemetry.
//
// The sensor subscribes to the Security event log through wevtapi
// (winapi.StreamEventLog) and parses the rendered event XML itself. This file
// owns the bounded, strict parser and the observation triage; watcher_windows.go
// owns the stream lifecycle.
//
// Triage never trusts the image file name alone. An event is observed when the
// file name is a tracked LOLBin, when its PE OriginalFilename is a tracked
// LOLBin but the file name differs (renamed system binary), when the command
// line carries an encoded PowerShell payload, or when a cheap behavioral
// signal matches. Everything else is dropped after one bounded version-resource
// lookup per unique image; no signature or hash work runs for dropped events.
const (
	// maximumProcessEventXMLBytes bounds one rendered event record before XML
	// decoding (also enforced by the wevtapi bridge).
	maximumProcessEventXMLBytes = 1 << 20
	// maximumProcessCommandLineBytes bounds the command line kept on the event.
	maximumProcessCommandLineBytes = 32768
	// maximumProcessImagePathBytes bounds image and parent image paths.
	maximumProcessImagePathBytes = 4096
	// maximumProcessImageNameBytes bounds the process image base name.
	maximumProcessImageNameBytes = 260
	// maximumProcessEventDataFields bounds the EventData field count.
	maximumProcessEventDataFields = 64
	// maximumProcessFieldNameBytes bounds one EventData field name.
	maximumProcessFieldNameBytes = 64

	securityProcessCreationEventID = 4688
	securityChannelName            = "Security"
)

var (
	errProcessEventRejected = errors.New("process creation event rejected")
	errProcessEventBoundary = errors.New("process creation event boundary rejected")
)

// processCreationDocument mirrors the rendered Security 4688 event XML. Field
// tags are namespace-agnostic so the default event schema namespace from
// EvtRenderEventXml is accepted, while unknown fields are ignored.
type processCreationDocument struct {
	XMLName   xml.Name                    `xml:"Event"`
	System    processCreationSystem       `xml:"System"`
	EventData processCreationEventDataXML `xml:"EventData"`
}

type processCreationSystem struct {
	EventID       uint32 `xml:"EventID"`
	Channel       string `xml:"Channel"`
	EventRecordID int64  `xml:"EventRecordID"`
	TimeCreated   struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
}

type processCreationEventDataXML struct {
	Fields []processCreationField `xml:"Data"`
}

type processCreationField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// parseProcessCreationEvent parses one rendered Security 4688 record into a
// ProcessEvent. The event record ID is returned separately so the caller can
// prove it handles the same record the stream reported. Every field is capped;
// malformed records are rejected instead of being partially interpreted.
func parseProcessCreationEvent(raw []byte) (ProcessEvent, int64, error) {
	if len(raw) == 0 || len(raw) > maximumProcessEventXMLBytes {
		return ProcessEvent{}, 0, errProcessEventBoundary
	}
	var document processCreationDocument
	if err := xml.Unmarshal(raw, &document); err != nil {
		return ProcessEvent{}, 0, fmt.Errorf("process creation XML rejected: %w", err)
	}
	if document.System.EventID != securityProcessCreationEventID {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	if channel := strings.TrimSpace(document.System.Channel); channel != "" && !strings.EqualFold(channel, securityChannelName) {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	if document.System.EventRecordID <= 0 {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	timestamp, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(document.System.TimeCreated.SystemTime))
	if err != nil || timestamp.IsZero() {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	timestamp = timestamp.UTC()
	// A rendered record with an implausible clock cannot be correlated; reject
	// it instead of trusting corrupt time evidence.
	if timestamp.Year() < 2000 || timestamp.Year() > 2100 {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	if len(document.EventData.Fields) > maximumProcessEventDataFields {
		return ProcessEvent{}, 0, errProcessEventBoundary
	}
	values := make(map[string]string, len(document.EventData.Fields))
	for _, field := range document.EventData.Fields {
		name := strings.TrimSpace(field.Name)
		if name == "" {
			continue
		}
		if len(name) > maximumProcessFieldNameBytes {
			return ProcessEvent{}, 0, errProcessEventBoundary
		}
		if _, exists := values[name]; exists {
			continue
		}
		values[name] = field.Value
	}

	pid, err := parseProcessIdentifier(values["NewProcessId"])
	if err != nil {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	imagePath, err := sanitizeProcessImagePath(values["NewProcessName"])
	if err != nil {
		return ProcessEvent{}, 0, err
	}
	image := filepath.Base(imagePath)
	if image == "" || image == "." || image == string(filepath.Separator) {
		return ProcessEvent{}, 0, errProcessEventRejected
	}
	if len(image) > maximumProcessImageNameBytes {
		return ProcessEvent{}, 0, errProcessEventBoundary
	}
	commandLine := values["CommandLine"]
	if len(commandLine) > maximumProcessCommandLineBytes {
		return ProcessEvent{}, 0, errProcessEventBoundary
	}
	if strings.IndexByte(commandLine, 0) >= 0 {
		return ProcessEvent{}, 0, errProcessEventRejected
	}

	// Windows 11 renders the creating process as CreatorProcessId; older
	// renderings only carry the creator PID in ProcessId. The creator identity is
	// optional evidence: when the parent already exited (or the field is
	// unavailable) the child creation event must still be observed, so a
	// missing or malformed creator PID degrades to ParentPID 0 instead of
	// rejecting the record.
	parentID := uint32(0)
	for _, field := range []string{"CreatorProcessId", "ProcessId"} {
		creator := strings.TrimSpace(values[field])
		if creator == "" {
			continue
		}
		if parsed, parseErr := parseProcessIdentifier(creator); parseErr == nil {
			parentID = parsed
			break
		}
	}

	event := ProcessEvent{
		TimestampUTC: timestamp,
		CreationUTC:  timestamp,
		PID:          pid,
		ParentPID:    parentID,
		Image:        image,
		ImagePath:    imagePath,
		CommandLine:  commandLine,
	}
	// The parent identity is best-effort context. Some renderers produce a bare
	// image name instead of a full path; that still yields a usable basename-only
	// ancestry hop. Unusable parent data never rejects the child event.
	for _, field := range []string{"ParentProcessName", "CreatorProcessName"} {
		parentImage, parentPath, ok := parentIdentityFromRenderedName(values[field])
		if !ok {
			continue
		}
		event.ParentImage = parentImage
		event.ParentPath = parentPath
		// The 4688 record carries only the parent identity, so the ancestry is
		// capped at exactly that one proven hop (no live process-table walk).
		event.Ancestry = []ProcessIdentity{{PID: parentID, Image: parentImage, Path: parentPath}}
		break
	}
	return event, document.System.EventRecordID, nil
}

// parentIdentityFromRenderedName extracts an optional parent identity. It never
// fails the child event: unusable input simply yields no ancestry hop.
func parentIdentityFromRenderedName(raw string) (string, string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maximumProcessImagePathBytes {
		return "", "", false
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", "", false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 {
			return "", "", false
		}
	}
	parentPath := ""
	if filepath.IsAbs(value) {
		parentPath = value
	}
	parentImage := filepath.Base(value)
	if parentImage == "" || parentImage == "." || parentImage == string(filepath.Separator) {
		return "", "", false
	}
	if len(parentImage) > maximumProcessImageNameBytes {
		return "", "", false
	}
	return parentImage, parentPath, true
}

// parseProcessIdentifier accepts the rendered hexadecimal (0x1a4) and decimal
// forms. Windows reserves PIDs 0-3, so anything below the System process is
// rejected instead of being correlated with a recycled PID.
func parseProcessIdentifier(raw string) (uint32, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 16 {
		return 0, errProcessEventRejected
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
		if value == "" {
			return 0, errProcessEventRejected
		}
	}
	parsed, err := strconv.ParseUint(value, base, 32)
	if err != nil || parsed < 4 {
		return 0, errProcessEventRejected
	}
	return uint32(parsed), nil
}

// sanitizeProcessImagePath bounds and validates the mandatory child image path:
// absolute only, no control characters, bounded length.
func sanitizeProcessImagePath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errProcessEventRejected
	}
	if len(value) > maximumProcessImagePathBytes {
		return "", errProcessEventBoundary
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", errProcessEventRejected
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 {
			return "", errProcessEventRejected
		}
	}
	if !filepath.IsAbs(value) {
		return "", errProcessEventRejected
	}
	return value, nil
}

// FIND-WIN-003: the process-creation triage must never be the reason an event
// that an active engine would strike never reaches the engine. The previous
// implementation forward-filtered against a static 21-entry LOLBin list and a
// few CLI signals, so Paranoia Mode, Strict Lineage, System-App Integrity,
// Ghost Mode telemetry and non-LOLBin Killerdom signatures were unreachable.
//
// The triage now drops an event only when it is provably uninteresting for
// EVERY active engine:
//
//  1. Paranoia Mode forwards every image (the engine owns the whitelist
//     decision and would otherwise default-deny it).
//  2. A restricted strict-lineage image or parent is forwarded.
//  3. A Ghost Mode telemetry process is always forwarded: the engine must have
//     it in its recent-process table for network correlation.
//  4. Known LOLBins are forwarded (unchanged fast path).
//  5. Unknown images are forwarded. This includes python.exe, bash.exe,
//     mimikatz.exe and renamed system binaries; triage cannot prove that no
//     engine reacts to them.
//  6. Only a curated low-risk inbox system binary on a canonical Windows path
//     may still be dropped. For that candidate a bounded PE provenance read
//     (rename contract) and the cheap CLI/RE2 signal checks run first; a probe
//     failure forwards the event (fail-safe toward detection).
//
// Every forwarded branch fills PE provenance and SignerStatus so Fair Scoring
// and provenance consumers keep the signature signal.

// maximumTriageProbeFailureEntries and triageProbeFailureInterval bound the
// diagnostic log for probe failures: one entry per image basename per interval,
// at most 256 keys, so a boot-time storm cannot flood the log/ledger.
const (
	maximumTriageProbeFailureEntries = 256
	triageProbeFailureInterval       = 10 * time.Minute
)

var (
	triageProbeFailureMu sync.Mutex
	triageProbeFailureAt map[string]time.Time
)

// curatedLowRiskSystemBinaries is the conservative allowlist that preserves the
// triage performance contract. It contains only inbox Windows utilities and
// shell hosts that the evaluator has no signal for when started with an
// innocuous command line, and it is only honored for a canonical installation
// path (%SystemRoot%\System32, %SystemRoot%\SysWOW64 or %SystemRoot%\explorer.exe).
// It deliberately excludes every tracked LOLBin, every interpreter and every
// installer/scripting host. Anything not listed here is unknown and therefore
// forwarded; a renamed LOLBin on a curated path is still detected through the PE
// OriginalFilename check before any drop.
var curatedLowRiskSystemBinaries = map[string]struct{}{
	"notepad.exe":              {},
	"mspaint.exe":              {},
	"snippingtool.exe":         {},
	"charmap.exe":              {},
	"magnify.exe":              {},
	"narrator.exe":             {},
	"osk.exe":                  {},
	"cleanmgr.exe":             {},
	"dfrgui.exe":               {},
	"dvdplay.exe":              {},
	"taskmgr.exe":              {},
	"conhost.exe":              {},
	"explorer.exe":             {},
	"dwm.exe":                  {},
	"sihost.exe":               {},
	"ctfmon.exe":               {},
	"dllhost.exe":              {},
	"runtimebroker.exe":        {},
	"backgroundtaskhost.exe":   {},
	"applicationframehost.exe": {},
	"werfault.exe":             {},
	"wermgr.exe":               {},
	"smartscreen.exe":          {},
	"comppkgsrv.exe":           {},
}

// triageSystemRoot returns the canonical, lower-cased Windows root used for the
// curated-path check.
func triageSystemRoot() string {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" || !filepath.IsAbs(root) {
		root = `C:\Windows`
	}
	return strings.ToLower(filepath.Clean(root))
}

// isCuratedLowRiskSystemBinary reports whether the event names one of the
// curated inbox binaries on a canonical Windows installation path. Any
// user-writable, temp, UNC or renamed location is treated as unknown.
func isCuratedLowRiskSystemBinary(imagePath, image string) bool {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(imagePath)))
	if clean == "" || clean == "." || !filepath.IsAbs(clean) {
		return false
	}
	base := strings.ToLower(filepath.Base(clean))
	if base == "" || base == "." {
		return false
	}
	if _, curated := curatedLowRiskSystemBinaries[base]; !curated {
		return false
	}
	// The parsed image basename and the path basename must agree; a record
	// whose path/name pair is inconsistent is not trusted for a drop decision.
	if name := strings.ToLower(strings.TrimSpace(image)); name != "" && name != base {
		return false
	}
	root := triageSystemRoot()
	return strings.HasPrefix(clean, root+`\system32\`) ||
		strings.HasPrefix(clean, root+`\syswow64\`) ||
		clean == root+`\explorer.exe`
}

// strictLineageRelevant reports whether the image or its parent belongs to the
// strict-lineage rule set. Those identities must always reach the engine.
func strictLineageRelevant(event ProcessEvent) bool {
	for _, candidate := range []string{event.Image, event.ParentImage} {
		base := strings.ToLower(filepath.Base(strings.TrimSpace(candidate)))
		if base == "" || base == "." {
			continue
		}
		if _, restricted := StrictLineageRules[base]; restricted {
			return true
		}
	}
	return false
}

// triageKillerdomCLIMatch evaluates the existing Killerdom signatures against a
// command line. An unpublished policy evaluates every signature (fail-safe); a
// disabled Killerdom engine cannot provide a forwarding reason.
func triageKillerdomCLIMatch(commandLine string, policy *sentinelTriagePolicy) bool {
	if strings.TrimSpace(commandLine) == "" {
		return false
	}
	if policy == nil {
		matched, _, _ := EvaluateKillerdomCLI(commandLine, nil)
		return matched
	}
	if !policy.killerdomEnabled {
		return false
	}
	matched, _, _ := EvaluateKillerdomCLI(commandLine, policy.activeSignatures)
	return matched
}

// logTriageProbeFailure records a bounded diagnostic when the bounded image
// probe cannot provide provenance for a forwarded event. The event is still
// forwarded: a failed probe may never suppress detection.
func logTriageProbeFailure(event *ProcessEvent) {
	if event == nil {
		return
	}
	key := strings.ToLower(strings.TrimSpace(event.Image))
	if key == "" {
		key = "unknown"
	}
	now := time.Now()
	triageProbeFailureMu.Lock()
	if triageProbeFailureAt == nil {
		triageProbeFailureAt = make(map[string]time.Time)
	}
	if last, exists := triageProbeFailureAt[key]; exists && now.Sub(last) < triageProbeFailureInterval {
		triageProbeFailureMu.Unlock()
		return
	}
	if len(triageProbeFailureAt) >= maximumTriageProbeFailureEntries {
		for existing := range triageProbeFailureAt {
			delete(triageProbeFailureAt, existing)
		}
	}
	triageProbeFailureAt[key] = now
	triageProbeFailureMu.Unlock()
	winapi.ReportError("mhx.process_creation.triage_provenance", fmt.Errorf("image provenance unavailable for %q; event forwarded (fail-safe)", truncate(key, 64)))
}

// observeProcessCreation is the single forwarded-event branch: it enriches the
// event with bounded PE provenance and Authenticode state when readable and
// forwards it. A probe failure is logged (bounded) and never suppresses the
// event.
func (p *processImageProbe) observeProcessCreation(event *ProcessEvent) bool {
	version, key, available := p.inspect(event.ImagePath)
	if !available {
		logTriageProbeFailure(event)
		return true
	}
	return p.observeProcessCreationWithProvenance(event, version, key)
}

// observeProcessCreationWithProvenance fills the provenance fields and the
// signer status for an event that is already known to be forwarded.
func (p *processImageProbe) observeProcessCreationWithProvenance(event *ProcessEvent, version imageVersionMetadata, key imageProbeKey) bool {
	event.OriginalImageName = version.originalFilename
	event.ImageVersionCompany = version.companyName
	if status := p.signerStatus(key); status != "" {
		event.SignerStatus = status
	} else {
		logTriageProbeFailure(event)
	}
	return true
}

// triageProcessCreation decides whether a parsed process-creation event is in
// MHX observation scope and enriches it with PE provenance. An event is dropped
// only when every active engine is provably uninterested (see the FIND-WIN-003
// contract above).
func (p *processImageProbe) triageProcessCreation(event *ProcessEvent) bool {
	if event == nil {
		return false
	}
	policy, policyKnown := currentSentinelTriagePolicy()

	// 1. Cheap, I/O-free forwarding predicates. They must run before any
	// signature work so the common strict-lineage/paranoia traffic stays cheap.
	if isKnownLolbinImage(event.Image) {
		return p.observeProcessCreation(event)
	}
	if policyKnown && policy.paranoia {
		// Paranoia Mode is default-deny for every non-whitelisted image; the
		// whitelist decision belongs to the engine, so every image must reach it.
		return p.observeProcessCreation(event)
	}
	if strictLineageRelevant(*event) {
		return p.observeProcessCreation(event)
	}
	// Ghost Mode correlates telemetry processes with outbound connections from
	// the engine's recent-process table; the handful of telemetry images is
	// cheap to forward and must never be dropped by triage.
	if isTelemetryProcess(event.ImagePath) || isTelemetryProcess(event.ParentPath) {
		return p.observeProcessCreation(event)
	}
	// 2. Unknown images must be forwarded: python.exe/bash.exe/mimikatz.exe and
	// renamed system binaries may be struck by the evaluator or Killerdom even
	// though they are not on the static LOLBin list.
	if !isCuratedLowRiskSystemBinary(event.ImagePath, event.Image) {
		return p.observeProcessCreation(event)
	}

	// 3. Drop candidate: a curated low-risk inbox binary on a canonical path.
	// The bounded provenance read preserves the renamed-LOLBin contract; if it
	// fails, fail-safe toward detection and forward.
	version, key, available := p.inspect(event.ImagePath)
	if !available {
		logTriageProbeFailure(event)
		return true
	}
	if version.isRenamedLolbin(event.Image) {
		return p.observeProcessCreationWithProvenance(event, version, key)
	}
	// 4. Expensive-ish RE2/CLI checks run only for the drop candidate, after all
	// cheap filters above have failed to forward the event.
	if triageKillerdomCLIMatch(event.CommandLine, policy) || len(rawBehaviorSignals(*event)) > 0 {
		return p.observeProcessCreationWithProvenance(event, version, key)
	}
	return false
}
