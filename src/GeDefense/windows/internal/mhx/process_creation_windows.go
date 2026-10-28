// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

// triageProcessCreation decides whether a parsed process-creation event is in
// MHX observation scope and enriches it with PE provenance. The cheap checks
// (shared LOLBin allowlist, encoded command line, behavioral signals) run
// first; only when none matches does a bounded version-resource lookup run to
// expose renamed system binaries. Dropped events receive no signature work.
func (p *processImageProbe) triageProcessCreation(event *ProcessEvent) bool {
	knownImage := isKnownLolbinImage(event.Image)
	if knownImage {
		version, key, available := p.inspect(event.ImagePath)
		if available {
			event.OriginalImageName = version.originalFilename
			event.ImageVersionCompany = version.companyName
			if status := p.signerStatus(key); status != "" {
				event.SignerStatus = status
			}
		}
		return true
	}
	_, _, encoded, _ := DecodePowerShellCommand(event.CommandLine)
	if !encoded && len(rawBehaviorSignals(*event)) == 0 {
		version, key, available := p.inspect(event.ImagePath)
		if !available || !version.isRenamedLolbin(event.Image) {
			return false
		}
		event.OriginalImageName = version.originalFilename
		event.ImageVersionCompany = version.companyName
		if status := p.signerStatus(key); status != "" {
			event.SignerStatus = status
		}
		return true
	}
	// Observed through command-line evidence (encoded payload or a behavioral
	// signal); still record the PE provenance when it is safely readable.
	if version, _, available := p.inspect(event.ImagePath); available {
		event.OriginalImageName = version.originalFilename
		event.ImageVersionCompany = version.companyName
	}
	return true
}
