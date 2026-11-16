// STATUS: PLATIN VGT SUPREME
package spyware

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Capability names that Windows tracks in the CapabilityAccessManager consent
// store. They are the Windows-native equivalent of a camera/microphone LED: the
// operating system records who started using the capability and whether that use
// is still active.
const (
	CapabilityWebcam          = "webcam"
	CapabilityMicrophone      = "microphone"
	CapabilityGraphicsCapture = "graphicsCaptureProgrammatic"
	CapabilityLocation        = "location"
)

// CapabilityState is one observed consent-store entry. Path is the decoded
// application path (or the packaged application identifier). Start and Stop are
// Windows FILETIME values; Stop == 0 while the capability is in active use.
type CapabilityState struct {
	Capability string
	Path       string
	Start      uint64
	Stop       uint64
}

// Active reports whether the capability is currently held open.
func (state CapabilityState) Active() bool {
	return state.Start > 0 && state.Stop == 0
}

// startedUTC converts the FILETIME start value; it returns the zero time for an
// unreadable value instead of inventing a timestamp.
func (state CapabilityState) startedUTC() time.Time {
	if state.Start == 0 {
		return time.Time{}
	}
	const unixEpochInWindowsTicks = 116444736000000000
	const ticksPerSecond = 10000000
	if state.Start < unixEpochInWindowsTicks {
		return time.Time{}
	}
	seconds := int64(state.Start-unixEpochInWindowsTicks) / ticksPerSecond
	nanos := (int64(state.Start-unixEpochInWindowsTicks) % ticksPerSecond) * 100
	return time.Unix(seconds, nanos).UTC()
}

// CapabilityClassifier decides whether an observed capability access is benign,
// suspicious or an active surveillance event. It is pure so the whole matrix is
// unit-tested without a camera.
type CapabilityClassifier struct {
	// IsAllowed reports whether the application is explicitly allowed to use the
	// capability (operator whitelist / curated system app with valid signature).
	IsAllowed func(path string) bool
	// WorkstationLocked is true while no interactive user is present.
	WorkstationLocked bool
}

// Classify returns nil when the access is expected, or a finding otherwise. The
// rules are ordered from most to least severe and never suppress an active
// capture by an unknown background application:
//
//  1. an active capability while the workstation is locked and the app is not
//     allowed is the highest-signal surveillance case (CRITICAL),
//  2. an active capability held by an application running from a user-writable
//     directory (Temp, AppData, Downloads, Public) and not allowed is HIGH,
//  3. any other active capability by a not-allowed application is MEDIUM,
//  4. inactive history entries are not findings.
func (classifier CapabilityClassifier) Classify(state CapabilityState, observed time.Time) *Finding {
	if !state.Active() {
		return nil
	}
	allowed := classifier.IsAllowed != nil && classifier.IsAllowed(state.Path)
	userWritable := isUserWritablePath(state.Path)
	severity := SeverityMedium
	detail := "Aktivierte Fähigkeit ohne dokumentierte Autorisierung"
	switch {
	case classifier.WorkstationLocked && !allowed:
		severity = SeverityCritical
		detail = "Fähigkeit aktiv, während die Arbeitsstation gesperrt ist und keine Autorisierung vorliegt"
	case userWritable && !allowed:
		severity = SeverityHigh
		detail = "Fähigkeit wird von einer Anwendung aus einem benutzerbeschreibbaren Pfad gehalten"
	case allowed:
		return nil
	}
	timer := map[string]string{
		CapabilityWebcam:          "Kamera",
		CapabilityMicrophone:      "Mikrofon",
		CapabilityGraphicsCapture: "Bildschirmaufzeichnung",
		CapabilityLocation:        "Standort",
	}[state.Capability]
	if timer == "" {
		timer = sanitizeText(state.Capability)
	}
	return &Finding{
		Source:      SourceCapability,
		Severity:    severity,
		Title:       "Capability-Zugriff: " + timer,
		Detail:      fmt.Sprintf("%s (%s) durch %s", detail, timer, sanitizeText(state.Path)),
		Asset:       sanitizeText(state.Path),
		ObservedUTC: observed.UTC(),
		Evidence: boundedEvidence(
			"capability="+state.Capability,
			"path="+state.Path,
			"startedUtc="+state.startedUTC().Format(time.RFC3339),
			"workstationLocked="+boolText(classifier.WorkstationLocked),
			"allowed="+boolText(allowed),
		),
		Response:  "OBSERVE_ONLY",
		DedupeKey: "capability|" + strings.ToLower(state.Capability) + "|" + strings.ToLower(state.Path),
	}
}

// isUserWritablePath reports whether windows path is inside a directory an
// unprivileged user can write to. Those are the locations from which
// surveillance payloads are actually dropped.
func isUserWritablePath(path string) bool {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(path)))
	if clean == "" || clean == "." {
		return false
	}
	markers := []string{
		`\appdata\local\temp\`,
		`\appdata\roaming\`,
		`\appdata\local\`,
		`\users\public\`,
		`\downloads\`,
		`\desktop\`,
		`\programdata\temp\`,
	}
	for _, marker := range markers {
		if strings.Contains(clean, marker) {
			return true
		}
	}
	return false
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
