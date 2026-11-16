// STATUS: PLATIN VGT SUPREME
package spyware

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// PersistenceKind names the Windows persistence mechanism that was observed.
// These are the mechanisms commercial surveillance tooling and APT implants
// actually use on Windows and that a pure process/file watcher does not see.
type PersistenceKind string

const (
	PersistenceIFEO              PersistenceKind = "IFEO_DEBUGGER"
	PersistenceSilentProcessExit PersistenceKind = "SILENT_PROCESS_EXIT"
	PersistenceAppCertDLLs       PersistenceKind = "APPCERT_DLLS"
	PersistenceAppInitDLLs       PersistenceKind = "APPINIT_DLLS"
	PersistenceLSAPackages       PersistenceKind = "LSA_SECURITY_PACKAGES"
	PersistencePrintMonitor      PersistenceKind = "PRINT_MONITOR"
	PersistenceCOMHijack         PersistenceKind = "COM_CLSID_HIJACK"
	PersistenceWMISubscription   PersistenceKind = "WMI_SUBSCRIPTION"
	PersistenceBITSCallback      PersistenceKind = "BITS_NOTIFY_CMDLINE"
)

// PersistenceObservation is one value read from a monitored persistence
// location. It is data, never an instruction.
type PersistenceObservation struct {
	Kind        PersistenceKind
	KeyPath     string
	ValueName   string
	ValueData   string
	ObservedUTC time.Time
}

// lsaKnownPackages are the package DLL names a stock Windows installation loads.
// Anything else in LSA Security Packages is a credential-theft surface and needs
// an operator decision.
var lsaKnownPackages = map[string]struct{}{
	"kerberos": {}, "msv1_0": {}, "schannel": {}, "wdigest": {}, "tspkg": {},
	"pku2u": {}, "cloudap": {}, "negoexts": {}, "livessp": {}, "credssp": {},
}

// suspiciousNotifyExecutables are interpreters/loaders that must not appear in
// persistence-command values unless an operator explicitly allowed them.
var suspiciousNotifyExecutables = map[string]struct{}{
	"powershell.exe": {}, "pwsh.exe": {}, "cmd.exe": {}, "wscript.exe": {},
	"cscript.exe": {}, "mshta.exe": {}, "rundll32.exe": {}, "regsvr32.exe": {},
	"curl.exe": {}, "bitsadmin.exe": {}, "certutil.exe": {}, "wmic.exe": {},
}

// ClassifyPersistence decides whether an observed persistence value is benign.
// It never enforces by itself: it returns the finding the engine records (and,
// where an enforcement adapter exists, the response that would be requested).
func ClassifyPersistence(observation PersistenceObservation) *Finding {
	value := sanitizeText(observation.ValueData)
	if value == "" {
		return nil
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(value)))
	userWritable := isUserWritablePath(value)
	systemPath := isCanonicalSystemPath(value)

	severity := Severity("")
	title := ""
	detail := ""
	switch observation.Kind {
	case PersistenceIFEO:
		if systemPath {
			return nil
		}
		severity, title = SeverityCritical, "IFEO-Debugger-Persistenz"
		detail = "Image File Execution Options Debugger zeigt auf einen nicht-System-Pfad"
	case PersistenceSilentProcessExit:
		if systemPath {
			return nil
		}
		severity, title = SeverityHigh, "SilentProcessExit-Monitor"
		detail = "SilentProcessExit MonitorProcess zeigt auf einen nicht-System-Pfad"
	case PersistenceAppCertDLLs, PersistenceAppInitDLLs:
		if systemPath && !userWritable {
			return nil
		}
		severity, title = SeverityCritical, "AppCert/AppInit-DLL-Persistenz"
		detail = "DLL-Persistenz zeigt auf einen benutzerbeschreibbaren oder nicht-System-Pfad"
	case PersistenceLSAPackages:
		name := strings.ToLower(strings.TrimSuffix(base, ".dll"))
		if _, known := lsaKnownPackages[name]; known && systemPath {
			return nil
		}
		severity, title = SeverityHigh, "LSA-Sicherheitspaket außerhalb des Standards"
		detail = "LSA Security Packages enthält ein unbekanntes Paket"
	case PersistencePrintMonitor:
		if systemPath {
			return nil
		}
		severity, title = SeverityHigh, "Print-Monitor-DLL-Persistenz"
		detail = "Print-Monitor-Treiberpfad zeigt auf einen nicht-System-Pfad"
	case PersistenceCOMHijack:
		if systemPath {
			return nil
		}
		severity, title = SeverityHigh, "COM-CLSID-Hijack"
		detail = "InprocServer32/LocalServer32 zeigt auf einen nicht-System-Pfad"
	case PersistenceWMISubscription:
		severity, title = SeverityHigh, "WMI-Event-Subscription-Persistenz"
		detail = "WMI __FilterToConsumerBinding wurde angelegt oder geändert"
	case PersistenceBITSCallback:
		if _, suspicious := suspiciousNotifyExecutables[commandTokenBase(value)]; !suspicious {
			return nil
		}
		severity, title = SeverityHigh, "BITS-Notify-CmdLine mit Interpreter"
		detail = "BITS-Job startet einen Interpreter/Downloader als Benachrichtigungsaktion"
	default:
		return nil
	}

	return &Finding{
		Source:      SourcePersistence,
		Severity:    severity,
		Title:       title,
		Detail:      fmt.Sprintf("%s: %s", detail, sanitizeText(observation.ValueData)),
		Asset:       sanitizeText(observation.KeyPath),
		ObservedUTC: observation.ObservedUTC.UTC(),
		Evidence: boundedEvidence(
			"kind="+string(observation.Kind),
			"key="+observation.KeyPath,
			"valueName="+observation.ValueName,
			"valueData="+observation.ValueData,
		),
		Response:  "OBSERVE_ONLY",
		DedupeKey: "persistence|" + string(observation.Kind) + "|" + strings.ToLower(observation.KeyPath) + "|" + strings.ToLower(observation.ValueName),
	}
}

// isCanonicalSystemPath reports whether path is below a system directory where
// only administrators/SYSTEM (and the OS itself) can write.
// commandTokenBase extracts the executable file name from a command line value.
// Persistence values are frequently full command lines ("powershell.exe -enc …"),
// so the first token decides whether an interpreter is involved.
func commandTokenBase(value string) string {
	trimmed := strings.TrimSpace(strings.Trim(value, `"`))
	if trimmed == "" {
		return ""
	}
	if separator := strings.IndexAny(trimmed, " \t"); separator >= 0 {
		trimmed = trimmed[:separator]
	}
	trimmed = strings.Trim(trimmed, `"`)
	return strings.ToLower(filepath.Base(trimmed))
}

func isCanonicalSystemPath(path string) bool {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(path)))
	if clean == "" || clean == "." {
		return false
	}
	if strings.HasPrefix(clean, `\systemroot\`) {
		return true
	}
	for _, marker := range []string{`\windows\system32\`, `\windows\syswow64\`, `\program files\`, `\program files (x86)\`} {
		if strings.Contains(clean, marker) {
			return true
		}
	}
	return false
}

// EventLogTarget is one Windows event-log subscription a persistence sensor
// needs. The values are fixed, not operator input.
type EventLogTarget struct {
	Channel string
	XPath   string
}

// PersistenceEventLogTargets returns the real-time event sources for
// persistence classes that are event-driven rather than registry-value driven.
func PersistenceEventLogTargets() []EventLogTarget {
	return []EventLogTarget{
		{Channel: "Microsoft-Windows-WMI-Activity/Operational", XPath: "*[System[(EventID=5861 or EventID=5860)]]"},
		{Channel: "Microsoft-Windows-Bits-Client/Operational", XPath: "*[System[(EventID=59)]]"},
	}
}
