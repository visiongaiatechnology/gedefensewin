// STATUS: PLATIN VGT SUPREME
package spyware

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// DriverService is one kernel service entry read from
// HKLM\SYSTEM\CurrentControlSet\Services. Only Type 1 (kernel driver) and Type 2
// (file system driver) are relevant for BYOVD analysis.
type DriverService struct {
	Name      string
	ImagePath string
	Type      uint32
	Start     uint32
	Signature string
}

// IsKernelDriver reports whether the service is a kernel-mode driver.
func (service DriverService) IsKernelDriver() bool {
	return service.Type&0x1 != 0 || service.Type&0x2 != 0
}

// knownVulnerableDrivers is a conservative, curated fast path for driver file
// names that are publicly documented as BYOVD ammunition. It is intentionally
// only a *name* list: it accelerates recognition of the well-known set, while
// the authoritative hash/signature allowlist must be supplied by a signed
// threat-intelligence feed. A renamed driver is therefore not missed by the
// structural rules below; only this fast path is name-based.
//
// The list is not a substitute for a live blocklist and must never be presented
// as complete.
var knownVulnerableDrivers = map[string]string{
	"rtcore64.sys":       "RTCore64 (MSI Afterburner) arbitrary physical memory access",
	"dbutil_2_3.sys":     "Dell dbutil driver elevation of privilege",
	"gdrv.sys":           "Gigabyte gdrv arbitrary memory access",
	"procexp152.sys":     "Process Explorer driver used for handle/kernel primitives",
	"winio32.sys":        "WinIO port I/O driver",
	"winio64.sys":        "WinIO port I/O driver",
	"winring0.sys":       "WinRing0 port I/O driver",
	"winring0x64.sys":    "WinRing0 port I/O driver",
	"msio64.sys":         "MSI MSIO driver",
	"msio32.sys":         "MSI MSIO driver",
	"cpuz.sys":           "CPUID drivers exposing kernel primitives",
	"cpuz_x64.sys":       "CPUID drivers exposing kernel primitives",
	"cpuz_x32.sys":       "CPUID drivers exposing kernel primitives",
	"ene.sys":            "ENE Technology I/O driver",
	"inpoutx64.sys":      "inpout32/inpoutx64 port I/O driver",
	"inpout32.sys":       "inpout32/inpoutx64 port I/O driver",
	"viragt64.sys":       "Vir.IT eXplorer driver",
	"atillk64.sys":       "ATI/AMD kernel driver",
	"aswsp.sys":          "Avast self-protection driver (abused variants)",
	"eversp.sys":         "Eversys driver",
	"kprocesshacker.sys": "Process Hacker kernel component",
}

// securityPosture captures the two Windows settings that determine whether a
// vulnerable driver is actually a live risk.
type SecurityPosture struct {
	VulnerableDriverBlocklistEnabled bool
	HVCIEnabled                      bool
}

// ClassifyDriverService decides whether a driver service is a BYOVD risk. It is
// pure and exhaustively tested. A driver is only considered malicious-relevant
// when it is a kernel driver; user-mode services are ignored.
//
// The rules:
//  1. a known vulnerable driver name is CRITICAL regardless of location,
//  2. an unsigned kernel driver outside the canonical driver directory is HIGH
//     (this catches renamed BYOVD binaries the name list cannot see),
//  3. an unsigned kernel driver inside the driver directory is MEDIUM (unknown
//     third-party driver; may be legitimate but needs review),
//  4. a signed kernel driver is not a finding.
func ClassifyDriverService(service DriverService, posture SecurityPosture, observed time.Time) *Finding {
	if !service.IsKernelDriver() {
		return nil
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(service.ImagePath)))
	nameReason, knownVulnerable := knownVulnerableDrivers[base]
	signature := strings.ToLower(strings.TrimSpace(service.Signature))
	signed := signature == "signed" || signature == "microsoft" || signature == "valid"
	unverified := signature == "" || signature == "unverified"
	canonical := isCanonicalDriverPath(service.ImagePath)

	severity := Severity("")
	title := ""
	detail := ""
	switch {
	case knownVulnerable:
		severity = SeverityCritical
		title = "BYOVD: bekannter verwundbarer Kernel-Treiber geladen"
		detail = fmt.Sprintf("%s (%s)", nameReason, sanitizeText(service.ImagePath))
	case !signed && !canonical:
		severity = SeverityHigh
		title = "Kernel-Treiber außerhalb des Treiberverzeichnisses"
		detail = fmt.Sprintf("Treiber läuft aus %s (Signaturstatus: %s)", sanitizeText(service.ImagePath), signatureOrUnknown(service.Signature))
	case !signed && canonical && unverified:
		// Cannot prove the signature is invalid, and the canonical driver
		// directory is administrator-owned. Report as review-level, not as a
		// confirmed unsigned driver.
		severity = SeverityMedium
		title = "Kernel-Treiber mit unbestätigter Signatur"
		detail = fmt.Sprintf("Treiber im Treiberverzeichnis, Signatur nicht verifiziert: %s", sanitizeText(service.ImagePath))
	case !signed && canonical:
		severity = SeverityMedium
		title = "Unsignierter/ungültig signierter Kernel-Treiber"
		detail = fmt.Sprintf("Treiber im Treiberverzeichnis ohne gültige Signatur: %s", sanitizeText(service.ImagePath))
	default:
		return nil
	}

	response := "OBSERVE_ONLY"
	if severity == SeverityCritical || severity == SeverityHigh {
		if posture.VulnerableDriverBlocklistEnabled && posture.HVCIEnabled {
			response = "BLOCK_CANDIDATE"
		} else {
			// A critical finding on a host without its own BYOVD mitigations is
			// more severe, not less.
			severity = SeverityCritical
			response = "BLOCK_CANDIDATE|HOST_MITIGATIONS_DISABLED"
		}
	}
	return &Finding{
		Source:      SourceBYOVD,
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Asset:       sanitizeText(service.Name),
		ObservedUTC: observed.UTC(),
		Evidence: boundedEvidence(
			"service="+service.Name,
			"imagePath="+service.ImagePath,
			"type="+fmt.Sprintf("0x%x", service.Type),
			"start="+fmt.Sprintf("0x%x", service.Start),
			"signature="+service.Signature,
			"vulnerableDriverBlocklist="+boolText(posture.VulnerableDriverBlocklistEnabled),
			"hvci="+boolText(posture.HVCIEnabled),
		),
		Response:  response,
		DedupeKey: "byovd|" + strings.ToLower(service.Name) + "|" + base,
	}
}

// signatureOrUnknown renders a signature status for evidence without implying a
// value that was not measured.
func signatureOrUnknown(signature string) string {
	if strings.TrimSpace(signature) == "" {
		return "unverified"
	}
	return sanitizeText(signature)
}

// isCanonicalDriverPath reports whether the driver image lives in the canonical
// System32\drivers directory (expanded paths only; the adapter expands
// \SystemRoot and %SystemRoot%).
func isCanonicalDriverPath(path string) bool {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(path)))
	if clean == "" || clean == "." {
		return false
	}
	return strings.Contains(clean, `\system32\drivers\`)
}
