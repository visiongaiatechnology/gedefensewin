// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"os"
	"path/filepath"
	"strings"
)

// protectedSystemImages are process images whose termination would immediately
// degrade the operating system's own security boundary. A heuristically
// attributed detection (for example a four-second temporal correlation) must
// never be allowed to kill them: that turned a detection heuristic into a
// SYSTEM-level denial of service against arbitrary administrator and operating
// system processes (FIND-WIN-002 / CHAIN-WIN-001).
//
// The name alone is not sufficient. A protected name only counts when the
// verified image path is inside the canonical System32/SysWOW64 directory (or
// the Microsoft Defender platform directory), so a renamed or relocated
// payload cannot hide behind a protected name.
var protectedSystemImages = map[string]struct{}{
	"smss.exe":                  {},
	"csrss.exe":                 {},
	"wininit.exe":               {},
	"winlogon.exe":              {},
	"services.exe":              {},
	"lsass.exe":                 {},
	"svchost.exe":               {},
	"fontdrvhost.exe":           {},
	"dwm.exe":                   {},
	"sihost.exe":                {},
	"taskhostw.exe":             {},
	"msmpeng.exe":               {},
	"msmpsvc.exe":               {},
	"mssense.exe":               {},
	"nissrv.exe":                {},
	"securityhealthservice.exe": {},
	"sppsvc.exe":                {},
}

// IsProtectedOSProcess reports whether the caller may not terminate this
// process as a kinetic response. image and path are the image name and the
// kernel-verified image path of the target process.
func IsProtectedOSProcess(image, path string) bool {
	trimmedPath := strings.TrimSpace(path)
	base := strings.ToLower(filepath.Base(strings.TrimSpace(image)))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = strings.ToLower(filepath.Base(trimmedPath))
	}
	switch base {
	case "system", "registry", "memcompression", "idle":
		return true
	}
	if _, protected := protectedSystemImages[base]; !protected {
		return false
	}
	clean := strings.ToLower(filepath.Clean(trimmedPath))
	if isCanonicalSystemBinaryPath(clean) {
		return true
	}
	// The Defender platform lives below ProgramData and is protected by name
	// plus publisher tree instead of System32.
	return strings.Contains(clean, `\microsoft\windows defender\`)
}

// isCanonicalSystemBinaryPath reports whether path is inside the canonical
// System32 or SysWOW64 directory of the running Windows installation.
func isCanonicalSystemBinaryPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	systemRoot := strings.ToLower(strings.TrimSpace(os.Getenv("SystemRoot")))
	if len(systemRoot) < 3 {
		systemRoot = `c:\windows`
	}
	systemRoot = strings.TrimSuffix(filepath.Clean(systemRoot), string(filepath.Separator))
	return strings.HasPrefix(path, systemRoot+string(filepath.Separator)+"system32"+string(filepath.Separator)) ||
		strings.HasPrefix(path, systemRoot+string(filepath.Separator)+"syswow64"+string(filepath.Separator))
}
