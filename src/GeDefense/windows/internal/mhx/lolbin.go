// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"path/filepath"
	"strings"
)

// lolbinImages is the single source of truth for the Windows living-off-the-
// land binaries that MHX process telemetry tracks. Share it between the
// evaluator and the process sensor so both layers agree on the same set; the
// sensor must nevertheless not rely on this list alone (see the PE
// OriginalFilename relocation check in the native process telemetry).
var lolbinImages = map[string]struct{}{
	"powershell.exe": {}, "pwsh.exe": {}, "cmd.exe": {}, "cscript.exe": {},
	"wscript.exe": {}, "mshta.exe": {}, "rundll32.exe": {}, "regsvr32.exe": {},
	"wmic.exe": {}, "certutil.exe": {}, "bitsadmin.exe": {}, "vssadmin.exe": {},
	"schtasks.exe": {}, "reg.exe": {}, "sc.exe": {}, "msiexec.exe": {},
	"installutil.exe": {}, "msbuild.exe": {}, "regsvcs.exe": {}, "regasm.exe": {},
	"forfiles.exe": {},
}

// isKnownLolbinImage reports whether image (a file name or a full path) names
// one of the tracked living-off-the-land binaries.
func isKnownLolbinImage(image string) bool {
	name := strings.ToLower(filepath.Base(strings.TrimSpace(image)))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return false
	}
	_, known := lolbinImages[name]
	return known
}
