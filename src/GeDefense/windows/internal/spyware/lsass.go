// STATUS: PLATIN VGT SUPREME
package spyware

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ProcessVMRead is the Windows access right LSASS credential dumping needs
// (PROCESS_VM_READ = 0x0010).
const ProcessVMRead uint32 = 0x0010

// lsassReaderAllowlist contains the Microsoft components that legitimately open
// LSASS for memory reads (Defender, Credential Guard plumbing, crash handling).
// An allowlisted name still requires a valid Microsoft signature.
var lsassReaderAllowlist = map[string]struct{}{
	"msmpeng.exe":               {},
	"mssense.exe":               {},
	"csrss.exe":                 {},
	"werfault.exe":              {},
	"wmiprvse.exe":              {},
	"svchost.exe":               {},
	"securityhealthservice.exe": {},
}

// ClassifyLSASSAccess reports credential-dump-shaped access to lsass.exe. Audit
// events 4656/4663 carry the requested access mask and the calling image; a read
// handle from an unexpected process is a direct precursor to credential theft.
func ClassifyLSASSAccess(accessMask uint32, callerImage, callerSignature string, observed time.Time) *Finding {
	if accessMask&ProcessVMRead == 0 {
		return nil
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(callerImage)))
	signature := strings.ToLower(strings.TrimSpace(callerSignature))
	trustedSigner := signature == "microsoft" || signature == "valid" || signature == "signed"
	if _, allowed := lsassReaderAllowlist[base]; allowed && trustedSigner {
		return nil
	}
	return &Finding{
		Source:      SourceLSASS,
		Severity:    SeverityCritical,
		Title:       "LSASS-Speicherzugriff außerhalb der Allowlist",
		Detail:      fmt.Sprintf("Prozess %s öffnete lsass.exe mit PROCESS_VM_READ (AccessMask 0x%x)", sanitizeText(callerImage), accessMask),
		Asset:       "lsass.exe",
		ObservedUTC: observed.UTC(),
		Evidence: boundedEvidence(
			"callerImage="+callerImage,
			"callerSignature="+callerSignature,
			fmt.Sprintf("accessMask=0x%x", accessMask),
			"requiredRight=PROCESS_VM_READ",
		),
		Response:  "OBSERVE_ONLY",
		DedupeKey: "lsass|" + base,
	}
}
