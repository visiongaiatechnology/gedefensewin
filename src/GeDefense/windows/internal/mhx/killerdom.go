// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type SignatureDef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	// Pattern is the human-readable detection expression shown in the
	// Sentinel control center. It is part of the API contract: the web UI
	// renders it in the signature table, so it must never be omitted.
	Pattern  string         `json:"pattern"`
	Compiled *regexp.Regexp `json:"-"`
}

var (
	// KD-SIG-01: LOLBin Obfuscation & Download Cradles.
	// "bypass"/"hidden" alone are normal execution-policy flags used by
	// installers and build systems and must not be a strike by themselves; the
	// signature requires an encoded/obfuscated or download/invoke primitive.
	sigLolbin = regexp.MustCompile(`(?i)(?:powershell|pwsh|cmd|cscript|wscript|certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|schtasks|vssadmin|bash|sh|node|python)\.exe\s+.*(?:-enc|-decode|-encodedcommand|downloadstring|xmlhttp|webclient|wshshell|system\.net\.webclient|sys\.argv|invoke-expression|\biex\b|eval\()`)

	// KD-SIG-02: High-Entropy Base64 Execution Blobs & Hex Injection.
	// Bare long strings (SHA-256 hashes, paths, tokens) are not malware. The
	// signature requires encoded-command context or a padded base64 blob that is
	// not a plain 64-hex-character hash.
	sigBase64 = regexp.MustCompile(`(?i)(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{40,}={0,2}|frombase64string\s*\(\s*['"][A-Za-z0-9+/]{40,}={0,2}|(?:[A-Za-z0-9+/]{4}){20,}={1,2}|(?:\\x[0-9a-fA-F]{2}){4,})`)

	// KD-SIG-03: C2 Exploits, JNDI Payloads & Webminers
	sigC2Miners = regexp.MustCompile(`(?i)\$\{jndi:(?:ldap|rmi|dns|iiop|http|https)://|coinhive|webminer|cryptonight|stratum\+tcp|monero|minerd`)

	// KD-SIG-04: Destructive OS Sabotage & Shadow Copy Erasure.
	// A bare "cmd.exe /c ..." is normal Windows operation (installers, tests,
	// scheduled jobs) and must NOT be a signature match by itself. The signature
	// therefore requires an actual destructive operation inside the cmd line.
	sigDestructive = regexp.MustCompile(`(?i)(?:vssadmin(?:\.exe)?\s+delete|bitsadmin(?:\.exe)?\s+/transfer|certutil(?:\.exe)?\s+-urlcache|scrcons(?:\.exe)?|cmd(?:\.exe)?\s+/c\s+[^\r\n]{0,200}?(?:del\s|erase\s|rd\s|rmdir\s|format\s|vssadmin\s+delete|bcdedit\s|schtasks\s+/delete|reg\s+delete|cipher\s+/w|wevtutil\s+cl|net\s+stop|sc\s+delete|wmic\s+shadowcopy\s+delete))`)

	// KD-SIG-05: Remote Memory Injection & Process Hollowing Tokens
	sigMemoryInject = regexp.MustCompile(`(?i)(?:virtualallocex|writeprocessmemory|createremotethread|queueuserapc|ntmapviewofsection|setthreadcontext)`)

	// KD-SIG-06: Credential Harvesting & LSASS Dumping
	sigCredentialDump = regexp.MustCompile(`(?i)(?:minidumpwritedump|sekurlsa|lsass\.dmp|sam\.save|reg\s+save\s+hklm\\sam)`)
)

var killerdomSignatures = []SignatureDef{
	{
		ID:          "KD-SIG-01",
		Name:        "LOLBin Obfuscation & Download Cradles",
		Description: "Erkennt bösartige Living-off-the-Land Parameter wie -enc, -decode, encodedcommand, downloadstring, invoke-expression",
		Severity:    "HIGH",
		Pattern:     sigLolbin.String(),
		Compiled:    sigLolbin,
	},
	{
		ID:          "KD-SIG-02",
		Name:        "High-Entropy Base64 Blobs",
		Description: "Erkennt Base64-obfuskierte Befehlsblöcke ab 60 Zeichen oder fortlaufende Hex-Payloads",
		Severity:    "HIGH",
		Pattern:     sigBase64.String(),
		Compiled:    sigBase64,
	},
	{
		ID:          "KD-SIG-03",
		Name:        "C2 Exploits, JNDI & Cryptominer",
		Description: "Erkennt Log4j/JNDI Remote-Exploits sowie Mining-Protokolle (Stratum, Monero, Coinhive)",
		Severity:    "CRITICAL",
		Pattern:     sigC2Miners.String(),
		Compiled:    sigC2Miners,
	},
	{
		ID:          "KD-SIG-04",
		Name:        "Destruktive Sabotage & Shadow Copies",
		Description: "Erkennt das Löschen von Schattenkopien (vssadmin delete), BITS-Transfers und Certutil-Downloads",
		Severity:    "CRITICAL",
		Pattern:     sigDestructive.String(),
		Compiled:    sigDestructive,
	},
	{
		ID:          "KD-SIG-05",
		Name:        "Remote Memory Injection Tokens",
		Description: "Erkennt Win32-Speicherinjektions-Tokens wie VirtualAllocEx, WriteProcessMemory, CreateRemoteThread",
		Severity:    "CRITICAL",
		Pattern:     sigMemoryInject.String(),
		Compiled:    sigMemoryInject,
	},
	{
		ID:          "KD-SIG-06",
		Name:        "Credential Harvesting & LSASS Dump",
		Description: "Erkennt Angriffe auf Anmeldeinformationen wie MiniDumpWriteDump, Sekurlsa und SAM-Export",
		Severity:    "CRITICAL",
		Pattern:     sigCredentialDump.String(),
		Compiled:    sigCredentialDump,
	},
}

// StrictLineageRules defines the single authorized parent ancestry for critical Windows system processes.
var StrictLineageRules = map[string][]string{
	"svchost.exe":   {"services.exe"},
	"lsass.exe":     {"wininit.exe"},
	"csrss.exe":     {"smss.exe"},
	"winlogon.exe":  {"smss.exe"},
	"taskhostw.exe": {"svchost.exe", "explorer.exe"},
}

// TargetLotLProcs lists living-off-the-land interpreters subject to real-time AMSI memory inspection.
var TargetLotLProcs = map[string]struct{}{
	"powershell":     {},
	"powershell.exe": {},
	"pwsh":           {},
	"pwsh.exe":       {},
	"cmd":            {},
	"cmd.exe":        {},
	"cscript":        {},
	"cscript.exe":    {},
	"wscript":        {},
	"wscript.exe":    {},
	"mshta":          {},
	"mshta.exe":      {},
	"rundll32":       {},
	"rundll32.exe":   {},
	"regsvr32":       {},
	"regsvr32.exe":   {},
}

func DefaultKillerdomSignatures() []SignatureDef {
	result := make([]SignatureDef, len(killerdomSignatures))
	copy(result, killerdomSignatures)
	return result
}

// EvaluateKillerdomCLI tests the process command line against all enabled Killerdom signatures.
func EvaluateKillerdomCLI(commandLine string, activeSigs map[string]bool) (matched bool, sigID string, sigName string) {
	if strings.TrimSpace(commandLine) == "" {
		return false, "", ""
	}
	for _, sig := range killerdomSignatures {
		if activeSigs != nil {
			if enabled, exists := activeSigs[sig.ID]; exists && !enabled {
				continue
			}
		}
		if sig.Compiled.MatchString(commandLine) {
			return true, sig.ID, sig.Name
		}
	}
	return false, "", ""
}

// CheckLineageBreach verifies that a privileged system process was spawned only
// by its legitimate parent. When full paths are supplied (live sensor), the
// image and parent must additionally live in the canonical Windows system
// directory; a renamed copy outside System32 can no longer satisfy the rule.
func CheckLineageBreach(image string, parentImage string) (breach bool, reason string) {
	baseImage := strings.ToLower(filepath.Base(strings.TrimSpace(image)))
	allowedParents, restricted := StrictLineageRules[baseImage]
	if !restricted {
		return false, ""
	}
	if looksLikeImagePath(image) && !isCanonicalSystemImage(image) {
		return true, fmt.Sprintf("Critical Lineage Breach: %s is masquerading outside the canonical System32 directory (%s)", baseImage, image)
	}
	baseParent := strings.ToLower(filepath.Base(strings.TrimSpace(parentImage)))
	allowed := false
	for _, expected := range allowedParents {
		if baseParent == expected {
			allowed = true
			break
		}
	}
	if !allowed {
		return true, fmt.Sprintf("Critical Lineage Breach: %s spawned by unauthorized parent %s (allowed: %v)", baseImage, baseParent, allowedParents)
	}
	if looksLikeImagePath(parentImage) && !isCanonicalSystemParent(baseParent, parentImage) {
		return true, fmt.Sprintf("Critical Lineage Breach: %s claims parent %s but the parent image path is not canonical (%s)", baseImage, baseParent, parentImage)
	}
	return false, ""
}

// CheckLineageBreachEvent is the live-sensor variant. It adds PE provenance
// (OriginalFilename) and ancestry fallback when the parent path was not captured
// by the process telemetry, without ever trusting a bare basename alone when a
// path is available.
func CheckLineageBreachEvent(event ProcessEvent) (bool, string) {
	image := event.ImagePath
	if strings.TrimSpace(image) == "" {
		image = event.Image
	}
	parent := event.ParentPath
	if strings.TrimSpace(parent) == "" {
		parent = event.ParentImage
	}
	baseImage := strings.ToLower(filepath.Base(strings.TrimSpace(image)))
	allowedParents, restricted := StrictLineageRules[baseImage]
	if !restricted {
		return false, ""
	}
	if event.OriginalImageName != "" && len(event.OriginalImageName) <= 260 &&
		!strings.EqualFold(baseImage, event.OriginalImageName) {
		return true, fmt.Sprintf("Critical Lineage Breach: %s has PE OriginalFilename %q (renamed system binary)", baseImage, event.OriginalImageName)
	}
	if breach, reason := CheckLineageBreach(image, parent); breach {
		return true, reason
	}
	if strings.TrimSpace(event.ParentPath) != "" {
		return false, ""
	}
	// Parent path missing: locate the claimed parent in the ancestry chain and
	// validate its canonical path instead of trusting the image name.
	baseParent := strings.ToLower(filepath.Base(strings.TrimSpace(parent)))
	for _, ancestor := range event.Ancestry {
		if ancestor.Path == "" || !strings.EqualFold(filepath.Base(ancestor.Image), baseParent) {
			continue
		}
		return CheckLineageBreach(image, ancestor.Path)
	}
	_ = allowedParents
	return false, ""
}

func looksLikeImagePath(value string) bool {
	return strings.ContainsAny(value, `\/`)
}

func isCanonicalSystemImage(imagePath string) bool {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(imagePath)))
	return strings.HasPrefix(clean, `c:\windows\system32\`) ||
		strings.HasPrefix(clean, `c:\windows\syswow64\`)
}

func isCanonicalSystemParent(parentBase, parentPath string) bool {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(parentPath)))
	if strings.HasPrefix(clean, `c:\windows\system32\`) || strings.HasPrefix(clean, `c:\windows\syswow64\`) {
		return true
	}
	// explorer.exe is the only allowed parent outside System32 (taskhostw).
	return parentBase == "explorer.exe" && clean == `c:\windows\explorer.exe`
}

// IsTargetLotL reports whether image is a tracked living-off-the-land script interpreter.
func IsTargetLotL(image string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(image)))
	_, found := TargetLotLProcs[base]
	if !found {
		baseWithoutExt := strings.TrimSuffix(base, filepath.Ext(base))
		_, found = TargetLotLProcs[baseWithoutExt]
	}
	return found
}
