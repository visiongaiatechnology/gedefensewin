// STATUS: PLATIN VGT SUPREME
package titan

// This file owns the deterministic evidence that policy tolerances for Windows
// platform activity (Defender updates, per-user service instances, installer and
// developer artifacts) must be based on. All decisions are fail-closed: an empty
// actor, a name-only match or an unverifiable signature never produces a
// tolerance (FIND-WIN-010). Evidence is derived from registry service
// definitions and Authenticode verification, never from attacker-controlled
// strings alone.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	signatureStatusValid       = "VALID"
	signatureStatusInvalid     = "INVALID"
	signatureStatusUnavailable = "UNAVAILABLE"

	maxTitanSignatureProbes = 256
	maxTitanWindowsPathSize = 1024
)

// errTitanSignatureVerifierUnavailable is returned when the platform-specific
// Authenticode verifier has not been bound. It is an error, never a tolerance.
var errTitanSignatureVerifierUnavailable = errors.New("titan authenticode verifier unavailable")

// titanVerifyAuthenticode is bound to winapi.VerifyAuthenticode in
// platform_evidence_windows.go. On other platforms it stays fail-closed.
var titanVerifyAuthenticode = func(string) error { return errTitanSignatureVerifierUnavailable }

type titanSignatureProbeKey struct {
	path  string
	size  int64
	mtime int64
}

type titanSignatureProbeStore struct {
	mu    sync.Mutex
	cache map[titanSignatureProbeKey]string
	order []titanSignatureProbeKey
}

var titanSignatureProbes = &titanSignatureProbeStore{cache: make(map[titanSignatureProbeKey]string)}

// titanFileSignatureStatus reports the bounded Authenticode state of a local
// file. Results are cached per path+size+mtime so a replaced binary is always
// re-verified and the cache stays bounded.
func titanFileSignatureStatus(path string) string {
	return titanSignatureProbes.status(path)
}

func (store *titanSignatureProbeStore) status(path string) string {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return signatureStatusUnavailable
	}
	key, cacheable := titanSignatureProbeKeyFor(clean)
	if cacheable {
		store.mu.Lock()
		status, exists := store.cache[key]
		store.mu.Unlock()
		if exists {
			return status
		}
	}
	status := signatureStatusInvalid
	if err := titanVerifyAuthenticode(clean); err == nil {
		status = signatureStatusValid
	}
	if cacheable {
		store.mu.Lock()
		if _, exists := store.cache[key]; !exists {
			store.cache[key] = status
			store.order = append(store.order, key)
			if len(store.order) > maxTitanSignatureProbes {
				delete(store.cache, store.order[0])
				store.order = store.order[1:]
			}
		}
		store.mu.Unlock()
	}
	return status
}

func titanSignatureProbeKeyFor(path string) (titanSignatureProbeKey, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return titanSignatureProbeKey{}, false
	}
	return titanSignatureProbeKey{path: strings.ToLower(path), size: info.Size(), mtime: info.ModTime().UnixNano()}, true
}

// resetTitanSignatureProbes drops cached verification results. Tests that inject
// a verifier use it to keep their assertions deterministic.
func resetTitanSignatureProbes() {
	titanSignatureProbes.mu.Lock()
	titanSignatureProbes.cache = make(map[titanSignatureProbeKey]string)
	titanSignatureProbes.order = nil
	titanSignatureProbes.mu.Unlock()
}

// titanExpandWindowsEnvironment replaces %NAME% tokens with the process
// environment. Unknown or malformed tokens stop expansion instead of inventing a
// value; expansion is bounded to avoid attacker-controlled loops.
func titanExpandWindowsEnvironment(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	result := value
	for iteration := 0; iteration < 8; iteration++ {
		start := strings.IndexByte(result, '%')
		if start < 0 {
			break
		}
		end := strings.IndexByte(result[start+1:], '%')
		if end < 0 {
			break
		}
		end += start + 1
		name := result[start+1 : end]
		if name == "" {
			break
		}
		replacement, exists := os.LookupEnv(name)
		if !exists {
			break
		}
		result = result[:start] + replacement + result[end+1:]
	}
	return result
}

// titanCleanWindowsPath canonicalizes a drive-absolute Windows path without
// touching the filesystem. It strips quotes, expands environment tokens,
// normalizes separators and collapses "." / ".." components. Relative paths,
// UNC/device paths, ADS suffixes and traversal above the drive root are rejected
// by returning the empty string.
func titanCleanWindowsPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	if trimmed == "" || len(trimmed) > maxTitanWindowsPathSize {
		return ""
	}
	trimmed = titanExpandWindowsEnvironment(trimmed)
	trimmed = strings.ReplaceAll(trimmed, "/", `\`)
	if strings.HasPrefix(trimmed, `\\`) {
		return ""
	}
	if len(trimmed) < 3 || trimmed[1] != ':' || trimmed[2] != '\\' {
		return ""
	}
	volume := strings.ToUpper(trimmed[:2])
	components := strings.Split(trimmed[3:], `\`)
	stack := make([]string, 0, len(components))
	for _, component := range components {
		switch component {
		case "", ".":
			continue
		case "..":
			if len(stack) == 0 {
				return ""
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(component, ':') {
				// Alternate data stream or drive-relative component.
				return ""
			}
			if strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
				// Windows silently trims these; canonicalize instead of trusting them.
				component = strings.TrimRight(component, ". ")
				if component == "" {
					return ""
				}
			}
			stack = append(stack, component)
		}
	}
	if len(stack) == 0 {
		return volume + `\`
	}
	return volume + `\` + strings.Join(stack, `\`)
}

// titanPathBase returns the final component of a Windows-style path without
// depending on the host operating system's separator.
func titanPathBase(value string) string {
	cleaned := strings.TrimSpace(value)
	cleaned = strings.ReplaceAll(cleaned, "/", `\`)
	cleaned = strings.TrimRight(cleaned, `\`)
	if index := strings.LastIndexByte(cleaned, '\\'); index >= 0 {
		return cleaned[index+1:]
	}
	return cleaned
}

// titanPathWithin reports whether candidate is root itself or below root. Both
// paths are canonicalized; non-absolute roots reject everything.
func titanPathWithin(candidate, root string) bool {
	cleanCandidate := titanCleanWindowsPath(candidate)
	cleanRoot := titanCleanWindowsPath(root)
	if cleanCandidate == "" || cleanRoot == "" {
		return false
	}
	cleanCandidate = strings.ToLower(cleanCandidate)
	cleanRoot = strings.ToLower(cleanRoot)
	if cleanCandidate == cleanRoot {
		return true
	}
	return strings.HasPrefix(cleanCandidate, strings.TrimRight(cleanRoot, `\`)+`\`)
}

func titanWindowsRootDir() string {
	if root := titanCleanWindowsPath(strings.TrimSpace(os.Getenv("SystemRoot"))); root != "" {
		return root
	}
	return `C:\Windows`
}

func titanWindowsSystem32Dir() string { return titanWindowsRootDir() + `\System32` }

func titanProgramDataDir() string {
	if root := titanCleanWindowsPath(strings.TrimSpace(os.Getenv("ProgramData"))); root != "" {
		return root
	}
	return `C:\ProgramData`
}

func titanProgramFilesDir() string {
	if root := titanCleanWindowsPath(strings.TrimSpace(os.Getenv("ProgramFiles"))); root != "" {
		return root
	}
	return `C:\Program Files`
}

func titanProgramFilesX86Dir() string {
	if root := titanCleanWindowsPath(strings.TrimSpace(os.Getenv("ProgramFiles(x86)"))); root != "" {
		return root
	}
	return `C:\Program Files (x86)`
}

// titanActorEvidence extracts the actor image and path that Titan actually
// observed. A path without a consistent image identity is not evidence:
// actor-controlled bare names never satisfy an evidence check.
func titanActorEvidence(observation Observation) (image, path string) {
	image = strings.ToLower(titanPathBase(observation.Actor.Image))
	path = titanCleanWindowsPath(observation.Actor.Path)
	if path == "" {
		if candidate := titanCleanWindowsPath(observation.Actor.Image); candidate != "" {
			path = candidate
			image = strings.ToLower(titanPathBase(candidate))
		}
		return image, path
	}
	pathImage := strings.ToLower(titanPathBase(path))
	if image == "" {
		image = pathImage
	}
	if image != pathImage {
		// Inconsistent identity (image does not match the evidenced path) is not
		// accepted as evidence for a tolerance decision.
		return "", ""
	}
	return image, path
}

var titanDefenderPlatformSubdirs = []string{
	`\Microsoft\Windows Defender\Platform`,
	`\Microsoft\Windows Defender Advanced Threat Protection\Platform`,
}

var titanDefenderInstallSubdirs = []string{
	`\Windows Defender`,
	`\Windows Defender Advanced Threat Protection`,
}

// titanIsCanonicalDefenderBinaryPath reports whether path is inside an
// ACL-protected Microsoft Defender installation directory.
func titanIsCanonicalDefenderBinaryPath(path string) bool {
	for _, root := range []string{titanProgramDataDir(), titanProgramFilesDir(), titanProgramFilesX86Dir()} {
		for _, subdir := range append(append([]string{}, titanDefenderPlatformSubdirs...), titanDefenderInstallSubdirs...) {
			if titanPathWithin(path, root+subdir) {
				return true
			}
		}
	}
	return false
}

func titanIsCanonicalDefenderDriverPath(path string) bool {
	return titanPathWithin(path, titanWindowsSystem32Dir()+`\drivers\wd`)
}

var titanDefenderBinaryNames = map[string]struct{}{
	"msmpeng.exe":        {},
	"nissrv.exe":         {},
	"mpdefendercore.exe": {},
	"mssense.exe":        {},
	"sensecncproxy.exe":  {},
	"mpcmdrun.exe":       {},
	"mpsigstub.exe":      {},
	"mprtp.dll":          {},
	"mpclient.dll":       {},
	"mpcommu.dll":        {},
	"mpasbase.vdm":       {},
	"mpavbase.vdm":       {},
	"mpasdlta.vdm":       {},
	"mpavdlta.vdm":       {},
}

var titanDefenderDriverNames = map[string]struct{}{
	"wddevflt.sys": {},
	"wdfilter.sys": {},
	"wdboot.sys":   {},
	"wdnisdrv.sys": {},
	"ksld.sys":     {},
	"mpfilter.sys": {},
}

// titanDefenderUpdaterImages are the only processes that may legitimately
// perform Defender platform maintenance. The check is only applied when an
// actor was actually observed.
var titanDefenderUpdaterImages = map[string]struct{}{
	"msmpeng.exe":          {},
	"mpsigstub.exe":        {},
	"trustedinstaller.exe": {},
	"tiworker.exe":         {},
	"services.exe":         {},
	"svchost.exe":          {},
	"usoclient.exe":        {},
	"mpcmdrun.exe":         {},
}

func titanIsDefenderBinaryName(name string) bool {
	_, exists := titanDefenderBinaryNames[strings.ToLower(name)]
	return exists
}

func titanIsDefenderDriverName(name string) bool {
	_, exists := titanDefenderDriverNames[strings.ToLower(name)]
	return exists
}

// titanDefenderPlatformEvidence decides whether an observation is a verifiable
// Microsoft Defender platform/binary update. Tolerance requires a canonical
// Defender path AND a valid Authenticode signature on the binary body. For a
// service object the service's own ImagePath (reported through the actor
// evidence fields) is authoritative; an empty actor never yields a tolerance.
// For a file object the changed binary itself is the evidenced image.
func titanDefenderPlatformEvidence(observation Observation) (bool, string) {
	actorImage, actorPath := titanActorEvidence(observation)
	switch observation.Object.Kind {
	case ObjectFile:
		if observation.Type == EventFileDeleted {
			return false, ""
		}
		filePath := titanCleanWindowsPath(observation.Object.Path)
		if filePath == "" {
			return false, ""
		}
		base := strings.ToLower(titanPathBase(filePath))
		canonicalBinary := titanIsCanonicalDefenderBinaryPath(filePath) && titanIsDefenderBinaryName(base)
		canonicalDriver := titanIsCanonicalDefenderDriverPath(filePath) && titanIsDefenderDriverName(base)
		if !canonicalBinary && !canonicalDriver {
			return false, ""
		}
		if actorImage != "" {
			if _, allowed := titanDefenderUpdaterImages[actorImage]; !allowed {
				return false, ""
			}
			if actorPath != "" && titanFileSignatureStatus(actorPath) != signatureStatusValid {
				return false, ""
			}
		}
		signature := titanFileSignatureStatus(filePath)
		if signature != signatureStatusValid {
			return false, ""
		}
		return true, fmt.Sprintf("%s mit gültiger Authenticode-Signatur (%s)", filePath, signature)
	case ObjectService:
		serviceName := strings.ToUpper(strings.TrimSpace(observation.Object.Name))
		switch serviceName {
		case "WINDEFEND", "WDNISSVC", "MDCORESVC", "SENSE":
		default:
			return false, ""
		}
		if observation.Type == EventPersistenceRemoved {
			return false, ""
		}
		if observation.Type == EventPersistenceChanged && strings.TrimSpace(observation.Object.Change) != "IMAGE_PATH" {
			// Disabling or reconfiguring a Defender service is tampering, not a
			// platform update.
			return false, ""
		}
		if actorImage == "" || actorPath == "" {
			return false, ""
		}
		if !titanIsCanonicalDefenderBinaryPath(actorPath) || !titanIsDefenderBinaryName(actorImage) {
			return false, ""
		}
		signature := titanFileSignatureStatus(actorPath)
		if signature != signatureStatusValid {
			return false, ""
		}
		return true, fmt.Sprintf("Dienst %s → %s mit gültiger Authenticode-Signatur (%s)", serviceName, actorPath, signature)
	}
	return false, ""
}

// titanIsCanonicalWindowsSystemBinary reports whether path is a binary inside an
// ACL-protected Windows installation directory with the expected image name.
func titanIsCanonicalWindowsSystemBinary(path, expectedImage string) bool {
	if !strings.EqualFold(titanPathBase(path), expectedImage) {
		return false
	}
	if titanPathWithin(path, titanWindowsSystem32Dir()) {
		return true
	}
	if titanPathWithin(path, titanWindowsRootDir()+`\SysWOW64`) {
		return true
	}
	return false
}

// titanIsCanonicalTrustedToolPath reports whether path is inside a
// non-user-writable Windows installation or Program Files tree. Installer
// session artifacts may only be tolerated for such signed Microsoft tooling.
func titanIsCanonicalTrustedToolPath(path string) bool {
	return titanPathWithin(path, titanWindowsRootDir()) ||
		titanPathWithin(path, titanProgramFilesDir()) ||
		titanPathWithin(path, titanProgramFilesX86Dir())
}

// titanResolveServiceExecutable resolves a registry ImagePath into the
// executable path the service is configured to run. The returned path is
// always a canonical drive-absolute path, or empty when it cannot be proven.
func titanResolveServiceExecutable(imagePath string) string {
	raw := strings.TrimSpace(titanExpandWindowsEnvironment(strings.TrimSpace(imagePath)))
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(raw)), `\??\`) {
		raw = raw[len(`\??\`):]
	}
	if strings.HasPrefix(strings.ToLower(raw), `\\?\`) {
		raw = raw[len(`\\?\`):]
	}
	token := raw
	if strings.HasPrefix(token, `"`) {
		end := strings.IndexByte(token[1:], '"')
		if end < 0 {
			return ""
		}
		token = token[1 : end+1]
	} else if fields := strings.Fields(token); len(fields) > 0 {
		token = fields[0]
	}
	if token == "" {
		return ""
	}
	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, `\systemroot\`) {
		token = titanWindowsRootDir() + token[len(`\systemroot`):]
	}
	cleaned := titanCleanWindowsPath(token)
	if cleaned != "" {
		return cleaned
	}
	// Relative service images are resolved by the service loader against
	// System32 (for example "svchost.exe -k netsvcs").
	base := titanPathBase(token)
	if base == "" {
		return ""
	}
	if strings.ContainsAny(token, `\/`) {
		return titanCleanWindowsPath(titanWindowsSystem32Dir() + `\` + strings.TrimLeft(strings.ReplaceAll(token, "/", `\`), `\`))
	}
	return titanCleanWindowsPath(titanWindowsSystem32Dir() + `\` + base)
}

// titanResolveCommandExecutable resolves the executable referenced by a
// persistence command line (for example a Run registry value). Unresolvable
// commands yield an empty string instead of a guessed image.
func titanResolveCommandExecutable(commandLine string) string {
	return titanResolveServiceExecutable(commandLine)
}
