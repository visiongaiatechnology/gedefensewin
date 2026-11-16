// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

var (
	hostsFileLock sync.Mutex
	hostsFilePath = `C:\Windows\System32\drivers\etc\hosts`
	// ghostFirewallApply is replaceable in tests so no real firewall mutation
	// happens during `go test`.
	ghostFirewallApply = applyGhostModeFirewall

	hostsAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	hostsKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procHostsGetFileSecurity = hostsAdvapi32.NewProc("GetFileSecurityW")
	procHostsSetFileSecurity = hostsAdvapi32.NewProc("SetFileSecurityW")
	procHostsReplaceFile     = hostsKernel32.NewProc("ReplaceFileW")
)

const (
	hostsDACLSecurityInformation   = 0x00000004
	hostsErrorInsufficientBuffer   = 122
	hostsMaxSecurityDescriptorSize = 1 << 20
	hostsMaxHostsBytes             = 1 << 20
	hostsReplaceFileWriteThrough   = 0x00000001
	hostsReplaceFileIgnoreMerge    = 0x00000002
)

const (
	ghostModeHeader = "# === VGT GHOST MODE TELEMETRY SINKHOLE START ==="
	ghostModeFooter = "# === VGT GHOST MODE TELEMETRY SINKHOLE END ==="

	ghostModeFirewallGroup = "VGT Ghost Mode Telemetry"
	ghostModeFirewallTag   = "VGT Ghost Mode"
)

// telemetryDomains is the curated null-route list applied by Ghost Mode
// (>= 60 endpoints). Windows Update, Defender cloud protection (spynet),
// activation, Store/CDN and connectivity-check endpoints are deliberately
// excluded: enabling Ghost Mode must never disable security updates or break
// network connectivity detection.
var telemetryDomains = []string{
	"telemetry.microsoft.com",
	"v10.events.data.microsoft.com",
	"v20.events.data.microsoft.com",
	"v10c.events.data.microsoft.com",
	"v20c.events.data.microsoft.com",
	"v10.vortex-win.data.microsoft.com",
	"v20.vortex-win.data.microsoft.com",
	"eu.vortex-win.data.microsoft.com",
	"us.vortex-win.data.microsoft.com",
	"apac.vortex-win.data.microsoft.com",
	"vortex.data.microsoft.com",
	"vortex-win.data.microsoft.com",
	"web.vortex.data.microsoft.com",
	"settings-win.data.microsoft.com",
	"settings.data.microsoft.com",
	"watson.telemetry.microsoft.com",
	"watson.ppe.telemetry.microsoft.com",
	"watson.microsoft.com",
	"feedback.windows.com",
	"feedback.microsoft.com",
	"activity.windows.com",
	"diagnostic.events.data.microsoft.com",
	"diagnostics.support.microsoft.com",
	"self.events.data.microsoft.com",
	"mobile.events.data.microsoft.com",
	"functional.events.data.microsoft.com",
	"browser.pipe.aria.microsoft.com",
	"pipe.aria.microsoft.com",
	"mobile.pipe.aria.microsoft.com",
	"browser.events.data.msn.com",
	"browser.events.data.microsoft.com",
	"onecollector.cloudapp.aria.microsoft.com",
	"events.data.msn.com",
	"events.data.microsoft.com",
	"data.microsoft.com",
	"arc.msn.com",
	"telemetry.visualstudio.com",
	"dc.services.visualstudio.com",
	"in.appcenter.ms",
	"oca.telemetry.microsoft.com",
	"oca.microsoft.com",
	"reports.wes.df.telemetry.microsoft.com",
	"wes.df.telemetry.microsoft.com",
	"df.telemetry.microsoft.com",
	"statsfe2.ws.microsoft.com",
	"sqm.microsoft.com",
	"telemetry.appex.bing.com",
	"telemetry.datacenter.microsoft.com",
	"telemetry.remoteapp.windowsazure.com",
	"telemetry.mgt.microsoft.com",
	"telemetry.officeapps.live.com",
	"nexus.officeapps.live.com",
	"telemetry.service.microsoft.com",
	"office.telemetry.microsoft.com",
	"telemetry.mail.microsoft.com",
	"telemetry.events.data.microsoft.com",
	"telemetry.azure.com",
	"telemetry.office.com",
	"telemetry.msn.com",
	"telemetry.bing.com",
}

// telemetryFirewallPrograms are the Windows telemetry / diagnostics binaries
// that Ghost Mode blocks at the Windows Filtering Platform (via the Windows
// Firewall rule engine, which is itself backed by WFP).
var telemetryFirewallPrograms = []string{
	`C:\Windows\ImmersiveControlPanel\SystemSettings.exe`,
	`C:\Windows\System32\SystemSettingsAdminFlows.exe`,
	`C:\Windows\System32\CompPkgSrv.exe`,
	`C:\Windows\System32\smartscreen.exe`,
	`C:\Windows\System32\WerFault.exe`,
	`C:\Windows\System32\wermgr.exe`,
}

// telemetryFirewallServices blocks all WFP traffic of the given services. This
// covers DiagTrack even though it runs inside a shared svchost.exe image and is
// therefore invisible to a program-path-only rule.
var telemetryFirewallServices = []string{
	"DiagTrack",
	"dmwappushservice",
	"RetailDemo",
}

var telemetryProcesses = map[string]struct{}{
	"systemsettings.exe":           {},
	"systemsettingsadminflows.exe": {},
	"comppkgsrv.exe":               {},
	"smartscreen.exe":              {},
	"werfault.exe":                 {},
	"wermgr.exe":                   {},
	"diagtrack.exe":                {},
}

func isTelemetryProcess(imagePath string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(imagePath)))
	_, found := telemetryProcesses[base]
	return found
}

// stripGhostModeBlock removes a previously written VGT block, tolerating a
// partially truncated block so a crashed earlier write cannot wedge the file.
func stripGhostModeBlock(content string) string {
	for {
		startIdx := strings.Index(content, ghostModeHeader)
		if startIdx == -1 {
			return content
		}
		endIdx := strings.Index(content[startIdx:], ghostModeFooter)
		if endIdx == -1 {
			// No footer: drop the rest of the file from the block header on.
			return strings.TrimRight(content[:startIdx], "\r\n") + "\n"
		}
		after := startIdx + endIdx + len(ghostModeFooter)
		content = content[:startIdx] + content[after:]
	}
}

// applyGhostModeEffects applies or removes BOTH enforcement layers (WFP-backed
// firewall rules + hosts sinkhole) and rolls back a partially applied layer so
// the OS never ends up in a half-enabled Ghost Mode state.
func applyGhostModeEffects(enable bool) error {
	if err := ghostFirewallApply(enable); err != nil {
		return err
	}
	hostsErr := applyGhostModeHostsSinkhole(enable)
	if hostsErr != nil {
		// Roll back the firewall layer if the hosts layer failed.
		_ = ghostFirewallApply(!enable)
		return hostsErr
	}
	return nil
}

// firewallScriptRunner is replaceable in tests so no real firewall mutation
// happens during `go test`.
var firewallScriptRunner = runFirewallScript

// applyGhostModeFirewall installs/removes WFP-backed Windows Firewall rules via
// the locale-independent NetSecurity cmdlets (netsh syntax is localized and was
// rejected on German Windows). The script contains only fixed literals from this
// package and is fed over stdin, so it adds no command-line signature surface.
func applyGhostModeFirewall(enable bool) error {
	if err := firewallScriptRunner(buildGhostFirewallScript(enable)); err != nil {
		if enable {
			// Best-effort rollback of a partially applied rule generation.
			_ = firewallScriptRunner(buildGhostFirewallScript(false))
		}
		return err
	}
	return nil
}

func buildGhostFirewallScript(enable bool) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop'\n")
	fmt.Fprintf(&b, "$group='%s'\n", ghostModeFirewallGroup)
	b.WriteString("Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue\n")
	if !enable {
		return b.String()
	}
	for _, program := range telemetryFirewallPrograms {
		fmt.Fprintf(&b,
			"New-NetFirewallRule -Group $group -DisplayName '%s - %s' -Direction Outbound -Action Block -Program '%s' -Profile Any -Enabled True | Out-Null\n",
			ghostModeFirewallTag, filepath.Base(program), strings.ReplaceAll(program, "'", "''"))
	}
	for _, service := range telemetryFirewallServices {
		fmt.Fprintf(&b,
			"New-NetFirewallRule -Group $group -DisplayName '%s - service %s' -Direction Outbound -Action Block -Service %s -Profile Any -Enabled True | Out-Null\n",
			ghostModeFirewallTag, service, service)
	}
	return b.String()
}

// ghostFirewallPowerShellArguments is the project-standard hardened Windows
// PowerShell invocation: absolute System32 PowerShell resolved by winexec,
// no profile, non-interactive and AllSigned so no unsigned script or module can
// be loaded by the firewall transaction (FIND-WIN-017).
func ghostFirewallPowerShellArguments() []string {
	return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-Command", "-"}
}

// hardenedPowerShellEnvironment removes any inherited PSModulePath so the
// firewall script can only import modules from the signed system module root
// (an inherited, user-writable PSModulePath is a module-hijack surface).
func hardenedPowerShellEnvironment() []string {
	moduleRoot := system32Binary(filepath.Join("WindowsPowerShell", "v1.0", "Modules"))
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if entry == "" || strings.IndexByte(entry, 0) >= 0 {
			continue
		}
		name := entry
		if separator := strings.IndexByte(entry, '='); separator > 0 {
			name = entry[:separator]
		}
		if strings.EqualFold(name, "PSModulePath") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "PSModulePath="+moduleRoot)
}

func runFirewallScript(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	shell, err := winexec.PowerShell()
	if err != nil {
		return fmt.Errorf("ghost firewall script: %w", err)
	}
	command := exec.CommandContext(ctx, shell, ghostFirewallPowerShellArguments()...)
	command.Env = hardenedPowerShellEnvironment()
	command.Stdin = strings.NewReader(script)
	output, err := command.CombinedOutput()
	if len(output) > 2048 {
		output = output[:2048]
	}
	if err != nil {
		return fmt.Errorf("ghost firewall script failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func system32Binary(name string) string {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" || !filepath.IsAbs(root) {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}

// hostsFileSecurityDescriptor reads the effective DACL of path. A failure is
// fatal for the hosts mutation: without the original DACL the replacement file
// could not be proven to carry the same access control (FIND-WIN-017).
func hostsFileSecurityDescriptor(path string) ([]byte, error) {
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var required uint32
	result, _, callErr := procHostsGetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		hostsDACLSecurityInformation,
		0, 0,
		uintptr(unsafe.Pointer(&required)),
	)
	if result == 0 && (required == 0 || required > hostsMaxSecurityDescriptorSize) {
		return nil, hostsCallError("GetFileSecurityW", callErr)
	}
	if required == 0 || required > hostsMaxSecurityDescriptorSize {
		return nil, fmt.Errorf("hosts security descriptor size rejected: %d", required)
	}
	buffer := make([]byte, required)
	var written uint32
	result, _, callErr = procHostsGetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		hostsDACLSecurityInformation,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&written)),
	)
	if result == 0 || written == 0 || int(written) > len(buffer) {
		return nil, hostsCallError("GetFileSecurityW", callErr)
	}
	return buffer[:written], nil
}

// hostsApplySecurityDescriptor applies the DACL part of a self-relative
// security descriptor to path (used for the sibling staging file so a fallback
// move can never transfer a restrictive directory DACL onto hosts).
func hostsApplySecurityDescriptor(path string, descriptor []byte) error {
	if len(descriptor) == 0 {
		return fmt.Errorf("empty security descriptor rejected")
	}
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	result, _, callErr := procHostsSetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		hostsDACLSecurityInformation,
		uintptr(unsafe.Pointer(&descriptor[0])),
		uintptr(len(descriptor)),
	)
	if result == 0 {
		return hostsCallError("SetFileSecurityW", callErr)
	}
	return nil
}

func hostsCallError(operation string, callErr error) error {
	var errno syscall.Errno
	if errors.As(callErr, &errno) && errno != 0 {
		return fmt.Errorf("%s failed with Windows error %d", operation, uint32(errno))
	}
	return fmt.Errorf("%s failed", operation)
}

// replaceHostsFile performs the atomic replacement. ReplaceFileW preserves the
// destination security descriptor/attributes; MoveFileEx with REPLACE_EXISTING
// is only the fallback after the staging file received the original DACL. Both
// paths are atomic and there is deliberately no truncating in-place fallback:
// a torn hosts file would break name resolution for the whole machine.
func replaceHostsFile(temporaryPath string) error {
	replacedPointer, err := syscall.UTF16PtrFromString(hostsFilePath)
	if err != nil {
		return err
	}
	temporaryPointer, err := syscall.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	result, _, callErr := procHostsReplaceFile.Call(
		uintptr(unsafe.Pointer(replacedPointer)),
		uintptr(unsafe.Pointer(temporaryPointer)),
		0,
		hostsReplaceFileWriteThrough|hostsReplaceFileIgnoreMerge,
		0, 0,
	)
	if result != 0 {
		return nil
	}
	primaryErr := hostsCallError("ReplaceFileW", callErr)
	if err := winapi.MoveFileReplace(temporaryPath, hostsFilePath); err != nil {
		return fmt.Errorf("replace hosts file: %v (atomic fallback failed: %w)", primaryErr, err)
	}
	return nil
}

// stageAndReplaceHosts writes content through an empty sibling temporary file.
// The original DACL is applied to the staging file before the first content
// byte, the replacement is atomic and the result is read back (content and
// DACL) before the mutation is reported as successful.
func stageAndReplaceHosts(content string, original string, originalDescriptor []byte) error {
	if len(content) > hostsMaxHostsBytes {
		return fmt.Errorf("hosts content size rejected: %d bytes", len(content))
	}
	directory := filepath.Dir(hostsFilePath)
	temporary, err := os.CreateTemp(directory, ".vgt-hosts-*.tmp")
	if err != nil {
		return fmt.Errorf("create hosts staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := hostsApplySecurityDescriptor(temporaryPath, originalDescriptor); err != nil {
		return fmt.Errorf("apply original hosts DACL to staging file: %w", err)
	}
	if _, err := temporary.WriteString(content); err != nil {
		return fmt.Errorf("write hosts staging file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("flush hosts staging file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close hosts staging file: %w", err)
	}
	if err := replaceHostsFile(temporaryPath); err != nil {
		return err
	}
	committed = true
	written, err := os.ReadFile(hostsFilePath)
	if err != nil {
		return fmt.Errorf("read back hosts file: %w", err)
	}
	if string(written) != content {
		return fmt.Errorf("hosts read-back verification failed: %d bytes differ", len(written))
	}
	applied, err := hostsFileSecurityDescriptor(hostsFilePath)
	if err != nil {
		return fmt.Errorf("read back hosts DACL: %w", err)
	}
	if !bytes.Equal(applied, originalDescriptor) {
		// Roll the content back so a DACL change never survives as a silent
		// access-control regression.
		if restoreErr := stageAndReplaceHosts(original, original, applied); restoreErr != nil {
			return fmt.Errorf("hosts DACL read-back mismatch and rollback failed: %w", restoreErr)
		}
		return fmt.Errorf("hosts DACL read-back mismatch; original content restored")
	}
	return nil
}

// applyGhostModeHostsSinkhole is the Ghost Mode DNS-layer effect. The hosts file
// is replaced atomically through a sibling temporary file that carries the exact
// original DACL, so neither a cross-directory rename nor a truncating fallback
// can widen or narrow the access control of System32\drivers\etc\hosts
// (FIND-WIN-017).
func applyGhostModeHostsSinkhole(enable bool) error {
	hostsFileLock.Lock()
	defer hostsFileLock.Unlock()

	raw, err := os.ReadFile(hostsFilePath)
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}
	originalDescriptor, err := hostsFileSecurityDescriptor(hostsFilePath)
	if err != nil {
		return fmt.Errorf("read hosts DACL: %w", err)
	}
	content := stripGhostModeBlock(string(raw))

	if enable {
		var b strings.Builder
		b.WriteString(strings.TrimRight(content, "\r\n"))
		b.WriteString("\n\n")
		b.WriteString(ghostModeHeader)
		b.WriteString("\n")
		for _, domain := range telemetryDomains {
			b.WriteString("0.0.0.0 ")
			b.WriteString(domain)
			b.WriteString("\n")
		}
		b.WriteString(ghostModeFooter)
		b.WriteString("\n")
		content = b.String()
	} else if content == string(raw) {
		return nil
	}

	if err := stageAndReplaceHosts(content, string(raw), originalDescriptor); err != nil {
		return err
	}
	flushDNSCache()
	return nil
}

// flushDNSCache makes a Ghost Mode change effective immediately: Windows keeps
// negative/positive resolver entries that would otherwise bypass the new hosts
// entries until their TTL expires. Best effort only; failure never fails the
// security mutation.
func flushDNSCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, system32Binary("ipconfig.exe"), "/flushdns").Run()
}
