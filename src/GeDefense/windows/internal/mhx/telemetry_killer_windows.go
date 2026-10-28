// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	hostsFileLock sync.Mutex
	hostsFilePath = `C:\Windows\System32\drivers\etc\hosts`
	// ghostStagingDirOverride is a test seam. In production the staging file is
	// written under ProgramData so the sensitive System32\drivers\etc directory
	// never contains a short-lived VGT temp file (which Titan would report as a
	// system modification).
	ghostStagingDirOverride = ""
	// ghostFirewallApply is replaceable in tests so no real firewall mutation
	// happens during `go test`.
	ghostFirewallApply = applyGhostModeFirewall
)

// ghostStagingDirectory returns a same-volume directory outside System32 for
// the atomic hosts replacement staging file.
func ghostStagingDirectory() string {
	if ghostStagingDirOverride != "" {
		return ghostStagingDirOverride
	}
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData != "" && filepath.IsAbs(programData) {
		return filepath.Join(programData, "VGT", "GeDefense")
	}
	return os.TempDir()
}

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

func runFirewallScript(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	shell := system32Binary(filepath.Join("WindowsPowerShell", "v1.0", "powershell.exe"))
	command := exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
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

// applyGhostModeHostsSinkhole is the Ghost Mode DNS-layer effect. The hosts file
// is replaced crash-safely (temp file + flush + atomic rename) because a torn
// write would break name resolution for the whole machine.
func applyGhostModeHostsSinkhole(enable bool) error {
	hostsFileLock.Lock()
	defer hostsFileLock.Unlock()

	raw, err := os.ReadFile(hostsFilePath)
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
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

	stagingDir := ghostStagingDirectory()
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return fmt.Errorf("create hosts staging directory: %w", err)
	}
	tmpFile, err := os.CreateTemp(stagingDir, "hosts.vgt-*")
	if err != nil {
		return fmt.Errorf("create hosts staging file: %w", err)
	}
	tmpName := tmpFile.Name()
	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		cleanup()
		return fmt.Errorf("write hosts staging file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("flush hosts staging file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close hosts staging file: %w", err)
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("permission hosts staging file: %w", err)
	}
	if err := os.Rename(tmpName, hostsFilePath); err != nil {
		_ = os.Remove(tmpName)
		// The hosts file is owned by TrustedInstaller; deleting/renaming it can
		// be denied even for SYSTEM although the Modify ACE allows an in-place
		// rewrite. Keep a recovery backup, then fall back to a truncating write.
		backupPath := hostsFilePath + ".vgt-backup"
		if _, statErr := os.Stat(backupPath); statErr != nil {
			_ = os.WriteFile(backupPath, raw, 0600)
		}
		if writeErr := os.WriteFile(hostsFilePath, []byte(content), 0644); writeErr != nil {
			return fmt.Errorf("replace hosts file: %v (fallback rewrite failed: %w)", err, writeErr)
		}
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
