// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystem32BinaryIsAbsolute(t *testing.T) {
	for _, name := range []string{"netsh.exe", "ipconfig.exe"} {
		path := system32Binary(name)
		if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Base(path), name) {
			t.Fatalf("expected absolute System32 path for %s, got %q", name, path)
		}
	}
}

func TestGhostFirewallPowerShellInvocationIsHardened(t *testing.T) {
	arguments := ghostFirewallPowerShellArguments()
	joined := strings.Join(arguments, " ")
	for _, required := range []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy AllSigned", "-Command -"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("ghost firewall PowerShell arguments are missing %q: %v", required, arguments)
		}
	}
	environment := hardenedPowerShellEnvironment()
	moduleEntries := make([]string, 0, 1)
	for _, entry := range environment {
		if strings.HasPrefix(strings.ToUpper(entry), "PSMODULEPATH=") {
			moduleEntries = append(moduleEntries, entry)
		}
	}
	if len(moduleEntries) != 1 {
		t.Fatalf("expected exactly one sanitized PSModulePath entry, got %v", moduleEntries)
	}
	expectedModuleRoot := system32Binary(filepath.Join("WindowsPowerShell", "v1.0", "Modules"))
	if moduleEntries[0] != "PSModulePath="+expectedModuleRoot {
		t.Fatalf("unexpected PSModulePath entry: %q", moduleEntries[0])
	}
}

// TestHostsWritePreservesOriginalDACL is the FIND-WIN-017 regression test: the
// previous cross-directory rename replaced the hosts DACL with the restrictive
// staging-directory DACL. The new sibling-file replacement must keep the exact
// original DACL.
func TestHostsWritePreservesOriginalDACL(t *testing.T) {
	stubGhostFirewall(t)
	previousHosts := hostsFilePath
	hostsFilePath = filepath.Join(t.TempDir(), "hosts")
	t.Cleanup(func() { hostsFilePath = previousHosts })

	if err := os.WriteFile(hostsFilePath, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before, err := hostsFileSecurityDescriptor(hostsFilePath)
	if err != nil {
		t.Fatalf("read hosts DACL: %v", err)
	}
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetGhostMode(true, "dacl preservation test"); err != nil {
		t.Fatalf("enable ghost mode: %v", err)
	}
	after, err := hostsFileSecurityDescriptor(hostsFilePath)
	if err != nil {
		t.Fatalf("read hosts DACL after write: %v", err)
	}
	if !hostsDACLsEquivalent(after, before) {
		t.Fatalf("hosts DACL changed after ghost mode write: before=%x after=%x", before, after)
	}
	if entries, err := os.ReadDir(filepath.Dir(hostsFilePath)); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".vgt-hosts-") {
				t.Fatalf("hosts staging file leaked into the target directory: %s", entry.Name())
			}
		}
	} else {
		t.Fatal(err)
	}
}

// TestHostsWriteFailsClosedWithoutTarget proves that a hosts mutation is
// refused when the target (and therefore its access control) cannot be read;
// there is no permissive fallback that would create or overwrite hosts.
func TestHostsWriteFailsClosedWithoutTarget(t *testing.T) {
	stubGhostFirewall(t)
	previousHosts := hostsFilePath
	hostsFilePath = filepath.Join(t.TempDir(), "missing-hosts")
	t.Cleanup(func() { hostsFilePath = previousHosts })
	if err := applyGhostModeHostsSinkhole(true); err == nil {
		t.Fatal("hosts mutation succeeded without an existing hosts target")
	}
	if _, err := os.Stat(hostsFilePath); !os.IsNotExist(err) {
		t.Fatalf("failed hosts mutation created a file: %v", err)
	}
}

func TestGhostStagingUsesTargetDirectory(t *testing.T) {
	stubGhostFirewall(t)
	previousHosts := hostsFilePath
	hostsFilePath = filepath.Join(t.TempDir(), "hosts")
	t.Cleanup(func() { hostsFilePath = previousHosts })
	if err := os.WriteFile(hostsFilePath, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := applyGhostModeHostsSinkhole(true); err != nil {
		t.Fatalf("enable hosts sinkhole: %v", err)
	}
	raw, err := os.ReadFile(hostsFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), ghostModeHeader) {
		t.Fatal("ghost mode block missing")
	}
	// The staging file must be created next to the target (same directory)
	// and cleaned up; nothing may be written to the legacy ProgramData cache or
	// system temp locations.
	entries, err := os.ReadDir(filepath.Dir(hostsFilePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(hostsFilePath) {
			t.Fatalf("unexpected file next to hosts after sinkhole write: %s", entry.Name())
		}
	}
}

func stubGhostFirewall(t *testing.T) {
	t.Helper()
	previous := ghostFirewallApply
	ghostFirewallApply = func(bool) error { return nil }
	t.Cleanup(func() {
		ghostFirewallApply = previous
	})
}

func TestGhostModeAppliesAndRevertsHostsSinkhole(t *testing.T) {
	stubGhostFirewall(t)
	previousHosts := hostsFilePath
	hostsFilePath = t.TempDir() + `\hosts`
	t.Cleanup(func() { hostsFilePath = previousHosts })

	const baseHosts = "127.0.0.1 localhost\n"
	if err := os.WriteFile(hostsFilePath, []byte(baseHosts), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetGhostMode(true, "test enable"); err != nil {
		t.Fatalf("enable ghost mode: %v", err)
	}
	raw, err := os.ReadFile(hostsFilePath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, ghostModeHeader) || !strings.Contains(content, ghostModeFooter) {
		t.Fatalf("ghost mode block missing:\n%s", content)
	}
	if !strings.Contains(content, "0.0.0.0 telemetry.microsoft.com") {
		t.Fatal("expected telemetry domain null-route")
	}
	if !store.Config().GhostModeTelemetryKill {
		t.Fatal("ghost mode state not persisted")
	}

	// Idempotent second enable must not duplicate the block.
	if err := store.SetGhostMode(true, "test enable again"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(hostsFilePath)
	if got := strings.Count(string(raw), ghostModeHeader); got != 1 {
		t.Fatalf("ghost mode block duplicated: %d headers", got)
	}

	if err := store.SetGhostMode(false, "test disable"); err != nil {
		t.Fatalf("disable ghost mode: %v", err)
	}
	raw, _ = os.ReadFile(hostsFilePath)
	if strings.Contains(string(raw), ghostModeHeader) {
		t.Fatal("ghost mode block must be removed on disable")
	}
	if strings.Contains(string(raw), "0.0.0.0 telemetry.microsoft.com") {
		t.Fatal("telemetry null-routes must be removed on disable")
	}
	if !strings.Contains(string(raw), "127.0.0.1 localhost") {
		t.Fatal("original hosts content must be retained")
	}
}

func TestGhostModeRecoversFromTruncatedBlock(t *testing.T) {
	stubGhostFirewall(t)
	previousHosts := hostsFilePath
	hostsFilePath = t.TempDir() + `\hosts`
	t.Cleanup(func() { hostsFilePath = previousHosts })

	truncated := "127.0.0.1 localhost\n" + ghostModeHeader + "\n0.0.0.0 telemetry.microsoft.com\n"
	if err := os.WriteFile(hostsFilePath, []byte(truncated), 0644); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetGhostMode(false, "test cleanup"); err != nil {
		t.Fatalf("cleanup truncated block: %v", err)
	}
	raw, _ := os.ReadFile(hostsFilePath)
	if strings.Contains(string(raw), ghostModeHeader) {
		t.Fatal("truncated block must be removed")
	}
	if !strings.Contains(string(raw), "127.0.0.1 localhost") {
		t.Fatal("hosts content before the block must be retained")
	}
}

func TestTelemetryDomainCoverage(t *testing.T) {
	if len(telemetryDomains) < 60 {
		t.Fatalf("expected >=60 curated telemetry domains, got %d", len(telemetryDomains))
	}
	seen := make(map[string]struct{}, len(telemetryDomains))
	for _, domain := range telemetryDomains {
		if _, dup := seen[domain]; dup {
			t.Fatalf("duplicate telemetry domain %q", domain)
		}
		seen[domain] = struct{}{}
	}
	// Security updates, Defender cloud protection, activation, Store/CDN and
	// connectivity checks must never be null-routed by Ghost Mode.
	forbidden := []string{
		"windowsupdate", "delivery.mp", "definitionupdate", "wdcp", "spynet",
		"login.live.com", "login.microsoftonline.com", "activation",
		"msftconnecttest", "msftncsi", "storeedgefd", "displaycatalog",
	}
	joined := strings.Join(telemetryDomains, "\n")
	for _, needle := range forbidden {
		if strings.Contains(joined, needle) {
			t.Fatalf("forbidden endpoint %q must not be part of the Ghost Mode sinkhole", needle)
		}
	}
}

func TestGhostFirewallRuleGeneration(t *testing.T) {
	stubGhostFirewall(t)
	previousRunner := firewallScriptRunner
	var scripts []string
	firewallScriptRunner = func(script string) error {
		scripts = append(scripts, script)
		return nil
	}
	t.Cleanup(func() { firewallScriptRunner = previousRunner })

	if err := applyGhostModeFirewall(true); err != nil {
		t.Fatalf("enable firewall rules: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("expected exactly one enable script, got %d", len(scripts))
	}
	enable := scripts[0]
	for _, needle := range []string{
		"Get-NetFirewallRule -Group $group",
		"Remove-NetFirewallRule",
		"New-NetFirewallRule",
		"Direction Outbound",
		"Action Block",
		"-Group $group",
		"SystemSettings.exe",
		"-Service DiagTrack",
		"-Service dmwappushservice",
	} {
		if !strings.Contains(enable, needle) {
			t.Fatalf("enable script missing %q:\n%s", needle, enable)
		}
	}
	if strings.Count(enable, "New-NetFirewallRule") != len(telemetryFirewallPrograms)+len(telemetryFirewallServices) {
		t.Fatalf("unexpected firewall rule count in script:\n%s", enable)
	}

	scripts = nil
	if err := applyGhostModeFirewall(false); err != nil {
		t.Fatalf("disable firewall rules: %v", err)
	}
	if len(scripts) != 1 || strings.Contains(scripts[0], "New-NetFirewallRule") ||
		!strings.Contains(scripts[0], "Remove-NetFirewallRule") {
		t.Fatalf("disable must only remove the group, got %v", scripts)
	}
}

func TestGhostFirewallFailureRollsBack(t *testing.T) {
	stubGhostFirewall(t)
	previousRunner := firewallScriptRunner
	var scripts []string
	firewallScriptRunner = func(script string) error {
		scripts = append(scripts, script)
		if strings.Contains(script, "New-NetFirewallRule") {
			return errors.New("firewall rejected rule")
		}
		return nil
	}
	t.Cleanup(func() { firewallScriptRunner = previousRunner })

	if err := applyGhostModeFirewall(true); err == nil {
		t.Fatal("expected firewall apply failure")
	}
	if len(scripts) < 2 {
		t.Fatal("failed apply must trigger a rollback script")
	}
	rollback := scripts[len(scripts)-1]
	if strings.Contains(rollback, "New-NetFirewallRule") || !strings.Contains(rollback, "Remove-NetFirewallRule") {
		t.Fatalf("unexpected rollback script:\n%s", rollback)
	}
}

func TestGhostModeRuntimeState(t *testing.T) {
	stubGhostFirewall(t)
	previousHosts := hostsFilePath
	hostsFilePath = t.TempDir() + `\hosts`
	t.Cleanup(func() { hostsFilePath = previousHosts })
	if err := os.WriteFile(hostsFilePath, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if applied, lastError := store.GhostRuntime(); applied || lastError != "" {
		t.Fatalf("unexpected initial ghost runtime: applied=%v err=%q", applied, lastError)
	}
	if err := store.SetGhostMode(true, "runtime state test"); err != nil {
		t.Fatal(err)
	}
	if applied, lastError := store.GhostRuntime(); !applied || lastError != "" {
		t.Fatalf("ghost runtime must be applied after enable: applied=%v err=%q", applied, lastError)
	}
	if err := store.SetGhostMode(false, "runtime state test disabled"); err != nil {
		t.Fatal(err)
	}
	if applied, lastError := store.GhostRuntime(); applied || lastError != "" {
		t.Fatalf("ghost runtime must be clean after disable: applied=%v err=%q", applied, lastError)
	}
}
