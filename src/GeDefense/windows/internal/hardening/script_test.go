// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// engineDirectory resolves the shipped PowerShell engine tree from the package
// directory. Tests skip when the package is copied without the repository
// layout instead of pretending the contract was verified.
func engineDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join("..", "..", "..", "..", "..", "engine")
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		t.Skipf("PowerShell engine directory unavailable: %v", err)
	}
	return directory
}

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func TestPowerShellEngineStaticContracts(t *testing.T) {
	root := engineDirectory(t)
	script := readContractFile(t, filepath.Join(root, "Invoke-VgtHardening.ps1"))
	defender := readContractFile(t, filepath.Join(root, "Modules", "Vgt.Defender.psm1"))
	system := readContractFile(t, filepath.Join(root, "Modules", "Vgt.System.psm1"))

	for _, token := range []string{
		"-ConfigPath",
		"'ApplyConfig'",
		"Get-VgtDefenderTelemetry",
		"Get-VgtFirewallTelemetry",
		"Read-VgtSettingsConfig",
		"Set-VgtDefenderSettings",
		"Set-VgtFirewallSettings",
		"Save-VgtBaseline",
		"Assert-VgtConfigPathJail",
		"DefenderTelemetry =",
		"ApplyReport",
	} {
		if !strings.Contains(script, token) {
			t.Fatalf("hardening script is missing contract token %q", token)
		}
	}
	if !strings.Contains(script, "ApplyConfig") || !strings.Contains(script, "ValidateSet") {
		t.Fatal("hardening script does not expose the ApplyConfig mode")
	}
	if !strings.Contains(defender, "Export-ModuleMember -Function Get-VgtDefenderTelemetry,Get-VgtAsrRuleCatalog,Read-VgtSettingsConfig,Set-VgtDefenderSettings,Set-VgtDefenderBaseline") {
		t.Fatal("defender module export surface changed")
	}
	if !strings.Contains(system, "Export-ModuleMember -Function Get-VgtFirewallTelemetry,Set-VgtFirewallSettings,Set-VgtSystemBaseline") {
		t.Fatal("system module export surface changed")
	}
	for _, rule := range ASRRuleCatalog() {
		if !strings.Contains(defender, rule.ID) {
			t.Fatalf("defender module is missing ASR rule %s", rule.ID)
		}
	}
	for _, definition := range Catalog() {
		if !strings.Contains(script, "'"+definition.ID+"'") {
			t.Fatalf("hardening script is missing component %q", definition.ID)
		}
	}
	for _, token := range []string{"Get-VgtFirewallTelemetry", "Set-VgtFirewallSettings"} {
		if !strings.Contains(system, token) {
			t.Fatalf("system module is missing token %q", token)
		}
	}
}

func TestPowerShellEngineRejectsDynamicExecutionTokens(t *testing.T) {
	root := engineDirectory(t)
	files := []string{
		filepath.Join(root, "Invoke-VgtHardening.ps1"),
		filepath.Join(root, "Modules", "Vgt.Defender.psm1"),
		filepath.Join(root, "Modules", "Vgt.System.psm1"),
	}
	forbidden := []string{
		"Invoke-Expression",
		"Start-Process",
		"DownloadString",
		"DownloadFile",
		"Net.WebClient",
		"cmd.exe",
		"wscript",
		"cscript",
		"ExecutionPolicy Bypass",
		"Set-ExecutionPolicy",
		"Add-Type",
		"New-Object -ComObject",
	}
	for _, path := range files {
		content := readContractFile(t, path)
		for _, token := range forbidden {
			if strings.Contains(content, token) {
				t.Fatalf("forbidden dynamic execution token %q in %s", token, filepath.Base(path))
			}
		}
	}
}
