//go:build windows

// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

func runPowerShellCommand(t *testing.T, command string) string {
	t.Helper()
	powerShell, err := winexec.PowerShell()
	if err != nil {
		t.Skipf("Windows PowerShell unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	process := exec.CommandContext(ctx, powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", command)
	var stdout, stderr bytes.Buffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	if err := process.Run(); err != nil {
		t.Fatalf("PowerShell command failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func quotePowerShellPath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "''") + "'"
}

func TestPowerShellEngineScriptsParse(t *testing.T) {
	root := engineDirectory(t)
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if extension := strings.ToLower(filepath.Ext(path)); extension == ".ps1" || extension == ".psm1" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk engine directory: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no PowerShell engine files discovered")
	}
	var builder strings.Builder
	builder.WriteString("$parseErrors = @(); $files = @(")
	for index, file := range files {
		if index > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(quotePowerShellPath(file))
	}
	builder.WriteString("); foreach ($file in $files) { $tokens = $null; $errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors); if (@($errors).Count -gt 0) { $parseErrors += ($errors | ForEach-Object { [string]$_.Extent.StartLineNumber + ': ' + $_.Message }) } }; if (@($parseErrors).Count -gt 0) { Write-Output ($parseErrors -join ' | '); exit 1 }")
	output := strings.TrimSpace(runPowerShellCommand(t, builder.String()))
	if output != "" {
		t.Fatalf("PowerShell parse failures: %s", output)
	}
}

// TestPowerShellLiveContracts runs read-only module checks against the real host.
// It never applies settings or changes Defender/firewall state. Set
// VGT_TEST_POWERSHELL=1 to opt in.
func TestPowerShellLiveContracts(t *testing.T) {
	if os.Getenv("VGT_TEST_POWERSHELL") != "1" {
		t.Skip("set VGT_TEST_POWERSHELL=1 to run read-only PowerShell contract checks")
	}
	root := engineDirectory(t)
	defenderPath, err := filepath.Abs(filepath.Join(root, "Modules", "Vgt.Defender.psm1"))
	if err != nil {
		t.Fatalf("resolve defender module: %v", err)
	}
	systemPath, err := filepath.Abs(filepath.Join(root, "Modules", "Vgt.System.psm1"))
	if err != nil {
		t.Fatalf("resolve system module: %v", err)
	}
	validPath, err := filepath.Abs(filepath.Join("testdata", "settings_valid.json"))
	if err != nil {
		t.Fatalf("resolve valid fixture: %v", err)
	}
	unknownPath, err := filepath.Abs(filepath.Join("testdata", "settings_unknown_field.json"))
	if err != nil {
		t.Fatalf("resolve unknown fixture: %v", err)
	}
	badEnumPath, err := filepath.Abs(filepath.Join("testdata", "settings_bad_enum.json"))
	if err != nil {
		t.Fatalf("resolve bad enum fixture: %v", err)
	}
	duplicatePath, err := filepath.Abs(filepath.Join("testdata", "settings_duplicate_asr.json"))
	if err != nil {
		t.Fatalf("resolve duplicate ASR fixture: %v", err)
	}
	nullOptionalPath, err := filepath.Abs(filepath.Join("testdata", "settings_null_optional.json"))
	if err != nil {
		t.Fatalf("resolve null-optional fixture: %v", err)
	}
	var builder strings.Builder
	builder.WriteString("$ErrorActionPreference = 'Stop'; ")
	builder.WriteString("Import-Module " + quotePowerShellPath(defenderPath) + " -Force; ")
	builder.WriteString("Import-Module " + quotePowerShellPath(systemPath) + " -Force; ")
	builder.WriteString("$result = [ordered]@{ ValidAccepted = $false; Sha256Length = 0; UnknownRejected = $false; BadEnumRejected = $false; DuplicateAsrRejected = $false; NullOptionalAccepted = $false; AsrCatalogCount = 0; Telemetry = $null }; ")
	builder.WriteString("try { $policy = Read-VgtSettingsConfig -ConfigPath " + quotePowerShellPath(validPath) + "; $result['ValidAccepted'] = $true; $result['Sha256Length'] = ([string]$policy.Sha256).Length } catch { }; ")
	builder.WriteString("try { $null = Read-VgtSettingsConfig -ConfigPath " + quotePowerShellPath(unknownPath) + " } catch [Security.SecurityException] { $result['UnknownRejected'] = $true } catch { }; ")
	builder.WriteString("try { $null = Read-VgtSettingsConfig -ConfigPath " + quotePowerShellPath(badEnumPath) + " } catch [Security.SecurityException] { $result['BadEnumRejected'] = $true } catch { }; ")
	builder.WriteString("try { $null = Read-VgtSettingsConfig -ConfigPath " + quotePowerShellPath(duplicatePath) + " } catch [Security.SecurityException] { $result['DuplicateAsrRejected'] = $true } catch { }; ")
	builder.WriteString("try { $null = Read-VgtSettingsConfig -ConfigPath " + quotePowerShellPath(nullOptionalPath) + "; $result['NullOptionalAccepted'] = $true } catch { }; ")
	builder.WriteString("$result['AsrCatalogCount'] = @(Get-VgtAsrRuleCatalog).Count; ")
	builder.WriteString("$telemetry = Get-VgtDefenderTelemetry; ")
	builder.WriteString("$firewall = Get-VgtFirewallTelemetry; ")
	builder.WriteString("$telemetry['Firewall'] = $firewall; ")
	builder.WriteString("$telemetry['FirewallAvailable'] = [bool]$firewall['Available']; ")
	builder.WriteString("$result['Telemetry'] = $telemetry; ")
	builder.WriteString("$result | ConvertTo-Json -Depth 8 -Compress")
	output := strings.TrimSpace(runPowerShellCommand(t, builder.String()))

	var envelope struct {
		ValidAccepted        bool            `json:"ValidAccepted"`
		Sha256Length         int             `json:"Sha256Length"`
		UnknownRejected      bool            `json:"UnknownRejected"`
		BadEnumRejected      bool            `json:"BadEnumRejected"`
		DuplicateASRRejected bool            `json:"DuplicateAsrRejected"`
		NullOptionalAccepted bool            `json:"NullOptionalAccepted"`
		ASRCatalogCount      int             `json:"AsrCatalogCount"`
		Telemetry            json.RawMessage `json:"Telemetry"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("decode PowerShell envelope: %v\noutput: %s", err, output)
	}
	if !envelope.ValidAccepted {
		t.Fatal("PowerShell validation rejected the fixture that Go accepts")
	}
	if !envelope.NullOptionalAccepted {
		t.Fatal("PowerShell rejected null-valued optional settings that Go treats as unset")
	}
	if envelope.Sha256Length != 64 {
		t.Fatalf("config digest length = %d", envelope.Sha256Length)
	}
	if !envelope.UnknownRejected || !envelope.BadEnumRejected || !envelope.DuplicateASRRejected {
		t.Fatalf("PowerShell validation accepted invalid fixtures: %+v", envelope)
	}
	if envelope.ASRCatalogCount != 11 {
		t.Fatalf("PowerShell ASR catalog count = %d", envelope.ASRCatalogCount)
	}
	var telemetryKeys map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Telemetry, &telemetryKeys); err != nil {
		t.Fatalf("decode telemetry object: %v", err)
	}
	for _, key := range []string{
		"CapturedUtc", "SourcesAttempted", "Available", "ComputerStatusAvailable",
		"PreferenceAvailable", "ThreatDetectionAvailable", "ThreatQueryAvailable",
		"FirewallAvailable", "Status", "Preference", "AttackSurfaceReduction",
		"Exclusions", "Threats", "Firewall",
	} {
		if _, ok := telemetryKeys[key]; !ok {
			t.Fatalf("PowerShell telemetry schema is missing key %q", key)
		}
	}
	var telemetry DefenderTelemetry
	if err := json.Unmarshal(envelope.Telemetry, &telemetry); err != nil {
		t.Fatalf("decode telemetry into Go schema: %v", err)
	}
	if telemetry.CapturedUTC == "" {
		t.Fatal("PowerShell telemetry has no capture timestamp")
	}
	if len(telemetry.SourcesAttempted) != 5 {
		t.Fatalf("SourcesAttempted = %v", telemetry.SourcesAttempted)
	}
	if telemetry.Available {
		if telemetry.Status == nil || telemetry.Preference == nil {
			t.Fatalf("available telemetry missing sections: %+v", telemetry)
		}
	}
	if telemetry.FirewallAvailable && telemetry.Firewall == nil {
		t.Fatal("firewall reported available without a firewall section")
	}
	t.Logf("live telemetry: available=%t status=%t preference=%t detections=%t firewall=%t; ASR configured=%d firewall profiles=%d",
		telemetry.Available, telemetry.ComputerStatusAvailable, telemetry.PreferenceAvailable,
		telemetry.ThreatDetectionAvailable, telemetry.FirewallAvailable,
		func() int {
			if telemetry.AttackSurfaceReduction == nil {
				return 0
			}
			return telemetry.AttackSurfaceReduction.ConfiguredCount
		}(),
		func() int {
			if telemetry.Firewall == nil {
				return 0
			}
			return telemetry.Firewall.ProfileCount
		}())
}
