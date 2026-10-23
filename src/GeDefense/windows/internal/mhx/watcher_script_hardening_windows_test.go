// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// HP-FIND-002 verification: the embedded process-telemetry script must never
// let a SYSTEM signature/hash read follow an attacker-controlled UNC/device
// path or traverse a reparse point. The harness extracts only the
// Test-VgtLocalImagePath function from the production script text.
const localImagePathHarness = `$ErrorActionPreference='Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$payload.SourceBase64))
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$null,[ref]$null)
$wanted = @{}
foreach ($name in @($payload.Functions)) { $wanted[[string]$name] = $true }
$defined = @{}
foreach ($function in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($wanted.ContainsKey($function.Name)) {
    . ([scriptblock]::Create($function.Extent.Text))
    $defined[$function.Name] = $true
  }
}
foreach ($name in $wanted.Keys) {
  if (-not $defined.ContainsKey($name)) {
    [Console]::Error.WriteLine("missing helper function: $name")
    exit 3
  }
}
$results = @()
foreach ($case in @($payload.Cases)) {
  if ($null -eq $case) { continue }
  try {
    $parameters = @{}
    foreach ($property in $case.Named.PSObject.Properties) { $parameters[$property.Name] = $property.Value }
    $value = & ([string]$case.Function) @parameters
    $results += [ordered]@{ id=[string]$case.Id; ok=$true; value=[bool]$value }
  } catch {
    $results += [ordered]@{ id=[string]$case.Id; ok=$false; error=[string]$_.Exception.Message }
  }
}
ConvertTo-Json -Compress -InputObject @($results)
`

type localImagePathResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Value bool   `json:"value"`
	Error string `json:"error"`
}

func runLocalImagePathHarness(t *testing.T, cases []map[string]any) map[string]localImagePathResult {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"SourceBase64": base64.StdEncoding.EncodeToString([]byte(processTraceScript)),
		"Functions":    []string{"Test-VgtLocalImagePath"},
		"Cases":        cases,
	})
	if err != nil {
		t.Fatalf("payload encoding failed: %v", err)
	}
	powerShell, err := winexec.PowerShell()
	if err != nil {
		t.Fatalf("Windows PowerShell unavailable: %v", err)
	}
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", localImagePathHarness)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("local image path harness failed: %v: %s", err, stderr.String())
	}
	var results []localImagePathResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &results); err != nil {
		t.Fatalf("harness output rejected: %v: %q", err, stdout.String())
	}
	byID := make(map[string]localImagePathResult, len(results))
	for _, result := range results {
		if !result.OK {
			t.Fatalf("case %s failed: %s", result.ID, result.Error)
		}
		byID[result.ID] = result
	}
	if len(byID) != len(cases) {
		t.Fatalf("harness returned %d results for %d cases", len(byID), len(cases))
	}
	return byID
}

func TestProcessTraceLocalImagePathRejectsNetworkAndReparse(t *testing.T) {
	temp := t.TempDir()
	realDirectory := temp + `\real-target`
	if err := os.MkdirAll(realDirectory, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(realDirectory+`\evil.exe`, []byte("vgt reparse probe"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	junction := temp + `\junction`
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, realDirectory).CombinedOutput(); err != nil {
		t.Logf("junction creation unavailable (%v: %s); intermediate reparse case skipped", err, strings.TrimSpace(string(output)))
		junction = ""
	}

	cases := []struct {
		ID     string
		Path   string
		Expect bool
	}{
		{ID: "unc", Path: `\\attacker\share\Users\x\AppData\y.exe`, Expect: false},
		{ID: "device", Path: `\\.\C:\Windows\System32\cmd.exe`, Expect: false},
		{ID: "extended", Path: `\\?\C:\Windows\System32\cmd.exe`, Expect: false},
		{ID: "relative", Path: `Users\x\AppData\y.exe`, Expect: false},
		{ID: "ads", Path: `C:\Windows\System32\cmd.exe:stream`, Expect: false},
		{ID: "local-system32", Path: `C:\Windows\System32\cmd.exe`, Expect: true},
		{ID: "local-missing", Path: `C:\Windows\System32\definitely-not-there-vgt.exe`, Expect: false},
	}
	if junction != "" {
		cases = append(cases, struct {
			ID     string
			Path   string
			Expect bool
		}{ID: "intermediate-junction", Path: junction + `\evil.exe`, Expect: false})
	}
	harnessCases := make([]map[string]any, 0, len(cases))
	for _, item := range cases {
		harnessCases = append(harnessCases, map[string]any{
			"Id":       item.ID,
			"Function": "Test-VgtLocalImagePath",
			"Named":    map[string]any{"Path": item.Path},
		})
	}
	results := runLocalImagePathHarness(t, harnessCases)
	for _, item := range cases {
		result, ok := results[item.ID]
		if !ok {
			t.Fatalf("%s: missing harness result", item.ID)
		}
		if result.Value != item.Expect {
			t.Fatalf("%s: local path check = %v for %q, want %v", item.ID, result.Value, item.Path, item.Expect)
		}
	}
}

// Static guard: the production telemetry script must validate local image paths
// before every Authenticode/hash enrichment call.
func TestProcessTraceGuardsEnrichmentWithLocalPathCheck(t *testing.T) {
	if !strings.Contains(processTraceScript, "function Test-VgtLocalImagePath") {
		t.Fatal("process telemetry script lost the local image path guard")
	}
	if count := strings.Count(processTraceScript, "Test-VgtLocalImagePath ([string]"); count < 3 {
		t.Fatalf("expected the local image guard for process, parent and ancestry paths, found %d call sites", count)
	}
	if !strings.Contains(processTraceScript, "if ($localImage -and $process.ExecutablePath) { Get-AuthenticodeSignature") {
		t.Fatal("process signature read is not gated on the local path guard")
	}
	if !strings.Contains(processTraceScript, "if ($parentLocal -and $parent -and $parent.ExecutablePath) { Get-AuthenticodeSignature") {
		t.Fatal("parent signature read is not gated on the local path guard")
	}
	if !strings.Contains(processTraceScript, "elseif ($cursorLocal -and $cursor.ExecutablePath) { Get-AuthenticodeSignature") {
		t.Fatal("ancestry signature read is not gated on the local path guard")
	}
}
