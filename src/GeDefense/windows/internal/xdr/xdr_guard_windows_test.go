// STATUS: DIAMANT VGT SUPREME
//go:build windows

package xdr

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// xdrScriptPath resolves the shipped XDR scan script from the package
// directory (src/GeDefense/windows/internal/xdr -> repository root).
const xdrScriptPath = `../../../../../xdr/Invoke-VgtXdrScan.ps1`

// xdrHelperHarness parses the production script, evaluates only the requested
// helper function definitions (their AST extents) and executes the supplied
// regression cases. It never runs the mutating/scanning main body. Input and
// output are JSON; script text is base64-encoded UTF-8 so the console code page
// cannot corrupt it.
const xdrHelperHarness = `$ErrorActionPreference='Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$payload.SourceBase64))
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors.Count -gt 0) {
  [Console]::Error.WriteLine((($errors | ForEach-Object { $_.Message }) -join '; '))
  exit 2
}
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
foreach ($case in @($payload.Cases)) {
  if ($null -eq $case) { continue }
  $id = [string]$case.Id
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    if ($null -ne $case.Positional) {
      $arguments = @()
      if ($null -ne $case.Script) { $arguments += [scriptblock]::Create([string]$case.Script) }
      foreach ($argument in @($case.Positional)) { $arguments += $argument }
      $value = & ([string]$case.Function) @arguments
    } else {
      $parameters = @{}
      if ($null -ne $case.Named) {
        foreach ($property in $case.Named.PSObject.Properties) { $parameters[$property.Name] = $property.Value }
      }
      if ($null -ne $case.Budget) {
        $deadlineOffset = 90
        if ($null -ne $case.Budget.DeadlineOffsetSeconds) { $deadlineOffset = [int]$case.Budget.DeadlineOffsetSeconds }
        $parameters['Budget'] = @{
          DeadlineUtc = [DateTime]::UtcNow.AddSeconds($deadlineOffset)
          Checks = [int]$case.Budget.Checks
          MaxChecks = [int]$case.Budget.MaxChecks
          Exhausted = [bool]$case.Budget.Exhausted
        }
      }
      if ($null -ne $case.Script) { $parameters['Script'] = [scriptblock]::Create([string]$case.Script) }
      $value = & ([string]$case.Function) @parameters
    }
    $sw.Stop()
    $serialized = if ($null -eq $value) { 'null' } else { $value | ConvertTo-Json -Compress -Depth 6 }
    [ordered]@{ id=$id; ok=$true; value=$serialized; elapsedMs=[int]$sw.ElapsedMilliseconds } | ConvertTo-Json -Compress
  } catch {
    $sw.Stop()
    [ordered]@{ id=$id; ok=$false; error=[string]$_.Exception.Message; elapsedMs=[int]$sw.ElapsedMilliseconds } | ConvertTo-Json -Compress
  }
}
`

var xdrHelperFunctions = []string{
	"Get-VgtSafeText",
	"Get-VgtExecutableFromCommand",
	"Get-VgtPathTrust",
	"Test-VgtLocalFixedPath",
	"Test-VgtPathNoReparse",
	"Invoke-VgtBoundedScript",
	"Get-VgtSignatureStatus",
	"Add-VgtSignatureFindings",
}

type xdrHelperBudget struct {
	Checks                int  `json:"Checks"`
	MaxChecks             int  `json:"MaxChecks"`
	DeadlineOffsetSeconds *int `json:"DeadlineOffsetSeconds,omitempty"`
	Exhausted             bool `json:"Exhausted"`
}

type xdrHelperCase struct {
	ID         string           `json:"Id"`
	Function   string           `json:"Function"`
	Named      map[string]any   `json:"Named,omitempty"`
	Positional []any            `json:"Positional,omitempty"`
	Script     string           `json:"Script,omitempty"`
	Budget     *xdrHelperBudget `json:"Budget,omitempty"`
}

type xdrHelperResult struct {
	ID        string `json:"id"`
	OK        bool   `json:"ok"`
	Value     string `json:"value"`
	Error     string `json:"error"`
	ElapsedMS int    `json:"elapsedMs"`
}

func readXdrScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(xdrScriptPath)
	if err != nil {
		t.Fatalf("cannot read XDR scan script %q: %v", xdrScriptPath, err)
	}
	if len(raw) == 0 || len(raw) > 256<<10 {
		t.Fatalf("XDR scan script size rejected: %d", len(raw))
	}
	return string(raw)
}

func runXdrHelperHarness(t *testing.T, cases []xdrHelperCase) map[string]xdrHelperResult {
	t.Helper()
	source := readXdrScript(t)
	if cases == nil {
		cases = []xdrHelperCase{}
	}
	payload := map[string]any{
		"SourceBase64": base64.StdEncoding.EncodeToString([]byte(source)),
		"Functions":    xdrHelperFunctions,
		"Cases":        cases,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("payload encoding failed: %v", err)
	}
	powerShell, err := winexec.PowerShell()
	if err != nil {
		t.Fatalf("Windows PowerShell unavailable: %v", err)
	}
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", xdrHelperHarness)
	command.Stdin = bytes.NewReader(rawPayload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("XDR helper harness failed: %v: %s", err, stderr.String())
	}
	results := make(map[string]xdrHelperResult, len(cases))
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var result xdrHelperResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("harness output rejected: %v: %q", err, line)
		}
		if result.ID == "" {
			t.Fatalf("harness result without id: %q", line)
		}
		if !result.OK {
			t.Fatalf("helper %s failed: %s", result.ID, result.Error)
		}
		results[result.ID] = result
	}
	return results
}

type xdrPathTrust struct {
	Kind         string `json:"Kind"`
	Path         string `json:"Path"`
	UserWritable bool   `json:"UserWritable"`
}

func TestXdrScriptParsesAndKeepsSingleBoundedSignatureHelper(t *testing.T) {
	source := readXdrScript(t)
	if count := strings.Count(source, "Get-AuthenticodeSignature -LiteralPath"); count != 1 {
		t.Fatalf("Get-AuthenticodeSignature -LiteralPath must only exist inside the bounded helper (found %d occurrences)", count)
	}
	for _, required := range []string{"Get-VgtSignatureStatus", "Invoke-VgtBoundedScript", "RejectedLocalOnly", "RejectedReparse", "BudgetExhausted"} {
		if !strings.Contains(source, required) {
			t.Fatalf("XDR scan script lost required helper marker %q", required)
		}
	}
	if strings.Contains(source, "Test-VgtUserWritablePath") {
		t.Fatal("substring-only user-writable path test must not be reintroduced")
	}
	// The harness parses the script, so an empty case list only proves syntax.
	runXdrHelperHarness(t, nil)
}

// HP-FIND-003: UNC/device/alias paths are classified without any file access.
func TestXdrPathTrustClassification(t *testing.T) {
	cases := []struct {
		ID           string
		Path         string
		WantKind     string
		WantWritable bool
		WantPath     string
	}{
		{ID: "unc", Path: `\\attacker\share\Users\x\AppData\y.exe`, WantKind: "NonLocal"},
		{ID: "device", Path: `\\.\C:\Windows\System32\cmd.exe`, WantKind: "NonLocal"},
		{ID: "extended", Path: `\\?\C:\Windows\System32\cmd.exe`, WantKind: "NonLocal"},
		{ID: "forward-slash-unc", Path: `//attacker/share/Users/x/AppData/y.exe`, WantKind: "NonLocal"},
		{ID: "relative", Path: `Users\x\AppData\y.exe`, WantKind: "Invalid"},
		{ID: "drive-relative", Path: `C:Windows\System32\cmd.exe`, WantKind: "Invalid"},
		{ID: "ads", Path: `C:\Users\Public\AppData\Local\evil.exe:stream`, WantKind: "AlternateDataStream"},
		{ID: "system32", Path: `C:\Windows\System32\cmd.exe`, WantKind: "LocalFixed", WantPath: `C:\Windows\System32\cmd.exe`},
		{ID: "environment", Path: `%SystemRoot%\System32\cmd.exe`, WantKind: "LocalFixed", WantPath: `C:\Windows\System32\cmd.exe`},
		{ID: "traversal", Path: `C:\Users\Public\AppData\Local\..\..\..\..\Windows\System32\cmd.exe`, WantKind: "LocalFixed", WantPath: `C:\Windows\System32\cmd.exe`},
		{ID: "forward-slash-local", Path: `C:/Windows/System32/cmd.exe`, WantKind: "LocalFixed", WantPath: `C:\Windows\System32\cmd.exe`},
		{ID: "user-writable", Path: `C:\Users\Public\AppData\Local\Temp\vgt-scan-test.exe`, WantKind: "LocalFixed", WantWritable: true},
		{ID: "windows-temp", Path: `C:\Windows\Temp\vgt-scan-test.exe`, WantKind: "LocalFixed", WantWritable: true},
	}
	harnessCases := make([]xdrHelperCase, 0, len(cases))
	for _, item := range cases {
		harnessCases = append(harnessCases, xdrHelperCase{ID: item.ID, Function: "Get-VgtPathTrust", Named: map[string]any{"Path": item.Path}})
	}
	results := runXdrHelperHarness(t, harnessCases)
	for _, item := range cases {
		var trust xdrPathTrust
		if err := json.Unmarshal([]byte(results[item.ID].Value), &trust); err != nil {
			t.Fatalf("%s: cannot decode path trust %q: %v", item.ID, results[item.ID].Value, err)
		}
		if trust.Kind != item.WantKind {
			t.Fatalf("%s: kind = %q, want %q (path %q)", item.ID, trust.Kind, item.WantKind, item.Path)
		}
		if trust.UserWritable != item.WantWritable {
			t.Fatalf("%s: userWritable = %v, want %v", item.ID, trust.UserWritable, item.WantWritable)
		}
		if item.WantPath != "" && !strings.EqualFold(trust.Path, item.WantPath) {
			t.Fatalf("%s: canonical path = %q, want %q", item.ID, trust.Path, item.WantPath)
		}
	}
}

type xdrSignatureStatus struct {
	Status     string `json:"Status"`
	FileAccess bool   `json:"FileAccess"`
}

func TestXdrSignatureStatusRejectsNonLocalAndReparse(t *testing.T) {
	temp := t.TempDir()
	unsigned := filepath.Join(temp, "unsigned.bin")
	if err := os.WriteFile(unsigned, []byte("vgt unsigned test payload"), 0o600); err != nil {
		t.Fatalf("cannot write test file: %v", err)
	}
	// A junction on a fixed drive must be rejected before any signature read.
	junctionParent := filepath.Join(temp, "junction-parent")
	realTarget := filepath.Join(temp, "real-target")
	if err := os.MkdirAll(junctionParent, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(realTarget, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	junction := filepath.Join(junctionParent, "link")
	mklink := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, realTarget)
	mklink.Stdout, mklink.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	junctionUsable := mklink.Run() == nil
	reparsePath := filepath.Join(junction, "evil.exe")
	if junctionUsable {
		if err := os.WriteFile(filepath.Join(realTarget, "evil.exe"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write target file: %v", err)
		}
	}

	cases := []xdrHelperCase{
		{ID: "unc", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": `\\attacker\share\Users\x\AppData\y.exe`}},
		{ID: "device", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": `\\.\C:\Windows\System32\cmd.exe`}},
		{ID: "valid-signed", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": `C:\Windows\System32\cmd.exe`}},
		{ID: "unsigned", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": unsigned}},
		{ID: "budget-checks", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": `C:\Windows\System32\cmd.exe`}, Budget: &xdrHelperBudget{Checks: 64, MaxChecks: 64}},
		{ID: "budget-deadline", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": `C:\Windows\System32\cmd.exe`}, Budget: &xdrHelperBudget{MaxChecks: 64, DeadlineOffsetSeconds: intPtr(-10)}},
	}
	if junctionUsable {
		cases = append(cases, xdrHelperCase{ID: "junction", Function: "Get-VgtSignatureStatus", Named: map[string]any{"Path": reparsePath}})
	}
	results := runXdrHelperHarness(t, cases)

	expect := func(id, status string, fileAccess bool) {
		t.Helper()
		var value xdrSignatureStatus
		if err := json.Unmarshal([]byte(results[id].Value), &value); err != nil {
			t.Fatalf("%s: cannot decode signature status %q: %v", id, results[id].Value, err)
		}
		if value.Status != status {
			t.Fatalf("%s: status = %q, want %q", id, value.Status, status)
		}
		if value.FileAccess != fileAccess {
			t.Fatalf("%s: fileAccess = %v, want %v", id, value.FileAccess, fileAccess)
		}
	}
	expect("unc", "RejectedLocalOnly", false)
	expect("device", "RejectedLocalOnly", false)
	if !junctionUsable {
		t.Log("junction creation unavailable; reparse regression case skipped")
	} else {
		expect("junction", "RejectedReparse", false)
	}
	expect("valid-signed", "Valid", true)
	var unsignedStatus xdrSignatureStatus
	if err := json.Unmarshal([]byte(results["unsigned"].Value), &unsignedStatus); err != nil {
		t.Fatalf("unsigned: cannot decode signature status: %v", err)
	}
	if unsignedStatus.Status == "Valid" || unsignedStatus.Status == "RejectedLocalOnly" || unsignedStatus.Status == "RejectedReparse" || unsignedStatus.Status == "BudgetExhausted" {
		t.Fatalf("unsigned local file must reach the bounded signature callback, got %q", unsignedStatus.Status)
	}
	if !unsignedStatus.FileAccess {
		t.Fatal("unsigned local file must be opened by the bounded callback")
	}
	expect("budget-checks", "BudgetExhausted", false)
	expect("budget-deadline", "BudgetExhausted", false)
}

type xdrBoundedResult struct {
	Completed bool `json:"Completed"`
	TimedOut  bool `json:"TimedOut"`
}

func TestXdrBoundedSignatureHelperIsTimeBounded(t *testing.T) {
	cases := []xdrHelperCase{
		{
			ID:         "quick",
			Function:   "Invoke-VgtBoundedScript",
			Script:     `param($value) 'ok:' + [string]$value`,
			Positional: []any{"hello"},
		},
		{
			ID:         "slow",
			Function:   "Invoke-VgtBoundedScript",
			Script:     `param($value) Start-Sleep -Seconds 10; 'late'`,
			Positional: []any{},
			Named:      map[string]any{"TimeoutSeconds": 1},
		},
	}
	results := runXdrHelperHarness(t, cases)
	var quick xdrBoundedResult
	if err := json.Unmarshal([]byte(results["quick"].Value), &quick); err != nil {
		t.Fatalf("cannot decode bounded result: %v", err)
	}
	if !quick.Completed {
		t.Fatalf("quick bounded call did not complete: %s", results["quick"].Value)
	}
	var slow xdrBoundedResult
	if err := json.Unmarshal([]byte(results["slow"].Value), &slow); err != nil {
		t.Fatalf("cannot decode bounded result: %v", err)
	}
	if slow.Completed || !slow.TimedOut {
		t.Fatalf("slow bounded call was not abandoned: %s", results["slow"].Value)
	}
	if results["slow"].ElapsedMS > 5000 {
		t.Fatalf("bounded timeout was not enforced: %d ms", results["slow"].ElapsedMS)
	}
}

func TestXdrExecutableCommandExtraction(t *testing.T) {
	cases := []struct {
		ID         string
		Command    string
		WantOutput string
	}{
		{ID: "quoted", Command: `"C:\Program Files\VGT\app.exe" /background`, WantOutput: `C:\Program Files\VGT\app.exe`},
		{ID: "unquoted", Command: `C:\Windows\System32\cmd.exe /c whoami`, WantOutput: `C:\Windows\System32\cmd.exe`},
		{ID: "unc", Command: `"\\attacker\share\Users\x\AppData\y.exe" -x`, WantOutput: `\\attacker\share\Users\x\AppData\y.exe`},
		{ID: "environment", Command: `%SystemRoot%\System32\cmd.exe /c whoami`, WantOutput: `C:\Windows\System32\cmd.exe`},
		{ID: "none", Command: `calc`, WantOutput: ""},
		{ID: "oversized", Command: strings.Repeat("A", 9000) + ".exe", WantOutput: ""},
	}
	harnessCases := make([]xdrHelperCase, 0, len(cases))
	for _, item := range cases {
		harnessCases = append(harnessCases, xdrHelperCase{ID: item.ID, Function: "Get-VgtExecutableFromCommand", Named: map[string]any{"CommandLine": item.Command}})
	}
	results := runXdrHelperHarness(t, harnessCases)
	for _, item := range cases {
		var value string
		if err := json.Unmarshal([]byte(results[item.ID].Value), &value); err != nil {
			t.Fatalf("%s: cannot decode output %q: %v", item.ID, results[item.ID].Value, err)
		}
		if !strings.EqualFold(value, item.WantOutput) {
			t.Fatalf("%s: output = %q, want %q", item.ID, value, item.WantOutput)
		}
	}
}

func TestXdrHarnessMissingHelperFails(t *testing.T) {
	// Subprocess-level negative control: a renamed function must be detected by
	// the harness instead of silently passing without assertions.
	source := readXdrScript(t)
	renamed := strings.ReplaceAll(source, "Get-VgtPathTrust", "Get-VgtPathTrustRenamed")
	payload := map[string]any{
		"SourceBase64": base64.StdEncoding.EncodeToString([]byte(renamed)),
		"Functions":    []string{"Get-VgtPathTrust"},
		"Cases":        []any{},
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("payload encoding failed: %v", err)
	}
	powerShell, err := winexec.PowerShell()
	if err != nil {
		t.Fatalf("Windows PowerShell unavailable: %v", err)
	}
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", xdrHelperHarness)
	command.Stdin = bytes.NewReader(rawPayload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	if err == nil {
		t.Fatalf("harness accepted a script without required helper functions (stdout %q)", stdout.String())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("harness failure was not an exit error: %v", err)
	}
	if exitErr.ExitCode() != 3 {
		t.Fatalf("harness exit code = %d, want 3 (missing helper)", exitErr.ExitCode())
	}
}

func intPtr(value int) *int {
	return &value
}
