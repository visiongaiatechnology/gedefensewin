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

// xdr/Set-VgtMhxProtection.ps1 applies firewall/ASR baseline state as SYSTEM.
// HP-FIND-006 regression: its persisted baseline must be structurally validated
// before Restore applies any value.
const mhxProtectionScriptPath = `../../../../../xdr/Set-VgtMhxProtection.ps1`

const mhxBaselineHelperHarness = `$ErrorActionPreference='Stop'
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
  try {
    $parameters = @{}
    if ($null -ne $case.JsonState) { $parameters['State'] = ([string]$case.JsonState | ConvertFrom-Json) }
    $value = & ([string]$case.Function) @parameters
    $serialized = if ($null -eq $value) { 'null' } else { $value | ConvertTo-Json -Compress -Depth 8 }
    [ordered]@{ id=[string]$case.Id; ok=$true; value=$serialized } | ConvertTo-Json -Compress
  } catch {
    [ordered]@{ id=[string]$case.Id; ok=$false; error=[string]$_.Exception.Message } | ConvertTo-Json -Compress
  }
}
`

var mhxBaselineHelperFunctions = []string{
	"Test-VgtMhxBaselineState",
	"Get-VgtMhxBaselineIntegrityMaterial",
	"Get-VgtMhxBaselineIntegrityHash",
	"Test-VgtMhxBaselineIntegrity",
}

type mhxBaselineCase struct {
	ID        string `json:"Id"`
	Function  string `json:"Function"`
	JsonState string `json:"JsonState,omitempty"`
}

type mhxBaselineResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Value string `json:"value"`
	Error string `json:"error"`
}

func runMhxBaselineHarness(t *testing.T, cases []mhxBaselineCase) map[string]mhxBaselineResult {
	t.Helper()
	raw, err := os.ReadFile(mhxProtectionScriptPath)
	if err != nil {
		t.Fatalf("cannot read %q: %v", mhxProtectionScriptPath, err)
	}
	if len(raw) == 0 || len(raw) > 512<<10 {
		t.Fatalf("script size rejected: %d", len(raw))
	}
	if cases == nil {
		cases = []mhxBaselineCase{}
	}
	payload, err := json.Marshal(map[string]any{
		"SourceBase64": base64.StdEncoding.EncodeToString(raw),
		"Functions":    mhxBaselineHelperFunctions,
		"Cases":        cases,
	})
	if err != nil {
		t.Fatalf("payload encoding failed: %v", err)
	}
	powerShell, err := winexec.PowerShell()
	if err != nil {
		t.Fatalf("Windows PowerShell unavailable: %v", err)
	}
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", mhxBaselineHelperHarness)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("MHX baseline helper harness failed: %v: %s", err, stderr.String())
	}
	results := make(map[string]mhxBaselineResult, len(cases))
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var result mhxBaselineResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("harness output rejected: %v: %q", err, line)
		}
		if !result.OK {
			t.Fatalf("MHX baseline case %s failed: %s", result.ID, result.Error)
		}
		results[result.ID] = result
	}
	if len(results) != len(cases) {
		t.Fatalf("harness returned %d results for %d cases", len(results), len(cases))
	}
	return results
}

func mhxBaselineFixture() map[string]any {
	return map[string]any{
		"Format":       2,
		"TimestampUtc": "2026-01-01T00:00:00.0000000Z",
		"FirewallProfiles": []any{
			map[string]any{"Name": "Domain", "DefaultOutboundAction": "Allow"},
			map[string]any{"Name": "Private", "DefaultOutboundAction": "Block"},
			map[string]any{"Name": "Public", "DefaultOutboundAction": "Block"},
		},
		"AsrIds":     []any{"5beb7efe-fd9a-4556-801d-275e5ffc04cc"},
		"AsrActions": []any{1},
	}
}

func cloneFixture(fixture map[string]any, mutate func(map[string]any)) map[string]any {
	copy := map[string]any{}
	for key, value := range fixture {
		copy[key] = value
	}
	mutate(copy)
	return copy
}

func fixtureJSON(t *testing.T, value map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("fixture encoding failed: %v", err)
	}
	return string(raw)
}

func TestMhxBaselineStateValidation(t *testing.T) {
	fixture := mhxBaselineFixture()
	cases := []struct {
		ID     string
		Value  map[string]any
		Expect bool
	}{
		{ID: "valid", Value: fixture, Expect: true},
		{ID: "format-3", Value: cloneFixture(fixture, func(m map[string]any) { m["Format"] = 3 }), Expect: false},
		{ID: "bad-profile-name", Value: cloneFixture(fixture, func(m map[string]any) {
			m["FirewallProfiles"] = []any{map[string]any{"Name": "Fake", "DefaultOutboundAction": "Block"}}
		}), Expect: false},
		{ID: "bad-outbound-action", Value: cloneFixture(fixture, func(m map[string]any) {
			m["FirewallProfiles"] = []any{map[string]any{"Name": "Domain", "DefaultOutboundAction": "Permit"}}
		}), Expect: false},
		{ID: "duplicate-profile", Value: cloneFixture(fixture, func(m map[string]any) {
			m["FirewallProfiles"] = []any{
				map[string]any{"Name": "Domain", "DefaultOutboundAction": "Allow"},
				map[string]any{"Name": "Domain", "DefaultOutboundAction": "Block"},
			}
		}), Expect: false},
		{ID: "too-many-profiles", Value: cloneFixture(fixture, func(m map[string]any) {
			m["FirewallProfiles"] = []any{
				map[string]any{"Name": "Domain", "DefaultOutboundAction": "Allow"},
				map[string]any{"Name": "Private", "DefaultOutboundAction": "Allow"},
				map[string]any{"Name": "Public", "DefaultOutboundAction": "Allow"},
				map[string]any{"Name": "Public", "DefaultOutboundAction": "Block"},
			}
		}), Expect: false},
		{ID: "missing-profiles", Value: cloneFixture(fixture, func(m map[string]any) { delete(m, "FirewallProfiles") }), Expect: false},
		{ID: "bad-asr-action", Value: cloneFixture(fixture, func(m map[string]any) { m["AsrActions"] = []any{3} }), Expect: false},
		{ID: "bad-asr-guid", Value: cloneFixture(fixture, func(m map[string]any) { m["AsrIds"] = []any{"not-a-guid"} }), Expect: false},
		{ID: "asr-count-mismatch", Value: cloneFixture(fixture, func(m map[string]any) { m["AsrActions"] = []any{} }), Expect: false},
		{ID: "missing-asr", Value: cloneFixture(fixture, func(m map[string]any) { delete(m, "AsrIds"); delete(m, "AsrActions") }), Expect: false},
		{ID: "legacy-formatless", Value: map[string]any{
			"TimestampUtc": "2026-01-01T00:00:00.0000000Z",
			"FirewallProfiles": []any{
				map[string]any{"Name": "Domain", "DefaultOutboundAction": "Allow"},
				map[string]any{"Name": "Private", "DefaultOutboundAction": "Block"},
				map[string]any{"Name": "Public", "DefaultOutboundAction": "Block"},
			},
			"AsrIds": []any{}, "AsrActions": []any{},
		}, Expect: true},
	}
	harnessCases := make([]mhxBaselineCase, 0, len(cases))
	for _, item := range cases {
		harnessCases = append(harnessCases, mhxBaselineCase{ID: item.ID, Function: "Test-VgtMhxBaselineState", JsonState: fixtureJSON(t, item.Value)})
	}
	results := runMhxBaselineHarness(t, harnessCases)
	for _, item := range cases {
		var value bool
		if err := json.Unmarshal([]byte(results[item.ID].Value), &value); err != nil {
			t.Fatalf("%s: cannot decode %q: %v", item.ID, results[item.ID].Value, err)
		}
		if value != item.Expect {
			t.Fatalf("%s: validation = %v, want %v", item.ID, value, item.Expect)
		}
	}
}

func TestMhxBaselineIntegrityBinding(t *testing.T) {
	fixture := mhxBaselineFixture()
	rawFixture := fixtureJSON(t, fixture)
	hashResults := runMhxBaselineHarness(t, []mhxBaselineCase{
		{ID: "hash", Function: "Get-VgtMhxBaselineIntegrityHash", JsonState: rawFixture},
	})
	var baselineHash string
	if err := json.Unmarshal([]byte(hashResults["hash"].Value), &baselineHash); err != nil {
		t.Fatalf("cannot decode hash: %v", err)
	}
	if len(baselineHash) != 64 {
		t.Fatalf("unexpected integrity hash %q", baselineHash)
	}
	withIntegrity := cloneFixture(fixture, func(m map[string]any) {
		m["Integrity"] = map[string]any{"Algorithm": "SHA256", "BaselineSha256": baselineHash}
	})
	tampered := cloneFixture(withIntegrity, func(m map[string]any) { m["AsrActions"] = []any{0} })
	badAlgorithm := cloneFixture(withIntegrity, func(m map[string]any) {
		m["Integrity"] = map[string]any{"Algorithm": "MD5", "BaselineSha256": baselineHash}
	})
	results := runMhxBaselineHarness(t, []mhxBaselineCase{
		{ID: "valid", Function: "Test-VgtMhxBaselineIntegrity", JsonState: fixtureJSON(t, withIntegrity)},
		{ID: "tampered", Function: "Test-VgtMhxBaselineIntegrity", JsonState: fixtureJSON(t, tampered)},
		{ID: "bad-algorithm", Function: "Test-VgtMhxBaselineIntegrity", JsonState: fixtureJSON(t, badAlgorithm)},
		{ID: "legacy", Function: "Test-VgtMhxBaselineIntegrity", JsonState: rawFixture},
	})
	expect := func(id, want string) {
		t.Helper()
		var value string
		if err := json.Unmarshal([]byte(results[id].Value), &value); err != nil {
			t.Fatalf("%s: cannot decode %q: %v", id, results[id].Value, err)
		}
		if value != want {
			t.Fatalf("%s: %q, want %q", id, value, want)
		}
	}
	expect("valid", "Valid")
	expect("tampered", "Mismatch")
	expect("bad-algorithm", "Mismatch")
	expect("legacy", "Legacy")
}

func TestMhxProtectionScriptUsesBaselineValidation(t *testing.T) {
	raw, err := os.ReadFile(mhxProtectionScriptPath)
	if err != nil {
		t.Fatalf("cannot read script: %v", err)
	}
	source := string(raw)
	for _, required := range []string{
		"Test-VgtMhxBaselineState",
		"Test-VgtMhxBaselineIntegrity",
		"refusing to relax outbound defaults",
		"restore verification failed",
		"BaselineSha256",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("MHX protection script lost required baseline-validation marker %q", required)
		}
	}
	if count := strings.Count(source, "Test-VgtMhxBaselineState"); count < 3 {
		t.Fatalf("baseline validation must guard Save, network restore and ASR restore (found %d call sites)", count)
	}
	if strings.Contains(source, "DefaultOutboundAction Allow`r`n        return") {
		t.Fatal("legacy fail-open network restore path must not be reintroduced")
	}
}
