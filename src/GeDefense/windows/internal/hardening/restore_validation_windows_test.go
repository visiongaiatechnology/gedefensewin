// STATUS: DIAMANT VGT SUPREME
//go:build windows

package hardening

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// Vgt.Common.psm1 is the privileged restore/rollback module (HP-FIND-006). The
// regression harness parses the module, evaluates only the validation helper
// function definitions from their AST extents and never executes the
// mutating Save/Restore bodies.
const commonModulePath = `../../../../../engine/Modules/Vgt.Common.psm1`

const baselineHelperHarness = `$ErrorActionPreference='Stop'
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
  try {
    $parameters = @{}
    if ($null -ne $case.Named) {
      foreach ($property in $case.Named.PSObject.Properties) { $parameters[$property.Name] = $property.Value }
    }
    if ($null -ne $case.JsonState) { $parameters['State'] = ([string]$case.JsonState | ConvertFrom-Json) }
    $value = & ([string]$case.Function) @parameters
    $serialized = if ($null -eq $value) { 'null' } else { $value | ConvertTo-Json -Compress -Depth 8 }
    [ordered]@{ id=$id; ok=$true; value=$serialized } | ConvertTo-Json -Compress
  } catch {
    [ordered]@{ id=$id; ok=$false; error=[string]$_.Exception.Message } | ConvertTo-Json -Compress
  }
}
`

var baselineHelperFunctions = []string{
	"Get-VgtBaselineRegistryAllowlist",
	"Test-VgtBaselineRegistryEntry",
	"Test-VgtBaselineFirewallProfile",
	"Get-VgtBaselinePropertyValues",
	"Test-VgtBaselineDefenderPreference",
	"Test-VgtBaselineAuditPolicyPath",
	"Get-VgtBaselineIntegrityMaterial",
	"Get-VgtBaselineIntegrityHash",
	"Test-VgtBaselineIntegrity",
	"Test-VgtBaselineState",
}

type baselineHelperCase struct {
	ID        string         `json:"Id"`
	Function  string         `json:"Function"`
	Named     map[string]any `json:"Named,omitempty"`
	JsonState string         `json:"JsonState,omitempty"`
}

type baselineHelperResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Value string `json:"value"`
	Error string `json:"error"`
}

func runBaselineHelperHarness(t *testing.T, cases []baselineHelperCase) map[string]baselineHelperResult {
	t.Helper()
	raw, err := os.ReadFile(commonModulePath)
	if err != nil {
		t.Fatalf("cannot read %q: %v", commonModulePath, err)
	}
	if len(raw) == 0 || len(raw) > 512<<10 {
		t.Fatalf("module size rejected: %d", len(raw))
	}
	if cases == nil {
		cases = []baselineHelperCase{}
	}
	payload, err := json.Marshal(map[string]any{
		"SourceBase64": base64.StdEncoding.EncodeToString(raw),
		"Functions":    baselineHelperFunctions,
		"Cases":        cases,
	})
	if err != nil {
		t.Fatalf("payload encoding failed: %v", err)
	}
	powerShell, err := winexec.PowerShell()
	if err != nil {
		t.Fatalf("Windows PowerShell unavailable: %v", err)
	}
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", baselineHelperHarness)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("baseline helper harness failed: %v: %s", err, stderr.String())
	}
	results := make(map[string]baselineHelperResult, len(cases))
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var result baselineHelperResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("harness output rejected: %v: %q", err, line)
		}
		if !result.OK {
			t.Fatalf("helper case %s failed: %s", result.ID, result.Error)
		}
		results[result.ID] = result
	}
	if len(results) != len(cases) {
		t.Fatalf("harness returned %d results for %d cases", len(results), len(cases))
	}
	return results
}

func readBaselineValue(t *testing.T, results map[string]baselineHelperResult, id string, target any) {
	t.Helper()
	if err := json.Unmarshal([]byte(results[id].Value), target); err != nil {
		t.Fatalf("%s: cannot decode %q: %v", id, results[id].Value, err)
	}
}

func baselineTempAuditPolicy(t *testing.T) (stateDirectory, auditPolicy string) {
	t.Helper()
	stateDirectory = filepath.Join(t.TempDir(), "State")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	auditPolicy = filepath.Join(stateDirectory, "audit-policy.csv")
	if err := os.WriteFile(auditPolicy, []byte("Machine Name,Policy Target,Subcategory,Subcategory GUID\r\n"), 0o600); err != nil {
		t.Fatalf("write audit policy: %v", err)
	}
	return stateDirectory, auditPolicy
}

func baselineStateFixture(t *testing.T, stateDirectory, auditPolicy string) map[string]any {
	t.Helper()
	profiles := []any{}
	for _, name := range []string{"Domain", "Private", "Public"} {
		profiles = append(profiles, map[string]any{
			"Name": name, "Enabled": true,
			"DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow",
			"NotifyOnListen": true, "AllowUnicastResponseToMulticast": false,
			"LogBlocked": false, "LogAllowed": false, "LogMaxSizeKilobytes": 4096,
		})
	}
	return map[string]any{
		"format":     2,
		"createdUtc": "2026-01-01T00:00:00.0000000Z",
		"registry": []any{
			map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL", "existed": true, "value": 1},
			map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR`, "name": "Start", "existed": false, "value": nil},
		},
		"firewall": profiles,
		"defender": map[string]any{
			"PUAProtection": 1, "MAPSReporting": 2, "SubmitSamplesConsent": 1,
			"EnableNetworkProtection": 1, "CloudBlockLevel": 0, "EnableControlledFolderAccess": 0,
			"AttackSurfaceReductionRules_Ids":     []any{"5beb7efe-fd9a-4556-801d-275e5ffc04cc"},
			"AttackSurfaceReductionRules_Actions": []any{1},
		},
		"smb1State":   "Disabled",
		"auditPolicy": auditPolicy,
	}
}

func TestVgtBaselineRegistryEntryValidation(t *testing.T) {
	cases := []struct {
		ID     string
		Entry  map[string]any
		Expect bool
	}{
		{ID: "valid-existing", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL", "existed": true, "value": 1}, Expect: true},
		{ID: "valid-absent", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPLBoot", "existed": false, "value": nil}, Expect: true},
		{ID: "unknown-path", Entry: map[string]any{"path": `HKLM:\SOFTWARE\Attacker`, "name": "RunAsPPL", "existed": true, "value": 1}, Expect: false},
		{ID: "unknown-name", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "AttackerValue", "existed": true, "value": 1}, Expect: false},
		{ID: "string-existed", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL", "existed": "true", "value": 1}, Expect: false},
		{ID: "missing-value", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL", "existed": true}, Expect: false},
		{ID: "negative-value", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL", "existed": true, "value": -5}, Expect: false},
		{ID: "overflow-value", Entry: map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPL", "existed": true, "value": 4294967296}, Expect: false},
	}
	harnessCases := make([]baselineHelperCase, 0, len(cases))
	for _, item := range cases {
		raw, err := json.Marshal(item.Entry)
		if err != nil {
			t.Fatal(err)
		}
		harnessCases = append(harnessCases, baselineHelperCase{ID: item.ID, Function: "Test-VgtBaselineRegistryEntry", Named: map[string]any{"Entry": json.RawMessage(raw)}})
	}
	results := runBaselineHelperHarness(t, harnessCases)
	for _, item := range cases {
		var value bool
		readBaselineValue(t, results, item.ID, &value)
		if value != item.Expect {
			t.Fatalf("%s: validation = %v, want %v", item.ID, value, item.Expect)
		}
	}
}

func TestVgtBaselineFirewallProfileValidation(t *testing.T) {
	valid := map[string]any{
		"Name": "Domain", "Enabled": true,
		"DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow",
		"NotifyOnListen": true, "AllowUnicastResponseToMulticast": false,
		"LogBlocked": false, "LogAllowed": false, "LogMaxSizeKilobytes": 4096,
	}
	mutate := func(mutator func(map[string]any)) map[string]any {
		copy := map[string]any{}
		for key, value := range valid {
			copy[key] = value
		}
		mutator(copy)
		return copy
	}
	cases := []struct {
		ID     string
		Value  map[string]any
		Expect bool
	}{
		{ID: "valid", Value: valid, Expect: true},
		{ID: "bad-name", Value: mutate(func(m map[string]any) { m["Name"] = "Fake" }), Expect: false},
		{ID: "bad-inbound", Value: mutate(func(m map[string]any) { m["DefaultInboundAction"] = "Permit" }), Expect: false},
		{ID: "bad-outbound", Value: mutate(func(m map[string]any) { m["DefaultOutboundAction"] = "AllowAll" }), Expect: false},
		{ID: "string-enabled", Value: mutate(func(m map[string]any) { m["Enabled"] = "true" }), Expect: false},
		{ID: "zero-log-size", Value: mutate(func(m map[string]any) { m["LogMaxSizeKilobytes"] = 0 }), Expect: false},
		{ID: "huge-log-size", Value: mutate(func(m map[string]any) { m["LogMaxSizeKilobytes"] = 40000 }), Expect: false},
		{ID: "missing-log-size", Value: mutate(func(m map[string]any) { delete(m, "LogMaxSizeKilobytes") }), Expect: false},
	}
	harnessCases := make([]baselineHelperCase, 0, len(cases))
	for _, item := range cases {
		raw, err := json.Marshal(item.Value)
		if err != nil {
			t.Fatal(err)
		}
		harnessCases = append(harnessCases, baselineHelperCase{ID: item.ID, Function: "Test-VgtBaselineFirewallProfile", Named: map[string]any{"Profile": json.RawMessage(raw)}})
	}
	results := runBaselineHelperHarness(t, harnessCases)
	for _, item := range cases {
		var value bool
		readBaselineValue(t, results, item.ID, &value)
		if value != item.Expect {
			t.Fatalf("%s: validation = %v, want %v", item.ID, value, item.Expect)
		}
	}
}

func TestVgtBaselineDefenderPreferenceValidation(t *testing.T) {
	valid := map[string]any{
		"PUAProtection": 1, "MAPSReporting": 2, "SubmitSamplesConsent": 1,
		"EnableNetworkProtection": 1, "CloudBlockLevel": 0, "EnableControlledFolderAccess": 0,
		"AttackSurfaceReductionRules_Ids":     []any{"5beb7efe-fd9a-4556-801d-275e5ffc04cc"},
		"AttackSurfaceReductionRules_Actions": []any{1},
	}
	mutate := func(mutator func(map[string]any)) map[string]any {
		copy := map[string]any{}
		for key, value := range valid {
			copy[key] = value
		}
		mutator(copy)
		return copy
	}
	withoutRules := map[string]any{}
	for key, value := range valid {
		withoutRules[key] = value
	}
	withoutRules["AttackSurfaceReductionRules_Ids"] = nil
	withoutRules["AttackSurfaceReductionRules_Actions"] = nil
	cases := []struct {
		ID     string
		Value  map[string]any
		Expect bool
	}{
		{ID: "valid", Value: valid, Expect: true},
		{ID: "valid-no-rules", Value: withoutRules, Expect: true},
		{ID: "bad-pua", Value: mutate(func(m map[string]any) { m["PUAProtection"] = 7 }), Expect: false},
		{ID: "bad-cloud", Value: mutate(func(m map[string]any) { m["CloudBlockLevel"] = 3 }), Expect: false},
		{ID: "bad-consent", Value: mutate(func(m map[string]any) { m["SubmitSamplesConsent"] = 9 }), Expect: false},
		{ID: "bad-asr-action", Value: mutate(func(m map[string]any) { m["AttackSurfaceReductionRules_Actions"] = []any{3} }), Expect: false},
		{ID: "bad-asr-id", Value: mutate(func(m map[string]any) { m["AttackSurfaceReductionRules_Ids"] = []any{"not-a-guid"} }), Expect: false},
		{ID: "asr-count-mismatch", Value: mutate(func(m map[string]any) { m["AttackSurfaceReductionRules_Actions"] = []any{} }), Expect: false},
		{ID: "asr-duplicate", Value: mutate(func(m map[string]any) {
			m["AttackSurfaceReductionRules_Ids"] = []any{"5beb7efe-fd9a-4556-801d-275e5ffc04cc", "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"}
			m["AttackSurfaceReductionRules_Actions"] = []any{1, 2}
		}), Expect: false},
	}
	harnessCases := make([]baselineHelperCase, 0, len(cases))
	for _, item := range cases {
		raw, err := json.Marshal(item.Value)
		if err != nil {
			t.Fatal(err)
		}
		harnessCases = append(harnessCases, baselineHelperCase{ID: item.ID, Function: "Test-VgtBaselineDefenderPreference", Named: map[string]any{"Defender": json.RawMessage(raw)}})
	}
	results := runBaselineHelperHarness(t, harnessCases)
	for _, item := range cases {
		var value bool
		readBaselineValue(t, results, item.ID, &value)
		if value != item.Expect {
			t.Fatalf("%s: validation = %v, want %v", item.ID, value, item.Expect)
		}
	}
}

// HP-FIND-006: the audit policy path from the baseline must stay inside the
// protected state directory and must not resolve through a reparse point.
func TestVgtBaselineAuditPolicyPathValidation(t *testing.T) {
	stateDirectory, auditPolicy := baselineTempAuditPolicy(t)
	outside := filepath.Join(t.TempDir(), "audit-policy.csv")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	traversal := filepath.Join(stateDirectory, "..", "audit-policy.csv")
	cases := []struct {
		ID        string
		Path      string
		Directory string
		Expect    bool
	}{
		{ID: "valid", Path: auditPolicy, Directory: stateDirectory, Expect: true},
		{ID: "outside", Path: outside, Directory: stateDirectory, Expect: false},
		{ID: "traversal", Path: traversal, Directory: stateDirectory, Expect: false},
		{ID: "wrong-name", Path: filepath.Join(stateDirectory, "other.csv"), Directory: stateDirectory, Expect: false},
		{ID: "missing-file", Path: filepath.Join(stateDirectory, "audit-policy.csv.missing"), Directory: stateDirectory, Expect: false},
		{ID: "empty-path", Path: "", Directory: stateDirectory, Expect: false},
	}
	harnessCases := make([]baselineHelperCase, 0, len(cases))
	for _, item := range cases {
		harnessCases = append(harnessCases, baselineHelperCase{ID: item.ID, Function: "Test-VgtBaselineAuditPolicyPath", Named: map[string]any{"Path": item.Path, "StateDirectory": item.Directory}})
	}
	results := runBaselineHelperHarness(t, harnessCases)
	for _, item := range cases {
		var value bool
		readBaselineValue(t, results, item.ID, &value)
		if value != item.Expect {
			t.Fatalf("%s: validation = %v, want %v", item.ID, value, item.Expect)
		}
	}
}

func TestVgtBaselineStateValidationAndIntegrity(t *testing.T) {
	stateDirectory, auditPolicy := baselineTempAuditPolicy(t)
	fixture := baselineStateFixture(t, stateDirectory, auditPolicy)
	rawFixture, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}

	// First run: structural validation of the fixture and its SHA-256.
	hashResult := runBaselineHelperHarness(t, []baselineHelperCase{
		{ID: "state", Function: "Test-VgtBaselineState", JsonState: string(rawFixture), Named: map[string]any{"StateDirectory": stateDirectory}},
		{ID: "hash", Function: "Get-VgtBaselineIntegrityHash", JsonState: string(rawFixture)},
	})
	var stateValid bool
	readBaselineValue(t, hashResult, "state", &stateValid)
	if !stateValid {
		t.Fatal("valid baseline fixture was rejected")
	}
	var baselineHash string
	readBaselineValue(t, hashResult, "hash", &baselineHash)
	if len(baselineHash) != 64 {
		t.Fatalf("unexpected baseline hash %q", baselineHash)
	}

	withIntegrity := map[string]any{}
	for key, value := range fixture {
		withIntegrity[key] = value
	}
	withIntegrity["integrity"] = map[string]any{"algorithm": "SHA256", "baselineSha256": baselineHash}
	rawWithIntegrity, err := json.Marshal(withIntegrity)
	if err != nil {
		t.Fatal(err)
	}

	tampered := map[string]any{}
	for key, value := range withIntegrity {
		tampered[key] = value
	}
	tampered["smb1State"] = "Enabled"
	rawTampered, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}

	registryTampered := map[string]any{}
	for key, value := range withIntegrity {
		registryTampered[key] = value
	}
	registryTampered["registry"] = []any{
		map[string]any{"path": `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`, "name": "RunAsPPLBoot", "existed": true, "value": 0},
	}
	rawRegistryTampered, err := json.Marshal(registryTampered)
	if err != nil {
		t.Fatal(err)
	}

	// Structural mutations that must fail even with a valid integrity hash
	// recomputed (integrity is corruption detection, not authenticity).
	badRegistry := map[string]any{}
	for key, value := range fixture {
		badRegistry[key] = value
	}
	badRegistry["registry"] = append([]any{}, fixture["registry"].([]any)...)
	badRegistry["registry"] = append(badRegistry["registry"].([]any), map[string]any{"path": `HKLM:\SOFTWARE\Attacker`, "name": "Pwn", "existed": true, "value": 1})
	rawBadRegistry, err := json.Marshal(badRegistry)
	if err != nil {
		t.Fatal(err)
	}
	badFirewall := map[string]any{}
	for key, value := range fixture {
		badFirewall[key] = value
	}
	badFirewall["firewall"] = fixture["firewall"].([]any)[:2]
	rawBadFirewall, err := json.Marshal(badFirewall)
	if err != nil {
		t.Fatal(err)
	}
	badAuditPolicy := map[string]any{}
	for key, value := range fixture {
		badAuditPolicy[key] = value
	}
	badAuditPolicy["auditPolicy"] = filepath.Join(t.TempDir(), "audit-policy.csv")
	rawBadAuditPolicy, err := json.Marshal(badAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}

	results := runBaselineHelperHarness(t, []baselineHelperCase{
		{ID: "valid-with-integrity", Function: "Test-VgtBaselineIntegrity", JsonState: string(rawWithIntegrity)},
		{ID: "tampered", Function: "Test-VgtBaselineIntegrity", JsonState: string(rawTampered)},
		{ID: "registry-tampered", Function: "Test-VgtBaselineIntegrity", JsonState: string(rawRegistryTampered)},
		{ID: "legacy", Function: "Test-VgtBaselineIntegrity", JsonState: string(rawFixture)},
		{ID: "bad-registry", Function: "Test-VgtBaselineState", JsonState: string(rawBadRegistry), Named: map[string]any{"StateDirectory": stateDirectory}},
		{ID: "bad-firewall", Function: "Test-VgtBaselineState", JsonState: string(rawBadFirewall), Named: map[string]any{"StateDirectory": stateDirectory}},
		{ID: "bad-audit-policy", Function: "Test-VgtBaselineState", JsonState: string(rawBadAuditPolicy), Named: map[string]any{"StateDirectory": stateDirectory}},
	})
	expectString := func(id, want string) {
		t.Helper()
		var value string
		readBaselineValue(t, results, id, &value)
		if value != want {
			t.Fatalf("%s: %q, want %q", id, value, want)
		}
	}
	expectString("valid-with-integrity", "Valid")
	expectString("tampered", "Mismatch")
	expectString("registry-tampered", "Mismatch")
	expectString("legacy", "Legacy")
	for _, id := range []string{"bad-registry", "bad-firewall", "bad-audit-policy"} {
		var value bool
		readBaselineValue(t, results, id, &value)
		if value {
			t.Fatalf("%s: tampered baseline structure was accepted", id)
		}
	}
}

func TestCommonModuleRestoreUsesValidation(t *testing.T) {
	raw, err := os.ReadFile(commonModulePath)
	if err != nil {
		t.Fatalf("cannot read module: %v", err)
	}
	source := string(raw)
	for _, required := range []string{
		"Test-VgtBaselineState",
		"Test-VgtBaselineIntegrity",
		"Test-VgtBaselineRestoredState",
		"Baseline restored and verified.",
		"baseline integrity verification failed",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("restore/rollback module lost required validation marker %q", required)
		}
	}
	if strings.Count(source, "function Restore-VgtBaseline") != 1 {
		t.Fatal("Restore-VgtBaseline must exist exactly once")
	}
}
