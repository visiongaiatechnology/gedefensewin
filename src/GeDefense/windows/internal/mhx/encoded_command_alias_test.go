// STATUS: DIAMANT VGT SUPREME
package mhx

import "testing"

func TestPowerShellEncodedCommandAliasesAreNormalized(t *testing.T) {
	payload := `Get-Date`
	for _, alias := range []string{"-e", "-en", "-ec", "-EC", "/e", "/en", "/ec"} {
		event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe " + alias + " " + encodedUTF16LE(payload)}
		result := (Evaluator{}).Analyze(event)
		if result.Classification != "UNRESOLVED ENCODED COMMAND" && result.Classification != "SUSPICIOUS" {
			t.Fatalf("alias %q was not normalized: %+v", alias, result)
		}
	}
}

func TestExecutionPolicyBypassWithoutEncodedCommandRemainsReviewOnly(t *testing.T) {
	event := ProcessEvent{Image: "powershell.exe", CommandLine: `powershell.exe -ExecutionPolicy Bypass -Command Get-Date`}
	result := (Evaluator{}).Analyze(event)
	if result.Classification == "UNRESOLVED ENCODED COMMAND" || result.Classification == "MALFORMED ENCODED COMMAND" {
		t.Fatalf("execution-policy flag was confused with encoded command: %+v", result)
	}
}
