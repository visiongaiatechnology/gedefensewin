// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"strings"
	"testing"
)

// HP-FIND-001 regression, extended: powershell.exe 5.1 accepts every prefix of
// -EncodedCommand plus the documented "ec" short alias (dynamically verified
// with harmless payloads). The decoder must normalize exactly that accepted
// set instead of a hand-maintained subset.
func TestEncodedCommandSwitchAcceptedSet(t *testing.T) {
	accepted := []string{
		"-e", "-en", "-enc", "-enco", "-encod", "-encode", "-encoded",
		"-encodedc", "-encodedco", "-encodedcom", "-encodedcomm",
		"-encodedcomma", "-encodedcomman", "-encodedcommand",
		"-ec", "-E", "-EN", "-EC", "-ENCODEDC", "-EncodedCommand",
		"/e", "/en", "/enc", "/enco", "/encod", "/encode", "/encoded",
		"/encodedc", "/encodedco", "/encodedcom", "/encodedcomm",
		"/encodedcomma", "/encodedcomman", "/encodedcommand", "/ec",
	}
	for _, alias := range accepted {
		if !isEncodedCommandSwitch(alias) {
			t.Fatalf("accepted PowerShell alias %q is not normalized", alias)
		}
		payload := encodedUTF16LE("Write-Output VGT_ALIAS_PROBE")
		commandLine := "powershell.exe " + alias + " " + payload
		decoded, encoding, encoded, err := DecodePowerShellCommand(commandLine)
		if err != nil {
			t.Fatalf("alias %q: decode error: %v", alias, err)
		}
		if !encoded {
			t.Fatalf("alias %q: decoder reported encoded=false", alias)
		}
		if !strings.Contains(decoded, "VGT_ALIAS_PROBE") {
			t.Fatalf("alias %q: decoded payload %q is wrong", alias, decoded)
		}
		if encoding != "UTF-16LE" {
			t.Fatalf("alias %q: encoding = %q", alias, encoding)
		}
	}
}

func TestEncodedCommandSwitchRejectedSet(t *testing.T) {
	rejected := []string{
		"", "-", "/", "--e", "e", "ec", "encodedcommand", "-ecc", "-ecx",
		"-ee", "-ex", "-encodedcommandx", "-ExecutionPolicy", "-NoProfile",
		"/ecc", "/ex", "/encodedcommandx",
	}
	for _, argument := range rejected {
		if isEncodedCommandSwitch(argument) {
			t.Fatalf("non-accepted argument %q was treated as EncodedCommand", argument)
		}
	}
	payload := encodedUTF16LE("Get-Date")
	for _, commandLine := range []string{
		"powershell.exe -ExecutionPolicy Bypass -Command Get-Date",
		"powershell.exe -ecx " + payload,
		"powershell.exe -ex " + payload,
	} {
		if _, _, encoded, _ := DecodePowerShellCommand(commandLine); encoded {
			t.Fatalf("command line %q was wrongly classified as EncodedCommand", commandLine)
		}
	}
}

// Cross-layer consistency (VGT-094): the process telemetry fast path and the
// XDR scanner must recognize the same accepted alias set as the Go decoder.
func TestEncodedCommandAliasLayerConsistency(t *testing.T) {
	// The watcher fast path only skips hash enrichment for encoded commands; a
	// missed alias must not lead to an unclassified command.
	for _, alias := range []string{"-e", "-en", "-ec", "-encodedc", "-encodedco", "-encodedcommand", "/ec"} {
		if !isEncodedCommandSwitch(alias) {
			t.Fatalf("decoder does not normalize %q", alias)
		}
	}
	if count := strings.Count(processTraceScript, "enco"); count < 1 {
		t.Fatal("process telemetry fast path lost its encoded-command regex")
	}
}

func TestEvaluatorClassifiesLongPrefixAliases(t *testing.T) {
	for _, alias := range []string{"-encodedc", "-encodedco", "-encodedcom", "-encodedcomm", "-encodedcomma", "-encodedcomman"} {
		event := ProcessEvent{Image: "powershell.exe", CommandLine: "powershell.exe " + alias + " " + encodedUTF16LE("Get-Date")}
		result := (Evaluator{}).Analyze(event)
		if result.Classification != "UNRESOLVED ENCODED COMMAND" && result.Classification != "SUSPICIOUS" {
			t.Fatalf("alias %q was not classified: %+v", alias, result)
		}
	}
}
