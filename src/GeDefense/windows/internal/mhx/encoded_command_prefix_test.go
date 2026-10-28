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

// Cross-layer consistency (VGT-094): every layer that recognizes an encoded
// command switch must normalize the same accepted alias set as the Go decoder;
// the native Security 4688 sensor calls this decoder directly, so a missed alias
// would drop an encoded payload from the process telemetry triage.
func TestEncodedCommandAliasLayerConsistency(t *testing.T) {
	for _, alias := range []string{"-e", "-en", "-ec", "-encodedc", "-encodedco", "-encodedcommand", "/ec"} {
		if !isEncodedCommandSwitch(alias) {
			t.Fatalf("decoder does not normalize %q", alias)
		}
	}
	payload := encodedUTF16LE("Get-Date")
	for _, alias := range []string{"-e", "-en", "-ec", "-encodedc", "-encodedco", "-encodedcommand", "/ec"} {
		_, _, encoded, err := DecodePowerShellCommand("powershell.exe " + alias + " " + payload)
		if err != nil || !encoded {
			t.Fatalf("decoder did not classify alias %q as encoded (%v)", alias, err)
		}
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
