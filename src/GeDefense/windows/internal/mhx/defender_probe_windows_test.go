// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestDefenderTelemetryPowerShellSyntax verifies the fixed read-only probe
// script parses in the installed Windows PowerShell without executing any
// Defender query.
func TestDefenderTelemetryPowerShellSyntax(t *testing.T) {
	assertPowerShellSyntax(t, defenderTelemetryScript)
}

// assertPowerShellSyntax parses source with the installed Windows PowerShell
// parser only (no execution). The process/Defender event-log sensors no longer
// run PowerShell bridges, so this helper localizes the syntax guard to the one
// remaining fixed read-only diagnostic script.
func assertPowerShellSyntax(t *testing.T, source string) {
	t.Helper()
	powerShell, err := windowsPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	parser := `$source=[Console]::In.ReadToEnd();$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors);if($errors.Count){$errors|ForEach-Object{[Console]::Error.WriteLine($_.Message)};exit 1}`
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser)
	command.Stdin = strings.NewReader(source)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("PowerShell script parse failed: %v: %s", err, stderr.String())
	}
}

// TestDefenderTelemetryScriptContainsOnlyReadOnlyCmdlets guards against an
// accidental write/Destruction verb in the telemetry probe.
func TestDefenderTelemetryScriptContainsOnlyReadOnlyCmdlets(t *testing.T) {
	lowered := strings.ToLower(defenderTelemetryScript)
	for _, forbidden := range []string{"set-mppreference", "remove-mppreference", "add-mppreference", "start-mpscan", "update-mpsignature", "set-netfirewall", "remove-netfirewall", "new-netfirewallrule", "set-content", "out-file", "invoke-expression", "invoke-webrequest", "start-process", "remove-item", "set-itemproperty"} {
		if strings.Contains(lowered, forbidden) {
			t.Fatalf("defender telemetry probe contains a non-read-only command: %s", forbidden)
		}
	}
	for _, required := range []string{"get-mpcomputerstatus", "get-mppreference", "convertto-json"} {
		if !strings.Contains(lowered, required) {
			t.Fatalf("defender telemetry probe is missing required read-only command: %s", required)
		}
	}
	// The probe must not interpolate external input into the script.
	if strings.Contains(lowered, "$args") || strings.Contains(lowered, "$env:") {
		t.Fatal("defender telemetry probe interpolates external input")
	}
}

func TestBoundedBufferTruncatesAndFlagsOverflow(t *testing.T) {
	buffer := &boundedBuffer{limit: 8}
	if written, err := buffer.Write([]byte("abcdefgh")); err != nil || written != 8 {
		t.Fatalf("in-bound write failed: %d %v", written, err)
	}
	if buffer.overflow || !bytes.Equal(buffer.buffer.Bytes(), []byte("abcdefgh")) {
		t.Fatalf("in-bound write corrupted: %q %v", buffer.buffer.Bytes(), buffer.overflow)
	}
	if written, err := buffer.Write([]byte("ijkl")); err != nil || written != 4 {
		t.Fatalf("overflowing write did not report full consumption: %d %v", written, err)
	}
	if !buffer.overflow || buffer.buffer.Len() != 8 {
		t.Fatalf("overflow was not bounded: len=%d overflow=%v", buffer.buffer.Len(), buffer.overflow)
	}
}
