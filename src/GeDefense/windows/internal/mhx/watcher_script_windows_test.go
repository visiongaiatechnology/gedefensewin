// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestProcessTracePowerShellSyntax(t *testing.T) {
	powerShell, err := windowsPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	parser := `$source=[Console]::In.ReadToEnd();$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors);if($errors.Count){$errors|ForEach-Object{[Console]::Error.WriteLine($_.Message)};exit 1}`
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser)
	command.Stdin = strings.NewReader(processTraceScript)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("process trace script parse failed: %v: %s", err, stderr.String())
	}
}
