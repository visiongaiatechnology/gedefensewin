// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"encoding/base64"
	"os"
	"os/exec"
	"testing"
	"time"
	"unicode/utf16"
)

func TestInstalledEngineBlocksUnresolvedEncodedCommand(t *testing.T) {
	if os.Getenv("VGT_MHX_RUNTIME_INTEGRATION") != "1" {
		t.Skip("set VGT_MHX_RUNTIME_INTEGRATION=1 for installed-engine enforcement validation")
	}
	payload := "Start-Sleep -Seconds 20"
	encoded := encodeUTF16LE(payload)
	powerShellPath, err := windowsPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(powerShellPath, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unresolved encoded command completed instead of being blocked")
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("installed MHX engine did not terminate unresolved encoded command within 10 seconds")
	}
}

func encodeUTF16LE(value string) string {
	units := utf16.Encode([]rune(value))
	bytes := make([]byte, len(units)*2)
	for index, unit := range units {
		bytes[index*2] = byte(unit)
		bytes[index*2+1] = byte(unit >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
