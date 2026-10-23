// STATUS: DIAMANT VGT SUPREME
//go:build vgt_bundle

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmbeddedPayloadExtractsCoreModules(t *testing.T) {
	raw, err := installerPayload()
	if err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := extractArchive(raw, destination); err != nil {
		t.Fatal(err)
	}
	for _, relativePath := range []string{
		"payload/installer/Install-GeDefense.ps1",
		"payload/installer/Uninstall-GeDefense.ps1",
		"payload/installer/Bootstrap-GeDefense.ps1",
		"payload/audit/Invoke-VgtSecurityAudit.ps1",
		"payload/xdr/Invoke-VgtXdrScan.ps1",
		"payload/bin/gedefense-windows.exe",
		"payload/bin/GeDefenseCenter.exe",
		"payload/vgt-payload.cat",
	} {
		path := filepath.Join(destination, filepath.FromSlash(relativePath))
		var info os.FileInfo
		var statErr error
		for attempt := 0; attempt < 20; attempt++ {
			info, statErr = os.Stat(path)
			if statErr == nil && info.Mode().IsRegular() {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("embedded module unavailable: %s (%v)", relativePath, statErr)
		}
	}
}
