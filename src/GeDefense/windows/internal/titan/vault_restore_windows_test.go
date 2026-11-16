// STATUS: PLATIN VGT SUPREME
//go:build windows

package titan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FIND-WIN-021: the Mark-of-the-Web alternate data stream is captured at
// quarantine time and restored with the file.
func TestVaultRestorePreservesZoneIdentifierADS(t *testing.T) {
	vault, err := OpenVault(filepath.Join(t.TempDir(), "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "downloaded.exe")
	if err := os.WriteFile(source, []byte("downloaded payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	zone := "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/download.exe\r\nReferrerUrl=https://example.invalid/\r\n"
	if err := os.WriteFile(source+zoneIdentifierStream, []byte(zone), 0o600); err != nil {
		t.Skipf("ADS creation is unavailable in this environment: %v", err)
	}
	entry, err := vault.Add(source, "Quarantäne im Mark-of-the-Web-Restore-Test", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("quarantine did not remove the source: %v", err)
	}
	restored, err := vault.Restore(entry.ID, "Besitzer stellt heruntergeladenes Objekt wieder her")
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if restored.State != "RESTORED" {
		t.Fatalf("restore state=%q, want RESTORED (MOTW present and restored)", restored.State)
	}
	raw, err := os.ReadFile(entry.OriginalPath + zoneIdentifierStream)
	if err != nil {
		t.Fatalf("Mark-of-the-Web ADS was not restored: %v", err)
	}
	restoredZone := string(raw)
	if !strings.Contains(restoredZone, "ZoneId=3") {
		t.Fatalf("restored Zone.Identifier has no Internet zone: %q", restoredZone)
	}
	if !strings.Contains(restoredZone, "HostUrl=https://example.invalid/download.exe") {
		t.Fatalf("restored Zone.Identifier lost the stored HostUrl: %q", restoredZone)
	}
	if !strings.Contains(restoredZone, "ReferrerUrl=https://example.invalid/") {
		t.Fatalf("restored Zone.Identifier lost the stored ReferrerUrl: %q", restoredZone)
	}
}
