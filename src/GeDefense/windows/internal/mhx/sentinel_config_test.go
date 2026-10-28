// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsAppAllowedSystemAppRequiresExactPath(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	allowed, _, isSystem := store.IsAppAllowed(`C:\Windows\System32\svchost.exe`)
	if !allowed || !isSystem {
		t.Fatalf("canonical svchost.exe must be an allowed system app, got allowed=%v system=%v", allowed, isSystem)
	}

	// Masquerading: a foreign binary with the same basename must NOT inherit
	// the system-app authorization.
	allowed, _, isSystem = store.IsAppAllowed(`C:\Users\Public\svchost.exe`)
	if allowed || isSystem {
		t.Fatalf("foreign svchost.exe must not be authorized as system app, got allowed=%v system=%v", allowed, isSystem)
	}
}

func TestIsAppAllowedFullPathPatternHasNoBasenameFallback(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entry, err := store.AddWhitelistApp("Test App", `C:\Program Files\VGT\test-app.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID == "" {
		t.Fatal("expected generated whitelist id")
	}

	if allowed, _, _ := store.IsAppAllowed(`C:\Program Files\VGT\test-app.exe`); !allowed {
		t.Fatal("exact whitelist path must be allowed")
	}
	if allowed, _, _ := store.IsAppAllowed(`C:\Users\Public\test-app.exe`); allowed {
		t.Fatal("full-path whitelist entry must not authorize the same basename elsewhere")
	}
}

func TestAddWhitelistAppRejectsUnsafePatterns(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"", "*", `\*`, `C:\Tools\`, `..\evil.exe`, `C:\a?b.exe`, "a\x00b.exe"} {
		if _, err := store.AddWhitelistApp("Unsafe", pattern); err == nil {
			t.Fatalf("pattern %q must be rejected", pattern)
		}
	}
	if _, err := store.AddWhitelistApp(strings.Repeat("x", maxSentinelNameBytes+1), `C:\Tools\app.exe`); err == nil {
		t.Fatal("oversized whitelist name must be rejected")
	}
}

func TestToggleSignatureRejectsUnknownID(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ToggleSignature("KD-SIG-99", false); err == nil {
		t.Fatal("unknown signature id must be rejected")
	}
	if err := store.ToggleSignature("KD-SIG-01", false); err != nil {
		t.Fatalf("known signature id must be toggled: %v", err)
	}
	if store.Config().ActiveSignatures["KD-SIG-01"] {
		t.Fatal("signature toggle did not persist")
	}
}

func TestOpenSentinelStorePreservesCorruptConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, sentinelConfigFileName)
	const corrupt = `{"activeSignatures":`
	if err := os.WriteFile(path, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSentinelStore(root)
	if err != nil {
		t.Fatalf("store must still open with safe defaults: %v", err)
	}
	if !store.Config().KillerdomEnabled {
		t.Fatal("defaults must keep Killerdom enabled after corrupt config recovery")
	}
	backups, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("corrupt config must be preserved as forensic backup, got %v (err=%v)", backups, err)
	}
	raw, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != corrupt {
		t.Fatalf("backup content mismatch: %q", string(raw))
	}
}

func TestGeDefenseExemptionRequiresInstalledPath(t *testing.T) {
	// A renamed payload outside the installed tree must NOT inherit the
	// sovereign exemption, regardless of its basename.
	if isGeDefenseBinary("gedefense-windows.exe", `C:\Users\Public\gedefense-windows.exe`) {
		t.Fatal("foreign binary named gedefense-windows.exe must not be exempt")
	}
	if isGeDefenseBinary("gedefense-windows.exe", "") {
		t.Fatal("empty path must never grant the sovereign exemption")
	}
	if !isGeDefenseBinary("gedefense-windows.exe", `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`) {
		t.Fatal("installed GeDefense binary must be exempt")
	}
}

func TestSystemWhitelistEntriesAreImmutable(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ToggleWhitelistApp("wl_gedefense_svc", false); err == nil {
		t.Fatal("self-protection whitelist entry must not be disableable")
	}
	if err := store.RemoveWhitelistApp("wl_gedefense_svc"); err == nil {
		t.Fatal("self-protection whitelist entry must not be removable")
	}
	if !store.Config().Whitelist["wl_gedefense_svc"].Enabled {
		t.Fatal("self-protection entry must remain enabled")
	}
}

func TestWhitelistCapacityIsBounded(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	added := 0
	for {
		_, err := store.AddWhitelistApp("App", `C:\Tools\app.exe`)
		if err != nil {
			break
		}
		added++
		if added > maxWhitelistEntries+2 {
			t.Fatalf("whitelist capacity not enforced (added %d)", added)
		}
	}
	if added == 0 || added > maxWhitelistEntries {
		t.Fatalf("expected capacity error at %d entries, added=%d", maxWhitelistEntries, added)
	}
}

func TestWhitelistSHA256PinIsFailClosed(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	goodPath := filepath.Join(root, "pinned-app.exe")
	goodContent := []byte("MZ pinned-owner-approved")
	if err := os.WriteFile(goodPath, goodContent, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(goodContent)
	pin := hex.EncodeToString(sum[:])
	if _, err := store.AddWhitelistAppPinned("Pinned App", `*pinned-app.exe`, pin, ""); err != nil {
		t.Fatalf("add pinned entry: %v", err)
	}
	allowed, _, _, reason := store.IsAppAllowedEvent(ProcessEvent{ImagePath: goodPath, Image: "pinned-app.exe"})
	if !allowed {
		t.Fatalf("hash-matching whitelist entry must be allowed, reason=%q", reason)
	}
	// Replace the binary at the same path: the path still matches, the pin must
	// fail closed.
	if err := os.WriteFile(goodPath, []byte("MZ attacker-replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed, _, _, reason = store.IsAppAllowedEvent(ProcessEvent{ImagePath: goodPath, Image: "pinned-app.exe"})
	if allowed || reason == "" {
		t.Fatalf("hash-mismatching image must be denied with reason, allowed=%v reason=%q", allowed, reason)
	}
}

func TestWhitelistSignerPinIsFailClosed(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddWhitelistAppPinned("Signed App", `*signed-app.exe`, "", "Microsoft"); err != nil {
		t.Fatalf("add signer-pinned entry: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signed-app.exe")
	if err := os.WriteFile(path, []byte("MZ signed"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed, _, _, reason := store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "signed-app.exe", SignerStatus: "Valid", ImageVersionCompany: "Microsoft Corporation",
	})
	if !allowed {
		t.Fatalf("matching signer must be allowed, reason=%q", reason)
	}
	allowed, _, _, reason = store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "signed-app.exe", SignerStatus: "Valid", ImageVersionCompany: "Evil Corp",
	})
	if allowed || reason == "" {
		t.Fatalf("foreign publisher must be denied with reason, allowed=%v reason=%q", allowed, reason)
	}
	allowed, _, _, reason = store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "signed-app.exe", SignerStatus: "NotSigned", ImageVersionCompany: "Microsoft Corporation",
	})
	if allowed || reason == "" {
		t.Fatalf("unsigned image must not satisfy a signer pin, allowed=%v reason=%q", allowed, reason)
	}
}
