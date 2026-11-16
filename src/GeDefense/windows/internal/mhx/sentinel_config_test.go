// STATUS: PLATIN VGT SUPREME
package mhx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if isGeDefenseBinary(`C:\Users\Public\gedefense-windows.exe`) {
		t.Fatal("foreign binary named gedefense-windows.exe must not be exempt")
	}
	if isGeDefenseBinary("") {
		t.Fatal("empty path must never grant the sovereign exemption")
	}
	if !isGeDefenseBinary(`C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`) {
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
	// A missing signer signal is fail-closed: it is not treated as a satisfied
	// pin even when the publisher string happens to match.
	allowed, _, _, reason = store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "signed-app.exe", SignerStatus: "", ImageVersionCompany: "Microsoft Corporation",
	})
	if allowed || reason == "" {
		t.Fatalf("missing signer state must not satisfy a signer pin, allowed=%v reason=%q", allowed, reason)
	}
}

// TestDefaultWildcardsCannotAuthorize is the FIND-WIN-009 regression: the
// shipped developer-tool entries used to authorize any binary named code.exe,
// go.exe, git.exe or ollama.exe, including a copy in a user-writable directory.
func TestDefaultWildcardsCannotAuthorize(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Config()
	for _, id := range []string{"wl_antigravity", "wl_codex", "wl_vscodium", "wl_code", "wl_go", "wl_git", "wl_ollama"} {
		entry, found := cfg.Whitelist[id]
		if !found {
			continue
		}
		if entry.Enabled {
			t.Fatalf("default wildcard entry %s is enabled", id)
		}
		if !strings.Contains(entry.DisabledReason, "FIND-WIN-009") {
			t.Fatalf("default wildcard entry %s has no migration reason: %q", id, entry.DisabledReason)
		}
	}
	for _, path := range []string{
		`C:\Users\Public\code.exe`,
		`C:\Users\Public\go.exe`,
		`C:\Users\Public\git.exe`,
		`C:\Users\Public\ollama.exe`,
		`C:\Program Files\Microsoft VS Code\code.exe`,
	} {
		if allowed, _, _ := store.IsAppAllowed(path); allowed {
			t.Fatalf("filename-only default wildcard authorized %q", path)
		}
		if allowed, _, _, _ := store.IsAppAllowedEvent(ProcessEvent{ImagePath: path, Image: filepath.Base(path)}); allowed {
			t.Fatalf("filename-only default wildcard authorized event %q", path)
		}
	}
	// The store refuses to re-enable the unsafe entry through the API.
	if err := store.ToggleWhitelistApp("wl_code", true); err == nil {
		t.Fatal("enabling an unpinned wildcard entry must be rejected")
	}
}

// TestLegacyWildcardMigrationDeactivatesUnsafeEntries proves that an old
// sentinel-config.json cannot silently materialize filename-only wildcards
// again, while pinned wildcard entries and exact-path entries stay valid.
func TestLegacyWildcardMigrationDeactivatesUnsafeEntries(t *testing.T) {
	root := t.TempDir()
	cfg := defaultSentinelConfig()
	cfg.Whitelist["wl_legacy_code"] = WhitelistEntry{
		ID: "wl_legacy_code", Name: "Legacy VS Code", PathPattern: `*code.exe`,
		Enabled: true, AddedUTC: time.Now().UTC(),
	}
	cfg.Whitelist["wl_legacy_pinned"] = WhitelistEntry{
		ID: "wl_legacy_pinned", Name: "Legacy Pinned", PathPattern: `*pinned.exe`,
		SHA256: strings.Repeat("A", 64), Enabled: true, AddedUTC: time.Now().UTC(),
	}
	cfg.Whitelist["wl_legacy_exact"] = WhitelistEntry{
		ID: "wl_legacy_exact", Name: "Legacy Exact", PathPattern: `C:\Tools\exact.exe`,
		Enabled: true, AddedUTC: time.Now().UTC(),
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, sentinelConfigFileName)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSentinelStore(root)
	if err != nil {
		t.Fatalf("open legacy config: %v", err)
	}
	loaded := store.Config()
	legacy := loaded.Whitelist["wl_legacy_code"]
	if legacy.Enabled {
		t.Fatal("legacy filename-only wildcard stayed enabled after migration")
	}
	if !strings.Contains(legacy.DisabledReason, "FIND-WIN-009") {
		t.Fatalf("legacy migration reason missing: %q", legacy.DisabledReason)
	}
	if !strings.Contains(loaded.Reason, "FIND-WIN-009") {
		t.Fatalf("migration was not recorded in the config reason: %q", loaded.Reason)
	}
	if !loaded.Whitelist["wl_legacy_pinned"].Enabled {
		t.Fatal("pinned legacy wildcard must stay enabled")
	}
	if !loaded.Whitelist["wl_legacy_exact"].Enabled {
		t.Fatal("exact-path legacy entry must stay enabled")
	}
	if allowed, _, _, reason := store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: `C:\Users\Public\code.exe`, Image: "code.exe",
	}); allowed {
		t.Fatalf("migrated wildcard authorized a user-writable copy, reason=%q", reason)
	}
	// A second open must not resurrect the entry.
	reopened, err := OpenSentinelStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Config().Whitelist["wl_legacy_code"].Enabled {
		t.Fatal("reopened config resurrected the legacy wildcard")
	}
}

func TestWildcardRequiresPinOnAdd(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddWhitelistApp("Unsigned Wildcard", `*tool.exe`); err == nil {
		t.Fatal("unpinned wildcard entry must be rejected")
	}
	if _, err := store.AddWhitelistAppPinned("Pinned Wildcard", `*tool.exe`, strings.Repeat("B", 64), ""); err != nil {
		t.Fatalf("pinned wildcard entry must be accepted: %v", err)
	}
	if _, err := store.AddWhitelistAppPinned("Signer Wildcard", `*signed-tool.exe`, "", "Microsoft"); err != nil {
		t.Fatalf("signer-pinned wildcard entry must be accepted: %v", err)
	}
}

// TestPinnedEntryNotAuthorizedByPathOnly proves the path-only helper stays
// fail-closed for pinned entries: it cannot verify the pin, so it must not
// authorize. The event-aware helper performs the pin check.
func TestPinnedEntryNotAuthorizedByPathOnly(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "pinned-app.exe")
	content := []byte("MZ pinned owner approved")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	pin := hex.EncodeToString(sum[:])
	if _, err := store.AddWhitelistAppPinned("Pinned App", `*pinned-app.exe`, pin, ""); err != nil {
		t.Fatal(err)
	}
	if allowed, _, _ := store.IsAppAllowed(path); allowed {
		t.Fatal("path-only helper must not treat a pinned entry as authorized")
	}
	if allowed, _, _, _ := store.IsAppAllowedEvent(ProcessEvent{ImagePath: path, Image: "pinned-app.exe"}); !allowed {
		t.Fatal("event-aware helper must authorize a matching hash pin")
	}
}

func TestWhitelistSHA256EventSignalIsAuthoritative(t *testing.T) {
	store, err := OpenSentinelStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	approved := []byte("MZ approved image")
	sum := sha256.Sum256(approved)
	pin := hex.EncodeToString(sum[:])
	if _, err := store.AddWhitelistAppPinned("Hash Signal App", `*hash-signal.exe`, pin, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hash-signal.exe")
	// The on-disk file is not the approved image, but the sensor captured the
	// approved hash: the event signal wins (it describes the executing image).
	if err := os.WriteFile(path, []byte("MZ different on disk"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed, _, _, reason := store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "hash-signal.exe", SHA256: pin,
	})
	if !allowed {
		t.Fatalf("matching event SHA-256 signal must authorize, reason=%q", reason)
	}
	allowed, _, _, reason = store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "hash-signal.exe", SHA256: strings.Repeat("0", 64),
	})
	if allowed || reason == "" {
		t.Fatalf("mismatching event SHA-256 must deny, allowed=%v reason=%q", allowed, reason)
	}
	// Missing event hash falls back to the bounded on-disk hash and stays
	// fail-closed because the file was replaced.
	allowed, _, _, reason = store.IsAppAllowedEvent(ProcessEvent{
		ImagePath: path, Image: "hash-signal.exe",
	})
	if allowed || reason == "" {
		t.Fatalf("missing signal with replaced file must deny, allowed=%v reason=%q", allowed, reason)
	}
}
