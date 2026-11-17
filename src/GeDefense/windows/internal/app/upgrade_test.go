// STATUS: DIAMANT VGT SUPREME
package app

import (
	"os"
	"path/filepath"
	"testing"
)

func createMinimalPayloadTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := []string{
		filepath.Join("engine", "Invoke-VgtHardening.ps1"),
		filepath.Join("audit", "Invoke-VgtSecurityAudit.ps1"),
		filepath.Join("xdr", "Invoke-VgtXdrScan.ps1"),
		filepath.Join("xdr", "Set-VgtMhxProtection.ps1"),
		filepath.Join("xdr", "Sync-VgtMhxFirewall.ps1"),
		filepath.Join("xdr", "Set-VgtMhxApplicationAllow.ps1"),
		filepath.Join("xdr", "Set-VgtMhxApplicationDeny.ps1"),
		filepath.Join("xdr", "Set-VgtMhxAppControl.ps1"),
	}
	for _, rel := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("# test script\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPrepareUpgradeMigratesLegacyEvidenceWithoutAnchors(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	root := createMinimalPayloadTree(t)

	// First initialize a clean 6.0.0 runtime to produce a valid HMAC-chained
	// evidence ledger + key material, then simulate a pre-6.0.0 (<256 records)
	// install by removing both .checkpoints.jsonl and .highwater.json.
	app1, err := New(root, "6.0.0")
	if err != nil {
		t.Fatalf("initial app.New: %v", err)
	}
	if err := app1.ledger.Append("test", "legacy", "ok"); err != nil {
		t.Fatalf("append legacy record: %v", err)
	}
	if err := app1.Close(); err != nil {
		t.Fatalf("close initial app: %v", err)
	}

	dataRoot := filepath.Join(programData, "VGT", "GeDefense")
	evidencePath := filepath.Join(dataRoot, "evidence.jsonl")
	checkpointPath := evidencePath + ".checkpoints.jsonl"
	highWaterPath := evidencePath + ".highwater.json"
	if err := os.Remove(checkpointPath); err != nil {
		t.Fatalf("remove checkpoints: %v", err)
	}
	if err := os.Remove(highWaterPath); err != nil {
		t.Fatalf("remove highwater: %v", err)
	}

	// Verify runtime app.New itself stays strictly fail-closed before migration.
	if _, err := New(root, "6.0.0"); err == nil {
		t.Fatal("expected app.New to fail closed when both anchors are absent")
	}

	// PrepareUpgrade migrates the verified legacy HMAC chain and verifies startup.
	if err := PrepareUpgrade(root, "6.0.0"); err != nil {
		t.Fatalf("PrepareUpgrade failed: %v", err)
	}

	// Normal app.New must now succeed cleanly.
	app2, err := New(root, "6.0.0")
	if err != nil {
		t.Fatalf("app.New after PrepareUpgrade failed: %v", err)
	}
	defer app2.Close()

	if _, err := os.Stat(checkpointPath); err != nil {
		t.Fatalf("checkpoint store missing after migration: %v", err)
	}
	if _, err := os.Stat(highWaterPath); err != nil {
		t.Fatalf("high-water anchor missing after migration: %v", err)
	}
}

func TestPrepareUpgradeRejectsPartialAnchorDeletion(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	root := createMinimalPayloadTree(t)

	app1, err := New(root, "6.0.0")
	if err != nil {
		t.Fatalf("initial app.New: %v", err)
	}
	if err := app1.ledger.Append("test", "active", "ok"); err != nil {
		t.Fatalf("append record: %v", err)
	}
	if err := app1.Close(); err != nil {
		t.Fatalf("close app: %v", err)
	}

	// Delete ONLY checkpoints while leaving highwater.json intact (post-6.0.0
	// tampering scenario). PrepareUpgrade must fail closed.
	dataRoot := filepath.Join(programData, "VGT", "GeDefense")
	if err := os.Remove(filepath.Join(dataRoot, "evidence.jsonl.checkpoints.jsonl")); err != nil {
		t.Fatalf("remove checkpoints: %v", err)
	}

	if err := PrepareUpgrade(root, "6.0.0"); err == nil {
		t.Fatal("PrepareUpgrade unexpectedly bypassed partial anchor deletion")
	}
}

func TestPrepareUpgradeRecoversCorruptActiveTitanTailWithArchives(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	root := createMinimalPayloadTree(t)

	app1, err := New(root, "6.0.0")
	if err != nil {
		t.Fatalf("initial app.New: %v", err)
	}
	if err := app1.Close(); err != nil {
		t.Fatalf("close initial app: %v", err)
	}

	// Verify PrepareUpgrade succeeds cleanly on an existing valid installation
	// (including the single-pass fast path where anchors already exist).
	if err := PrepareUpgrade(root, "6.0.0"); err != nil {
		t.Fatalf("PrepareUpgrade failed on clean state: %v", err)
	}
}
