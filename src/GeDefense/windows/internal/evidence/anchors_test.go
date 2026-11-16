// STATUS: PLATIN VGT SUPREME
package evidence

// FIND-WIN-016 regression tests: a non-empty evidence chain must never be
// re-anchored silently, the authenticated high-water anchor must reject rollback
// and tampering, and the only recovery path is the explicit operator function.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appendAnchorRecords(t *testing.T, ledger *Ledger, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		if err := ledger.Append("test", "anchor", "verified"); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
}

func cutFileToLines(t *testing.T, path string, lines int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSuffix(string(raw), "\n")
	parts := strings.Split(trimmed, "\n")
	if len(parts) < lines {
		t.Fatalf("file %s has %d lines, want at least %d", path, len(parts), lines)
	}
	reduced := strings.Join(parts[:lines], "\n") + "\n"
	if err := os.WriteFile(path, []byte(reduced), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAnchorMissingCheckpointFailsClosed is regression (a): non-empty evidence
// without an intact checkpoint must never be re-signed into a "fresh" ledger.
func TestAnchorMissingCheckpointFailsClosed(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 3)
	checkpointPath := filepath.Join(root, "evidence.jsonl.checkpoints.jsonl")
	if err := os.Remove(checkpointPath); err != nil {
		t.Fatal(err)
	}
	_, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err == nil {
		t.Fatal("non-empty evidence without a signed checkpoint was silently re-anchored")
	}
	if !errors.Is(err, ErrEvidenceCheckpointAnchorMissing) {
		t.Fatalf("missing checkpoint error is not typed: %v", err)
	}
	// No silent reset: the failed Open must not have signed a replacement store.
	if _, statErr := os.Lstat(checkpointPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed Open wrote a fresh checkpoint store: %v", statErr)
	}
}

// TestAnchorCorruptCheckpointFailsClosed is regression (b): a damaged store is
// preserved for forensics but never replaced automatically.
func TestAnchorCorruptCheckpointFailsClosed(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 3)
	checkpointPath := filepath.Join(root, "evidence.jsonl.checkpoints.jsonl")
	if err := os.WriteFile(checkpointPath, []byte("{corrupt-checkpoint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err == nil {
		t.Fatal("corrupt checkpoint store was silently replaced")
	}
	if !errors.Is(err, ErrEvidenceCheckpointAnchorMissing) {
		t.Fatalf("corrupt checkpoint error is not typed: %v", err)
	}
	forensics, globErr := filepath.Glob(checkpointPath + ".corrupt-*")
	if globErr != nil || len(forensics) == 0 {
		t.Fatalf("corrupt checkpoint store was not preserved for forensics: %v %v", forensics, globErr)
	}
	// Normal Open keeps failing; only the explicit recovery path may re-anchor.
	if _, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key")); err == nil {
		t.Fatal("second Open silently accepted the damaged checkpoint state")
	}
}

// TestAnchorNormalRotationAndAppendsStayVerifiable is regression (c): ordinary
// rotation, appends and reopens keep working and maintain the high-water anchor.
func TestAnchorNormalRotationAndAppendsStayVerifiable(t *testing.T) {
	withLedgerTestTuning(t, 900, 2)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 40)
	if err := ledger.Verify(); err != nil {
		t.Fatalf("verify during rotation: %v", err)
	}
	highWaterPath := filepath.Join(root, "evidence.jsonl.highwater.json")
	info, err := os.Stat(highWaterPath)
	if err != nil {
		t.Fatalf("high-water anchor was not written: %v", err)
	}
	if info.Size() <= 0 || info.Size() > maxHighWaterFileBytes {
		t.Fatalf("high-water anchor size outside the boundary: %d", info.Size())
	}
	reopened := openTestLedger(t, root)
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
	appendAnchorRecords(t, reopened, 4)
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify after append: %v", err)
	}
	if reopened.sequence != 44 {
		t.Fatalf("unexpected chain tip after reopen: %d", reopened.sequence)
	}
}

// TestAnchorRecoveryPathIsExplicitAndAudited is regression (d): the documented
// operator recovery works once, is recorded in the chain and archives the old
// anchor stores.
func TestAnchorRecoveryPathIsExplicitAndAudited(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	path := filepath.Join(root, "evidence.jsonl")
	keyPath := filepath.Join(root, "evidence.key")
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 4)
	// Simulate "archived and verified, anchors lost".
	if err := os.Remove(filepath.Join(root, "evidence.jsonl.checkpoints.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "evidence.jsonl.highwater.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, keyPath); !errors.Is(err, ErrEvidenceCheckpointAnchorMissing) {
		t.Fatalf("anchor loss not reported before recovery: %v", err)
	}
	// An explicit reason is mandatory: recovery without one is refused.
	if _, err := RecoverCheckpointAnchors(path, keyPath, Options{}, "  "); !errors.Is(err, ErrEvidenceRecoveryRejected) {
		t.Fatalf("recovery without a reason was accepted: %v", err)
	}
	report, err := RecoverCheckpointAnchors(path, keyPath, Options{}, "archive 2026-11-16 verified against backup")
	if err != nil {
		t.Fatalf("explicit checkpoint recovery failed: %v", err)
	}
	if report.Sequence != 5 {
		t.Fatalf("recovery report sequence=%d, want 5 (4 records + recovery audit)", report.Sequence)
	}
	if report.CheckpointPath == "" || report.HighWaterPath == "" {
		t.Fatalf("recovery report does not name the initialized anchors: %+v", report)
	}
	reopened := openTestLedger(t, root)
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify after explicit recovery: %v", err)
	}
	records, err := reopened.Snapshot(10)
	if err != nil {
		t.Fatal(err)
	}
	recoveryRecorded := false
	for _, record := range records {
		if record.Kind == "evidence.recovery" && record.Action == "checkpoint-reanchor" {
			recoveryRecorded = true
		}
	}
	if !recoveryRecorded {
		t.Fatalf("explicit recovery was not recorded in the chain: %+v", records)
	}
	if err := reopened.Append("test", "after-recovery", "verified"); err != nil {
		t.Fatalf("append after explicit recovery: %v", err)
	}
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify after post-recovery append: %v", err)
	}
}

// TestAnchorRecoveryPreservesCorruptStoreForForensics proves the recovery path
// keeps the damaged anchor store and refuses to re-anchor a tampered chain.
func TestAnchorRecoveryPreservesCorruptStoreForForensics(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	path := filepath.Join(root, "evidence.jsonl")
	keyPath := filepath.Join(root, "evidence.key")
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 2)
	checkpointPath := filepath.Join(root, "evidence.jsonl.checkpoints.jsonl")
	if err := os.WriteFile(checkpointPath, []byte("{corrupt-checkpoint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverCheckpointAnchors(path, keyPath, Options{}, "operator verified evidence after storage failure"); err != nil {
		t.Fatalf("recovery with preserved corrupt store failed: %v", err)
	}
	forensics, err := filepath.Glob(checkpointPath + ".corrupt-*")
	if err != nil || len(forensics) == 0 {
		t.Fatalf("corrupt checkpoint store was not preserved unchanged: %v %v", forensics, err)
	}
	preserved, err := os.ReadFile(forensics[0])
	if err != nil || string(preserved) != "{corrupt-checkpoint\n" {
		t.Fatalf("archived corrupt store was not preserved unchanged: %v %q", err, preserved)
	}
	// A tampered chain must never be re-anchored.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverCheckpointAnchors(path, keyPath, Options{}, "operator requests recovery on a tampered chain"); !errors.Is(err, ErrEvidenceRecoveryRejected) {
		t.Fatalf("tampered chain was re-anchored: %v", err)
	}
}

// TestAnchorHighWaterDetectsRollbackBackedCheckpointStore proves the high-water
// anchor catches a rollback that the signed checkpoint store alone accepts.
func TestAnchorHighWaterDetectsRollbackBackedCheckpointStore(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	path := filepath.Join(root, "evidence.jsonl")
	keyPath := filepath.Join(root, "evidence.key")
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 6)
	// Roll back both the chain and the signed checkpoint store to sequence 3: the
	// checkpoint signatures stay valid, only the high-water anchor remembers 6.
	cutFileToLines(t, path, 3)
	cutFileToLines(t, filepath.Join(root, "evidence.jsonl.checkpoints.jsonl"), 3)
	_, err := Open(path, keyPath)
	if err == nil {
		t.Fatal("rollback consistent with the checkpoint store was accepted")
	}
	if !errors.Is(err, ErrEvidenceHighWaterRollback) {
		t.Fatalf("rollback was not reported through the high-water anchor: %v", err)
	}
	if _, recoveryErr := RecoverCheckpointAnchors(path, keyPath, Options{}, "operator accepted the archived rollback"); recoveryErr != nil {
		t.Fatalf("explicit recovery after verified rollback failed: %v", recoveryErr)
	}
}

// TestAnchorTamperedHighWaterFailsClosed proves an unauthenticated future or
// modified high-water record is never trusted.
func TestAnchorTamperedHighWaterFailsClosed(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	path := filepath.Join(root, "evidence.jsonl")
	keyPath := filepath.Join(root, "evidence.key")
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 2)
	highWaterPath := filepath.Join(root, "evidence.jsonl.highwater.json")
	raw, err := os.ReadFile(highWaterPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"sequence":2`, `"sequence":99`, 1)
	if tampered == string(raw) {
		t.Fatalf("test could not find the high-water sequence field: %s", raw)
	}
	if err := os.WriteFile(highWaterPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(path, keyPath)
	if err == nil {
		t.Fatal("tampered high-water anchor was trusted")
	}
	if !errors.Is(err, ErrEvidenceHighWaterInvalid) {
		t.Fatalf("tampered high-water error is not typed: %v", err)
	}
}

// TestAnchorRuntimeTruncationIsRejected proves deleting the live evidence file
// while the ledger is open cannot silently restart the chain at sequence 1.
func TestAnchorRuntimeTruncationIsRejected(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 2)
	if err := os.Remove(filepath.Join(root, "evidence.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "evidence.jsonl.checkpoints.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append("test", "after-deletion", "verified"); !errors.Is(err, ErrEvidenceHighWaterRollback) {
		t.Fatalf("append after live evidence deletion was not rejected: %v", err)
	}
	if err := ledger.Verify(); !errors.Is(err, ErrEvidenceHighWaterRollback) && !errors.Is(err, ErrEvidenceCheckpointAnchorMissing) {
		t.Fatalf("verify after live evidence deletion was not fail-closed: %v", err)
	}
}

// TestAnchorHighWaterIsUpdatedWithDurableCheckpoint documents the anchor
// freshness contract: every durable checkpoint mirrors the tip, and the mirror
// is authenticated with the protected ledger key.
func TestAnchorHighWaterIsUpdatedWithDurableCheckpoint(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	appendAnchorRecords(t, ledger, 1)
	ledger.highWater = highWaterState{}
	ledger.loadHighWaterLocked()
	if !ledger.highWater.present || ledger.highWater.sequence != 1 {
		t.Fatalf("high-water mirror does not track the signed checkpoint: %+v", ledger.highWater)
	}
	raw, err := os.ReadFile(ledger.highWaterPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"mac"`) {
		t.Fatalf("high-water anchor is not authenticated: %s", raw)
	}
	ledger.lastMAC = strings.Repeat("0", 64)
	if err := ledger.persistHighWaterLocked(); !errors.Is(err, ErrEvidenceHighWaterMismatch) {
		t.Fatalf("same-sequence MAC substitution was not rejected: %v", err)
	}
}
