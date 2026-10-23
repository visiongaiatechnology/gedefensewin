// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withLedgerTestTuning(t *testing.T, rotateBytes int64, checkpointInterval uint64) {
	t.Helper()
	previousRotate := ledgerRotateBytes
	previousInterval := appendCheckpointInterval
	ledgerRotateBytes = rotateBytes
	appendCheckpointInterval = checkpointInterval
	t.Cleanup(func() {
		ledgerRotateBytes = previousRotate
		appendCheckpointInterval = previousInterval
	})
}

func openTestLedger(t *testing.T, root string) *Ledger {
	t.Helper()
	ledger, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	return ledger
}

func TestLedgerRotatesRetainsAndVerifiesArchives(t *testing.T) {
	withLedgerTestTuning(t, 800, 4)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	for index := 0; index < 60; index++ {
		if err := ledger.Append("test", "rotate", fmt.Sprintf("record-%03d", index)); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	archives, err := filepath.Glob(filepath.Join(root, "evidence.jsonl.*-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) == 0 {
		t.Fatal("rotation did not archive any evidence file")
	}
	if len(archives) > maxRetainedArchives+1 {
		t.Fatalf("archive retention exceeded: %d archives", len(archives))
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	page, total, err := ledger.Page(10, 0)
	if err != nil || total <= 0 || len(page) == 0 {
		t.Fatalf("page len=%d total=%d err=%v", len(page), total, err)
	}
	if total > 60 {
		t.Fatalf("retained window total=%d exceeds recorded events", total)
	}
	if page[0].Sequence != 60 {
		t.Fatalf("newest retained sequence=%d, want 60", page[0].Sequence)
	}
	oldestPage, total, err := ledger.Page(1, total-1)
	if err != nil || total <= 0 || len(oldestPage) != 1 {
		t.Fatalf("oldest page len=%d total=%d err=%v", len(oldestPage), total, err)
	}
	oldestExpected := uint64(60 - total + 1)
	if oldestPage[0].Sequence != oldestExpected {
		t.Fatalf("oldest retained sequence=%d, want %d", oldestPage[0].Sequence, oldestExpected)
	}
	// Reopening must re-verify the archive chain and the retention anchors.
	reopened := openTestLedger(t, root)
	if err := reopened.Verify(); err != nil {
		t.Fatalf("reopen verify: %v", err)
	}
	if err := reopened.Append("test", "after-reopen", "verified"); err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify after reopen append: %v", err)
	}
}

func TestLedgerDetectsTruncatedTailAgainstSignedCheckpoint(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	for index := 0; index < 6; index++ {
		if err := ledger.Append("test", "truncation", "verified"); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	path := filepath.Join(root, "evidence.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSuffix(string(raw), "\n")
	lastNewline := strings.LastIndex(trimmed, "\n")
	if lastNewline < 0 {
		t.Fatal("test ledger too small to truncate")
	}
	if err := os.WriteFile(path, []byte(trimmed[:lastNewline+1]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, filepath.Join(root, "evidence.key")); err == nil {
		t.Fatal("truncated ledger tail was accepted despite a signed checkpoint")
	}
}

func TestLedgerQuarantinesCorruptCheckpointStoreAndKeepsRecording(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	for index := 0; index < 3; index++ {
		if err := ledger.Append("test", "checkpoint", "verified"); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	checkpointPath := filepath.Join(root, "evidence.jsonl.checkpoints.jsonl")
	if err := os.WriteFile(checkpointPath, []byte("{corrupt-checkpoint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatalf("corrupt checkpoint store bricked the ledger: %v", err)
	}
	forensics, err := filepath.Glob(filepath.Join(root, "evidence.jsonl.checkpoints.jsonl.corrupt-*"))
	if err != nil || len(forensics) == 0 {
		t.Fatalf("corrupt checkpoint store was not preserved for forensics: %v %v", forensics, err)
	}
	if err := reopened.Append("test", "after-repair", "verified"); err != nil {
		t.Fatalf("append after checkpoint repair: %v", err)
	}
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify after checkpoint repair: %v", err)
	}
}

func TestLedgerSerializesConcurrentWriters(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 2)
	root := t.TempDir()
	first := openTestLedger(t, root)
	second := openTestLedger(t, root)
	for index := 0; index < 12; index++ {
		target := first
		if index%2 == 1 {
			target = second
		}
		if err := target.Append("test", "interleaved", fmt.Sprintf("record-%02d", index)); err != nil {
			t.Fatalf("interleaved append %d: %v", index, err)
		}
	}
	verifier := openTestLedger(t, root)
	if err := verifier.Verify(); err != nil {
		t.Fatalf("interleaved writers produced an invalid chain: %v", err)
	}
	_, total, err := verifier.Page(1, 0)
	if err != nil || total != 12 {
		t.Fatalf("total=%d err=%v, want 12", total, err)
	}
}

func TestLedgerAppendFailureIsSurfaced(t *testing.T) {
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	original := ledger.path
	ledger.path = filepath.Join(root, "missing-subdirectory", "evidence.jsonl")
	if err := ledger.Append("test", "failure", "rejected"); err == nil {
		t.Fatal("append into a missing directory reported success")
	}
	if ledger.AppendFailures() == 0 {
		t.Fatal("append failure was not counted")
	}
	if ledger.LastError() == nil {
		t.Fatal("append failure was not exposed through LastError")
	}
	ledger.path = original
	if err := ledger.Append("test", "recovered", "verified"); err != nil {
		t.Fatalf("append after restored path: %v", err)
	}
}

func TestLedgerSnapshotKeepsChronologicalTail(t *testing.T) {
	root := t.TempDir()
	ledger := openTestLedger(t, root)
	for index := 0; index < 5; index++ {
		if err := ledger.Append("test", "snapshot", fmt.Sprintf("record-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	records, err := ledger.Snapshot(3)
	if err != nil || len(records) != 3 {
		t.Fatalf("snapshot len=%d err=%v", len(records), err)
	}
	if records[0].Sequence != 3 || records[2].Sequence != 5 {
		t.Fatalf("snapshot order changed: %d..%d", records[0].Sequence, records[2].Sequence)
	}
}
