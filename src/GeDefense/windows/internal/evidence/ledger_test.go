// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerPagesNewestFirst(t *testing.T) {
	root := t.TempDir()
	ledger, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		if err := ledger.Append("test", "page", "verified"); err != nil {
			t.Fatal(err)
		}
	}
	first, total, err := ledger.Page(20, 0)
	if err != nil || total != 25 || len(first) != 20 {
		t.Fatalf("first page: len=%d total=%d err=%v", len(first), total, err)
	}
	if first[0].Sequence != 25 || first[len(first)-1].Sequence != 6 {
		t.Fatalf("first page not newest-first: first=%d last=%d", first[0].Sequence, first[len(first)-1].Sequence)
	}
	second, total, err := ledger.Page(20, 20)
	if err != nil || total != 25 || len(second) != 5 {
		t.Fatalf("second page: len=%d total=%d err=%v", len(second), total, err)
	}
	if second[0].Sequence != 5 || second[len(second)-1].Sequence != 1 {
		t.Fatalf("second page not newest-first: first=%d last=%d", second[0].Sequence, second[len(second)-1].Sequence)
	}
	if _, _, err := ledger.Page(101, 0); err == nil {
		t.Fatal("oversized page accepted")
	}
}

func TestLedgerDetectsTampering(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "evidence.jsonl")
	ledger, err := Open(path, filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append("hardening.operation", "Audit:EnterpriseBalanced", "verified"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Verify(); err == nil {
		t.Fatal("tampered evidence chain accepted")
	}
}
