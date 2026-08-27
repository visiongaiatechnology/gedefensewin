// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

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
