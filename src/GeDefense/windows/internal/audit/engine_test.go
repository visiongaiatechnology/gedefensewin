// STATUS: DIAMANT VGT SUPREME
package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

func TestResultDecodingIsBackwardCompatible(t *testing.T) {
	legacy := []byte(`{
		"TimestampUtc": "2026-10-01T00:00:00Z",
		"Framework": "VGT-SafetySys",
		"Score": 10,
		"MaxScore": 12,
		"Percent": 83.33,
		"Passed": 10,
		"Failed": 1,
		"Warnings": 1,
		"Checks": []
	}`)
	var result Result
	if err := json.Unmarshal(legacy, &result); err != nil {
		t.Fatalf("decode legacy audit result: %v", err)
	}
	if result.Score != 10 || result.Percent != 83.33 || len(result.Checks) != 0 {
		t.Fatalf("legacy audit result mismatch: %+v", result)
	}
	future := []byte(`{
		"TimestampUtc": "2026-10-22T00:00:00Z",
		"Framework": "VGT-SafetySys",
		"Score": 1,
		"MaxScore": 2,
		"Percent": 50,
		"Passed": 1,
		"Failed": 1,
		"Warnings": 0,
		"FutureField": {"ignored": true},
		"Checks": [
			{"Id": "VGT-D-001", "Category": "Defender", "Title": "Microsoft Defender", "Status": "Pass", "Severity": "Critical", "Expected": "Enabled", "Actual": "Enabled", "FutureCheckField": 1}
		]
	}`)
	if err := json.Unmarshal(future, &result); err != nil {
		t.Fatalf("decode forward-compatible audit result: %v", err)
	}
	if len(result.Checks) != 1 || result.Checks[0].ID != "VGT-D-001" || result.Checks[0].Status != "Pass" {
		t.Fatalf("audit check mismatch: %+v", result.Checks)
	}
}

func TestNewRejectsUnsafePaths(t *testing.T) {
	if _, err := New("relative-audit.ps1", t.TempDir(), nil); err == nil {
		t.Fatal("relative audit script path was accepted")
	}
	if _, err := New(filepath.Join(t.TempDir(), "missing-audit.ps1"), t.TempDir(), nil); err == nil {
		t.Fatal("missing audit script was accepted")
	}
}

func TestRunFailsClosedAndRecordsEvidence(t *testing.T) {
	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "inert-audit.ps1")
	if err := os.WriteFile(scriptPath, []byte("param([string]$OutputPath) exit 20\n"), 0o600); err != nil {
		t.Fatalf("write inert audit script: %v", err)
	}
	ledger, err := evidence.Open(filepath.Join(directory, "evidence.jsonl"), filepath.Join(directory, "evidence.key"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	engine, err := New(scriptPath, filepath.Join(directory, "operations"), ledger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := engine.Run(ctx); err == nil {
		t.Fatal("unverifiable audit reported success")
	}
	records, err := ledger.Snapshot(10)
	if err != nil {
		t.Fatalf("snapshot ledger: %v", err)
	}
	if len(records) != 1 || records[0].Kind != "audit.operation" || records[0].Result != "failed" {
		t.Fatalf("failed audit evidence missing: %+v", records)
	}
}

func TestRunWithoutLedgerFailsClosedWithoutPanic(t *testing.T) {
	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "inert-audit.ps1")
	if err := os.WriteFile(scriptPath, []byte("param([string]$OutputPath) exit 20\n"), 0o600); err != nil {
		t.Fatalf("write inert audit script: %v", err)
	}
	engine, err := New(scriptPath, filepath.Join(directory, "operations"), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := engine.Run(ctx); err == nil {
		t.Fatal("unverifiable audit reported success without a ledger")
	}
}
