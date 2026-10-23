// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func witnessPathOutside(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "evidence-witness.json")
}

func openWitnessLedger(t *testing.T, root, witnessPath string) *Ledger {
	t.Helper()
	ledger, err := OpenWithOptions(
		filepath.Join(root, "evidence.jsonl"),
		filepath.Join(root, "evidence.key"),
		Options{WitnessPath: witnessPath},
	)
	if err != nil {
		t.Fatalf("open ledger with witness: %v", err)
	}
	return ledger
}

func appendWitnessRecords(t *testing.T, ledger *Ledger, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		if err := ledger.Append("test", "witness", "verified"); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
}

// DP-FIND-012 regression: a matching external tip is accepted, survives a
// reopen and Verify().
func TestEvidenceWitnessMatchingTipIsVerified(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	witnessPath := witnessPathOutside(t)
	ledger := openWitnessLedger(t, root, witnessPath)
	appendWitnessRecords(t, ledger, 3)
	status := ledger.Witness()
	if !status.Configured || !status.Reachable || !status.Verified || status.Degraded {
		t.Fatalf("matching witness not verified: %+v", status)
	}
	if status.Sequence != 3 || status.LocalSequence != 3 {
		t.Fatalf("witness sequence mismatch: %+v", status)
	}
	reopened := openWitnessLedger(t, root, witnessPath)
	if status := reopened.Witness(); !status.Verified || status.Sequence != 3 || status.Degraded {
		t.Fatalf("reopened witness not verified: %+v", status)
	}
	if err := reopened.Verify(); err != nil {
		t.Fatalf("verify with matching witness: %v", err)
	}
}

// DP-FIND-012 truncation detection: an attacker that rolls back the whole local
// data root (journal and checkpoint store) is caught by the witness that lives
// outside it.
func TestEvidenceWitnessDetectsRollbackBeyondCheckpointStore(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	witnessPath := witnessPathOutside(t)
	ledger := openWitnessLedger(t, root, witnessPath)
	appendWitnessRecords(t, ledger, 3)
	for _, name := range []string{"evidence.jsonl", "evidence.jsonl.checkpoints.jsonl"} {
		if err := os.Remove(filepath.Join(root, name)); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", name, err)
		}
	}
	_, err := OpenWithOptions(
		filepath.Join(root, "evidence.jsonl"),
		filepath.Join(root, "evidence.key"),
		Options{WitnessPath: witnessPath},
	)
	if err == nil {
		t.Fatal("rolled back ledger was accepted despite an ahead external witness")
	}
	if !strings.Contains(err.Error(), "witness") || !strings.Contains(err.Error(), "ahead") {
		t.Fatalf("rollback was not reported as an ahead witness: %v", err)
	}
}

// DP-FIND-012: a configured but corrupt witness is never silently ignored.
func TestEvidenceWitnessCorruptionFailsClosed(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	witnessPath := witnessPathOutside(t)
	ledger := openWitnessLedger(t, root, witnessPath)
	appendWitnessRecords(t, ledger, 2)
	valid, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatalf("read witness: %v", err)
	}
	openWithWitness := func() error {
		_, err := OpenWithOptions(
			filepath.Join(root, "evidence.jsonl"),
			filepath.Join(root, "evidence.key"),
			Options{WitnessPath: witnessPath},
		)
		return err
	}

	if err := os.WriteFile(witnessPath, []byte("{not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openWithWitness(); err == nil || !strings.Contains(err.Error(), "witness") {
		t.Fatalf("garbage witness accepted: %v", err)
	}

	var tip witnessTip
	if err := json.Unmarshal(valid, &tip); err != nil {
		t.Fatalf("decode valid witness: %v", err)
	}
	tampered := tip
	flipped := []byte("b")
	if tampered.Signature[0] == 'b' {
		flipped = []byte("a")
	}
	tampered.Signature = string(flipped) + tampered.Signature[1:]
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(witnessPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openWithWitness(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered witness signature accepted: %v", err)
	}

	oversized := make([]byte, maxWitnessFileBytes+1)
	if err := os.WriteFile(witnessPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openWithWitness(); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversized witness accepted: %v", err)
	}
}

// DP-FIND-012: a witness signed by a different evidence key must fail closed,
// e.g. after a data-root restore from a foreign backup.
func TestEvidenceWitnessRejectsDifferentSigningKey(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	rootA := t.TempDir()
	witnessA := witnessPathOutside(t)
	ledgerA := openWitnessLedger(t, rootA, witnessA)
	appendWitnessRecords(t, ledgerA, 2)
	raw, err := os.ReadFile(witnessA)
	if err != nil {
		t.Fatalf("read witness A: %v", err)
	}
	rootB := t.TempDir()
	witnessB := witnessPathOutside(t)
	if err := os.WriteFile(witnessB, raw, 0o600); err != nil {
		t.Fatalf("copy witness: %v", err)
	}
	_, err = OpenWithOptions(
		filepath.Join(rootB, "evidence.jsonl"),
		filepath.Join(rootB, "evidence.key"),
		Options{WitnessPath: witnessB},
	)
	if err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("foreign-key witness accepted: %v", err)
	}
}

// DP-FIND-012: without a configured witness the ledger behaves exactly as
// before and never reports a witness state.
func TestEvidenceWitnessUnconfiguredKeepsLegacyBehaviour(t *testing.T) {
	t.Setenv(witnessPathEnvVar, "")
	root := t.TempDir()
	ledger, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	appendWitnessRecords(t, ledger, 3)
	status := ledger.Witness()
	if status.Configured || status.Reachable || status.Degraded || status.Verified {
		t.Fatalf("unconfigured witness reported state: %+v", status)
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("verify without witness: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name()), "witness") {
			t.Fatalf("unconfigured ledger wrote a witness file: %s", entry.Name())
		}
	}
}

// DP-FIND-012: the operator can enable the witness through the environment.
func TestEvidenceWitnessConfiguredThroughEnvironment(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	witnessPath := witnessPathOutside(t)
	t.Setenv(witnessPathEnvVar, witnessPath)
	ledger, err := Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatalf("open ledger with environment witness: %v", err)
	}
	appendWitnessRecords(t, ledger, 1)
	status := ledger.Witness()
	if !status.Configured || !status.Reachable || !status.Verified || status.Degraded {
		t.Fatalf("environment witness not verified: %+v", status)
	}
	if status.Sequence != 1 {
		t.Fatalf("environment witness sequence=%d, want 1", status.Sequence)
	}
}

// DP-FIND-012 path boundary: absolute, bounded, outside the data root; UNC
// paths stay allowed for an off-host witness.
func TestEvidenceWitnessPathBoundary(t *testing.T) {
	root := t.TempDir()
	ledgerPath := filepath.Join(root, "evidence.jsonl")
	keyPath := filepath.Join(root, "evidence.key")
	cases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "empty means unconfigured", path: "", wantErr: false},
		{name: "relative path rejected", path: "evidence-witness.json", wantErr: true},
		{name: "inside data root rejected", path: filepath.Join(root, "witness.json"), wantErr: true},
		{name: "inside data root with casing alias rejected", path: strings.ToUpper(filepath.Join(root, "witness.json")), wantErr: true},
		{name: "sibling prefix is outside", path: root + "-sibling\\witness.json", wantErr: false},
		{name: "ledger path rejected", path: ledgerPath, wantErr: true},
		{name: "data root itself rejected", path: root, wantErr: true},
		{name: "unc path accepted", path: `\\server\share\vgt-witness.json`, wantErr: false},
		{name: "outside absolute path accepted", path: witnessPathOutside(t), wantErr: false},
	}
	for _, testCase := range cases {
		if _, err := validateWitnessPath(testCase.path, filepath.Dir(ledgerPath)); (err != nil) != testCase.wantErr {
			t.Fatalf("%s: path=%q err=%v wantErr=%v", testCase.name, testCase.path, err, testCase.wantErr)
		}
	}
	if _, err := OpenWithOptions(ledgerPath, keyPath, Options{WitnessPath: "relative.json"}); err == nil {
		t.Fatal("OpenWithOptions accepted a relative witness path")
	}
	if _, err := OpenWithOptions(ledgerPath, keyPath, Options{WitnessPath: filepath.Join(root, "witness.json")}); err == nil {
		t.Fatal("OpenWithOptions accepted a witness path inside the data root")
	}
}

// DP-FIND-012 degraded semantics: an absent removable medium must not stop
// evidence recording, must be visible, and must recover once it is available.
func TestEvidenceWitnessMissingMediumDegradesAndRecovers(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	medium := filepath.Join(t.TempDir(), "removable-medium")
	witnessPath := filepath.Join(medium, "evidence-witness.json")
	ledger := openWitnessLedger(t, root, witnessPath)
	status := ledger.Witness()
	if !status.Configured || !status.Degraded || status.Reachable {
		t.Fatalf("missing medium not reported as degraded: %+v", status)
	}
	appendWitnessRecords(t, ledger, 2)
	if ledger.LastError() == nil {
		t.Fatal("failed witness write was not surfaced through LastError")
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("degraded witness must not fail verification: %v", err)
	}
	previousRetry := witnessRetryInterval
	witnessRetryInterval = 0
	t.Cleanup(func() { witnessRetryInterval = previousRetry })
	if err := os.MkdirAll(medium, 0o700); err != nil {
		t.Fatalf("create medium: %v", err)
	}
	appendWitnessRecords(t, ledger, 1)
	status = ledger.Witness()
	if !status.Reachable || !status.Verified || status.Degraded {
		t.Fatalf("witness did not recover with the medium: %+v", status)
	}
	if status.Sequence != 3 {
		t.Fatalf("recovered witness sequence=%d, want 3", status.Sequence)
	}
}

// The witness write itself must be bounded and atomic: no temp files survive a
// successful write and the record never exceeds the file boundary.
func TestEvidenceWitnessWriteIsBoundedAndAtomic(t *testing.T) {
	withLedgerTestTuning(t, 64<<20, 1)
	root := t.TempDir()
	witnessDirectory := t.TempDir()
	witnessPath := filepath.Join(witnessDirectory, "evidence-witness.json")
	ledger := openWitnessLedger(t, root, witnessPath)
	appendWitnessRecords(t, ledger, 2)
	info, err := os.Stat(witnessPath)
	if err != nil {
		t.Fatalf("stat witness: %v", err)
	}
	if info.Size() <= 0 || info.Size() > maxWitnessFileBytes {
		t.Fatalf("witness size outside boundary: %d", info.Size())
	}
	entries, err := os.ReadDir(witnessDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary witness file survived: %s", entry.Name())
		}
	}
	// The record is a signed tip, not a key store: no secret material is on the
	// external medium beyond the public key fingerprint and signatures.
	raw, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded witnessTip
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode witness: %v", err)
	}
	if decoded.Sequence != 2 || decoded.WrittenUTC.IsZero() {
		t.Fatalf("unexpected witness tip: %+v", decoded)
	}
	status := ledger.Witness()
	if status.WrittenUTC.Before(time.Now().Add(-time.Hour)) {
		t.Fatalf("witness write time is implausible: %v", status.WrittenUTC)
	}
}
