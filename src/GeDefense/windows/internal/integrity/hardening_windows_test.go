// STATUS: DIAMANT VGT SUPREME
//go:build windows

package integrity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

func newIntegrityTestEngine(t *testing.T) *Engine {
	t.Helper()
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(filepath.Join(root, "integrity"), ledger)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestIntegrityStateTamperingIsRejected(t *testing.T) {
	engine := newIntegrityTestEngine(t)
	if _, err := engine.Configure(false, 12); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(engine.root, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"intervalHours":12`, `"intervalHours":24`, 1)
	if tampered == string(raw) {
		t.Fatal("test could not construct a tampered state document")
	}
	if err := os.WriteFile(statePath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(engine.root, engine.ledger)
	if err != nil {
		t.Fatalf("tampered state bricked the engine: %v", err)
	}
	status := reopened.Status()
	if !strings.Contains(status.Error, "integrity state rejected") || status.State != "DEGRADED" {
		t.Fatalf("tampered state was not surfaced fail-closed: %+v", status)
	}
}

func TestIntegritySnapshotBucketTamperingIsDetected(t *testing.T) {
	engine := newIntegrityTestEngine(t)
	generation := "20260101T000000Z-0123456789abcdef"
	directory := filepath.Join(engine.root, "snapshots", generation)
	createBucketSet(t, directory, []FileRecord{
		{Path: `C:\stable.dll`, Size: 10, SHA256: repeatedHash('a')},
	})
	if err := os.WriteFile(filepath.Join(directory, "changes.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.writeSnapshotManifest(directory, generation, 1); err != nil {
		t.Fatal(err)
	}
	if err := engine.authenticateSnapshotManifest(mustReadManifest(t, directory)); err != nil {
		t.Fatalf("fresh manifest rejected: %v", err)
	}
	// Tamper one baseline bucket while keeping the authenticated manifest.
	bucketPath := filepath.Join(directory, fmt.Sprintf("%02x.jsonl", pathBucket(`C:\stable.dll`)))
	raw, err := os.ReadFile(bucketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bucketPath, append(raw, []byte("\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	// The next differential scan authenticates the previous baseline before it
	// diffes against it; a tampered bucket must abort the scan.
	current := filepath.Join(engine.root, "snapshots", "20260102T000000Z-0123456789abcdef")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := engine.compare(generation, current); err == nil {
		t.Fatal("tampered previous baseline bucket was accepted by the diff")
	}
}

func TestIntegrityChangesReportTamperingIsDetected(t *testing.T) {
	engine := newIntegrityTestEngine(t)
	generation := "20260101T000000Z-0123456789abcdef"
	directory := filepath.Join(engine.root, "snapshots", generation)
	createBucketSet(t, directory, []FileRecord{
		{Path: `C:\stable.dll`, Size: 10, SHA256: repeatedHash('a')},
	})
	if err := os.WriteFile(filepath.Join(directory, "changes.jsonl"), []byte("{\"kind\":\"ADDED\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.writeSnapshotManifest(directory, generation, 1); err != nil {
		t.Fatal(err)
	}
	changesPath := filepath.Join(directory, "changes.jsonl")
	raw, err := os.ReadFile(changesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changesPath, append(raw, '{', '}'), 0o600); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.status.Generation = generation
	engine.mu.Unlock()
	if _, err := engine.Changes(10, 0); err == nil {
		t.Fatal("tampered changes report was accepted by the changes API")
	}
}

func mustReadManifest(t *testing.T, directory string) snapshotManifest {
	t.Helper()
	manifest, err := readSnapshotManifest(directory)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestIntegrityGenerationValidation(t *testing.T) {
	valid := []string{"20260101T000000Z-0123456789abcdef", "20261231T235959Z-fedcba9876543210"}
	for _, value := range valid {
		if !validGenerationID(value) {
			t.Fatalf("valid generation rejected: %s", value)
		}
	}
	invalid := []string{"", "../../etc", "20260101T000000Z", "20260101T000000Z-0123456789ABCDEF", "20260101T000000Z-0123456789abcde", "previous", "20260101T000000Z-0123456789abcdef/../x"}
	for _, value := range invalid {
		if validGenerationID(value) {
			t.Fatalf("invalid generation accepted: %s", value)
		}
	}
	engine := newIntegrityTestEngine(t)
	engine.mu.Lock()
	engine.status.Generation = "previous"
	engine.mu.Unlock()
	if _, err := engine.Changes(10, 0); err == nil {
		t.Fatal("invalid generation was used in a path join")
	}
}

func TestIntegrityPrunesRetainedGenerations(t *testing.T) {
	engine := newIntegrityTestEngine(t)
	generations := []string{
		"20260101T000000Z-0000000000000001",
		"20260102T000000Z-0000000000000002",
		"20260103T000000Z-0000000000000003",
		"20260104T000000Z-0000000000000004",
		"20260105T000000Z-0000000000000005",
		"20260106T000000Z-0000000000000006",
		"20260107T000000Z-0000000000000007",
	}
	for _, generation := range generations {
		if err := os.Mkdir(filepath.Join(engine.root, "snapshots", generation), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	invalidDir := filepath.Join(engine.root, "snapshots", "do-not-touch")
	if err := os.Mkdir(invalidDir, 0o700); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.status.Generation = generations[len(generations)-1]
	engine.mu.Unlock()
	engine.pruneGenerations(maximumRetainedGenerations)
	remaining := 0
	for _, generation := range generations {
		if _, err := os.Stat(filepath.Join(engine.root, "snapshots", generation)); err == nil {
			remaining++
		}
	}
	if remaining != maximumRetainedGenerations {
		t.Fatalf("retained generations=%d, want %d", remaining, maximumRetainedGenerations)
	}
	if _, err := os.Stat(invalidDir); err != nil {
		t.Fatalf("non-generation directory was pruned: %v", err)
	}
}

func TestIntegrityReparsePointDetection(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if isReparseInfo(info) {
		t.Fatal("plain directory classified as reparse point")
	}
	link := filepath.Join(dir, "junction")
	if err := exec.Command("cmd", "/c", "mklink", "/J", link, dir).Run(); err != nil {
		t.Skipf("junction creation is unavailable in this environment: %v", err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !isReparseInfo(linkInfo) {
		t.Fatal("junction was not detected as a reparse point")
	}
}

func TestIntegrityEvidenceAppendFailureIsSurfaced(t *testing.T) {
	root := t.TempDir()
	ledgerDirectory := filepath.Join(root, "ledger")
	if err := os.MkdirAll(ledgerDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := evidence.Open(filepath.Join(ledgerDirectory, "evidence.jsonl"), filepath.Join(ledgerDirectory, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(filepath.Join(root, "integrity"), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(ledgerDirectory); err != nil {
		t.Fatal(err)
	}
	if err := engine.appendEvidence("integrity.test", "append", "failed"); err == nil {
		t.Fatal("evidence append into a missing directory reported success")
	}
	status := engine.Status()
	if !strings.Contains(status.Error, "evidence ledger append failed") {
		t.Fatalf("evidence append failure was not surfaced in status: %+v", status)
	}
}
