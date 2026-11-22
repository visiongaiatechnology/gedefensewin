// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

func TestArtifactOracleEscalatesUnexpectedDropToCompromised(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(filepath.Join(root, "titan"), "6.0.0", ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = engine.Close() }()

	if _, err := engine.SetPolicy(ModeContain, false, "enable contain with oracle verification"); err != nil {
		t.Fatal(err)
	}

	dropDir := filepath.Join(root, "downloads")
	if err := os.MkdirAll(dropDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sample := filepath.Join(dropDir, "payload.exe")
	if err := os.WriteFile(sample, []byte("MZ-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	oracleCalled := make(chan string, 1)
	engine.SetArtifactOracle(func(_ context.Context, path string) (bool, string, error) {
		oracleCalled <- path
		return true, "Trojan:Win32/TestOracle", nil
	})

	err = engine.record(Observation{
		Type:     EventFileCreated,
		Severity: SeverityHigh,
		Source:   "titan-file-watch",
		Object:   Object{Kind: ObjectFile, Path: sample, Name: "payload.exe", FileType: "EXECUTABLE"},
	})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case scanned := <-oracleCalled:
		if scanned != sample {
			t.Fatalf("unexpected oracle target: %q", scanned)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Titan did not invoke registered Defender artifact oracle")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, _, _ := engine.Events(20, 0, FilterAll)
		for _, item := range events {
			if item.Collection.Source == "titan-defender-oracle" && item.Authorization.Status == TrustCompromised {
				return
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("Defender oracle detection was not recorded as TrustCompromised in Titan journal")
}
