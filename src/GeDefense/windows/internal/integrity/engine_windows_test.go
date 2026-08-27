// STATUS: DIAMANT VGT SUPREME
//go:build windows

package integrity

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
)

func TestPartitionedGenerationDiff(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(filepath.Join(root, "integrity"), ledger)
	if err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(engine.root, "snapshots", "previous")
	current := filepath.Join(engine.root, "snapshots", "current")
	createBucketSet(t, previous, []FileRecord{
		{Path: `C:\stable.dll`, Size: 10, SHA256: repeatedHash('a')},
		{Path: `C:\modified.dll`, Size: 11, SHA256: repeatedHash('b')},
		{Path: `C:\deleted.dll`, Size: 12, SHA256: repeatedHash('c')},
	})
	createBucketSet(t, current, []FileRecord{
		{Path: `C:\stable.dll`, Size: 10, SHA256: repeatedHash('a')},
		{Path: `C:\modified.dll`, Size: 13, SHA256: repeatedHash('d')},
		{Path: `C:\added.dll`, Size: 14, SHA256: repeatedHash('e')},
	})
	added, modified, deleted, stored, err := engine.compare("previous", current)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || modified != 1 || deleted != 1 || stored != 3 {
		t.Fatalf("unexpected diff counts: added=%d modified=%d deleted=%d stored=%d", added, modified, deleted, stored)
	}
	engine.mu.Lock()
	engine.status.Generation = "current"
	engine.mu.Unlock()
	changes, err := engine.Changes(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 {
		t.Fatalf("got %d changes, want 3", len(changes))
	}
}

func TestIntegrityConfigurationBoundaries(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(filepath.Join(root, "integrity"), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Configure(true, 13); err == nil {
		t.Fatal("unsupported interval was accepted")
	}
	status, err := engine.Configure(false, 12)
	if err != nil {
		t.Fatal(err)
	}
	if status.Enabled || status.IntervalHours != 12 || status.State != "DISABLED" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func createBucketSet(t *testing.T, directory string, records []FileRecord) {
	t.Helper()
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	files := make([]*os.File, bucketCount)
	writers := make([]*bufio.Writer, bucketCount)
	for index := 0; index < bucketCount; index++ {
		file, err := os.OpenFile(filepath.Join(directory, bucketName(index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		files[index] = file
		writers[index] = bufio.NewWriter(file)
	}
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writers[pathBucket(record.Path)].Write(append(payload, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := closeBucketFiles(files, writers); err != nil {
		t.Fatal(err)
	}
}

func bucketName(index int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[index>>4], digits[index&15]}) + ".jsonl"
}

func repeatedHash(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return string(result)
}
