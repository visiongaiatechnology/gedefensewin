// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDirectoryWatcherReceivesCreation(t *testing.T) {
	directory := t.TempDir()
	watcher, err := OpenDirectoryWatcher(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watcher.Close() }()
	target := filepath.Join(directory, "arrival.txt")
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = os.WriteFile(target, []byte("observed"), 0o600)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		changes, err := watcher.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range changes {
			if filepath.Clean(change.Path) == filepath.Clean(target) {
				return
			}
		}
	}
}

func TestProcessListIsBoundedAndNonEmpty(t *testing.T) {
	processes, err := ProcessList()
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) == 0 || len(processes) > maxProcesses {
		t.Fatalf("process count=%d", len(processes))
	}
	for _, process := range processes {
		if process.PID == 0 || process.Image == "" {
			t.Fatalf("invalid process entry: %+v", process)
		}
	}
}
