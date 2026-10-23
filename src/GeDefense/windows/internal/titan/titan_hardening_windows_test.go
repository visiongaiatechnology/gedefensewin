// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func createTestJunction(link, target string) error {
	command := exec.Command("cmd", "/c", "mklink", "/J", link, target)
	return command.Run()
}

func TestZoneIdentifierADSReadIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "downloaded.exe")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, 256<<10)
	for index := range large {
		large[index] = 'A'
	}
	if err := os.WriteFile(path+":Zone.Identifier", large, 0o600); err != nil {
		t.Skipf("ADS creation is unavailable in this environment: %v", err)
	}
	if zone := readZoneIdentifier(path); zone != "" {
		t.Fatalf("oversized Zone.Identifier ADS produced %q, want empty", zone)
	}
	small := []byte("[ZoneTransfer]\r\nZoneId=3\r\n")
	if err := os.WriteFile(path+":Zone.Identifier", small, 0o600); err != nil {
		t.Fatal(err)
	}
	if zone := readZoneIdentifier(path); zone != "3" {
		t.Fatalf("bounded Zone.Identifier read=%q, want 3", zone)
	}
}

func TestFileSensorFloodSetsOverflowAndRateLimitedNotice(t *testing.T) {
	engine := newTestEngine(t)
	sensor := newFileSensor(engine)
	base := filepath.Join(t.TempDir(), "flood")
	for index := 0; index < maxPendingChanges+128; index++ {
		sensor.schedule(filepath.Join(base, fmt.Sprintf("event-%05d.tmp", index)), 1)
	}
	status := engine.Status()
	if status.WatcherOverflows == 0 {
		t.Fatal("watcher flood was not counted as an overflow")
	}
	sensor.mu.Lock()
	dropped := sensor.dropped
	sensor.mu.Unlock()
	if dropped == 0 {
		t.Fatal("watcher flood did not record dropped pending events")
	}
}

func TestWatcherBoundaryErrorIsClassifiedAsOverflowSymptom(t *testing.T) {
	if !isWatcherBoundaryError(fmt.Errorf("directory watcher event boundary exceeded")) {
		t.Fatal("watcher boundary error was not classified as an overflow symptom")
	}
	if isWatcherBoundaryError(nil) || isWatcherBoundaryError(fmt.Errorf("other error")) {
		t.Fatal("watcher boundary classification is not specific")
	}
}
