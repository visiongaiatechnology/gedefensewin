// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistenceBaselineIsMeasuredWithoutSyntheticFindings(t *testing.T) {
	engine := newTestEngine(t)
	engine.scanPersistence(context.Background())
	status := engine.Status()
	if len(status.SecurityControls) < 8 {
		t.Fatalf("security controls measured=%d, want at least 8", len(status.SecurityControls))
	}
	if status.Boot.CheckedUTC.IsZero() {
		t.Fatal("boot measurement timestamp is missing")
	}
	if status.Sensors[2].State != SensorHealthy {
		t.Fatalf("persistence sensor state=%s, want HEALTHY", status.Sensors[2].State)
	}
}

func TestDefaultWatchRootsAreAbsoluteAndBounded(t *testing.T) {
	engine := newTestEngine(t)
	roots := engine.defaultWatchRoots()
	if len(roots) == 0 || len(roots) > 64 {
		t.Fatalf("watch roots=%d, want 1..64", len(roots))
	}
	for _, root := range roots {
		if !filepath.IsAbs(root.Path) {
			t.Fatalf("watch root is not absolute: %s", root.Path)
		}
		if !root.Active {
			t.Fatalf("watch root is inactive after stat: %s", root.Path)
		}
	}
}

func TestFileSensorCapturesStableContentAfterDebounce(t *testing.T) {
	engine := newTestEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.consume(ctx)
	dir := t.TempDir()
	path := filepath.Join(dir, "arrived.exe")
	if err := os.WriteFile(path, []byte("titan"), 0o600); err != nil {
		t.Fatal(err)
	}
	sensor := newFileSensor(engine)
	sensor.schedule(path, 1)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		events, _, err := engine.Events(10, 0, FilterAll)
		if err == nil {
			for _, event := range events {
				if strings.EqualFold(event.Object.Path, path) {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("file sensor did not record the created executable")
}

func TestKnownTelemetryNoiseDoesNotCreateIngressAlerts(t *testing.T) {
	for _, testCase := range []struct {
		path, fileType string
		expected       bool
	}{
		{`C:\WINDOWS\System32\drivers\DriverData\AMD\MmdDumps\R-gpu.log`, "OTHER", true},
		{`C:\Users\Operator\AppData\Local\Temp\__PSScriptPolicyTest_abc.ps1`, "SCRIPT", true},
		{`C:\Users\Operator\AppData\Local\Temp\chrome.png`, "OTHER", true},
		{`C:\Users\Operator\AppData\Local\Temp\dropped.ps1`, "SCRIPT", false},
		{`C:\Users\Operator\Downloads\installer.exe`, "EXECUTABLE", false},
	} {
		if actual := isKnownTelemetryNoise(testCase.path, testCase.fileType); actual != testCase.expected {
			t.Fatalf("noise(%q,%q)=%t, want %t", testCase.path, testCase.fileType, actual, testCase.expected)
		}
	}
}

func TestTemporaryPathsAreRecognizedForDeletionSuppression(t *testing.T) {
	for _, path := range []string{
		`C:\Users\Operator\AppData\Local\Temp\go-build123\b001\exe\a.out.exe`,
		`C:\WINDOWS\Temp\installer.tmp`,
	} {
		if !isTemporaryPath(path) {
			t.Fatalf("temporary path not recognized: %s", path)
		}
	}
	if isTemporaryPath(`C:\Users\Operator\Downloads\installer.exe`) {
		t.Fatal("downloads path was classified as temporary")
	}
}

func TestSystemLogIsNotAnIngressEscalation(t *testing.T) {
	engine := newTestEngine(t)
	engine.record(Observation{Type: EventFileModified, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Windows\System32\drivers\DriverData\AMD\MmdDumps\R-gpu.log`, Name: "R-gpu.log", FileType: "OTHER"}})
	events, _, err := engine.Events(10, 0, FilterAll)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if events[0].Authorization.Status != TrustTolerated {
		t.Fatalf("system telemetry status=%s, want TOLERATED", events[0].Authorization.Status)
	}
}

func TestServiceFingerprintNormalizesRepresentationOnlyDrift(t *testing.T) {
	left := normalizeServiceFingerprint(`C:\WINDOWS\System32\svchost.exe -k netsvcs -p`, "2", "32", "LocalSystem")
	right := normalizeServiceFingerprint(`%systemroot%\System32\svchost.exe -k netsvcs -p`, "2", "32", "LocalSystem")
	if left != right {
		t.Fatalf("service normalization drift: %q != %q", left, right)
	}
	if normalizeServiceFingerprint(`C:\Windows\System32\svchost.exe -k netsvcs -p`, "3", "32", "LocalSystem") == left {
		t.Fatal("service normalization hid a start-mode change")
	}
}
