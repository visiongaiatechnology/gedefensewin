// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := New(t.TempDir(), "5.1.0-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

func TestTrustEvaluationSeparatesAuthorizedUnexpectedAndTolerated(t *testing.T) {
	engine := newTestEngine(t)
	engine.record(Observation{Type: EventFileCreated, Severity: SeverityMedium, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\payload.exe`, Name: "payload.exe", SHA256: strings.Repeat("a", 64), FileType: "EXECUTABLE"}})
	engine.record(Observation{Type: EventFileCreated, Severity: SeverityLow, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Documents\report.pdf`, Name: "report.pdf", FileType: "OTHER"}})
	events, total, err := engine.Events(10, 0, FilterAll)
	if err != nil || total != 2 {
		t.Fatalf("events total=%d err=%v", total, err)
	}
	if events[0].Authorization.Status != TrustTolerated {
		t.Fatalf("document event status=%s, want TOLERATED", events[0].Authorization.Status)
	}
	if events[1].Authorization.Status != TrustUnexpected || !events[1].Authorization.NeedsReview {
		t.Fatalf("executable event authorization=%+v, want UNEXPECTED review", events[1].Authorization)
	}
}

func TestMatchingPermitIsAuthorizedAndSingleUse(t *testing.T) {
	engine := newTestEngine(t)
	path := `C:\Users\Operator\Downloads\approved.exe`
	hash := strings.Repeat("b", 64)
	permit, err := engine.policy.AddPermit(path, hash, string(EventFileCreated), time.Hour, true, "Genehmigter Testinstaller")
	if err != nil {
		t.Fatal(err)
	}
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: path, Name: "approved.exe", SHA256: hash, FileType: "EXECUTABLE"}})
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: path, Name: "approved.exe", SHA256: hash, FileType: "EXECUTABLE"}})
	events, _, err := engine.Events(10, 0, FilterAll)
	if err != nil {
		t.Fatal(err)
	}
	if events[1].Authorization.Status != TrustAuthorized || events[1].Authorization.MatchedGrant != permit.ID {
		t.Fatalf("first event authorization=%+v, want permit %s", events[1].Authorization, permit.ID)
	}
	if events[0].Authorization.Status != TrustUnexpected {
		t.Fatalf("second event must not reuse single-use permit: %+v", events[0].Authorization)
	}
}

func TestNotificationsExposeOnlyHighSignalFindings(t *testing.T) {
	engine := newTestEngine(t)
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\payload.exe`, Name: "payload.exe", SHA256: strings.Repeat("d", 64), FileType: "EXECUTABLE"}})
	notifications := engine.Notifications(10)
	if len(notifications) != 1 || notifications[0].Kind != "TITAN_BLOCK" || notifications[0].Severity != SeverityHigh {
		t.Fatalf("unexpected Titan notification projection: %+v", notifications)
	}
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Documents\report.pdf`, Name: "report.pdf", FileType: "OTHER"}})
	for _, notification := range engine.Notifications(10) {
		if strings.Contains(notification.Detail, "report.pdf") {
			t.Fatalf("tolerated content leaked into high-signal notifications: %+v", notification)
		}
	}
}

func TestAcknowledgingFindingsRestoresOwnerPosture(t *testing.T) {
	engine := newTestEngine(t)
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\payload.exe`, Name: "payload.exe", FileType: "EXECUTABLE"}})
	if posture := engine.Status().TrustPosture; posture != TrustUnexpected {
		t.Fatalf("posture=%s, want UNEXPECTED", posture)
	}
	events, _, err := engine.Events(1, 0, FilterAll)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if err := engine.AcknowledgeEvent(events[0].ID, "Befund nach Prüfung als Entwicklungsvorgang bestätigt"); err != nil {
		t.Fatal(err)
	}
	status := engine.Status()
	if status.TrustPosture != TrustTolerated || status.OpenFindings != 0 {
		t.Fatalf("posture=%s open=%d, want TOLERATED/0", status.TrustPosture, status.OpenFindings)
	}
}

func TestDevelopmentRootToleratesSourceArtifactsButNotProtectedChanges(t *testing.T) {
	engine := newTestEngine(t)
	root := `C:\Users\Operator\Projects\MyApp`
	if _, err := engine.AddDevelopmentRoot(root, "Owner markiert den lokalen Projektbaum als Entwicklungsbaum"); err != nil {
		t.Fatal(err)
	}
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: root + `\src\main.go`, Name: "main.go", FileType: "SCRIPT"}})
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\outside.exe`, Name: "outside.exe", FileType: "EXECUTABLE"}})
	events, _, err := engine.Events(10, 0, FilterAll)
	if err != nil {
		t.Fatal(err)
	}
	if events[1].Authorization.Status != TrustTolerated {
		t.Fatalf("development artifact status=%s, want TOLERATED", events[1].Authorization.Status)
	}
	if events[0].Authorization.Status != TrustUnexpected {
		t.Fatalf("outside executable status=%s, want UNEXPECTED", events[0].Authorization.Status)
	}
	if _, err := engine.RemoveDevelopmentRoot(root, "Projektbaum-Markierung nach Abschluss entfernt"); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceStartOnlyIsToleratedButImagePathChangeIsNot(t *testing.T) {
	engine := newTestEngine(t)
	engine.record(Observation{Type: EventPersistenceChanged, Source: "titan-persistence", Health: "HEALTHY",
		Object: Object{Kind: ObjectService, Path: `HKLM\SYSTEM\CurrentControlSet\Services\BITS`, Name: "BITS", Change: "START_ONLY"}})
	engine.record(Observation{Type: EventPersistenceChanged, Source: "titan-persistence", Health: "HEALTHY",
		Object: Object{Kind: ObjectService, Path: `HKLM\SYSTEM\CurrentControlSet\Services\BITS`, Name: "BITS", Change: "IMAGE_PATH"}})
	events, _, err := engine.Events(10, 0, FilterAll)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if events[1].Authorization.Status != TrustTolerated {
		t.Fatalf("BITS start-only status=%s, want TOLERATED", events[1].Authorization.Status)
	}
	if events[0].Authorization.Status != TrustUnexpected {
		t.Fatalf("BITS image-path status=%s, want UNEXPECTED", events[0].Authorization.Status)
	}
}

func TestServiceChangeDistinguishesStartFromImagePath(t *testing.T) {
	base := normalizeServiceFingerprint(`%systemroot%\System32\svchost.exe -k netsvcs -p`, "2", "32", "LocalSystem")
	startOnly := normalizeServiceFingerprint(`%systemroot%\System32\svchost.exe -k netsvcs -p`, "3", "32", "LocalSystem")
	imageChanged := normalizeServiceFingerprint(`C:\Temp\evil.exe`, "2", "32", "LocalSystem")
	if change := serviceChange(base, startOnly); change != "START_ONLY" {
		t.Fatalf("start change=%q", change)
	}
	if change := serviceChange(base, imageChanged); change != "IMAGE_PATH" {
		t.Fatalf("image change=%q", change)
	}
}

func TestNotificationsCoalesceRepeatedIdenticalFindings(t *testing.T) {
	engine := newTestEngine(t)
	observation := Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\payload.exe`, Name: "payload.exe", FileType: "EXECUTABLE"}}
	engine.record(observation)
	engine.record(observation)
	if notifications := engine.Notifications(10); len(notifications) != 1 {
		t.Fatalf("repeated finding produced %d notifications, want 1", len(notifications))
	}
}

func TestAcknowledgeOpenFindingsPagesThroughOlderFindings(t *testing.T) {
	engine := newTestEngine(t)
	for index := 0; index < 105; index++ {
		engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
			Object: Object{Kind: ObjectFile, Path: fmt.Sprintf(`C:\Users\Operator\Downloads\payload-%03d.exe`, index), Name: "payload.exe", FileType: "EXECUTABLE"}})
	}
	reviewed, err := engine.AcknowledgeOpenFindings(100, "Erste Seite historischer Testbefunde nach Owner-Prüfung bestätigt")
	if err != nil || reviewed != 100 {
		t.Fatalf("first page reviewed=%d err=%v", reviewed, err)
	}
	reviewed, err = engine.AcknowledgeOpenFindings(100, "Zweite Seite historischer Testbefunde nach Owner-Prüfung bestätigt")
	if err != nil || reviewed != 5 {
		t.Fatalf("second page reviewed=%d err=%v", reviewed, err)
	}
	if status := engine.Status(); status.OpenFindings != 0 {
		t.Fatalf("open findings=%d, want 0 after two review pages", status.OpenFindings)
	}
}

func TestAcknowledgeOpenFindingsReviewsABoundedPage(t *testing.T) {
	engine := newTestEngine(t)
	for index := 0; index < 3; index++ {
		engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
			Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\payload-` + string(rune('a'+index)) + `.exe`, Name: "payload.exe", FileType: "EXECUTABLE"}})
	}
	reviewed, err := engine.AcknowledgeOpenFindings(2, "Sichtbare Testbefunde nach Prüfung als Entwicklungsvorgang bestätigt")
	if err != nil || reviewed != 2 {
		t.Fatalf("reviewed=%d err=%v", reviewed, err)
	}
	if status := engine.Status(); status.OpenFindings != 1 {
		t.Fatalf("open findings=%d, want 1 after page review", status.OpenFindings)
	}
}

func testFileHash(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

func TestStrictAutoQuarantineIsolatesPlantedExecutable(t *testing.T) {
	engine := newTestEngine(t)
	if _, err := engine.SetPolicy(ModeStrict, true, "Owner aktiviert STRICT mit automatischer Quarantäne für den Release-Betrieb"); err != nil {
		t.Fatal(err)
	}
	// The planted file must live in a path Titan classifies as user ingress.
	// C:\Users\Public is such a path and remains writable in normal Windows
	// test/CI sessions; this keeps the behaviour test independent of GOTMPDIR
	// (Go 1.26 maps t.TempDir() to GOTMPDIR when that variable is set).
	sourceParent := os.Getenv("PUBLIC")
	if sourceParent == "" {
		sourceParent = os.TempDir()
	}
	sourceDir, err := os.MkdirTemp(sourceParent, "vgt-titan-quarantine-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sourceDir) })
	source := filepath.Join(sourceDir, "planted.exe")
	if err := os.WriteFile(source, []byte("titan live auto quarantine test"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: source, Name: "planted.exe", SHA256: testFileHash(t, source), FileType: "EXECUTABLE"}})
	// The race-enabled full-suite gate runs many packages in parallel; the
	// quarantining goroutine can legitimately need more than three seconds under
	// that load. Keep a generous bounded deadline instead of a CI-flaky timeout.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if entries := engine.QuarantineEntries(); len(entries) == 1 {
			if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("planted file was not removed: %v", err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("STRICT auto-quarantine did not create a vault entry")
}

func TestQuarantineRefusesFileSubstitutedAfterObservation(t *testing.T) {
	engine := newTestEngine(t)
	source := filepath.Join(t.TempDir(), "planted.exe")
	if err := os.WriteFile(source, []byte("original payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: source, Name: "planted.exe", SHA256: strings.Repeat("0", 64), FileType: "EXECUTABLE"}})
	events, _, err := engine.Events(1, 0, FilterAll)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if _, err := engine.QuarantineEvent(events[0].ID, "Substitutionstest nach unerwarteter Ablage"); err == nil {
		t.Fatal("quarantine accepted a file that no longer matched the observed hash")
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("mismatched source was removed: %v", err)
	}
}

func TestQuarantineEncryptsRemovesAndRestoresWithHashVerification(t *testing.T) {
	engine := newTestEngine(t)
	source := filepath.Join(t.TempDir(), "planted.exe")
	payload := []byte("titan quarantine roundtrip")
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: source, Name: "planted.exe", SHA256: testFileHash(t, source), FileType: "EXECUTABLE"}})
	events, _, err := engine.Events(1, 0, FilterAll)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	entry, err := engine.QuarantineEvent(events[0].ID, "Isoliertes Testobjekt nach unerwarteter Ablage")
	if err != nil {
		t.Fatal(err)
	}
	if !entry.OriginalGone {
		t.Fatal("quarantine reported a successful isolation but original remains")
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
	entries := engine.QuarantineEntries()
	if len(entries) != 1 || entries[0].SHA256 == "" {
		t.Fatalf("unexpected quarantine entries: %+v", entries)
	}
	restored, err := engine.RestoreQuarantine(entry.ID, "Besitzer hat die Datei nach Prüfung freigegeben")
	if err != nil {
		t.Fatal(err)
	}
	if restored.State != "RESTORED" {
		t.Fatalf("restore state=%q", restored.State)
	}
	restoredPayload, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredPayload) != string(payload) {
		t.Fatalf("restored content mismatch")
	}
	verification := engine.Verify()
	if !verification.Verified {
		t.Fatalf("journal verification failed: %+v", verification)
	}
}

func TestTamperedJournalIsDetected(t *testing.T) {
	engine := newTestEngine(t)
	engine.record(Observation{Type: EventFileCreated, Source: "titan-file-watch", Health: "HEALTHY",
		Object: Object{Kind: ObjectFile, Path: `C:\Users\Operator\Downloads\one.txt`, FileType: "OTHER"}})
	if _, err := engine.journal.Checkpoint(true); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(engine.root, "evidence", "events.jsonl")
	file, err := os.OpenFile(journalPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{\"sequence\":999}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	verification := engine.Verify()
	if verification.Verified {
		t.Fatal("tampered journal was reported as verified")
	}
}

func TestPolicyPersistsAndRejectsObserveWithAutoQuarantine(t *testing.T) {
	root := t.TempDir()
	engine, err := New(root, "5.1.0-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	policy, err := engine.SetPolicy(ModeContain, true, "Operator aktiviert Containment für neue ausführbare Ingest-Objekte")
	if err != nil || policy.Mode != ModeContain || !policy.AutoQuarantine {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	if _, err := engine.SetPolicy(ModeObserve, true, "Beobachten ohne automatische Quarantäne"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPolicyStore(filepath.Join(root, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Current(); got.Mode != ModeObserve || got.AutoQuarantine {
		t.Fatalf("persisted policy=%+v", got)
	}
}

func TestRunStopsSensorsAndKeepsStatusHonest(t *testing.T) {
	root := t.TempDir()
	engine, err := New(root, "5.1.0-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		engine.Run(stop)
		close(done)
	}()
	time.Sleep(250 * time.Millisecond)
	status := engine.Status()
	if status.State != "OBSERVING" && status.State != "DEGRADED" {
		t.Fatalf("unexpected running state: %s", status.State)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Titan run did not stop")
	}
	_ = engine.Close()
}

func TestEngineRejectsInvalidRoot(t *testing.T) {
	if _, err := New("relative", "5.1.0", nil); err == nil {
		t.Fatal("relative Titan root accepted")
	}
}
