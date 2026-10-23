// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withJournalTestTuning(t *testing.T, rotateBytes, checkpointStoreBytes int64) {
	t.Helper()
	previousRotate := journalRotateBytes
	previousCheckpoint := checkpointStoreRotateBytes
	previousClockTolerance := journalClockTolerance
	journalRotateBytes = rotateBytes
	checkpointStoreRotateBytes = checkpointStoreBytes
	journalClockTolerance = 5 * time.Minute
	t.Cleanup(func() {
		journalRotateBytes = previousRotate
		checkpointStoreRotateBytes = previousCheckpoint
		journalClockTolerance = previousClockTolerance
	})
}

func TestJournalCheckpointStoreLoadsBeyondLegacyLimit(t *testing.T) {
	engine := newTestEngine(t)
	journal := engine.journal
	path := filepath.Join(journal.root, checkpointPathName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= journalRingLimit+4; index++ {
		checkpoint := Checkpoint{
			Sequence: uint64(index), LastHash: strings.Repeat("a", 64), CreatedUTC: time.Now().UTC(),
			BootID: journal.bootID, PublicKeySHA256: journal.publicSHA256,
		}
		checkpoint.Signature = hex.EncodeToString(ed25519.Sign(journal.privateKey, checkpointMessage(checkpoint)))
		line, marshalErr := json.Marshal(checkpoint)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err := file.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := &Journal{root: journal.root, privateKey: journal.privateKey, publicKey: journal.publicKey, publicSHA256: journal.publicSHA256}
	if err := fresh.loadCheckpoints(); err != nil {
		t.Fatalf("checkpoint store with %d signed entries was rejected: %v", journalRingLimit+4, err)
	}
	if len(fresh.checkpoints) == 0 || len(fresh.checkpoints) > journalRingLimit {
		t.Fatalf("loaded checkpoint ring=%d, want 1..%d", len(fresh.checkpoints), journalRingLimit)
	}
}

func TestJournalCorruptCheckpointTailIsQuarantinedAndRepaired(t *testing.T) {
	root := t.TempDir()
	journal, err := OpenJournal(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, err := journal.Append(Observation{Type: EventSensorHealth, Severity: SeverityLow,
			Object: Object{Kind: ObjectSensor, Path: "titan://test", Name: fmt.Sprintf("event-%d", index)},
			Source: "titan-self", Health: "HEALTHY"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.Checkpoint(true); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(root, checkpointPathName)
	file, err := os.OpenFile(storePath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{\"sequence\":999\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_ = journal.Close()
	reopened, err := OpenJournal(root, nil)
	if err != nil {
		t.Fatalf("corrupt checkpoint tail bricked the journal: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if reopened.journalBad {
		t.Fatalf("corrupt checkpoint tail marked the journal bad: %s", reopened.Error())
	}
	if verification := reopened.Verify(); !verification.Verified {
		t.Fatalf("journal did not verify after checkpoint repair: %+v", verification)
	}
	forensics, err := filepath.Glob(filepath.Join(root, "checkpoints.corrupt-*.jsonl"))
	if err != nil || len(forensics) == 0 {
		t.Fatalf("corrupt checkpoint store was not preserved: %v %v", forensics, err)
	}
	if _, err := reopened.Append(Observation{Type: EventSensorHealth, Severity: SeverityLow,
		Object: Object{Kind: ObjectSensor, Path: "titan://test", Name: "after-repair"},
		Source: "titan-self", Health: "HEALTHY"}); err != nil {
		t.Fatalf("append after checkpoint repair: %v", err)
	}
}

func TestJournalRotationArchivesAndVerifies(t *testing.T) {
	withJournalTestTuning(t, 2048, 4<<20)
	root := t.TempDir()
	journal, err := OpenJournal(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 24; index++ {
		if _, err := journal.Append(Observation{Type: EventSensorHealth, Severity: SeverityLow,
			Object: Object{Kind: ObjectSensor, Path: "titan://rotation", Name: fmt.Sprintf("event-%02d", index)},
			Source: "titan-self", Health: "HEALTHY"}); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	manifests, err := filepath.Glob(filepath.Join(root, journalArchiveDirName, "archive-*.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("journal rotation produced no signed archive manifests: %v %v", manifests, err)
	}
	if verification := journal.Verify(); !verification.Verified {
		t.Fatalf("verify after rotation: %+v", verification)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(root, nil)
	if err != nil {
		t.Fatalf("reopen rotated journal: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if verification := reopened.Verify(); !verification.Verified {
		t.Fatalf("verify after reopen: %+v", verification)
	}
	if reopened.Count() != 24 {
		t.Fatalf("event count after rotation=%d, want 24", reopened.Count())
	}
	if _, err := reopened.Append(Observation{Type: EventSensorHealth, Severity: SeverityLow,
		Object: Object{Kind: ObjectSensor, Path: "titan://rotation", Name: "after-rotation"},
		Source: "titan-self", Health: "HEALTHY"}); err != nil {
		t.Fatalf("append after rotation reopen: %v", err)
	}
	if verification := reopened.Verify(); !verification.Verified {
		t.Fatalf("verify after post-rotation append: %+v", verification)
	}
}

func TestJournalMarksClockRollbackWithoutDroppingEvidence(t *testing.T) {
	withJournalTestTuning(t, 64<<20, 4<<20)
	previousNow := journalNow
	base := time.Now().UTC()
	journalNow = func() time.Time { return base }
	t.Cleanup(func() { journalNow = previousNow })
	journal, err := OpenJournal(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	first, err := journal.Append(Observation{Type: EventSensorHealth, Severity: SeverityLow,
		Object: Object{Kind: ObjectSensor, Path: "titan://clock", Name: "first"}, Source: "titan-self", Health: "HEALTHY"})
	if err != nil {
		t.Fatal(err)
	}
	if first.TimeSource != journalTimeSourceWall {
		t.Fatalf("first event time source=%q", first.TimeSource)
	}
	journalNow = func() time.Time { return base.Add(-2 * time.Hour) }
	second, err := journal.Append(Observation{Type: EventSensorHealth, Severity: SeverityLow,
		Object: Object{Kind: ObjectSensor, Path: "titan://clock", Name: "second"}, Source: "titan-self", Health: "HEALTHY"})
	if err != nil {
		t.Fatal(err)
	}
	if second.TimeSource != journalTimeSourceClock {
		t.Fatalf("rolled-back event time source=%q, want %q", second.TimeSource, journalTimeSourceClock)
	}
	if !journal.ClockRollbackDetected() {
		t.Fatal("clock rollback was not recorded")
	}
	if journal.Error() == "" {
		t.Fatal("clock rollback did not surface a degraded journal detail")
	}
}

func TestSecretKeysLiveInDedicatedKeyDirectories(t *testing.T) {
	engine := newTestEngine(t)
	for _, path := range []string{
		filepath.Join(engine.root, "evidence", "keys", signingKeyName),
		filepath.Join(engine.root, "quarantine", "keys", vaultKeyName),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("protected key file missing at %s: %v", path, err)
		}
		if info.Mode().IsDir() {
			t.Fatalf("key path is a directory: %s", path)
		}
	}
	for _, legacy := range []string{
		filepath.Join(engine.root, "evidence", signingKeyName),
		filepath.Join(engine.root, "quarantine", vaultKeyName),
	} {
		if _, err := os.Stat(legacy); err == nil {
			t.Fatalf("legacy unprotected key location still present: %s", legacy)
		}
	}
}

func TestVaultEnforcesEntryAndByteQuota(t *testing.T) {
	engine := newTestEngine(t)
	vault := engine.vault
	vault.maxEntries = 2
	work := t.TempDir()
	reason := "Quarantäne im Quota-Härtungstest für Titan"
	for index := 0; index < 2; index++ {
		path := filepath.Join(work, fmt.Sprintf("sample-%d.exe", index))
		if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := vault.Add(path, reason, ""); err != nil {
			t.Fatalf("quarantine %d: %v", index, err)
		}
	}
	third := filepath.Join(work, "sample-2.exe")
	if err := os.WriteFile(third, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Add(third, reason, ""); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("vault accepted a third object past the entry quota: %v", err)
	}
	if _, err := os.Stat(third); err != nil {
		t.Fatalf("quota rejection removed the original file: %v", err)
	}
	entries, bytes := vault.Usage()
	if entries != 2 || bytes != 128 {
		t.Fatalf("usage entries=%d bytes=%d", entries, bytes)
	}
}

func TestVaultMetadataTamperIsRejected(t *testing.T) {
	engine := newTestEngine(t)
	vault := engine.vault
	work := t.TempDir()
	path := filepath.Join(work, "sample.exe")
	if err := os.WriteFile(path, []byte("tamper me"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := vault.Add(path, "Quarantäne im Metadaten-Härtungstest", "")
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(vault.root, entry.ID+".json")
	tampered := entry
	tampered.OriginalPath = filepath.Join(work, "redirected.exe")
	tamperedRaw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, append(tamperedRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(entry.ID, "Besitzer versucht Wiederherstellung nach Tamper-Test"); err == nil {
		t.Fatal("restore accepted tampered, unauthenticated metadata")
	}
}

func TestVaultRecoversOriginalGoneAfterCrashWindow(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	vault, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	path := filepath.Join(work, "sample.exe")
	if err := os.WriteFile(path, []byte("crash window"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := vault.Add(path, "Quarantäne im Crash-Fenster-Härtungstest", "")
	if err != nil {
		t.Fatal(err)
	}
	if !entry.OriginalGone {
		t.Fatal("original was not removed")
	}
	// Simulate a crash between os.Remove and persisting OriginalGone=true.
	entry.OriginalGone = false
	if err := vault.writeMetadata(entry); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.readMetadata(entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.OriginalGone {
		t.Fatal("OriginalGone was not recovered after the crash window")
	}
	if _, err := reopened.Restore(entry.ID, "Besitzer stellt Objekt nach Crash-Recovery wieder her"); err != nil {
		t.Fatalf("restore after crash recovery: %v", err)
	}
}

func TestPermitConsumptionFailsClosedOnClockRollback(t *testing.T) {
	engine := newTestEngine(t)
	path := `C:\Users\Operator\Downloads\approved.exe`
	now := time.Now().UTC()
	if _, err := engine.policy.AddPermit(path, "", "ALLOW_CHANGE", time.Hour, false, "Freigabe im Uhr-Rollback-Härtungstest"); err != nil {
		t.Fatal(err)
	}
	if permit := engine.policy.ConsumePermit(path, "", "ALLOW_CHANGE", now); permit == nil {
		t.Fatal("permit was not consumed at the trusted clock")
	}
	if permit := engine.policy.ConsumePermit(path, "", "ALLOW_CHANGE", now.Add(-2*time.Hour)); permit != nil {
		t.Fatal("permit was honored after a wall-clock rollback")
	}
	if !engine.policy.ClockRollbackDetected() {
		t.Fatal("clock rollback was not recorded by the permit store")
	}
}

func TestVaultRestoreTargetParentReparseIsRejected(t *testing.T) {
	engine := newTestEngine(t)
	vault := engine.vault
	work := t.TempDir()
	link := filepath.Join(work, "junction")
	target := filepath.Join(work, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := createTestJunction(link, target); err != nil {
		t.Skipf("junction creation is unavailable in this environment: %v", err)
	}
	source := filepath.Join(link, "sample.exe")
	if err := os.WriteFile(source, []byte("through junction"), 0o600); err != nil {
		t.Skipf("writing through a junction is unavailable: %v", err)
	}
	entry, err := vault.Add(source, "Quarantäne durch Junction im Restore-Ziel-Härtungstest", "")
	if err != nil {
		t.Fatalf("quarantine through junction: %v", err)
	}
	// The tracked original path now traverses a reparse point; restore must
	// refuse instead of writing through the swapped directory.
	if _, err := vault.Restore(entry.ID, "Besitzer versucht Wiederherstellung durch Junction"); err == nil {
		t.Fatal("restore accepted a target whose parent chain contains a junction")
	}
}
