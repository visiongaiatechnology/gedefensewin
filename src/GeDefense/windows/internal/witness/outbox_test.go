// STATUS: PLATIN VGT SUPREME

package witness

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestOutbox(t *testing.T) (*Outbox, string, []byte) {
	t.Helper()
	key, err := GenerateOutboxKey()
	if err != nil {
		t.Fatalf("GenerateOutboxKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "outbox.enc")
	outbox, err := OpenOutbox(path, key, testHostID)
	if err != nil {
		t.Fatalf("OpenOutbox: %v", err)
	}
	return outbox, path, key
}

func TestOutboxRoundTripAndFIFO(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	first := signedTestCheckpointAt(t, provider, 1)
	second := signedTestCheckpointAt(t, provider, 2)
	outbox, path, key := newTestOutbox(t)

	sequence, err := outbox.Append(first)
	if err != nil {
		t.Fatalf("append first: %v", err)
	}
	if sequence != 1 {
		t.Fatalf("first local sequence is %d, want 1", sequence)
	}
	sequence, err = outbox.Append(second)
	if err != nil {
		t.Fatalf("append second: %v", err)
	}
	if sequence != 2 {
		t.Fatalf("second local sequence is %d, want 2", sequence)
	}
	if outbox.Depth() != 2 || outbox.Bytes() <= 0 || outbox.Full() || outbox.Corrupt() {
		t.Fatalf("unexpected outbox state: depth=%d bytes=%d full=%t corrupt=%t",
			outbox.Depth(), outbox.Bytes(), outbox.Full(), outbox.Corrupt())
	}
	entries := outbox.Pending()
	if len(entries) != 2 || entries[0].LocalSequence != 1 || entries[1].LocalSequence != 2 {
		t.Fatalf("pending order is %+v", entries)
	}
	if entries[0].Checkpoint.CheckpointID != first.CheckpointID {
		t.Fatal("pending entry does not carry the appended checkpoint")
	}
	// Mutating the returned copy must not mutate the outbox.
	entries[0].Checkpoint.CheckpointID = "mutated"
	if outbox.Pending()[0].Checkpoint.CheckpointID != first.CheckpointID {
		t.Fatal("Pending exposed internal state")
	}
	last, ok := outbox.LastCheckpoint()
	if !ok || last.CheckpointID != second.CheckpointID {
		t.Fatal("LastCheckpoint is not the newest queued checkpoint")
	}

	reopened, err := OpenOutbox(path, key, testHostID)
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	if reopened.Depth() != 2 {
		t.Fatalf("reopened depth is %d", reopened.Depth())
	}
	reopenedLast, ok := reopened.LastCheckpoint()
	if !ok || reopenedLast.CheckpointID != second.CheckpointID {
		t.Fatal("reopened outbox lost the newest checkpoint")
	}
}

func TestOutboxNonceIsFreshPerWrite(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	outbox, path, _ := newTestOutbox(t)
	nonces := make(map[string]struct{})
	for sequence := uint64(1); sequence <= 3; sequence++ {
		if _, err := outbox.Append(signedTestCheckpointAt(t, provider, sequence)); err != nil {
			t.Fatalf("append %d: %v", sequence, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read outbox: %v", err)
		}
		if len(raw) < outboxEnvelopeSize {
			t.Fatalf("sealed outbox is too short: %d", len(raw))
		}
		if !bytes.Equal(raw[:4], outboxMagic[:]) || raw[4] != outboxVersion {
			t.Fatal("sealed outbox header is not the expected magic/version")
		}
		nonce := string(raw[outboxHeaderBytes : outboxHeaderBytes+outboxNonceBytes])
		if _, reused := nonces[nonce]; reused {
			t.Fatal("AES-GCM nonce was reused across writes")
		}
		nonces[nonce] = struct{}{}
	}
}

func TestOutboxDedupe(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 1)
	outbox, _, _ := newTestOutbox(t)
	if _, err := outbox.Append(checkpoint); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := outbox.Append(checkpoint); !errors.Is(err, ErrOutboxDuplicate) {
		t.Fatalf("duplicate append error is %v", err)
	}
	if outbox.Depth() != 1 {
		t.Fatalf("duplicate append changed depth to %d", outbox.Depth())
	}
}

func TestOutboxAckAndRecordAttemptPersist(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	first := signedTestCheckpointAt(t, provider, 1)
	second := signedTestCheckpointAt(t, provider, 2)
	outbox, path, key := newTestOutbox(t)
	if _, err := outbox.Append(first); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if _, err := outbox.Append(second); err != nil {
		t.Fatalf("append second: %v", err)
	}
	next := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := outbox.RecordAttempt(2, 3, next); err != nil {
		t.Fatalf("record attempt: %v", err)
	}
	if err := outbox.Ack(1); err != nil {
		t.Fatalf("ack first: %v", err)
	}
	if err := outbox.Ack(1); !errors.Is(err, ErrOutboxEntryMissing) {
		t.Fatalf("second ack error is %v", err)
	}
	reopened, err := OpenOutbox(path, key, testHostID)
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	entries := reopened.Pending()
	if len(entries) != 1 {
		t.Fatalf("reopened depth is %d, want 1", len(entries))
	}
	if entries[0].LocalSequence != 2 || entries[0].Attempts != 3 || !entries[0].NextAttemptUTC.Equal(next) {
		t.Fatalf("attempt bookkeeping was not persisted: %+v", entries[0])
	}
	if _, ok := reopened.NextDue(next.Add(-time.Second)); ok {
		t.Fatal("NextDue returned an entry before its next attempt time")
	}
	if entry, ok := reopened.NextDue(next); !ok || entry.LocalSequence != 2 {
		t.Fatal("NextDue did not return the due entry")
	}
}

func TestOutboxCorruptionFailsClosed(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 1)
	t.Run("garbage document", func(t *testing.T) {
		key, err := GenerateOutboxKey()
		if err != nil {
			t.Fatalf("GenerateOutboxKey: %v", err)
		}
		path := filepath.Join(t.TempDir(), "outbox.enc")
		if err := os.WriteFile(path, []byte("not an outbox"), 0o600); err != nil {
			t.Fatalf("write garbage: %v", err)
		}
		outbox, err := OpenOutbox(path, key, testHostID)
		if !errors.Is(err, ErrOutboxCorrupt) || outbox == nil || !outbox.Corrupt() {
			t.Fatalf("OpenOutbox error is %v, outbox=%v", err, outbox)
		}
		if _, err := outbox.Append(checkpoint); !errors.Is(err, ErrOutboxCorrupt) {
			t.Fatalf("append to corrupt outbox error is %v", err)
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		outbox, path, key := newTestOutbox(t)
		if _, err := outbox.Append(checkpoint); err != nil {
			t.Fatalf("append: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read outbox: %v", err)
		}
		raw[len(raw)-1] ^= 0x01
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write tampered outbox: %v", err)
		}
		if _, err := OpenOutbox(path, key, testHostID); !errors.Is(err, ErrOutboxCorrupt) {
			t.Fatalf("tampered outbox error is %v", err)
		}
	})
	t.Run("wrong key or host", func(t *testing.T) {
		outbox, path, key := newTestOutbox(t)
		if _, err := outbox.Append(checkpoint); err != nil {
			t.Fatalf("append: %v", err)
		}
		otherKey, err := GenerateOutboxKey()
		if err != nil {
			t.Fatalf("GenerateOutboxKey: %v", err)
		}
		if _, err := OpenOutbox(path, otherKey, testHostID); !errors.Is(err, ErrOutboxCorrupt) {
			t.Fatalf("wrong key error is %v", err)
		}
		if _, err := OpenOutbox(path, key, "other-host"); !errors.Is(err, ErrOutboxCorrupt) {
			t.Fatalf("wrong host AAD error is %v", err)
		}
	})
	t.Run("oversized document", func(t *testing.T) {
		key, err := GenerateOutboxKey()
		if err != nil {
			t.Fatalf("GenerateOutboxKey: %v", err)
		}
		path := filepath.Join(t.TempDir(), "outbox.enc")
		if err := os.WriteFile(path, bytes.Repeat([]byte{0x00}, OutboxMaxFileBytes+1), 0o600); err != nil {
			t.Fatalf("write oversized outbox: %v", err)
		}
		if _, err := OpenOutbox(path, key, testHostID); !errors.Is(err, ErrOutboxCorrupt) {
			t.Fatalf("oversized outbox error is %v", err)
		}
	})
	t.Run("crash leftover temp file is ignored", func(t *testing.T) {
		outbox, path, key := newTestOutbox(t)
		if _, err := outbox.Append(checkpoint); err != nil {
			t.Fatalf("append: %v", err)
		}
		tempPath := filepath.Join(filepath.Dir(path), ".witness-outbox-crash.tmp")
		if err := os.WriteFile(tempPath, []byte("partial write"), 0o600); err != nil {
			t.Fatalf("write leftover temp file: %v", err)
		}
		reopened, err := OpenOutbox(path, key, testHostID)
		if err != nil {
			t.Fatalf("reopen despite leftover temp file: %v", err)
		}
		if reopened.Depth() != 1 {
			t.Fatalf("reopened depth is %d", reopened.Depth())
		}
	})
}

func TestOutboxBounds(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 1)
	outbox, _, _ := newTestOutbox(t)
	outbox.mu.Lock()
	outbox.bytes = OutboxMaxFileBytes
	outbox.mu.Unlock()
	if !outbox.Full() {
		t.Fatal("outbox at the byte bound is not full")
	}
	if _, err := outbox.Append(checkpoint); !errors.Is(err, ErrOutboxFull) {
		t.Fatalf("append to full outbox error is %v", err)
	}
	outbox.mu.Lock()
	outbox.bytes = 0
	outbox.entries = make([]OutboxEntry, OutboxMaxEntries)
	outbox.mu.Unlock()
	if !outbox.Full() {
		t.Fatal("outbox at the entry bound is not full")
	}
	if _, err := outbox.Append(checkpoint); !errors.Is(err, ErrOutboxFull) {
		t.Fatalf("append at the entry bound error is %v", err)
	}
}

func TestOutboxCreatesParentDirectory(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	key, err := GenerateOutboxKey()
	if err != nil {
		t.Fatalf("GenerateOutboxKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "witness", "outbox.enc")
	outbox, err := OpenOutbox(path, key, testHostID)
	if err != nil {
		t.Fatalf("OpenOutbox: %v", err)
	}
	if _, err := outbox.Append(signedTestCheckpointAt(t, provider, 1)); err != nil {
		t.Fatalf("append into a fresh directory: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("outbox file was not created: %v", err)
	}
}

func TestOutboxLocking(t *testing.T) {
	provider, _ := newTestKeyProvider(t)
	checkpoint := signedTestCheckpointAt(t, provider, 1)
	outbox, path, _ := newTestOutbox(t)
	lockPath := path + outboxLockSuffix
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("create lock: %v", err)
	}
	if _, err := outbox.Append(checkpoint); !errors.Is(err, ErrOutboxLocked) {
		t.Fatalf("append with a fresh lock error is %v", err)
	}
	stale := time.Now().Add(-2 * outboxLockStale)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatalf("age lock file: %v", err)
	}
	if _, err := outbox.Append(checkpoint); err != nil {
		t.Fatalf("append with a stale lock: %v", err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file was not released: %v", err)
	}
}
