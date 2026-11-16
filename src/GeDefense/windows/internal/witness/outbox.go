// STATUS: PLATIN VGT SUPREME

package witness

// Bounded, authenticated witness outbox (witness/outbox.enc).
//
// The outbox is the only place an unacknowledged checkpoint survives a crash or
// restart. It is one AES-256-GCM document with a versioned binary envelope
// (magic, version, 12-byte nonce, ciphertext) whose AAD binds the prefix
// "outbox-v1" and the host id, so a file copied to another host or a document
// replayed under another purpose fails authentication. Entries are FIFO by local
// sequence, deduplicated by checkpoint id, bounded to 1024 entries and 4 MiB, and
// removed only after a verified push acknowledgement.
//
// Writes are crash-safe: the new sealed document is written to a temporary file in
// the same directory, flushed, fsynced, closed and atomically renamed over the
// previous file. Memory is advanced only after the rename succeeded, so a failed
// or interrupted write loses nothing. A per-document lock file guards against a
// second writer process; a fresh lock is honoured, a stale one is replaced.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	outboxSchema = "vgt-gedefense-witness-outbox-v1"
	// OutboxMaxEntries is the hard entry bound of one outbox document.
	OutboxMaxEntries = 1024
	// OutboxMaxFileBytes is the hard sealed-document bound (4 MiB).
	OutboxMaxFileBytes = 4 << 20

	outboxKeyBytes     = 32
	outboxNonceBytes   = 12
	outboxAADPrefix    = "outbox-v1"
	outboxMagicBytes   = 4
	outboxHeaderBytes  = 8 // 4 magic + 1 version + 3 reserved
	outboxEnvelopeSize = outboxHeaderBytes + outboxNonceBytes + 16
	outboxLockSuffix   = ".lock"
	outboxLockStale    = time.Minute
)

var (
	outboxMagic   = [outboxMagicBytes]byte{'V', 'G', 'W', 'O'}
	outboxVersion = byte(1)

	// ErrOutboxCorrupt marks an outbox that cannot be authenticated or decoded.
	ErrOutboxCorrupt = errors.New("witness outbox is corrupt")
	// ErrOutboxFull marks an outbox at its entry or byte bound.
	ErrOutboxFull = errors.New("witness outbox is full")
	// ErrOutboxDuplicate marks a checkpoint id that is already queued.
	ErrOutboxDuplicate = errors.New("witness outbox already holds the checkpoint")
	// ErrOutboxLocked marks a writer conflict with another process.
	ErrOutboxLocked = errors.New("witness outbox is locked by another writer")
	// ErrOutboxEntryMissing marks an acknowledgement of an entry that is no
	// longer queued.
	ErrOutboxEntryMissing = errors.New("witness outbox entry is not queued")
)

// OutboxEntry is one queued checkpoint plus its delivery bookkeeping.
type OutboxEntry struct {
	LocalSequence  uint64     `json:"local_sequence"`
	Checkpoint     Checkpoint `json:"checkpoint"`
	Attempts       int        `json:"attempts"`
	NextAttemptUTC time.Time  `json:"next_attempt_utc"`
}

// outboxDocument is the sealed plaintext.
type outboxDocument struct {
	Schema  string        `json:"schema"`
	Entries []OutboxEntry `json:"entries"`
}

// Outbox is the encrypted queue. It owns no goroutine and is safe for concurrent
// use; the mutex serialises every state transition and every write.
type Outbox struct {
	mu           sync.Mutex
	path         string
	key          []byte
	hostID       string
	now          func() time.Time
	entries      []OutboxEntry
	bytes        int64
	nextSequence uint64
	corrupt      bool
}

// OpenOutbox loads and authenticates the outbox file. A missing file is an empty
// outbox. A file that fails authentication or decoding returns a non-nil *Outbox
// marked corrupt together with an error wrapping ErrOutboxCorrupt, so the caller
// can report FAULT without ever discarding queued evidence.
func OpenOutbox(path string, key []byte, hostID string) (*Outbox, error) {
	if err := validateOutboxPath(path); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOutboxCorrupt, err)
	}
	if len(key) != outboxKeyBytes {
		return nil, fmt.Errorf("%w: outbox key must be %d bytes", ErrOutboxCorrupt, outboxKeyBytes)
	}
	if err := validateHostID(hostID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOutboxCorrupt, err)
	}
	outbox := &Outbox{
		path: path, key: append([]byte(nil), key...), hostID: hostID,
		now: func() time.Time { return time.Now().UTC() },
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return outbox, nil
	}
	if err != nil {
		outbox.corrupt = true
		return outbox, fmt.Errorf("%w: %v", ErrOutboxCorrupt, err)
	}
	if len(raw) > OutboxMaxFileBytes {
		outbox.corrupt = true
		outbox.bytes = int64(len(raw))
		return outbox, fmt.Errorf("%w: document exceeds %d bytes", ErrOutboxCorrupt, OutboxMaxFileBytes)
	}
	entries, err := outbox.open(raw)
	if err != nil {
		outbox.corrupt = true
		return outbox, err
	}
	outbox.entries = entries
	outbox.bytes = int64(len(raw))
	if len(entries) > 0 {
		outbox.nextSequence = entries[len(entries)-1].LocalSequence
	}
	return outbox, nil
}

// open authenticates and decodes one sealed document.
func (o *Outbox) open(raw []byte) ([]OutboxEntry, error) {
	if len(raw) < outboxEnvelopeSize {
		return nil, fmt.Errorf("%w: document is truncated", ErrOutboxCorrupt)
	}
	if !bytes.Equal(raw[:outboxMagicBytes], outboxMagic[:]) {
		return nil, fmt.Errorf("%w: magic does not match", ErrOutboxCorrupt)
	}
	if raw[outboxMagicBytes] != outboxVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrOutboxCorrupt, raw[outboxMagicBytes])
	}
	for _, reserved := range raw[outboxMagicBytes+1 : outboxHeaderBytes] {
		if reserved != 0 {
			return nil, fmt.Errorf("%w: reserved header bytes are not zero", ErrOutboxCorrupt)
		}
	}
	nonce := raw[outboxHeaderBytes : outboxHeaderBytes+outboxNonceBytes]
	ciphertext := raw[outboxHeaderBytes+outboxNonceBytes:]
	aead, err := o.aead()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOutboxCorrupt, err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, o.aad())
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrOutboxCorrupt)
	}
	var document outboxDocument
	if err := decodeStrictJSON(plaintext, OutboxMaxFileBytes, &document); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOutboxCorrupt, err)
	}
	if document.Schema != outboxSchema {
		return nil, fmt.Errorf("%w: schema is unknown", ErrOutboxCorrupt)
	}
	if len(document.Entries) > OutboxMaxEntries {
		return nil, fmt.Errorf("%w: document exceeds %d entries", ErrOutboxCorrupt, OutboxMaxEntries)
	}
	entries := make([]OutboxEntry, 0, len(document.Entries))
	var previous uint64
	seen := make(map[string]struct{}, len(document.Entries))
	for _, entry := range document.Entries {
		if entry.LocalSequence == 0 || entry.LocalSequence <= previous {
			return nil, fmt.Errorf("%w: local sequence is not strictly increasing", ErrOutboxCorrupt)
		}
		if entry.Attempts < 0 || entry.Attempts > OutboxMaxEntries {
			return nil, fmt.Errorf("%w: attempt counter is outside its bound", ErrOutboxCorrupt)
		}
		if entry.NextAttemptUTC.IsZero() || entry.NextAttemptUTC.Year() < checkpointMinPlausibleYear ||
			entry.NextAttemptUTC.Year() >= checkpointMaxPlausibleYear {
			return nil, fmt.Errorf("%w: next attempt time is not plausible", ErrOutboxCorrupt)
		}
		if err := ValidateCheckpoint(entry.Checkpoint); err != nil {
			return nil, fmt.Errorf("%w: queued checkpoint is invalid", ErrOutboxCorrupt)
		}
		if _, duplicate := seen[entry.Checkpoint.CheckpointID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate checkpoint id", ErrOutboxCorrupt)
		}
		seen[entry.Checkpoint.CheckpointID] = struct{}{}
		previous = entry.LocalSequence
		entries = append(entries, entry)
	}
	return entries, nil
}

// aead returns the AES-256-GCM primitive for the configured key.
func (o *Outbox) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(o.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds the sealed document to the outbox purpose and the host id.
func (o *Outbox) aad() []byte {
	aad := make([]byte, 0, len(outboxAADPrefix)+len(o.hostID))
	aad = append(aad, outboxAADPrefix...)
	aad = append(aad, o.hostID...)
	return aad
}

// seal encodes and encrypts one document with a fresh crypto/rand nonce.
func (o *Outbox) seal(entries []OutboxEntry) ([]byte, error) {
	document := outboxDocument{Schema: outboxSchema, Entries: entries}
	plaintext, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("witness outbox encoding: %w", err)
	}
	aead, err := o.aead()
	if err != nil {
		return nil, fmt.Errorf("witness outbox cipher: %w", err)
	}
	if aead.NonceSize() != outboxNonceBytes {
		return nil, errors.New("witness outbox nonce size is unexpected")
	}
	nonce := make([]byte, outboxNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("witness outbox nonce: %w", err)
	}
	sealed := make([]byte, 0, outboxHeaderBytes+outboxNonceBytes+len(plaintext)+aead.Overhead())
	sealed = append(sealed, outboxMagic[:]...)
	sealed = append(sealed, outboxVersion, 0, 0, 0)
	sealed = append(sealed, nonce...)
	sealed = aead.Seal(sealed, nonce, plaintext, o.aad())
	if len(sealed) > OutboxMaxFileBytes {
		return nil, fmt.Errorf("%w: sealed document would exceed %d bytes", ErrOutboxFull, OutboxMaxFileBytes)
	}
	return sealed, nil
}

// persisting seal+atomic-write. The caller holds o.mu.
func (o *Outbox) persist(entries []OutboxEntry) (int64, error) {
	sealed, err := o.seal(entries)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(o.path), 0o700); err != nil {
		return 0, fmt.Errorf("witness outbox directory: %w", err)
	}
	release, err := o.acquireLock()
	if err != nil {
		return 0, err
	}
	defer release()
	temp, err := os.CreateTemp(filepath.Dir(o.path), ".witness-outbox-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("witness outbox temp file: %w", err)
	}
	tempName := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = temp.Close()
			_ = os.Remove(tempName)
		}
	}()
	if _, err := temp.Write(sealed); err != nil {
		return 0, fmt.Errorf("witness outbox temp write: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return 0, fmt.Errorf("witness outbox temp sync: %w", err)
	}
	if err := temp.Close(); err != nil {
		return 0, fmt.Errorf("witness outbox temp close: %w", err)
	}
	if err := os.Rename(tempName, o.path); err != nil {
		return 0, fmt.Errorf("witness outbox replace: %w", err)
	}
	cleanup = false
	return int64(len(sealed)), nil
}

// acquireLock takes the per-document writer lock. A fresh lock held by another
// process is honoured; a lock older than outboxLockStale is replaced.
func (o *Outbox) acquireLock() (func(), error) {
	lockPath := o.path + outboxLockSuffix
	for attempt := 0; attempt < 2; attempt++ {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%w: %v", ErrOutboxLocked, err)
		}
		info, statErr := os.Stat(lockPath)
		if statErr != nil || o.now().Sub(info.ModTime()) <= outboxLockStale {
			return nil, ErrOutboxLocked
		}
		_ = os.Remove(lockPath)
	}
	return nil, ErrOutboxLocked
}

// Append queues one signed checkpoint. It is durable before it becomes visible in
// memory: a failed or interrupted write leaves the previous document and the
// in-memory queue unchanged. A duplicate checkpoint id is reported, not appended.
func (o *Outbox) Append(checkpoint Checkpoint) (uint64, error) {
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return 0, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.corrupt {
		return 0, ErrOutboxCorrupt
	}
	if o.fullLocked() {
		return 0, ErrOutboxFull
	}
	for _, entry := range o.entries {
		if entry.Checkpoint.CheckpointID == checkpoint.CheckpointID {
			return 0, ErrOutboxDuplicate
		}
	}
	next := o.nextSequence + 1
	entry := OutboxEntry{
		LocalSequence: next, Checkpoint: checkpoint, Attempts: 0,
		NextAttemptUTC: o.now().UTC(),
	}
	candidate := make([]OutboxEntry, len(o.entries), len(o.entries)+1)
	copy(candidate, o.entries)
	candidate = append(candidate, entry)
	size, err := o.persist(candidate)
	if err != nil {
		return 0, err
	}
	o.entries = candidate
	o.nextSequence = next
	o.bytes = size
	return next, nil
}

// Pending returns a copy of the queued entries in FIFO order.
func (o *Outbox) Pending() []OutboxEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]OutboxEntry(nil), o.entries...)
}

// NextDue returns the oldest queued entry whose next attempt time has arrived.
func (o *Outbox) NextDue(now time.Time) (OutboxEntry, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, entry := range o.entries {
		if !entry.NextAttemptUTC.After(now) {
			return entry, true
		}
	}
	return OutboxEntry{}, false
}

// RecordAttempt persists the attempt counter and the next attempt time of one
// entry. A failed write leaves the previous state in force; the checkpoint stays
// queued.
func (o *Outbox) RecordAttempt(localSequence uint64, attempts int, next time.Time) error {
	if attempts < 0 || attempts > OutboxMaxEntries {
		return fmt.Errorf("%w: attempt counter is outside its bound", ErrOutboxCorrupt)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.corrupt {
		return ErrOutboxCorrupt
	}
	index := o.indexLocked(localSequence)
	if index < 0 {
		return ErrOutboxEntryMissing
	}
	candidate := append([]OutboxEntry(nil), o.entries...)
	candidate[index].Attempts = attempts
	candidate[index].NextAttemptUTC = next.UTC()
	size, err := o.persist(candidate)
	if err != nil {
		return err
	}
	o.entries = candidate
	o.bytes = size
	return nil
}

// Ack removes one acknowledged entry. The entry is deleted only after the
// verified receipt, so a crash before the receipt never loses a checkpoint.
func (o *Outbox) Ack(localSequence uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.corrupt {
		return ErrOutboxCorrupt
	}
	index := o.indexLocked(localSequence)
	if index < 0 {
		return ErrOutboxEntryMissing
	}
	candidate := make([]OutboxEntry, 0, len(o.entries)-1)
	candidate = append(candidate, o.entries[:index]...)
	candidate = append(candidate, o.entries[index+1:]...)
	size, err := o.persist(candidate)
	if err != nil {
		return err
	}
	o.entries = candidate
	o.bytes = size
	return nil
}

// depthLocked returns the number of queued entries.
func (o *Outbox) depthLocked() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

// Depth returns the number of queued entries.
func (o *Outbox) Depth() int { return o.depthLocked() }

// Bytes returns the current sealed document size, or 0 for an empty outbox.
func (o *Outbox) Bytes() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bytes
}

// Full reports whether the outbox has reached an entry or byte bound (or is
// corrupt, in which case no checkpoint may be appended either).
func (o *Outbox) Full() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.fullLocked()
}

// Corrupt reports whether the on-disk document failed authentication or decoding.
func (o *Outbox) Corrupt() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.corrupt
}

// LastCheckpoint returns the newest queued checkpoint, which the engine uses as
// the previous-checkpoint anchor after a restart.
func (o *Outbox) LastCheckpoint() (Checkpoint, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.entries) == 0 {
		return Checkpoint{}, false
	}
	return o.entries[len(o.entries)-1].Checkpoint, true
}

func (o *Outbox) fullLocked() bool {
	if o.corrupt {
		return true
	}
	if len(o.entries) >= OutboxMaxEntries {
		return true
	}
	return o.bytes >= OutboxMaxFileBytes
}

func (o *Outbox) indexLocked(localSequence uint64) int {
	for index := range o.entries {
		if o.entries[index].LocalSequence == localSequence {
			return index
		}
	}
	return -1
}
