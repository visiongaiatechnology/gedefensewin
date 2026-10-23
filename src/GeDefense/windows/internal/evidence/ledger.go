// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

const (
	ledgerSchemaVersion                = 1
	maxRecordBytes                     = 128 << 10
	maxLedgerPageLimit                 = 100
	maxLedgerSnapshotLimit             = 500
	maxLedgerPageOffset                = 50_000
	maxRetainedArchives                = 4
	maxCheckpointEntriesInMemory       = 8192
	maxCheckpointFileBytes       int64 = 4 << 20
	ledgerHMACKeyBytes                 = 32
	checkpointKindTip                  = "TIP"
	checkpointKindArchive              = "ARCHIVE"
	checkpointKindRetention            = "RETENTION"
)

// ledgerRotateBytes bounds the live evidence file. Larger values keep the
// append path cheap; tests override it to exercise rotation quickly.
var ledgerRotateBytes int64 = 64 << 20

// appendCheckpointInterval controls how often a signed chain-tip checkpoint is
// written. Truncation of the tail after the newest checkpoint is detectable
// because the signed checkpoint records a higher sequence than the file.
var appendCheckpointInterval uint64 = 256

type Record struct {
	Sequence    uint64    `json:"sequence"`
	Timestamp   time.Time `json:"timestamp"`
	Kind        string    `json:"kind"`
	Action      string    `json:"action"`
	Result      string    `json:"result"`
	PreviousMAC string    `json:"previous_mac"`
	MAC         string    `json:"mac"`
}

// checkpointRecord is one signed anchor of the HMAC evidence chain. It is
// signed with an Ed25519 key stored through the protected secret filesystem, so
// an actor that can write the ledger cannot recompute a consistent chain
// without also reading the signing seed.
type checkpointRecord struct {
	SchemaVersion           int       `json:"schemaVersion"`
	Kind                    string    `json:"kind"`
	Sequence                uint64    `json:"sequence"`
	LastMAC                 string    `json:"lastMac"`
	CreatedUTC              time.Time `json:"createdUtc"`
	ArchiveName             string    `json:"archiveName,omitempty"`
	ArchiveSHA256           string    `json:"archiveSha256,omitempty"`
	RetainedFromSequence    uint64    `json:"retainedFromSequence,omitempty"`
	RetainedFromPreviousMAC string    `json:"retainedFromPreviousMac,omitempty"`
	PublicKeySHA256         string    `json:"publicKeySha256"`
	Signature               string    `json:"signatureEd25519"`
}

type ledgerArchive struct {
	Name          string
	FirstSequence uint64
	LastSequence  uint64
}

type Ledger struct {
	mu       sync.Mutex
	path     string
	dir      string
	key      []byte
	sequence uint64
	lastMAC  string

	fileFirstSequence uint64
	fileBytes         int64
	// retainedFromSequence is the oldest sequence number still present on disk
	// after archive retention pruning. Page totals are relative to the retained
	// window, never to the absolute chain length.
	retainedFromSequence uint64

	signingKey          ed25519.PrivateKey
	signingPublicSHA256 string
	checkpointPath      string
	checkpointFileBytes int64
	checkpoints         []checkpointRecord
	archives            []ledgerArchive

	appendFailures uint64
	lastError      error
	keyRestriction secretfs.Restriction

	// External witness state (DP-FIND-012). witnessPath is empty when the
	// operator did not configure an independent witness.
	witnessPath        string
	witnessStatus      WitnessStatus
	witnessLastFailure time.Time
}

// Open opens the ledger with the operator environment configuration. It is the
// backward-compatible entry point; OpenWithOptions allows an explicit witness
// path instead of VGT_EVIDENCE_WITNESS.
func Open(path, keyPath string) (*Ledger, error) {
	return OpenWithOptions(path, keyPath, defaultOptions())
}

// OpenWithOptions opens the ledger with explicit options. A configured witness
// path must be absolute and outside the evidence data root; the configured
// witness is authenticated before the ledger is returned.
func OpenWithOptions(path, keyPath string, options Options) (*Ledger, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyPath) {
		return nil, errors.New("evidence paths must be absolute")
	}
	directory := filepath.Dir(path)
	witnessPath, err := validateWitnessPath(options.WitnessPath, directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	lockFile, err := acquireWriterLock(path)
	if err != nil {
		return nil, err
	}
	defer releaseWriterLock(lockFile)
	key, err := secretfs.LoadOrCreateRawKey(keyPath, ledgerHMACKeyBytes)
	if err != nil {
		return nil, err
	}
	keyRestriction, err := secretfs.HardenFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("evidence key access control: %w", err)
	}
	// The signing seed lives in a dedicated protected directory. This is the
	// DP-FIND-001 separation: even when the installer's data-root grant is
	// operator-readable, the key directory and its files carry their own
	// SYSTEM/Administrators-only DACL.
	signingKey, _, fingerprint, err := secretfs.LoadOrCreateEd25519Seed(filepath.Join(directory, "keys", "evidence-signing.key"))
	if err != nil {
		return nil, err
	}
	ledger := &Ledger{
		path:                filepath.Clean(path),
		dir:                 directory,
		key:                 key,
		signingKey:          signingKey,
		signingPublicSHA256: fingerprint,
		checkpointPath:      filepath.Clean(path) + ".checkpoints.jsonl",
		keyRestriction:      keyRestriction,
		witnessPath:         witnessPath,
	}
	ledger.loadCheckpoints()
	if err := ledger.loadArchives(); err != nil {
		return nil, err
	}
	ledger.loadJournalState()
	if err := ledger.verifyLocked(); err != nil {
		return nil, err
	}
	if err := ledger.verifyWitnessLocked(); err != nil {
		return nil, err
	}
	if err := ledger.ensureTipCheckpointLocked(); err != nil {
		return nil, err
	}
	ledger.refreshWitnessLocked()
	return ledger, nil
}

func (l *Ledger) Append(kind, action, result string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.withWriterLock(func() error {
		if err := l.refreshLocked(); err != nil {
			return err
		}
		return l.appendLocked(kind, action, result)
	})
	if err != nil {
		l.appendFailures++
		l.lastError = err
	}
	return err
}

// withWriterLock runs one ledger operation under the cross-process single
// writer lock. The lock is held only for the operation (not for the lifetime of
// the service) so the kernel releases it even on a crash and no stale handle
// survives a restart.
func (l *Ledger) withWriterLock(operation func() error) error {
	lockFile, err := acquireWriterLock(l.path)
	if err != nil {
		return err
	}
	defer releaseWriterLock(lockFile)
	return operation()
}

func (l *Ledger) appendLocked(kind, action, result string) error {
	record := Record{Sequence: l.sequence + 1, Timestamp: time.Now().UTC(), Kind: kind, Action: action, Result: result, PreviousMAC: l.lastMAC}
	mac, err := l.calculate(record)
	if err != nil {
		return err
	}
	record.MAC = mac
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(raw)+1 > maxRecordBytes {
		return errors.New("evidence record exceeds the line boundary")
	}
	if l.fileBytes+int64(len(raw))+1 > ledgerRotateBytes {
		if err := l.rotateLocked(); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := func() error {
		if _, err := file.Write(append(raw, '\n')); err != nil {
			return err
		}
		return file.Sync()
	}()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	l.fileBytes += int64(len(raw)) + 1
	l.sequence = record.Sequence
	l.lastMAC = record.MAC
	if appendCheckpointInterval > 0 && l.sequence%appendCheckpointInterval == 0 {
		if err := l.appendCheckpointLocked(checkpointRecord{Kind: checkpointKindTip, Sequence: l.sequence, LastMAC: l.lastMAC}); err != nil {
			l.lastError = fmt.Errorf("evidence checkpoint: %w", err)
		}
	}
	return nil
}

// refreshLocked reconciles the cached chain tip with the on-disk files. The
// single-writer lock makes this a cheap operation; a differing file size means
// another run archived or appended, so the tip is re-read and authenticated.
func (l *Ledger) refreshLocked() error {
	info, err := os.Stat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		l.sequence = 0
		l.lastMAC = ""
		l.fileBytes = 0
		l.fileFirstSequence = 1
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	previousArchives := len(l.archives)
	if err := l.loadArchives(); err != nil {
		return err
	}
	if err == nil && info.Size() == l.fileBytes && len(l.archives) == previousArchives {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		info, err = os.Stat(l.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err != nil { // file still absent
		return l.refreshFromArchivesLocked()
	}
	lines, err := readNewestLines(l.path, 1)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return l.refreshFromArchivesLocked()
	}
	record, err := decodeRecord(lines[0])
	if err != nil {
		return err
	}
	if err := l.authenticate(record); err != nil {
		return err
	}
	l.sequence = record.Sequence
	l.lastMAC = record.MAC
	l.fileBytes = info.Size()
	l.fileFirstSequence = 1
	if len(l.archives) > 0 {
		l.fileFirstSequence = l.archives[len(l.archives)-1].LastSequence + 1
	}
	l.refreshRetainedFromLocked()
	return nil
}

func (l *Ledger) refreshRetainedFromLocked() {
	l.retainedFromSequence = 1
	if len(l.archives) > 0 && l.archives[0].FirstSequence > 1 {
		l.retainedFromSequence = l.archives[0].FirstSequence
	}
}

func (l *Ledger) refreshFromArchivesLocked() error {
	l.sequence = 0
	l.lastMAC = ""
	l.fileFirstSequence = 1
	if len(l.archives) == 0 {
		l.fileBytes = 0
		return nil
	}
	newest := l.archives[len(l.archives)-1]
	lines, err := readNewestLines(filepath.Join(l.dir, newest.Name), 1)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return errors.New("evidence archive is empty")
	}
	record, err := decodeRecord(lines[0])
	if err != nil {
		return err
	}
	if err := l.authenticate(record); err != nil {
		return err
	}
	l.sequence = record.Sequence
	l.lastMAC = record.MAC
	l.fileBytes = 0
	l.fileFirstSequence = newest.LastSequence + 1
	l.refreshRetainedFromLocked()
	return nil
}

// rotateLocked archives the live file and starts a fresh one. The hash chain is
// continued across files (sequence and PreviousMAC keep counting), so the
// rotation is not a reset: Verify still walks every retained archive.
func (l *Ledger) rotateLocked() error {
	if l.sequence == 0 || l.fileBytes == 0 {
		return nil
	}
	digest, err := hashFileSHA256(l.path)
	if err != nil {
		return err
	}
	archivedName := fmt.Sprintf("%s.%012d-%012d.jsonl", filepath.Base(l.path), l.fileFirstSequence, l.sequence)
	archivedPath := filepath.Join(l.dir, archivedName)
	if _, err := os.Lstat(archivedPath); err == nil {
		return errors.New("evidence archive target already exists")
	}
	if err := os.Rename(l.path, archivedPath); err != nil {
		return err
	}
	l.archives = append(l.archives, ledgerArchive{Name: archivedName, FirstSequence: l.fileFirstSequence, LastSequence: l.sequence})
	// The archive checkpoint is written after the rename so a crash cannot leave
	// a checkpoint that points at a file that was never archived. Verification
	// does not depend on it (it walks the chain); the checkpoint adds the archive
	// digest for retention bookkeeping.
	if checkpointErr := l.appendCheckpointLocked(checkpointRecord{
		Kind: checkpointKindArchive, Sequence: l.sequence, LastMAC: l.lastMAC,
		ArchiveName: archivedName, ArchiveSHA256: digest,
	}); checkpointErr != nil {
		l.lastError = fmt.Errorf("evidence archive checkpoint: %w", checkpointErr)
	}
	l.pruneArchivesLocked()
	l.fileFirstSequence = l.sequence + 1
	l.fileBytes = 0
	l.refreshRetainedFromLocked()
	return nil
}

func (l *Ledger) pruneArchivesLocked() {
	for len(l.archives) > maxRetainedArchives {
		oldest := l.archives[0]
		next := l.archives[1]
		firstPreviousMAC, err := firstRecordPreviousMAC(filepath.Join(l.dir, next.Name))
		if err != nil {
			return
		}
		anchor := checkpointRecord{
			Kind: checkpointKindRetention, Sequence: l.sequence, LastMAC: l.lastMAC,
			RetainedFromSequence: next.FirstSequence, RetainedFromPreviousMAC: firstPreviousMAC,
		}
		if err := l.appendCheckpointLocked(anchor); err != nil {
			l.lastError = fmt.Errorf("evidence retention anchor: %w", err)
			return
		}
		if err := os.Remove(filepath.Join(l.dir, oldest.Name)); err != nil {
			l.lastError = fmt.Errorf("evidence archive retention: %w", err)
			return
		}
		l.archives = l.archives[1:]
	}
}

func (l *Ledger) Snapshot(limit int) (result []Record, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit < 1 || limit > maxLedgerSnapshotLimit {
		return nil, errors.New("evidence limit outside boundary")
	}
	if err := l.refreshLocked(); err != nil {
		return nil, err
	}
	records, err := l.newestRecordsLocked(limit, 0)
	if err != nil {
		return nil, err
	}
	// Preserve the historical Snapshot contract: chronological order of the
	// newest `limit` records (oldest of the page first).
	for left, right := 0, len(records)-1; left < right; left, right = left+1, right-1 {
		records[left], records[right] = records[right], records[left]
	}
	return records, nil
}

// Page returns a newest-first page of evidence records. offset 0 selects the
// newest page. The query reads backwards from the end of the active file (and
// then from the newest archives) instead of scanning the whole ledger, so the
// cost is bounded by the requested page, not by the total ledger size.
func (l *Ledger) Page(limit, offset int) (items []Record, total int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit < 1 || limit > maxLedgerPageLimit {
		return nil, 0, errors.New("evidence page limit outside boundary")
	}
	if offset < 0 {
		return nil, 0, errors.New("evidence page offset outside boundary")
	}
	if err := l.refreshLocked(); err != nil {
		return nil, 0, err
	}
	total = int(l.availableRecords())
	if offset >= total {
		return []Record{}, total, nil
	}
	if offset > maxLedgerPageOffset {
		// Reverse-scan paging is bounded: an offset that would require walking
		// more than maxLedgerPageOffset records from the tail is refused instead
		// of turning an API request into a full-ledger scan.
		return nil, 0, errors.New("evidence page offset exceeds the bounded reverse-scan window")
	}
	if total == 0 {
		return []Record{}, 0, nil
	}
	records, err := l.newestRecordsLocked(limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return records, total, nil
}

// availableRecords is the number of records still present on disk (the retained
// window). The absolute chain sequence can be larger after archive retention.
func (l *Ledger) availableRecords() uint64 {
	if l.sequence == 0 || l.sequence < l.retainedFromSequence {
		return 0
	}
	return l.sequence - l.retainedFromSequence + 1
}

func (l *Ledger) newestRecordsLocked(limit, offset int) ([]Record, error) {
	if limit <= 0 || uint64(offset) >= l.availableRecords() {
		return []Record{}, nil
	}
	remainingSkip := offset
	remainingNeed := limit
	result := make([]Record, 0, limit)
	files := make([]string, 0, len(l.archives)+1)
	files = append(files, l.path)
	for index := len(l.archives) - 1; index >= 0; index-- {
		files = append(files, filepath.Join(l.dir, l.archives[index].Name))
	}
	for _, path := range files {
		if remainingNeed <= 0 {
			break
		}
		lines, err := readNewestLines(path, remainingSkip+remainingNeed)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			if remainingSkip > 0 {
				remainingSkip--
				continue
			}
			record, err := decodeRecord(line)
			if err != nil {
				return nil, err
			}
			result = append(result, record)
			remainingNeed--
			if remainingNeed == 0 {
				break
			}
		}
	}
	return result, nil
}

func (l *Ledger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.withWriterLock(func() error {
		l.loadCheckpoints()
		if err := l.verifyLocked(); err != nil {
			return err
		}
		// A configured but corrupt witness is a failed verification, not a
		// silently ignored side condition.
		return l.verifyWitnessLocked()
	})
	if err != nil {
		l.lastError = err
	}
	return err
}

// Sign returns a hex HMAC-SHA256 over a domain-separated payload using the
// protected ledger key. Other service components (for example the integrity
// baseline) use it to authenticate their own persisted state without inventing a
// second unprotected key.
func (l *Ledger) Sign(domain string, payload []byte) (string, error) {
	l.mu.Lock()
	key := l.key
	l.mu.Unlock()
	if len(key) != 32 {
		return "", errors.New("evidence key unavailable")
	}
	if len(domain) == 0 || len(domain) > 64 {
		return "", errors.New("evidence signing domain rejected")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifySignature verifies a HMAC produced by Sign in constant time.
func (l *Ledger) VerifySignature(domain string, payload []byte, signature string) error {
	expected, err := l.Sign(domain, payload)
	if err != nil {
		return err
	}
	provided, providedErr := hex.DecodeString(signature)
	expectedBytes, expectedErr := hex.DecodeString(expected)
	if providedErr != nil || expectedErr != nil || len(provided) != sha256.Size || !hmac.Equal(provided, expectedBytes) {
		return errors.New("evidence signature authentication failed")
	}
	return nil
}

// LastError reports the most recent append/checkpoint/rotation error. Service
// owners use it to surface evidence loss instead of silently dropping audits.
func (l *Ledger) LastError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastError
}

// AppendFailures counts failed evidence appends since the ledger was opened.
func (l *Ledger) AppendFailures() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendFailures
}

// KeyRestriction exposes how the HMAC key was protected on this host.
func (l *Ledger) KeyRestriction() secretfs.Restriction {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyRestriction
}

func (l *Ledger) verifyLocked() (err error) {
	startSequence, startMAC, err := l.retentionStart()
	if err != nil {
		return err
	}
	expectedSequence := startSequence
	previous := startMAC
	checkpointMACs := make(map[uint64]string, len(l.checkpoints))
	for _, checkpoint := range l.checkpoints {
		checkpointMACs[checkpoint.Sequence] = checkpoint.LastMAC
	}
	var lastArchiveSequence uint64
	for _, archive := range l.archives {
		if archive.FirstSequence != expectedSequence {
			return errors.New("evidence archive chain gap detected")
		}
		archivePath := filepath.Join(l.dir, archive.Name)
		if err := scanLedgerFile(archivePath, func(raw []byte) error {
			record, err := decodeRecord(raw)
			if err != nil {
				return err
			}
			if record.Sequence != expectedSequence || record.PreviousMAC != previous {
				return errors.New("evidence archive chain linkage invalid")
			}
			if err := l.authenticate(record); err != nil {
				return err
			}
			checkpointMACs[record.Sequence] = record.MAC
			previous = record.MAC
			expectedSequence++
			return nil
		}); err != nil {
			return err
		}
		if expectedSequence == 0 || expectedSequence-1 != archive.LastSequence {
			return errors.New("evidence archive sequence boundary rejected")
		}
		lastArchiveSequence = archive.LastSequence
	}
	if err := scanLedgerFile(l.path, func(raw []byte) error {
		record, err := decodeRecord(raw)
		if err != nil {
			return err
		}
		if record.Sequence != expectedSequence || record.PreviousMAC != previous {
			return errors.New("evidence chain linkage invalid")
		}
		if err := l.authenticate(record); err != nil {
			return err
		}
		checkpointMACs[record.Sequence] = record.MAC
		previous = record.MAC
		expectedSequence++
		return nil
	}); err != nil {
		return err
	}
	total := expectedSequence - 1
	l.sequence = total
	l.lastMAC = previous
	l.fileFirstSequence = 1
	if lastArchiveSequence > 0 {
		l.fileFirstSequence = lastArchiveSequence + 1
	}
	l.fileBytes = 0
	if info, statErr := os.Stat(l.path); statErr == nil {
		l.fileBytes = info.Size()
	}
	l.retainedFromSequence = startSequence
	// Signed chain-tip checkpoints make tail truncation detectable: a checkpoint
	// that claims a longer chain than the files contain is a failed verification
	// (the operator has to restore the missing evidence), not a fresh ledger.
	for _, checkpoint := range l.checkpoints {
		if checkpoint.Sequence > total {
			return errors.New("evidence ledger truncation detected: signed checkpoint is newer than the recorded chain")
		}
		if mac, ok := checkpointMACs[checkpoint.Sequence]; ok && mac != "" && !strings.EqualFold(mac, checkpoint.LastMAC) {
			return errors.New("evidence ledger does not match the signed checkpoint")
		}
	}
	return nil
}

func (l *Ledger) retentionStart() (uint64, string, error) {
	if len(l.archives) == 0 {
		return 1, "", nil
	}
	oldest := l.archives[0]
	if oldest.FirstSequence == 1 {
		return 1, "", nil
	}
	firstPreviousMAC, err := firstRecordPreviousMAC(filepath.Join(l.dir, oldest.Name))
	if err != nil {
		return 0, "", err
	}
	for index := len(l.checkpoints) - 1; index >= 0; index-- {
		checkpoint := l.checkpoints[index]
		if checkpoint.Kind != checkpointKindRetention || checkpoint.RetainedFromSequence != oldest.FirstSequence {
			continue
		}
		if checkpoint.RetainedFromPreviousMAC != firstPreviousMAC {
			return 0, "", errors.New("evidence retention anchor does not match the retained archive")
		}
		return oldest.FirstSequence, firstPreviousMAC, nil
	}
	return 0, "", errors.New("retained evidence archive has no authenticated retention anchor")
}

func (l *Ledger) authenticate(record Record) error {
	expected, err := l.calculate(record)
	if err != nil {
		return err
	}
	provided, providedErr := hex.DecodeString(record.MAC)
	expectedBytes, expectedErr := hex.DecodeString(expected)
	if providedErr != nil || expectedErr != nil || len(provided) != sha256.Size || !hmac.Equal(expectedBytes, provided) {
		return errors.New("evidence chain authentication failed")
	}
	return nil
}

func (l *Ledger) calculate(record Record) (string, error) {
	record.MAC = ""
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (l *Ledger) loadArchives() error {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	base := filepath.Base(l.path)
	prefix := base + "."
	archives := make([]ledgerArchive, 0, 4)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), prefix), ".jsonl")
		parts := strings.Split(middle, "-")
		if len(parts) != 2 {
			continue
		}
		first, firstErr := parseSequence(parts[0])
		last, lastErr := parseSequence(parts[1])
		if firstErr != nil || lastErr != nil || first == 0 || last < first {
			return errors.New("evidence archive name rejected")
		}
		archives = append(archives, ledgerArchive{Name: entry.Name(), FirstSequence: first, LastSequence: last})
	}
	sort.Slice(archives, func(left, right int) bool { return archives[left].FirstSequence < archives[right].FirstSequence })
	l.archives = archives
	return nil
}

func (l *Ledger) loadCheckpoints() {
	info, err := os.Lstat(l.checkpointPath)
	if errors.Is(err, os.ErrNotExist) {
		l.checkpoints = nil
		l.checkpointFileBytes = 0
		return
	}
	if err != nil {
		l.lastError = fmt.Errorf("evidence checkpoint store: %w", err)
		l.checkpoints = nil
		l.checkpointFileBytes = 0
		return
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if quarantineErr := l.quarantineCheckpointStore("not a regular file"); quarantineErr != nil {
			l.lastError = quarantineErr
		}
		return
	}
	if info.Size() > maxCheckpointFileBytes {
		if quarantineErr := l.quarantineCheckpointStore("size boundary exceeded"); quarantineErr != nil {
			l.lastError = quarantineErr
		}
		return
	}
	// Read the bounded store into memory first so a corrupt store can be renamed
	// aside: Windows refuses to rename a file that still has an open handle.
	payload, err := os.ReadFile(l.checkpointPath)
	if err != nil {
		l.lastError = err
		l.checkpoints = nil
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 16<<10), maxRecordBytes)
	checkpoints := make([]checkpointRecord, 0, 64)
	count := 0
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		count++
		if count > maxCheckpointEntriesInMemory*2 {
			if quarantineErr := l.quarantineCheckpointStore("checkpoint count boundary exceeded"); quarantineErr != nil {
				l.lastError = quarantineErr
			}
			return
		}
		checkpoint, decodeErr := decodeCheckpoint(line)
		if decodeErr != nil {
			if quarantineErr := l.quarantineCheckpointStore(decodeErr.Error()); quarantineErr != nil {
				l.lastError = quarantineErr
			}
			return
		}
		if authErr := l.authenticateCheckpoint(checkpoint); authErr != nil {
			if quarantineErr := l.quarantineCheckpointStore(authErr.Error()); quarantineErr != nil {
				l.lastError = quarantineErr
			}
			return
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := scanner.Err(); err != nil {
		if quarantineErr := l.quarantineCheckpointStore("checkpoint store read rejected"); quarantineErr != nil {
			l.lastError = quarantineErr
		}
		return
	}
	if len(checkpoints) > maxCheckpointEntriesInMemory {
		checkpoints = checkpoints[len(checkpoints)-maxCheckpointEntriesInMemory:]
	}
	l.checkpoints = checkpoints
	l.checkpointFileBytes = info.Size()
}

// quarantineCheckpointStore preserves a damaged checkpoint store unchanged for
// forensics and starts a fresh store. It intentionally does not mark the whole
// ledger bad: the HMAC chain is verified independently and a new signed tip
// checkpoint is written after verification.
func (l *Ledger) quarantineCheckpointStore(reason string) error {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	target := fmt.Sprintf("%s.corrupt-%s", l.checkpointPath, stamp)
	if err := os.Rename(l.checkpointPath, target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("evidence checkpoint store rejected: "+reason), err)
	}
	l.checkpoints = nil
	l.checkpointFileBytes = 0
	return errors.New("evidence checkpoint store rejected: " + reason)
}

func (l *Ledger) appendCheckpointLocked(partial checkpointRecord) error {
	checkpoint := partial
	checkpoint.SchemaVersion = ledgerSchemaVersion
	checkpoint.CreatedUTC = time.Now().UTC()
	checkpoint.PublicKeySHA256 = l.signingPublicSHA256
	checkpoint.Signature = hex.EncodeToString(ed25519.Sign(l.signingKey, checkpointMessage(checkpoint)))
	line, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if len(line)+1 > maxRecordBytes {
		return errors.New("evidence checkpoint exceeds the line boundary")
	}
	if l.checkpointFileBytes+int64(len(line))+1 > maxCheckpointFileBytes {
		if err := l.rotateCheckpointStoreLocked(); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(l.checkpointPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	l.checkpointFileBytes += int64(len(line)) + 1
	l.checkpoints = append(l.checkpoints, checkpoint)
	if len(l.checkpoints) > maxCheckpointEntriesInMemory {
		copy(l.checkpoints, l.checkpoints[len(l.checkpoints)-maxCheckpointEntriesInMemory:])
		l.checkpoints = l.checkpoints[:maxCheckpointEntriesInMemory]
	}
	// Publish the new signed tip to the external witness after the checkpoint
	// itself is durable. A failed witness write degrades the independent anchor
	// (visible through LastError/Witness) but never drops local evidence.
	l.updateWitnessLocked()
	return nil
}

func (l *Ledger) rotateCheckpointStoreLocked() error {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	target := fmt.Sprintf("%s.old-%s", l.checkpointPath, stamp)
	if err := os.Rename(l.checkpointPath, target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l.checkpointFileBytes = 0
	return nil
}

func (l *Ledger) ensureTipCheckpointLocked() error {
	if l.sequence == 0 {
		return nil
	}
	for _, checkpoint := range l.checkpoints {
		if checkpoint.Kind == checkpointKindTip && checkpoint.Sequence == l.sequence && checkpoint.LastMAC == l.lastMAC {
			return nil
		}
	}
	return l.appendCheckpointLocked(checkpointRecord{Kind: checkpointKindTip, Sequence: l.sequence, LastMAC: l.lastMAC})
}

// loadJournalState seeds the cached tip from the files so Open can verify
// without a second directory scan.
func (l *Ledger) loadJournalState() {
	l.sequence = 0
	l.lastMAC = ""
	l.fileFirstSequence = 1
	l.fileBytes = 0
	l.retainedFromSequence = 1
	if info, err := os.Stat(l.path); err == nil {
		l.fileBytes = info.Size()
	}
	l.refreshRetainedFromLocked()
}

func decodeCheckpoint(raw []byte) (checkpointRecord, error) {
	var checkpoint checkpointRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return checkpointRecord{}, errors.New("evidence checkpoint JSON rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return checkpointRecord{}, errors.New("evidence checkpoint trailing data rejected")
	}
	if checkpoint.SchemaVersion != ledgerSchemaVersion || checkpoint.Sequence == 0 || len(checkpoint.LastMAC) != 64 ||
		len(checkpoint.PublicKeySHA256) != 64 || len(checkpoint.Signature) != ed25519.SignatureSize*2 {
		return checkpointRecord{}, errors.New("evidence checkpoint metadata rejected")
	}
	switch checkpoint.Kind {
	case checkpointKindTip, checkpointKindArchive, checkpointKindRetention:
	default:
		return checkpointRecord{}, errors.New("evidence checkpoint kind rejected")
	}
	if checkpoint.Kind == checkpointKindArchive {
		if checkpoint.ArchiveName == "" || strings.ContainsAny(checkpoint.ArchiveName, `/\:`) || len(checkpoint.ArchiveName) > 260 || len(checkpoint.ArchiveSHA256) != 64 {
			return checkpointRecord{}, errors.New("evidence archive checkpoint metadata rejected")
		}
	}
	if checkpoint.Kind == checkpointKindRetention {
		if checkpoint.RetainedFromSequence == 0 || len(checkpoint.RetainedFromPreviousMAC) != 64 {
			return checkpointRecord{}, errors.New("evidence retention checkpoint metadata rejected")
		}
	}
	if _, err := hex.DecodeString(checkpoint.LastMAC); err != nil {
		return checkpointRecord{}, errors.New("evidence checkpoint MAC rejected")
	}
	if _, err := hex.DecodeString(checkpoint.Signature); err != nil {
		return checkpointRecord{}, errors.New("evidence checkpoint signature encoding rejected")
	}
	return checkpoint, nil
}

func (l *Ledger) authenticateCheckpoint(checkpoint checkpointRecord) error {
	if checkpoint.PublicKeySHA256 != l.signingPublicSHA256 {
		return errors.New("evidence checkpoint public key rejected")
	}
	signature, err := hex.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("evidence checkpoint signature encoding rejected")
	}
	publicKey := l.signingKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, checkpointMessage(checkpoint), signature) {
		return errors.New("evidence checkpoint signature invalid")
	}
	return nil
}

func checkpointMessage(checkpoint checkpointRecord) []byte {
	message := struct {
		SchemaVersion           int    `json:"schemaVersion"`
		Kind                    string `json:"kind"`
		Sequence                uint64 `json:"sequence"`
		LastMAC                 string `json:"lastMac"`
		CreatedUTC              string `json:"createdUtc"`
		ArchiveName             string `json:"archiveName,omitempty"`
		ArchiveSHA256           string `json:"archiveSha256,omitempty"`
		RetainedFromSequence    uint64 `json:"retainedFromSequence,omitempty"`
		RetainedFromPreviousMAC string `json:"retainedFromPreviousMac,omitempty"`
		PublicKeySHA256         string `json:"publicKeySha256"`
	}{
		SchemaVersion:           checkpoint.SchemaVersion,
		Kind:                    checkpoint.Kind,
		Sequence:                checkpoint.Sequence,
		LastMAC:                 checkpoint.LastMAC,
		CreatedUTC:              checkpoint.CreatedUTC.UTC().Format(time.RFC3339Nano),
		ArchiveName:             checkpoint.ArchiveName,
		ArchiveSHA256:           checkpoint.ArchiveSHA256,
		RetainedFromSequence:    checkpoint.RetainedFromSequence,
		RetainedFromPreviousMAC: checkpoint.RetainedFromPreviousMAC,
		PublicKeySHA256:         checkpoint.PublicKeySHA256,
	}
	raw, _ := json.Marshal(message)
	return raw
}

// Close releases no persistent file handles: every operation opens and closes
// its file while holding the single-writer lock. It exists so callers can free
// in-memory state and so tests can reopen the same ledger deterministically.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.checkpoints = nil
	l.archives = nil
	return nil
}

func scanLedgerFile(path string, visit func(raw []byte) error) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := visit(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func decodeRecord(raw []byte) (Record, error) {
	var record Record
	if err := json.Unmarshal(raw, &record); err != nil {
		return Record{}, errors.New("evidence record decoding failed")
	}
	if record.Sequence == 0 || len(record.MAC) != 64 {
		return Record{}, errors.New("evidence record metadata rejected")
	}
	return record, nil
}

func firstRecordPreviousMAC(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("evidence archive is empty")
	}
	record, err := decodeRecord(bytes.TrimSpace(scanner.Bytes()))
	if err != nil {
		return "", err
	}
	return record.PreviousMAC, nil
}

func readNewestLines(path string, limit int) ([][]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence file must be a regular non-reparse file")
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}
	const chunkSize = 64 << 10
	lines := make([][]byte, 0, limit)
	var carry []byte
	position := size
	for position > 0 && len(lines) < limit {
		step := int64(chunkSize)
		if step > position {
			step = position
		}
		position -= step
		chunk := make([]byte, step)
		if _, err := file.ReadAt(chunk, position); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		combined := append(append([]byte(nil), chunk...), carry...)
		end := len(combined)
		for end > 0 && len(lines) < limit {
			index := bytes.LastIndexByte(combined[:end], '\n')
			if index < 0 {
				break
			}
			line := combined[index+1 : end]
			end = index
			if len(line) == 0 {
				continue
			}
			if len(line) > maxRecordBytes {
				return nil, errors.New("evidence record exceeds the line boundary")
			}
			lines = append(lines, append([]byte(nil), line...))
		}
		if len(lines) >= limit {
			return lines, nil
		}
		carry = append([]byte(nil), combined[:end]...)
		if len(carry) > maxRecordBytes {
			return nil, errors.New("evidence record exceeds the line boundary")
		}
	}
	if len(lines) < limit && len(carry) > 0 {
		if len(carry) > maxRecordBytes {
			return nil, errors.New("evidence record exceeds the line boundary")
		}
		lines = append(lines, carry)
	}
	return lines, nil
}

func hashFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func parseSequence(value string) (uint64, error) {
	if value == "" || len(value) > 20 {
		return 0, errors.New("sequence rejected")
	}
	var result uint64
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < '0' || character > '9' {
			return 0, errors.New("sequence rejected")
		}
		result = result*10 + uint64(character-'0')
	}
	return result, nil
}
