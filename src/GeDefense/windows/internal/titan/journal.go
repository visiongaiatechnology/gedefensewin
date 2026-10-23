// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

const (
	journalRingLimit       = 4096
	maxJournalLine         = 1 << 20
	checkpointInterval     = 64
	checkpointPathName     = "checkpoints.jsonl"
	signingKeyName         = "signing.key"
	journalName            = "events.jsonl"
	journalArchiveDirName  = "archives"
	journalArchiveSchema   = 1
	journalTimeSourceWall  = "SYSTEM_UTC"
	journalTimeSourceClock = "SYSTEM_UTC_ROLLBACK_DETECTED"
)

// journalRotateBytes bounds the active journal file. The active file is rotated
// into a signed retention archive before it can reach the historical 512 MiB
// hard stop, so evidence recording does not simply end when the file grows.
var journalRotateBytes int64 = 256 << 20

// checkpointStoreRotateBytes bounds the checkpoint append log. Old checkpoints
// stay available in a rotated forensic copy.
var checkpointStoreRotateBytes int64 = 8 << 20

// journalClockTolerance is how far the wall clock may move backwards before the
// journal marks an event as recorded under a rolled-back clock.
var journalClockTolerance = 5 * time.Minute

// journalNow is a test hook so clock-rollback handling can be exercised without
// touching the machine clock.
var journalNow = time.Now

// Journal is the append-only Titan evidence chain. It is tamper-evident, not
// tamper-proof: its signed checkpoints are what a future independent witness can
// anchor outside this host.
type Journal struct {
	mu           sync.Mutex
	root         string
	path         string
	file         *os.File
	size         int64
	bootID       string
	sequence     uint64
	lastHash     string
	ring         []Event
	checkpoints  []Checkpoint
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	publicSHA256 string
	lastCheck    CheckpointStatus
	journalError string
	journalBad   bool
	ledger       *evidence.Ledger
	reviews      map[string]time.Time
	eventTotal   uint64

	archives          []journalArchive
	archivedEvents    uint64
	archiveCheckpoint map[uint64]string
	fileFirstSequence uint64
	fileFirstHash     string
	lastTimestamp     time.Time
	clockRollback     bool
}

func OpenJournal(root string, ledger *evidence.Ledger) (*Journal, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("titan journal root must be absolute")
	}
	if err := ensurePrivateDir(root); err != nil {
		return nil, err
	}
	privateKey, publicKey, fingerprint, err := loadOrCreateSigningKey(filepath.Join(root, "keys", signingKeyName))
	if err != nil {
		return nil, err
	}
	bootRandom := make([]byte, 8)
	if _, err := rand.Read(bootRandom); err != nil {
		return nil, err
	}
	journal := &Journal{
		root: root, path: filepath.Join(root, journalName), bootID: hex.EncodeToString(bootRandom),
		privateKey: privateKey, publicKey: publicKey, publicSHA256: fingerprint, ledger: ledger,
		reviews: make(map[string]time.Time), archiveCheckpoint: make(map[uint64]string),
		fileFirstSequence: 1,
	}
	// Checkpoints are loaded before the archive scan so the archive verification
	// can resolve checkpoint sequences without keeping the whole archive in RAM.
	if err := journal.loadCheckpoints(); err != nil {
		journal.journalError = "Checkpoint-Speicher wurde als Forensikkopie gesichert und neu aufgebaut: " + err.Error()
	}
	if err := journal.loadArchives(); err != nil {
		return nil, err
	}
	if err := journal.loadJournal(); err != nil {
		if resetErr := journal.resetCorruptJournal(err); resetErr != nil {
			return nil, errors.Join(err, resetErr)
		}
	}
	if journal.file == nil {
		if err := journal.openCurrent(); err != nil {
			return nil, err
		}
	}
	if journal.sequence > 0 && journal.lastCheck.Sequence == 0 {
		if _, err := journal.checkpointLocked(journalNow().UTC()); err != nil {
			journal.journalError = "Checkpoint konnte nicht neu verankert werden: " + err.Error()
		}
	}
	if len(journal.ring) < journalRingLimit && len(journal.archives) > 0 {
		journal.fillRingFromArchive()
	}
	if len(journal.ring) > 0 {
		journal.lastTimestamp = journal.ring[len(journal.ring)-1].TimestampUTC
	}
	return journal, nil
}

// loadOrCreateSigningKey stores the Ed25519 seed in a dedicated keys/
// subdirectory that carries a SYSTEM/Administrators-only DACL (DP-FIND-001).
// Existing installations that keep the legacy root-level signing.key are
// migrated once, then the legacy file is removed.
func loadOrCreateSigningKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	legacy := filepath.Join(filepath.Dir(filepath.Dir(path)), signingKeyName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if raw, legacyErr := os.ReadFile(legacy); legacyErr == nil {
			privateKey, publicKey, fingerprint, parseErr := parseSigningKey(raw)
			if parseErr == nil {
				encoded := []byte(base64.RawStdEncoding.EncodeToString(privateKey.Seed()))
				if writeErr := secretfs.CreateSecretFile(path, encoded); writeErr == nil {
					_ = os.Remove(legacy)
					return privateKey, publicKey, fingerprint, nil
				}
			}
		}
	}
	privateKey, publicKey, fingerprint, err := secretfs.LoadOrCreateEd25519Seed(path)
	if err != nil {
		return nil, nil, "", err
	}
	if _, legacyErr := os.Lstat(legacy); legacyErr == nil {
		// A different valid seed in two locations would break checkpoint
		// verification after the migration; fail closed for operator review.
		if raw, readErr := os.ReadFile(legacy); readErr == nil {
			if _, _, legacyFingerprint, parseErr := parseSigningKey(raw); parseErr == nil && legacyFingerprint != fingerprint {
				return nil, nil, "", errors.New("titan signing key exists in both legacy and protected locations with different seeds")
			}
		}
	}
	return privateKey, publicKey, fingerprint, nil
}

func parseSigningKey(raw []byte) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	seed, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, "", errors.New("titan signing key is invalid")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(publicKey)
	return privateKey, publicKey, hex.EncodeToString(fingerprint[:]), nil
}

func (j *Journal) loadJournal() error {
	expectedSequence := j.sequence + 1
	previous := j.lastHash
	file, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	j.size = info.Size()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxJournalLine)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return errors.New("titan journal contains invalid JSON")
		}
		if event.Sequence != expectedSequence || event.PreviousHash != previous {
			return errors.New("titan journal chain linkage invalid")
		}
		provided, decodeErr := hex.DecodeString(event.Hash)
		expected := eventHash(event)
		expectedBytes, expectedErr := hex.DecodeString(expected)
		if decodeErr != nil || expectedErr != nil || len(provided) != sha256.Size || !bytes.Equal(provided, expectedBytes) {
			return errors.New("titan journal authentication failed")
		}
		if event.Type == EventReviewed && event.Object.Name != "" {
			j.reviews[event.Object.Name] = event.TimestampUTC
		}
		j.sequence = event.Sequence
		j.lastHash = event.Hash
		j.eventTotal++
		j.ring = append(j.ring, event)
		if len(j.ring) > journalRingLimit {
			copy(j.ring, j.ring[1:])
			j.ring = j.ring[:journalRingLimit]
		}
		previous = event.Hash
		expectedSequence++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// fillRingFromArchive tops the in-memory event ring up with the tail of the
// newest archive so attribution/review state survives a rotation boundary.
func (j *Journal) fillRingFromArchive() {
	if len(j.archives) == 0 {
		return
	}
	newest := j.archives[len(j.archives)-1]
	events, err := readLastJournalEvents(filepath.Join(j.root, journalArchiveDirName, newest.Name), journalRingLimit-len(j.ring))
	if err != nil {
		return
	}
	if len(events) == 0 {
		return
	}
	combined := make([]Event, 0, len(events)+len(j.ring))
	combined = append(combined, events...)
	combined = append(combined, j.ring...)
	if len(combined) > journalRingLimit {
		combined = combined[len(combined)-journalRingLimit:]
	}
	j.ring = combined
	for _, event := range j.ring {
		if event.Type == EventReviewed && event.Object.Name != "" {
			j.reviews[event.Object.Name] = event.TimestampUTC
		}
	}
}

func (j *Journal) resetCorruptJournal(cause error) error {
	stamp := journalNow().UTC().Format("20060102T150405Z")
	corruptName := fmt.Sprintf("events.corrupt-%s.jsonl", stamp)
	corruptPath := filepath.Join(j.root, corruptName)
	if err := os.Rename(j.path, corruptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	checkpointSource := filepath.Join(j.root, checkpointPathName)
	checkpointTarget := filepath.Join(j.root, fmt.Sprintf("checkpoints.corrupt-%s.jsonl", stamp))
	if err := os.Rename(checkpointSource, checkpointTarget); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	j.journalError = "Journal war nicht verifizierbar und wurde unverändert als Forensikkopie gesichert: " + cause.Error()
	j.journalBad = true
	j.sequence = 0
	j.lastHash = ""
	j.ring = nil
	j.reviews = make(map[string]time.Time)
	j.eventTotal = 0
	j.checkpoints = nil
	j.lastCheck = CheckpointStatus{}
	return nil
}

func (j *Journal) openCurrent() error {
	file, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	j.file = file
	j.size = info.Size()
	if j.fileFirstSequence == 0 {
		j.fileFirstSequence = j.sequence + 1
	}
	return nil
}

// loadCheckpoints reads the whole signed checkpoint log instead of failing at a
// fixed 4096-entry boundary. The in-memory ring is bounded, but every retained
// checkpoint is verified and can anchor the chain (DP-FIND-011).
func (j *Journal) loadCheckpoints() error {
	path := filepath.Join(j.root, checkpointPathName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return j.quarantineCheckpointStore("not a regular file")
	}
	if info.Size() > checkpointStoreRotateBytes*2 {
		return j.quarantineCheckpointStore("checkpoint store size boundary exceeded")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 16<<10), 256<<10)
	checkpoints := make([]Checkpoint, 0, 128)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var checkpoint Checkpoint
		if err := json.Unmarshal(line, &checkpoint); err != nil {
			return j.quarantineCheckpointStore("invalid JSON")
		}
		if err := j.verifyCheckpoint(checkpoint); err != nil {
			return j.quarantineCheckpointStore(err.Error())
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := scanner.Err(); err != nil {
		return j.quarantineCheckpointStore("checkpoint store read rejected")
	}
	if len(checkpoints) > journalRingLimit {
		checkpoints = checkpoints[len(checkpoints)-journalRingLimit:]
	}
	j.checkpoints = checkpoints
	if len(checkpoints) > 0 {
		last := checkpoints[len(checkpoints)-1]
		j.lastCheck = CheckpointStatus{Sequence: last.Sequence, CreatedUTC: last.CreatedUTC,
			PublicKeySHA256: last.PublicKeySHA256, Signature: last.Signature, Verified: true}
	}
	return nil
}

// quarantineCheckpointStore preserves a damaged checkpoint tail unchanged for
// forensics and rebuilds a fresh signed store after the journal chain has been
// verified. A corrupt checkpoint tail must not permanently mark the journal as
// tampered (DP-FIND-011).
func (j *Journal) quarantineCheckpointStore(reason string) error {
	stamp := journalNow().UTC().Format("20060102T150405Z")
	source := filepath.Join(j.root, checkpointPathName)
	target := filepath.Join(j.root, fmt.Sprintf("checkpoints.corrupt-%s.jsonl", stamp))
	if err := os.Rename(source, target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("titan checkpoint store rejected: "+reason), err)
	}
	j.checkpoints = nil
	j.lastCheck = CheckpointStatus{}
	return errors.New("titan checkpoint store quarantined: " + reason)
}

func (j *Journal) verifyCheckpoint(checkpoint Checkpoint) error {
	if checkpoint.Sequence == 0 || !validSHA256(checkpoint.LastHash) || checkpoint.PublicKeySHA256 != j.publicSHA256 {
		return errors.New("titan checkpoint metadata invalid")
	}
	signature, err := hex.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("titan checkpoint signature encoding invalid")
	}
	message := checkpointMessage(checkpoint)
	if !ed25519.Verify(j.publicKey, message, signature) {
		return errors.New("titan checkpoint signature invalid")
	}
	return nil
}

func (j *Journal) Append(observation Observation) (Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		if err := j.openCurrent(); err != nil {
			return Event{}, err
		}
	}
	now := journalNow().UTC()
	timeSource := journalTimeSourceWall
	if !j.lastTimestamp.IsZero() && now.Add(journalClockTolerance).Before(j.lastTimestamp) {
		// Wall clock moved backwards significantly. The event is still recorded
		// (evidence must not be silently dropped), but it is marked so consumers
		// never treat a rolled-back timestamp as a trusted ordering anchor.
		j.clockRollback = true
		timeSource = journalTimeSourceClock
		j.journalError = "Systemzeit ist rückwärts gesprungen; Evidenzzeitstempel sind als nicht vertrauenswürdig markiert."
	}
	event := Event{
		Sequence: j.sequence + 1, ID: randomEventID(), BootID: j.bootID,
		TimestampUTC: now, TimeSource: timeSource, Type: observation.Type, Severity: observation.Severity,
		Object: observation.Object, Actor: observation.Actor, Network: observation.Network,
		Authorization: observation.Authorization,
		Response:      observation.Response, Collection: Collection{Source: observation.Source, TelemetryHealth: observation.Health},
		PreviousHash: j.lastHash,
	}
	if event.Collection.TelemetryHealth == "" {
		event.Collection.TelemetryHealth = "HEALTHY"
	}
	if event.Collection.ObservationError == "" {
		event.Collection.ObservationError = observation.Detail
	}
	event.Hash = eventHash(event)
	line, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if int64(len(line))+1 > maxJournalLine {
		return Event{}, errors.New("titan journal event exceeds the line boundary")
	}
	if j.size+int64(len(line))+1 > journalRotateBytes {
		if err := j.rotateLocked(now); err != nil {
			return Event{}, err
		}
	}
	if _, err := j.file.Write(append(line, '\n')); err != nil {
		return Event{}, err
	}
	if err := j.file.Sync(); err != nil {
		return Event{}, err
	}
	j.size += int64(len(line)) + 1
	j.sequence = event.Sequence
	j.lastHash = event.Hash
	j.eventTotal++
	if j.lastTimestamp.IsZero() || now.After(j.lastTimestamp) {
		j.lastTimestamp = now
	}
	if event.Type == EventReviewed && event.Object.Name != "" {
		j.reviews[event.Object.Name] = event.TimestampUTC
	}
	j.ring = append(j.ring, event)
	if len(j.ring) > journalRingLimit {
		copy(j.ring, j.ring[1:])
		j.ring = j.ring[:journalRingLimit]
	}
	if j.sequence%checkpointInterval == 0 {
		if _, err := j.checkpointLocked(now); err != nil {
			j.journalError = "Checkpoint konnte nicht geschrieben werden: " + err.Error()
		}
	}
	return event, nil
}

func (j *Journal) Recent(limit, offset int, filter EventFilter) ([]Event, int, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 1_000_000 {
		return nil, 0, errors.New("titan event window rejected")
	}
	if !ValidFilter(filter) {
		return nil, 0, errors.New("titan event filter rejected")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	filtered := make([]Event, 0, len(j.ring))
	for index := len(j.ring) - 1; index >= 0; index-- {
		event := j.ring[index]
		if !matchesFilter(event, filter) {
			continue
		}
		filtered = append(filtered, event)
	}
	total := len(filtered)
	if offset >= total {
		return []Event{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return append([]Event(nil), filtered[offset:end]...), total, nil
}

func matchesFilter(event Event, filter EventFilter) bool {
	switch filter {
	case FilterUnexpected:
		return event.Authorization.Status == TrustUnexpected || event.Authorization.Status == TrustCompromised
	case FilterPersistence:
		return event.Authorization.RiskClass == RiskPersistence || event.Authorization.RiskClass == RiskSystem
	case FilterSecurity:
		return event.Authorization.RiskClass == RiskSecurity || event.Authorization.RiskClass == RiskBoot
	case FilterQuarantine:
		return event.Type == EventQuarantined || event.Type == EventRestored || event.Response.State == "QUARANTINED"
	default:
		return true
	}
}

func (j *Journal) Checkpoint(force bool) (CheckpointStatus, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !force && j.lastCheck.Sequence == j.sequence {
		return j.lastCheck, nil
	}
	if j.lastCheck.Sequence == j.sequence && j.lastCheck.Signature != "" {
		return j.lastCheck, nil
	}
	checkpoint, err := j.checkpointLocked(journalNow().UTC())
	if err != nil {
		return CheckpointStatus{}, err
	}
	return CheckpointStatus{Sequence: checkpoint.Sequence, CreatedUTC: checkpoint.CreatedUTC,
		PublicKeySHA256: checkpoint.PublicKeySHA256, Signature: checkpoint.Signature, Verified: true}, nil
}

func (j *Journal) checkpointLocked(now time.Time) (Checkpoint, error) {
	if j.sequence == 0 || j.lastHash == "" {
		return Checkpoint{}, errors.New("titan checkpoint requires at least one event")
	}
	checkpoint := Checkpoint{Sequence: j.sequence, LastHash: j.lastHash, CreatedUTC: now, BootID: j.bootID,
		PublicKeySHA256: j.publicSHA256}
	checkpoint.Signature = hex.EncodeToString(ed25519.Sign(j.privateKey, checkpointMessage(checkpoint)))
	line, err := json.Marshal(checkpoint)
	if err != nil {
		return Checkpoint{}, err
	}
	storePath := filepath.Join(j.root, checkpointPathName)
	if info, statErr := os.Stat(storePath); statErr == nil && info.Size()+int64(len(line))+1 > checkpointStoreRotateBytes {
		stamp := journalNow().UTC().Format("20060102T150405Z")
		target := filepath.Join(j.root, fmt.Sprintf("checkpoints.old-%s.jsonl", stamp))
		if renameErr := os.Rename(storePath, target); renameErr != nil && !errors.Is(renameErr, os.ErrNotExist) {
			return Checkpoint{}, renameErr
		}
	}
	file, err := os.OpenFile(storePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return Checkpoint{}, err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		_ = file.Close()
		return Checkpoint{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return Checkpoint{}, err
	}
	if err := file.Close(); err != nil {
		return Checkpoint{}, err
	}
	j.checkpoints = append(j.checkpoints, checkpoint)
	if len(j.checkpoints) > journalRingLimit {
		copy(j.checkpoints, j.checkpoints[len(j.checkpoints)-journalRingLimit:])
		j.checkpoints = j.checkpoints[:journalRingLimit]
	}
	j.lastCheck = CheckpointStatus{Sequence: checkpoint.Sequence, CreatedUTC: checkpoint.CreatedUTC,
		PublicKeySHA256: checkpoint.PublicKeySHA256, Signature: checkpoint.Signature, Verified: true}
	if j.ledger != nil {
		if err := j.ledger.Append("titan.evidence", "checkpoint", fmt.Sprintf("sequence=%d", checkpoint.Sequence)); err != nil {
			j.journalError = "Ledger-Checkpoint konnte nicht geschrieben werden: " + err.Error()
		}
	}
	return checkpoint, nil
}

func (j *Journal) Checkpoints(limit int) []Checkpoint {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make([]Checkpoint, 0, limit)
	for index := len(j.checkpoints) - 1; index >= 0 && len(result) < limit; index-- {
		result = append(result, j.checkpoints[index])
	}
	return result
}

func (j *Journal) Verify() VerificationResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := VerificationResult{CheckedUTC: journalNow().UTC(), Events: len(j.ring), Checkpoints: len(j.checkpoints)}
	if j.journalBad {
		result.Detail = j.journalError
		return result
	}
	if err := j.verifyArchivesLocked(false); err != nil {
		result.Detail = err.Error()
		return result
	}
	checkpointHashes := make(map[uint64]string, len(j.checkpoints))
	for sequence, hash := range j.archiveCheckpoint {
		checkpointHashes[sequence] = hash
	}
	total := j.archivedEvents + j.eventTotal
	if total == 0 {
		file, err := os.Open(j.path)
		if errors.Is(err, os.ErrNotExist) {
			result.Verified = true
			result.Detail = "Noch keine Titan-Ereignisse aufgezeichnet."
			return result
		}
		if err != nil {
			result.Detail = err.Error()
			return result
		}
		_ = file.Close()
	}
	file, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) {
		file = nil
	} else if err != nil {
		result.Detail = err.Error()
		return result
	}
	if file != nil {
		defer func() { _ = file.Close() }()
		expectedSequence := j.fileFirstSequence
		previous := j.fileFirstHash
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), maxJournalLine)
		for scanner.Scan() {
			var event Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				result.Detail = "Journal enthält ungültiges JSON."
				return result
			}
			if event.Sequence != expectedSequence || event.PreviousHash != previous || event.Hash != eventHash(event) {
				result.Detail = "Journal-Kette oder Ereignis-Hash ist ungültig."
				return result
			}
			if result.FirstSequence == 0 {
				result.FirstSequence = event.Sequence
			}
			result.LastSequence = event.Sequence
			result.Events++
			checkpointHashes[event.Sequence] = event.Hash
			previous = event.Hash
			expectedSequence++
		}
		if err := scanner.Err(); err != nil {
			result.Detail = err.Error()
			return result
		}
	}
	var previousCheckpoint uint64
	for _, checkpoint := range j.checkpoints {
		if err := j.verifyCheckpoint(checkpoint); err != nil {
			result.Detail = err.Error()
			return result
		}
		if checkpoint.Sequence <= previousCheckpoint || checkpoint.Sequence > total {
			result.Detail = "Checkpoint deckt keine gültige Journal-Position ab."
			return result
		}
		if hash, exists := checkpointHashes[checkpoint.Sequence]; exists && hash != checkpoint.LastHash {
			result.Detail = "Checkpoint verweist nicht auf den verifizierten Journal-Hash."
			return result
		}
		previousCheckpoint = checkpoint.Sequence
	}
	result.Verified = true
	result.Detail = "Journal-Kette, signierte Retentionsarchive und alle Checkpoint-Signaturen sind gültig."
	return result
}

func (j *Journal) MarkReviewed(eventID, note string) (Event, error) {
	if eventID == "" || len(eventID) > 64 || strings.ContainsAny(eventID, "\r\n\x00") {
		return Event{}, errors.New("titan review target rejected")
	}
	note = strings.TrimSpace(note)
	if len(note) < 8 || len(note) > 512 {
		return Event{}, errors.New("titan review reason boundary rejected")
	}
	return j.Append(Observation{
		Type: EventReviewed, Severity: SeverityLow,
		Object:   Object{Kind: ObjectQuarantine, Name: eventID, Path: eventID},
		Response: Response{Action: "REVIEW", State: "RECORDED", Detail: note},
		Source:   "titan-owner", Health: "HEALTHY", Detail: note,
	})
}

func (j *Journal) Reviewed(eventID string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, exists := j.reviews[eventID]
	return exists
}

func (j *Journal) Find(eventID string) (Event, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for index := len(j.ring) - 1; index >= 0; index-- {
		if j.ring[index].ID == eventID {
			return j.ring[index], true
		}
	}
	return Event{}, false
}

func (j *Journal) OpenFindings() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	count := 0
	for _, event := range j.ring {
		if event.Authorization.Status != TrustUnexpected && event.Authorization.Status != TrustCompromised {
			continue
		}
		if _, reviewed := j.reviews[event.ID]; reviewed {
			continue
		}
		count++
	}
	return count
}

func (j *Journal) LastEventUTC() time.Time {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.ring) == 0 {
		return time.Time{}
	}
	return j.ring[len(j.ring)-1].TimestampUTC
}

func (j *Journal) Count() uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.eventTotal + j.archivedEvents
}

func (j *Journal) Posture() TrustStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	posture := TrustAuthorized
	for _, event := range j.ring {
		if event.Authorization.Status != TrustUnexpected && event.Authorization.Status != TrustCompromised {
			continue
		}
		if _, reviewed := j.reviews[event.ID]; reviewed {
			continue
		}
		if event.Authorization.Status == TrustCompromised {
			return TrustCompromised
		}
		posture = TrustUnexpected
	}
	if posture == TrustAuthorized && len(j.ring) > 0 {
		return TrustTolerated
	}
	return posture
}

func (j *Journal) Export(limit int) (EvidenceBundle, VerificationResult, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	events, _, err := j.Recent(limit, 0, FilterAll)
	if err != nil {
		return EvidenceBundle{}, VerificationResult{}, err
	}
	verification := j.Verify()
	bundle := EvidenceBundle{
		SchemaVersion: 1, GeneratedUTC: journalNow().UTC(), BootID: j.bootID,
		Events: events, Checkpoints: j.Checkpoints(100), Verification: verification,
		PublicKeySHA256: j.publicSHA256,
		Limitations: []string{
			"Das Paket belegt technische Beobachtungen und ihre Verkettung, nicht die Urheberschaft oder Absicht eines Akteurs.",
			"Fehlende Prozess- oder Netzwerkzuordnung ist als NONE/TEMPORAL ausgewiesen und kein Beweis für Unbeteiligte.",
			"Ein lokaler Checkpoint ist tamper-evident, aber ohne unabhängigen Witness nicht gegen vollständige Host-Kontrolle geschützt.",
			"Rotierte Journalarchive sind mit einem signierten Manifest (Datei-SHA-256, Sequenzgrenzen) verankert; der aktive Teil bleibt separat verkettet.",
		},
	}
	return bundle, verification, nil
}

func (j *Journal) Status() CheckpointStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.journalBad {
		status := j.lastCheck
		status.Verified = false
		status.Detail = j.journalError
		return status
	}
	status := j.lastCheck
	if j.journalError != "" {
		status.Detail = j.journalError
	}
	return status
}

func (j *Journal) PublicKeySHA256() string { return j.publicSHA256 }

func (j *Journal) BootID() string { return j.bootID }

func (j *Journal) Error() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.journalError
}

func (j *Journal) Total() uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.eventTotal + j.archivedEvents
}

// ClockRollbackDetected reports whether the wall clock moved backwards while
// this journal was active.
func (j *Journal) ClockRollbackDetected() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.clockRollback
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

func eventHash(event Event) string {
	event.Hash = ""
	raw, _ := json.Marshal(event)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func checkpointMessage(checkpoint Checkpoint) []byte {
	message := struct {
		Sequence        uint64 `json:"sequence"`
		LastHash        string `json:"lastHash"`
		CreatedUTC      string `json:"createdUtc"`
		BootID          string `json:"bootId"`
		PublicKeySHA256 string `json:"publicKeySha256"`
	}{
		Sequence: checkpoint.Sequence, LastHash: checkpoint.LastHash,
		CreatedUTC: checkpoint.CreatedUTC.UTC().Format(time.RFC3339Nano),
		BootID:     checkpoint.BootID, PublicKeySHA256: checkpoint.PublicKeySHA256,
	}
	raw, _ := json.Marshal(message)
	return raw
}

func randomEventID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("evt-%d", journalNow().UnixNano())
	}
	return "evt-" + hex.EncodeToString(raw)
}

// readLastJournalEvents reads the newest n events from one journal archive in
// chronological order. It scans backwards so a large archive does not have to be
// loaded into memory just to seed the bounded event ring.
func readLastJournalEvents(path string, n int) ([]Event, error) {
	if n <= 0 {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}
	const chunkSize = 256 << 10
	lines := make([][]byte, 0, n)
	var carry []byte
	position := size
	for position > 0 && len(lines) < n {
		step := int64(chunkSize)
		if step > position {
			step = position
		}
		position -= step
		chunk := make([]byte, step)
		if _, err := file.ReadAt(chunk, position); err != nil {
			return nil, err
		}
		combined := append(append([]byte(nil), chunk...), carry...)
		end := len(combined)
		for end > 0 && len(lines) < n {
			index := bytes.LastIndexByte(combined[:end], '\n')
			if index < 0 {
				break
			}
			line := combined[index+1 : end]
			end = index
			if len(line) == 0 {
				continue
			}
			lines = append(lines, append([]byte(nil), line...))
		}
		if len(lines) >= n {
			break
		}
		carry = append([]byte(nil), combined[:end]...)
	}
	if len(lines) < n && len(carry) > 0 {
		lines = append(lines, carry)
	}
	events := make([]Event, 0, len(lines))
	for index := len(lines) - 1; index >= 0; index-- {
		var event Event
		if err := json.Unmarshal(lines[index], &event); err != nil {
			return nil, errors.New("titan archive contains invalid JSON")
		}
		events = append(events, event)
	}
	return events, nil
}
