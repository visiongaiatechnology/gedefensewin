// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
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
	"time"
)

// journalArchive is one signed retention bundle: a rotated journal file together
// with the manifest that binds its SHA-256, sequence boundaries and hash-chain
// endpoints. Archives are what make the journal retention bounded without
// silently ending evidence recording at the historical 512 MiB hard stop.
type journalArchive struct {
	Name              string
	ManifestName      string
	FirstSequence     uint64
	LastSequence      uint64
	FirstPreviousHash string
	LastHash          string
	SHA256            string
	CreatedUTC        time.Time
	Manifest          journalArchiveManifest

	verifiedSize    int64
	verifiedModTime int64
}

type journalArchiveManifest struct {
	SchemaVersion     int       `json:"schemaVersion"`
	FirstSequence     uint64    `json:"firstSequence"`
	LastSequence      uint64    `json:"lastSequence"`
	FirstPreviousHash string    `json:"firstPreviousHash,omitempty"`
	LastHash          string    `json:"lastHash"`
	SHA256            string    `json:"sha256"`
	CreatedUTC        time.Time `json:"createdUtc"`
	PublicKeySHA256   string    `json:"publicKeySha256"`
	Signature         string    `json:"signatureEd25519"`
}

func journalArchiveManifestMessage(manifest journalArchiveManifest) []byte {
	message := struct {
		SchemaVersion     int    `json:"schemaVersion"`
		FirstSequence     uint64 `json:"firstSequence"`
		LastSequence      uint64 `json:"lastSequence"`
		FirstPreviousHash string `json:"firstPreviousHash,omitempty"`
		LastHash          string `json:"lastHash"`
		SHA256            string `json:"sha256"`
		CreatedUTC        string `json:"createdUtc"`
		PublicKeySHA256   string `json:"publicKeySha256"`
	}{
		SchemaVersion:     manifest.SchemaVersion,
		FirstSequence:     manifest.FirstSequence,
		LastSequence:      manifest.LastSequence,
		FirstPreviousHash: manifest.FirstPreviousHash,
		LastHash:          manifest.LastHash,
		SHA256:            manifest.SHA256,
		CreatedUTC:        manifest.CreatedUTC.UTC().Format(time.RFC3339Nano),
		PublicKeySHA256:   manifest.PublicKeySHA256,
	}
	raw, _ := json.Marshal(message)
	return raw
}

func (j *Journal) archiveDirectory() string {
	return filepath.Join(j.root, journalArchiveDirName)
}

func (j *Journal) archivePath(archive journalArchive) string {
	return filepath.Join(j.archiveDirectory(), archive.Name)
}

// loadArchives discovers, authenticates and deeply verifies every retained
// journal archive, then seeds the live chain from the newest archive so the
// active file can continue the sequence/hash chain after a rotation.
func (j *Journal) loadArchives() error {
	directory := j.archiveDirectory()
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	archives := make([]journalArchive, 0, 8)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "archive-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr != nil {
			return readErr
		}
		if len(raw) == 0 || len(raw) > 64<<10 {
			return errors.New("titan archive manifest size rejected")
		}
		manifest, decodeErr := decodeJournalArchiveManifest(raw)
		if decodeErr != nil {
			return decodeErr
		}
		manifestName := strings.TrimSuffix(entry.Name(), ".json")
		archive := journalArchive{
			Name:              strings.TrimPrefix(manifestName, "archive-") + ".jsonl",
			ManifestName:      entry.Name(),
			FirstSequence:     manifest.FirstSequence,
			LastSequence:      manifest.LastSequence,
			FirstPreviousHash: manifest.FirstPreviousHash,
			LastHash:          manifest.LastHash,
			SHA256:            manifest.SHA256,
			CreatedUTC:        manifest.CreatedUTC,
			Manifest:          manifest,
		}
		archive.Name = archiveFileName(manifest.FirstSequence, manifest.LastSequence)
		archives = append(archives, archive)
	}
	sort.Slice(archives, func(left, right int) bool { return archives[left].FirstSequence < archives[right].FirstSequence })

	expectedSequence := uint64(1)
	expectedHash := ""
	archivedEvents := uint64(0)
	for index := range archives {
		archive := &archives[index]
		if archive.FirstSequence != expectedSequence {
			return errors.New("titan archive sequence gap detected")
		}
		if archive.FirstPreviousHash != expectedHash {
			return errors.New("titan archive chain linkage invalid")
		}
		if archive.LastSequence < archive.FirstSequence || len(archive.LastHash) != 64 {
			return errors.New("titan archive boundary rejected")
		}
		// Crash recovery: the manifest is written before the file rename. If the
		// process died in between, the still-active file is the archive content.
		if _, statErr := os.Stat(j.archivePath(*archive)); errors.Is(statErr, os.ErrNotExist) {
			if recoverErr := j.completePendingArchiveRotation(*archive); recoverErr != nil {
				return recoverErr
			}
		}
		if err := j.deepVerifyArchive(archive); err != nil {
			return err
		}
		expectedSequence = archive.LastSequence + 1
		expectedHash = archive.LastHash
		archivedEvents += archive.LastSequence - archive.FirstSequence + 1
	}
	j.archives = archives
	j.archivedEvents = archivedEvents
	j.sequence = expectedSequence - 1
	j.lastHash = expectedHash
	j.fileFirstSequence = expectedSequence
	j.fileFirstHash = expectedHash
	if j.fileFirstSequence == 0 {
		j.fileFirstSequence = 1
	}
	return nil
}

func archiveFileName(firstSequence, lastSequence uint64) string {
	return fmt.Sprintf("events.%012d-%012d.jsonl", firstSequence, lastSequence)
}

func archiveManifestName(firstSequence, lastSequence uint64) string {
	return fmt.Sprintf("archive-%012d-%012d.json", firstSequence, lastSequence)
}

func decodeJournalArchiveManifest(raw []byte) (journalArchiveManifest, error) {
	var manifest journalArchiveManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return journalArchiveManifest{}, errors.New("titan archive manifest JSON rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return journalArchiveManifest{}, errors.New("titan archive manifest trailing data rejected")
	}
	if manifest.SchemaVersion != journalArchiveSchema || manifest.FirstSequence == 0 ||
		manifest.LastSequence < manifest.FirstSequence || !validSHA256(manifest.LastHash) ||
		len(manifest.SHA256) != 64 || len(manifest.PublicKeySHA256) != 64 ||
		len(manifest.Signature) != ed25519.SignatureSize*2 || manifest.CreatedUTC.IsZero() {
		return journalArchiveManifest{}, errors.New("titan archive manifest metadata rejected")
	}
	if manifest.FirstSequence > 1 && !validSHA256(manifest.FirstPreviousHash) {
		return journalArchiveManifest{}, errors.New("titan archive manifest linkage rejected")
	}
	return manifest, nil
}

func (j *Journal) authenticateArchiveManifest(manifest journalArchiveManifest) error {
	if manifest.PublicKeySHA256 != j.publicSHA256 {
		return errors.New("titan archive manifest public key rejected")
	}
	signature, err := hex.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("titan archive manifest signature encoding rejected")
	}
	if !ed25519.Verify(j.publicKey, journalArchiveManifestMessage(manifest), signature) {
		return errors.New("titan archive manifest signature invalid")
	}
	return nil
}

func (j *Journal) completePendingArchiveRotation(archive journalArchive) error {
	if _, err := os.Stat(j.path); err != nil {
		return errors.New("titan archive file and pending rotation source are both missing")
	}
	digest, err := hashJournalFile(j.path)
	if err != nil {
		return err
	}
	if digest != archive.SHA256 {
		return errors.New("titan pending archive rotation content does not match the signed manifest")
	}
	if err := os.Rename(j.path, j.archivePath(archive)); err != nil {
		return err
	}
	return nil
}

func hashJournalFile(path string) (string, error) {
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

// deepVerifyArchive authenticates the manifest, hashes the archive file, walks
// its event chain and records checkpoint-sequence hashes for later Verify calls.
func (j *Journal) deepVerifyArchive(archive *journalArchive) error {
	if err := j.authenticateArchiveManifest(archive.Manifest); err != nil {
		return err
	}
	path := j.archivePath(*archive)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("titan archive must be a regular file")
	}
	digest, err := hashJournalFile(path)
	if err != nil {
		return err
	}
	if digest != archive.SHA256 {
		return errors.New("titan archive SHA-256 mismatch")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	expectedSequence := archive.FirstSequence
	previous := archive.FirstPreviousHash
	checkpointSet := make(map[uint64]struct{}, len(j.checkpoints))
	for _, checkpoint := range j.checkpoints {
		checkpointSet[checkpoint.Sequence] = struct{}{}
	}
	lastHash := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxJournalLine)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return errors.New("titan archive contains invalid JSON")
		}
		if event.Sequence != expectedSequence || event.PreviousHash != previous || event.Hash != eventHash(event) {
			return errors.New("titan archive chain invalid")
		}
		if _, tracked := checkpointSet[event.Sequence]; tracked {
			j.archiveCheckpoint[event.Sequence] = event.Hash
		}
		lastHash = event.Hash
		previous = event.Hash
		expectedSequence++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if expectedSequence-1 != archive.LastSequence || lastHash != archive.LastHash {
		return errors.New("titan archive endpoint does not match the signed manifest")
	}
	archive.verifiedSize = info.Size()
	archive.verifiedModTime = info.ModTime().UnixNano()
	return nil
}

// verifyArchivesLocked re-authenticates manifests and archive linkage on every
// verification. The content hash is re-read only when the file changed since it
// was deeply verified (size/mtime memo); the signed manifest binds the bytes.
func (j *Journal) verifyArchivesLocked(deep bool) error {
	expectedSequence := uint64(1)
	expectedHash := ""
	for index := range j.archives {
		archive := &j.archives[index]
		if err := j.authenticateArchiveManifest(archive.Manifest); err != nil {
			return err
		}
		if archive.FirstSequence != expectedSequence || archive.FirstPreviousHash != expectedHash {
			return errors.New("titan archive chain linkage invalid")
		}
		info, err := os.Stat(j.archivePath(*archive))
		if err != nil {
			return err
		}
		if deep || info.Size() != archive.verifiedSize || info.ModTime().UnixNano() != archive.verifiedModTime {
			if err := j.deepVerifyArchive(archive); err != nil {
				return err
			}
		}
		expectedSequence = archive.LastSequence + 1
		expectedHash = archive.LastHash
	}
	return nil
}

// rotateLocked archives the active journal into a signed retention bundle and
// starts a fresh active file that continues the same hash chain.
func (j *Journal) rotateLocked(now time.Time) error {
	if j.sequence == 0 || j.size == 0 {
		return nil
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	digest, err := hashJournalFile(j.path)
	if err != nil {
		return err
	}
	firstSequence := j.fileFirstSequence
	firstPreviousHash := j.fileFirstHash
	lastSequence := uint64(0)
	lastHash := ""
	checkpointSet := make(map[uint64]struct{}, len(j.checkpoints))
	for _, checkpoint := range j.checkpoints {
		checkpointSet[checkpoint.Sequence] = struct{}{}
	}
	file, err := os.Open(j.path)
	if err != nil {
		return err
	}
	expectedSequence := firstSequence
	previous := firstPreviousHash
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxJournalLine)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			_ = file.Close()
			return errors.New("titan journal contains invalid JSON during rotation")
		}
		if event.Sequence != expectedSequence || event.PreviousHash != previous || event.Hash != eventHash(event) {
			_ = file.Close()
			return errors.New("titan journal chain invalid during rotation")
		}
		if _, tracked := checkpointSet[event.Sequence]; tracked {
			j.archiveCheckpoint[event.Sequence] = event.Hash
		}
		lastSequence = event.Sequence
		lastHash = event.Hash
		previous = event.Hash
		expectedSequence++
	}
	scanErr := scanner.Err()
	closeErr := file.Close()
	if scanErr != nil {
		return scanErr
	}
	if closeErr != nil {
		return closeErr
	}
	if lastSequence != j.sequence || lastHash != j.lastHash {
		return errors.New("titan journal changed during rotation")
	}
	manifest := journalArchiveManifest{
		SchemaVersion: journalArchiveSchema, FirstSequence: firstSequence,
		LastSequence: lastSequence, FirstPreviousHash: firstPreviousHash,
		LastHash: lastHash, SHA256: digest, CreatedUTC: now.UTC(),
		PublicKeySHA256: j.publicSHA256,
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(j.privateKey, journalArchiveManifestMessage(manifest)))
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	directory := j.archiveDirectory()
	if err := ensurePrivateDir(directory); err != nil {
		return err
	}
	// The manifest is persisted before the rename so a crash can be completed on
	// the next start; the manifest alone can never misattribute a file because it
	// binds the file SHA-256 and the full chain endpoints.
	if err := atomicWriteFile(filepath.Join(directory, archiveManifestName(firstSequence, lastSequence)), append(manifestRaw, '\n')); err != nil {
		return err
	}
	archive := journalArchive{
		Name:         archiveFileName(firstSequence, lastSequence),
		ManifestName: archiveManifestName(firstSequence, lastSequence), FirstSequence: firstSequence,
		LastSequence: lastSequence, FirstPreviousHash: firstPreviousHash, LastHash: lastHash,
		SHA256: digest, CreatedUTC: now.UTC(), Manifest: manifest,
	}
	if err := j.file.Close(); err != nil {
		return err
	}
	j.file = nil
	if err := os.Rename(j.path, j.archivePath(archive)); err != nil {
		return err
	}
	j.archives = append(j.archives, archive)
	j.archivedEvents += lastSequence - firstSequence + 1
	j.eventTotal = 0
	if err := j.openCurrent(); err != nil {
		return err
	}
	j.fileFirstSequence = lastSequence + 1
	j.fileFirstHash = lastHash
	j.lastHash = lastHash
	j.size = 0
	return nil
}
