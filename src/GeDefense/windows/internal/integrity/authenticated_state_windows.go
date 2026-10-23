// STATUS: DIAMANT VGT SUPREME
//go:build windows

package integrity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	snapshotManifestSchema      = 1
	integrityStateSigningDomain = "VGT-GEDEFENSE-INTEGRITY-STATE-V2"
	snapshotManifestDomain      = "VGT-GEDEFENSE-INTEGRITY-MANIFEST-V2"
	maxSnapshotManifestBytes    = 256 << 10
	maximumRetainedGenerations  = 5
)

// persistedState is the authenticated integrity configuration/status document.
type persistedState struct {
	Enabled       bool      `json:"enabled"`
	IntervalHours int       `json:"intervalHours"`
	LastScanUTC   time.Time `json:"lastScanUtc,omitempty"`
	Generation    string    `json:"generation,omitempty"`
	Status        Status    `json:"status"`
	MAC           string    `json:"mac,omitempty"`
}

type snapshotBucket struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Records int64  `json:"records"`
}

// snapshotManifest authenticates one snapshot generation (bucket hashes, record
// counts, changes-report hash and generation identifier). The MAC is derived from
// the protected evidence-ledger key, so a tampered baseline or change history is
// rejected even when the attacker can write the integrity root (DP-FIND-013).
type snapshotManifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	Generation    string           `json:"generation"`
	CreatedUTC    time.Time        `json:"createdUtc"`
	Buckets       []snapshotBucket `json:"buckets"`
	TotalRecords  int64            `json:"totalRecords"`
	ChangesSHA256 string           `json:"changesSha256"`
	MAC           string           `json:"mac,omitempty"`
}

func (e *Engine) signState(state persistedState) (string, error) {
	unsigned := state
	unsigned.MAC = ""
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	return e.ledger.Sign(integrityStateSigningDomain, raw)
}

func (e *Engine) authenticateState(state persistedState) error {
	if state.MAC == "" {
		return errors.New("integrity state is not authenticated")
	}
	unsigned := state
	unsigned.MAC = ""
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	return e.ledger.VerifySignature(integrityStateSigningDomain, raw, state.MAC)
}

func validGenerationID(generation string) bool {
	if len(generation) != 33 {
		return false
	}
	if generation[16] != '-' {
		return false
	}
	if _, err := time.Parse("20060102T150405Z", generation[:16]); err != nil {
		return false
	}
	for index := 17; index < 33; index++ {
		character := generation[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// writeSnapshotManifest authenticates the snapshot directory after all bucket
// and changes files have been closed. It must be called before the directory is
// renamed into its final generation path.
func (e *Engine) writeSnapshotManifest(directory, generation string, totalRecords int64) (err error) {
	manifest := snapshotManifest{
		SchemaVersion: snapshotManifestSchema, Generation: generation, CreatedUTC: time.Now().UTC(),
		Buckets: make([]snapshotBucket, 0, bucketCount), TotalRecords: totalRecords,
	}
	for index := 0; index < bucketCount; index++ {
		name := fmt.Sprintf("%02x.jsonl", index)
		digest, records, hashErr := hashBucketFile(filepath.Join(directory, name))
		if hashErr != nil {
			return hashErr
		}
		manifest.Buckets = append(manifest.Buckets, snapshotBucket{Name: name, SHA256: digest, Records: records})
	}
	changesDigest, err := hashFileSHA256(filepath.Join(directory, "changes.jsonl"))
	if err != nil {
		return err
	}
	manifest.ChangesSHA256 = changesDigest
	unsigned := manifest
	unsigned.MAC = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	mac, err := e.ledger.Sign(snapshotManifestDomain, payload)
	if err != nil {
		return err
	}
	manifest.MAC = mac
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if len(raw) > maxSnapshotManifestBytes {
		return errors.New("integrity snapshot manifest exceeds the boundary")
	}
	return os.WriteFile(filepath.Join(directory, "manifest.json"), append(raw, '\n'), 0o600)
}

func readSnapshotManifest(directory string) (snapshotManifest, error) {
	raw, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return snapshotManifest{}, err
	}
	if len(raw) == 0 || len(raw) > maxSnapshotManifestBytes {
		return snapshotManifest{}, errors.New("integrity snapshot manifest size rejected")
	}
	var manifest snapshotManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return snapshotManifest{}, errors.New("integrity snapshot manifest decoding rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return snapshotManifest{}, errors.New("integrity snapshot manifest trailing data rejected")
	}
	if manifest.SchemaVersion != snapshotManifestSchema || !validGenerationID(manifest.Generation) ||
		len(manifest.Buckets) != bucketCount || len(manifest.MAC) != 64 || len(manifest.ChangesSHA256) != 64 {
		return snapshotManifest{}, errors.New("integrity snapshot manifest metadata rejected")
	}
	for _, bucket := range manifest.Buckets {
		if len(bucket.Name) != len("00.jsonl") || len(bucket.SHA256) != 64 || bucket.Records < 0 {
			return snapshotManifest{}, errors.New("integrity snapshot bucket metadata rejected")
		}
	}
	return manifest, nil
}

func (e *Engine) authenticateSnapshotManifest(manifest snapshotManifest) error {
	if manifest.MAC == "" {
		return errors.New("integrity snapshot manifest is not authenticated")
	}
	unsigned := manifest
	unsigned.MAC = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	return e.ledger.VerifySignature(snapshotManifestDomain, payload, manifest.MAC)
}

// verifySnapshotBuckets re-hashes the retained snapshot files against the
// authenticated manifest, so a modified baseline record is detected.
func verifySnapshotBuckets(directory string, manifest snapshotManifest) error {
	for _, bucket := range manifest.Buckets {
		digest, records, err := hashBucketFile(filepath.Join(directory, bucket.Name))
		if err != nil {
			return err
		}
		if digest != bucket.SHA256 || records != bucket.Records {
			return errors.New("integrity snapshot bucket does not match its authenticated manifest")
		}
	}
	return nil
}

func hashBucketFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, hash))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	var records int64
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		records++
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), records, nil
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

// pruneGenerations keeps the newest retained generations and deletes older
// snapshot directories (DP-FIND-013 disk-growth finding). Only directories with
// a strictly validated generation identifier are eligible; anything else is left
// untouched for forensic review.
func (e *Engine) pruneGenerations(keep int) {
	if keep < 1 {
		keep = 1
	}
	entries, err := os.ReadDir(filepath.Join(e.root, "snapshots"))
	if err != nil {
		return
	}
	generations := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !validGenerationID(entry.Name()) {
			continue
		}
		generations = append(generations, entry.Name())
	}
	sort.Strings(generations)
	pruned := 0
	for len(generations) > keep {
		oldest := generations[0]
		if oldest == e.Status().Generation {
			generations = generations[1:]
			continue
		}
		if err := os.RemoveAll(filepath.Join(e.root, "snapshots", oldest)); err == nil {
			pruned++
		}
		generations = generations[1:]
	}
	if pruned > 0 {
		e.appendEvidence("integrity.retention", "snapshot-generations", fmt.Sprintf("pruned=%d retained=%d", pruned, keep))
	}
}

// isReparseInfo detects junctions/mount points/cloud placeholders, not only
// symlinks, so WalkDir cannot traverse or duplicate a reparse-point target.
func isReparseInfo(info os.FileInfo) bool {
	if info == nil {
		return true
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return data.FileAttributes&winapi.FileAttributeReparsePoint != 0
	}
	return true
}

// appendEvidence records an audit entry and surfaces append failures in the
// engine status instead of silently dropping evidence (DP-FIND-012).
func (e *Engine) appendEvidence(kind, action, result string) error {
	if e.ledger == nil {
		return errors.New("integrity evidence ledger unavailable")
	}
	if err := e.ledger.Append(kind, action, result); err != nil {
		e.mu.Lock()
		e.status.Error = "evidence ledger append failed: " + err.Error()
		if e.status.State == "VERIFIED" || e.status.State == "BASELINE_CREATED" {
			e.status.State = "DEGRADED"
		}
		e.mu.Unlock()
		return err
	}
	return nil
}
