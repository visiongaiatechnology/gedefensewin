// STATUS: DIAMANT VGT SUPREME
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DP-FIND-012: external evidence witness.
//
// The local HMAC chain plus the Ed25519-signed local checkpoints are
// tamper-evident, but an actor with full host control can still roll the whole
// data root (journal, archive and checkpoint store) back to an older, locally
// consistent state. The optional witness is a small signed tip record written
// to an operator-supplied absolute path outside the evidence data root, for
// example a UNC path or a removable medium that is not mounted on the same
// host. On Open the witness is authenticated and compared with the local chain:
//
//   - witness ahead of the local chain  => truncation/rollback; fail closed,
//   - corrupt/invalid witness record    => fail closed,
//   - witness equals the local tip      => verified,
//   - witness behind the local tip      => normal (records were appended since
//     the last witness write); the local chain is ahead, never behind,
//   - missing/unreachable witness       => documented DEGRADED state, because
//     an offline removable medium must not stop the service; it is never
//     silently ignored when the configured witness exists but is corrupt.
//
// The witness intentionally contains no secrets: schema version, sequence,
// last chain MAC, write time, the signing public key fingerprint and an
// Ed25519 signature over those fields.

const (
	witnessSchemaVersion = 1
	witnessPathEnvVar    = "VGT_EVIDENCE_WITNESS"
	maxWitnessFileBytes  = 8 << 10
	maxWitnessPathBytes  = 4096
)

// witnessRetryInterval is a test seam. After a failed witness write the next
// attempt is suppressed for this interval, so an offline removable medium never
// turns every checkpoint write into a blocking I/O attempt.
var witnessRetryInterval = time.Minute

// Options configures optional ledger behaviour. The zero value is the legacy
// behaviour without an external witness.
type Options struct {
	// WitnessPath is an absolute operator-supplied path outside the evidence
	// data root. Relative paths and paths inside the data root are rejected.
	// UNC and removable-media paths are accepted.
	WitnessPath string
}

// WitnessStatus is the operator-visible state of the external witness. It is
// safe to render in status endpoints: it contains no keys and no record data.
type WitnessStatus struct {
	// Configured is true when a witness path was supplied (option or env).
	Configured bool
	// Reachable is true when the witness file could be read or written.
	Reachable bool
	// Degraded is true when a configured witness is missing, unreadable or
	// could not be written. DEGRADED is not a security failure by itself; it
	// means the independent rollback anchor is currently unavailable.
	Degraded bool
	// Verified is true when the witness could be authenticated and did not
	// contradict the local chain.
	Verified bool
	// Sequence is the local evidence sequence recorded in the witness.
	Sequence uint64
	// LocalSequence is the local chain tip at the time the status was read.
	LocalSequence uint64
	// WrittenUTC is the write time recorded in the witness record.
	WrittenUTC time.Time
	// Detail is a bounded human-readable description (English, stable).
	Detail string
}

// witnessTip is the on-medium record. Fields are bounded by decodeWitnessTip
// before anything is trusted.
type witnessTip struct {
	SchemaVersion   int       `json:"schemaVersion"`
	Sequence        uint64    `json:"sequence"`
	LastMAC         string    `json:"lastMac"`
	WrittenUTC      time.Time `json:"writtenUtc"`
	PublicKeySHA256 string    `json:"publicKeySha256"`
	Signature       string    `json:"signatureEd25519"`
}

func witnessMessage(tip witnessTip) []byte {
	message := struct {
		SchemaVersion   int    `json:"schemaVersion"`
		Sequence        uint64 `json:"sequence"`
		LastMAC         string `json:"lastMac"`
		WrittenUTC      string `json:"writtenUtc"`
		PublicKeySHA256 string `json:"publicKeySha256"`
	}{
		SchemaVersion:   tip.SchemaVersion,
		Sequence:        tip.Sequence,
		LastMAC:         tip.LastMAC,
		WrittenUTC:      tip.WrittenUTC.UTC().Format(time.RFC3339Nano),
		PublicKeySHA256: tip.PublicKeySHA256,
	}
	raw, _ := json.Marshal(message)
	return raw
}

// defaultOptions derives the Open options from the operator environment.
func defaultOptions() Options {
	return Options{WitnessPath: os.Getenv(witnessPathEnvVar)}
}

// validateWitnessPath enforces the witness path boundary: absolute, bounded,
// outside the evidence data root. An empty path means "left".
func validateWitnessPath(path, dataDirectory string) (string, error) {
	if path == "" {
		return "", nil
	}
	if len(path) > maxWitnessPathBytes {
		return "", errors.New("evidence witness path exceeds the boundary")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("evidence witness path contains a NUL byte")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("evidence witness path must be absolute")
	}
	clean := filepath.Clean(path)
	if pathWithinDirectory(clean, dataDirectory) {
		return "", errors.New("evidence witness path must be outside the evidence data root")
	}
	return clean, nil
}

// pathWithinDirectory reports whether candidate is directory itself or below
// it. Paths are compared case-insensitively because Windows filesystems are
// case-insensitive; a witness path that aliases the data root by casing must be
// rejected just like the literal path. Cross-volume paths are not contained.
func pathWithinDirectory(candidate, directory string) bool {
	candidateClean := strings.ToLower(filepath.Clean(candidate))
	directoryClean := strings.TrimRight(strings.ToLower(filepath.Clean(directory)), string(filepath.Separator))
	if directoryClean == "" {
		return false
	}
	if candidateClean == directoryClean {
		return true
	}
	return strings.HasPrefix(candidateClean, directoryClean+string(filepath.Separator))
}

// updateWitnessLocked publishes the current signed chain tip to the external
// witness. Callers must hold the ledger mutex and must have persisted the
// corresponding signed checkpoint before calling it, so the witness never
// points past the locally anchored chain.
func (l *Ledger) updateWitnessLocked() {
	if l.witnessPath == "" || l.sequence == 0 {
		return
	}
	if !l.witnessLastFailure.IsZero() && time.Since(l.witnessLastFailure) < witnessRetryInterval {
		return
	}
	tip := witnessTip{
		SchemaVersion:   witnessSchemaVersion,
		Sequence:        l.sequence,
		LastMAC:         l.lastMAC,
		WrittenUTC:      time.Now().UTC(),
		PublicKeySHA256: l.signingPublicSHA256,
	}
	tip.Signature = hex.EncodeToString(ed25519.Sign(l.signingKey, witnessMessage(tip)))
	raw, err := json.Marshal(tip)
	if err != nil {
		l.failWitnessWriteLocked(err)
		return
	}
	if len(raw)+1 > maxWitnessFileBytes {
		l.failWitnessWriteLocked(errors.New("evidence witness record exceeds the file boundary"))
		return
	}
	if err := writeWitnessFileAtomically(l.witnessPath, raw); err != nil {
		l.failWitnessWriteLocked(err)
		return
	}
	l.witnessLastFailure = time.Time{}
	l.witnessStatus = WitnessStatus{
		Configured:    true,
		Reachable:     true,
		Verified:      true,
		Sequence:      l.sequence,
		LocalSequence: l.sequence,
		WrittenUTC:    tip.WrittenUTC,
		Detail:        "external witness holds the current signed chain tip",
	}
}

// refreshWitnessLocked publishes the tip when the configured witness is not
// current yet (missing medium came back, first start after configuration).
func (l *Ledger) refreshWitnessLocked() {
	if l.witnessPath == "" || l.sequence == 0 {
		return
	}
	if l.witnessStatus.Reachable && l.witnessStatus.Verified && l.witnessStatus.Sequence == l.sequence {
		return
	}
	l.updateWitnessLocked()
}

func (l *Ledger) failWitnessWriteLocked(err error) {
	l.witnessLastFailure = time.Now()
	l.witnessStatus = WitnessStatus{
		Configured:    true,
		Reachable:     false,
		Degraded:      true,
		LocalSequence: l.sequence,
		Detail:        "external witness write failed: " + boundedErrorText(err),
	}
	l.lastError = fmt.Errorf("evidence witness write: %w", err)
}

// verifyWitnessLocked authenticates the configured witness and compares it
// with the already verified local chain. Corrupt records and a witness that is
// ahead of the local chain fail closed; an unreachable witness only degrades.
func (l *Ledger) verifyWitnessLocked() error {
	l.witnessStatus = WitnessStatus{
		Configured:    l.witnessPath != "",
		LocalSequence: l.sequence,
	}
	if l.witnessPath == "" {
		l.witnessStatus.Detail = "external evidence witness is not configured"
		return nil
	}
	info, err := os.Lstat(l.witnessPath)
	if errors.Is(err, os.ErrNotExist) {
		l.degradeWitnessLocked("external witness file is missing (offline medium?)")
		return nil
	}
	if err != nil {
		l.degradeWitnessLocked("external witness is unreachable: " + boundedErrorText(err))
		return nil
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("evidence witness must be a regular non-reparse file")
	}
	if info.Size() <= 0 || info.Size() > maxWitnessFileBytes {
		return errors.New("evidence witness size outside the boundary")
	}
	payload, err := os.ReadFile(l.witnessPath)
	if err != nil {
		l.degradeWitnessLocked("external witness is unreadable: " + boundedErrorText(err))
		return nil
	}
	tip, err := decodeWitnessTip(payload)
	if err != nil {
		return fmt.Errorf("evidence witness rejected: %w", err)
	}
	if !strings.EqualFold(tip.PublicKeySHA256, l.signingPublicSHA256) {
		return errors.New("evidence witness was signed by a different evidence key")
	}
	signature, err := hex.DecodeString(tip.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("evidence witness signature encoding rejected")
	}
	publicKey := l.signingKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, witnessMessage(tip), signature) {
		return errors.New("evidence witness signature invalid")
	}
	l.witnessStatus.Reachable = true
	l.witnessStatus.Sequence = tip.Sequence
	l.witnessStatus.WrittenUTC = tip.WrittenUTC
	if tip.Sequence > l.sequence {
		return fmt.Errorf("evidence witness is ahead of the local chain: truncation or rollback detected (witness=%d local=%d)", tip.Sequence, l.sequence)
	}
	if tip.Sequence == l.sequence {
		if !strings.EqualFold(tip.LastMAC, l.lastMAC) {
			return errors.New("evidence witness does not match the local chain tip")
		}
		l.witnessStatus.Verified = true
		l.witnessStatus.Detail = "external witness matches the local chain tip"
		return nil
	}
	// The local chain is ahead of the witness: records were appended after the
	// last witness publication. Cross-check the witnessed MAC against the
	// retained signed checkpoint for that sequence when it is still available.
	if checkpointMAC, found := l.checkpointMACLocked(tip.Sequence); found {
		if !strings.EqualFold(checkpointMAC, tip.LastMAC) {
			return errors.New("evidence witness conflicts with the signed local checkpoint")
		}
		l.witnessStatus.Verified = true
		l.witnessStatus.Detail = fmt.Sprintf("local chain is ahead of the external witness (local=%d witness=%d)", l.sequence, tip.Sequence)
		return nil
	}
	l.witnessStatus.Detail = fmt.Sprintf("local chain is ahead of the external witness (local=%d witness=%d); witnessed tip is older than the retained signed checkpoints", l.sequence, tip.Sequence)
	return nil
}

func (l *Ledger) degradeWitnessLocked(detail string) {
	l.witnessStatus = WitnessStatus{
		Configured:    true,
		Reachable:     false,
		Degraded:      true,
		LocalSequence: l.sequence,
		Detail:        detail,
	}
}

// checkpointMACLocked returns the signed MAC for a sequence from the loaded
// checkpoint store. The store is bounded, so this is a bounded scan.
func (l *Ledger) checkpointMACLocked(sequence uint64) (string, bool) {
	for index := len(l.checkpoints) - 1; index >= 0; index-- {
		checkpoint := l.checkpoints[index]
		if checkpoint.Sequence == sequence {
			return checkpoint.LastMAC, true
		}
	}
	return "", false
}

// Witness reports the current external witness state. It never performs I/O.
func (l *Ledger) Witness() WitnessStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	status := l.witnessStatus
	status.LocalSequence = l.sequence
	return status
}

// writeWitnessFileAtomically replaces the witness file with a temp-file plus
// rename sequence in the same directory, so a crash never leaves a partially
// written witness record. The payload size is bounded by the caller.
func writeWitnessFileAtomically(path string, payload []byte) (err error) {
	directory := filepath.Dir(path)
	info, statErr := os.Stat(directory)
	if statErr != nil {
		return fmt.Errorf("witness directory unavailable: %w", statErr)
	}
	if !info.IsDir() {
		return errors.New("witness directory path is not a directory")
	}
	temp, err := os.CreateTemp(directory, ".vgt-evidence-witness-*.tmp")
	if err != nil {
		return fmt.Errorf("witness temp file: %w", err)
	}
	tempName := temp.Name()
	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempName)
		}
	}()
	if _, err = temp.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("witness temp write: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("witness temp sync: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("witness temp close: %w", err)
	}
	if err = os.Rename(tempName, path); err != nil {
		return fmt.Errorf("witness replace: %w", err)
	}
	return nil
}

// decodeWitnessTip applies strict, bounded JSON parsing: no unknown fields, no
// trailing data, schema version and field shapes enforced before use.
func decodeWitnessTip(raw []byte) (witnessTip, error) {
	var tip witnessTip
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tip); err != nil {
		return witnessTip{}, errors.New("evidence witness JSON rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return witnessTip{}, errors.New("evidence witness trailing data rejected")
	}
	if tip.SchemaVersion != witnessSchemaVersion || tip.Sequence == 0 ||
		len(tip.LastMAC) != 64 || len(tip.PublicKeySHA256) != 64 ||
		len(tip.Signature) != ed25519.SignatureSize*2 || tip.WrittenUTC.IsZero() {
		return witnessTip{}, errors.New("evidence witness metadata rejected")
	}
	if _, err := hex.DecodeString(tip.LastMAC); err != nil {
		return witnessTip{}, errors.New("evidence witness MAC rejected")
	}
	if _, err := hex.DecodeString(tip.PublicKeySHA256); err != nil {
		return witnessTip{}, errors.New("evidence witness public key fingerprint rejected")
	}
	if _, err := hex.DecodeString(tip.Signature); err != nil {
		return witnessTip{}, errors.New("evidence witness signature encoding rejected")
	}
	return tip, nil
}

// boundedErrorText keeps operator-facing detail bounded and free of secrets.
func boundedErrorText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}
