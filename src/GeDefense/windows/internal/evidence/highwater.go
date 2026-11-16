// STATUS: PLATIN VGT SUPREME
package evidence

// FIND-WIN-016: authenticated evidence high-water anchor.
//
// The HMAC record chain and the Ed25519-signed checkpoint store are the primary
// tamper-evidence anchors of the ledger. A delete or corruption of the whole
// checkpoint store used to pin the ledger to "no anchors at all": Open() then
// verified the (possibly truncated) chain, signed a fresh tip checkpoint and
// continued, so a tail truncation stayed undetected. Two hard rules close that
// root cause:
//
//  1. A non-empty chain (live file or retained archives) without any intact
//     signed checkpoint is a failed verification. Open() returns the typed
//     ErrEvidenceCheckpointAnchorMissing error; it never silently re-signs.
//  2. The verified chain tip is additionally mirrored into this small,
//     service-key-authenticated high-water record. A chain tip below the
//     authenticated high-water mark, or a different chain MAC at the same
//     sequence, is a typed failure (rollback / tamper). The file carries its own
//     SYSTEM/Administrators-only DACL through internal/evidence/secretfs when
//     the service identity can manage one; the HMAC does not depend on the DACL.
//
// The high-water record is updated whenever a signed checkpoint is written, on
// every verified Open() and after the explicit operator recovery path
// (RecoverCheckpointAnchors in recovery.go). It is never discarded
// automatically and never lowered.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

const (
	highWaterSchemaVersion = 1
	highWaterFileSuffix    = ".highwater.json"
	// highWaterSigningDomain domain-separates the high-water HMAC from the record
	// chain HMAC, the checkpoint signatures and every other consumer of the
	// evidence key (for example the integrity snapshot MACs).
	highWaterSigningDomain    = "VGT-GEDEFENSE-EVIDENCE-HIGHWATER-V1"
	maxHighWaterFileBytes     = 4 << 10
	maxHighWaterReasonBytes   = 256
	recoveryArchiveStamp      = "20060102T150405.000000000Z"
	recoveryArchiveSuffixName = ".recovery-"
)

// Typed anchor failures. Callers and operators can test them with errors.Is; no
// failure path panics and no failure path auto-repairs the anchor state.
var (
	// ErrEvidenceCheckpointAnchorMissing is returned when a non-empty evidence
	// chain has no intact Ed25519-signed checkpoint. The chain cannot be
	// distinguished from a truncated one, so the ledger fails closed.
	ErrEvidenceCheckpointAnchorMissing = errors.New("evidence checkpoint anchor missing")
	// ErrEvidenceHighWaterInvalid is returned when the authenticated high-water
	// record exists but cannot be trusted (corrupt, unauthenticated or forged).
	ErrEvidenceHighWaterInvalid = errors.New("evidence high-water anchor rejected")
	// ErrEvidenceHighWaterRollback is returned when the verified chain tip is
	// older than the authenticated high-water mark.
	ErrEvidenceHighWaterRollback = errors.New("evidence high-water rollback detected")
	// ErrEvidenceHighWaterMismatch is returned when the chain tip has the
	// high-water sequence but a different chain MAC.
	ErrEvidenceHighWaterMismatch = errors.New("evidence high-water tip mismatch")
	// ErrEvidenceRecoveryRejected is returned when the explicit operator
	// checkpoint re-anchoring cannot prove that the chain itself is intact.
	ErrEvidenceRecoveryRejected = errors.New("evidence checkpoint re-anchoring rejected")
)

// highWaterRecord is the on-disk authenticated anchor. It contains no secrets.
type highWaterRecord struct {
	SchemaVersion int       `json:"schemaVersion"`
	Sequence      uint64    `json:"sequence"`
	LastMAC       string    `json:"lastMac"`
	UpdatedUTC    time.Time `json:"updatedUtc"`
	MAC           string    `json:"mac"`
}

// highWaterMessage is the canonical MAC input. Byte-for-byte identical on write
// and verification so the MAC never depends on map ordering or JSON time zones.
type highWaterMessage struct {
	SchemaVersion int    `json:"schemaVersion"`
	Sequence      uint64 `json:"sequence"`
	LastMAC       string `json:"lastMac"`
	UpdatedUTC    string `json:"updatedUtc"`
}

// highWaterState is the in-memory view of the anchor file. rejectReason is set
// when the file exists but is not trustworthy; the value is surfaced through the
// typed verification error, never used as a trusted timestamp.
type highWaterState struct {
	present      bool
	sequence     uint64
	lastMAC      string
	rejectReason string
}

// highWaterPath returns the anchor path. It is derived from the evidence path so
// two ledgers in one directory can never share an anchor.
func (l *Ledger) highWaterPath() string {
	return filepath.Clean(l.path) + highWaterFileSuffix
}

// evidenceHighWaterMAC authenticates the canonical high-water message with the
// protected ledger key under a dedicated domain.
func (l *Ledger) evidenceHighWaterMAC(message highWaterMessage) (string, error) {
	if len(l.key) != ledgerHMACKeyBytes {
		return "", errors.New("evidence high-water key unavailable")
	}
	raw, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte(highWaterSigningDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// loadHighWaterLocked reads and authenticates the high-water anchor. A missing
// file is a documented legacy/bootstrap state (the chain still has to verify
// against the signed checkpoints); a present but invalid file is recorded as a
// rejected anchor and never yields a trusted sequence or timestamp.
func (l *Ledger) loadHighWaterLocked() {
	l.highWater = highWaterState{}
	path := l.highWaterPath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		l.highWater.rejectReason = "high-water anchor is unreadable: " + boundedErrorText(err)
		return
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		l.highWater.rejectReason = "high-water anchor must be a regular non-reparse file"
		return
	}
	if info.Size() <= 0 || info.Size() > maxHighWaterFileBytes {
		l.highWater.rejectReason = "high-water anchor size outside the boundary"
		return
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		l.highWater.rejectReason = "high-water anchor is unreadable: " + boundedErrorText(err)
		return
	}
	var record highWaterRecord
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		l.highWater.rejectReason = "high-water anchor JSON rejected"
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		l.highWater.rejectReason = "high-water anchor trailing data rejected"
		return
	}
	if record.SchemaVersion != highWaterSchemaVersion || record.Sequence == 0 ||
		len(record.LastMAC) != 64 || len(record.MAC) != 64 || record.UpdatedUTC.IsZero() {
		l.highWater.rejectReason = "high-water anchor metadata rejected"
		return
	}
	if _, err := hex.DecodeString(record.LastMAC); err != nil {
		l.highWater.rejectReason = "high-water anchor chain MAC rejected"
		return
	}
	expected, err := l.evidenceHighWaterMAC(highWaterMessage{
		SchemaVersion: record.SchemaVersion,
		Sequence:      record.Sequence,
		LastMAC:       record.LastMAC,
		UpdatedUTC:    record.UpdatedUTC.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		l.highWater.rejectReason = "high-water anchor authentication unavailable"
		return
	}
	if !constantTimeHexEqual(expected, record.MAC) {
		l.highWater.rejectReason = "high-water anchor authentication failed"
		return
	}
	l.highWater = highWaterState{present: true, sequence: record.Sequence, lastMAC: record.LastMAC}
}

// persistHighWaterLocked mirrors the verified chain tip into the authenticated
// anchor. The anchor is never lowered: a lower or differently-MACed tip at the
// same sequence is refused, so an in-memory rollback cannot rewrite the anchor.
func (l *Ledger) persistHighWaterLocked() error {
	if l.sequence == 0 {
		return nil
	}
	// An untrusted on-disk anchor (rejectReason set) is deliberately overwritten:
	// this function is only reached after the chain verified and the anchor rules
	// passed (Open), or after the explicit operator re-anchoring cleared the state.
	if l.highWater.rejectReason == "" && l.highWater.present {
		if l.sequence < l.highWater.sequence {
			return fmt.Errorf("%w: refusing to lower the authenticated high-water mark from %d to %d",
				ErrEvidenceHighWaterRollback, l.highWater.sequence, l.sequence)
		}
		if l.sequence == l.highWater.sequence {
			if strings.EqualFold(l.lastMAC, l.highWater.lastMAC) {
				return nil
			}
			return fmt.Errorf("%w: chain MAC at sequence %d differs from the authenticated high-water mark",
				ErrEvidenceHighWaterMismatch, l.sequence)
		}
	}
	record := highWaterRecord{
		SchemaVersion: highWaterSchemaVersion,
		Sequence:      l.sequence,
		LastMAC:       l.lastMAC,
		UpdatedUTC:    time.Now().UTC(),
	}
	mac, err := l.evidenceHighWaterMAC(highWaterMessage{
		SchemaVersion: record.SchemaVersion,
		Sequence:      record.Sequence,
		LastMAC:       record.LastMAC,
		UpdatedUTC:    record.UpdatedUTC.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("evidence high-water authentication: %w", err)
	}
	record.MAC = mac
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(raw)+1 > maxHighWaterFileBytes {
		return errors.New("evidence high-water record exceeds the file boundary")
	}
	if err := writeProtectedAnchorFile(l.highWaterPath(), append(raw, '\n')); err != nil {
		return fmt.Errorf("evidence high-water persistence: %w", err)
	}
	l.highWater = highWaterState{present: true, sequence: record.Sequence, lastMAC: record.LastMAC}
	return nil
}

// verifyHighWaterAgainstChainLocked compares the authenticated anchor with the
// already verified chain tip. A legacy ledger without an anchor bootstraps on the
// next persistHighWaterLocked; every present but untrusted anchor fails closed
// once the chain is non-empty.
func (l *Ledger) verifyHighWaterAgainstChainLocked() error {
	if l.highWater.rejectReason != "" {
		return fmt.Errorf("%w: %s (evidence anchors require explicit operator recovery)",
			ErrEvidenceHighWaterInvalid, l.highWater.rejectReason)
	}
	if !l.highWater.present {
		return nil
	}
	if l.sequence < l.highWater.sequence {
		return fmt.Errorf("%w: authenticated high-water sequence %d exceeds the verified chain tip %d",
			ErrEvidenceHighWaterRollback, l.highWater.sequence, l.sequence)
	}
	if l.sequence == l.highWater.sequence && !strings.EqualFold(l.lastMAC, l.highWater.lastMAC) {
		return fmt.Errorf("%w: chain MAC at sequence %d does not match the authenticated high-water mark",
			ErrEvidenceHighWaterMismatch, l.sequence)
	}
	return nil
}

// verifyAnchorStateLocked enforces the two FIND-WIN-016 rules on top of a
// successfully verified HMAC chain and witness.
func (l *Ledger) verifyAnchorStateLocked() error {
	if l.sequence == 0 {
		// An empty chain behind an authenticated high-water mark is a full
		// evidence wipe, not a fresh ledger.
		if l.highWater.present && l.highWater.sequence > 0 {
			return fmt.Errorf("%w: the evidence chain is empty but the authenticated high-water mark records sequence %d",
				ErrEvidenceHighWaterRollback, l.highWater.sequence)
		}
		return nil
	}
	if len(l.checkpoints) == 0 {
		detail := "a non-empty evidence chain has no intact signed checkpoint"
		if l.checkpointProblem != "" {
			detail = l.checkpointProblem
		}
		return fmt.Errorf("%w: %s (run the explicit operator checkpoint recovery after archival and verification)",
			ErrEvidenceCheckpointAnchorMissing, detail)
	}
	return l.verifyHighWaterAgainstChainLocked()
}

// verifyRuntimeTipAgainstAnchorsLocked is the runtime counterpart of the Open
// anchor check. It rejects a cached-tip reconciliation that would move the chain
// backwards (live file deleted or tail-truncated while the service runs) or that
// would fall behind the authenticated high-water mark.
func (l *Ledger) verifyRuntimeTipAgainstAnchorsLocked(previousSequence uint64) error {
	if previousSequence > 0 && l.sequence < previousSequence {
		return fmt.Errorf("%w: live chain tip moved backwards from %d to %d",
			ErrEvidenceHighWaterRollback, previousSequence, l.sequence)
	}
	if l.highWater.sequence > 0 && l.sequence < l.highWater.sequence {
		return fmt.Errorf("%w: live chain tip %d is behind the authenticated high-water mark %d",
			ErrEvidenceHighWaterRollback, l.sequence, l.highWater.sequence)
	}
	return nil
}

// writeProtectedAnchorFile atomically replaces an anchor file with 0600 mode and
// applies the secretfs file DACL before the rename, so the final path never
// exists unprotected. On a non-privileged developer process the DACL is deferred
// to the LocalSystem service (documented secretfs behaviour), exactly like the
// evidence keys.
func writeProtectedAnchorFile(path string, payload []byte) (err error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vgt-evidence-anchor-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if _, err = secretfs.HardenFile(temporaryPath); err != nil {
		return fmt.Errorf("high-water access control: %w", err)
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return nil
}

// constantTimeHexEqual compares two hex-encoded SHA-256 sized values in constant
// time. Malformed or differently sized inputs are a mismatch, never a panic.
func constantTimeHexEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	if leftErr != nil || rightErr != nil || len(leftBytes) != sha256.Size || len(rightBytes) != sha256.Size {
		return false
	}
	return hmac.Equal(leftBytes, rightBytes)
}

// archiveAnchorFile preserves an existing anchor store unchanged for forensics
// and returns the archive path. The explicit operator recovery path calls it; no
// automatic code path ever archives a still-valid anchor.
func archiveAnchorFile(path, suffix string) (string, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format(recoveryArchiveStamp)
	target := fmt.Sprintf("%s%s%s", path, suffix, stamp)
	if _, err := os.Lstat(target); err == nil {
		return "", errors.New("evidence anchor recovery archive target already exists")
	}
	if err := os.Rename(path, target); err != nil {
		return "", err
	}
	return target, nil
}
