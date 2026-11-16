// STATUS: PLATIN VGT SUPREME
package evidence

// FIND-WIN-016: explicit operator checkpoint re-anchoring.
//
// A ledger whose signed checkpoint store and authenticated high-water anchor are
// missing or unreadable fails closed in Open() (see highwater.go). That is
// intentional: the HMAC chain alone cannot prove that its tail was not
// truncated, so silently signing a fresh tip on top of a shortened chain is
// exactly the bypass the audit found.
//
// The only way back is this explicit, audited recovery entry point:
//
//  1. the operator archives/retains the evidence files and verifies out of band
//     that the chain is complete (for example against an external witness or an
//     offline backup),
//  2. a maintenance tool calls RecoverCheckpointAnchors once with a non-empty,
//     bounded operator reason,
//  3. the function re-verifies the complete HMAC chain and the configured
//     witness, appends an audit record describing the recovery to the chain,
//     preserves the old anchor stores unchanged (renamed with a timestamp) and
//     then writes fresh signed checkpoints plus the authenticated high-water
//     record for the verified tip,
//  4. the service is started normally again.
//
// It is never invoked by Open(), Append(), Verify() or rotation, so normal
// operation can neither trigger nor disguise a re-anchoring. The evidence key is
// required: recovery cannot be performed without access to the protected key
// store, and the recovery record itself becomes part of the HMAC chain.
//
// Example (maintenance tooling, run while the service is stopped):
//
//	report, err := evidence.RecoverCheckpointAnchors(
//		`C:\ProgramData\VGT\GeDefense\evidence.jsonl`,
//		`C:\ProgramData\VGT\GeDefense\evidence.key`,
//		evidence.Options{},
//		"archive 2026-11-16 verified against the offline backup",
//	)
//
// The returned RecoveryReport names the initialized anchors and the archived
// forensic copies; it contains no record contents and no key material.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// RecoveryReport describes the state after an explicit checkpoint re-anchoring.
// It is safe to log: it contains no keys and no record contents.
type RecoveryReport struct {
	// Sequence is the verified chain tip after the recovery audit record was
	// appended.
	Sequence uint64
	// CheckpointPath is the freshly initialized signed checkpoint store.
	CheckpointPath string
	// HighWaterPath is the freshly initialized authenticated high-water anchor.
	HighWaterPath string
	// ArchivedCheckpointStore is the forensically preserved previous checkpoint
	// store; empty when there was nothing to archive.
	ArchivedCheckpointStore string
	// ArchivedHighWater is the forensically preserved previous high-water anchor;
	// empty when there was nothing to archive.
	ArchivedHighWater string
}

// RecoverCheckpointAnchors re-establishes the signed checkpoint and high-water
// anchors of a ledger whose anchor state is missing or corrupt, after the
// operator has verified the chain out of band. The supplied reason is bounded,
// digest-bound and written into the evidence chain; recovery without a reason is
// rejected. A chain that does not verify (bad HMAC chain, chain gap, tampered
// archive, witness ahead of the local chain) is never re-anchored.
func RecoverCheckpointAnchors(path, keyPath string, options Options, reason string) (RecoveryReport, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > maxHighWaterReasonBytes {
		return RecoveryReport{}, fmt.Errorf("%w: an explicit bounded operator reason is required", ErrEvidenceRecoveryRejected)
	}
	for index := 0; index < len(reason); index++ {
		if reason[index] < 0x20 || reason[index] == 0x7f {
			return RecoveryReport{}, fmt.Errorf("%w: the operator reason contains control characters", ErrEvidenceRecoveryRejected)
		}
	}
	ledger, release, err := prepareLedger(path, keyPath, options)
	if err != nil {
		return RecoveryReport{}, err
	}
	defer release()

	ledger.loadCheckpoints()
	if err := ledger.loadArchives(); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: evidence archives unreadable: %v", ErrEvidenceRecoveryRejected, err)
	}
	ledger.loadJournalState()
	ledger.loadHighWaterLocked()
	// The chain itself must be intact before any anchor is written. A tampered or
	// truncated chain must never be re-signed.
	if err := ledger.verifyLocked(); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: evidence chain verification failed: %v", ErrEvidenceRecoveryRejected, err)
	}
	if err := ledger.verifyWitnessLocked(); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: external witness conflicts with the local chain: %v", ErrEvidenceRecoveryRejected, err)
	}

	// Preserve the previous anchor stores unchanged for forensic review before
	// writing new ones.
	report := RecoveryReport{CheckpointPath: ledger.checkpointPath, HighWaterPath: ledger.highWaterPath()}
	priorSequence := ledger.sequence
	priorCheckpoints := len(ledger.checkpoints)
	if report.ArchivedCheckpointStore, err = archiveAnchorFile(ledger.checkpointPath, recoveryArchiveSuffixName); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: checkpoint store archive failed: %v", ErrEvidenceRecoveryRejected, err)
	}
	if report.ArchivedHighWater, err = archiveAnchorFile(ledger.highWaterPath(), recoveryArchiveSuffixName); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: high-water archive failed: %v", ErrEvidenceRecoveryRejected, err)
	}
	ledger.checkpoints = nil
	ledger.checkpointFileBytes = 0
	ledger.checkpointProblem = ""
	ledger.highWater = highWaterState{}

	// Record the conscious re-anchoring decision inside the evidence chain. The
	// record also advances the treated-as-untrusted tip by one sequence.
	reasonDigest := sha256.Sum256([]byte(reason))
	result := fmt.Sprintf("prior-sequence=%d prior-checkpoints=%d reason-sha256=%s",
		priorSequence, priorCheckpoints, hex.EncodeToString(reasonDigest[:]))
	if err := ledger.appendLocked("evidence.recovery", "checkpoint-reanchor", result); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: recovery audit record could not be appended: %v", ErrEvidenceRecoveryRejected, err)
	}
	if err := ledger.ensureTipCheckpointLocked(); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: checkpoint initialization failed: %v", ErrEvidenceRecoveryRejected, err)
	}
	if err := ledger.persistHighWaterLocked(); err != nil {
		return RecoveryReport{}, fmt.Errorf("%w: high-water initialization failed: %v", ErrEvidenceRecoveryRejected, err)
	}
	ledger.refreshWitnessLocked()
	report.Sequence = ledger.sequence
	return report, nil
}
