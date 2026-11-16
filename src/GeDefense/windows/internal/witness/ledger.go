// STATUS: PLATIN VGT SUPREME

package witness

// The narrow ledger contract of the witness engine.
//
// The engine signs the authenticated head of the evidence ledger, but it does not
// know the evidence package: the application provides an adapter that implements
// LedgerSource. Every head is validated again here before it is signed, so a bug
// or a stale adapter cannot make the package sign an inconsistent window.

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"
)

var (
	// ErrLedgerRollback marks a ledger epoch/sequence moving backwards.
	ErrLedgerRollback = errors.New("witness ledger rollback detected")
	// ErrLedgerFork marks the same (epoch, sequence) carrying a different tip.
	ErrLedgerFork = errors.New("witness ledger fork detected")
	// ErrLedgerHeadInvalid marks a ledger head that violates the contract.
	ErrLedgerHeadInvalid = errors.New("witness ledger head is invalid")
)

// LedgerHead is the authenticated view of the evidence ledger the engine signs.
// The adapter supplied by the application must derive it from the verified chain;
// the engine validates it again before signing.
type LedgerHead struct {
	// LedgerEpoch is the epoch of the current chain generation.
	LedgerEpoch uint64
	// Sequence is the monotonic ledger sequence of the tip (greater than zero).
	Sequence uint64
	// TipSHA256 is the lowercase hex SHA-256 of the authenticated tip.
	TipSHA256 string
	// SegmentFirstSequence is the first sequence covered by this checkpoint
	// segment; the segment always ends at the head sequence.
	SegmentFirstSequence uint64
	// EventCount is the number of ledger events in [first..last].
	EventCount uint64
	// WindowStartUTC and WindowEndUTC bound the evidence window in UTC.
	WindowStartUTC time.Time
	WindowEndUTC   time.Time
}

// LedgerSource is the only view the engine needs of the evidence ledger. Keeping
// it this narrow is what avoids an import of internal/evidence and lets the lead
// wire the ledger without cycles.
type LedgerSource interface {
	WitnessLedgerHead(ctx context.Context) (LedgerHead, error)
}

// validateLedgerHead enforces the ledger contract before the engine signs it.
func validateLedgerHead(head LedgerHead) error {
	if head.Sequence == 0 {
		return errors.New("sequence must be greater than zero")
	}
	if head.Sequence > maxCounter || head.LedgerEpoch > maxCounter ||
		head.SegmentFirstSequence > maxCounter || head.EventCount > maxCounter {
		return errors.New("a counter exceeds the JSON-safe bound")
	}
	if !validDigestHex(head.TipSHA256) {
		return errors.New("tip digest is not a SHA-256 digest")
	}
	if head.SegmentFirstSequence == 0 || head.SegmentFirstSequence > head.Sequence {
		return errors.New("segment window is not ordered")
	}
	if head.EventCount != head.Sequence-head.SegmentFirstSequence+1 {
		return errors.New("event count does not match the segment window")
	}
	if head.WindowStartUTC.IsZero() || head.WindowEndUTC.IsZero() {
		return errors.New("window bounds are required")
	}
	start := head.WindowStartUTC.UTC()
	end := head.WindowEndUTC.UTC()
	if end.Before(start) {
		return errors.New("window end precedes window start")
	}
	if year := start.Year(); year < checkpointMinPlausibleYear || year >= checkpointMaxPlausibleYear {
		return errors.New("window start is outside the plausible year range")
	}
	if year := end.Year(); year < checkpointMinPlausibleYear || year >= checkpointMaxPlausibleYear {
		return errors.New("window end is outside the plausible year range")
	}
	return nil
}

// digestsEqual compares two lowercase hex SHA-256 digests in constant time.
func digestsEqual(left, right string) bool {
	if !validDigestHex(left) || !validDigestHex(right) {
		return false
	}
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	if leftErr != nil || rightErr != nil || len(leftBytes) != len(rightBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}
