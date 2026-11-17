// STATUS: DIAMANT VGT SUPREME
package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/startup"
)

const legacyUpgradeReason = "authorized installer upgrade migration from legacy pre-6.0.0 evidence ledger"

// PrepareUpgrade runs inside the signed installer transaction before the Windows
// service starts. It preserves strict fail-closed runtime semantics in evidence.Open
// while explicitly migrating legacy pre-6.0.0 ledgers (where checkpoints were only
// emitted every 256 records and no high-water anchor existed yet) through the
// audited RecoverCheckpointAnchors path, then verifies a full App startup dry-check.
func PrepareUpgrade(root, version string) error {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return errors.New("ProgramData is unavailable")
	}
	dataRoot := filepath.Join(programData, "VGT", "GeDefense")
	evidencePath := filepath.Join(dataRoot, "evidence.jsonl")
	evidenceKeyPath := filepath.Join(dataRoot, "evidence.key")
	startupPath := filepath.Join(dataRoot, "startup-state.json")

	// Existing installations with a persisted startup-state file must not
	// re-trigger the first-run setup wizard after updates.
	if !isMissingFile(startupPath) {
		if gate, gateErr := startup.Open(startupPath); gateErr == nil {
			if preserveErr := gate.PreserveSetupOnUpgrade("business", version); preserveErr != nil {
				return fmt.Errorf("startup setup upgrade migration: %w", preserveErr)
			}
		}
	}

	if err := migrateLegacyEvidenceIfEligible(evidencePath, evidenceKeyPath); err != nil {
		return fmt.Errorf("evidence upgrade migration: %w", err)
	}

	application, err := New(root, version)
	if err != nil {
		return fmt.Errorf("service initialization precheck: %w", err)
	}
	if closeErr := application.Close(); closeErr != nil {
		return fmt.Errorf("service precheck cleanup: %w", closeErr)
	}
	return nil
}

// PreserveSetupOnUpgrade marks first-run setup as completed when an authorized
// installer confirms an existing prior GeDefense installation was upgraded.
func PreserveSetupOnUpgrade(version string) error {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return errors.New("ProgramData is unavailable")
	}
	startupPath := filepath.Join(programData, "VGT", "GeDefense", "startup-state.json")
	gate, err := startup.Open(startupPath)
	if err != nil {
		return fmt.Errorf("open startup state: %w", err)
	}
	return gate.PreserveSetupOnUpgrade("business", version)
}

// MigrateLegacyEvidenceOnStartup runs at service startup (as LocalSystem) before
// app.New so that a pre-6.0.0 evidence ledger (<256 records without checkpoint or
// high-water files) is migrated even if an earlier upgrade step skipped it.
func MigrateLegacyEvidenceOnStartup() error {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return nil
	}
	dataRoot := filepath.Join(programData, "VGT", "GeDefense")
	return migrateLegacyEvidenceIfEligible(
		filepath.Join(dataRoot, "evidence.jsonl"),
		filepath.Join(dataRoot, "evidence.key"),
	)
}

func migrateLegacyEvidenceIfEligible(evidencePath, keyPath string) error {
	if _, err := os.Lstat(evidencePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	// Fast path: if either post-6.0.0 anchor file already exists, legacy
	// migration is never eligible; let app.New perform the single authoritative
	// evidence.Open verification instead of scanning the full ledger twice.
	checkpointPath := filepath.Clean(evidencePath) + ".checkpoints.jsonl"
	highWaterPath := filepath.Clean(evidencePath) + ".highwater.json"
	if !isMissingFile(checkpointPath) || !isMissingFile(highWaterPath) {
		return nil
	}

	ledger, err := evidence.Open(evidencePath, keyPath)
	if err == nil {
		return ledger.Close()
	}
	if !errors.Is(err, evidence.ErrEvidenceCheckpointAnchorMissing) {
		return err
	}

	// Only a true pre-6.0.0 legacy ledger (never had a checkpoint store AND
	// never had a high-water anchor file) is auto-migrated during the signed
	// installer upgrade. If either anchor file exists (e.g. corrupt/deleted
	// partially after 6.0.0 already ran), fail closed and require explicit
	// operator recovery.
	_, recoverErr := evidence.RecoverCheckpointAnchors(evidencePath, keyPath, evidence.Options{}, legacyUpgradeReason)
	return recoverErr
}

func isMissingFile(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}
