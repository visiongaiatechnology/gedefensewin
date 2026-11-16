// STATUS: PLATIN VGT SUPREME
package titan

// Mark-of-the-Web preservation for quarantine restore (FIND-WIN-021).
//
// Removing a quarantined file also removes its :Zone.Identifier alternate data
// stream. A restored executable without that stream is no longer treated as
// "downloaded from the Internet" by Windows. The captured stream content is
// stored next to the authenticated metadata as an AES-GCM sealed sidecar keyed by
// the SAME vault key and bound to the quarantine ID, so it cannot be forged or
// transplanted between objects. An empty payload proves the verified absence of
// a zone identifier; a missing sidecar therefore always identifies a legacy
// record whose MOTW state was never captured.

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	vaultZoneRecordSuffix   = ".zone"
	maxZoneIdentifierBytes  = 4096
	maxVaultZoneRecordBytes = maxZoneIdentifierBytes + 128
	vaultZoneRecordLabel    = "VGT-GEDEFENSE-TITAN-QUARANTINE-ZONE-IDENTIFIER-V1"
	zoneIdentifierStream    = ":Zone.Identifier"
)

func (v *Vault) zoneRecordPath(id string) string {
	return filepath.Join(v.root, id+vaultZoneRecordSuffix)
}

func zoneRecordAssociatedData(id string) []byte {
	return []byte(vaultZoneRecordLabel + ":" + id)
}

// writeZoneRecord stores the captured zone identifier encrypted and
// authenticated with the vault key.
func (v *Vault) writeZoneRecord(id string, raw []byte) error {
	if !validQuarantineID(id) {
		return errors.New("titan zone record id rejected")
	}
	if len(raw) > maxZoneIdentifierBytes {
		return errors.New("titan zone identifier boundary rejected")
	}
	nonce := make([]byte, v.aed.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := v.aed.Seal(nonce, nonce, raw, zoneRecordAssociatedData(id))
	return atomicWriteFile(v.zoneRecordPath(id), sealed)
}

// readZoneRecord returns the captured zone identifier. The boolean reports
// whether the authenticated record exists at all; a missing record means the
// object predates MOTW capture.
func (v *Vault) readZoneRecord(id string) (raw []byte, present bool, err error) {
	if !validQuarantineID(id) {
		return nil, false, errors.New("titan quarantine id rejected")
	}
	file, _, openErr := openVaultSource(v.zoneRecordPath(id))
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, openErr
	}
	encrypted, readErr := io.ReadAll(io.LimitReader(file, maxVaultZoneRecordBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, false, readErr
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	if len(encrypted) > maxVaultZoneRecordBytes {
		return nil, false, errors.New("titan zone record size boundary rejected")
	}
	nonceSize := v.aed.NonceSize()
	if len(encrypted) < nonceSize+16 {
		return nil, false, errors.New("titan zone record is truncated")
	}
	payload, openErr := v.aed.Open(nil, encrypted[:nonceSize], encrypted[nonceSize:], zoneRecordAssociatedData(id))
	if openErr != nil {
		return nil, false, errors.New("titan zone record authentication failed")
	}
	if len(payload) > maxZoneIdentifierBytes {
		return nil, false, errors.New("titan zone record payload boundary rejected")
	}
	return payload, true, nil
}

func (v *Vault) removeZoneRecord(id string) error {
	if err := os.Remove(v.zoneRecordPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
