// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Staging adapter. Input is staged under the injected, validated root with
// O_EXCL and SHA-256 in the file name, protected by a protected DACL that grants
// the current user full control and the exact AppContainer SID read access only.
// A bounded crash journal records the cell before the kernel profile exists, so
// an engine restart can reclaim orphaned profiles and directories.

const (
	// maxOrphanRecords bounds the crash-journal scan.
	maxOrphanRecords = 128
	// maxJournalBytes bounds one journal record.
	maxJournalBytes = 4096
	// sddlRevision1 is the only supported SDDL revision.
	sddlRevision1 uint32 = 1
	// daclSecurityInformation is DACL_SECURITY_INFORMATION.
	daclSecurityInformation uint32 = 0x00000004
)

var (
	procConvertStringSecurityDescriptorToSD = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetFileSecurityW                    = advapi32.NewProc("SetFileSecurityW")
)

// stagedInput describes one staged input file.
type stagedInput struct {
	Dir          string
	Path         string
	SHA256       string
	Bytes        int64
	ContainerSID string
	ManifestPath string
}

// orphanRecord is one crash-journal entry.
type orphanRecord struct {
	CellID        string    `json:"cellId"`
	ContainerName string    `json:"containerName"`
	CreatedUTC    time.Time `json:"createdUtc"`
}

// windowsPlatform is the production platform adapter. It binds the staging root
// once and exposes the injectable platform interface to cells and the engine.
type windowsPlatform struct {
	root   string
	mu     sync.Mutex
	rootOK bool
}

// newPlatform returns the production platform adapter for a validated root.
func newPlatform(root string) platform {
	return &windowsPlatform{root: root}
}

// stagingRoot returns the configured root after validating it.
func (p *windowsPlatform) stagingRoot() (string, error) {
	if err := ValidateStagingRoot(p.root); err != nil {
		return "", &Error{Op: "staging.root", Kind: ErrStagingUnsafe, Detail: err.Error()}
	}
	return p.root, nil
}

// PrepareRoot ensures the staging root and journal directory exist with a
// restrictive DACL. Directories created by this call are locked to the current
// user before any cell file is written.
func (p *windowsPlatform) PrepareRoot() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	root, err := p.stagingRoot()
	if err != nil {
		return err
	}
	createdRoot := false
	if _, statErr := os.Stat(root); statErr != nil {
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("parsercells: staging root stat: %w", statErr)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("parsercells: staging root create: %w", err)
		}
		createdRoot = true
	}
	if createdRoot {
		if err := applyProtectedDACL(root, ""); err != nil {
			return fmt.Errorf("parsercells: staging root DACL: %w", err)
		}
	}
	for _, directory := range []string{filepath.Join(root, "cells"), filepath.Join(root, "journal")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("parsercells: staging directory create: %w", err)
		}
		if err := applyProtectedDACL(directory, ""); err != nil {
			return fmt.Errorf("parsercells: staging directory DACL: %w", err)
		}
	}
	p.rootOK = true
	return nil
}

// rootReady returns the root, preparing it on first use.
func (p *windowsPlatform) rootReady() (string, error) {
	p.mu.Lock()
	ready := p.rootOK
	p.mu.Unlock()
	if !ready {
		if err := p.PrepareRoot(); err != nil {
			return "", err
		}
	}
	return p.stagingRoot()
}

// cellDirectory returns the per-cell staging directory path (not created).
func cellDirectory(root, cellID string) (string, error) {
	if !validCellID(cellID) {
		return "", &Error{Op: "staging.cell", Kind: ErrStagingUnsafe, Detail: "cell id is not a canonical UUID v4"}
	}
	return filepath.Join(root, "cells", cellID), nil
}

// journalDirectory returns the crash-journal directory path.
func journalDirectory(root string) string {
	return filepath.Join(root, "journal")
}

// withinRoot reports whether path is strictly below root on the cleaned path
// level. It is used before any recursive delete.
func withinRoot(root, path string) bool {
	cleanRoot := filepath.Clean(root)
	cleanPath := filepath.Clean(path)
	if cleanPath == cleanRoot || !strings.HasPrefix(cleanPath, cleanRoot) {
		return false
	}
	return strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator))
}

// StageInput writes the input with O_EXCL under a fresh per-cell directory,
// applies the protected DACL and returns the staged descriptor. The directory
// must not already exist: a cell never reuses staging state.
func (p *windowsPlatform) StageInput(cellID, profileName string, data []byte, containerSID string) (stagedInput, error) {
	root, err := p.rootReady()
	if err != nil {
		return stagedInput{}, err
	}
	if int64(len(data)) > HardMaxInputBytes {
		return stagedInput{}, &Error{Op: "staging.input", Kind: ErrInputTooLarge,
			Detail: fmt.Sprintf("input %d bytes exceeds hard ceiling %d", len(data), HardMaxInputBytes)}
	}
	if len(data) == 0 {
		return stagedInput{}, &Error{Op: "staging.input", Kind: ErrInvalidProfile, Detail: "empty input"}
	}
	cellDir, err := cellDirectory(root, cellID)
	if err != nil {
		return stagedInput{}, err
	}
	if err := os.Mkdir(cellDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return stagedInput{}, &Error{Op: "staging.input", Kind: ErrStagingUnsafe,
				Detail: "cell staging directory already exists"}
		}
		return stagedInput{}, fmt.Errorf("parsercells: cell staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(cellDir)
		}
	}()
	if err := applyProtectedDACL(cellDir, ""); err != nil {
		return stagedInput{}, fmt.Errorf("parsercells: cell directory DACL: %w", err)
	}
	digest := sha256.Sum256(data)
	digestHex := hex.EncodeToString(digest[:])
	inputPath := filepath.Join(cellDir, "input-"+digestHex+".bin")
	if err := writeExclusiveFile(inputPath, data); err != nil {
		return stagedInput{}, err
	}
	if err := applyProtectedDACL(inputPath, containerSID); err != nil {
		return stagedInput{}, fmt.Errorf("parsercells: input DACL: %w", err)
	}
	manifest := struct {
		CellID       string `json:"cellId"`
		ProfileName  string `json:"profileName"`
		SHA256       string `json:"sha256"`
		Bytes        int64  `json:"bytes"`
		ContainerSID string `json:"containerSid"`
		CreatedUTC   string `json:"createdUtc"`
	}{
		CellID:       cellID,
		ProfileName:  profileName,
		SHA256:       digestHex,
		Bytes:        int64(len(data)),
		ContainerSID: containerSID,
		CreatedUTC:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return stagedInput{}, fmt.Errorf("parsercells: staging manifest encode: %w", err)
	}
	manifestPath := filepath.Join(cellDir, "manifest.json")
	if err := writeExclusiveFile(manifestPath, encoded); err != nil {
		return stagedInput{}, err
	}
	if err := applyProtectedDACL(manifestPath, containerSID); err != nil {
		return stagedInput{}, fmt.Errorf("parsercells: manifest DACL: %w", err)
	}
	committed = true
	return stagedInput{
		Dir:          cellDir,
		Path:         inputPath,
		SHA256:       digestHex,
		Bytes:        int64(len(data)),
		ContainerSID: containerSID,
		ManifestPath: manifestPath,
	}, nil
}

// VerifyStagedInput re-reads the staged file, bounded by its recorded size, and
// compares the SHA-256. This detects tampering between staging and execution.
func (p *windowsPlatform) VerifyStagedInput(staged stagedInput) error {
	if !validCellID(cellIDFromPath(staged.Dir)) {
		return &Error{Op: "staging.verify", Kind: ErrStagingUnsafe, Detail: "staged directory does not embed a cell id"}
	}
	file, err := os.Open(staged.Path)
	if err != nil {
		return fmt.Errorf("parsercells: staged input open: %w", err)
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, staged.Bytes+1))
	if err != nil {
		return fmt.Errorf("parsercells: staged input read: %w", err)
	}
	if written != staged.Bytes {
		return &Error{Op: "staging.verify", Kind: ErrStagingUnsafe,
			Detail: fmt.Sprintf("staged size %d != recorded %d", written, staged.Bytes)}
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != staged.SHA256 {
		return &Error{Op: "staging.verify", Kind: ErrStagingUnsafe, Detail: "staged input SHA-256 mismatch"}
	}
	return nil
}

// PurgeStaging removes the per-cell staging directory. It refuses to delete
// anything outside the configured root.
func (p *windowsPlatform) PurgeStaging(staged stagedInput) error {
	root, err := p.stagingRoot()
	if err != nil {
		return err
	}
	if !withinRoot(root, staged.Dir) {
		return &Error{Op: "staging.purge", Kind: ErrStagingUnsafe, Detail: "staged directory outside the staging root"}
	}
	if err := os.RemoveAll(staged.Dir); err != nil {
		return fmt.Errorf("parsercells: purge staging: %w", err)
	}
	return nil
}

// WriteOrphan records the cell in the crash journal before the AppContainer
// profile is created. It is written with O_EXCL: an existing journal entry means
// a previous engine did not clean up and must be reclaimed first.
func (p *windowsPlatform) WriteOrphan(record orphanRecord) error {
	root, err := p.rootReady()
	if err != nil {
		return err
	}
	if err := validateContainerName(record.ContainerName); err != nil {
		return err
	}
	if record.CreatedUTC.IsZero() {
		record.CreatedUTC = time.Now().UTC()
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("parsercells: journal encode: %w", err)
	}
	path := filepath.Join(journalDirectory(root), record.CellID+".json")
	if err := writeExclusiveFile(path, encoded); err != nil {
		return err
	}
	if err := applyProtectedDACL(path, ""); err != nil {
		return fmt.Errorf("parsercells: journal DACL: %w", err)
	}
	return nil
}

// ClearOrphan removes the crash-journal entry after a successful burn.
func (p *windowsPlatform) ClearOrphan(cellID string) error {
	root, err := p.rootReady()
	if err != nil {
		return err
	}
	if !validCellID(cellID) {
		return &Error{Op: "journal.clear", Kind: ErrStagingUnsafe, Detail: "cell id is not a canonical UUID v4"}
	}
	err = os.Remove(filepath.Join(journalDirectory(root), cellID+".json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("parsercells: clear journal: %w", err)
	}
	return nil
}

// ScanOrphans returns the bounded list of crash-journal entries.
func (p *windowsPlatform) ScanOrphans(limit int) ([]orphanRecord, error) {
	root, err := p.rootReady()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxOrphanRecords {
		return nil, fmt.Errorf("parsercells: orphan limit %d outside (0,%d]", limit, maxOrphanRecords)
	}
	entries, err := os.ReadDir(journalDirectory(root))
	if err != nil {
		return nil, fmt.Errorf("parsercells: journal read: %w", err)
	}
	records := make([]orphanRecord, 0, limit)
	for _, entry := range entries {
		if len(records) >= limit {
			break
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(journalDirectory(root), entry.Name())
		info, statErr := entry.Info()
		if statErr != nil || info.Size() > maxJournalBytes {
			continue
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil || len(raw) > maxJournalBytes {
			continue
		}
		var record orphanRecord
		if jsonErr := json.Unmarshal(raw, &record); jsonErr != nil {
			continue
		}
		if !validCellID(record.CellID) || strings.TrimSuffix(entry.Name(), ".json") != record.CellID {
			continue
		}
		if validateContainerName(record.ContainerName) != nil {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

// ReclaimOrphan deletes an orphaned AppContainer profile, its staging directory
// and the journal entry. Missing objects are tolerated so reclamation is
// idempotent.
func (p *windowsPlatform) ReclaimOrphan(ctx context.Context, record orphanRecord) error {
	root, err := p.stagingRoot()
	if err != nil {
		return err
	}
	if err := validateContainerName(record.ContainerName); err != nil {
		return err
	}
	if !validCellID(record.CellID) {
		return &Error{Op: "journal.reclaim", Kind: ErrStagingUnsafe, Detail: "cell id is not a canonical UUID v4"}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("parsercells: reclaim canceled: %w", err)
	}
	containers := windowsContainers{}
	reclaimErr := containers.Delete(record.ContainerName)
	cellDir, dirErr := cellDirectory(root, record.CellID)
	if dirErr != nil {
		return errors.Join(reclaimErr, dirErr)
	}
	if err := os.RemoveAll(cellDir); err != nil {
		reclaimErr = errors.Join(reclaimErr, fmt.Errorf("parsercells: reclaim staging: %w", err))
	}
	if err := p.ClearOrphan(record.CellID); err != nil {
		reclaimErr = errors.Join(reclaimErr, err)
	}
	return reclaimErr
}

// writeExclusiveFile writes data to a new file with O_EXCL and fsync.
func writeExclusiveFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("parsercells: create %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("parsercells: write %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("parsercells: sync %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("parsercells: close %s: %w", filepath.Base(path), err)
	}
	return nil
}

// cellIDFromPath returns the last path element, used for the embedded-UUID check
// of a staged directory.
func cellIDFromPath(path string) string {
	return filepath.Base(filepath.Clean(path))
}

// applyProtectedDACL installs a protected DACL on path: the current user gets
// full control, and when containerSID is non-empty the exact AppContainer SID
// gets file read access. No inheritance and no other principals are granted.
func applyProtectedDACL(path, containerSID string) error {
	userSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if containerSID != "" && (len(containerSID) == 0 || len(containerSID) > 256) {
		return errors.New("container SID out of bounds")
	}
	sddl := "D:P(A;;FA;;;" + userSID + ")"
	if containerSID != "" {
		sddl += "(A;;FR;;;" + containerSID + ")"
	}
	sddlPointer, err := utf16Ptr(sddl)
	if err != nil {
		return err
	}
	var descriptor uintptr
	result, _, callErr := procConvertStringSecurityDescriptorToSD.Call(
		uintptr(unsafe.Pointer(sddlPointer)),
		uintptr(sddlRevision1),
		uintptr(unsafe.Pointer(&descriptor)),
		0,
	)
	if result == 0 {
		if err := errnoOrNil(callErr); err != nil {
			return fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptorW: %w", err)
		}
		return errors.New("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")
	}
	defer func() { _, _, _ = procLocalFree.Call(descriptor) }()
	pathPointer, err := utf16Ptr(path)
	if err != nil {
		return err
	}
	result, _, callErr = procSetFileSecurityW.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		uintptr(daclSecurityInformation),
		descriptor,
	)
	if err := checkBOOL("SetFileSecurityW", result, callErr); err != nil {
		return err
	}
	return nil
}

// currentUserSID returns the canonical SID string of the process user token.
func currentUserSID() (string, error) {
	process, _, _ := procGetCurrentProcess.Call()
	var token syscall.Handle
	result, _, callErr := procOpenProcessToken.Call(process, uintptr(tokenQuery), uintptr(unsafe.Pointer(&token)))
	if err := checkBOOL("OpenProcessToken", result, callErr); err != nil {
		return "", err
	}
	defer func() { _ = closeHandle(token) }()
	const tokenUser uint32 = 1
	var required uint32
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenUser), 0, 0, uintptr(unsafe.Pointer(&required)),
	)
	if result != 0 {
		return "", errors.New("GetTokenInformation(TokenUser) size query unexpectedly succeeded")
	}
	if err := errnoOrNil(callErr); !errors.Is(err, errorInsufficientBuffer) {
		return "", err
	}
	if required == 0 || required > maxTokenInformationBytes {
		return "", fmt.Errorf("token user buffer %d outside (0,%d]", required, maxTokenInformationBytes)
	}
	buffer := make([]byte, required)
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenUser),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(required), uintptr(unsafe.Pointer(&required)),
	)
	if err := checkBOOL("GetTokenInformation(TokenUser)", result, callErr); err != nil {
		return "", err
	}
	if len(buffer) < 8 {
		return "", errors.New("token user buffer too small")
	}
	sidPointer := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	if sidPointer == 0 {
		return "", errors.New("token user SID is nil")
	}
	return sidToString(sidPointer)
}
