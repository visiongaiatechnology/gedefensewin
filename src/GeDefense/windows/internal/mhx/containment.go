// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maximumContainmentRecords = 128
	maximumContainmentTree    = 128
	maximumContainmentDepth   = 16
)

type ContainmentState string

const (
	ContainmentFrozen     ContainmentState = "FROZEN"
	ContainmentResumed    ContainmentState = "RESUMED"
	ContainmentTerminated ContainmentState = "TERMINATED"
)

// ContainmentProcess identifies one verified process inside a contained tree.
// Every transition (suspend, resume, terminate) re-verifies CreationUnixNano
// and ImagePath to defeat PID reuse (FIND-WIN-002).
type ContainmentProcess struct {
	PID              uint32 `json:"pid"`
	ParentPID        uint32 `json:"parentPid"`
	Image            string `json:"image"`
	ImagePath        string `json:"imagePath"`
	CreationUnixNano int64  `json:"creationUnixNano"`
	ActionState      string `json:"actionState"`
}

// ContainmentRecord captures a reversible process-tree freeze or escalation
// decision triggered by Defender Symbiosis, Titan correlation, or Sentinel.
type ContainmentRecord struct {
	ID         string               `json:"id"`
	CreatedUTC time.Time            `json:"createdUtc"`
	UpdatedUTC time.Time            `json:"updatedUtc"`
	State      ContainmentState     `json:"state"`
	Source     string               `json:"source"`
	Reason     string               `json:"reason"`
	RootPID    uint32               `json:"rootPid"`
	RootImage  string               `json:"rootImage"`
	Processes  []ContainmentProcess `json:"processes"`
	Outcome    string               `json:"outcome,omitempty"`
}

type containmentExecutor interface {
	FreezeTree(target TerminationTarget) ([]ContainmentProcess, error)
	ResumeTree(processes []ContainmentProcess) (int, error)
	TerminateTree(processes []ContainmentProcess) (int, error)
}

func newContainmentID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("cnt-%d", time.Now().UTC().UnixNano())
	}
	return "cnt-" + hex.EncodeToString(raw[:])
}

func validateTerminationTarget(target TerminationTarget) error {
	if target.PID <= 4 {
		return errors.New("pid boundary rejected")
	}
	if target.PID == uint32(os.Getpid()) {
		return errors.New("self-protection: own service process cannot be contained")
	}
	if target.CreationUnixNano <= 0 {
		return errors.New("process identity incomplete: creation time missing")
	}
	if strings.TrimSpace(target.ImagePath) == "" {
		return errors.New("process identity incomplete: image path missing")
	}
	if IsProtectedOSProcess("", target.ImagePath) {
		return errors.New("protected operating-system process: containment rejected")
	}
	if isGeDefenseBinary(target.ImagePath) {
		return errors.New("self-protection: GeDefense process containment rejected")
	}
	return nil
}

// FreezeProcessTree reversibly suspends a verified process and its non-system
// descendant tree (equivalent to Linux 6.2.0 M2.3 GROUP_STOP) so ransomware or
// active malware stops writing before evidence/quarantine decisions complete.
func (e *Engine) FreezeProcessTree(target TerminationTarget, source string) (ContainmentRecord, error) {
	if err := validateTerminationTarget(target); err != nil {
		return ContainmentRecord{}, err
	}
	if isTrackedChild(target.PID) {
		return ContainmentRecord{}, errors.New("self-protection: tracked child process cannot be contained")
	}
	exec := e.containmentOps()
	processes, err := exec.FreezeTree(target)
	if err != nil {
		_ = e.ledger.Append("mhx.containment", "freeze-failed", fmt.Sprintf("source=%s; pid=%d; err=%v", trimSentinelText(source), target.PID, err))
		return ContainmentRecord{}, err
	}
	now := time.Now().UTC()
	record := ContainmentRecord{
		ID:         newContainmentID(),
		CreatedUTC: now,
		UpdatedUTC: now,
		State:      ContainmentFrozen,
		Source:     trimSentinelText(source),
		Reason:     trimSentinelText(target.Reason),
		RootPID:    target.PID,
		RootImage:  filepath.Base(target.ImagePath),
		Processes:  processes,
		Outcome:    fmt.Sprintf("%d Prozess(e) reversibel eingefroren (NtSuspendProcess)", len(processes)),
	}
	e.mu.Lock()
	e.storeContainmentLocked(record)
	e.mu.Unlock()
	_ = e.ledger.Append("mhx.containment", "freeze", fmt.Sprintf("id=%s; root=%d; count=%d; source=%s", record.ID, record.RootPID, len(record.Processes), record.Source))
	e.notifyEvent(notificationKindBlock, SeverityCritical, "Prozessbaum eingefroren (Containment)", fmt.Sprintf("%s (PID %d · %d Prozesse) wurde reversibel gestoppt.", record.RootImage, record.RootPID, len(record.Processes)))
	return record, nil
}

// ResumeContainment releases a previously frozen process tree after operator
// review and typed confirmation, re-verifying every PID identity first.
func (e *Engine) ResumeContainment(id, reason string) (ContainmentRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 64 {
		return ContainmentRecord{}, errors.New("containment id invalid")
	}
	trimmedReason := trimSentinelText(reason)
	if len(trimmedReason) < 8 {
		return ContainmentRecord{}, errors.New("operator reason required")
	}
	e.mu.RLock()
	record, found := e.findContainmentLocked(id)
	e.mu.RUnlock()
	if !found {
		return ContainmentRecord{}, errors.New("containment record not found")
	}
	if record.State != ContainmentFrozen {
		return ContainmentRecord{}, fmt.Errorf("containment %s is %s, expected FROZEN", record.ID, record.State)
	}
	resumed, err := e.containmentOps().ResumeTree(record.Processes)
	if err != nil {
		_ = e.ledger.Append("mhx.containment", "resume-failed", fmt.Sprintf("id=%s; err=%v", record.ID, err))
		return ContainmentRecord{}, err
	}
	now := time.Now().UTC()
	e.mu.Lock()
	if current, ok := e.findContainmentLocked(id); ok {
		current.State = ContainmentResumed
		current.UpdatedUTC = now
		current.Outcome = fmt.Sprintf("%d Prozess(e) freigegeben: %s", resumed, trimmedReason)
		for i := range current.Processes {
			current.Processes[i].ActionState = "RESUMED"
		}
		e.storeContainmentLocked(current)
		record = current
	}
	e.mu.Unlock()
	_ = e.ledger.Append("mhx.containment", "resume", fmt.Sprintf("id=%s; resumed=%d", record.ID, resumed))
	return record, nil
}

// TerminateContainment escalates a frozen process tree to hard termination
// (`KILL_TREE`), re-verifying CreationTime and ImagePath on every target.
func (e *Engine) TerminateContainment(id, reason string) (ContainmentRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 64 {
		return ContainmentRecord{}, errors.New("containment id invalid")
	}
	trimmedReason := trimSentinelText(reason)
	if len(trimmedReason) < 8 {
		return ContainmentRecord{}, errors.New("operator reason required")
	}
	e.mu.RLock()
	record, found := e.findContainmentLocked(id)
	e.mu.RUnlock()
	if !found {
		return ContainmentRecord{}, errors.New("containment record not found")
	}
	if record.State == ContainmentTerminated {
		return record, nil
	}
	killed, err := e.containmentOps().TerminateTree(record.Processes)
	if err != nil {
		_ = e.ledger.Append("mhx.containment", "terminate-failed", fmt.Sprintf("id=%s; err=%v", record.ID, err))
		return ContainmentRecord{}, err
	}
	now := time.Now().UTC()
	e.mu.Lock()
	if current, ok := e.findContainmentLocked(id); ok {
		current.State = ContainmentTerminated
		current.UpdatedUTC = now
		current.Outcome = fmt.Sprintf("%d Prozess(e) beendet: %s", killed, trimmedReason)
		for i := range current.Processes {
			current.Processes[i].ActionState = "TERMINATED"
		}
		e.storeContainmentLocked(current)
		record = current
	}
	e.mu.Unlock()
	if killed > 0 {
		e.blocked.Add(uint64(killed))
	}
	_ = e.ledger.Append("mhx.containment", "terminate", fmt.Sprintf("id=%s; killed=%d", record.ID, killed))
	return record, nil
}

// TerminateProcessTree kills a verified root process and its safe descendants
// directly (used by high-confidence enforcement bridges).
func (e *Engine) TerminateProcessTree(target TerminationTarget) (int, error) {
	if err := validateTerminationTarget(target); err != nil {
		return 0, err
	}
	if isTrackedChild(target.PID) {
		return 0, errors.New("self-protection: tracked child process cannot be terminated")
	}
	frozen, err := e.containmentOps().FreezeTree(target)
	if err != nil {
		return 0, err
	}
	killed, err := e.containmentOps().TerminateTree(frozen)
	if err != nil {
		return killed, err
	}
	if killed > 0 {
		e.blocked.Add(uint64(killed))
	}
	now := time.Now().UTC()
	record := ContainmentRecord{
		ID:         newContainmentID(),
		CreatedUTC: now,
		UpdatedUTC: now,
		State:      ContainmentTerminated,
		Source:     "kill-tree",
		Reason:     trimSentinelText(target.Reason),
		RootPID:    target.PID,
		RootImage:  filepath.Base(target.ImagePath),
		Processes:  frozen,
		Outcome:    fmt.Sprintf("Freeze+Kill-Tree beendet (%d/%d Prozesse)", killed, len(frozen)),
	}
	for i := range record.Processes {
		record.Processes[i].ActionState = "TERMINATED"
	}
	e.mu.Lock()
	e.storeContainmentLocked(record)
	e.mu.Unlock()
	return killed, nil
}

// Containments returns all tracked containment records (newest first).
func (e *Engine) Containments() []ContainmentRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]ContainmentRecord, len(e.containments))
	for i := range e.containments {
		src := e.containments[len(e.containments)-1-i]
		src.Processes = append([]ContainmentProcess(nil), src.Processes...)
		result[i] = src
	}
	return result
}

func (e *Engine) storeContainmentLocked(record ContainmentRecord) {
	for i := range e.containments {
		if e.containments[i].ID == record.ID {
			e.containments[i] = record
			return
		}
	}
	e.containments = append(e.containments, record)
	if len(e.containments) > maximumContainmentRecords {
		// Prefer evicting completed records before any active FROZEN record.
		trimmed := make([]ContainmentRecord, 0, maximumContainmentRecords)
		for _, candidate := range e.containments {
			if candidate.State == ContainmentFrozen {
				trimmed = append(trimmed, candidate)
			}
		}
		tailRoom := maximumContainmentRecords - len(trimmed)
		if tailRoom > 0 {
			for i := len(e.containments) - 1; i >= 0 && len(trimmed) < maximumContainmentRecords; i-- {
				if e.containments[i].State != ContainmentFrozen {
					trimmed = append(trimmed, e.containments[i])
				}
			}
		}
		e.containments = trimmed
	}
}

func (e *Engine) findContainmentLocked(id string) (ContainmentRecord, bool) {
	for _, record := range e.containments {
		if record.ID == id {
			copyRecord := record
			copyRecord.Processes = append([]ContainmentProcess(nil), record.Processes...)
			return copyRecord, true
		}
	}
	return ContainmentRecord{}, false
}

func (e *Engine) containmentOps() containmentExecutor {
	if e != nil && e.containmentExec != nil {
		return e.containmentExec
	}
	return defaultContainmentExecutor{}
}
