// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winexec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	// maxTrackedProcesses bounds the pinned-handle registry. The engine spawns
	// at most one long-lived watcher per subsystem, so this is a hard safety
	// limit rather than a working set.
	maxTrackedProcesses = 256
	// creationTimeTolerance allows for FileTime rounding between the pinned
	// identity and a re-query through the same handle.
	creationTimeTolerance = 2 * time.Second
)

// trackedProcess pins the kernel process object of a child that this process
// spawned. Holding the handle for the lifetime of the child prevents Windows
// from recycling its PID, which is the precondition for the former
// taskkill-by-PID TOCTOU (HP-FIND-004).
type trackedProcess struct {
	identity         winapi.ProcessIdentity
	creationUnixNano int64
	imagePath        string
}

var (
	trackedMu        sync.Mutex
	trackedProcesses = make(map[int]*trackedProcess)
)

// StartTracked starts command exactly like (*exec.Cmd).Start and pins the
// child process object while it runs. Command cancellation handlers can then
// call KillProcessTree, which refuses to act unless the PIN still matches the
// originally observed creation time and image path. If the child exits before
// it can be pinned (or access is denied) the command still starts; tree kills
// for that PID fail closed and only the caller's handle-safe Process.Kill is
// available.
func StartTracked(command *exec.Cmd) error {
	if command == nil {
		return errors.New("command required")
	}
	if err := command.Start(); err != nil {
		return err
	}
	if command.Process != nil && command.Process.Pid > 4 {
		trackProcess(command.Process.Pid)
	}
	return nil
}

// RunTracked is StartTracked followed by Wait. The pinned handle is released
// once the child has been reaped.
func RunTracked(command *exec.Cmd) error {
	if err := StartTracked(command); err != nil {
		return err
	}
	pid := 0
	if command.Process != nil {
		pid = command.Process.Pid
	}
	waitErr := command.Wait()
	ReleaseTrackedProcess(pid)
	return waitErr
}

// ReleaseTrackedProcess closes the pinned handle for a reaped child. It is a
// no-op for untracked PIDs and is safe to call multiple times.
func ReleaseTrackedProcess(pid int) {
	trackedMu.Lock()
	defer trackedMu.Unlock()
	if entry, ok := trackedProcesses[pid]; ok {
		_ = entry.identity.Close()
		delete(trackedProcesses, pid)
	}
}

func trackProcess(pid int) {
	if pid <= 4 {
		return
	}
	identity, err := winapi.OpenProcessIdentity(uint32(pid), true)
	if err != nil {
		return
	}
	trackedMu.Lock()
	defer trackedMu.Unlock()
	pruneTrackedLocked()
	if existing, ok := trackedProcesses[pid]; ok {
		_ = existing.identity.Close()
		delete(trackedProcesses, pid)
	}
	if len(trackedProcesses) >= maxTrackedProcesses {
		_ = identity.Close()
		return
	}
	trackedProcesses[pid] = &trackedProcess{
		identity:         identity,
		creationUnixNano: identity.CreationUnixNano,
		imagePath:        identity.ImagePath,
	}
}

// pruneTrackedLocked drops entries whose process already signalled. Callers
// must hold trackedMu.
func pruneTrackedLocked() {
	for pid, entry := range trackedProcesses {
		if entry.identity.Handle == 0 {
			delete(trackedProcesses, pid)
			continue
		}
		signalled, err := winapi.WaitForSingleObject(entry.identity.Handle, 0)
		if err != nil || signalled != winapi.WaitObject0 {
			continue
		}
		_ = entry.identity.Close()
		delete(trackedProcesses, pid)
	}
}

func lookupTrackedProcess(pid int) *trackedProcess {
	trackedMu.Lock()
	defer trackedMu.Unlock()
	pruneTrackedLocked()
	entry, ok := trackedProcesses[pid]
	if !ok {
		return nil
	}
	copy := *entry
	return &copy
}

func dropTrackedProcess(pid int) {
	trackedMu.Lock()
	defer trackedMu.Unlock()
	if entry, ok := trackedProcesses[pid]; ok {
		_ = entry.identity.Close()
		delete(trackedProcesses, pid)
	}
}

// validateTrackedIdentity rejects a tree kill when the pinned identity no
// longer matches the values captured at spawn time. A genuine PID reuse can
// never be observed through the pinned handle, so a mismatch always indicates
// registry corruption and the kill fails closed.
func validateTrackedIdentity(tracked *trackedProcess, observed winapi.ProcessIdentity) error {
	if tracked == nil {
		return errors.New("process tree kill rejected: process is not tracked")
	}
	if observed.Handle == 0 {
		return errors.New("process tree kill rejected: process handle unavailable")
	}
	difference := time.Duration(observed.CreationUnixNano - tracked.creationUnixNano)
	if difference < 0 {
		difference = -difference
	}
	if difference > creationTimeTolerance {
		return errors.New("process tree kill rejected: creation time changed")
	}
	if !winapi.SameImagePath(observed.ImagePath, tracked.imagePath) {
		return errors.New("process tree kill rejected: image path changed")
	}
	return nil
}

// KillProcessTree terminates a process previously started with StartTracked or
// RunTracked and all of its descendants. The call fails closed for untracked
// PIDs and for identities that no longer match the values captured at spawn
// time. While taskkill resolves the PID, this process keeps the pinned handle
// open, so Windows cannot recycle the PID and taskkill cannot target an
// unrelated process tree.
func KillProcessTree(pid int) error {
	if pid <= 4 {
		return errors.New("invalid process ID")
	}
	tracked := lookupTrackedProcess(pid)
	if tracked == nil {
		return errors.New("process tree kill rejected: process is not tracked")
	}
	observed, err := winapi.QueryProcessIdentity(tracked.identity.Handle)
	if err != nil {
		dropTrackedProcess(pid)
		return fmt.Errorf("process tree kill rejected: identity query failed: %w", err)
	}
	if err := validateTrackedIdentity(tracked, observed); err != nil {
		dropTrackedProcess(pid)
		return err
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" || !filepath.IsAbs(systemRoot) {
		systemRoot = `C:\Windows`
	}
	taskkill := filepath.Join(filepath.Clean(systemRoot), "System32", "taskkill.exe")
	info, err := os.Lstat(taskkill)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("taskkill is unavailable")
	}
	// taskkill runs while the pinned handle stays open: the PID is guaranteed
	// to still name the verified process object for the whole call.
	cmd := exec.Command(taskkill, "/F", "/T", "/PID", strconv.Itoa(pid))
	return cmd.Run()
}
