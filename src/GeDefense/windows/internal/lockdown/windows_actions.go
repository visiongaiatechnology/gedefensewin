// STATUS: PLATIN VGT SUPREME
//go:build windows

package lockdown

// Production Windows adapters of the injected interfaces.
//
//   - WindowsProcessController: Toolhelp32 process inventory plus GetProcessTimes
//     identity, and ntdll NtSuspendProcess/NtResumeProcess for the broker freeze.
//     Every signal is bound to the recorded creation time, so a recycled PID is
//     refused before the process is touched.
//   - WindowsSessionController: user32 LockWorkStation, WTSEnumerateSessionsW /
//     WTSDisconnectSession and an OpenInputDesktop lock read-back.
//
// Both adapters are thin: no policy, no retry storm, no panic, bounded scans and
// real errors. They are never invoked by the unit tests with a destructive
// action; tests inject fakes instead.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	processQueryLimitedInformation = 0x1000
	processSuspendResume           = 0x0800
	th32csSnapshot                 = 0x00000002
	desktopReadObjects             = 0x0001
	wtsCurrentServerHandle         = 0
	wtsEnumerateSessionsVersion    = 1
	wtsSessionActive               = 0
	wtsSessionConnected            = 1
	maxWTSSessions                 = 256
	processScanLimit               = 512
	filetimeUnixEpochOffset        = 116444736000000000 // 100 ns intervals 1601-01-01 -> 1970-01-01
	desktopPollAttempts            = 10
	desktopPollInterval            = 50 * time.Millisecond
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32.NewProc("Process32NextW")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procGetProcessTimes          = kernel32.NewProc("GetProcessTimes")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procNtSuspendProcess         = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProcess          = ntdll.NewProc("NtResumeProcess")
	procLockWorkStation          = user32.NewProc("LockWorkStation")
	procOpenInputDesktop         = user32.NewProc("OpenInputDesktop")
	procCloseDesktop             = user32.NewProc("CloseDesktop")
	procWTSEnumerateSessionsW    = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory            = wtsapi32.NewProc("WTSFreeMemory")
	procWTSDisconnectSession     = wtsapi32.NewProc("WTSDisconnectSession")
	procGetCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	procProcessIdToSessionId     = kernel32.NewProc("ProcessIdToSessionId")
)

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

var (
	_ ProcessController = (*WindowsProcessController)(nil)
	_ SessionController = (*WindowsSessionController)(nil)
)

// WindowsProcessController is the production ProcessController.
type WindowsProcessController struct{}

// NewWindowsProcessController returns the ntdll/Toolhelp process adapter.
func NewWindowsProcessController() *WindowsProcessController { return &WindowsProcessController{} }

// ListProcesses returns the accessible process inventory with creation times.
// Inaccessible protected processes are skipped (their PIDs are never useful for
// the broker freezer); the scan is bounded to 512 entries.
func (c *WindowsProcessController) ListProcesses(ctx context.Context) ([]ProcessInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	snapshot, _, callErr := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapshot), 0)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return nil, lastWindowsError("CreateToolhelp32Snapshot", callErr)
	}
	defer func() { _, _, _ = procCloseHandle.Call(snapshot) }()
	processes := make([]ProcessInfo, 0, 128)
	entry := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	result, _, callErr := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	runtime.KeepAlive(&entry)
	if result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_NO_MORE_FILES {
			return processes, nil
		}
		return nil, lastWindowsError("Process32FirstW", callErr)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("process inventory interrupted: %w", err)
		}
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if entry.ProcessID != 0 && name != "" {
			if creation, err := processCreationUnixNano(entry.ProcessID); err == nil && creation > 0 {
				processes = append(processes, ProcessInfo{
					PID: entry.ProcessID, Name: name, CreationUnixNano: creation,
				})
			}
		}
		if len(processes) >= processScanLimit {
			return processes, nil
		}
		entry.Size = uint32(unsafe.Sizeof(processEntry32{}))
		result, _, callErr = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		runtime.KeepAlive(&entry)
		if result == 0 {
			if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_NO_MORE_FILES {
				return processes, nil
			}
			return processes, nil
		}
	}
}

// Suspend stops the process under the identity check.
func (c *WindowsProcessController) Suspend(pid uint32, creationUnixNano int64) error {
	return windowsSignalProcess(pid, creationUnixNano, true)
}

// Resume continues the process under the identity check.
func (c *WindowsProcessController) Resume(pid uint32, creationUnixNano int64) error {
	return windowsSignalProcess(pid, creationUnixNano, false)
}

// windowsSignalProcess performs the identity re-check and the ntdll call.
func windowsSignalProcess(pid uint32, creationUnixNano int64, suspend bool) error {
	if pid <= 4 {
		return fmt.Errorf("%w: pid %d is in the protected system range", ErrProcessProtected, pid)
	}
	if creationUnixNano <= 0 {
		return fmt.Errorf("%w: pid %d has no creation-time identity", ErrProcessIdentityMismatch, pid)
	}
	handle, err := openProcessHandle(pid, processQueryLimitedInformation|processSuspendResume)
	if err != nil {
		return err
	}
	defer func() { _, _, _ = procCloseHandle.Call(uintptr(handle)) }()
	actual, err := processCreationUnixNanoFromHandle(handle)
	if err != nil {
		return fmt.Errorf("process %d creation time: %w", pid, err)
	}
	if actual != creationUnixNano {
		return fmt.Errorf("%w: pid %d expected creation %d, got %d", ErrProcessIdentityMismatch, pid, creationUnixNano, actual)
	}
	procedure := procNtSuspendProcess
	name := "NtSuspendProcess"
	if !suspend {
		procedure = procNtResumeProcess
		name = "NtResumeProcess"
	}
	status, _, _ := procedure.Call(uintptr(handle))
	if status != 0 {
		return fmt.Errorf("%s failed for pid %d with NTSTATUS 0x%x", name, pid, status)
	}
	return nil
}

// processCreationUnixNano returns the creation time of one process.
func processCreationUnixNano(pid uint32) (int64, error) {
	handle, err := openProcessHandle(pid, processQueryLimitedInformation)
	if err != nil {
		return 0, err
	}
	defer func() { _, _, _ = procCloseHandle.Call(uintptr(handle)) }()
	return processCreationUnixNanoFromHandle(handle)
}

// processCreationUnixNanoFromHandle reads the creation FILETIME.
func processCreationUnixNanoFromHandle(handle syscall.Handle) (int64, error) {
	var creation, exit, kernel, user filetime
	result, _, callErr := procGetProcessTimes.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	runtime.KeepAlive(&creation)
	runtime.KeepAlive(&exit)
	runtime.KeepAlive(&kernel)
	runtime.KeepAlive(&user)
	if result == 0 {
		return 0, lastWindowsError("GetProcessTimes", callErr)
	}
	value := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if value == 0 {
		return 0, nil
	}
	return (int64(value) - filetimeUnixEpochOffset) * 100, nil
}

// openProcessHandle opens one process with the requested access.
func openProcessHandle(pid uint32, access uint32) (syscall.Handle, error) {
	handle, _, callErr := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if handle == 0 {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, lastWindowsError("OpenProcess", callErr))
	}
	return syscall.Handle(handle), nil
}

// WindowsSessionController is the production SessionController.
type WindowsSessionController struct{}

// NewWindowsSessionController returns the user32/WTS session adapter.
func NewWindowsSessionController() *WindowsSessionController { return &WindowsSessionController{} }

// Lock locks the workstation.
func (c *WindowsSessionController) Lock(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, _, callErr := procLockWorkStation.Call()
	if result == 0 {
		return lastWindowsError("LockWorkStation", callErr)
	}
	return nil
}

// Locked reads the input-desktop lock state back. A locked secure desktop cannot
// be opened by the user process (ERROR_ACCESS_DENIED); the adapter polls the
// bounded window because LockWorkStation returns before the desktop switch.
func (c *WindowsSessionController) Locked(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; attempt < desktopPollAttempts; attempt++ {
		locked, err := inputDesktopLocked()
		if err != nil {
			return false, err
		}
		if locked {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(desktopPollInterval):
		}
	}
	return false, nil
}

// inputDesktopLocked probes the input desktop.
func inputDesktopLocked() (bool, error) {
	desktop, _, callErr := procOpenInputDesktop.Call(0, 0, uintptr(desktopReadObjects))
	if desktop != 0 {
		_, _, _ = procCloseDesktop.Call(desktop)
		return false, nil
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
		return true, nil
	}
	return false, lastWindowsError("OpenInputDesktop", callErr)
}

// DisconnectAll disconnects every active/connected session except the current
// one. The session list is bounded before it is walked.
func (c *WindowsSessionController) DisconnectAll(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var sessions *wtsSessionInfo
	var count uint32
	result, _, callErr := procWTSEnumerateSessionsW.Call(
		uintptr(wtsCurrentServerHandle), 0, uintptr(wtsEnumerateSessionsVersion),
		uintptr(unsafe.Pointer(&sessions)), uintptr(unsafe.Pointer(&count)),
	)
	if result == 0 {
		return 0, lastWindowsError("WTSEnumerateSessionsW", callErr)
	}
	if sessions == nil {
		return 0, errors.New("WTSEnumerateSessionsW returned no session buffer")
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(sessions))) }()
	if count > maxWTSSessions {
		return 0, fmt.Errorf("session count %d exceeds the bounded scan", count)
	}
	if count == 0 {
		return 0, nil
	}
	current := currentSessionID()
	list := unsafe.Slice(sessions, int(count))
	disconnected := 0
	for index := range list {
		if err := ctx.Err(); err != nil {
			return disconnected, err
		}
		session := list[index]
		if session.SessionID == current {
			continue
		}
		if session.State != wtsSessionActive && session.State != wtsSessionConnected {
			continue
		}
		ok, _, disconnectErr := procWTSDisconnectSession.Call(
			uintptr(wtsCurrentServerHandle), uintptr(session.SessionID), 0,
		)
		if ok == 0 {
			return disconnected, lastWindowsError(fmt.Sprintf("WTSDisconnectSession(%d)", session.SessionID), disconnectErr)
		}
		disconnected++
	}
	return disconnected, nil
}

// currentSessionID returns the session of the calling process.
func currentSessionID() uint32 {
	pid, _, _ := procGetCurrentProcessId.Call()
	var session uint32
	result, _, _ := procProcessIdToSessionId.Call(pid, uintptr(unsafe.Pointer(&session)))
	runtime.KeepAlive(&session)
	if result == 0 {
		return ^uint32(0)
	}
	return session
}

// lastWindowsError converts a syscall error into a bounded error.
func lastWindowsError(call string, callErr error) error {
	if callErr == nil {
		return fmt.Errorf("%s failed", call)
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == 0 {
		return fmt.Errorf("%s failed", call)
	}
	return fmt.Errorf("%s failed: %w", call, callErr)
}
