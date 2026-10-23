// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	th32CSProcess = 0x00000002
	maxProcesses  = 8192
)

type ProcessEntry struct {
	PID       uint32
	ParentPID uint32
	Image     string
}

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

var (
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32.NewProc("Process32NextW")
)

// ProcessList returns the live process table without opening each process.
// Enrichment (path, creation time) remains the caller's responsibility.
func ProcessList() ([]ProcessEntry, error) {
	snapshot, _, callErr := procCreateToolhelp32Snapshot.Call(uintptr(th32CSProcess), 0)
	if snapshot == ^uintptr(0) || snapshot == 0 {
		if err := errnoResult(callErr); err != nil {
			return nil, err
		}
		return nil, errors.New("CreateToolhelp32Snapshot failed")
	}
	defer func() { _ = CloseHandle(Handle(snapshot)) }()
	entry := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	result, _, callErr := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if result == 0 {
		if err := errnoResult(callErr); err != nil && !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
			return nil, err
		}
		return []ProcessEntry{}, nil
	}
	processes := make([]ProcessEntry, 0, 256)
	for {
		if entry.ProcessID != 0 {
			processes = append(processes, ProcessEntry{
				PID: entry.ProcessID, ParentPID: entry.ParentProcessID,
				Image: syscall.UTF16ToString(entry.ExeFile[:]),
			})
		}
		if len(processes) >= maxProcesses {
			return nil, errors.New("process table boundary exceeded")
		}
		entry.Size = uint32(unsafe.Sizeof(processEntry32{}))
		result, _, callErr = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if result == 0 {
			if err := errnoResult(callErr); err != nil && !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				return nil, err
			}
			break
		}
	}
	return processes, nil
}
