// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Job Object adapter. The job is the second kernel boundary of a cell: one
// active process, a hard commit charge, a per-process user-time budget,
// kill-on-close (so dropping the last handle always terminates the parser),
// die-on-unhandled-exception and every UI limitation. Every limit is read back
// after it was set; a mismatch makes the cell fail closed.

// Job object information classes.
const (
	jobObjectBasicAccountingInformation uint32 = 1
	jobObjectBasicProcessIDList         uint32 = 3
	jobObjectBasicUIRestrictions        uint32 = 4
	jobObjectExtendedLimitInformation   uint32 = 9
)

// Job object limit flags.
const (
	jobObjectLimitProcessTime          uint32 = 0x00000002
	jobObjectLimitActiveProcess        uint32 = 0x00000008
	jobObjectLimitJobMemory            uint32 = 0x00000200
	jobObjectLimitDieOnUnhandledExcept uint32 = 0x00000400
	jobObjectLimitKillOnJobClose       uint32 = 0x00002000
)

// Job object UI restriction flags (all of them are requested and verified).
const (
	jobObjectUILimitHandles          uint32 = 0x00000001
	jobObjectUILimitReadClipboard    uint32 = 0x00000002
	jobObjectUILimitWriteClipboard   uint32 = 0x00000004
	jobObjectUILimitSystemParameters uint32 = 0x00000008
	jobObjectUILimitDisplaySettings  uint32 = 0x00000010
	jobObjectUILimitGlobalAtoms      uint32 = 0x00000020
	jobObjectUILimitDesktop          uint32 = 0x00000040
	jobObjectUILimitExitWindows      uint32 = 0x00000080
	// jobObjectUILimitAll is the complete UI lockdown mask.
	jobObjectUILimitAll uint32 = jobObjectUILimitHandles | jobObjectUILimitReadClipboard |
		jobObjectUILimitWriteClipboard | jobObjectUILimitSystemParameters |
		jobObjectUILimitDisplaySettings | jobObjectUILimitGlobalAtoms |
		jobObjectUILimitDesktop | jobObjectUILimitExitWindows
)

// maxJobProcessIDs bounds the process ID list query.
const maxJobProcessIDs = 8

var (
	procCreateJobObjectW          = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject   = kernel32.NewProc("SetInformationJobObject")
	procQueryInformationJobObject = kernel32.NewProc("QueryInformationJobObject")
	procAssignProcessToJobObject  = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject        = kernel32.NewProc("TerminateJobObject")
	procIsProcessInJob            = kernel32.NewProc("IsProcessInJob")
)

// LARGE_INTEGER / SIZE_T structures mirroring the Windows ABI (64-bit target).
type joBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	_                       uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	_                       uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type joIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type joExtendedLimitInformation struct {
	BasicLimitInformation joBasicLimitInformation
	IOInfo                joIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type joBasicUIRestrictions struct {
	UIRestrictionsClass uint32
}

type joBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type joBasicProcessIDList struct {
	NumberOfAssignedProcesses uint32
	NumberOfProcessIDsInList  uint32
	ProcessIDList             [maxJobProcessIDs]uintptr
}

// jobLimits is the requested, validated job configuration. It is a pure value
// type so tests can assert the exact kernel limits without a live job.
type jobLimits struct {
	ActiveProcesses         uint32
	JobMemoryBytes          uint64
	PerProcessUserTime      time.Duration
	KillOnClose             bool
	DieOnUnhandledException bool
	UIRestrictions          uint32
}

// jobLimitsForProfile derives the kernel job limits from a validated profile.
func jobLimitsForProfile(profile Profile) jobLimits {
	return jobLimits{
		ActiveProcesses:         1,
		JobMemoryBytes:          uint64(profile.MaxMemoryBytes),
		PerProcessUserTime:      profile.MaxRuntime,
		KillOnClose:             true,
		DieOnUnhandledException: true,
		UIRestrictions:          jobObjectUILimitAll,
	}
}

// Validate checks that the requested limits are inside the package ceilings and
// that nothing weaker than the mandatory set is requested.
func (l jobLimits) Validate() error {
	if l.ActiveProcesses != 1 {
		return &Error{Op: "job.limits", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("active process limit %d must be 1", l.ActiveProcesses)}
	}
	if l.JobMemoryBytes < uint64(HardMinMemoryBytes) || l.JobMemoryBytes > uint64(HardMaxMemoryBytes) {
		return &Error{Op: "job.limits", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("job memory %d outside [%d,%d]", l.JobMemoryBytes, HardMinMemoryBytes, HardMaxMemoryBytes)}
	}
	if l.PerProcessUserTime < HardMinRuntime || l.PerProcessUserTime > HardMaxRuntime {
		return &Error{Op: "job.limits", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("per-process user time %s outside [%s,%s]", l.PerProcessUserTime, HardMinRuntime, HardMaxRuntime)}
	}
	if !l.KillOnClose {
		return &Error{Op: "job.limits", Kind: ErrInvalidProfile, Detail: "kill-on-job-close must be enabled"}
	}
	if !l.DieOnUnhandledException {
		return &Error{Op: "job.limits", Kind: ErrInvalidProfile, Detail: "die-on-unhandled-exception must be enabled"}
	}
	if l.UIRestrictions != jobObjectUILimitAll {
		return &Error{Op: "job.limits", Kind: ErrInvalidProfile,
			Detail: fmt.Sprintf("UI restrictions 0x%02x must equal 0x%02x", l.UIRestrictions, jobObjectUILimitAll)}
	}
	return nil
}

// limitFlags returns the JOBOBJECT_BASIC_LIMIT_INFORMATION LimitFlags for the
// requested limits.
func (l jobLimits) limitFlags() uint32 {
	flags := jobObjectLimitActiveProcess | jobObjectLimitJobMemory | jobObjectLimitProcessTime
	if l.KillOnClose {
		flags |= jobObjectLimitKillOnJobClose
	}
	if l.DieOnUnhandledException {
		flags |= jobObjectLimitDieOnUnhandledExcept
	}
	return flags
}

// perProcessUserTime100ns converts the duration into the 100 ns units required
// by the kernel.
func (l jobLimits) perProcessUserTime100ns() int64 {
	return int64(l.PerProcessUserTime / (100 * time.Nanosecond))
}

// jobReadback is the kernel truth read back from QueryInformationJobObject.
type jobReadback struct {
	LimitFlags              uint32
	ActiveProcessLimit      uint32
	JobMemoryLimit          uint64
	PerProcessUserTimeLimit int64
	UIRestrictions          uint32
	ActiveProcesses         uint32
	TotalProcesses          uint32
}

// Verify compares the requested limits with the kernel read-back. Every
// mandatory property must match exactly; anything else fails closed.
func (l jobLimits) Verify(readback jobReadback) error {
	required := l.limitFlags()
	if readback.LimitFlags&required != required {
		return &Error{Op: "job.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("limit flags 0x%08x missing required 0x%08x", readback.LimitFlags, required)}
	}
	if readback.ActiveProcessLimit != l.ActiveProcesses {
		return &Error{Op: "job.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("active process limit read-back %d != %d", readback.ActiveProcessLimit, l.ActiveProcesses)}
	}
	if readback.JobMemoryLimit != l.JobMemoryBytes {
		return &Error{Op: "job.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("job memory read-back %d != %d", readback.JobMemoryLimit, l.JobMemoryBytes)}
	}
	if readback.PerProcessUserTimeLimit != l.perProcessUserTime100ns() {
		return &Error{Op: "job.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("per-process user time read-back %d != %d", readback.PerProcessUserTimeLimit, l.perProcessUserTime100ns())}
	}
	if readback.UIRestrictions != l.UIRestrictions {
		return &Error{Op: "job.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("UI restrictions read-back 0x%02x != 0x%02x", readback.UIRestrictions, l.UIRestrictions)}
	}
	if readback.ActiveProcesses > 1 {
		return &Error{Op: "job.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("job has %d active processes, limit 1", readback.ActiveProcesses)}
	}
	return nil
}

// job is the injectable Job Object adapter.
type job interface {
	Assign(process syscall.Handle) error
	IsProcessAssigned(process syscall.Handle) (bool, error)
	Readback() (jobReadback, error)
	MemberPIDs(limit int) ([]uint32, error)
	Terminate(exitCode uint32) error
	Close() error
}

// windowsJob is the production adapter backed by kernel32.
type windowsJob struct {
	mu     sync.Mutex
	handle syscall.Handle
	limits jobLimits
}

// newWindowsJob creates and verifies a job object with the requested limits.
func newWindowsJob(limits jobLimits) (*windowsJob, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	handle, _, callErr := procCreateJobObjectW.Call(0, 0)
	if handle == 0 {
		return nil, fmt.Errorf("parsercells: CreateJobObjectW: %w", errnoOrNil(callErr))
	}
	created, err := setJobLimits(syscall.Handle(handle), limits)
	if err != nil {
		_ = closeHandle(syscall.Handle(handle))
		return nil, err
	}
	return created, nil
}

// setJobLimits applies the extended limits and the UI restrictions, then reads
// both back and verifies them.
func setJobLimits(handle syscall.Handle, limits jobLimits) (*windowsJob, error) {
	extended := joExtendedLimitInformation{}
	extended.BasicLimitInformation.LimitFlags = limits.limitFlags()
	extended.BasicLimitInformation.ActiveProcessLimit = limits.ActiveProcesses
	extended.BasicLimitInformation.PerProcessUserTimeLimit = limits.perProcessUserTime100ns()
	extended.JobMemoryLimit = uintptr(limits.JobMemoryBytes)
	result, _, callErr := procSetInformationJobObject.Call(
		uintptr(handle),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&extended)),
		unsafe.Sizeof(extended),
	)
	if err := checkBOOL("SetInformationJobObject(extended)", result, callErr); err != nil {
		return nil, fmt.Errorf("parsercells: %w", err)
	}
	uiRestrictions := joBasicUIRestrictions{UIRestrictionsClass: limits.UIRestrictions}
	result, _, callErr = procSetInformationJobObject.Call(
		uintptr(handle),
		uintptr(jobObjectBasicUIRestrictions),
		uintptr(unsafe.Pointer(&uiRestrictions)),
		unsafe.Sizeof(uiRestrictions),
	)
	if err := checkBOOL("SetInformationJobObject(ui)", result, callErr); err != nil {
		return nil, fmt.Errorf("parsercells: %w", err)
	}
	created := &windowsJob{handle: handle, limits: limits}
	readback, err := created.Readback()
	if err != nil {
		_ = created.Close()
		return nil, err
	}
	if err := limits.Verify(readback); err != nil {
		_ = created.Close()
		return nil, err
	}
	return created, nil
}

// Assign puts the process into the job. Failure is fatal for the cell because
// an unassigned process would not be covered by kill-on-close.
func (j *windowsJob) Assign(process syscall.Handle) error {
	if process == 0 || process == syscall.InvalidHandle {
		return errors.New("parsercells: job assign requires a process handle")
	}
	j.mu.Lock()
	handle := j.handle
	j.mu.Unlock()
	if handle == 0 {
		return errors.New("parsercells: job is closed")
	}
	result, _, callErr := procAssignProcessToJobObject.Call(uintptr(handle), uintptr(process))
	if result == 0 {
		err := errnoOrNil(callErr)
		if errors.Is(err, errorAccessDenied) {
			return &Error{Op: "job.assign", Kind: ErrIsolationNotVerified,
				Detail: "AssignProcessToJobObject denied (process already in an incompatible job)"}
		}
		return fmt.Errorf("parsercells: AssignProcessToJobObject: %w", err)
	}
	return nil
}

// IsProcessAssigned reads back job membership through the kernel.
func (j *windowsJob) IsProcessAssigned(process syscall.Handle) (bool, error) {
	j.mu.Lock()
	handle := j.handle
	j.mu.Unlock()
	if handle == 0 {
		return false, errors.New("parsercells: job is closed")
	}
	var assigned int32
	result, _, callErr := procIsProcessInJob.Call(uintptr(process), uintptr(handle), uintptr(unsafe.Pointer(&assigned)))
	if result == 0 {
		return false, fmt.Errorf("parsercells: IsProcessInJob: %w", errnoOrNil(callErr))
	}
	return assigned != 0, nil
}

// Readback queries the kernel for the effective job configuration.
func (j *windowsJob) Readback() (jobReadback, error) {
	j.mu.Lock()
	handle := j.handle
	j.mu.Unlock()
	if handle == 0 {
		return jobReadback{}, errors.New("parsercells: job is closed")
	}
	extended := joExtendedLimitInformation{}
	result, _, callErr := procQueryInformationJobObject.Call(
		uintptr(handle),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&extended)),
		unsafe.Sizeof(extended),
		0,
	)
	if result == 0 {
		return jobReadback{}, fmt.Errorf("parsercells: QueryInformationJobObject(extended): %w", errnoOrNil(callErr))
	}
	ui := joBasicUIRestrictions{}
	result, _, callErr = procQueryInformationJobObject.Call(
		uintptr(handle),
		uintptr(jobObjectBasicUIRestrictions),
		uintptr(unsafe.Pointer(&ui)),
		unsafe.Sizeof(ui),
		0,
	)
	if result == 0 {
		return jobReadback{}, fmt.Errorf("parsercells: QueryInformationJobObject(ui): %w", errnoOrNil(callErr))
	}
	accounting := joBasicAccountingInformation{}
	result, _, callErr = procQueryInformationJobObject.Call(
		uintptr(handle),
		uintptr(jobObjectBasicAccountingInformation),
		uintptr(unsafe.Pointer(&accounting)),
		unsafe.Sizeof(accounting),
		0,
	)
	if result == 0 {
		return jobReadback{}, fmt.Errorf("parsercells: QueryInformationJobObject(accounting): %w", errnoOrNil(callErr))
	}
	return jobReadback{
		LimitFlags:              extended.BasicLimitInformation.LimitFlags,
		ActiveProcessLimit:      extended.BasicLimitInformation.ActiveProcessLimit,
		JobMemoryLimit:          uint64(extended.JobMemoryLimit),
		PerProcessUserTimeLimit: extended.BasicLimitInformation.PerProcessUserTimeLimit,
		UIRestrictions:          ui.UIRestrictionsClass,
		ActiveProcesses:         accounting.ActiveProcesses,
		TotalProcesses:          accounting.TotalProcesses,
	}, nil
}

// MemberPIDs returns the bounded list of process IDs assigned to the job.
func (j *windowsJob) MemberPIDs(limit int) ([]uint32, error) {
	if limit <= 0 || limit > maxJobProcessIDs {
		return nil, fmt.Errorf("parsercells: process id limit %d outside (0,%d]", limit, maxJobProcessIDs)
	}
	j.mu.Lock()
	handle := j.handle
	j.mu.Unlock()
	if handle == 0 {
		return nil, errors.New("parsercells: job is closed")
	}
	list := joBasicProcessIDList{}
	result, _, callErr := procQueryInformationJobObject.Call(
		uintptr(handle),
		uintptr(jobObjectBasicProcessIDList),
		uintptr(unsafe.Pointer(&list)),
		unsafe.Sizeof(list),
		0,
	)
	if result == 0 {
		return nil, fmt.Errorf("parsercells: QueryInformationJobObject(process list): %w", errnoOrNil(callErr))
	}
	count := int(list.NumberOfProcessIDsInList)
	if count > maxJobProcessIDs {
		count = maxJobProcessIDs
	}
	if count > limit {
		count = limit
	}
	pids := make([]uint32, 0, count)
	for index := 0; index < count; index++ {
		pids = append(pids, uint32(list.ProcessIDList[index]))
	}
	return pids, nil
}

// Terminate is the burn primitive: it kills every process in the job and
// returns once the kernel accepted the request.
func (j *windowsJob) Terminate(exitCode uint32) error {
	j.mu.Lock()
	handle := j.handle
	j.mu.Unlock()
	if handle == 0 {
		return nil // already closed; nothing left to terminate
	}
	result, _, callErr := procTerminateJobObject.Call(uintptr(handle), uintptr(exitCode))
	if result == 0 {
		err := errnoOrNil(callErr)
		if errors.Is(err, errorInvalidHandle) {
			return nil
		}
		return fmt.Errorf("parsercells: TerminateJobObject: %w", err)
	}
	return nil
}

// Close releases the job handle. Kill-on-close guarantees that closing the last
// job handle terminates any surviving parser process.
func (j *windowsJob) Close() error {
	j.mu.Lock()
	handle := j.handle
	j.handle = 0
	j.mu.Unlock()
	if handle == 0 {
		return nil
	}
	return closeHandle(handle)
}

// platform adapter delegation.
func (p *windowsPlatform) NewJob(limits jobLimits) (job, error) {
	return newWindowsJob(limits)
}
