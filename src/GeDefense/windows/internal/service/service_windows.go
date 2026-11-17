// STATUS: DIAMANT VGT SUPREME
//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Runner func(stop <-chan struct{}) error
type ReadyRunner func(stop <-chan struct{}, ready func()) error

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

const (
	serviceWin32OwnProcess = 0x00000010
	serviceStopped         = 0x00000001
	serviceStartPending    = 0x00000002
	serviceStopPending     = 0x00000003
	serviceRunning         = 0x00000004

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005

	errorFailedServiceControllerConnect syscall.Errno = 1063
)

var (
	advapi32                       = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcher = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandler = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus           = advapi32.NewProc("SetServiceStatus")
	procRegisterEventSource        = advapi32.NewProc("RegisterEventSourceW")
	procDeregisterEventSource      = advapi32.NewProc("DeregisterEventSource")
	procReportEvent                = advapi32.NewProc("ReportEventW")

	stateMu       sync.Mutex
	activeRunner  ReadyRunner
	activeName    string
	activeStop    chan struct{}
	stopOnce      sync.Once
	statusHandle  uintptr
	serviceMainCB = syscall.NewCallback(serviceMain)
	handlerCB     = syscall.NewCallback(serviceControlHandler)
)

func Run(name string, runner Runner) error {
	if runner == nil {
		return errors.New("invalid Windows service configuration")
	}
	return RunWithReady(name, func(stop <-chan struct{}, ready func()) error {
		if ready != nil {
			ready()
		}
		return runner(stop)
	})
}

// RunWithReady keeps Windows SCM in SERVICE_START_PENDING (with periodic
// CheckPoint heartbeats) until the runner invokes ready after binding its
// control-plane listener.
func RunWithReady(name string, runner ReadyRunner) error {
	if name == "" || runner == nil {
		return errors.New("invalid Windows service configuration")
	}
	stateMu.Lock()
	activeRunner = runner
	activeName = name
	activeStop = make(chan struct{})
	stopOnce = sync.Once{}
	statusHandle = 0
	stateMu.Unlock()

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	table := [2]serviceTableEntry{{Name: namePtr, Proc: serviceMainCB}, {}}
	result, _, callErr := procStartServiceCtrlDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if result == 0 {
		if errors.Is(callErr, errorFailedServiceControllerConnect) {
			return errors.New("not running under the Windows Service Control Manager; use --console")
		}
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			return errno
		}
		return errors.New("StartServiceCtrlDispatcherW failed")
	}
	return nil
}

func serviceMain(_ uintptr, _ uintptr) uintptr {
	stateMu.Lock()
	name := activeName
	runner := activeRunner
	stop := activeStop
	stateMu.Unlock()
	if runner == nil || stop == nil {
		return 0
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	handle, _, _ := procRegisterServiceCtrlHandler.Call(uintptr(unsafe.Pointer(namePtr)), handlerCB, 0)
	if handle == 0 {
		return 0
	}
	stateMu.Lock()
	statusHandle = handle
	stateMu.Unlock()
	_ = setStatusWithCheckpoint(serviceStartPending, 0, 0, 1, 15000)

	readyDone := make(chan struct{})
	var readyOnce sync.Once
	markReady := func() {
		readyOnce.Do(func() {
			close(readyDone)
			_ = setStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)
		})
	}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		checkpoint := uint32(2)
		for {
			select {
			case <-readyDone:
				return
			case <-stop:
				return
			case <-ticker.C:
				_ = setStatusWithCheckpoint(serviceStartPending, 0, 0, checkpoint, 15000)
				checkpoint++
			}
		}
	}()

	runErr := func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("service panic: %v", recovered)
			}
		}()
		return runner(stop, markReady)
	}()
	readyOnce.Do(func() { close(readyDone) })
	<-heartbeatDone
	exitCode := uint32(0)
	if runErr != nil {
		exitCode = 1
		reportServiceFailure(name, runErr)
	}
	_ = setStatus(serviceStopped, 0, exitCode, 0)
	return 0
}

func reportServiceFailure(serviceName string, err error) {
	if err == nil {
		return
	}
	msg := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	writeServiceErrorFile(serviceName, msg)
	writeServiceEventLog(serviceName, fmt.Sprintf("%s failed: %s", serviceName, msg))
}

func writeServiceErrorFile(serviceName, msg string) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return
	}
	dataRoot := filepath.Join(programData, "VGT", "GeDefense")
	if info, err := os.Lstat(dataRoot); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	logPath := filepath.Join(dataRoot, "service-error.log")
	if info, err := os.Lstat(logPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return
		}
		if info.Size() > 64<<10 {
			_ = os.Remove(logPath)
		}
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s|%s|FAILED|%s\n", time.Now().UTC().Format(time.RFC3339Nano), serviceName, msg)
}

func writeServiceEventLog(source, message string) {
	srcPtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return
	}
	handle, _, _ := procRegisterEventSource.Call(0, uintptr(unsafe.Pointer(srcPtr)))
	if handle == 0 {
		return
	}
	defer func() { _, _, _ = procDeregisterEventSource.Call(handle) }()
	msgPtr, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return
	}
	ptrs := [1]*uint16{msgPtr}
	const eventLogErrorType = 0x0001
	_, _, _ = procReportEvent.Call(
		handle,
		eventLogErrorType,
		0,
		1,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ptrs[0])),
		0,
	)
}

func serviceControlHandler(control uintptr, _ uintptr, _ uintptr, _ uintptr) uintptr {
	switch uint32(control) {
	case serviceControlStop, serviceControlShutdown:
		_ = setStatus(serviceStopPending, 0, 0, 5000)
		stateMu.Lock()
		stop := activeStop
		stateMu.Unlock()
		if stop != nil {
			stopOnce.Do(func() { close(stop) })
		}
	case serviceControlInterrogate:
		// SCM receives the most recently published state. No mutation required.
	}
	return 0
}

func setStatus(state, accepts, exitCode, waitHint uint32) error {
	return setStatusWithCheckpoint(state, accepts, exitCode, 0, waitHint)
}

func setStatusWithCheckpoint(state, accepts, exitCode, checkpoint, waitHint uint32) error {
	stateMu.Lock()
	handle := statusHandle
	stateMu.Unlock()
	if handle == 0 {
		return errors.New("service status handle unavailable")
	}
	status := serviceStatus{
		ServiceType:      serviceWin32OwnProcess,
		CurrentState:     state,
		ControlsAccepted: accepts,
		Win32ExitCode:    exitCode,
		CheckPoint:       checkpoint,
		WaitHint:         waitHint,
	}
	result, _, callErr := procSetServiceStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			return errno
		}
		return errors.New("SetServiceStatus failed")
	}
	return nil
}

func RunConsole(runner Runner) error {
	if runner == nil {
		return errors.New("runner is required")
	}
	stop := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		close(stop)
	}()
	return runner(stop)
}
