// STATUS: DIAMANT VGT SUPREME
//go:build windows

package service

import (
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

type Runner func(stop <-chan struct{}) error

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

	stateMu       sync.Mutex
	activeRunner  Runner
	activeName    string
	activeStop    chan struct{}
	stopOnce      sync.Once
	statusHandle  uintptr
	serviceMainCB = syscall.NewCallback(serviceMain)
	handlerCB     = syscall.NewCallback(serviceControlHandler)
)

func Run(name string, runner Runner) error {
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
	_ = setStatus(serviceStartPending, 0, 0, 3000)
	_ = setStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)
	runErr := runner(stop)
	exitCode := uint32(0)
	if runErr != nil {
		exitCode = 1
	}
	_ = setStatus(serviceStopped, 0, exitCode, 0)
	return 0
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
