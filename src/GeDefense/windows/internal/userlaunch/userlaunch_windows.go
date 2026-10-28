// STATUS: DIAMANT VGT SUPREME
//go:build windows

package userlaunch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// The relaunch relay is deliberately narrow: one validated, absolute
// .exe target plus at most a handful of small arguments. The Center, the tray
// and the installer only ever pass an empty argument list, so every bound here
// is far above the legitimate need while still fail-closed.
const (
	maxExecutableBytes = 1024
	maxArguments       = 8
	maxArgumentBytes   = 4096

	// The Windows environment block limit for CreateProcess is 32767 UTF-16
	// code units. The relay refuses to build an oversized block instead of
	// silently truncating it.
	maxEnvironmentUnits = 32767

	logonWithProfile         = 0x00000001
	createUnicodeEnvironment = 0x00000400
	createNewProcessGroup    = 0x00000200

	tokenAssignPrimary = 0x0001
	tokenDuplicate     = 0x0002
	tokenQuery         = 0x0008

	maximumAllowed        = 0x02000000
	securityImpersonation = 2
	tokenPrimary          = 1

	// explorerStartTimeout bounds only the Start call of the last-resort
	// explorer relay. It never waits for or kills the shell process.
	explorerStartTimeout = 10 * time.Second
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procGetShellWindow           = user32.NewProc("GetShellWindow")
	procGetWindowThreadProcessID = user32.NewProc("GetWindowThreadProcessId")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx         = advapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithTokenW  = advapi32.NewProc("CreateProcessWithTokenW")
)

// STARTUPINFOW from processthreadsapi.h. The x64 layout is reproduced exactly;
// the struct is only used as an in/out parameter for CreateProcessWithTokenW.
type startupInfoW struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	Reserved2     uint16
	Reserved2Ptr  *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdError      syscall.Handle
}

type processInformation struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessID uint32
	ThreadID  uint32
}

// IsElevated reports whether the current process token is elevated.
func IsElevated() bool {
	return winapi.IsProcessElevated()
}

// CommandLine validates the executable and renders it plus args as one Windows
// command line. Only an absolute, canonical .exe path is accepted; arguments are
// bounded and never flow through a shell interpreter. Quoting uses the standard
// library's Windows escaping so the result is parsed exactly like os/exec input.
func CommandLine(executable string, args []string) (string, error) {
	if err := validateExecutable(executable); err != nil {
		return "", err
	}
	if len(args) > maxArguments {
		return "", fmt.Errorf("userlaunch: more than %d arguments rejected", maxArguments)
	}
	var builder strings.Builder
	builder.Grow(len(executable) + 2 + len(args)*16)
	builder.WriteString(syscall.EscapeArg(executable))
	for index, argument := range args {
		if err := validateArgument(argument); err != nil {
			return "", fmt.Errorf("userlaunch: argument %d: %w", index, err)
		}
		builder.WriteByte(' ')
		builder.WriteString(syscall.EscapeArg(argument))
	}
	return builder.String(), nil
}

func validateExecutable(executable string) error {
	if executable == "" || len(executable) > maxExecutableBytes {
		return errors.New("userlaunch: executable path length rejected")
	}
	if strings.ContainsAny(executable, "\x00\r\n") {
		return errors.New("userlaunch: executable path contains control bytes")
	}
	if executable != filepath.Clean(executable) || !filepath.IsAbs(executable) || filepath.VolumeName(executable) == "" {
		return errors.New("userlaunch: executable path is not canonical and absolute")
	}
	if !strings.EqualFold(filepath.Ext(executable), ".exe") {
		return errors.New("userlaunch: executable is not a .exe file")
	}
	if strings.HasSuffix(executable, " ") || strings.HasSuffix(executable, ".") {
		return errors.New("userlaunch: executable path has an ambiguous Windows suffix")
	}
	for index, char := range executable {
		switch {
		case char < 0x20:
			return errors.New("userlaunch: executable path contains control characters")
		case char == '"' || char == '|' || char == '<' || char == '>' || char == '?' || char == '*':
			return errors.New("userlaunch: executable path contains reserved characters")
		case char == ':' && index != 1:
			return errors.New("userlaunch: executable path contains a reserved colon")
		}
	}
	return nil
}

func validateArgument(argument string) error {
	if len(argument) > maxArgumentBytes {
		return errors.New("length rejected")
	}
	if strings.ContainsAny(argument, "\x00\r\n") {
		return errors.New("control bytes rejected")
	}
	return nil
}

// LaunchAsShellUser starts executable as the unprivileged user that owns the
// interactive desktop shell. It is only legal for an elevated caller (the setup
// process or an escalated UI instance). The token path is mandatory unless no
// arguments are relayed, in which case the documented explorer fallback is used
// because the shell itself starts the target unprivileged.
func LaunchAsShellUser(executable string, args []string) error {
	if !IsElevated() {
		return errors.New("userlaunch: the current process is not elevated")
	}
	if _, err := CommandLine(executable, args); err != nil {
		return err
	}
	tokenErr := launchWithShellToken(executable, args)
	if tokenErr == nil {
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("userlaunch: shell-user launch failed: %w", tokenErr)
	}
	if fallbackErr := launchViaExplorer(executable); fallbackErr != nil {
		return errors.Join(fmt.Errorf("userlaunch: shell-user launch failed: %w", tokenErr), fallbackErr)
	}
	return nil
}

// RelaunchUnelevatedIfNeeded hands an elevated UI process over to the desktop
// shell user exactly once. The marker in the child's environment prevents a
// relaunch loop when an elevated process inherits it.
func RelaunchUnelevatedIfNeeded(executable string, args []string) (relaunched bool, err error) {
	if !ShouldRelaunchUnelevated(IsElevated(), os.Getenv(MarkerEnv)) {
		return false, nil
	}
	if err := LaunchAsShellUser(executable, args); err != nil {
		return false, err
	}
	return true, nil
}

// launchWithShellToken duplicates the shell process token into a primary token
// and uses CreateProcessWithTokenW. Every handle is closed on both paths; only
// the intermediate handles are best-effort (a close failure must never turn a
// successful launch into an error that would trigger a duplicate relaunch).
func launchWithShellToken(executable string, args []string) error {
	shellProcess, shellToken, primaryToken, err := shellPrimaryToken()
	if err != nil {
		return err
	}
	defer func() {
		winapi.ReportError("shell process handle close", winapi.CloseHandle(shellProcess))
	}()
	defer func() {
		winapi.ReportError("shell token handle close", winapi.CloseHandle(shellToken))
	}()
	defer func() {
		winapi.ReportError("primary token handle close", winapi.CloseHandle(primaryToken))
	}()

	environment, err := unprivilegedEnvironment()
	if err != nil {
		return err
	}
	commandLine, err := CommandLine(executable, args)
	if err != nil {
		return err
	}
	applicationName, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return fmt.Errorf("userlaunch: executable encoding: %w", err)
	}
	commandLinePointer, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return fmt.Errorf("userlaunch: command line encoding: %w", err)
	}
	var startup startupInfoW
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var created processInformation
	result, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(primaryToken),
		uintptr(logonWithProfile),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLinePointer)),
		uintptr(uint32(createUnicodeEnvironment|createNewProcessGroup)),
		uintptr(unsafe.Pointer(&environment[0])),
		0,
		uintptr(unsafe.Pointer(&startup)),
		uintptr(unsafe.Pointer(&created)),
	)
	processCloseErr := winapi.CloseHandle(winapi.Handle(created.Process))
	threadCloseErr := winapi.CloseHandle(winapi.Handle(created.Thread))
	if result == 0 {
		return errors.Join(
			fmt.Errorf("userlaunch: CreateProcessWithTokenW: %w", winapiError("CreateProcessWithTokenW", callErr)),
			processCloseErr,
			threadCloseErr,
		)
	}
	winapi.ReportError("shell-user process handle close", processCloseErr)
	winapi.ReportError("shell-user thread handle close", threadCloseErr)
	return nil
}

// shellPrimaryToken resolves the desktop shell process, opens its token and
// duplicates it into a primary token. All three handles are returned to the
// caller, which owns and closes them.
func shellPrimaryToken() (shellProcess, shellToken, primaryToken winapi.Handle, err error) {
	shellWindow, _, _ := procGetShellWindow.Call()
	if shellWindow == 0 {
		return 0, 0, 0, errors.New("userlaunch: desktop shell window unavailable")
	}
	var shellPID uint32
	thread, _, callErr := procGetWindowThreadProcessID.Call(shellWindow, uintptr(unsafe.Pointer(&shellPID)))
	if thread == 0 || shellPID == 0 {
		return 0, 0, 0, fmt.Errorf("userlaunch: desktop shell process id: %w", winapiError("GetWindowThreadProcessId", callErr))
	}
	process, _, callErr := procOpenProcess.Call(uintptr(winapi.ProcessQueryLimitedInformation), 0, uintptr(shellPID))
	if process == 0 {
		return 0, 0, 0, fmt.Errorf("userlaunch: OpenProcess: %w", winapiError("OpenProcess", callErr))
	}
	shellProcess = winapi.Handle(process)
	var token syscall.Handle
	opened, _, callErr := procOpenProcessToken.Call(
		uintptr(shellProcess),
		uintptr(tokenDuplicate|tokenQuery|tokenAssignPrimary),
		uintptr(unsafe.Pointer(&token)),
	)
	if opened == 0 || token == 0 {
		winapi.ReportError("shell process handle close", winapi.CloseHandle(shellProcess))
		return 0, 0, 0, fmt.Errorf("userlaunch: OpenProcessToken: %w", winapiError("OpenProcessToken", callErr))
	}
	shellToken = winapi.Handle(token)
	var duplicate syscall.Handle
	duplicated, _, callErr := procDuplicateTokenEx.Call(
		uintptr(shellToken),
		uintptr(maximumAllowed),
		0,
		uintptr(securityImpersonation),
		uintptr(tokenPrimary),
		uintptr(unsafe.Pointer(&duplicate)),
	)
	if duplicated == 0 || duplicate == 0 {
		winapi.ReportError("shell token handle close", winapi.CloseHandle(shellToken))
		winapi.ReportError("shell process handle close", winapi.CloseHandle(shellProcess))
		return 0, 0, 0, fmt.Errorf("userlaunch: DuplicateTokenEx: %w", winapiError("DuplicateTokenEx", callErr))
	}
	return shellProcess, shellToken, winapi.Handle(duplicate), nil
}

// unprivilegedEnvironment builds a sorted, double-NUL terminated UTF-16
// environment block from the elevated process environment, forcing the marker
// value to 1 and rejecting anything outside the CreateProcess bound.
func unprivilegedEnvironment() ([]uint16, error) {
	entries := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name := entry
		if separator := strings.IndexByte(entry, '='); separator > 0 {
			name = entry[:separator]
		}
		if strings.EqualFold(name, MarkerEnv) {
			continue
		}
		if entry == "" || strings.IndexByte(entry, 0) >= 0 {
			return nil, errors.New("userlaunch: environment entry rejected")
		}
		entries = append(entries, entry)
	}
	entries = append(entries, MarkerEnv+"=1")
	sort.Strings(entries)
	units := make([]uint16, 0, len(entries)*8)
	for _, entry := range entries {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("userlaunch: environment encoding: %w", err)
		}
		if len(units)+len(encoded)+1 > maxEnvironmentUnits {
			return nil, errors.New("userlaunch: environment block exceeds the Windows limit")
		}
		units = append(units, encoded...)
	}
	// Every entry already carries its terminating NUL; the additional zero
	// terminates the block itself (double NUL at the end).
	units = append(units, 0)
	return units, nil
}

// launchViaExplorer is the last-resort relay: the desktop shell (explorer.exe)
// starts the target with the unprivileged shell token. It never accepts
// arguments and never waits for or terminates the shell.
func launchViaExplorer(executable string) error {
	if err := validateExecutable(executable); err != nil {
		return err
	}
	windowsDirectory := os.Getenv("WINDIR")
	if !filepath.IsAbs(windowsDirectory) {
		windowsDirectory = os.Getenv("SystemRoot")
	}
	if !filepath.IsAbs(windowsDirectory) {
		return errors.New("userlaunch: Windows directory unavailable for explorer fallback")
	}
	explorer := filepath.Join(filepath.Clean(windowsDirectory), "explorer.exe")
	info, err := os.Lstat(explorer)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("userlaunch: explorer.exe unavailable for fallback")
	}
	command := exec.Command(explorer, executable)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	started := make(chan error, 1)
	go func() {
		if startErr := command.Start(); startErr != nil {
			started <- startErr
			return
		}
		started <- command.Process.Release()
	}()
	select {
	case startErr := <-started:
		if startErr != nil {
			return fmt.Errorf("userlaunch: explorer fallback: %w", startErr)
		}
		return nil
	case <-time.After(explorerStartTimeout):
		return errors.New("userlaunch: explorer fallback start timed out")
	}
}

// winapiError keeps a meaningful syscall error and replaces the zero errno that
// LazyProc.Call reports for successful calls.
func winapiError(operation string, callErr error) error {
	if callErr == nil {
		return fmt.Errorf("%s failed", operation)
	}
	var errno syscall.Errno
	if errors.As(callErr, &errno) && errno == 0 {
		return fmt.Errorf("%s failed", operation)
	}
	return callErr
}
