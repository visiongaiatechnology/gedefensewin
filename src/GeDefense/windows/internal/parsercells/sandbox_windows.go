// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Process-creation adapter. This is the third kernel boundary of a cell: the
// CreateProcess attribute block carries the AppContainer security capabilities,
// the process mitigation policy, the restricted child-process policy and an
// explicit inherit handle list. No shell is involved and the argument vector is
// passed as separate, quoted arguments.

// Process thread attribute identifiers (PROC_THREAD_ATTRIBUTE_*).
const (
	procThreadAttributeHandleList           uintptr = 0x00020002
	procThreadAttributeMitigationPolicy     uintptr = 0x00020007
	procThreadAttributeSecurityCapabilities uintptr = 0x00020009
	procThreadAttributeChildProcessPolicy   uintptr = 0x0002000E
)

// Process creation flags.
const (
	createSuspended            uint32 = 0x00000004
	createUnicodeEnvironment   uint32 = 0x00000400
	extendedStartupInfoPresent uint32 = 0x00080000
)

// STARTUPINFO flags.
const (
	startfUseStdHandles uint32 = 0x00000100
)

// PROCESS_MITIGATION_POLICY selectors used by GetProcessMitigationPolicy.
const (
	processDynamicCodePolicy       uint32 = 2
	processSystemCallDisablePolicy uint32 = 4
	processSignaturePolicy         uint32 = 8
	processFontDisablePolicy       uint32 = 9
	processImageLoadPolicy         uint32 = 10
	processChildProcessPolicy      uint32 = 13
)

// PROCESS_CREATION_CHILD_PROCESS_RESTRICTED.
const processCreationChildProcessRestricted uint32 = 0x00000001

// Mitigation policy bits (each policy is one bit in the 64-bit attribute value).
const (
	mitigationWin32kSystemCallDisable uint64 = 0x1 << 28
	mitigationProhibitDynamicCode     uint64 = 0x1 << 36
	mitigationBlockNonMicrosoftBinary uint64 = 0x1 << 44
	mitigationFontDisable             uint64 = 0x1 << 48
	mitigationImageLoadNoRemote       uint64 = 0x1 << 52
)

const (
	tokenQuery               uint32 = 0x0008
	tokenIsAppContainer      uint32 = 29
	tokenCapabilities        uint32 = 30
	tokenAppContainerSID     uint32 = 31
	maxTokenInformationBytes        = 64 << 10
)

var (
	procInitializeProcThreadAttrList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute    = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttribute    = kernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessW               = kernel32.NewProc("CreateProcessW")
	procResumeThread                 = kernel32.NewProc("ResumeThread")
	procWaitForSingleObject          = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeProcess           = kernel32.NewProc("GetExitCodeProcess")
	procGetProcessMitigationPolicy   = kernel32.NewProc("GetProcessMitigationPolicy")
	procOpenProcessToken             = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation          = advapi32.NewProc("GetTokenInformation")
	procCloseTokenHandle             = advapi32.NewProc("CloseHandle")
	procNtSuspendProcess             = ntdll.NewProc("NtSuspendProcess")
)

// securityCapabilities mirrors SECURITY_CAPABILITIES. Capabilities is nil and
// CapabilityCount is zero: that is the kernel network lock.
type securityCapabilities struct {
	AppContainerSID uintptr
	Capabilities    uintptr
	CapabilityCount uint32
	Reserved        uint32
}

// startupInfoEx mirrors STARTUPINFOEXW. It must be passed to CreateProcessW as a
// pointer to the embedded STARTUPINFOW plus the trailing attribute list.
type startupInfoEx struct {
	StartupInfo   syscall.StartupInfo
	AttributeList uintptr
}

// launchSpec is the validated spawn request handed to the launcher.
type launchSpec struct {
	Executable   string
	Args         []string
	ContainerSID string
	Input        syscall.Handle
	Output       syscall.Handle
}

// launchedProcess is the suspended process returned by the launcher. The cell
// owns all three handles until it verifies isolation and resumes the thread.
type launchedProcess struct {
	Process syscall.Handle
	Thread  syscall.Handle
	PID     uint32
}

// processLauncher is the injectable process-creation adapter.
type processLauncher interface {
	Launch(spec launchSpec) (launchedProcess, error)
	VerifyContainerToken(process syscall.Handle, expectedSID string) error
	VerifyMitigations(process syscall.Handle) ([]string, error)
	ResumeThread(thread syscall.Handle) error
	SuspendProcess(process syscall.Handle) error
}

// mitigationVerifier describes one read-back check.
type mitigationVerifier struct {
	Name         string
	Policy       uint32
	RequiredMask uint32
}

// mitigationVerificationPlan returns the read-back plan for the process
// mitigations requested at creation time. It is returned as a fresh slice so no
// mutable package state exists.
func mitigationVerificationPlan() []mitigationVerifier {
	return []mitigationVerifier{
		{Name: MitigationWin32kSystemCallDisable, Policy: processSystemCallDisablePolicy, RequiredMask: 0x1},
		{Name: MitigationFontDisable, Policy: processFontDisablePolicy, RequiredMask: 0x1},
		{Name: MitigationProhibitDynamicCode, Policy: processDynamicCodePolicy, RequiredMask: 0x1},
		{Name: MitigationBlockNonMicrosoftBinaries, Policy: processSignaturePolicy, RequiredMask: 0x1},
		{Name: MitigationImageLoadNoRemote, Policy: processImageLoadPolicy, RequiredMask: 0x1},
		{Name: MitigationChildProcessRestricted, Policy: processChildProcessPolicy, RequiredMask: 0x1},
	}
}

// mitigationPolicyValue returns the 64-bit PROCESS_CREATION_MITIGATION_POLICY
// value requested at creation time.
func mitigationPolicyValue() uint64 {
	return mitigationWin32kSystemCallDisable |
		mitigationFontDisable |
		mitigationProhibitDynamicCode |
		mitigationBlockNonMicrosoftBinary |
		mitigationImageLoadNoRemote
}

// windowsSandbox is the production process-creation adapter.
type windowsSandbox struct{}

// Launch creates a suspended process inside the AppContainer with every
// requested mitigation and exactly two inherited handles (input, output).
func (windowsSandbox) Launch(spec launchSpec) (launchedProcess, error) {
	if len(spec.Executable) == 0 || len(spec.Executable) > maxStagingPathChars {
		return launchedProcess{}, errors.New("parsercells: launch requires a bounded executable path")
	}
	if !strings.HasSuffix(strings.ToLower(spec.Executable), ".exe") {
		return launchedProcess{}, &Error{Op: "sandbox.launch", Kind: ErrIsolationNotVerified,
			Detail: "executable path does not name a .exe file"}
	}
	if spec.Input == 0 || spec.Output == 0 || spec.Input == syscall.InvalidHandle || spec.Output == syscall.InvalidHandle {
		return launchedProcess{}, errors.New("parsercells: launch requires inherited input and output handles")
	}
	sidPointer, err := sidFromString(spec.ContainerSID)
	if err != nil {
		return launchedProcess{}, fmt.Errorf("parsercells: container SID: %w", err)
	}
	defer freeSID(sidPointer)

	applicationName, err := utf16Ptr(spec.Executable)
	if err != nil {
		return launchedProcess{}, fmt.Errorf("parsercells: executable path: %w", err)
	}
	commandLine, err := buildCommandLine(spec.Executable, spec.Args)
	if err != nil {
		return launchedProcess{}, err
	}
	environment, err := buildEnvironment()
	if err != nil {
		return launchedProcess{}, err
	}

	capabilities := securityCapabilities{AppContainerSID: sidPointer}
	mitigationPolicy := mitigationPolicyValue()
	childPolicy := processCreationChildProcessRestricted
	inheritedHandles := [2]uintptr{uintptr(spec.Input), uintptr(spec.Output)}

	attributeList, attributeBuffer, err := newAttributeList(4)
	if err != nil {
		return launchedProcess{}, err
	}
	defer deleteAttributeList(attributeList)
	if err := updateAttribute(attributeList, procThreadAttributeSecurityCapabilities,
		unsafe.Pointer(&capabilities), unsafe.Sizeof(capabilities)); err != nil {
		return launchedProcess{}, err
	}
	if err := updateAttribute(attributeList, procThreadAttributeMitigationPolicy,
		unsafe.Pointer(&mitigationPolicy), unsafe.Sizeof(mitigationPolicy)); err != nil {
		return launchedProcess{}, err
	}
	if err := updateAttribute(attributeList, procThreadAttributeChildProcessPolicy,
		unsafe.Pointer(&childPolicy), unsafe.Sizeof(childPolicy)); err != nil {
		return launchedProcess{}, err
	}
	if err := updateAttribute(attributeList, procThreadAttributeHandleList,
		unsafe.Pointer(&inheritedHandles[0]), unsafe.Sizeof(inheritedHandles)); err != nil {
		return launchedProcess{}, err
	}

	startup := startupInfoEx{}
	startup.StartupInfo.Cb = uint32(unsafe.Sizeof(startup))
	startup.StartupInfo.Flags = startfUseStdHandles
	startup.StartupInfo.StdInput = spec.Input
	startup.StartupInfo.StdOutput = spec.Output
	startup.StartupInfo.StdErr = spec.Output
	startup.AttributeList = attributeList

	var processInfo syscall.ProcessInformation
	if len(commandLine) == 0 || len(environment) == 0 {
		return launchedProcess{}, errors.New("parsercells: empty command line or environment block")
	}
	result, _, callErr := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(&commandLine[0])),
		0, // process security attributes: none
		0, // thread security attributes: none
		1, // inherit handles (restricted by the handle list)
		uintptr(createSuspended|createUnicodeEnvironment|extendedStartupInfoPresent),
		uintptr(unsafe.Pointer(&environment[0])),
		0, // current directory: inherit
		uintptr(unsafe.Pointer(&startup)),
		uintptr(unsafe.Pointer(&processInfo)),
	)
	if err := checkBOOL("CreateProcessW", result, callErr); err != nil {
		return launchedProcess{}, fmt.Errorf("parsercells: %w", err)
	}
	// Keep the attribute payloads alive until CreateProcessW has consumed them.
	runtime.KeepAlive(&capabilities)
	runtime.KeepAlive(&mitigationPolicy)
	runtime.KeepAlive(&childPolicy)
	runtime.KeepAlive(&inheritedHandles)
	runtime.KeepAlive(attributeBuffer)
	if processInfo.Process == 0 || processInfo.Thread == 0 {
		_ = closeHandle(processInfo.Process)
		_ = closeHandle(processInfo.Thread)
		return launchedProcess{}, errors.New("parsercells: CreateProcessW returned empty handles")
	}
	return launchedProcess{Process: processInfo.Process, Thread: processInfo.Thread, PID: processInfo.ProcessId}, nil
}

// VerifyContainerToken opens the process token and proves that the process is an
// AppContainer whose AppContainer SID equals the created profile SID and whose
// capability list is empty.
func (windowsSandbox) VerifyContainerToken(process syscall.Handle, expectedSID string) error {
	var token syscall.Handle
	result, _, callErr := procOpenProcessToken.Call(uintptr(process), uintptr(tokenQuery), uintptr(unsafe.Pointer(&token)))
	if err := checkBOOL("OpenProcessToken", result, callErr); err != nil {
		return fmt.Errorf("parsercells: container token verification: %w", err)
	}
	defer func() { _ = closeHandle(token) }()

	var isAppContainer uint32
	var returned uint32
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenIsAppContainer),
		uintptr(unsafe.Pointer(&isAppContainer)), unsafe.Sizeof(isAppContainer),
		uintptr(unsafe.Pointer(&returned)),
	)
	if err := checkBOOL("GetTokenInformation(TokenIsAppContainer)", result, callErr); err != nil {
		return fmt.Errorf("parsercells: %w", err)
	}
	if isAppContainer == 0 {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: "process token is not an AppContainer token"}
	}

	var sidBufferSize uint32
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenAppContainerSID),
		0, 0, uintptr(unsafe.Pointer(&sidBufferSize)),
	)
	if result != 0 {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: "appcontainer SID size query unexpectedly succeeded"}
	}
	if err := errnoOrNil(callErr); !errors.Is(err, errorInsufficientBuffer) {
		return fmt.Errorf("parsercells: GetTokenInformation(TokenAppContainerSid) size query: %w", err)
	}
	if sidBufferSize < uint32(unsafe.Sizeof(uintptr(0))) || sidBufferSize > maxTokenInformationBytes {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("appcontainer SID buffer size %d outside bounds", sidBufferSize)}
	}
	sidBuffer := make([]byte, sidBufferSize)
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenAppContainerSID),
		uintptr(unsafe.Pointer(&sidBuffer[0])), uintptr(sidBufferSize),
		uintptr(unsafe.Pointer(&returned)),
	)
	if err := checkBOOL("GetTokenInformation(TokenAppContainerSid)", result, callErr); err != nil {
		return fmt.Errorf("parsercells: %w", err)
	}
	sidPointer := *(*uintptr)(unsafe.Pointer(&sidBuffer[0]))
	if returned < uint32(unsafe.Sizeof(sidPointer)) || sidPointer == 0 {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: "appcontainer SID read-back returned no SID"}
	}
	actualSID, err := sidToString(sidPointer)
	runtime.KeepAlive(sidBuffer)
	if err != nil {
		return fmt.Errorf("parsercells: appcontainer SID conversion: %w", err)
	}
	if actualSID != expectedSID {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: "process AppContainer SID does not match the created profile"}
	}
	if err := verifyEmptyCapabilities(token); err != nil {
		return err
	}
	return nil
}

// verifyEmptyCapabilities proves that the token carries zero capabilities. This
// is what makes the AppContainer network block a kernel property instead of an
// assumption: internetClient would appear here.
func verifyEmptyCapabilities(token syscall.Handle) error {
	var required uint32
	result, _, callErr := procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenCapabilities),
		0, 0, uintptr(unsafe.Pointer(&required)),
	)
	if result != 0 {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: "capability size query unexpectedly succeeded"}
	}
	if err := errnoOrNil(callErr); !errors.Is(err, errorInsufficientBuffer) {
		return fmt.Errorf("parsercells: GetTokenInformation(TokenCapabilities) size query: %w", err)
	}
	if required == 0 || required > maxTokenInformationBytes {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("capability buffer size %d outside (0,%d]", required, maxTokenInformationBytes)}
	}
	buffer := make([]byte, required)
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token), uintptr(tokenCapabilities),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(required), uintptr(unsafe.Pointer(&required)),
	)
	if err := checkBOOL("GetTokenInformation(TokenCapabilities)", result, callErr); err != nil {
		return fmt.Errorf("parsercells: %w", err)
	}
	if len(buffer) < 4 {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified, Detail: "capability buffer too small"}
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	if count != 0 {
		return &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
			Detail: fmt.Sprintf("token carries %d capabilities, expected 0 (network lock)", count)}
	}
	return nil
}

// VerifyMitigations reads every requested mitigation back from the live
// (suspended) process. An unreadable policy fails closed.
func (windowsSandbox) VerifyMitigations(process syscall.Handle) ([]string, error) {
	verified := make([]string, 0, len(mitigationVerificationPlan()))
	for _, verifier := range mitigationVerificationPlan() {
		var value uint32
		result, _, callErr := procGetProcessMitigationPolicy.Call(
			uintptr(process), uintptr(verifier.Policy),
			uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value),
		)
		if result == 0 {
			err := errnoOrNil(callErr)
			if errors.Is(err, errorInvalidParameter) || errors.Is(err, errorNotSupported) {
				return nil, &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
					Detail: fmt.Sprintf("mitigation %s cannot be read back on this build (NOT_IMPLEMENTED by kernel)", verifier.Name)}
			}
			return nil, fmt.Errorf("parsercells: GetProcessMitigationPolicy(%s): %w", verifier.Name, err)
		}
		if value&verifier.RequiredMask != verifier.RequiredMask {
			return nil, &Error{Op: "sandbox.verify", Kind: ErrIsolationNotVerified,
				Detail: fmt.Sprintf("mitigation %s read-back 0x%08x missing mask 0x%08x", verifier.Name, value, verifier.RequiredMask)}
		}
		verified = append(verified, verifier.Name)
	}
	return verified, nil
}

// ResumeThread releases the primary thread of the verified suspended process.
func (windowsSandbox) ResumeThread(thread syscall.Handle) error {
	result, _, callErr := procResumeThread.Call(uintptr(thread))
	if uint32(result) == 0xFFFFFFFF {
		return fmt.Errorf("parsercells: ResumeThread: %w", errnoOrNil(callErr))
	}
	return nil
}

// SuspendProcess freezes the parser through NtSuspendProcess (documented as
// unsupported but stable and used by every endpoint security product).
func (windowsSandbox) SuspendProcess(process syscall.Handle) error {
	if process == 0 || process == syscall.InvalidHandle {
		return errors.New("parsercells: suspend requires a process handle")
	}
	status, _, _ := procNtSuspendProcess.Call(uintptr(process))
	if int32(uint32(status)) < 0 {
		return fmt.Errorf("parsercells: NtSuspendProcess failed (NTSTATUS 0x%08X)", uint32(status))
	}
	return nil
}

// WaitProcess waits for process termination up to timeout and returns the exit
// code. A timeout is reported, not treated as an API error.
func (windowsSandbox) WaitProcess(process syscall.Handle, timeout time.Duration) (exitCode uint32, timedOut bool, err error) {
	milliseconds := uint32(0xFFFFFFFF)
	if timeout > 0 {
		value := timeout / time.Millisecond
		if value <= 0 {
			value = 1
		}
		if value >= 0xFFFFFFFE {
			value = 0xFFFFFFFE
		}
		milliseconds = uint32(value)
	}
	result, _, callErr := procWaitForSingleObject.Call(uintptr(process), uintptr(milliseconds))
	switch uint32(result) {
	case 0x00000000: // WAIT_OBJECT_0
	case 0x00000102: // WAIT_TIMEOUT
		return 0, true, nil
	default:
		return 0, false, fmt.Errorf("parsercells: WaitForSingleObject: %w", errnoOrNil(callErr))
	}
	var code uint32
	result, _, callErr = procGetExitCodeProcess.Call(uintptr(process), uintptr(unsafe.Pointer(&code)))
	if err := checkBOOL("GetExitCodeProcess", result, callErr); err != nil {
		return 0, false, fmt.Errorf("parsercells: %w", err)
	}
	return code, false, nil
}

// newAttributeList allocates a PROC_THREAD_ATTRIBUTE_LIST for count attributes.
// The backing slice is returned so the caller can keep it alive until the list
// and the CreateProcessW call are finished.
func newAttributeList(count uint32) (uintptr, []byte, error) {
	if count == 0 || count > 32 {
		return 0, nil, fmt.Errorf("parsercells: attribute count %d outside (0,32]", count)
	}
	var size uintptr
	result, _, callErr := procInitializeProcThreadAttrList.Call(0, uintptr(count), 0, uintptr(unsafe.Pointer(&size)))
	if result != 0 {
		return 0, nil, errors.New("parsercells: InitializeProcThreadAttributeList size query unexpectedly succeeded")
	}
	if err := errnoOrNil(callErr); !errors.Is(err, errorInsufficientBuffer) {
		return 0, nil, fmt.Errorf("parsercells: InitializeProcThreadAttributeList size query: %w", err)
	}
	if size == 0 || size > 64<<10 {
		return 0, nil, fmt.Errorf("parsercells: attribute list size %d outside (0,65536]", size)
	}
	buffer := make([]byte, size)
	result, _, callErr = procInitializeProcThreadAttrList.Call(
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(count), 0, uintptr(unsafe.Pointer(&size)),
	)
	if err := checkBOOL("InitializeProcThreadAttributeList", result, callErr); err != nil {
		return 0, nil, fmt.Errorf("parsercells: %w", err)
	}
	return uintptr(unsafe.Pointer(&buffer[0])), buffer, nil
}

// deleteAttributeList releases an attribute list allocated by newAttributeList.
func deleteAttributeList(list uintptr) {
	if list != 0 {
		_, _, _ = procDeleteProcThreadAttribute.Call(list)
	}
}

// updateAttribute sets one attribute on the list.
func updateAttribute(list uintptr, attribute uintptr, value unsafe.Pointer, size uintptr) error {
	result, _, callErr := procUpdateProcThreadAttribute.Call(
		list, 0, attribute, uintptr(value), size, 0, 0,
	)
	if err := checkBOOL("UpdateProcThreadAttribute", result, callErr); err != nil {
		return fmt.Errorf("parsercells: attribute 0x%08x: %w", attribute, err)
	}
	return nil
}

// buildCommandLine builds a quoted command line with the executable as argv[0].
func buildCommandLine(executable string, args []string) ([]uint16, error) {
	if len(args) > 64 {
		return nil, errors.New("parsercells: argument count exceeds 64")
	}
	var builder strings.Builder
	builder.WriteString(quoteWindowsArgument(executable))
	for _, argument := range args {
		if len(argument) > 4096 {
			return nil, errors.New("parsercells: single argument exceeds 4096 characters")
		}
		builder.WriteByte(' ')
		builder.WriteString(quoteWindowsArgument(argument))
	}
	if builder.Len() == 0 || builder.Len() > 32767 {
		return nil, fmt.Errorf("parsercells: command line length %d outside (0,32767]", builder.Len())
	}
	encoded, err := syscall.UTF16FromString(builder.String())
	if err != nil {
		return nil, fmt.Errorf("parsercells: command line encoding: %w", err)
	}
	return encoded, nil
}

// quoteWindowsArgument applies the documented CommandLineToArgvW quoting rules.
func quoteWindowsArgument(argument string) string {
	if argument != "" && !strings.ContainsAny(argument, " \t\n\v\"") {
		return argument
	}
	var builder strings.Builder
	builder.WriteByte('"')
	backslashes := 0
	for _, character := range argument {
		switch character {
		case '\\':
			backslashes++
			continue
		case '"':
			builder.WriteString(strings.Repeat(`\`, backslashes*2+1))
			builder.WriteByte('"')
			backslashes = 0
		default:
			if backslashes > 0 {
				builder.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
			}
			builder.WriteRune(character)
		}
	}
	if backslashes > 0 {
		builder.WriteString(strings.Repeat(`\`, backslashes*2))
	}
	builder.WriteByte('"')
	return builder.String()
}

// buildEnvironment builds a minimal UTF-16 environment block. Only LOCALAPPDATA
// (required by CreateProcessInternalW for AppContainer environment setup),
// SystemRoot and windir are provided; no user paths, credentials or writable
// temp directories are inherited.
func buildEnvironment() ([]uint16, error) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return nil, errors.New("parsercells: SystemRoot is not set")
	}
	if len(systemRoot) > 260 {
		return nil, errors.New("parsercells: SystemRoot is out of bounds")
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" || len(localAppData) > 260 {
		localAppData = strings.TrimRight(systemRoot, `\/`) + `\System32\config\systemprofile\AppData\Local`
	}
	entries := []string{
		"LOCALAPPDATA=" + localAppData,
		"SystemRoot=" + systemRoot,
		"windir=" + systemRoot,
	}
	block := make([]uint16, 0, 128)
	for _, entry := range entries {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("parsercells: environment encoding: %w", err)
		}
		block = append(block, encoded...)
	}
	block = append(block, 0)
	return block, nil
}

// platform adapter delegation.
func (p *windowsPlatform) Launch(spec launchSpec) (launchedProcess, error) {
	return windowsSandbox{}.Launch(spec)
}

func (p *windowsPlatform) VerifyContainerToken(process syscall.Handle, expectedSID string) error {
	return windowsSandbox{}.VerifyContainerToken(process, expectedSID)
}

func (p *windowsPlatform) VerifyMitigations(process syscall.Handle) ([]string, error) {
	return windowsSandbox{}.VerifyMitigations(process)
}

func (p *windowsPlatform) ResumeThread(thread syscall.Handle) error {
	return windowsSandbox{}.ResumeThread(thread)
}

func (p *windowsPlatform) SuspendProcess(process syscall.Handle) error {
	return windowsSandbox{}.SuspendProcess(process)
}

func (p *windowsPlatform) WaitProcess(process syscall.Handle, timeout time.Duration) (uint32, bool, error) {
	return windowsSandbox{}.WaitProcess(process, timeout)
}
