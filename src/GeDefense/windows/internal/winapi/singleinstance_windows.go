// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// utf16CharSize is the byte width of one UTF-16 code unit on Windows.
const utf16CharSize = 2

// Single-instance hardening for the operator UI (HP-FIND-005).
//
// The tray and center previously treated "named mutex already exists" as
// "GeDefense is already running", so a standard user process in the same
// session could suppress the operator UI by creating the well-known object
// first. The hardened helpers below:
//
//   - create the objects with an explicit restrictive DACL (SYSTEM,
//     Administrators and the creating user only) instead of the default DACL,
//   - verify that a pre-existing object carries exactly that DACL and report
//     objects created by other software as tampered,
//   - never accept a foreign object as authority: a bounded takeover restores
//     the product DACL or deletes and recreates the object, and the claim
//     fails closed with ErrSingleInstanceTakeover when neither is possible,
//   - and no longer treat object existence as the authority for suppressing
//     the UI: ResolveSingleInstance only delegates to another instance when a
//     live GeDefense window is actually present.
//
// Local\ namespace objects stay per session: the tray and center are per
// user-session UI, a Global\ namespace would expose the names to other
// sessions, and every additional slot in which an object can be pre-created
// is additional attack surface. Residual, explicitly accepted session
// boundary: a same-user process in the same session can still spoof the tray
// window class or terminate the user-level UI process, because user-level UI
// availability cannot be defended against an equal-privilege attacker. Closing
// that gap requires the SYSTEM service to become the UI single-instance
// authority (out of scope of the local hardening).

const (
	seKernelObject          = 6
	daclSecurityInformation = 0x00000004
	sddlRevision1           = 1
	tokenUser               = 1
)

// Bounded takeover of a pre-created single-instance object. The attempts are a
// fixed count with a short fixed backoff, so an attacker that holds the object
// can delay the decision by at most singleInstanceTakeoverAttempts *
// singleInstanceTakeoverBackoff; the decision itself never blocks indefinitely.
const (
	singleInstanceTakeoverAttempts = 3
	singleInstanceTakeoverBackoff  = 25 * time.Millisecond
)

// ErrSingleInstanceTakeover reports a pre-existing foreign single-instance
// object that could neither be replaced nor brought under the product DACL.
// The claim fails closed: callers must raise an integrity event instead of
// accepting the foreign object as a running-instance authority.
var ErrSingleInstanceTakeover = errors.New("single-instance object takeover failed")

// singleInstanceSDDL grants full control only to LocalSystem, the local
// Administrators group and the object owner. It never grants Everyone or
// Authenticated Users.
const singleInstanceSDDL = `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)`

// singleInstanceSpecificAllAccess is the object-type-specific expansion of
// GENERIC_ALL that the kernel stores in the DACL. A DACL read back from the
// object is compared against these concrete rights.
var singleInstanceSpecificAllAccess = map[string]uint32{
	"mutex": 0x001F0001, // MUTEX_ALL_ACCESS
	"event": 0x001F0003, // EVENT_ALL_ACCESS
}

type securityAttributes struct {
	length        uint32
	descriptor    unsafe.Pointer
	inheritHandle int32
}

var (
	advapi32SingleInstance = syscall.NewLazyDLL("advapi32.dll")
	kernel32SingleInstance = syscall.NewLazyDLL("kernel32.dll")

	procCreateMutexSingleInstance   = kernel32SingleInstance.NewProc("CreateMutexW")
	procCreateEventSingleInstance   = kernel32SingleInstance.NewProc("CreateEventW")
	procOpenMutexSingleInstance     = kernel32SingleInstance.NewProc("OpenMutexW")
	procOpenEventSingleInstance     = kernel32SingleInstance.NewProc("OpenEventW")
	procLocalFreeSingleInstance     = kernel32SingleInstance.NewProc("LocalFree")
	procGetCurrentProcessIDSingle   = kernel32SingleInstance.NewProc("GetCurrentProcessId")
	procProcessIDToSessionIDSingle  = kernel32SingleInstance.NewProc("ProcessIdToSessionId")
	procConvertSDDLToSDSingle       = advapi32SingleInstance.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procConvertSDToSDDLSingle       = advapi32SingleInstance.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	procGetSecurityInfoSingle       = advapi32SingleInstance.NewProc("GetSecurityInfo")
	procSetSecurityInfoSingle       = advapi32SingleInstance.NewProc("SetSecurityInfo")
	procGetSDDaclSingle             = advapi32SingleInstance.NewProc("GetSecurityDescriptorDacl")
	procConvertSIDToStringSIDSingle = advapi32SingleInstance.NewProc("ConvertSidToStringSidW")
	procGetTokenInformationSingle   = advapi32SingleInstance.NewProc("GetTokenInformation")
)

// SingleInstanceClaim describes the outcome of creating or attaching to a
// named single-instance object.
type SingleInstanceClaim struct {
	Kind    string // "mutex" or "event"
	Name    string
	Handle  Handle
	Existed bool
	// Trusted is true when the claimed object carries the product-specific
	// restrictive DACL. A freshly created object is trusted by construction; a
	// foreign object becomes trusted only after a successful bounded takeover.
	Trusted bool
	// TakenOver is true when a pre-existing foreign object was replaced by a
	// fresh product object or had its DACL restored to the product DACL during
	// this claim. It is the evidence that a pre-creation attempt was countered.
	TakenOver bool
}

// Close releases the claim handle.
func (claim *SingleInstanceClaim) Close() error {
	if claim == nil || claim.Handle == 0 {
		return nil
	}
	err := CloseHandle(claim.Handle)
	claim.Handle = 0
	return err
}

// SingleInstanceObjectName builds the Local\ object name for a UI component.
// The user/session token keeps objects bound to the current interactive
// identity instead of a well-known, machine-wide name.
func SingleInstanceObjectName(component string) (string, error) {
	if err := ValidateSingleInstanceComponent(component); err != nil {
		return "", err
	}
	token, err := currentSessionIdentityToken()
	if err != nil {
		return "", err
	}
	return `Local\VGT.GeDefense.` + component + `.` + token, nil
}

// ValidateSingleInstanceComponent rejects components that could escape the
// object namespace or exceed the Windows object name boundary.
func ValidateSingleInstanceComponent(component string) error {
	if component == "" || len(component) > 64 {
		return errors.New("single-instance component rejected")
	}
	for _, character := range component {
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.' || character == '-' || character == '_':
		default:
			return errors.New("single-instance component rejected")
		}
	}
	return nil
}

// currentSessionIdentityToken derives a stable per-user/per-session token from
// the interactive session ID and the process token user SID.
func currentSessionIdentityToken() (string, error) {
	processID, _, _ := procGetCurrentProcessIDSingle.Call()
	if processID == 0 {
		return "", errors.New("current process id unavailable")
	}
	var sessionID uint32
	result, _, callErr := procProcessIDToSessionIDSingle.Call(processID, uintptr(unsafe.Pointer(&sessionID)))
	if result == 0 {
		return "", errors.Join(errors.New("process session id unavailable"), errnoResult(callErr))
	}
	userSID, err := currentUserSID()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", sessionID, userSID)))
	return hex.EncodeToString(digest[:8]), nil
}

func currentUserSID() (string, error) {
	process, _, _ := procGetCurrentProcess.Call()
	var token Handle
	result, _, callErr := procOpenProcessToken.Call(process, uintptr(TokenQuery), uintptr(unsafe.Pointer(&token)))
	if result == 0 || token == 0 {
		return "", errors.Join(errors.New("process token unavailable"), errnoResult(callErr))
	}
	defer func() { _ = CloseHandle(token) }()
	var size uint32
	result, _, _ = procGetTokenInformationSingle.Call(uintptr(token), uintptr(tokenUser), 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > 4096 {
		return "", errors.New("token user information size rejected")
	}
	buffer := make([]byte, size)
	result, _, callErr = procGetTokenInformationSingle.Call(uintptr(token), uintptr(tokenUser), uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&size)))
	if result == 0 {
		return "", errors.Join(errors.New("token user information unavailable"), errnoResult(callErr))
	}
	if len(buffer) < int(unsafe.Sizeof(tokenUserSID{})) {
		return "", errors.New("token user information truncated")
	}
	user := (*tokenUserSID)(unsafe.Pointer(&buffer[0]))
	if user.sid == 0 {
		return "", errors.New("token user SID unavailable")
	}
	var sidString *uint16
	result, _, callErr = procConvertSIDToStringSIDSingle.Call(user.sid, uintptr(unsafe.Pointer(&sidString)))
	if result == 0 || sidString == nil {
		return "", errors.Join(errors.New("token user SID conversion failed"), errnoResult(callErr))
	}
	defer func() { _, _, _ = procLocalFreeSingleInstance.Call(uintptr(unsafe.Pointer(sidString))) }()
	value := utf16PtrToString(sidString)
	if value == "" || len(value) > 256 {
		return "", errors.New("token user SID rejected")
	}
	return value, nil
}

type tokenUserSID struct {
	sid        uintptr
	attributes uint32
}

// CreateSingleInstanceMutex creates or attaches to the hardened mutex for a UI
// component. A pre-existing object is only marked Trusted when its DACL equals
// the restrictive product DACL.
func CreateSingleInstanceMutex(component string) (SingleInstanceClaim, error) {
	name, err := SingleInstanceObjectName(component)
	if err != nil {
		return SingleInstanceClaim{}, err
	}
	return createSingleInstanceObject("mutex", name, 0, 0)
}

// CreateSingleInstanceEvent creates or attaches to the hardened event for a UI
// component.
func CreateSingleInstanceEvent(component string, manualReset, initialState bool) (SingleInstanceClaim, error) {
	name, err := SingleInstanceObjectName(component)
	if err != nil {
		return SingleInstanceClaim{}, err
	}
	manual := uintptr(0)
	if manualReset {
		manual = 1
	}
	initial := uintptr(0)
	if initialState {
		initial = 1
	}
	return createSingleInstanceObject("event", name, manual, initial)
}

func createSingleInstanceObject(kind, name string, manualReset, initialState uintptr) (SingleInstanceClaim, error) {
	claim := SingleInstanceClaim{Kind: kind, Name: name}
	handle, existed, err := createRawSingleInstanceObject(kind, name, manualReset, initialState)
	if err != nil {
		// A creation error can mean "foreign object exists but denies access",
		// which is a failed takeover rather than an unrelated failure. The
		// distinction keeps the fail-closed signal precise for callers.
		if singleInstanceObjectExists(kind, name) {
			return SingleInstanceClaim{}, errors.Join(ErrSingleInstanceTakeover, err)
		}
		return SingleInstanceClaim{}, err
	}
	claim.Handle = handle
	claim.Existed = existed
	if !existed {
		// The object was created by this process, so it carries the product
		// DACL and the current user as owner by construction.
		claim.Trusted = true
		return claim, nil
	}
	trusted, trustErr := singleInstanceObjectIsTrusted(claim.Handle, kind)
	if trustErr == nil && trusted {
		claim.Trusted = true
		return claim, nil
	}
	// A pre-existing object without the product DACL (or one whose DACL cannot
	// be read) is not an authority. Take it over deterministically instead of
	// accepting it or leaving it in place for the next launch.
	if takeoverErr := takeOverSingleInstanceObject(kind, name, manualReset, initialState, &claim); takeoverErr != nil {
		_ = claim.Close()
		return SingleInstanceClaim{}, errors.Join(ErrSingleInstanceTakeover, takeoverErr)
	}
	return claim, nil
}

// createRawSingleInstanceObject creates the named kernel object with the
// product security descriptor and reports whether it already existed.
func createRawSingleInstanceObject(kind, name string, manualReset, initialState uintptr) (Handle, bool, error) {
	namePointer, err := utf16Ptr(name)
	if err != nil {
		return 0, false, err
	}
	attributes, err := newSingleInstanceSecurityAttributes()
	if err != nil {
		return 0, false, err
	}
	defer attributes.free()
	var handle uintptr
	var callErr error
	switch kind {
	case "mutex":
		handle, _, callErr = procCreateMutexSingleInstance.Call(uintptr(unsafe.Pointer(attributes)), 0, uintptr(unsafe.Pointer(namePointer)))
	case "event":
		handle, _, callErr = procCreateEventSingleInstance.Call(uintptr(unsafe.Pointer(attributes)), manualReset, initialState, uintptr(unsafe.Pointer(namePointer)))
	default:
		return 0, false, errors.New("single-instance object kind rejected")
	}
	if handle == 0 {
		return 0, false, errors.Join(errors.New("single-instance object creation failed"), errnoResult(callErr))
	}
	return Handle(handle), errors.Is(callErr, ErrorAlreadyExists), nil
}

// singleInstanceObjectExists reports whether a kernel object with the given
// name exists, without requiring any access rights on it. It is used to
// distinguish "foreign object denies access" (a takeover failure) from an
// unrelated creation error.
func singleInstanceObjectExists(kind, name string) bool {
	namePointer, err := utf16Ptr(name)
	if err != nil {
		return false
	}
	var handle uintptr
	var callErr error
	switch kind {
	case "mutex":
		handle, _, callErr = procOpenMutexSingleInstance.Call(0, 0, uintptr(unsafe.Pointer(namePointer)))
	case "event":
		handle, _, callErr = procOpenEventSingleInstance.Call(0, 0, uintptr(unsafe.Pointer(namePointer)))
	default:
		return false
	}
	if handle != 0 {
		_ = CloseHandle(Handle(handle))
		return true
	}
	if errno := errnoResult(callErr); errno != nil {
		var errnoValue syscall.Errno
		if errors.As(errno, &errnoValue) && errnoValue == syscall.ERROR_FILE_NOT_FOUND {
			return false
		}
	}
	// Unknown or access-denied failures are treated conservatively as an
	// existing object that this process cannot take over.
	return true
}

// takeOverSingleInstanceObject neutralises a foreign pre-created object while
// keeping the takeover strictly bounded. Two independent mechanisms are tried
// in order:
//
//  1. DACL restoration: rewrite the object's DACL to the product DACL. This
//     needs WRITE_DAC on the existing object but keeps the object identity and
//     therefore any holder's handle alive, which is acceptable because the
//     single-instance decision never trusts object state, only the DACL.
//  2. Delete and recreate: drop this process's handle and create the object
//     again. If the foreign holder has released its handle in the meantime the
//     object disappears and the recreated object carries the product DACL and
//     owner.
//
// After singleInstanceTakeoverAttempts bounded attempts the claim fails closed
// with ErrSingleInstanceTakeover instead of silently accepting the object.
func takeOverSingleInstanceObject(kind, name string, manualReset, initialState uintptr, claim *SingleInstanceClaim) error {
	if claim == nil || claim.Handle == 0 {
		return errors.New("single-instance takeover requires an open handle")
	}
	var lastErr error
	for attempt := 0; attempt < singleInstanceTakeoverAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(singleInstanceTakeoverBackoff)
		}
		if claim.Handle != 0 {
			if err := repairSingleInstanceObjectDACL(claim.Handle, kind); err != nil {
				lastErr = err
			} else if trusted, err := singleInstanceObjectIsTrusted(claim.Handle, kind); err == nil && trusted {
				claim.Trusted = true
				claim.TakenOver = true
				return nil
			} else if err != nil {
				lastErr = err
			}
			if err := claim.Close(); err != nil {
				lastErr = err
			}
		}
		handle, existed, err := createRawSingleInstanceObject(kind, name, manualReset, initialState)
		if err != nil {
			// The foreign DACL denies this process the required access; further
			// attempts against the same object cannot succeed.
			return err
		}
		claim.Handle = handle
		claim.Existed = existed
		if !existed {
			claim.Trusted = true
			claim.TakenOver = true
			return nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("foreign single-instance object persisted through every bounded takeover attempt")
	}
	return lastErr
}

// repairSingleInstanceObjectDACL rewrites an existing kernel object's DACL to
// the product DACL. It requires WRITE_DAC access on the handle and re-verifies
// the result through singleInstanceObjectIsTrusted before reporting success.
func repairSingleInstanceObjectDACL(handle Handle, kind string) error {
	if handle == 0 {
		return errors.New("single-instance handle required")
	}
	if _, ok := singleInstanceSpecificAllAccess[kind]; !ok {
		return errors.New("single-instance object kind rejected")
	}
	descriptor, err := sddlToSecurityDescriptor(singleInstanceSDDL)
	if err != nil {
		return err
	}
	defer func() { _, _, _ = procLocalFreeSingleInstance.Call(uintptr(descriptor)) }()
	var dacl unsafe.Pointer
	present := int32(0)
	defaulted := int32(0)
	result, _, callErr := procGetSDDaclSingle.Call(
		uintptr(descriptor),
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&defaulted)),
	)
	if result == 0 || present == 0 || dacl == nil {
		return errors.Join(errors.New("product DACL descriptor rejected"), errnoResult(callErr))
	}
	result, _, callErr = procSetSecurityInfoSingle.Call(
		uintptr(handle),
		uintptr(seKernelObject),
		uintptr(daclSecurityInformation),
		0, 0,
		uintptr(dacl),
		0,
	)
	if result != 0 {
		return errors.Join(errors.New("single-instance DACL takeover failed"), errnoResult(callErr))
	}
	return nil
}

// ResolveSingleInstance decides whether this process must become the primary
// UI instance. It only delegates to an existing instance when the named object
// is trusted AND a live GeDefense window exists. A pre-created or tampered
// object without a real UI therefore never suppresses the operator UI; the
// caller reports the tamper and starts as primary. claimErr from a failed
// object creation or an impossible takeover also degrades to "start anyway"
// instead of a silent exit, so pre-creation can never lock the operator out.
func ResolveSingleInstance(claim SingleInstanceClaim, legitWindow bool, claimErr error) (primary bool, tamper bool) {
	if claimErr != nil {
		return true, true
	}
	if claim.TakenOver {
		tamper = true
	}
	if !claim.Existed {
		return true, tamper
	}
	if claim.Trusted && legitWindow {
		return false, tamper
	}
	// Trusted object but no live UI (or a taken-over object): stale handle left
	// by a crashed or still starting instance. Availability wins; report it so
	// the event is visible.
	return true, true
}

func newSingleInstanceSecurityAttributes() (*securityAttributes, error) {
	descriptor, err := sddlToSecurityDescriptor(singleInstanceSDDL)
	if err != nil {
		return nil, err
	}
	attributes := &securityAttributes{
		length:        uint32(unsafe.Sizeof(securityAttributes{})),
		descriptor:    descriptor,
		inheritHandle: 0,
	}
	return attributes, nil
}

func (attributes *securityAttributes) free() {
	if attributes == nil || attributes.descriptor == nil {
		return
	}
	_, _, _ = procLocalFreeSingleInstance.Call(uintptr(attributes.descriptor))
	attributes.descriptor = nil
}

func sddlToSecurityDescriptor(sddl string) (unsafe.Pointer, error) {
	pointer, err := utf16Ptr(sddl)
	if err != nil {
		return nil, err
	}
	var descriptor unsafe.Pointer
	result, _, callErr := procConvertSDDLToSDSingle.Call(uintptr(unsafe.Pointer(pointer)), uintptr(sddlRevision1), uintptr(unsafe.Pointer(&descriptor)), 0)
	if result == 0 || descriptor == nil {
		return nil, errors.Join(errors.New("security descriptor conversion failed"), errnoResult(callErr))
	}
	return descriptor, nil
}

func securityDescriptorToSDDL(descriptor unsafe.Pointer, information uint32) (string, error) {
	if descriptor == nil {
		return "", errors.New("security descriptor required")
	}
	var value *uint16
	result, _, callErr := procConvertSDToSDDLSingle.Call(uintptr(descriptor), uintptr(sddlRevision1), uintptr(information), uintptr(unsafe.Pointer(&value)), 0)
	if result == 0 || value == nil {
		return "", errors.Join(errors.New("security descriptor serialization failed"), errnoResult(callErr))
	}
	defer func() { _, _, _ = procLocalFreeSingleInstance.Call(uintptr(unsafe.Pointer(value))) }()
	return utf16PtrToString(value), nil
}

// utf16PtrToString converts a NUL-terminated UTF-16 string with a hard 64 KiB
// scan bound so a malformed or hostile descriptor can never trigger an
// unbounded read.
func utf16PtrToString(pointer *uint16) string {
	if pointer == nil {
		return ""
	}
	buffer := make([]uint16, 0, 128)
	for index := 0; index < 32768; index++ {
		value := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(pointer)) + uintptr(index)*utf16CharSize))
		if value == 0 {
			break
		}
		buffer = append(buffer, value)
	}
	return string(utf16.Decode(buffer))
}

func expectedSingleInstanceDACL(kind string) (string, error) {
	allAccess, ok := singleInstanceSpecificAllAccess[kind]
	if !ok {
		return "", errors.New("single-instance object kind rejected")
	}
	canonical := fmt.Sprintf(`D:P(A;;0x%X;;;SY)(A;;0x%X;;;BA)(A;;0x%X;;;OW)`, allAccess, allAccess, allAccess)
	descriptor, err := sddlToSecurityDescriptor(canonical)
	if err != nil {
		return "", err
	}
	defer func() { _, _, _ = procLocalFreeSingleInstance.Call(uintptr(descriptor)) }()
	return securityDescriptorToSDDL(descriptor, daclSecurityInformation)
}

// singleInstanceObjectIsTrusted reads the object's DACL and compares it with
// the restrictive DACL this product assigns. A default-DACL object created by
// an attacker never matches.
func singleInstanceObjectIsTrusted(handle Handle, kind string) (bool, error) {
	if handle == 0 {
		return false, errors.New("single-instance handle required")
	}
	var descriptor unsafe.Pointer
	result, _, callErr := procGetSecurityInfoSingle.Call(
		uintptr(handle),
		uintptr(seKernelObject),
		uintptr(daclSecurityInformation),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if result != 0 || descriptor == nil {
		return false, errors.Join(errors.New("object security descriptor unavailable"), errnoResult(callErr))
	}
	defer func() { _, _, _ = procLocalFreeSingleInstance.Call(uintptr(descriptor)) }()
	actual, err := securityDescriptorToSDDL(descriptor, daclSecurityInformation)
	if err != nil {
		return false, err
	}
	expected, err := expectedSingleInstanceDACL(kind)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected)), nil
}
