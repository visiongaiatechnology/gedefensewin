// STATUS: PLATIN
//go:build windows

package server

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// This file implements the local OS-identity verification used by the operator
// session broker (UI-FIND-001 / AN-FIND-001 / AN-FIND-004). It inspects the
// Windows access token of the process that owns a loopback TCP connection; it
// never trusts a client-supplied account name or SID. All handles are closed and
// all buffers are bounded. If anything is unavailable the caller fails closed.

const (
	processQueryLimitedInformation = 0x1000
	tokenQueryAccess               = 0x0008

	tokenUserClass   = 1
	tokenGroupsClass = 2

	seGroupEnabled        = 0x00000004
	seGroupUseForDenyOnly = 0x00000010
	maxTokenInfoBytes     = 1 << 20

	administratorsSID = "S-1-5-32-544"
	operatorGroupName = "VGT GeDefense Operators"
	productStateKey   = `SOFTWARE\VGT\GeDefense`
	operatorGroupSID  = "OperatorGroupSid"
)

var (
	operatorAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	operatorKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenProcessTokenOperator      = operatorAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformationOperator   = operatorAdvapi32.NewProc("GetTokenInformation")
	procLookupAccountSidOperator      = operatorAdvapi32.NewProc("LookupAccountSidW")
	procLookupAccountNameOperator     = operatorAdvapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSidOperator = operatorAdvapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSidToSidOperator = operatorAdvapi32.NewProc("ConvertStringSidToSidW")
	procLocalFreeOperator             = operatorKernel32.NewProc("LocalFree")
	operatorGroupSIDOnce              sync.Once
	operatorGroupSIDCached            string
	operatorGroupSIDLookupError       error
)

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

// operatorPeerFromPID resolves pid to a verified Windows identity. It requires
// PROCESS_QUERY_LIMITED_INFORMATION, which a LocalSystem service holds for a
// same-machine user process without elevation of the caller.
func operatorPeerFromPID(pid uint32) (operatorPeer, error) {
	if pid == 0 {
		return operatorPeer{}, errors.New("invalid peer process id")
	}
	process, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return operatorPeer{}, fmt.Errorf("open peer process: %w", err)
	}
	defer func() { _ = syscall.CloseHandle(process) }()
	var token syscall.Token
	result, _, callErr := procOpenProcessTokenOperator.Call(
		uintptr(process), uintptr(tokenQueryAccess), uintptr(unsafe.Pointer(&token)))
	if result == 0 {
		return operatorPeer{}, fmt.Errorf("open peer process token: %w", callError(callErr))
	}
	defer func() { _ = syscall.CloseHandle(syscall.Handle(token)) }()

	userSID, account, err := tokenUserIdentity(token)
	if err != nil {
		return operatorPeer{}, err
	}
	groups, err := tokenGroupSIDs(token)
	if err != nil {
		return operatorPeer{}, err
	}
	peer := operatorPeer{
		PID:           pid,
		Account:       account,
		SID:           userSID,
		Administrator: containsSID(groups, administratorsSID),
		Operator:      containsSID(groups, lookupOperatorGroupSID()),
	}
	return peer, nil
}

func callError(callErr error) error {
	if callErr == nil || errors.Is(callErr, syscall.Errno(0)) {
		return errors.New("windows api call failed")
	}
	return callErr
}

func tokenUserIdentity(token syscall.Token) (string, string, error) {
	buffer, err := tokenInformation(token, tokenUserClass)
	if err != nil {
		return "", "", err
	}
	if len(buffer) < int(unsafe.Sizeof(sidAndAttributes{})) {
		return "", "", errors.New("token user buffer truncated")
	}
	user := (*sidAndAttributes)(unsafe.Pointer(&buffer[0]))
	if user.Sid == 0 {
		return "", "", errors.New("token user sid missing")
	}
	sidText, err := sidToString(user.Sid)
	if err != nil {
		return "", "", err
	}
	account, err := accountNameForSID(user.Sid)
	if err != nil {
		// A resolvable SID is sufficient for attribution; name resolution can
		// fail for deleted accounts. Keep the SID-only identity instead of
		// granting authority without an account label.
		return sidText, "", err
	}
	return sidText, account, nil
}

func tokenGroupSIDs(token syscall.Token) ([]string, error) {
	buffer, err := tokenInformation(token, tokenGroupsClass)
	if err != nil {
		return nil, err
	}
	if len(buffer) < 8 {
		return nil, errors.New("token groups buffer truncated")
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	const groupEntrySize = int(unsafe.Sizeof(sidAndAttributes{}))
	if count > 4096 || len(buffer) < 8+int(count)*groupEntrySize {
		return nil, errors.New("token groups buffer invalid")
	}
	sids := make([]string, 0, count)
	for index := uint32(0); index < count; index++ {
		entry := (*sidAndAttributes)(unsafe.Pointer(&buffer[8+int(index)*groupEntrySize]))
		if entry.Sid == 0 {
			continue
		}
		if entry.Attributes&seGroupEnabled == 0 || entry.Attributes&seGroupUseForDenyOnly != 0 {
			continue
		}
		sidText, sidErr := sidToString(entry.Sid)
		if sidErr != nil {
			continue
		}
		sids = append(sids, sidText)
	}
	return sids, nil
}

func tokenInformation(token syscall.Token, class uint32) ([]byte, error) {
	var size uint32
	procGetTokenInformationOperator.Call(
		uintptr(token), uintptr(class), 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > maxTokenInfoBytes {
		return nil, errors.New("token information size invalid")
	}
	buffer := make([]byte, size)
	var returned uint32
	result, _, callErr := procGetTokenInformationOperator.Call(
		uintptr(token), uintptr(class),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&returned)))
	if result == 0 {
		return nil, fmt.Errorf("get token information: %w", callError(callErr))
	}
	if returned == 0 || int(returned) > len(buffer) {
		return nil, errors.New("token information truncated")
	}
	return buffer[:returned], nil
}

func sidToString(sid uintptr) (string, error) {
	var text *uint16
	result, _, callErr := procConvertSidToStringSidOperator.Call(
		sid, uintptr(unsafe.Pointer(&text)))
	if result == 0 || text == nil {
		return "", fmt.Errorf("convert sid: %w", callError(callErr))
	}
	defer func() { _, _, _ = procLocalFreeOperator.Call(uintptr(unsafe.Pointer(text))) }()
	return utf16PtrToString(text), nil
}

// utf16PtrToString converts a NUL-terminated UTF-16 string with a hard length
// bound so a malformed Windows buffer can never cause an unbounded scan.
func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	length := 0
	for length < 4096 {
		character := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(length)*2))
		if character == 0 {
			break
		}
		length++
	}
	if length == 0 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(ptr, length))
}

func accountNameForSID(sid uintptr) (string, error) {
	var nameLength, domainLength uint32
	var use uint32
	procLookupAccountSidOperator.Call(0, sid, 0,
		uintptr(unsafe.Pointer(&nameLength)), 0, uintptr(unsafe.Pointer(&domainLength)),
		uintptr(unsafe.Pointer(&use)))
	if nameLength == 0 || nameLength > 1024 || domainLength > 1024 {
		return "", errors.New("account name boundary rejected")
	}
	name := make([]uint16, nameLength+1)
	domain := make([]uint16, domainLength+1)
	result, _, callErr := procLookupAccountSidOperator.Call(0, sid,
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLength)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLength)),
		uintptr(unsafe.Pointer(&use)))
	if result == 0 {
		return "", fmt.Errorf("lookup account sid: %w", callError(callErr))
	}
	accountName := syscall.UTF16ToString(name)
	domainName := syscall.UTF16ToString(domain)
	if domainName == "" {
		return accountName, nil
	}
	return domainName + `\` + accountName, nil
}

func lookupOperatorGroupSID() string {
	operatorGroupSIDOnce.Do(func() {
		operatorGroupSIDCached, operatorGroupSIDLookupError = readOperatorGroupSIDFromRegistry()
		if operatorGroupSIDCached == "" {
			operatorGroupSIDCached, operatorGroupSIDLookupError = lookupAccountSIDByName(operatorGroupName)
		}
	})
	if operatorGroupSIDLookupError != nil {
		return ""
	}
	return operatorGroupSIDCached
}

func readOperatorGroupSIDFromRegistry() (string, error) {
	path, err := syscall.UTF16PtrFromString(productStateKey)
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ, &key); err != nil {
		return "", err
	}
	defer func() { _ = syscall.RegCloseKey(key) }()
	valueName, err := syscall.UTF16PtrFromString(operatorGroupSID)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 256)
	length := uint32(len(buffer) * 2)
	var valueType uint32
	if err := syscall.RegQueryValueEx(key, valueName, nil, &valueType,
		(*byte)(unsafe.Pointer(&buffer[0])), &length); err != nil {
		return "", err
	}
	if valueType != syscall.REG_SZ {
		return "", errors.New("operator group sid value type invalid")
	}
	value := strings.TrimSpace(syscall.UTF16ToString(buffer))
	if !strings.HasPrefix(value, "S-1-5-21-") {
		return "", errors.New("operator group sid value invalid")
	}
	return value, nil
}

func lookupAccountSIDByName(name string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var sidSize, domainSize uint32
	var use uint32
	procLookupAccountNameOperator.Call(0, uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&sidSize)), 0, uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&use)))
	if sidSize == 0 || sidSize > 4096 || domainSize > 1024 {
		return "", errors.New("operator group sid lookup unavailable")
	}
	sidBuffer := make([]byte, sidSize)
	domain := make([]uint16, domainSize+1)
	result, _, callErr := procLookupAccountNameOperator.Call(0,
		uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&sidBuffer[0])),
		uintptr(unsafe.Pointer(&sidSize)), uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&domainSize)), uintptr(unsafe.Pointer(&use)))
	if result == 0 {
		return "", fmt.Errorf("lookup operator group: %w", callError(callErr))
	}
	return sidToString(uintptr(unsafe.Pointer(&sidBuffer[0])))
}

func containsSID(sids []string, wanted string) bool {
	if wanted == "" {
		return false
	}
	for _, sid := range sids {
		if sid == wanted {
			return true
		}
	}
	return false
}
