// STATUS: DIAMANT VGT SUPREME
//go:build windows

package secretfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	seFileObject                  = 1
	daclSecurityInformation       = 0x00000004
	protectedDACLSecurityInfo     = 0x80000000
	sddlRevision1                 = 1
	accessAllowedACEType          = 0
	accessDeniedACEType           = 1
	inheritedACEFlag              = 0x10
	daclPresentControl            = 0x0004
	maximumSecurityDescriptorSize = 1 << 20

	// systemSID and administratorsSID are the only principals allowed to access
	// service-local secret material.
	systemSID         = "S-1-5-18"
	administratorsSID = "S-1-5-32-544"
)

const (
	// desiredSDDL is an inheritance-protected DACL: full access for LocalSystem
	// and Builtin Administrators only, applied to the object and inherited by
	// children. No ACE is granted to Users, Authenticated Users or the operator
	// group, so the installer's inherited operator-group RX grant no longer
	// exposes secret material.
	desiredSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

var (
	secretAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	secretKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procConvertStringSecurityDescriptor = secretAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDACL       = secretAdvapi32.NewProc("GetSecurityDescriptorDacl")
	procSetNamedSecurityInfo            = secretAdvapi32.NewProc("SetNamedSecurityInfoW")
	procGetFileSecurity                 = secretAdvapi32.NewProc("GetFileSecurityW")
	procLocalFree                       = secretKernel32.NewProc("LocalFree")
)

// canManageServiceDACL reports whether the current token is a service-level
// token (LocalSystem or elevated Administrator). Only such a token can apply a
// SYSTEM/Administrators-only DACL and still use the object afterwards.
func canManageServiceDACL() (bool, error) {
	if !winapi.IsProcessElevated() {
		return false, nil
	}
	return true, nil
}

func restrictPath(path string, directory bool) (Restriction, error) {
	restriction := Restriction{Path: path}
	canEnforce, err := canManageServiceDACL()
	if err != nil {
		return restriction, err
	}
	if !canEnforce {
		restriction.Detail = "service identity unavailable; DACL hardening deferred to the LocalSystem service"
		return restriction, nil
	}
	restriction.Enforced = true
	if err := applyProtectedDACL(path); err != nil {
		restriction.Detail = err.Error()
		return restriction, fmt.Errorf("secret access control: %w", err)
	}
	restricted, detail, inspectErr := inspectPathDACL(path)
	if inspectErr != nil {
		restriction.Detail = inspectErr.Error()
		return restriction, fmt.Errorf("secret access-control verification: %w", inspectErr)
	}
	restriction.Restricted = restricted
	restriction.Detail = detail
	if !restricted {
		return restriction, errors.New("secret access control did not restrict the effective DACL: " + detail)
	}
	if directory {
		restriction.Detail = "inheritance-protected DACL applied (LocalSystem/Administrators only)"
	}
	return restriction, nil
}

func applyProtectedDACL(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return err
	}
	sddlPtr, err := syscall.UTF16PtrFromString(desiredSDDL)
	if err != nil {
		return err
	}
	var descriptor uintptr
	result, _, callErr := procConvertStringSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(sddlPtr)), sddlRevision1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if result == 0 || descriptor == 0 {
		return dllError("ConvertStringSecurityDescriptorToSecurityDescriptorW", callErr)
	}
	defer func() { _, _, _ = procLocalFree.Call(descriptor) }()

	var present int32
	var dacl uintptr
	var defaulted int32
	result, _, callErr = procGetSecurityDescriptorDACL.Call(
		descriptor,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&defaulted)),
	)
	if result == 0 || present == 0 || dacl == 0 {
		return dllError("GetSecurityDescriptorDacl", callErr)
	}
	result, _, callErr = procSetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		seFileObject,
		daclSecurityInformation|protectedDACLSecurityInfo,
		0, 0,
		dacl,
		0,
	)
	if result != 0 {
		return &secretErrnoError{operation: "SetNamedSecurityInfoW", code: syscall.Errno(result)}
	}
	return nil
}

func inspectPathDACL(path string) (bool, string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return false, "", err
	}
	var needed uint32
	_, _, _ = procGetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		daclSecurityInformation,
		0, 0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if needed == 0 || needed > maximumSecurityDescriptorSize {
		return false, "effective DACL size unavailable", errors.New("secret DACL size unavailable")
	}
	buffer := make([]byte, needed)
	var written uint32
	result, _, callErr := procGetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		daclSecurityInformation,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&written)),
	)
	if result == 0 {
		return false, "", dllError("GetFileSecurityW", callErr)
	}
	if written == 0 || int(written) > len(buffer) {
		return false, "effective DACL result truncated", errors.New("secret DACL result truncated")
	}
	return inspectSecurityDescriptor(buffer[:written])
}

// inspectSecurityDescriptor validates a self-relative SECURITY_DESCRIPTOR that
// was read from the filesystem: the DACL must be present and must not contain
// any inherited ACE or any allow ACE for a principal other than LocalSystem or
// Builtin Administrators. Deny ACEs are permitted (they can only restrict).
func inspectSecurityDescriptor(buffer []byte) (bool, string, error) {
	// GetFileSecurityW always returns a self-relative SECURITY_DESCRIPTOR.
	// Its Owner/Group/Sacl/Dacl members are 32-bit offsets, not pointers:
	//   revision(1) sbz1(1) control(2) owner(4@4) group(4@8) sacl(4@12) dacl(4@16)
	// Reading a pointer-sized value here made every real filesystem DACL look
	// invalid ("DACL is not self-relative") and blocked service startup.
	const selfRelativeHeaderSize = 20
	if len(buffer) < selfRelativeHeaderSize {
		return false, "security descriptor truncated", errors.New("security descriptor truncated")
	}
	control := binary.LittleEndian.Uint16(buffer[2:4])
	if control&daclPresentControl == 0 {
		return false, "DACL is absent (NULL DACL grants full access)", nil
	}
	daclOffset := int(binary.LittleEndian.Uint32(buffer[16:20]))
	if daclOffset == 0 {
		return false, "DACL is absent (NULL DACL grants full access)", nil
	}
	if daclOffset < selfRelativeHeaderSize || daclOffset+8 > len(buffer) {
		return false, "DACL offset outside the descriptor", errors.New("DACL offset outside the descriptor")
	}
	return inspectACL(buffer[daclOffset:])
}

func inspectACL(acl []byte) (bool, string, error) {
	if len(acl) < 8 {
		return false, "DACL truncated", errors.New("DACL truncated")
	}
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	position := 8
	for index := 0; index < aceCount; index++ {
		if position+4 > len(acl) {
			return false, "ACE header truncated", errors.New("ACE header truncated")
		}
		aceType := acl[position]
		aceFlags := acl[position+1]
		aceSize := int(binary.LittleEndian.Uint16(acl[position+2 : position+4]))
		if aceSize < 4 || position+aceSize > len(acl) {
			return false, "ACE size rejected", errors.New("ACE size rejected")
		}
		if aceFlags&inheritedACEFlag != 0 {
			return false, "inherited ACE present", nil
		}
		switch aceType {
		case accessAllowedACEType:
			sidStart := position + 8
			if sidStart+8 > position+aceSize {
				return false, "allow ACE SID truncated", errors.New("allow ACE SID truncated")
			}
			sid, err := formatSID(acl[sidStart : position+aceSize])
			if err != nil {
				return false, "allow ACE SID invalid", nil
			}
			if sid != systemSID && sid != administratorsSID {
				return false, "allow ACE grants a non-service principal: " + sid, nil
			}
		case accessDeniedACEType:
			// Deny ACEs can only reduce access and are therefore acceptable.
		default:
			return false, fmt.Sprintf("unsupported ACE type %d", aceType), nil
		}
		position += aceSize
	}
	return true, "effective DACL grants only LocalSystem and Builtin Administrators", nil
}

func formatSID(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", errors.New("SID truncated")
	}
	revision := raw[0]
	count := int(raw[1])
	if count < 0 || count > 15 || len(raw) < 8+4*count {
		return "", errors.New("SID invalid")
	}
	authority := uint64(raw[2])<<40 | uint64(raw[3])<<32 | uint64(raw[4])<<24 |
		uint64(raw[5])<<16 | uint64(raw[6])<<8 | uint64(raw[7])
	result := fmt.Sprintf("S-%d-%d", revision, authority)
	for index := 0; index < count; index++ {
		start := 8 + 4*index
		subAuthority := binary.LittleEndian.Uint32(raw[start : start+4])
		result += fmt.Sprintf("-%d", subAuthority)
	}
	return result, nil
}

func readPointer(buffer []byte, pointerSize int) uintptr {
	if pointerSize == 8 {
		return uintptr(binary.LittleEndian.Uint64(buffer[:8]))
	}
	return uintptr(binary.LittleEndian.Uint32(buffer[:4]))
}

func align(value, alignment int) int {
	if alignment <= 1 {
		return value
	}
	return (value + alignment - 1) / alignment * alignment
}

type secretErrnoError struct {
	operation string
	code      syscall.Errno
}

func (e *secretErrnoError) Error() string {
	return fmt.Sprintf("%s failed with Windows error %d", e.operation, uint32(e.code))
}

func dllError(operation string, callErr error) error {
	var errno syscall.Errno
	if errors.As(callErr, &errno) && errno != 0 {
		return &secretErrnoError{operation: operation, code: errno}
	}
	return errors.New(operation + " failed")
}

func replaceFile(temporaryPath, path string) error {
	return winapi.MoveFileReplace(temporaryPath, path)
}
