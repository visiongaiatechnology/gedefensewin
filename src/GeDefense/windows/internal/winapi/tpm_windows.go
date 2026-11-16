// STATUS: PLATIN VGT SUPREME
//go:build windows

package winapi

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	tbs    = syscall.NewLazyDLL("tbs.dll")
	ncrypt = syscall.NewLazyDLL("ncrypt.dll")

	procTbsiContextCreate = tbs.NewProc("Tbsi_Context_Create")
	procTbsiContextClose  = tbs.NewProc("Tbsip_Context_Close")
	procTbsiGetDeviceInfo = tbs.NewProc("Tbsi_GetDeviceInfo")
	procTbsiGetTCGLog     = tbs.NewProc("Tbsi_Get_TCG_Log")

	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

// MeasureBootPosture reads TPM device info, TCG Measured Boot Log (WBCL),
// NCrypt Platform Crypto Provider PCR table, Secure Boot and HVCI/VBS posture.
func MeasureBootPosture() (BootPosture, error) {
	posture := BootPosture{QuoteKind: "none"}
	var problems []string

	if info, err := readTPMDeviceInfo(); err == nil {
		posture.TPMVersion = info.TPMVersion
		posture.TPMInterfaceType = info.TPMInterfaceType
		posture.TPMRevision = info.TPMImpRevision
		posture.TPMAvailable = info.TPMVersion > 0
	} else {
		problems = append(problems, err.Error())
	}

	if wbcl, err := readTBSMeasuredBootLog(); err == nil && len(wbcl) > 0 {
		sum := sha256.Sum256(wbcl)
		posture.WBCLAvailable = true
		posture.WBCLBytes = len(wbcl)
		posture.WBCLSHA256 = hex.EncodeToString(sum[:])
	} else if err != nil {
		problems = append(problems, err.Error())
	}

	if pcrBytes, pcrCount, err := readNCryptPCRTable(); err == nil && len(pcrBytes) > 0 {
		sum := sha256.Sum256(pcrBytes)
		posture.PCRCount = pcrCount
		posture.PCRTableSHA256 = hex.EncodeToString(sum[:])
	} else if err != nil {
		problems = append(problems, err.Error())
	}

	if sbVal, err := readWinRegDWORD(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled"); err == nil {
		posture.SecureBootKnown = true
		posture.SecureBootEnabled = sbVal == 1
	}
	if hvciVal, err := readWinRegDWORD(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled"); err == nil {
		posture.DeviceGuardKnown = true
		posture.HVCIEnabled = hvciVal == 1
	}
	if vbsVal, err := readWinRegDWORD(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard`, "EnableVirtualizationBasedSecurity"); err == nil {
		posture.DeviceGuardKnown = true
		posture.VBSConfigured = vbsVal == 1
	}

	if posture.TPMVersion >= 2 && posture.WBCLAvailable {
		posture.QuoteKind = "tpm2-wbcl"
	}
	if len(problems) > 0 {
		posture.LastError = strings.Join(problems, "; ")
		if len(posture.LastError) > 256 {
			posture.LastError = posture.LastError[:256]
		}
	}
	posture.Digest = computeBootPostureDigest(posture)
	return posture, nil
}

func computeBootPostureDigest(p BootPosture) string {
	canonical := fmt.Sprintf(
		"vgt-boot-posture-v1|tpm=%t:%d:%d:%d|wbcl=%t:%d:%s|pcr=%d:%s|sb=%t:%t|dg=%t:%t:%t|quote=%s",
		p.TPMAvailable, p.TPMVersion, p.TPMInterfaceType, p.TPMRevision,
		p.WBCLAvailable, p.WBCLBytes, p.WBCLSHA256,
		p.PCRCount, p.PCRTableSHA256,
		p.SecureBootKnown, p.SecureBootEnabled,
		p.DeviceGuardKnown, p.VBSConfigured, p.HVCIEnabled,
		p.QuoteKind,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func readTPMDeviceInfo() (tpmDeviceInfo, error) {
	var info tpmDeviceInfo
	r1, _, _ := procTbsiGetDeviceInfo.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
	if uint32(r1) != tbsSuccess {
		if uint32(r1) == tbsETPMNotFound {
			return tpmDeviceInfo{}, errors.New("tpm not present")
		}
		return tpmDeviceInfo{}, fmt.Errorf("Tbsi_GetDeviceInfo=0x%08x", uint32(r1))
	}
	return info, nil
}

func readTBSMeasuredBootLog() ([]byte, error) {
	params := tbsContextParams2{
		Version: tbsContextVersion2,
		Flags:   tbsIncludeTPM12 | tbsIncludeTPM20,
	}
	var ctxHandle uintptr
	rCreate, _, _ := procTbsiContextCreate.Call(uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&ctxHandle)))
	runtime.KeepAlive(params)
	if uint32(rCreate) != tbsSuccess {
		return nil, fmt.Errorf("Tbsi_Context_Create=0x%08x", uint32(rCreate))
	}
	defer procTbsiContextClose.Call(ctxHandle)

	var logSize uint32
	rSize, _, _ := procTbsiGetTCGLog.Call(ctxHandle, 0, uintptr(unsafe.Pointer(&logSize)))
	if uint32(rSize) != tbsSuccess {
		return nil, fmt.Errorf("Tbsi_Get_TCG_Log(size)=0x%08x", uint32(rSize))
	}
	if logSize == 0 || logSize > maxWBCLBytes {
		return nil, fmt.Errorf("wbcl size %d out of bounds (0,%d]", logSize, maxWBCLBytes)
	}
	buf := make([]byte, logSize)
	rRead, _, _ := procTbsiGetTCGLog.Call(ctxHandle, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&logSize)))
	if uint32(rRead) != tbsSuccess {
		return nil, fmt.Errorf("Tbsi_Get_TCG_Log(read)=0x%08x", uint32(rRead))
	}
	if int(logSize) > len(buf) {
		return nil, errors.New("wbcl size exceeded buffer during read")
	}
	return buf[:logSize], nil
}

func readNCryptPCRTable() ([]byte, int, error) {
	provName, err := utf16Ptr(ncryptPCPProviderName)
	if err != nil {
		return nil, 0, err
	}
	var provHandle uintptr
	rOpen, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&provHandle)), uintptr(unsafe.Pointer(provName)), 0)
	runtime.KeepAlive(provName)
	if rOpen != 0 {
		return nil, 0, fmt.Errorf("NCryptOpenStorageProvider=0x%08x", uint32(rOpen))
	}
	defer procNCryptFreeObject.Call(provHandle)

	propName, err := utf16Ptr(ncryptPCPPCRTableProp)
	if err != nil {
		return nil, 0, err
	}
	var needed uint32
	rQuery, _, _ := procNCryptGetProperty.Call(provHandle, uintptr(unsafe.Pointer(propName)), 0, 0, uintptr(unsafe.Pointer(&needed)), 0)
	if rQuery != 0 {
		return nil, 0, fmt.Errorf("NCryptGetProperty(size)=0x%08x", uint32(rQuery))
	}
	if needed == 0 || needed > 16<<10 {
		return nil, 0, fmt.Errorf("pcr table size %d out of bounds", needed)
	}
	buf := make([]byte, needed)
	rRead, _, _ := procNCryptGetProperty.Call(provHandle, uintptr(unsafe.Pointer(propName)), uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)), 0)
	runtime.KeepAlive(propName)
	if rRead != 0 {
		return nil, 0, fmt.Errorf("NCryptGetProperty(read)=0x%08x", uint32(rRead))
	}
	count := int(needed) / 32
	return buf[:needed], count, nil
}

func readWinRegDWORD(root syscall.Handle, subkey, name string) (uint32, error) {
	subPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(root, subPtr, 0, syscall.KEY_READ, &key); err != nil {
		return 0, err
	}
	defer syscall.RegCloseKey(key)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var valType uint32
	var data [4]byte
	size := uint32(len(data))
	if err := syscall.RegQueryValueEx(key, namePtr, nil, &valType, &data[0], &size); err != nil {
		return 0, err
	}
	if valType != syscall.REG_DWORD || size != 4 {
		return 0, errors.New("registry value is not a DWORD")
	}
	return binary.LittleEndian.Uint32(data[:]), nil
}
