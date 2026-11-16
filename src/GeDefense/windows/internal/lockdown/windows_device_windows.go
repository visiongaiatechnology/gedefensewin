// STATUS: PLATIN VGT SUPREME
//go:build windows

package lockdown

// Production device adapter (CfgMgr32 / cfgmgr32.dll).
//
//   - ListDevices enumerates the USB device nodes with
//     CM_Get_Device_ID_ListW and derives the interface class codes from the
//     devnode compatible IDs ("USB\Class_XX&..."). Each interface node is
//     classified independently, which is exactly the enforcement target of a
//     composite BadUSB device: the HID node stays usable, the storage/vendor node
//     is disabled.
//   - DisableDevice / EnableDevice call CM_Disable_DevNode / CM_Enable_DevNode.
//     Both are the real API; on a machine without the required privileges the
//     adapter returns the real CONFIGRET error and the phase reports FAILED. It
//     never reports a fake success.
//   - DeviceEnabled reads CM_Get_DevNode_Status back (DN_STARTED without
//     DN_HAS_PROBLEM).

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	configretSuccess            = 0x00000000
	configretBufferSmall        = 0x0000001a
	configretNoSuchValue        = 0x00000025
	cmGetIDListFilterEnumerator = 0x00000001
	cmDRPCompatibleIDs          = 0x00000002
	dnStarted                   = 0x00000008
	dnHasProblem                = 0x00000400
	dnPrivateProblem            = 0x00008000
	maxDeviceIDListUnits        = 1 << 16
	maxDevicePropertyBytes      = 8192
	maxCompatibleIDs            = 64
	maxClassCodesPerDevice      = 16
)

var (
	cfgmgr32 = syscall.NewLazyDLL("cfgmgr32.dll")

	procCMGetDeviceIDListSizeW        = cfgmgr32.NewProc("CM_Get_Device_ID_List_SizeW")
	procCMGetDeviceIDListW            = cfgmgr32.NewProc("CM_Get_Device_ID_ListW")
	procCMLocateDevNodeW              = cfgmgr32.NewProc("CM_Locate_DevNodeW")
	procCMGetDevNodeStatus            = cfgmgr32.NewProc("CM_Get_DevNode_Status")
	procCMGetDevNodeRegistryPropertyW = cfgmgr32.NewProc("CM_Get_DevNode_Registry_PropertyW")
	procCMDisableDevNode              = cfgmgr32.NewProc("CM_Disable_DevNode")
	procCMEnableDevNode               = cfgmgr32.NewProc("CM_Enable_DevNode")
)

var _ DeviceController = (*WindowsDeviceController)(nil)

// WindowsDeviceController is the production CfgMgr32 DeviceController.
type WindowsDeviceController struct{}

// NewWindowsDeviceController returns the CfgMgr32 device adapter.
func NewWindowsDeviceController() *WindowsDeviceController { return &WindowsDeviceController{} }

// ListDevices enumerates the bounded USB device node list with its class codes.
func (c *WindowsDeviceController) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	filter, err := syscall.UTF16PtrFromString("USB")
	if err != nil {
		return nil, fmt.Errorf("USB enumerator filter: %w", err)
	}
	var length uint32
	code, _, _ := procCMGetDeviceIDListSizeW.Call(
		uintptr(unsafe.Pointer(&length)),
		uintptr(unsafe.Pointer(filter)),
		uintptr(cmGetIDListFilterEnumerator),
	)
	if code != configretSuccess {
		return nil, configRET("CM_Get_Device_ID_List_SizeW", code)
	}
	if length == 0 {
		return []DeviceInfo{}, nil
	}
	if length > maxDeviceIDListUnits {
		return nil, fmt.Errorf("CM_Get_Device_ID_List_SizeW returned an oversized list (%d units)", length)
	}
	buffer := make([]uint16, length)
	code, _, _ = procCMGetDeviceIDListW.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(length),
		uintptr(cmGetIDListFilterEnumerator),
	)
	runtime.KeepAlive(buffer)
	if code != configretSuccess {
		return nil, configRET("CM_Get_Device_ID_ListW", code)
	}
	instanceIDs := splitUTF16MultiSZ(buffer)
	devices := make([]DeviceInfo, 0, minInt(len(instanceIDs), MaxPhaseTargets))
	for _, instanceID := range instanceIDs {
		if len(devices) >= MaxPhaseTargets {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("device enumeration interrupted: %w", err)
		}
		if !validInstanceID(instanceID) {
			continue
		}
		device, infoErr := windowsDeviceInfo(instanceID)
		if infoErr != nil {
			// A devnode that disappeared between listing and inspection is
			// skipped; it is not silently reported as blocked.
			continue
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// DisableDevice disables one devnode.
func (c *WindowsDeviceController) DisableDevice(ctx context.Context, instanceID string) error {
	devnode, err := locateDevNode(ctx, instanceID)
	if err != nil {
		return err
	}
	code, _, _ := procCMDisableDevNode.Call(uintptr(devnode), 0)
	if code != configretSuccess {
		return configRET("CM_Disable_DevNode("+instanceID+")", code)
	}
	return nil
}

// EnableDevice enables one devnode.
func (c *WindowsDeviceController) EnableDevice(ctx context.Context, instanceID string) error {
	devnode, err := locateDevNode(ctx, instanceID)
	if err != nil {
		return err
	}
	code, _, _ := procCMEnableDevNode.Call(uintptr(devnode), 0)
	if code != configretSuccess {
		return configRET("CM_Enable_DevNode("+instanceID+")", code)
	}
	return nil
}

// DeviceEnabled reads the devnode status back.
func (c *WindowsDeviceController) DeviceEnabled(ctx context.Context, instanceID string) (bool, error) {
	devnode, err := locateDevNode(ctx, instanceID)
	if err != nil {
		return false, err
	}
	return devNodeEnabled(devnode)
}

// windowsDeviceInfo inspects one device node.
func windowsDeviceInfo(instanceID string) (DeviceInfo, error) {
	devnode, err := locateDevNode(context.Background(), instanceID)
	if err != nil {
		return DeviceInfo{}, err
	}
	enabled, err := devNodeEnabled(devnode)
	if err != nil {
		return DeviceInfo{}, err
	}
	device := DeviceInfo{InstanceID: instanceID, Enabled: enabled, DeviceClass: 0x00}
	raw, found, propertyErr := devNodeProperty(devnode, cmDRPCompatibleIDs)
	if propertyErr != nil {
		// Without the compatible IDs the device cannot be classified; the phase
		// must not fake a decision, so this is reported explicitly.
		device.ClassificationUnavailable = true
		return device, nil
	}
	if !found {
		return device, nil
	}
	device.InterfaceClasses = usbClassCodes(raw)
	return device, nil
}

// devNodeEnabled reads DN_STARTED / DN_HAS_PROBLEM.
func devNodeEnabled(devnode uint32) (bool, error) {
	var status, problem uint32
	code, _, _ := procCMGetDevNodeStatus.Call(
		uintptr(unsafe.Pointer(&status)),
		uintptr(unsafe.Pointer(&problem)),
		uintptr(devnode),
		0,
	)
	runtime.KeepAlive(&status)
	runtime.KeepAlive(&problem)
	if code != configretSuccess {
		return false, configRET("CM_Get_DevNode_Status", code)
	}
	enabled := status&dnStarted != 0 && status&dnHasProblem == 0 && status&dnPrivateProblem == 0
	return enabled, nil
}

// locateDevNode resolves one instance ID and validates the bounded input first.
func locateDevNode(ctx context.Context, instanceID string) (uint32, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	if !validInstanceID(instanceID) {
		return 0, fmt.Errorf("device instance ID is invalid")
	}
	pointer, err := syscall.UTF16PtrFromString(instanceID)
	if err != nil {
		return 0, fmt.Errorf("device instance ID: %w", err)
	}
	var devnode uint32
	code, _, _ := procCMLocateDevNodeW.Call(
		uintptr(unsafe.Pointer(&devnode)),
		uintptr(unsafe.Pointer(pointer)),
		0,
	)
	runtime.KeepAlive(pointer)
	runtime.KeepAlive(&devnode)
	if code != configretSuccess {
		return 0, configRET("CM_Locate_DevNodeW("+instanceID+")", code)
	}
	return devnode, nil
}

// devNodeProperty reads one device registry property of a devnode.
func devNodeProperty(devnode uint32, property uint32) ([]byte, bool, error) {
	var dataType uint32
	var size uint32
	code, _, _ := procCMGetDevNodeRegistryPropertyW.Call(
		uintptr(devnode), uintptr(property),
		uintptr(unsafe.Pointer(&dataType)),
		0, uintptr(unsafe.Pointer(&size)), 0,
	)
	if code == configretNoSuchValue {
		return nil, false, nil
	}
	if code != configretBufferSmall && code != configretSuccess {
		return nil, false, configRET("CM_Get_DevNode_Registry_PropertyW", code)
	}
	if size == 0 {
		return nil, false, nil
	}
	if size > maxDevicePropertyBytes {
		return nil, false, fmt.Errorf("device property exceeds its bound")
	}
	buffer := make([]byte, size)
	code, _, _ = procCMGetDevNodeRegistryPropertyW.Call(
		uintptr(devnode), uintptr(property),
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)), 0,
	)
	runtime.KeepAlive(buffer)
	if code != configretSuccess {
		return nil, false, configRET("CM_Get_DevNode_Registry_PropertyW", code)
	}
	return buffer, true, nil
}

// usbClassCodes extracts the numeric USB interface classes from the compatible
// IDs of one devnode ("USB\Class_03&SubClass_01&Prot_01").
func usbClassCodes(raw []byte) []uint8 {
	entries := utf16MultiSZFromBytes(raw)
	classes := make([]uint8, 0, 2)
	for _, entry := range entries {
		if len(classes) >= maxClassCodesPerDevice {
			break
		}
		upper := strings.ToUpper(strings.TrimSpace(entry))
		if !strings.HasPrefix(upper, `USB\CLASS_`) {
			continue
		}
		if len(upper) < 12 {
			continue
		}
		value, err := strconv.ParseUint(upper[10:12], 16, 8)
		if err != nil {
			continue
		}
		classes = append(classes, uint8(value))
	}
	return classes
}

// splitUTF16MultiSZ decodes a bounded MULTI_SZ buffer.
func splitUTF16MultiSZ(buffer []uint16) []string {
	entries := make([]string, 0, 32)
	start := 0
	for index, unit := range buffer {
		if unit != 0 {
			continue
		}
		if index > start {
			entries = append(entries, syscall.UTF16ToString(buffer[start:index]))
		}
		start = index + 1
	}
	return entries
}

// utf16MultiSZFromBytes decodes a bounded little-endian MULTI_SZ byte buffer.
func utf16MultiSZFromBytes(raw []byte) []string {
	units := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		units = append(units, uint16(raw[index])|uint16(raw[index+1])<<8)
	}
	entries := splitUTF16MultiSZ(units)
	if len(entries) > maxCompatibleIDs {
		return entries[:maxCompatibleIDs]
	}
	return entries
}

// configRET converts a CONFIGRET code into a bounded error.
func configRET(call string, code uintptr) error {
	return fmt.Errorf("%s failed with CONFIGRET 0x%x", call, code)
}

// minInt returns the smaller of two ints.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
