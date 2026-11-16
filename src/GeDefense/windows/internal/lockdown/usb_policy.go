// STATUS: PLATIN VGT SUPREME

package lockdown

// Composite-BadUSB classification (port of the Linux arm-mode device policy
// matrix in rust/gedefense-core/src/lockdown_usb.rs).
//
// The classifier is pure: it takes the declared device class and the list of
// interface class codes and returns one verdict. It never opens a device and
// never touches the filesystem.
//
// The fail-safe matrix:
//
//	no interfaces                          -> AllowChargingOnly (cable/port)
//	only HID interfaces, class 0 or HID    -> AllowPureKeyboard
//	only hub interfaces, class 0 or hub    -> Allow
//	anything else (storage, CDC, vendor,
//	audio, composite HID+data, spoofed
//	device-level HID, partial enumeration) -> BlockBadUSB
//
// The unlocked arm mode is audit-only in the Linux engine, so the classifier
// returns Allow for it. Windows only executes the locked policy.

// USB class codes used by the matrix.
const (
	USBClassHID     uint8 = 0x03
	USBClassHub     uint8 = 0x09
	USBClassCDC     uint8 = 0x02
	USBClassStorage uint8 = 0x08
	USBClassVendor  uint8 = 0xff
)

// USBVerdict is the closed classification vocabulary.
type USBVerdict string

const (
	// AllowChargingOnly is a cable/charger/port: free, no block, no trigger.
	AllowChargingOnly USBVerdict = "allow-charging-only"
	// AllowPureKeyboard is a pure HID device: the local console stays usable.
	AllowPureKeyboard USBVerdict = "allow-pure-keyboard"
	// Allow is an explicitly allowed non-keyboard console device (hub) or any
	// device in the audit-only unlocked mode.
	Allow USBVerdict = "allow"
	// BlockBadUSB is a data-capable or composite device: blocked in lockdown.
	BlockBadUSB USBVerdict = "block-bad-usb"
)

// Blocks reports whether the verdict requires disabling the device.
func (v USBVerdict) Blocks() bool { return v == BlockBadUSB }

// USBDevice is the pure classifier input. DeclaredInterfaceCount is optional: a
// positive value that does not match the interface list is a partial (and
// therefore hostile) enumeration.
type USBDevice struct {
	Class                  uint8
	Interfaces             []uint8
	DeclaredInterfaceCount int
}

// ClassifyUSBDevice applies the fail-safe matrix. locked=false is the audit-only
// arm mode and always allows.
func ClassifyUSBDevice(device USBDevice, locked bool) USBVerdict {
	if !locked {
		return Allow
	}
	if len(device.Interfaces) == 0 {
		// A charger or a downstream port never enumerates an interface.
		return AllowChargingOnly
	}
	if device.DeclaredInterfaceCount > 0 && device.DeclaredInterfaceCount != len(device.Interfaces) {
		// Partial enumeration: the visible list is not the complete device.
		return BlockBadUSB
	}
	if allInterfaces(device.Interfaces, USBClassHID) &&
		(device.Class == 0x00 || device.Class == USBClassHID) {
		return AllowPureKeyboard
	}
	if allInterfaces(device.Interfaces, USBClassHub) &&
		(device.Class == 0x00 || device.Class == USBClassHub) {
		return Allow
	}
	// Everything else is either a data device or a composite device that hides a
	// data interface behind a console class.
	return BlockBadUSB
}

// allInterfaces reports whether every interface carries the same class.
func allInterfaces(interfaces []uint8, class uint8) bool {
	for _, candidate := range interfaces {
		if candidate != class {
			return false
		}
	}
	return len(interfaces) > 0
}
