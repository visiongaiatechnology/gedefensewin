// STATUS: PLATIN VGT SUPREME

package lockdown

import "testing"

func TestUSBClassifierFailSafeMatrix(t *testing.T) {
	cases := []struct {
		name    string
		device  USBDevice
		verdict USBVerdict
	}{
		{"charger-no-interface", USBDevice{Class: 0x00}, AllowChargingOnly},
		{"charger-despite-class", USBDevice{Class: USBClassStorage}, AllowChargingOnly},
		{"keyboard-interface-class", USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID}}, AllowPureKeyboard},
		{"keyboard-device-class", USBDevice{Class: USBClassHID, Interfaces: []uint8{USBClassHID}}, AllowPureKeyboard},
		{"keyboard-two-hid-interfaces", USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID, USBClassHID}}, AllowPureKeyboard},
		{"hub", USBDevice{Class: USBClassHub, Interfaces: []uint8{USBClassHub}}, Allow},
		{"hub-declared-at-interface", USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHub}}, Allow},
		{"storage", USBDevice{Class: USBClassStorage, Interfaces: []uint8{USBClassStorage}}, BlockBadUSB},
		{"cdc", USBDevice{Class: USBClassCDC, Interfaces: []uint8{USBClassCDC}}, BlockBadUSB},
		{"vendor", USBDevice{Class: USBClassVendor, Interfaces: []uint8{USBClassVendor}}, BlockBadUSB},
		{"audio", USBDevice{Class: 0x01, Interfaces: []uint8{0x01}}, BlockBadUSB},
		{"composite-hid-storage", USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID, USBClassStorage}}, BlockBadUSB},
		{"composite-hid-cdc", USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID, USBClassCDC}}, BlockBadUSB},
		{"composite-hid-vendor", USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID, USBClassVendor}}, BlockBadUSB},
		{"spoofed-hid-device-class", USBDevice{Class: USBClassHID, Interfaces: []uint8{USBClassHID, USBClassCDC}}, BlockBadUSB},
		{"unknown-interface-class", USBDevice{Class: 0x00, Interfaces: []uint8{0x00}}, BlockBadUSB},
		{"hub-with-data-interface", USBDevice{Class: USBClassHub, Interfaces: []uint8{USBClassHub, USBClassStorage}}, BlockBadUSB},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyUSBDevice(test.device, true); got != test.verdict {
				t.Fatalf("unexpected verdict: got %s want %s", got, test.verdict)
			}
		})
	}
}

func TestUSBClassifierPartialEnumerationBlocks(t *testing.T) {
	// The declared interface count does not match the visible list: a hostile
	// composite device hides an interface.
	device := USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID}, DeclaredInterfaceCount: 2}
	if got := ClassifyUSBDevice(device, true); got != BlockBadUSB {
		t.Fatalf("a partial enumeration was not blocked: %s", got)
	}
	complete := USBDevice{Class: 0x00, Interfaces: []uint8{USBClassHID}, DeclaredInterfaceCount: 1}
	if got := ClassifyUSBDevice(complete, true); got != AllowPureKeyboard {
		t.Fatalf("a complete enumeration was not allowed: %s", got)
	}
}

func TestUSBClassifierUnlockedModeIsAuditOnly(t *testing.T) {
	device := USBDevice{Class: USBClassStorage, Interfaces: []uint8{USBClassStorage}}
	if got := ClassifyUSBDevice(device, false); got != Allow {
		t.Fatalf("the audit-only arm mode must allow: %s", got)
	}
}

func TestUSBVerdictHelpers(t *testing.T) {
	if !BlockBadUSB.Blocks() {
		t.Fatal("BlockBadUSB must report Blocks")
	}
	for _, verdict := range []USBVerdict{Allow, AllowChargingOnly, AllowPureKeyboard} {
		if verdict.Blocks() {
			t.Fatalf("%s must not report Blocks", verdict)
		}
	}
}
