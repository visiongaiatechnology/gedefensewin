// STATUS: PLATIN VGT SUPREME
//go:build windows

package lockdown

// Read-only tests of the production Windows adapters. They never disable a real
// device, never suspend a real process and never lock the workstation: the
// identity and protection boundaries are exercised with values that are refused
// before any destructive API call.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestWindowsProcessControllerListsBoundedInventory(t *testing.T) {
	controller := NewWindowsProcessController()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	processes, err := controller.ListProcesses(ctx)
	if err != nil {
		t.Fatalf("process inventory: %v", err)
	}
	if len(processes) == 0 {
		t.Fatal("the process inventory is empty")
	}
	if len(processes) > processScanLimit {
		t.Fatalf("the inventory exceeds its bound: %d", len(processes))
	}
	ownPID := uint32(os.Getpid())
	foundOwn := false
	for _, process := range processes {
		if process.PID == 0 || process.Name == "" || process.CreationUnixNano <= 0 {
			t.Fatalf("invalid process inventory entry: %+v", process)
		}
		if process.PID == ownPID {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatal("the adapter did not report its own process")
	}
}

func TestWindowsProcessControllerRefusesProtectedAndReusedIdentities(t *testing.T) {
	controller := NewWindowsProcessController()
	if err := controller.Suspend(4, 1); !errors.Is(err, ErrProcessProtected) {
		t.Fatalf("pid 4 was not protected: %v", err)
	}
	if err := controller.Resume(2, 1); !errors.Is(err, ErrProcessProtected) {
		t.Fatalf("pid 2 was not protected: %v", err)
	}
	ownPID := uint32(os.Getpid())
	if err := controller.Suspend(ownPID, 1); !errors.Is(err, ErrProcessIdentityMismatch) {
		t.Fatalf("a wrong creation time was not refused: %v", err)
	}
	if err := controller.Suspend(ownPID, 0); !errors.Is(err, ErrProcessIdentityMismatch) {
		t.Fatalf("a missing creation time was not refused: %v", err)
	}
	// The identity check happens before NtSuspendProcess: the own process must
	// still run after every refused call.
	if _, err := controller.ListProcesses(context.Background()); err != nil {
		t.Fatalf("the process controller stopped working after the refusals: %v", err)
	}
}

func TestWindowsSessionControllerLockReadback(t *testing.T) {
	controller := NewWindowsSessionController()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	locked, err := controller.Locked(ctx)
	if err != nil {
		// A non-interactive session may not expose the input desktop. The honest
		// adapter reports the real error; the test documents the limitation.
		t.Skipf("input-desktop read-back is unavailable in this session: %v", err)
	}
	_ = locked
	// LockWorkStation is a real, disruptive action and is deliberately never called
	// by the test suite. Only the adapter wiring is asserted here.
}

func TestWindowsDeviceControllerEnumeratesAndRefusesInvalidIDs(t *testing.T) {
	controller := NewWindowsDeviceController()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	devices, err := controller.ListDevices(ctx)
	if err != nil {
		t.Fatalf("USB device enumeration: %v", err)
	}
	if len(devices) > MaxPhaseTargets {
		t.Fatalf("the device list exceeds its bound: %d", len(devices))
	}
	for _, device := range devices {
		if device.InstanceID == "" {
			t.Fatal("an enumerated device has no instance ID")
		}
		if len(device.InterfaceClasses) > maxClassCodesPerDevice {
			t.Fatalf("unexpected class code count: %d", len(device.InterfaceClasses))
		}
	}
	if err := controller.DisableDevice(ctx, `USB\BOGUS_INSTANCE`); err == nil {
		t.Fatal("an invalid instance ID was accepted for disable")
	}
	if err := controller.EnableDevice(ctx, `USB\BOGUS_INSTANCE`); err == nil {
		t.Fatal("an invalid instance ID was accepted for enable")
	}
	if _, err := controller.DeviceEnabled(ctx, `USB\BOGUS_INSTANCE`); err == nil {
		t.Fatal("an invalid instance ID was accepted for read-back")
	}
	if err := controller.DisableDevice(ctx, ""); err == nil {
		t.Fatal("an empty instance ID was accepted")
	}
}

func TestWindowsAdaptersSatisfyTheirInterfaces(t *testing.T) {
	var processController ProcessController = NewWindowsProcessController()
	var sessionController SessionController = NewWindowsSessionController()
	var deviceController DeviceController = NewWindowsDeviceController()
	if processController == nil || sessionController == nil || deviceController == nil {
		t.Fatal("a production adapter is missing")
	}
}

func TestWindowsDeviceClassCodeExtraction(t *testing.T) {
	raw := []byte{}
	for _, value := range []string{`USB\Class_03&SubClass_01&Prot_01`, `USB\Class_08&SubClass_06&Prot_50`, `USB\COMPOSITE`} {
		for _, char := range value {
			raw = append(raw, byte(char), 0)
		}
		raw = append(raw, 0, 0)
	}
	raw = append(raw, 0, 0)
	classes := usbClassCodes(raw)
	if len(classes) != 2 || classes[0] != 0x03 || classes[1] != 0x08 {
		t.Fatalf("unexpected class extraction: %v", classes)
	}
	if got := usbClassCodes(nil); len(got) != 0 {
		t.Fatalf("empty compatible IDs produced classes: %v", got)
	}
}
