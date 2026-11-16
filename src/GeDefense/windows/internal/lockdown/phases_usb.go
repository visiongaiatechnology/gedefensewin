// STATUS: PLATIN VGT SUPREME

package lockdown

// USB and Thunderbolt phases.
//
// Both phases are thin orchestration around an injected controller that owns the
// actual Windows device action (CfgMgr32 CM_Disable_DevNode / CM_Enable_DevNode
// in windows_device_windows.go, a fake in tests). The phase never claims a block
// it could not read back. The pure classification lives in usb_policy.go.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	// USBPhaseMaxDevices bounds one device enumeration.
	USBPhaseMaxDevices = 256
	// MaxInstanceIDBytes bounds one Windows device instance ID.
	MaxInstanceIDBytes = 512
)

// DeviceInfo is one enumerable PnP device node.
type DeviceInfo struct {
	InstanceID                string
	InterfaceClasses          []uint8
	DeviceClass               uint8
	DeclaredInterfaceCount    int
	Description               string
	Enabled                   bool
	ClassificationUnavailable bool
}

// DeviceController is the injected device interface. The production adapter uses
// CfgMgr32; tests inject a fake.
type DeviceController interface {
	ListDevices(ctx context.Context) ([]DeviceInfo, error)
	DisableDevice(ctx context.Context, instanceID string) error
	EnableDevice(ctx context.Context, instanceID string) error
	DeviceEnabled(ctx context.Context, instanceID string) (bool, error)
}

// USBPhase applies the composite-BadUSB policy.
type USBPhase struct {
	Controller DeviceController
	timeout    time.Duration
}

// NewUSBPhase returns the USB phase. A nil controller produces the honest
// NOT_IMPLEMENTED result.
func NewUSBPhase(controller DeviceController) *USBPhase {
	return &USBPhase{Controller: controller, timeout: DefaultPhaseTimeout}
}

func (p *USBPhase) Name() PhaseName        { return PhaseUSB }
func (p *USBPhase) Timeout() time.Duration { return p.timeout }

// Engage disables every device the classifier blocks and verifies the read-back.
func (p *USBPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseUSB}
	if p.Controller == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: no Windows device controller is attached; the USB policy requires CfgMgr32"
		return result
	}
	devices, err := p.Controller.ListDevices(ctx)
	if err != nil {
		result.Status = PhaseUnavailable
		result.Detail = truncateText("USB device enumeration failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	var blocked, verified, failed, unsupported int
	bounded := false
	for index := range devices {
		device := devices[index]
		if blocked >= MaxPhaseTargets {
			bounded = true
			break
		}
		if !validInstanceID(device.InstanceID) {
			unsupported++
			continue
		}
		if device.ClassificationUnavailable {
			// Without the class data no safe decision is possible. The device is
			// not touched and the phase says so instead of claiming a block.
			unsupported++
			continue
		}
		verdict := ClassifyUSBDevice(USBDevice{
			Class: device.DeviceClass, Interfaces: device.InterfaceClasses,
			DeclaredInterfaceCount: device.DeclaredInterfaceCount,
		}, true)
		if !verdict.Blocks() {
			continue
		}
		blocked++
		if err := p.Controller.DisableDevice(ctx, device.InstanceID); err != nil {
			failed++
			continue
		}
		enabled, readBackErr := p.Controller.DeviceEnabled(ctx, device.InstanceID)
		if readBackErr != nil || enabled {
			failed++
			continue
		}
		verified++
	}
	result.Targets = verified
	detail := fmt.Sprintf("blocked=%d verified=%d failed=%d unsupported=%d", blocked, verified, failed, unsupported)
	if bounded {
		detail = appendDetail(detail, "bounded to max targets")
	}
	switch {
	case blocked == 0 && unsupported == 0:
		result.Status = PhaseApplied
		detail = appendDetail(detail, "no composite/data USB device present")
	case failed > 0 && verified == 0:
		result.Status = PhaseFailed
	case failed > 0 || unsupported > 0:
		result.Status = PhasePartial
	default:
		result.Status = PhaseApplied
	}
	result.Detail = truncateText(detail, MaxDetailBytes)
	return result
}

// Release re-enables every device the locked policy classifies as blocked. It is
// classification-based and therefore idempotent across a restart.
func (p *USBPhase) Release(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseUSB}
	if p.Controller == nil {
		result.Status = PhaseApplied
		result.Detail = "nothing to release: no device controller is attached"
		return result
	}
	devices, err := p.Controller.ListDevices(ctx)
	if err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("USB device enumeration failed during release: "+err.Error(), MaxDetailBytes)
		return result
	}
	var enabled, failed, unsupported int
	for index := range devices {
		device := devices[index]
		if !validInstanceID(device.InstanceID) || device.ClassificationUnavailable {
			unsupported++
			continue
		}
		verdict := ClassifyUSBDevice(USBDevice{
			Class: device.DeviceClass, Interfaces: device.InterfaceClasses,
			DeclaredInterfaceCount: device.DeclaredInterfaceCount,
		}, true)
		if !verdict.Blocks() {
			continue
		}
		if err := p.Controller.EnableDevice(ctx, device.InstanceID); err != nil {
			failed++
			continue
		}
		readBack, readBackErr := p.Controller.DeviceEnabled(ctx, device.InstanceID)
		if readBackErr != nil || !readBack {
			failed++
			continue
		}
		enabled++
	}
	result.Targets = enabled
	detail := fmt.Sprintf("re-enabled=%d failed=%d unclassified=%d", enabled, failed, unsupported)
	switch {
	case failed > 0 && enabled == 0:
		result.Status = PhaseFailed
	case failed > 0 || unsupported > 0:
		result.Status = PhasePartial
	default:
		result.Status = PhaseApplied
		if enabled == 0 {
			detail = appendDetail(detail, "no blocked USB device was present")
		}
	}
	result.Detail = truncateText(detail, MaxDetailBytes)
	return result
}

// Verify reads the locked policy back: every blocked device must be disabled.
func (p *USBPhase) Verify(ctx context.Context) error {
	if p.Controller == nil {
		return fmt.Errorf("%w: no device controller is attached", ErrPhaseUnsupported)
	}
	devices, err := p.Controller.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("USB verify enumeration failed: %w", err)
	}
	for index := range devices {
		device := devices[index]
		if !validInstanceID(device.InstanceID) {
			continue
		}
		if device.ClassificationUnavailable {
			return fmt.Errorf("USB verify: device %s could not be classified", device.InstanceID)
		}
		verdict := ClassifyUSBDevice(USBDevice{
			Class: device.DeviceClass, Interfaces: device.InterfaceClasses,
			DeclaredInterfaceCount: device.DeclaredInterfaceCount,
		}, true)
		if !verdict.Blocks() {
			continue
		}
		enabled, enabledErr := p.Controller.DeviceEnabled(ctx, device.InstanceID)
		if enabledErr != nil {
			return fmt.Errorf("USB verify: device %s read-back failed: %w", device.InstanceID, enabledErr)
		}
		if enabled {
			return fmt.Errorf("USB verify: blocked device %s is still enabled", device.InstanceID)
		}
	}
	return nil
}

// ThunderboltDevice is one enumerable Thunderbolt device.
type ThunderboltDevice struct {
	InstanceID  string
	Authorized  bool
	Description string
}

// ThunderboltController is the injected Thunderbolt DMA interface. V6 phase 1
// has no production implementation: Windows does not expose a supported
// non-administrative authorization API, so the phase reports NOT_IMPLEMENTED
// instead of faking success.
type ThunderboltController interface {
	ListDevices(ctx context.Context) ([]ThunderboltDevice, error)
	SetAuthorized(ctx context.Context, instanceID string, authorized bool) error
	DeviceAuthorized(ctx context.Context, instanceID string) (bool, error)
}

// ThunderboltPhase applies the Thunderbolt DMA policy.
type ThunderboltPhase struct {
	Controller ThunderboltController
	timeout    time.Duration
}

// NewThunderboltPhase returns the TB phase.
func NewThunderboltPhase(controller ThunderboltController) *ThunderboltPhase {
	return &ThunderboltPhase{Controller: controller, timeout: DefaultPhaseTimeout}
}

func (p *ThunderboltPhase) Name() PhaseName        { return PhaseThunderbolt }
func (p *ThunderboltPhase) Timeout() time.Duration { return p.timeout }

// Engage de-authorizes every enumerated Thunderbolt device.
func (p *ThunderboltPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseThunderbolt}
	if p.Controller == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: Thunderbolt DMA authorization has no supported non-administrative Windows API in V6 phase 1"
		return result
	}
	devices, err := p.Controller.ListDevices(ctx)
	if err != nil {
		result.Status = PhaseUnavailable
		result.Detail = truncateText("Thunderbolt enumeration failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	var blocked, verified, failed int
	for index := range devices {
		device := devices[index]
		if blocked >= MaxPhaseTargets {
			break
		}
		if !validInstanceID(device.InstanceID) {
			continue
		}
		blocked++
		if !device.Authorized {
			verified++
			continue
		}
		if err := p.Controller.SetAuthorized(ctx, device.InstanceID, false); err != nil {
			failed++
			continue
		}
		authorized, readBackErr := p.Controller.DeviceAuthorized(ctx, device.InstanceID)
		if readBackErr != nil || authorized {
			failed++
			continue
		}
		verified++
	}
	result.Targets = verified
	detail := fmt.Sprintf("de-authorized=%d failed=%d", verified, failed)
	switch {
	case blocked == 0:
		result.Status = PhaseApplied
		detail = appendDetail(detail, "no Thunderbolt device present")
	case failed > 0 && verified == 0:
		result.Status = PhaseFailed
	case failed > 0:
		result.Status = PhasePartial
	default:
		result.Status = PhaseApplied
	}
	result.Detail = truncateText(detail, MaxDetailBytes)
	return result
}

// Release re-authorizes every enumerated Thunderbolt device.
func (p *ThunderboltPhase) Release(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseThunderbolt}
	if p.Controller == nil {
		result.Status = PhaseApplied
		result.Detail = "nothing to release: no Thunderbolt controller is attached"
		return result
	}
	devices, err := p.Controller.ListDevices(ctx)
	if err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("Thunderbolt enumeration failed during release: "+err.Error(), MaxDetailBytes)
		return result
	}
	var enabled, failed int
	for index := range devices {
		device := devices[index]
		if !validInstanceID(device.InstanceID) {
			continue
		}
		if err := p.Controller.SetAuthorized(ctx, device.InstanceID, true); err != nil {
			failed++
			continue
		}
		authorized, readBackErr := p.Controller.DeviceAuthorized(ctx, device.InstanceID)
		if readBackErr != nil || !authorized {
			failed++
			continue
		}
		enabled++
	}
	result.Targets = enabled
	detail := fmt.Sprintf("re-authorized=%d failed=%d", enabled, failed)
	switch {
	case failed > 0 && enabled == 0:
		result.Status = PhaseFailed
	case failed > 0:
		result.Status = PhasePartial
	default:
		result.Status = PhaseApplied
	}
	result.Detail = truncateText(detail, MaxDetailBytes)
	return result
}

// Verify reads the DMA policy back.
func (p *ThunderboltPhase) Verify(ctx context.Context) error {
	if p.Controller == nil {
		return fmt.Errorf("%w: no Thunderbolt controller is attached", ErrPhaseUnsupported)
	}
	devices, err := p.Controller.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("Thunderbolt verify enumeration failed: %w", err)
	}
	for index := range devices {
		device := devices[index]
		if !validInstanceID(device.InstanceID) {
			continue
		}
		authorized, readBackErr := p.Controller.DeviceAuthorized(ctx, device.InstanceID)
		if readBackErr != nil {
			return fmt.Errorf("Thunderbolt verify: device %s read-back failed: %w", device.InstanceID, readBackErr)
		}
		if authorized {
			return fmt.Errorf("Thunderbolt verify: device %s is still authorized", device.InstanceID)
		}
	}
	return nil
}

// validInstanceID bounds one device instance ID.
func validInstanceID(instanceID string) bool {
	if instanceID == "" || len(instanceID) > MaxInstanceIDBytes {
		return false
	}
	for _, char := range instanceID {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return strings.TrimSpace(instanceID) == instanceID
}
