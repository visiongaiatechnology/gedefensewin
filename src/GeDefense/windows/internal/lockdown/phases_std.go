// STATUS: PLATIN VGT SUPREME

package lockdown

// Network, hardening, session and device-mapper phases plus the standard phase
// factory.
//
// Only the session phase has a complete production adapter in V6 phase 1
// (LockWorkStation + WTSDisconnectSession). The network, hardening and BitLocker
// DeviceMapper actions require administrator privileges and a far wider action
// surface; their interfaces exist and the default implementations return the
// documented NOT_IMPLEMENTED error instead of faking success.

import (
	"context"
	"fmt"
	"time"
)

// NetworkController is the injected network isolation interface.
type NetworkController interface {
	Block(ctx context.Context, allowLoopback bool) error
	Release(ctx context.Context) error
	Blocked(ctx context.Context) (bool, error)
}

// NetworkPhase applies the network isolation.
type NetworkPhase struct {
	Controller    NetworkController
	AllowLoopback bool
	timeout       time.Duration
}

// NewNetworkPhase returns the NET phase.
func NewNetworkPhase(controller NetworkController, allowLoopback bool) *NetworkPhase {
	return &NetworkPhase{Controller: controller, AllowLoopback: allowLoopback, timeout: DefaultPhaseTimeout}
}

func (p *NetworkPhase) Name() PhaseName        { return PhaseNetwork }
func (p *NetworkPhase) Timeout() time.Duration { return p.timeout }

// Engage blocks outbound traffic.
func (p *NetworkPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseNetwork}
	if p.Controller == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: the Windows Filtering Platform requires administrator privileges; no unprivileged network lockdown exists in V6 phase 1"
		return result
	}
	if err := p.Controller.Block(ctx, p.AllowLoopback); err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("network block failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Targets = 1
	result.Status = PhaseApplied
	result.Detail = "network isolation acknowledged"
	if p.AllowLoopback {
		result.Detail = "network isolation acknowledged; loopback allowed"
	}
	return result
}

// Release removes the network isolation.
func (p *NetworkPhase) Release(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseNetwork}
	if p.Controller == nil {
		result.Status = PhaseApplied
		result.Detail = "nothing to release: no network controller is attached"
		return result
	}
	if err := p.Controller.Release(ctx); err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("network release failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Status = PhaseApplied
	result.Detail = "network isolation released"
	return result
}

// Verify reads the network isolation back.
func (p *NetworkPhase) Verify(ctx context.Context) error {
	if p.Controller == nil {
		return fmt.Errorf("%w: no network controller is attached", ErrPhaseUnsupported)
	}
	blocked, err := p.Controller.Blocked(ctx)
	if err != nil {
		return fmt.Errorf("network verify failed: %w", err)
	}
	if !blocked {
		return fmt.Errorf("network verify: isolation is not in force")
	}
	return nil
}

// HardeningController is the injected reversible hardening interface.
type HardeningController interface {
	Apply(ctx context.Context) error
	Verify(ctx context.Context) error
	Revert(ctx context.Context) error
}

// HardeningPhase applies the allowlisted reversible hardening profile.
type HardeningPhase struct {
	Controller HardeningController
	timeout    time.Duration
}

// NewHardeningPhase returns the HARDENING phase.
func NewHardeningPhase(controller HardeningController) *HardeningPhase {
	return &HardeningPhase{Controller: controller, timeout: DefaultPhaseTimeout}
}

func (p *HardeningPhase) Name() PhaseName        { return PhaseHardening }
func (p *HardeningPhase) Timeout() time.Duration { return p.timeout }

// Engage applies the hardening profile.
func (p *HardeningPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseHardening}
	if p.Controller == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: no reversible Windows hardening profile is implemented in V6 phase 1"
		return result
	}
	if err := p.Controller.Apply(ctx); err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("hardening apply failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Targets = 1
	result.Status = PhaseApplied
	result.Detail = "hardening profile applied"
	return result
}

// Release reverts the hardening profile.
func (p *HardeningPhase) Release(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseHardening}
	if p.Controller == nil {
		result.Status = PhaseApplied
		result.Detail = "nothing to release: no hardening controller is attached"
		return result
	}
	if err := p.Controller.Revert(ctx); err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("hardening revert failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Status = PhaseApplied
	result.Detail = "hardening profile reverted"
	return result
}

// Verify reads the hardening profile back.
func (p *HardeningPhase) Verify(ctx context.Context) error {
	if p.Controller == nil {
		return fmt.Errorf("%w: no hardening controller is attached", ErrPhaseUnsupported)
	}
	if err := p.Controller.Verify(ctx); err != nil {
		return fmt.Errorf("hardening verify failed: %w", err)
	}
	return nil
}

// SessionController is the injected session interface (WTS + LockWorkStation).
type SessionController interface {
	Lock(ctx context.Context) error
	Locked(ctx context.Context) (bool, error)
	DisconnectAll(ctx context.Context) (int, error)
}

// SessionsPhase disconnects remote sessions and locks the workstation.
type SessionsPhase struct {
	Controller SessionController
	timeout    time.Duration
}

// NewSessionsPhase returns the SESSIONS phase.
func NewSessionsPhase(controller SessionController) *SessionsPhase {
	return &SessionsPhase{Controller: controller, timeout: DefaultPhaseTimeout}
}

func (p *SessionsPhase) Name() PhaseName        { return PhaseSessions }
func (p *SessionsPhase) Timeout() time.Duration { return p.timeout }

// Engage disconnects the active remote sessions and locks the workstation.
func (p *SessionsPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseSessions}
	if p.Controller == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: no Windows session controller is attached; sessions require LockWorkStation/WTSDisconnectSession"
		return result
	}
	disconnected, disconnectErr := p.Controller.DisconnectAll(ctx)
	lockErr := p.Controller.Lock(ctx)
	if lockErr != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText(fmt.Sprintf("workstation lock failed (disconnected=%d): %v", disconnected, lockErr), MaxDetailBytes)
		return result
	}
	result.Targets = disconnected
	if disconnectErr != nil {
		result.Status = PhasePartial
		result.Detail = truncateText(fmt.Sprintf("workstation locked; remote session disconnect incomplete: %v", disconnectErr), MaxDetailBytes)
		return result
	}
	result.Status = PhaseApplied
	result.Detail = fmt.Sprintf("workstation locked; disconnected=%d remote session(s)", disconnected)
	return result
}

// Release reports the honest fact that a workstation lock is not released by
// the engine: the operator unlocks interactively.
func (p *SessionsPhase) Release(context.Context) PhaseResult {
	return PhaseResult{Phase: PhaseSessions, Status: PhaseApplied, Detail: "nothing to release: the workstation lock is released by the operator"}
}

// Verify reads the lock state back.
func (p *SessionsPhase) Verify(ctx context.Context) error {
	if p.Controller == nil {
		return fmt.Errorf("%w: no session controller is attached", ErrPhaseUnsupported)
	}
	locked, err := p.Controller.Locked(ctx)
	if err != nil {
		return fmt.Errorf("session verify failed: %w", err)
	}
	if !locked {
		return fmt.Errorf("session verify: the workstation is not locked")
	}
	return nil
}

// DeviceMapperController is the injected BitLocker ForceRecovery interface.
type DeviceMapperController interface {
	ForceRecovery(ctx context.Context) error
	VerifyForcedRecovery(ctx context.Context) error
	ReleaseRecovery(ctx context.Context) error
}

// DeviceMapperPhase is the optional destructive DM phase.
type DeviceMapperPhase struct {
	Controller DeviceMapperController
	timeout    time.Duration
}

// NewDeviceMapperPhase returns the DM phase.
func NewDeviceMapperPhase(controller DeviceMapperController) *DeviceMapperPhase {
	return &DeviceMapperPhase{Controller: controller, timeout: DefaultPhaseTimeout}
}

func (p *DeviceMapperPhase) Name() PhaseName        { return PhaseDeviceMapper }
func (p *DeviceMapperPhase) Timeout() time.Duration { return p.timeout }

// Engage forces BitLocker recovery.
func (p *DeviceMapperPhase) Engage(ctx context.Context) PhaseResult {
	result := PhaseResult{Phase: PhaseDeviceMapper}
	if p.Controller == nil {
		result.Status = PhaseUnavailable
		result.Detail = "NOT_IMPLEMENTED: BitLocker ForceRecovery requires administrative WMI/COM access; the DM phase is off by default"
		return result
	}
	if err := p.Controller.ForceRecovery(ctx); err != nil {
		result.Status = PhaseFailed
		result.Detail = truncateText("BitLocker ForceRecovery failed: "+err.Error(), MaxDetailBytes)
		return result
	}
	result.Targets = 1
	result.Status = PhaseApplied
	result.Detail = "BitLocker recovery was forced; the volume is locked to the recovery key"
	return result
}

// Release reports that forced BitLocker recovery is not reversible by the
// engine.
func (p *DeviceMapperPhase) Release(context.Context) PhaseResult {
	return PhaseResult{
		Phase: PhaseDeviceMapper, Status: PhaseApplied,
		Detail: "BitLocker ForceRecovery is not reversible by the engine; the operator must recover the volume interactively",
	}
}

// Verify reads the forced-recovery state back.
func (p *DeviceMapperPhase) Verify(ctx context.Context) error {
	if p.Controller == nil {
		return fmt.Errorf("%w: no BitLocker controller is attached", ErrPhaseUnsupported)
	}
	if err := p.Controller.VerifyForcedRecovery(ctx); err != nil {
		return fmt.Errorf("BitLocker verify failed: %w", err)
	}
	return nil
}

// Dependencies are the injected Windows subsystem adapters of the standard phase
// set. Every nil adapter yields an honest NOT_IMPLEMENTED phase result.
type Dependencies struct {
	Clock         Clock
	Devices       DeviceController
	Thunderbolt   ThunderboltController
	Network       NetworkController
	Hardening     HardeningController
	Sessions      SessionController
	Processes     ProcessController
	DeviceMapper  DeviceMapperController
	AllowLoopback bool
}

// NewStandardPhases builds the phase subset selected by settings in the fixed
// engage order. engine.New requires the injected set to match the selection
// exactly, so callers must not pass the full set to an engine that selects less.
func NewStandardPhases(dependencies Dependencies, settings Settings) []Phase {
	all := map[PhaseName]Phase{
		PhaseNetwork:      NewNetworkPhase(dependencies.Network, dependencies.AllowLoopback),
		PhaseUSB:          NewUSBPhase(dependencies.Devices),
		PhaseThunderbolt:  NewThunderboltPhase(dependencies.Thunderbolt),
		PhaseHardening:    NewHardeningPhase(dependencies.Hardening),
		PhaseBrokers:      NewBrokersPhase(dependencies.Processes, dependencies.Clock),
		PhaseParsers:      NewUnsupportedPhase(PhaseParsers, "Windows has no parser-cell substrate; the Linux PARSERS phase does not apply"),
		PhaseSessions:     NewSessionsPhase(dependencies.Sessions),
		PhaseDeviceMapper: NewDeviceMapperPhase(dependencies.DeviceMapper),
	}
	selected := settings.selectedPhases()
	phases := make([]Phase, 0, len(selected))
	for _, name := range selected {
		if phase, present := all[name]; present {
			phases = append(phases, phase)
		}
	}
	return phases
}
