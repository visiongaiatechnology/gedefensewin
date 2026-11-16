// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func validateObservedProcess(event ProcessEvent) error {
	identity, err := openObservedProcess(event, false)
	if err != nil {
		return err
	}
	return identity.Close()
}

func terminateProcess(event ProcessEvent) (err error) {
	if IsProtectedOSProcess(event.Image, event.ImagePath) {
		return errors.New("protected operating-system process: kinetic response rejected")
	}
	identity, err := openObservedProcess(event, true)
	if err != nil {
		return err
	}
	defer cleanup.CloseInto(&err, &identity)
	if err := identity.Terminate(0xC0000420); err != nil {
		return fmt.Errorf("terminate observed process: %w", err)
	}
	return nil
}

// terminateTargetVerified is the cross-engine kinetic response seam. The
// requesting engine (Titan) only knows the PID that its own sensors attributed
// to a compromised persistence observation. This function therefore requires
// full identity evidence in the request, re-opens the live process, proves that
// the identity still matches, rejects protected operating-system processes and
// the product's own tree, and only then terminates.
//
// A request without creation time or image path is rejected outright: a bare
// PID is not evidence. Without this gate a temporal heuristic could kill an
// unrelated process through PID reuse, including SYSTEM and Defender services.
func (e *Engine) terminateTargetVerified(target TerminationTarget) error {
	if target.PID <= 4 {
		return errors.New("pid boundary rejected")
	}
	if target.CreationUnixNano <= 0 {
		return errors.New("process identity incomplete: creation time missing")
	}
	if strings.TrimSpace(target.ImagePath) == "" {
		return errors.New("process identity incomplete: image path missing")
	}
	if IsProtectedOSProcess("", target.ImagePath) {
		return errors.New("protected operating-system process: kinetic response rejected")
	}
	identity, err := winapi.OpenProcessIdentity(target.PID, true)
	if err != nil {
		return fmt.Errorf("open process %d: %w", target.PID, err)
	}
	defer func() { _ = identity.Close() }()
	if identity.CreationUnixNano <= 0 || strings.TrimSpace(identity.ImagePath) == "" {
		return errors.New("process identity incomplete")
	}
	difference := time.Duration(identity.CreationUnixNano - target.CreationUnixNano)
	if difference < 0 {
		difference = -difference
	}
	if difference > 2*time.Second {
		return errors.New("process identity changed before response: creation time mismatch")
	}
	if !winapi.SameImagePath(identity.ImagePath, target.ImagePath) {
		return errors.New("process image changed before response: image path mismatch")
	}
	if IsProtectedOSProcess("", identity.ImagePath) {
		return errors.New("protected operating-system process: kinetic response rejected")
	}
	if isGeDefenseBinary(identity.ImagePath) {
		return errors.New("self-protection: GeDefense process termination rejected")
	}
	if err := identity.Terminate(0xC0000420); err != nil {
		return fmt.Errorf("terminate pid %d: %w", target.PID, err)
	}
	return nil
}

func openObservedProcess(event ProcessEvent, terminate bool) (winapi.ProcessIdentity, error) {
	if event.PID <= 4 || event.CreationUTC.IsZero() || event.ImagePath == "" {
		return winapi.ProcessIdentity{}, errors.New("process identity boundary rejected")
	}
	identity, err := winapi.OpenProcessIdentity(event.PID, terminate)
	if err != nil {
		return winapi.ProcessIdentity{}, err
	}
	difference := time.Duration(identity.CreationUnixNano - event.CreationUTC.UnixNano())
	if difference < 0 {
		difference = -difference
	}
	// CIM timestamps and GetProcessTimes can differ slightly in representation.
	// A two-second tolerance preserves identity validation without accepting PID reuse.
	if difference > 2*time.Second {
		return winapi.ProcessIdentity{}, errors.Join(errors.New("process identity changed before response"), identity.Close())
	}
	if !winapi.SameImagePath(identity.ImagePath, event.ImagePath) {
		return winapi.ProcessIdentity{}, errors.Join(errors.New("process image changed before response"), identity.Close())
	}
	return identity, nil
}
