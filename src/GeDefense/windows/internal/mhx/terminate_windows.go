// STATUS: DIAMANT VGT SUPREME
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

// terminatePIDVerified is the Titan-correlation seam. Titan only knows the PID
// of the actor that caused a compromised persistence observation; unlike the
// file/process watchers it has no CIM creation timestamp or original image
// path. This function therefore re-opens the live process, derives and checks
// its identity itself, rejects GeDefense's own install tree, and terminates it.
// Limitation (documented): PID reuse between the Titan observation and this
// call cannot be fully excluded without a creation-time witness from Titan.
func terminatePIDVerified(pid uint32, reason string) error {
	if pid <= 4 {
		return errors.New("pid boundary rejected")
	}
	identity, err := winapi.OpenProcessIdentity(pid, true)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer func() { _ = identity.Close() }()
	if identity.CreationUnixNano <= 0 || strings.TrimSpace(identity.ImagePath) == "" {
		return errors.New("process identity incomplete")
	}
	if isGeDefenseBinary("", identity.ImagePath) {
		return errors.New("self-protection: GeDefense process termination rejected")
	}
	if err := identity.Terminate(0xC0000420); err != nil {
		return fmt.Errorf("terminate pid %d: %w", pid, err)
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
