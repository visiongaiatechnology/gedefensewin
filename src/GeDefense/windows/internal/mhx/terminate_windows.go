// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"errors"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func validateObservedProcess(event ProcessEvent) error {
	identity, err := openObservedProcess(event, false)
	if err != nil {
		return err
	}
	return identity.Close()
}

func terminateProcess(event ProcessEvent) error {
	identity, err := openObservedProcess(event, true)
	if err != nil {
		return err
	}
	defer identity.Close()
	if err := identity.Terminate(0xC0000420); err != nil {
		return fmt.Errorf("terminate observed process: %w", err)
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
		identity.Close()
		return winapi.ProcessIdentity{}, errors.New("process identity changed before response")
	}
	if !winapi.SameImagePath(identity.ImagePath, event.ImagePath) {
		identity.Close()
		return winapi.ProcessIdentity{}, errors.New("process image changed before response")
	}
	return identity, nil
}
