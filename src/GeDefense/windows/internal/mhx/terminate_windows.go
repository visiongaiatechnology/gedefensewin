// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"errors"
	"fmt"
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
