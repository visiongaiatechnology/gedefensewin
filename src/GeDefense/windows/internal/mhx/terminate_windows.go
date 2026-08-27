// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func terminateProcess(pid uint32) error {
	if pid <= 4 {
		return errors.New("protected process boundary")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := windows.TerminateProcess(handle, 0xC0000420); err != nil {
		return fmt.Errorf("terminate process: %w", err)
	}
	return nil
}
