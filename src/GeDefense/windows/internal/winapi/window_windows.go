// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	SW_HIDE            uint32 = 0
	SW_SHOWNORMAL      uint32 = 1
	SW_SHOWMINIMIZED   uint32 = 2
	SW_MAXIMIZE        uint32 = 3
	SW_SHOWNOACTIVATE  uint32 = 4
	SW_SHOW            uint32 = 5
	SW_MINIMIZE        uint32 = 6
	SW_SHOWMINNOACTIVE uint32 = 7
	SW_SHOWNA          uint32 = 8
	SW_RESTORE         uint32 = 9

	WM_CLOSE uint32 = 0x0010
)

var (
	procFindWindowW              = user32.NewProc("FindWindowW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procShowWindow               = user32.NewProc("ShowWindow")
	procIsZoomed                 = user32.NewProc("IsZoomed")
	procIsIconic                 = user32.NewProc("IsIconic")
	procPostMessageW             = user32.NewProc("PostMessageW")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
)

var ErrWindowNotFound = errors.New("no active GeDefense window found")

// FindGeDefenseWindow searches for the primary top-level window of GeDefense.
// It checks exact known title matches first, followed by a visible-window enumeration.
func FindGeDefenseWindow() (Handle, error) {
	exactTitles := []string{
		"GeDefense 4 · Windows Security Center",
		"GeDefense 4",
		"VGT GeDefense",
	}
	for _, title := range exactTitles {
		ptr, err := utf16Ptr(title)
		if err != nil {
			continue
		}
		hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(ptr)))
		if hwnd != 0 {
			if visible, _, _ := procIsWindowVisible.Call(hwnd); visible != 0 {
				return Handle(hwnd), nil
			}
		}
	}

	var matched Handle
	callback := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		if visible, _, _ := procIsWindowVisible.Call(hwnd); visible == 0 {
			return 1 // continue enumeration
		}
		buf := make([]uint16, 256)
		length, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
		if length > 0 {
			title := syscall.UTF16ToString(buf[:length])
			if strings.Contains(title, "GeDefense") {
				matched = Handle(hwnd)
				return 0 // stop enumeration
			}
		}
		return 1
	})
	procEnumWindows.Call(callback, 0)

	if matched != 0 {
		return matched, nil
	}
	return 0, ErrWindowNotFound
}

// MinimizeWindow minimizes the specified window.
func MinimizeWindow(hwnd Handle) error {
	if hwnd == 0 {
		return errors.New("invalid window handle")
	}
	result, _, _ := procShowWindow.Call(uintptr(hwnd), uintptr(SW_MINIMIZE))
	_ = result
	return nil
}

// MaximizeOrRestoreWindow toggles maximize/restore for the window.
// Returns true if the window became maximized, false if restored.
func MaximizeOrRestoreWindow(hwnd Handle) (bool, error) {
	if hwnd == 0 {
		return false, errors.New("invalid window handle")
	}
	zoomed, _, _ := procIsZoomed.Call(uintptr(hwnd))
	if zoomed != 0 {
		procShowWindow.Call(uintptr(hwnd), uintptr(SW_RESTORE))
		return false, nil
	}
	procShowWindow.Call(uintptr(hwnd), uintptr(SW_MAXIMIZE))
	return true, nil
}

// CloseWindow sends a WM_CLOSE message to the specified window.
func CloseWindow(hwnd Handle) error {
	if hwnd == 0 {
		return errors.New("invalid window handle")
	}
	result, _, callErr := procPostMessageW.Call(uintptr(hwnd), uintptr(WM_CLOSE), 0, 0)
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("PostMessageW failed")
	}
	return nil
}

// WindowState returns "minimized", "maximized", or "normal".
func WindowState(hwnd Handle) (string, error) {
	if hwnd == 0 {
		return "", errors.New("invalid window handle")
	}
	iconic, _, _ := procIsIconic.Call(uintptr(hwnd))
	if iconic != 0 {
		return "minimized", nil
	}
	zoomed, _, _ := procIsZoomed.Call(uintptr(hwnd))
	if zoomed != 0 {
		return "maximized", nil
	}
	return "normal", nil
}
