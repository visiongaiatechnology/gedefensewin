// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
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

	GWL_STYLE   uintptr = ^uintptr(15) // -16
	GWL_EXSTYLE uintptr = ^uintptr(19) // -20

	WS_CAPTION    uint32 = 0x00C00000
	WS_THICKFRAME uint32 = 0x00040000
	WS_SYSMENU    uint32 = 0x00080000

	SWP_NOSIZE       uint32 = 0x0001
	SWP_NOMOVE       uint32 = 0x0002
	SWP_NOZORDER     uint32 = 0x0004
	SWP_FRAMECHANGED uint32 = 0x0020
)

var (
	procFindWindowW              = user32.NewProc("FindWindowW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procIsWindow                 = user32.NewProc("IsWindow")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procShowWindow               = user32.NewProc("ShowWindow")
	procIsZoomed                 = user32.NewProc("IsZoomed")
	procIsIconic                 = user32.NewProc("IsIconic")
	procPostMessageW             = user32.NewProc("PostMessageW")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
)

var ErrWindowNotFound = errors.New("no active GeDefense window found")

type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

// GetWindowBounds returns the screen coordinates of the specified window.
func GetWindowBounds(hwnd Handle) (RECT, error) {
	if hwnd == 0 {
		return RECT{}, errors.New("invalid window handle")
	}
	var r RECT
	ret, _, callErr := procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	if ret == 0 {
		if err := errnoResult(callErr); err != nil {
			return RECT{}, err
		}
		return RECT{}, errors.New("GetWindowRect failed")
	}
	return r, nil
}

type windowSearch struct {
	pid     uint32
	matched Handle
}

// One immutable callback avoids leaking a Windows callback trampoline per retry.
var enumerateProcessWindow = syscall.NewCallback(func(hwnd uintptr, query *windowSearch) uintptr {
	if visible, _, _ := procIsWindowVisible.Call(hwnd); visible == 0 {
		return 1
	}
	var pid uint32
	if thread, _, _ := procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid))); thread == 0 {
		return 1
	}
	if pid == query.pid {
		query.matched = Handle(hwnd)
		return 0
	}
	return 1
})

// FindWindowByPID never falls back to titles or another process.
func FindWindowByPID(pid uint32) (Handle, error) {
	if pid == 0 {
		return 0, errors.New("invalid PID")
	}
	query := windowSearch{pid: pid}
	result, _, callErr := procEnumWindows.Call(enumerateProcessWindow, uintptr(unsafe.Pointer(&query)))
	if query.matched == 0 && result == 0 {
		if err := CheckBOOL("EnumWindows", result, callErr); err != nil {
			return 0, err
		}
	}
	if query.matched == 0 {
		return 0, ErrWindowNotFound
	}
	return query.matched, nil
}

// FindGeDefenseWindow locates only the launcher-owned native host class.
// Folder names, browser titles and URLs never identify an application window.
func FindGeDefenseWindow() (Handle, error) {
	return findWindowByClassName("VGT.GeDefense.Center.Host.v4")
}

// FindGeDefenseTrayWindow locates the tray's own native window class. The
// single-instance decision uses it as a liveness cross-check: a named object
// without a live UI is treated as pre-created (HP-FIND-005).
func FindGeDefenseTrayWindow() (Handle, error) {
	return findWindowByClassName("VGTGeDefenseTrayWindowV4")
}

func findWindowByClassName(classNameValue string) (Handle, error) {
	className, err := utf16Ptr(classNameValue)
	if err != nil {
		return 0, err
	}
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(className)), 0)
	if hwnd == 0 {
		return 0, ErrWindowNotFound
	}
	return Handle(hwnd), nil
}

// ShowWindowState applies a show state and verifies the observable result.
// ShowWindow's return value describes PREVIOUS visibility, not success.
func ShowWindowState(hwnd Handle, state uint32) error {
	if err := validateWindow(hwnd); err != nil {
		return err
	}
	_, _, _ = procShowWindow.Call(uintptr(hwnd), uintptr(state))
	actual, err := WindowState(hwnd)
	if err != nil {
		return err
	}
	expected := "normal"
	if state == SW_MINIMIZE {
		expected = "minimized"
	}
	if state == SW_MAXIMIZE {
		expected = "maximized"
	}
	if actual != expected {
		return errors.New("window state transition was not applied")
	}
	return nil
}
func validateWindow(hwnd Handle) error {
	if hwnd == 0 {
		return errors.New("invalid window handle")
	}
	if valid, _, _ := procIsWindow.Call(uintptr(hwnd)); valid == 0 {
		return errors.New("window no longer exists")
	}
	return nil
}

// MinimizeWindow minimizes a validated live window.
func MinimizeWindow(hwnd Handle) error { return ShowWindowState(hwnd, SW_MINIMIZE) }

// MaximizeOrRestoreWindow toggles using the actual native state.
func MaximizeOrRestoreWindow(hwnd Handle) (bool, error) {
	state, err := WindowState(hwnd)
	if err != nil {
		return false, err
	}
	if state == "maximized" {
		return false, ShowWindowState(hwnd, SW_RESTORE)
	}
	return true, ShowWindowState(hwnd, SW_MAXIMIZE)
}

// CloseWindow sends a WM_CLOSE message to the specified window.
func CloseWindow(hwnd Handle) error {
	if err := validateWindow(hwnd); err != nil {
		return err
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

// BringWindowToForeground restores if iconic and focuses the window.
func BringWindowToForeground(hwnd Handle) error {
	if err := validateWindow(hwnd); err != nil {
		return err
	}
	iconic, _, _ := procIsIconic.Call(uintptr(hwnd))
	if iconic != 0 {
		if err := ShowWindowState(hwnd, SW_RESTORE); err != nil {
			return err
		}
	}
	result, _, callErr := procSetForegroundWindow.Call(uintptr(hwnd))
	return CheckBOOL("SetForegroundWindow", result, callErr)
}

// WindowState returns "minimized", "maximized", or "normal".
func WindowState(hwnd Handle) (string, error) {
	if err := validateWindow(hwnd); err != nil {
		return "", err
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
