// STATUS: PLATIN
//go:build windows

package winframe

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	wmDestroy     = 0x0002
	wmSize        = 0x0005
	wmPaint       = 0x000F
	wmClose       = 0x0010
	wmEraseBkgnd  = 0x0014
	wmNcCalcSize  = 0x0083
	wmNcHitTest   = 0x0084
	wmSetCursor   = 0x0020
	wmMouseMove   = 0x0200
	wmLButtonDown = 0x0201
	wmLButtonUp   = 0x0202
	wmMouseLeave  = 0x02A3

	htError       = -2
	htTransparent = -1
	htNowhere     = 0
	htClient      = 1
	htCaption     = 2
	htLeft        = 10
	htRight       = 11
	htTop         = 12
	htTopLeft     = 13
	htTopRight    = 14
	htBottom      = 15
	htBottomLeft  = 16
	htBottomRight = 17

	wsOverlapped       = 0x00000000
	wsCaption          = 0x00C00000
	wsSysMenu          = 0x00080000
	wsThickFrame       = 0x00040000
	wsMinimizeBox      = 0x00020000
	wsMaximizeBox      = 0x00010000
	wsOverlappedWindow = wsOverlapped | wsCaption | wsSysMenu | wsThickFrame | wsMinimizeBox | wsMaximizeBox
	wsVisible          = 0x10000000

	wsExAppWindow = 0x00040000

	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwaBorderColor            = 34
	dwmwaSystemBackdropType     = 38

	dwmwcpRound           = 2
	dwmsbtMainWindow      = 2 // Mica
	dwmsbtTransientWindow = 3 // Acrylic Glass

)

type point struct {
	x int32
	y int32
}

type rect struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}

type margins struct {
	cxLeftWidth    int32
	cxRightWidth   int32
	cyTopHeight    int32
	cyBottomHeight int32
}

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")

	procRegisterClassExW              = user32.NewProc("RegisterClassExW")
	procCreateWindowExW               = user32.NewProc("CreateWindowExW")
	procDefWindowProcW                = user32.NewProc("DefWindowProcW")
	procDestroyWindow                 = user32.NewProc("DestroyWindow")
	procGetClientRect                 = user32.NewProc("GetClientRect")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procDwmSetWindowAttribute         = dwmapi.NewProc("DwmSetWindowAttribute")
	procDwmExtendFrameIntoClientArea  = dwmapi.NewProc("DwmExtendFrameIntoClientArea")
)

// CalculateHitTest determines the non-client hit test code based on window-relative coordinates.
// It is pure and independently testable across all screen layouts.
func CalculateHitTest(ptX, ptY, clientWidth, clientHeight, border, titlebarHeight, buttonsWidth int32) int {
	// 1. Resizing edges
	isTop := ptY < border
	isBottom := ptY >= clientHeight-border
	isLeft := ptX < border
	isRight := ptX >= clientWidth-border

	if isTop && isLeft {
		return htTopLeft
	}
	if isTop && isRight {
		return htTopRight
	}
	if isBottom && isLeft {
		return htBottomLeft
	}
	if isBottom && isRight {
		return htBottomRight
	}
	if isTop {
		return htTop
	}
	if isBottom {
		return htBottom
	}
	if isLeft {
		return htLeft
	}
	if isRight {
		return htRight
	}

	// 2. Custom titlebar
	if ptY < titlebarHeight {
		// Buttons area in top right -> HTCLIENT so clicks are received by button controls
		if ptX >= clientWidth-buttonsWidth {
			return htClient
		}
		// Otherwise draggable caption -> HTCAPTION for native OS dragging & Aero Snap
		return htCaption
	}

	// 3. Client area
	return htClient
}

// ConfigureDWM applies a dark, border-free compositor frame. Attributes absent
// on Windows 10 are optional; actual failures from supported DWM calls propagate.
func ConfigureDWM(hwnd winapi.Handle) error {
	if hwnd == 0 {
		return errors.New("invalid handle")
	}
	var failures []error
	for _, attribute := range []struct {
		id    uint32
		value uint32
	}{
		{dwmwaUseImmersiveDarkMode, 1}, {dwmwaWindowCornerPreference, dwmwcpRound},
		{dwmwaBorderColor, 0xfffffffe}, {dwmwaSystemBackdropType, dwmsbtMainWindow},
	} {
		value := attribute.value
		result, _, _ := procDwmSetWindowAttribute.Call(uintptr(hwnd), uintptr(attribute.id), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
		if uint32(result) == 0x80070057 || uint32(result) == 0x80004001 {
			continue
		} // Attribute unsupported by this Windows build.
		failures = append(failures, winapi.CheckHRESULT("DwmSetWindowAttribute", result))
	}
	// No glass extension: the host paints its entire client, including resize edges.
	m := margins{}
	result, _, _ := procDwmExtendFrameIntoClientArea.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&m)))
	failures = append(failures, winapi.CheckHRESULT("DwmExtendFrameIntoClientArea", result))
	return errors.Join(failures...)
}
