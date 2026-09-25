// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winframe

import (
	"errors"
	"sync"
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

	defaultTitlebarHeight = 38
	defaultResizeBorder   = 6
	defaultButtonsWidth   = 138
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
	procShowWindow                    = user32.NewProc("ShowWindow")
	procUpdateWindow                  = user32.NewProc("UpdateWindow")
	procGetClientRect                 = user32.NewProc("GetClientRect")
	procGetWindowRect                 = user32.NewProc("GetWindowRect")
	procScreenToClient                = user32.NewProc("ScreenToClient")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procDwmSetWindowAttribute         = dwmapi.NewProc("DwmSetWindowAttribute")
	procDwmExtendFrameIntoClientArea  = dwmapi.NewProc("DwmExtendFrameIntoClientArea")

	frameClassRegistered bool
	frameClassMu         sync.Mutex
)

// FrameConfig defines options for creating a custom Non-Client Win32 frame window.
type FrameConfig struct {
	Title          string
	Width          int32
	Height         int32
	TitlebarHeight int32
	ResizeBorder   int32
	ButtonsWidth   int32
}

// Frame represents a custom Non-Client Win32 Frame with borderless DWM styling.
type Frame struct {
	hwnd           winapi.Handle
	config         FrameConfig
	titlebarHeight int32
	resizeBorder   int32
	buttonsWidth   int32
}

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

// Handle returns the native window handle.
func (f *Frame) Handle() winapi.Handle {
	return f.hwnd
}

// Close destroys the frame window.
func (f *Frame) Close() error {
	if f.hwnd != 0 {
		procDestroyWindow.Call(uintptr(f.hwnd))
		f.hwnd = 0
	}
	return nil
}

// ConfigureDWM applies Windows 11 immersive dark mode, rounded corners, and frame extension.
func ConfigureDWM(hwnd winapi.Handle) error {
	if hwnd == 0 {
		return errors.New("invalid handle")
	}

	// Immersive Dark Mode
	var darkMode int32 = 1
	procDwmSetWindowAttribute.Call(
		uintptr(hwnd),
		uintptr(dwmwaUseImmersiveDarkMode),
		uintptr(unsafe.Pointer(&darkMode)),
		uintptr(unsafe.Sizeof(darkMode)),
	)

	// Rounded Corners
	var cornerPref int32 = dwmwcpRound
	procDwmSetWindowAttribute.Call(
		uintptr(hwnd),
		uintptr(dwmwaWindowCornerPreference),
		uintptr(unsafe.Pointer(&cornerPref)),
		uintptr(unsafe.Sizeof(cornerPref)),
	)

	// System Backdrop: Acrylic Glass / Mica
	var backdropType int32 = dwmsbtMainWindow
	procDwmSetWindowAttribute.Call(
		uintptr(hwnd),
		uintptr(dwmwaSystemBackdropType),
		uintptr(unsafe.Pointer(&backdropType)),
		uintptr(unsafe.Sizeof(backdropType)),
	)

	// Extend Frame Into Client Area by 1px to preserve DWM drop shadow
	m := margins{cxLeftWidth: 0, cxRightWidth: 0, cyTopHeight: 1, cyBottomHeight: 0}
	procDwmExtendFrameIntoClientArea.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&m)),
	)

	return nil
}
