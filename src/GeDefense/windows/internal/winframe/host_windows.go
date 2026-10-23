// STATUS: PLATIN
//go:build windows

package winframe

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const HostClass = "VGT.GeDefense.Center.Host.v4"
const hostCommand = 0x8001
const hostAttach = 0x8002
const hostBackground = 0x00140b05 // COLORREF for the product background #050b14.

type windowClass struct {
	Size, Style                        uint32
	Procedure                          uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}
type message struct {
	Window         uintptr
	ID             uint32
	WParam, LParam uintptr
	Time           uint32
	Position       point
	Private        uint32
}
type minMaxInfo struct{ Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack point }
type monitorInfo struct {
	Size          uint32
	Monitor, Work rect
	Flags         uint32
}
type hostState struct {
	window, child uintptr
	fault         error
}

var (
	getModule           = kernel32.NewProc("GetModuleHandleW")
	getMessage          = user32.NewProc("GetMessageW")
	translateMessage    = user32.NewProc("TranslateMessage")
	dispatchMessage     = user32.NewProc("DispatchMessageW")
	postQuit            = user32.NewProc("PostQuitMessage")
	postMessage         = user32.NewProc("PostMessageW")
	setParent           = user32.NewProc("SetParent")
	getParent           = user32.NewProc("GetParent")
	getStyle            = user32.NewProc("GetWindowLongW")
	setStyle            = user32.NewProc("SetWindowLongW")
	setPosition         = user32.NewProc("SetWindowPos")
	getDPI              = user32.NewProc("GetDpiForWindow")
	getDPIContext       = user32.NewProc("GetWindowDpiAwarenessContext")
	setThreadDPIContext = user32.NewProc("SetThreadDpiAwarenessContext")
	getAwareness        = user32.NewProc("GetAwarenessFromDpiAwarenessContext")
	monitorFromWindow   = user32.NewProc("MonitorFromWindow")
	monitorFromPoint    = user32.NewProc("MonitorFromPoint")
	getMonitorInfo      = user32.NewProc("GetMonitorInfoW")
	getCursorPosition   = user32.NewProc("GetCursorPos")
	releaseCapture      = user32.NewProc("ReleaseCapture")
	sendMessage         = user32.NewProc("SendMessageW")
	getKeyState         = user32.NewProc("GetAsyncKeyState")
	setFocus            = user32.NewProc("SetFocus")
	unregisterClass     = user32.NewProc("UnregisterClassW")
	isWindow            = user32.NewProc("IsWindow")
	gdi32               = syscall.NewLazyDLL("gdi32.dll")
	createSolidBrush    = gdi32.NewProc("CreateSolidBrush")
	deleteObject        = gdi32.NewProc("DeleteObject")
)

// InitialBounds uses the current monitor's work area, including negative origins.
// Native pixels are proportional to the monitor, rather than a fixed 1280px box.
func InitialBounds(work rect) rect {
	width, height := work.right-work.left, work.bottom-work.top
	w, h := width*92/100, height*90/100
	left, top := work.left+(width-w)/2, work.top+(height-h)/2
	return rect{left, top, left + w, top + h}
}
func currentWorkArea() (rect, error) {
	var cursor point
	result, _, callErr := getCursorPosition.Call(uintptr(unsafe.Pointer(&cursor)))
	if err := winapi.CheckBOOL("GetCursorPos", result, callErr); err != nil {
		return rect{}, err
	}
	packed := uint64(uint32(cursor.x)) | uint64(uint32(cursor.y))<<32
	monitor, _, _ := monitorFromPoint.Call(uintptr(packed), 2)
	info := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	result, _, callErr = getMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info)))
	if err := winapi.CheckBOOL("GetMonitorInfoW", result, callErr); err != nil {
		return rect{}, err
	}
	return info.Work, nil
}
func setBounds(window uintptr, bounds rect, flags uintptr) error {
	result, _, callErr := setPosition.Call(window, 0, uintptr(bounds.left), uintptr(bounds.top), uintptr(bounds.right-bounds.left), uintptr(bounds.bottom-bounds.top), flags)
	return winapi.CheckBOOL("SetWindowPos", result, callErr)
}
func destroy(window uintptr) error {
	result, _, callErr := procDestroyWindow.Call(window)
	return winapi.CheckBOOL("DestroyWindow", result, callErr)
}
func (s *hostState) fail(err error) {
	if err == nil {
		return
	}
	s.fault = errors.Join(s.fault, err)
	// PostQuitMessage returns VOID; the error is returned by Run after cleanup.
	_, _, _ = postQuit.Call(0)
}
func (s *hostState) resize() error {
	if s.child == 0 {
		return nil
	}
	var client rect
	result, _, callErr := procGetClientRect.Call(s.window, uintptr(unsafe.Pointer(&client)))
	if err := winapi.CheckBOOL("GetClientRect", result, callErr); err != nil {
		return err
	}
	dpi, _, _ := getDPI.Call(s.window)
	if dpi == 0 {
		return errors.New("window DPI unavailable")
	}
	border := int32(6 * dpi / 96)
	state, err := winapi.WindowState(winapi.Handle(s.window))
	if err != nil {
		return err
	}
	if state == "minimized" {
		return nil
	}
	if state == "maximized" {
		border = 0
	}
	if client.right <= 2*border || client.bottom <= 2*border {
		return nil
	}
	return setBounds(s.child, rect{border, border, client.right - border, client.bottom - border}, 0x0014)
}
func (s *hostState) windowProc(hwnd uintptr, msg uint32, wp uintptr, lp unsafe.Pointer) uintptr {
	switch msg {
	case wmNcCalcSize:
		if wp != 0 {
			return 0
		}
	case 0x0024:
		info := (*minMaxInfo)(lp)
		monitor, _, _ := monitorFromWindow.Call(hwnd, 2)
		mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
		result, _, callErr := getMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&mi)))
		if err := winapi.CheckBOOL("GetMonitorInfoW", result, callErr); err != nil {
			s.fail(err)
			return 0
		}
		info.MaxPosition = point{mi.Work.left - mi.Monitor.left, mi.Work.top - mi.Monitor.top}
		info.MaxSize = point{mi.Work.right - mi.Work.left, mi.Work.bottom - mi.Work.top}
		dpi, _, _ := getDPI.Call(hwnd)
		if dpi == 0 {
			dpi = 96
		} // Window creation can request min/max before DPI is assigned.
		info.MinTrack = point{min(640*int32(dpi)/96, info.MaxSize.x), min(480*int32(dpi)/96, info.MaxSize.y)}
		return 0
	case wmNcHitTest:
		bounds, err := winapi.GetWindowBounds(winapi.Handle(hwnd))
		if err != nil {
			s.fail(err)
			return htClient
		}
		dpi, _, _ := getDPI.Call(hwnd)
		if dpi == 0 {
			return htClient
		}
		state, err := winapi.WindowState(winapi.Handle(hwnd))
		if err != nil {
			s.fail(err)
			return htClient
		}
		if state == "maximized" {
			return htClient
		}
		x, y := int32(int16(uintptr(lp)&0xffff))-bounds.Left, int32(int16((uintptr(lp)>>16)&0xffff))-bounds.Top
		return uintptr(CalculateHitTest(x, y, bounds.Right-bounds.Left, bounds.Bottom-bounds.Top, int32(6*dpi/96), 0, 0))
	case wmSize:
		if s.window != 0 {
			s.fail(s.resize())
		}
		return 0
	case 0x02e0:
		s.fail(setBounds(hwnd, *(*rect)(lp), 0x0014))
		s.fail(s.resize())
		return 0
	case hostAttach:
		s.child = wp
		s.fail(s.resize())
		return 0
	case hostCommand:
		switch wp {
		case 1:
			s.fail(winapi.MinimizeWindow(winapi.Handle(hwnd)))
		case 2:
			_, err := winapi.MaximizeOrRestoreWindow(winapi.Handle(hwnd))
			s.fail(err)
		case 3:
			s.fail(destroy(hwnd))
		case 4:
			if pressed, _, _ := getKeyState.Call(1); pressed&0x8000 != 0 {
				// ReleaseCapture may return zero when this thread holds no capture. Sending
				// a caption mouse-down remains valid; the synchronous message returns LRESULT.
				result, _, callErr := releaseCapture.Call()
				if result == 0 {
					winapi.ReportError("release drag capture", winapi.CheckBOOL("ReleaseCapture", result, callErr))
				}
				_, _, _ = sendMessage.Call(hwnd, 0x00a1, htCaption, 0)
			}
		}
		return 0
	case 0x0007:
		if s.child != 0 {
			previous, _, callErr := setFocus.Call(s.child)
			if previous == 0 {
				winapi.ReportError("focus renderer", winapi.CheckBOOL("SetFocus", previous, callErr))
			}
		}
		return 0
	case wmClose:
		s.fail(destroy(hwnd))
		return 0
	case wmDestroy:
		// PostQuitMessage has a VOID contract.
		_, _, _ = postQuit.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wp, uintptr(lp))
	return result
}

// Run owns all host state and its message loop on one OS thread.
func Run(ready func(winapi.Handle)) (err error) {
	if ready == nil {
		return errors.New("host ready callback required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, callErr := procSetProcessDpiAwarenessContext.Call(^uintptr(3))
	if result == 0 {
		context, _, contextErr := user32.NewProc("GetThreadDpiAwarenessContext").Call()
		if context == 0 {
			return fmt.Errorf("current DPI context: %w", contextErr)
		}
		awareness, _, _ := getAwareness.Call(context)
		if awareness != 2 {
			return winapi.CheckBOOL("SetProcessDpiAwarenessContext", result, callErr)
		}
	}
	instance, _, callErr := getModule.Call(0)
	if instance == 0 {
		return fmt.Errorf("host module: %w", callErr)
	}
	className, err := syscall.UTF16PtrFromString(HostClass)
	if err != nil {
		return err
	}
	brush, _, callErr := createSolidBrush.Call(hostBackground)
	if brush == 0 {
		return fmt.Errorf("host background brush: %w", callErr)
	}
	brushTransferred := false
	defer func() {
		// Successful class registration transfers brush lifetime to Windows; the
		// system frees it when the class is unregistered. Only pre-registration
		// failures still own the GDI brush directly.
		if !brushTransferred {
			r, _, e := deleteObject.Call(brush)
			err = errors.Join(err, winapi.CheckBOOL("DeleteObject(host brush)", r, e))
		}
	}()
	state := &hostState{}
	callback := syscall.NewCallback(state.windowProc)
	wc := windowClass{Size: uint32(unsafe.Sizeof(windowClass{})), Procedure: callback, Instance: instance, Name: className, Background: brush}
	atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return fmt.Errorf("register host: %w", callErr)
	}
	brushTransferred = true
	defer func() {
		r, _, e := unregisterClass.Call(uintptr(unsafe.Pointer(className)), instance)
		err = errors.Join(err, winapi.CheckBOOL("UnregisterClassW", r, e))
	}()
	work, err := currentWorkArea()
	if err != nil {
		return err
	}
	bounds := InitialBounds(work)
	title, err := syscall.UTF16PtrFromString("GeDefense V5 · Windows Security Center")
	if err != nil {
		return err
	}
	state.window, _, callErr = procCreateWindowExW.Call(wsExAppWindow, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)), wsOverlappedWindow|0x02000000, uintptr(bounds.left), uintptr(bounds.top), uintptr(bounds.right-bounds.left), uintptr(bounds.bottom-bounds.top), 0, 0, instance, 0)
	if state.window == 0 {
		return fmt.Errorf("create host: %w", callErr)
	}
	defer func() {
		if valid, _, _ := isWindow.Call(state.window); valid != 0 {
			err = errors.Join(err, destroy(state.window))
		}
	}()
	if err := setBounds(state.window, bounds, 0x0037); err != nil {
		return err
	}
	winapi.ReportError("optional DWM styling", ConfigureDWM(winapi.Handle(state.window)))
	// Maximized first launch uses the work area. Restore returns to the proportional rectangle.
	if err := winapi.ShowWindowState(winapi.Handle(state.window), winapi.SW_MAXIMIZE); err != nil {
		return err
	}
	ready(winapi.Handle(state.window))
	var msg message
	for {
		result, _, callErr := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			return fmt.Errorf("host message loop: %w", callErr)
		}
		if result == 0 {
			return state.fault
		}
		// TranslateMessage returns whether a character was generated, DispatchMessage
		// returns the window procedure's LRESULT. Neither exposes a last-error contract.
		_, _, _ = translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// Attach embeds only the caller-verified browser process window, without a crop.
func Attach(host, browser winapi.Handle) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if host == 0 || browser == 0 {
		return errors.New("invalid host or browser")
	}
	context, _, callErr := getDPIContext.Call(uintptr(browser))
	if context == 0 {
		return fmt.Errorf("browser DPI context: %w", callErr)
	}
	previous, _, callErr := setThreadDPIContext.Call(context)
	if previous == 0 {
		return fmt.Errorf("set browser DPI context: %w", callErr)
	}
	defer func() {
		r, _, e := setThreadDPIContext.Call(previous)
		err = errors.Join(err, winapi.CheckBOOL("restore thread DPI context", r, e))
	}()
	style, _, callErr := getStyle.Call(uintptr(browser), winapi.GWL_STYLE)
	if style == 0 {
		return fmt.Errorf("browser style: %w", callErr)
	}
	childStyle := (uint32(style) &^ uint32(0x80cf0000)) | 0x40000000
	// SetWindowLong/SetParent can return zero on success. Verify their postconditions.
	_, _, _ = setStyle.Call(uintptr(browser), winapi.GWL_STYLE, uintptr(childStyle))
	actual, _, _ := getStyle.Call(uintptr(browser), winapi.GWL_STYLE)
	if uint32(actual) != childStyle {
		return errors.New("browser child style was not applied")
	}
	_, _, _ = setParent.Call(uintptr(browser), uintptr(host))
	parent, _, _ := getParent.Call(uintptr(browser))
	if parent != uintptr(host) {
		return errors.New("browser attachment failed")
	}
	if err := setBounds(uintptr(browser), rect{}, 0x0037); err != nil {
		return err
	}
	result, _, callErr := postMessage.Call(uintptr(host), hostAttach, uintptr(browser), 0)
	if err := winapi.CheckBOOL("attach notification", result, callErr); err != nil {
		return err
	}
	// ShowWindow reports previous visibility. Liveness is checked through WindowState.
	return winapi.ShowWindowState(browser, winapi.SW_SHOWNORMAL)
}

// Command marshals an operation to the owning UI thread exactly once.
func Command(host winapi.Handle, action string) error {
	commands := map[string]uintptr{"minimize": 1, "maximize": 2, "close": 3, "drag": 4}
	id, ok := commands[action]
	if !ok || host == 0 {
		return errors.New("invalid host command")
	}
	result, _, callErr := postMessage.Call(uintptr(host), hostCommand, id, 0)
	return winapi.CheckBOOL("host command", result, callErr)
}
