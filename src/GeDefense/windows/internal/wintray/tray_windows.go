// STATUS: DIAMANT VGT SUPREME
//go:build windows

package wintray

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	wmDestroy     = 0x0002
	wmCommand     = 0x0111
	wmTimer       = 0x0113
	wmLButtonUp   = 0x0202
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B
	wmApp         = 0x8000
	callbackMsg   = wmApp + 1
	externalOpen  = wmApp + 2

	mfString    = 0x0000
	mfDisabled  = 0x0002
	mfGrayed    = 0x0001
	mfSeparator = 0x0800
	mfByCommand = 0x0000

	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020

	imageIcon      = 1
	lrLoadFromFile = 0x0010
	lrDefaultSize  = 0x0040

	nidMessage = 0x00000001
	nidIcon    = 0x00000002
	nidTip     = 0x00000004
	nidInfo    = 0x00000010

	niiUser      = 0x00000004
	niiLargeIcon = 0x00000020

	statusTimer        = 1
	notificationTimer  = 2
	notificationPeriod = 5000

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	menuOpen    = 1001
	menuStatus  = 1002
	menuVersion = 1003
	menuQuit    = 1004
)

// Notification is a genuine blocking event supplied by the tray's local
// control-plane poller. The tray never manufactures events or shows a toast for
// audits, correlations or feed refreshes.
type Notification struct {
	ID     string
	Title  string
	Detail string
}

type Config struct {
	Title         string
	Version       string
	IconPath      string
	Open          func()
	Status        func() (bool, string)
	Notifications func() []Notification
	OpenEvent     uintptr
	OpenAtStart   bool
}

type point struct{ X, Y int32 }

type message struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSmall  uintptr
}

type notifyIconData struct {
	Size        uint32
	HWnd        uintptr
	ID          uint32
	Flags       uint32
	Callback    uint32
	Icon        uintptr
	Tip         [128]uint16
	State       uint32
	StateMask   uint32
	Info        [256]uint16
	Timeout     uint32
	InfoTitle   [64]uint16
	InfoFlags   uint32
	GUID        [16]byte
	BalloonIcon uintptr
}

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procDestroyIcon         = user32.NewProc("DestroyIcon")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procModifyMenuW         = user32.NewProc("ModifyMenuW")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procSetTimer            = user32.NewProc("SetTimer")
	procKillTimer           = user32.NewProc("KillTimer")
	procLoadImageW          = user32.NewProc("LoadImageW")
	procRegisterWindowMsgW  = user32.NewProc("RegisterWindowMessageW")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")

	callback = syscall.NewCallback(windowProc)
	activeMu sync.Mutex
	active   *trayState
)

type trayState struct {
	cfg            Config
	hwnd           uintptr
	menu           uintptr
	icon           uintptr
	taskbarCreated uint32
	iconAdded      bool
	lastHealthy    bool
	lastDetail     string

	notificationPrimed bool
	lastNotificationID string
}

func Run(cfg Config) (err error) {
	if cfg.Open == nil || cfg.Status == nil || cfg.Title == "" {
		return errors.New("invalid tray configuration")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	instance, _, callErr := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return syscallError("GetModuleHandleW", callErr)
	}
	className, _ := syscall.UTF16PtrFromString("VGTGeDefenseTrayWindowV4")
	iconPath, err := syscall.UTF16PtrFromString(cfg.IconPath)
	if err != nil || cfg.IconPath == "" {
		return errors.New("invalid tray icon path")
	}
	icon, _, iconErr := procLoadImageW.Call(0, uintptr(unsafe.Pointer(iconPath)), imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
	if icon == 0 {
		return syscallError("LoadImageW", iconErr)
	}
	defer func() {
		r, _, e := procDestroyIcon.Call(icon)
		err = errors.Join(err, winapi.CheckBOOL("DestroyIcon", r, e))
	}()
	wc := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: callback, Instance: instance, Icon: icon, IconSmall: icon, ClassName: className}
	atom, _, registerErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 && registerErr != syscall.Errno(1410) { // class already exists
		return syscallError("RegisterClassExW", registerErr)
	}
	if atom != 0 {
		defer func() {
			r, _, e := user32.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(className)), instance)
			err = errors.Join(err, winapi.CheckBOOL("UnregisterClassW(tray)", r, e))
		}()
	}
	hwnd, _, createErr := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, 0, instance, 0)
	if hwnd == 0 {
		return syscallError("CreateWindowExW", createErr)
	}
	state := &trayState{cfg: cfg, hwnd: hwnd, icon: icon}
	activeMu.Lock()
	active = state
	activeMu.Unlock()
	defer func() {
		activeMu.Lock()
		active = nil
		activeMu.Unlock()
	}()

	defer func() {
		if valid, _, _ := user32.NewProc("IsWindow").Call(hwnd); valid != 0 {
			r, _, e := procDestroyWindow.Call(hwnd)
			err = errors.Join(err, winapi.CheckBOOL("DestroyWindow(tray)", r, e))
		}
	}()
	defer func() {
		if state.menu != 0 {
			r, _, e := procDestroyMenu.Call(state.menu)
			err = errors.Join(err, winapi.CheckBOOL("DestroyMenu", r, e))
		}
	}()
	if err := state.createMenu(); err != nil {
		return err
	}
	taskbarName, _ := syscall.UTF16PtrFromString("TaskbarCreated")
	registered, _, _ := procRegisterWindowMsgW.Call(uintptr(unsafe.Pointer(taskbarName)))
	state.taskbarCreated = uint32(registered)
	if err := state.addIcon(); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, state.deleteIcon()) }()
	state.refreshStatus()
	timer, _, timerErr := procSetTimer.Call(hwnd, statusTimer, 60000, 0)
	if timer == 0 {
		return syscallError("SetTimer(status)", timerErr)
	}
	var notificationTimerHandle uintptr
	if cfg.Notifications != nil {
		notificationTimerHandle, _, timerErr = procSetTimer.Call(hwnd, notificationTimer, notificationPeriod, 0)
		if notificationTimerHandle == 0 {
			// Native toasts are a notification enhancement, not a tray-liveness
			// requirement; keep the tray alive but report the failed timer.
			winapi.ReportError("SetTimer(notifications)", syscallError("SetTimer(notifications)", timerErr))
		}
	}
	defer func() {
		// DestroyWindow already destroys its timers; only kill while the HWND is live.
		if valid, _, _ := user32.NewProc("IsWindow").Call(hwnd); valid != 0 {
			r, _, e := procKillTimer.Call(hwnd, timer)
			err = errors.Join(err, winapi.CheckBOOL("KillTimer(status)", r, e))
			if notificationTimerHandle != 0 {
				r, _, e = procKillTimer.Call(hwnd, notificationTimerHandle)
				err = errors.Join(err, winapi.CheckBOOL("KillTimer(notifications)", r, e))
			}
		}
	}()

	stopWatcher := make(chan struct{})
	var watcher sync.WaitGroup
	defer func() { close(stopWatcher); watcher.Wait() }()
	if cfg.OpenEvent != 0 {
		watcher.Add(1)
		go func() { defer watcher.Done(); watchOpenEvent(cfg.OpenEvent, hwnd, stopWatcher) }()
	}
	if cfg.OpenAtStart {
		result, _, callErr := procPostMessageW.Call(hwnd, externalOpen, 0, 0)
		if err := winapi.CheckBOOL("PostMessageW(open)", result, callErr); err != nil {
			return err
		}
	}

	var msg message
	for {
		result, _, getErr := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			return syscallError("GetMessageW", getErr)
		}
		if result == 0 {
			return nil
		}
		// Character-generation BOOL and WndProc LRESULT are informational, not errors.
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func watchOpenEvent(handle, hwnd uintptr, stop <-chan struct{}) {
	wait := kernel32.NewProc("WaitForSingleObject")
	for {
		select {
		case <-stop:
			return
		default:
		}
		result, _, callErr := wait.Call(handle, 500)
		if result == 258 {
			continue
		}
		if result != 0 {
			winapi.ReportError("tray open-event wait", syscallError("WaitForSingleObject", callErr))
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		result, _, callErr = procPostMessageW.Call(hwnd, externalOpen, 0, 0)
		if err := winapi.CheckBOOL("PostMessageW(open)", result, callErr); err != nil {
			winapi.ReportError("tray open event", err)
			return
		}
	}
}

func windowProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	activeMu.Lock()
	state := active
	activeMu.Unlock()
	if state == nil || state.hwnd != hwnd {
		result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return result
	}
	if state.taskbarCreated != 0 && msg == state.taskbarCreated {
		winapi.ReportError("tray icon recreation", state.addIcon())
		return 0
	}
	switch msg {
	case callbackMsg:
		switch uint32(lParam) {
		case wmLButtonUp:
			state.cfg.Open()
		case wmRButtonUp, wmContextMenu:
			state.showMenu()
		}
		return 0
	case externalOpen:
		state.cfg.Open()
		return 0
	case wmTimer:
		switch uint32(wParam) {
		case statusTimer:
			state.refreshStatus()
		case notificationTimer:
			state.refreshNotifications()
		}
		return 0
	case wmCommand:
		switch uint16(wParam & 0xFFFF) {
		case menuOpen:
			state.cfg.Open()
		case menuQuit:
			result, _, callErr := procDestroyWindow.Call(hwnd)
			winapi.ReportError("tray close", winapi.CheckBOOL("DestroyWindow", result, callErr))
		}
		return 0
	case wmDestroy:
		winapi.ReportError("tray icon removal", state.deleteIcon())
		// PostQuitMessage returns VOID.
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return result
}

func (s *trayState) createMenu() error {
	menu, _, callErr := procCreatePopupMenu.Call()
	if menu == 0 {
		return syscallError("CreatePopupMenu", callErr)
	}
	s.menu = menu
	if err := appendMenu(menu, mfString, menuOpen, "GeDefense öffnen"); err != nil {
		return err
	}
	if err := appendMenu(menu, mfString|mfDisabled|mfGrayed, menuStatus, "Schutzstatus: Prüfung läuft"); err != nil {
		return err
	}
	if err := appendMenu(menu, mfString|mfDisabled|mfGrayed, menuVersion, "Version "+s.cfg.Version); err != nil {
		return err
	}
	if err := appendMenu(menu, mfSeparator, 0, ""); err != nil {
		return err
	}
	return appendMenu(menu, mfString, menuQuit, "Tray beenden")
}

func appendMenu(menu uintptr, flags uint32, id uint32, title string) error {
	var ptr *uint16
	if title != "" {
		ptr, _ = syscall.UTF16PtrFromString(title)
	}
	result, _, callErr := procAppendMenuW.Call(menu, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(ptr)))
	if result == 0 {
		return syscallError("AppendMenuW", callErr)
	}
	return nil
}

func (s *trayState) refreshStatus() {
	healthy, detail := s.cfg.Status()
	if detail == "" {
		detail = "Status nicht verfügbar"
	}
	s.lastHealthy, s.lastDetail = healthy, detail
	title := "Schutzstatus: " + detail
	ptr, _ := syscall.UTF16PtrFromString(title)
	result, _, callErr := procModifyMenuW.Call(s.menu, menuStatus, mfByCommand|mfString|mfDisabled|mfGrayed, menuStatus, uintptr(unsafe.Pointer(ptr)))
	winapi.ReportError("tray status menu", winapi.CheckBOOL("ModifyMenuW", result, callErr))
	winapi.ReportError("tray status tooltip", s.modifyIcon("VGT GeDefense · "+detail))
}

// refreshNotifications polls the tray's local, already-block-filtered cache. It
// only surfaces the newest unseen event so a burst of blocks cannot turn into a
// notification storm.
func (s *trayState) refreshNotifications() {
	if s.cfg.Notifications == nil || !s.iconAdded {
		return
	}
	entries := s.cfg.Notifications()
	if len(entries) == 0 {
		return
	}
	selected, show, nextID := nextNativeNotification(entries, s.notificationPrimed, s.lastNotificationID)
	if !show {
		s.notificationPrimed = true
		s.lastNotificationID = nextID
		return
	}
	s.notificationPrimed = true
	s.lastNotificationID = nextID
	title := selected.Title
	if title == "" {
		title = "GeDefense hat eine Bedrohung blockiert"
	}
	detail := selected.Detail
	if detail == "" {
		detail = "Eine tatsächliche Blockaktion wurde von der lokalen Control Plane gemeldet."
	}
	if err := s.showNotification(title, detail); err != nil {
		winapi.ReportError("tray native notification", err)
	}
}

// nextNativeNotification is pure and suppresses replay of existing events after
// tray startup. A burst between polls still yields exactly one toast.
func nextNativeNotification(entries []Notification, primed bool, lastID string) (Notification, bool, string) {
	if len(entries) == 0 {
		return Notification{}, false, lastID
	}
	latest := entries[0]
	if latest.ID == "" {
		return Notification{}, false, lastID
	}
	if !primed {
		return Notification{}, false, latest.ID
	}
	if latest.ID == lastID {
		return Notification{}, false, lastID
	}
	return latest, true, latest.ID
}

func (s *trayState) showNotification(title, detail string) error {
	if !s.iconAdded {
		return errors.New("tray icon is not active")
	}
	data := s.iconData("")
	data.Flags |= nidInfo
	data.InfoFlags = niiUser | niiLargeIcon
	data.BalloonIcon = s.icon
	data.Timeout = 10000
	copyUTF16(data.InfoTitle[:], truncateText(title, 63))
	copyUTF16(data.Info[:], truncateText(detail, 255))
	result, _, callErr := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		return syscallError("Shell_NotifyIconW(NIM_MODIFY/NIF_INFO)", callErr)
	}
	return nil
}

func truncateText(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes])
}

func (s *trayState) showMenu() {
	var p point
	result, _, callErr := procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	if err := winapi.CheckBOOL("GetCursorPos", result, callErr); err != nil {
		winapi.ReportError("tray menu position", err)
		return
	}
	result, _, callErr = procSetForegroundWindow.Call(s.hwnd)
	if err := winapi.CheckBOOL("SetForegroundWindow", result, callErr); err != nil {
		winapi.ReportError("tray menu focus", err)
		return
	}
	result, _, callErr = procTrackPopupMenu.Call(s.menu, tpmRightButton|tpmBottomAlign, uintptr(p.X), uintptr(p.Y), 0, s.hwnd, 0)
	winapi.ReportError("tray menu", winapi.CheckBOOL("TrackPopupMenu", result, callErr))
}

func (s *trayState) addIcon() error {
	data := s.iconData("VGT GeDefense · Schutzstatus wird geprüft")
	result, _, callErr := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		return syscallError("Shell_NotifyIconW(NIM_ADD)", callErr)
	}
	s.iconAdded = true
	return nil
}

func (s *trayState) modifyIcon(tip string) error {
	data := s.iconData(tip)
	result, _, callErr := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		return syscallError("Shell_NotifyIconW(NIM_MODIFY)", callErr)
	}
	return nil
}

func (s *trayState) deleteIcon() error {
	if !s.iconAdded {
		return nil
	}
	data := s.iconData("")
	result, _, callErr := procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&data)))
	if err := winapi.CheckBOOL("Shell_NotifyIconW(NIM_DELETE)", result, callErr); err != nil {
		return err
	}
	s.iconAdded = false
	return nil
}

func (s *trayState) iconData(tip string) notifyIconData {
	data := notifyIconData{HWnd: s.hwnd, ID: 1, Flags: nidMessage | nidIcon | nidTip, Callback: callbackMsg, Icon: s.icon}
	data.Size = uint32(unsafe.Sizeof(data))
	copyUTF16(data.Tip[:], tip)
	return data
}

func copyUTF16(destination []uint16, value string) {
	encoded, err := syscall.UTF16FromString(value)
	if err != nil {
		encoded = []uint16{'V', 'G', 'T', 0}
	}
	if len(encoded) > len(destination) {
		encoded = encoded[:len(destination)]
		encoded[len(encoded)-1] = 0
	}
	copy(destination, encoded)
}

func syscallError(operation string, err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno != 0 {
		return fmt.Errorf("%s: %w", operation, errno)
	}
	return fmt.Errorf("%s failed", operation)
}
