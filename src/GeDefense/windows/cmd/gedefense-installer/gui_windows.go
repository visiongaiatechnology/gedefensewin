// STATUS: DIAMANT VGT SUPREME
//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
)

const (
	wmDestroy        = 0x0002
	wmSize           = 0x0005
	wmPaint          = 0x000F
	wmClose          = 0x0010
	wmEraseBkgnd     = 0x0014
	wmSetFont        = 0x0030
	wmKeyDown        = 0x0100
	wmCommand        = 0x0111
	wmCtlColorEdit   = 0x0133
	wmCtlColorStatic = 0x0138
	wmSetCursor      = 0x0020
	wmMouseMove      = 0x0200
	wmLButtonDown    = 0x0201
	wmLButtonUp      = 0x0202
	wmMouseLeave     = 0x02A3
	wmApp            = 0x8000
	wmSetupUpdate    = wmApp + 101
	wmSetupComplete  = wmApp + 102

	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsMaximizeBox  = 0x00010000
	wsThickFrame   = 0x00040000
	wsClipChildren = 0x02000000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsVScroll      = 0x00200000
	wsBorder       = 0x00800000

	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esReadOnly    = 0x0800

	dtLeft        = 0x00000000
	dtCenter      = 0x00000001
	dtRight       = 0x00000002
	dtVCenter     = 0x00000004
	dtWordBreak   = 0x00000010
	dtSingleLine  = 0x00000020
	dtNoPrefix    = 0x00000800
	dtEndEllipsis = 0x00008000

	srcCopy = 0x00CC0020

	colorBtnFace = 15

	idErrorBox = 202

	defaultWidth  = 620
	defaultHeight = 420
	minWidth      = 540
	minHeight     = 380

	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwaBorderColor            = 34
	dwmwaSystemBackdropType     = 38

	dwmwcpRound           = 2
	dwmsbtMainWindow      = 2 // Mica
	dwmsbtTransientWindow = 3 // Acrylic Glass

	idcArrow = 32512
	idcHand  = 32649
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")

	procRegisterClassExW              = user32.NewProc("RegisterClassExW")
	procCreateWindowExW               = user32.NewProc("CreateWindowExW")
	procDefWindowProcW                = user32.NewProc("DefWindowProcW")
	procDestroyWindow                 = user32.NewProc("DestroyWindow")
	procShowWindow                    = user32.NewProc("ShowWindow")
	procUpdateWindow                  = user32.NewProc("UpdateWindow")
	procGetMessageW                   = user32.NewProc("GetMessageW")
	procTranslateMessage              = user32.NewProc("TranslateMessage")
	procDispatchMessageW              = user32.NewProc("DispatchMessageW")
	procPostQuitMessage               = user32.NewProc("PostQuitMessage")
	procPostMessageW                  = user32.NewProc("PostMessageW")
	procSendMessageW                  = user32.NewProc("SendMessageW")
	procSetWindowTextW                = user32.NewProc("SetWindowTextW")
	procGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	procMoveWindow                    = user32.NewProc("MoveWindow")
	procLoadCursorW                   = user32.NewProc("LoadCursorW")
	procSetCursor                     = user32.NewProc("SetCursor")
	procLoadIconW                     = user32.NewProc("LoadIconW")
	procGetSysColorBrush              = user32.NewProc("GetSysColorBrush")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procBeginPaint                    = user32.NewProc("BeginPaint")
	procEndPaint                      = user32.NewProc("EndPaint")
	procGetClientRect                 = user32.NewProc("GetClientRect")
	procInvalidateRect                = user32.NewProc("InvalidateRect")
	procDrawTextW                     = user32.NewProc("DrawTextW")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")

	procCreateFontW            = gdi32.NewProc("CreateFontW")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procSetBkMode              = gdi32.NewProc("SetBkMode")
	procSetBkColor             = gdi32.NewProc("SetBkColor")
	procSetTextColor           = gdi32.NewProc("SetTextColor")
	procCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	procCreatePen              = gdi32.NewProc("CreatePen")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procRoundRect              = gdi32.NewProc("RoundRect")
	procRectangle              = gdi32.NewProc("Rectangle")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procMoveToEx               = gdi32.NewProc("MoveToEx")
	procLineTo                 = gdi32.NewProc("LineTo")
	procPolygon                = gdi32.NewProc("Polygon")

	procInitCommonControlsEx  = comctl32.NewProc("InitCommonControlsEx")
	procShellExecuteW         = shell32.NewProc("ShellExecuteW")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")

	setupCallback = syscall.NewCallback(setupWindowProc)

	activeWizardMu sync.Mutex
	activeWizard   *setupWizard
)

type point struct{ X, Y int32 }

type rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type paintStruct struct {
	Hdc         uintptr
	FErase      int32
	RcPaint     rect
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type msgStruct struct {
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

type initCommonControlsEx struct {
	Size uint32
	ICC  uint32
}

type setupWizard struct {
	hwnd         uintptr
	hwndErrorBox uintptr

	fontTitle   uintptr
	fontBadge   uintptr
	fontHeader  uintptr
	fontRegular uintptr
	fontSmall   uintptr
	fontMono    uintptr

	// Pens
	penTopRim    uintptr
	penDivider   uintptr
	penCardRim   uintptr
	penBadgeRim  uintptr
	penTrackRim  uintptr
	penBtnRim    uintptr
	penBtnDisRim uintptr
	penShield    uintptr
	penErrorRim  uintptr

	// Brushes
	brushWindowBg uintptr
	brushCardBg   uintptr
	brushBadgeBg  uintptr
	brushTrackBg  uintptr
	brushProgFill uintptr
	brushProgDone uintptr
	brushBtnNorm  uintptr
	brushBtnHover uintptr
	brushBtnPress uintptr
	brushBtnDis   uintptr
	brushErrorBg  uintptr
	brushShieldBg uintptr

	cursorArrow uintptr
	cursorHand  uintptr

	mu         sync.Mutex
	percent    int
	statusText string
	detailText string
	completed  bool
	success    bool
	errMessage string
	uninstall  bool
	currentW   int32
	currentH   int32
	btnHover   bool
	btnPressed bool
}

func rgb(r, g, b byte) uintptr {
	return uintptr(uint32(r) | (uint32(g) << 8) | (uint32(b) << 16))
}

func initCommonControls() {
	icce := initCommonControlsEx{
		Size: uint32(unsafe.Sizeof(initCommonControlsEx{})),
		ICC:  0x00000020 | 0x00004000,
	}
	_, _, _ = procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icce)))
}

func setDPIAwareness() {
	if procSetProcessDpiAwarenessContext.Find() == nil {
		_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3))
	}
}

func applyDwmGlassAttributes(hwnd uintptr) {
	if procDwmSetWindowAttribute.Find() == nil {
		darkMode := int32(1)
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&darkMode)), 4)

		cornerPref := int32(dwmwcpRound)
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&cornerPref)), 4)

		borderColor := uint32(0x00D8B400) // subtle cyan border RGB(0, 180, 216)
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaBorderColor, uintptr(unsafe.Pointer(&borderColor)), 4)

		backdrop := int32(dwmsbtTransientWindow) // Acrylic Glass
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaSystemBackdropType, uintptr(unsafe.Pointer(&backdrop)), 4)
	}
}

func createFont(name string, height int32, weight int32) uintptr {
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	font, _, _ := procCreateFontW.Call(
		uintptr(height),
		0, 0, 0,
		uintptr(weight),
		0, 0, 0,
		1,
		0, 0,
		5,
		0,
		uintptr(unsafe.Pointer(ptr)),
	)
	return font
}

func setupWindowProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	activeWizardMu.Lock()
	w := activeWizard
	activeWizardMu.Unlock()

	switch msg {
	case wmPaint:
		if w != nil {
			w.paint()
		}
		return 0

	case wmEraseBkgnd:
		return 1 // Flicker-free double buffering

	case wmSize:
		if w != nil {
			width := int32(lParam & 0xFFFF)
			height := int32((lParam >> 16) & 0xFFFF)
			w.layout(width, height)
		}
		return 0

	case wmMouseMove:
		if w != nil {
			x := int32(lParam & 0xFFFF)
			y := int32((lParam >> 16) & 0xFFFF)
			btnRc := w.getButtonRect()
			inside := x >= btnRc.Left && x <= btnRc.Right && y >= btnRc.Top && y <= btnRc.Bottom

			w.mu.Lock()
			changed := w.btnHover != inside
			w.btnHover = inside
			w.mu.Unlock()

			if changed {
				_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		return 0

	case wmSetCursor:
		if w != nil && w.isDone() {
			w.mu.Lock()
			hover := w.btnHover
			w.mu.Unlock()
			if hover && w.cursorHand != 0 {
				_, _, _ = procSetCursor.Call(w.cursorHand)
				return 1
			}
		}

	case wmLButtonDown:
		if w != nil && w.isDone() {
			x := int32(lParam & 0xFFFF)
			y := int32((lParam >> 16) & 0xFFFF)
			btnRc := w.getButtonRect()
			if x >= btnRc.Left && x <= btnRc.Right && y >= btnRc.Top && y <= btnRc.Bottom {
				w.mu.Lock()
				w.btnPressed = true
				w.mu.Unlock()
				_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		return 0

	case wmLButtonUp:
		if w != nil && w.isDone() {
			x := int32(lParam & 0xFFFF)
			y := int32((lParam >> 16) & 0xFFFF)
			btnRc := w.getButtonRect()
			w.mu.Lock()
			wasPressed := w.btnPressed
			w.btnPressed = false
			w.mu.Unlock()

			if wasPressed {
				_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
				if x >= btnRc.Left && x <= btnRc.Right && y >= btnRc.Top && y <= btnRc.Bottom {
					w.onActionClicked()
					_, _, _ = procDestroyWindow.Call(hwnd)
				}
			}
		}
		return 0

	case wmKeyDown:
		if wParam == 13 || wParam == 32 { // Enter or Space
			if w != nil && w.isDone() {
				w.onActionClicked()
				_, _, _ = procDestroyWindow.Call(hwnd)
			}
			return 0
		}

	case wmSetupUpdate:
		if w != nil {
			_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0

	case wmSetupComplete:
		if w != nil {
			w.handleComplete()
		}
		return 0

	case wmCtlColorEdit, wmCtlColorStatic:
		if w != nil && uintptr(lParam) == w.hwndErrorBox {
			hdc := wParam
			_, _, _ = procSetBkMode.Call(hdc, 2)
			_, _, _ = procSetTextColor.Call(hdc, rgb(252, 165, 165)) // Light Crimson Red
			_, _, _ = procSetBkColor.Call(hdc, rgb(20, 10, 14))      // Dark Glass Crimson
			return w.brushErrorBg
		}
		hdc := wParam
		_, _, _ = procSetBkMode.Call(hdc, 1)
		brush, _, _ := procGetSysColorBrush.Call(colorBtnFace)
		return brush

	case wmClose:
		if w != nil && !w.isDone() {
			return 0
		}
		_, _, _ = procDestroyWindow.Call(hwnd)
		return 0

	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
}

func (w *setupWizard) getButtonRect() rect {
	w.mu.Lock()
	curW := w.currentW
	curH := w.currentH
	w.mu.Unlock()

	btnW := int32(130)
	btnH := int32(36)
	btnX := curW - btnW - 24
	btnY := curH - btnH - 12
	return rect{Left: btnX, Top: btnY, Right: btnX + btnW, Bottom: btnY + btnH}
}

func (w *setupWizard) Update(percent int, status, detail string) {
	w.mu.Lock()
	if percent > 100 {
		percent = 100
	}
	if percent < 0 {
		percent = 0
	}
	w.percent = percent
	w.statusText = status
	w.detailText = detail
	w.mu.Unlock()

	if w.hwnd != 0 {
		_, _, _ = procPostMessageW.Call(w.hwnd, wmSetupUpdate, 0, 0)
	}
}

func (w *setupWizard) Complete(err error) {
	w.mu.Lock()
	w.completed = true
	if err != nil {
		w.success = false
		w.errMessage = err.Error()
	} else {
		w.success = true
	}
	w.mu.Unlock()

	if w.hwnd != 0 {
		_, _, _ = procPostMessageW.Call(w.hwnd, wmSetupComplete, 0, 0)
	}
}

func (w *setupWizard) isDone() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.completed
}

func (w *setupWizard) handleComplete() {
	w.mu.Lock()
	success := w.success
	errMsg := w.errMessage
	curW := w.currentW
	curH := w.currentH
	w.mu.Unlock()

	if !success {
		fullErrorText := "FEHLERDETAILS:\r\n" + errMsg + "\r\n"
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			diagLog := filepath.Join(localAppData, "VGT", "InstallerDiagnostics", "latest-transaction.log")
			if content, readErr := readDiagnosticLogTail(diagLog, 25); readErr == nil && len(content) > 0 {
				fullErrorText += "\r\nDIAGNOSE-PROTOKOLL:\r\n" + strings.Join(content, "\r\n")
			}
		}

		errTextPtr, _ := syscall.UTF16PtrFromString(fullErrorText)
		_, _, _ = procSetWindowTextW.Call(w.hwndErrorBox, uintptr(unsafe.Pointer(errTextPtr)))
	}

	w.layout(curW, curH)

	if w.hwnd != 0 {
		_, _, _ = procInvalidateRect.Call(w.hwnd, 0, 0)
	}
}

func (w *setupWizard) paint() {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(w.hwnd, uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	defer procEndPaint.Call(w.hwnd, uintptr(unsafe.Pointer(&ps)))

	var rc rect
	_, _, _ = procGetClientRect.Call(w.hwnd, uintptr(unsafe.Pointer(&rc)))
	width := rc.Right - rc.Left
	height := rc.Bottom - rc.Top
	if width <= 0 || height <= 0 {
		return
	}

	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	memBmp, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(width), uintptr(height))
	oldBmp, _, _ := procSelectObject.Call(memDC, memBmp)

	w.drawScene(memDC, width, height)

	_, _, _ = procBitBlt.Call(hdc, 0, 0, uintptr(width), uintptr(height), memDC, 0, 0, srcCopy)

	_, _, _ = procSelectObject.Call(memDC, oldBmp)
	_, _, _ = procDeleteObject.Call(memBmp)
	_, _, _ = procDeleteDC.Call(memDC)
}

func (w *setupWizard) drawScene(hdc uintptr, width, height int32) {
	w.mu.Lock()
	pct := w.percent
	status := w.statusText
	detail := w.detailText
	done := w.completed
	success := w.success
	isUninstall := w.uninstall
	hover := w.btnHover
	pressed := w.btnPressed
	w.mu.Unlock()

	hasError := done && !success

	// 1. Dark Obsidian Glass Canvas Background
	_, _, _ = procSelectObject.Call(hdc, w.brushWindowBg)
	_, _, _ = procSelectObject.Call(hdc, w.penDivider)
	_, _, _ = procRectangle.Call(hdc, 0, 0, uintptr(width), uintptr(height))

	// 2. Neon Cyan Glow Rim on Top Edge (2px)
	_, _, _ = procSelectObject.Call(hdc, w.penTopRim)
	_, _, _ = procMoveToEx.Call(hdc, 0, 0, 0)
	_, _, _ = procLineTo.Call(hdc, uintptr(width), 0)
	_, _, _ = procMoveToEx.Call(hdc, 0, 1, 0)
	_, _, _ = procLineTo.Call(hdc, uintptr(width), 1)

	// 3. Cyber Shield Emblem (left: 24, top: 18)
	shieldPts := []point{
		{X: 24, Y: 18},
		{X: 52, Y: 18},
		{X: 52, Y: 36},
		{X: 38, Y: 52},
		{X: 24, Y: 36},
	}
	_, _, _ = procSelectObject.Call(hdc, w.brushShieldBg)
	_, _, _ = procSelectObject.Call(hdc, w.penShield)
	_, _, _ = procPolygon.Call(hdc, uintptr(unsafe.Pointer(&shieldPts[0])), uintptr(len(shieldPts)))

	// Inner Core Accent
	_, _, _ = procSelectObject.Call(hdc, w.penTopRim)
	_, _, _ = procMoveToEx.Call(hdc, 38, 25, 0)
	_, _, _ = procLineTo.Call(hdc, 38, 42)

	// 4. Header Titles & Version Badge
	_, _, _ = procSetBkMode.Call(hdc, 1)

	// App Name
	titleText := "VGT GE·DEFENSE"
	if isUninstall {
		titleText = "VGT GE·DEFENSE DEINSTALLATION"
	}
	titlePtr, _ := syscall.UTF16PtrFromString(titleText)
	titleRc := rect{Left: 64, Top: 16, Right: 300, Bottom: 42}
	_, _, _ = procSetTextColor.Call(hdc, rgb(255, 255, 255))
	_, _, _ = procSelectObject.Call(hdc, w.fontTitle)
	_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(titlePtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&titleRc)), dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)

	// Version Glass Badge (pill)
	badgeX := int32(236)
	if isUninstall {
		badgeX = int32(410)
	}
	badgeW := int32(110)
	_, _, _ = procSelectObject.Call(hdc, w.brushBadgeBg)
	_, _, _ = procSelectObject.Call(hdc, w.penBadgeRim)
	_, _, _ = procRoundRect.Call(hdc, uintptr(badgeX), 18, uintptr(badgeX+badgeW), 40, 10, 10)

	badgeText := "v" + product.Version
	badgePtr, _ := syscall.UTF16PtrFromString(badgeText)
	badgeRc := rect{Left: badgeX, Top: 18, Right: badgeX + badgeW, Bottom: 40}
	_, _, _ = procSetTextColor.Call(hdc, rgb(56, 189, 248)) // Electric Cyan
	_, _, _ = procSelectObject.Call(hdc, w.fontBadge)
	_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(badgePtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&badgeRc)), dtCenter|dtVCenter|dtSingleLine|dtNoPrefix)

	// Subtitle
	subText := "SOVEREIGN ENDPOINT PROTECTION — DIAMANT VGT SUPREME"
	if isUninstall {
		subText = "Entfernen der Sovereign Security Komponenten"
	}
	subPtr, _ := syscall.UTF16PtrFromString(subText)
	subRc := rect{Left: 64, Top: 44, Right: width - 24, Bottom: 64}
	_, _, _ = procSetTextColor.Call(hdc, rgb(148, 163, 184)) // Steel Slate
	_, _, _ = procSelectObject.Call(hdc, w.fontSmall)
	_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(subPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&subRc)), dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)

	// 5. Divider Line Top (Y = 72)
	_, _, _ = procSelectObject.Call(hdc, w.penDivider)
	_, _, _ = procMoveToEx.Call(hdc, 0, 72, 0)
	_, _, _ = procLineTo.Call(hdc, uintptr(width), 72)

	cardMargin := int32(24)
	cardTop := int32(88)
	cardBottom := height - 66
	cardW := width - (cardMargin * 2)

	if hasError {
		// Glass Error Card Header
		errHeadText := "INSTALLATION FEHLGESCHLAGEN"
		errHeadPtr, _ := syscall.UTF16PtrFromString(errHeadText)
		errHeadRc := rect{Left: cardMargin + 16, Top: cardTop + 10, Right: width - cardMargin - 16, Bottom: cardTop + 34}
		_, _, _ = procSetTextColor.Call(hdc, rgb(248, 113, 113)) // Red
		_, _, _ = procSelectObject.Call(hdc, w.fontHeader)
		_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(errHeadPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&errHeadRc)), dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)
	} else {
		// 6. The Central Frosted Glass Card
		_, _, _ = procSelectObject.Call(hdc, w.brushCardBg)
		_, _, _ = procSelectObject.Call(hdc, w.penCardRim)
		_, _, _ = procRoundRect.Call(hdc, uintptr(cardMargin), uintptr(cardTop), uintptr(cardMargin+cardW), uintptr(cardBottom), 14, 14)

		// Inner Status Headline
		dispStatus := status
		if dispStatus == "" {
			dispStatus = "Vorbereitung..."
		}
		if done && success {
			if isUninstall {
				dispStatus = "Deinstallation erfolgreich abgeschlossen"
			} else {
				dispStatus = "Installation erfolgreich abgeschlossen!"
			}
		}
		stPtr, _ := syscall.UTF16PtrFromString(dispStatus)
		stRc := rect{Left: cardMargin + 20, Top: cardTop + 18, Right: cardMargin + cardW - 20, Bottom: cardTop + 44}
		_, _, _ = procSetTextColor.Call(hdc, rgb(248, 250, 252)) // Crisp White
		_, _, _ = procSelectObject.Call(hdc, w.fontHeader)
		_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(stPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&stRc)), dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)

		// Inner Detail Ticker
		dispDetail := detail
		if dispDetail == "" {
			dispDetail = "Sovereign Systemumgebung wird initialisiert..."
		}
		if done && success {
			if isUninstall {
				dispDetail = "GeDefense wurde sicher vom Host entfernt."
			} else {
				dispDetail = "Das Security Center ist einsatzbereit und im Startmenü registriert."
			}
		}
		dtPtr, _ := syscall.UTF16PtrFromString(dispDetail)
		dtRc := rect{Left: cardMargin + 20, Top: cardTop + 46, Right: cardMargin + cardW - 20, Bottom: cardTop + 84}
		_, _, _ = procSetTextColor.Call(hdc, rgb(148, 163, 184)) // Soft Cyan-Grey
		_, _, _ = procSelectObject.Call(hdc, w.fontRegular)
		_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(dtPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&dtRc)), dtLeft|dtWordBreak|dtNoPrefix)

		// Glass Progress Bar Capsule
		progX := cardMargin + 20
		progY := cardTop + 96
		progW := cardW - 40
		progH := int32(16)

		// Outer Dark Track
		_, _, _ = procSelectObject.Call(hdc, w.brushTrackBg)
		_, _, _ = procSelectObject.Call(hdc, w.penTrackRim)
		_, _, _ = procRoundRect.Call(hdc, uintptr(progX), uintptr(progY), uintptr(progX+progW), uintptr(progY+progH), 8, 8)

		// Inner Glowing Fill
		if pct > 0 {
			fillW := int32(float64(progW) * float64(pct) / 100.0)
			if fillW < 10 {
				fillW = 10
			}
			if fillW > progW {
				fillW = progW
			}

			fillBrush := w.brushProgFill
			if done && success {
				fillBrush = w.brushProgDone // Emerald Green
			}

			_, _, _ = procSelectObject.Call(hdc, fillBrush)
			_, _, _ = procSelectObject.Call(hdc, w.penTopRim)
			if done && success {
				_, _, _ = procSelectObject.Call(hdc, w.penCardRim)
			}
			_, _, _ = procRoundRect.Call(hdc, uintptr(progX), uintptr(progY), uintptr(progX+fillW), uintptr(progY+progH), 8, 8)
		}

		// Progress Meta Row
		metaY := progY + 24
		bulletText := "● Phase: In Bearbeitung..."
		bulletColor := rgb(56, 189, 248)
		if done && success {
			bulletText = "✔ Status: Guarded aktiv (Sovereign Endpoint)"
			bulletColor = rgb(52, 211, 153)
		}

		bPtr, _ := syscall.UTF16PtrFromString(bulletText)
		bRc := rect{Left: progX, Top: metaY, Right: progX + (progW / 2), Bottom: metaY + 20}
		_, _, _ = procSetTextColor.Call(hdc, bulletColor)
		_, _, _ = procSelectObject.Call(hdc, w.fontSmall)
		_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(bPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&bRc)), dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)

		pctText := fmt.Sprintf("%d%%", pct)
		pctPtr, _ := syscall.UTF16PtrFromString(pctText)
		pctRc := rect{Left: progX + (progW / 2), Top: metaY - 2, Right: progX + progW, Bottom: metaY + 20}
		_, _, _ = procSetTextColor.Call(hdc, rgb(0, 229, 255)) // Neon Cyan
		_, _, _ = procSelectObject.Call(hdc, w.fontHeader)
		_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(pctPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&pctRc)), dtRight|dtVCenter|dtSingleLine|dtNoPrefix)
	}

	// 7. Divider Line Bottom (Y = height - 58)
	_, _, _ = procSelectObject.Call(hdc, w.penDivider)
	_, _, _ = procMoveToEx.Call(hdc, 0, uintptr(height-58), 0)
	_, _, _ = procLineTo.Call(hdc, uintptr(width), uintptr(height-58))

	// 8. Brand Footer
	brandText := "VisionGaia Technology © 2026 | DIAMANT VGT SUPREME"
	brandPtr, _ := syscall.UTF16PtrFromString(brandText)
	brandRc := rect{Left: 24, Top: height - 44, Right: width - 150, Bottom: height - 16}
	_, _, _ = procSetTextColor.Call(hdc, rgb(100, 116, 139))
	_, _, _ = procSelectObject.Call(hdc, w.fontSmall)
	_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(brandPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&brandRc)), dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)

	// 9. Modern Glass Action Button (Pill)
	btnRc := w.getButtonRect()
	var btnBg uintptr
	var btnRim uintptr
	var btnTextColor uintptr
	btnLabel := "Bitte warten..."

	if !done {
		btnBg = w.brushBtnDis
		btnRim = w.penBtnDisRim
		btnTextColor = rgb(100, 116, 139)
	} else {
		if pressed {
			btnBg = w.brushBtnPress
		} else if hover {
			btnBg = w.brushBtnHover
		} else {
			btnBg = w.brushBtnNorm
		}
		btnRim = w.penBtnRim
		btnTextColor = rgb(255, 255, 255)

		if success {
			if isUninstall {
				btnLabel = "Schließen"
			} else {
				btnLabel = "Fertigstellen"
			}
		} else {
			btnLabel = "Schließen"
		}
	}

	_, _, _ = procSelectObject.Call(hdc, btnBg)
	_, _, _ = procSelectObject.Call(hdc, btnRim)
	_, _, _ = procRoundRect.Call(hdc, uintptr(btnRc.Left), uintptr(btnRc.Top), uintptr(btnRc.Right), uintptr(btnRc.Bottom), 10, 10)

	btnPtr, _ := syscall.UTF16PtrFromString(btnLabel)
	textRc := btnRc
	_, _, _ = procSetTextColor.Call(hdc, btnTextColor)
	_, _, _ = procSelectObject.Call(hdc, w.fontHeader)
	_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(btnPtr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&textRc)), dtCenter|dtVCenter|dtSingleLine|dtNoPrefix)
}

func readDiagnosticLogTail(path string, maxLines int) ([]string, error) {
	file, err := openSharedFileForRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, scanner.Err()
}

func (w *setupWizard) layout(width, height int32) {
	if width <= 0 || height <= 0 {
		return
	}
	w.mu.Lock()
	w.currentW = width
	w.currentH = height
	hasError := !w.success && w.completed
	w.mu.Unlock()

	if hasError {
		if w.hwndErrorBox != 0 {
			errX := int32(28)
			errY := int32(124)
			errW := width - 56
			errH := height - 194
			if errH < 80 {
				errH = 80
			}
			_, _, _ = procShowWindow.Call(w.hwndErrorBox, 5)
			_, _, _ = procMoveWindow.Call(w.hwndErrorBox, uintptr(errX), uintptr(errY), uintptr(errW), uintptr(errH), 1)
		}
	} else {
		if w.hwndErrorBox != 0 {
			_, _, _ = procShowWindow.Call(w.hwndErrorBox, 0)
		}
	}

	if w.hwnd != 0 {
		_, _, _ = procInvalidateRect.Call(w.hwnd, 0, 0)
	}
}

func (w *setupWizard) onActionClicked() {
	w.mu.Lock()
	launch := w.success && !w.uninstall
	w.mu.Unlock()

	if launch {
		centerPath := filepath.Join(os.Getenv("ProgramFiles"), "VGT", "GeDefense", "bin", "GeDefenseCenter.exe")
		if _, err := os.Stat(centerPath); err == nil {
			centerPtr, _ := syscall.UTF16PtrFromString(centerPath)
			openPtr, _ := syscall.UTF16PtrFromString("open")
			_, _, _ = procShellExecuteW.Call(0, uintptr(unsafe.Pointer(openPtr)), uintptr(unsafe.Pointer(centerPtr)), 0, 0, 1)
		}
	}
}

func (w *setupWizard) cleanup() {
	if w.fontTitle != 0 {
		_, _, _ = procDeleteObject.Call(w.fontTitle)
	}
	if w.fontBadge != 0 {
		_, _, _ = procDeleteObject.Call(w.fontBadge)
	}
	if w.fontHeader != 0 {
		_, _, _ = procDeleteObject.Call(w.fontHeader)
	}
	if w.fontRegular != 0 {
		_, _, _ = procDeleteObject.Call(w.fontRegular)
	}
	if w.fontSmall != 0 {
		_, _, _ = procDeleteObject.Call(w.fontSmall)
	}
	if w.fontMono != 0 {
		_, _, _ = procDeleteObject.Call(w.fontMono)
	}

	// Pens
	for _, pen := range []uintptr{w.penTopRim, w.penDivider, w.penCardRim, w.penBadgeRim, w.penTrackRim, w.penBtnRim, w.penBtnDisRim, w.penShield, w.penErrorRim} {
		if pen != 0 {
			_, _, _ = procDeleteObject.Call(pen)
		}
	}

	// Brushes
	for _, b := range []uintptr{w.brushWindowBg, w.brushCardBg, w.brushBadgeBg, w.brushTrackBg, w.brushProgFill, w.brushProgDone, w.brushBtnNorm, w.brushBtnHover, w.brushBtnPress, w.brushBtnDis, w.brushErrorBg, w.brushShieldBg} {
		if b != 0 {
			_, _, _ = procDeleteObject.Call(b)
		}
	}
}

func runSetupWizard(uninstall, elevated bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	setDPIAwareness()
	initCommonControls()

	instance, _, callErr := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return fmt.Errorf("GetModuleHandleW failed: %w", callErr)
	}

	cursorArrow, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))
	cursorHand, _, _ := procLoadCursorW.Call(0, uintptr(idcHand))
	icon, _, _ := procLoadIconW.Call(0, uintptr(idcArrow))
	classNamePtr, _ := syscall.UTF16PtrFromString("VGTGeDefenseGlassWizardV4")

	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		Style:      0x0003,
		WndProc:    setupCallback,
		Instance:   instance,
		Icon:       icon,
		Cursor:     cursorArrow,
		Background: 0, // Painted by WM_PAINT
		ClassName:  classNamePtr,
		IconSmall:  icon,
	}

	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 && regErr != syscall.Errno(1410) {
		return fmt.Errorf("RegisterClassExW failed: %w", regErr)
	}

	screenWidth, _, _ := procGetSystemMetrics.Call(0)
	screenHeight, _, _ := procGetSystemMetrics.Call(1)
	x := (int32(screenWidth) - defaultWidth) / 2
	y := (int32(screenHeight) - defaultHeight) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	title := fmt.Sprintf("VGT GeDefense Setup — Version %s", product.Version)
	if uninstall {
		title = fmt.Sprintf("VGT GeDefense Deinstallation — Version %s", product.Version)
	}
	titlePtr, _ := syscall.UTF16PtrFromString(title)

	hwnd, _, createErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox|wsMaximizeBox|wsThickFrame|wsClipChildren,
		uintptr(x),
		uintptr(y),
		uintptr(defaultWidth),
		uintptr(defaultHeight),
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %w", createErr)
	}

	applyDwmGlassAttributes(hwnd)

	// GDI Pens
	penTopRim, _, _ := procCreatePen.Call(0, 2, rgb(0, 229, 255))
	penDivider, _, _ := procCreatePen.Call(0, 1, rgb(28, 38, 56))
	penCardRim, _, _ := procCreatePen.Call(0, 1, rgb(34, 48, 71))
	penBadgeRim, _, _ := procCreatePen.Call(0, 1, rgb(14, 165, 233))
	penTrackRim, _, _ := procCreatePen.Call(0, 1, rgb(28, 38, 56))
	penBtnRim, _, _ := procCreatePen.Call(0, 1, rgb(0, 210, 255))
	penBtnDisRim, _, _ := procCreatePen.Call(0, 1, rgb(45, 60, 85))
	penShield, _, _ := procCreatePen.Call(0, 2, rgb(0, 229, 255))
	penErrorRim, _, _ := procCreatePen.Call(0, 1, rgb(153, 27, 27))

	// GDI Brushes
	brushWindowBg, _, _ := procCreateSolidBrush.Call(rgb(10, 14, 23))
	brushCardBg, _, _ := procCreateSolidBrush.Call(rgb(15, 23, 42))
	brushBadgeBg, _, _ := procCreateSolidBrush.Call(rgb(17, 24, 39))
	brushTrackBg, _, _ := procCreateSolidBrush.Call(rgb(7, 10, 18))
	brushProgFill, _, _ := procCreateSolidBrush.Call(rgb(0, 229, 255))
	brushProgDone, _, _ := procCreateSolidBrush.Call(rgb(16, 185, 129))
	brushBtnNorm, _, _ := procCreateSolidBrush.Call(rgb(0, 180, 216))
	brushBtnHover, _, _ := procCreateSolidBrush.Call(rgb(56, 215, 248))
	brushBtnPress, _, _ := procCreateSolidBrush.Call(rgb(0, 140, 175))
	brushBtnDis, _, _ := procCreateSolidBrush.Call(rgb(22, 30, 46))
	brushErrorBg, _, _ := procCreateSolidBrush.Call(rgb(24, 12, 16))
	brushShieldBg, _, _ := procCreateSolidBrush.Call(rgb(10, 36, 56))

	wizard := &setupWizard{
		hwnd:          hwnd,
		uninstall:     uninstall,
		currentW:      defaultWidth,
		currentH:      defaultHeight,
		cursorArrow:   cursorArrow,
		cursorHand:    cursorHand,
		fontTitle:     createFont("Segoe UI", -20, 700),
		fontBadge:     createFont("Segoe UI", -11, 700),
		fontHeader:    createFont("Segoe UI", -15, 600),
		fontRegular:   createFont("Segoe UI", -12, 400),
		fontSmall:     createFont("Segoe UI", -11, 400),
		fontMono:      createFont("Consolas", -11, 400),
		penTopRim:     penTopRim,
		penDivider:    penDivider,
		penCardRim:    penCardRim,
		penBadgeRim:   penBadgeRim,
		penTrackRim:   penTrackRim,
		penBtnRim:     penBtnRim,
		penBtnDisRim:  penBtnDisRim,
		penShield:     penShield,
		penErrorRim:   penErrorRim,
		brushWindowBg: brushWindowBg,
		brushCardBg:   brushCardBg,
		brushBadgeBg:  brushBadgeBg,
		brushTrackBg:  brushTrackBg,
		brushProgFill: brushProgFill,
		brushProgDone: brushProgDone,
		brushBtnNorm:  brushBtnNorm,
		brushBtnHover: brushBtnHover,
		brushBtnPress: brushBtnPress,
		brushBtnDis:   brushBtnDis,
		brushErrorBg:  brushErrorBg,
		brushShieldBg: brushShieldBg,
	}

	activeWizardMu.Lock()
	activeWizard = wizard
	activeWizardMu.Unlock()
	defer func() {
		activeWizardMu.Lock()
		activeWizard = nil
		activeWizardMu.Unlock()
		wizard.cleanup()
	}()

	editClass, _ := syscall.UTF16PtrFromString("EDIT")
	emptyPtr, _ := syscall.UTF16PtrFromString("")

	hErrorBox, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(editClass)), uintptr(unsafe.Pointer(emptyPtr)),
		wsChild|wsVScroll|wsBorder|esMultiline|esReadOnly|esAutoVScroll,
		28, 124, uintptr(defaultWidth-56), 200,
		hwnd, idErrorBox, instance, 0,
	)
	wizard.hwndErrorBox = hErrorBox
	if wizard.fontMono != 0 && hErrorBox != 0 {
		_, _, _ = procSendMessageW.Call(hErrorBox, wmSetFont, wizard.fontMono, 1)
	}

	_, _, _ = procShowWindow.Call(hwnd, 5)
	_, _, _ = procUpdateWindow.Call(hwnd)

	var workerErr error
	go func() {
		workerErr = execute(uninstall, elevated, func(percent int, status, detail string) {
			wizard.Update(percent, status, detail)
		})
		wizard.Complete(workerErr)
	}()

	var msg msgStruct
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	return workerErr
}

func openSharedFileForRead(path string) (*os.File, error) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const (
		genericRead     = 0x80000000
		fileShareRead   = 0x00000001
		fileShareWrite  = 0x00000002
		fileShareDelete = 0x00000004
		openExisting    = 3
	)
	h, err := syscall.CreateFile(
		ptr,
		genericRead,
		fileShareRead|fileShareWrite|fileShareDelete,
		nil,
		openExisting,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func monitorDiagnosticLog(stop <-chan struct{}, update ProgressCallback) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return
	}
	logPath := filepath.Join(localAppData, "VGT", "InstallerDiagnostics", "latest-transaction.log")
	_ = os.Remove(logPath)

	ticker := time.NewTicker(60 * time.Millisecond)
	defer ticker.Stop()

	var file *os.File
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	reader := bufio.NewReader(nil)

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if file == nil {
				f, err := openSharedFileForRead(logPath)
				if err != nil {
					continue
				}
				file = f
				reader = bufio.NewReader(file)
			}

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						break
					}
					break
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, "|", 4)
				if len(parts) >= 3 {
					phase := parts[1]
					state := parts[2]
					detail := ""
					if len(parts) >= 4 {
						detail = parts[3]
					}
					pct, headline := mapPhaseToProgress(phase, state)
					if pct > 0 {
						update(pct, headline, detail)
					}
				}
			}
		}
	}
}

func mapPhaseToProgress(phase, state string) (int, string) {
	switch phase {
	case "Elevation":
		return 40, "Administrator-Berechtigungen bestätigt"
	case "Trust":
		return 45, "Signaturen und Sicherheitszertifikate validiert"
	case "Files":
		return 55, "Programmdateien werden installiert"
	case "OperatorGroup":
		return 62, "VGT GeDefense Operatorengruppe eingerichtet"
	case "ACL":
		return 68, "Dateisystem-Zugriffsrechte gehärtet (ACL)"
	case "ServiceRegistration":
		return 74, "VGT GeDefense Systemdienst registriert"
	case "Branding":
		return 78, "OEM-Branding & Sperrbildschirm konfiguriert"
	case "ApplicationRegistration":
		return 82, "Security Center & Autostart registriert"
	case "MHXState":
		return 85, "MHX Kernel-Status initialisiert (Guarded)"
	case "ServiceStart":
		return 88, "GeDefense Windows-Dienst gestartet"
	case "DefenderReadiness":
		return 91, "Microsoft Defender Koexistenz geprüft"
	case "Hardening":
		return 94, "Systemhärtung aktiviert (EnterpriseBalanced)"
	case "MHXRealtime":
		return 96, "MHX Echtzeitschutz & WFP Filter aktiv"
	case "AppControl":
		return 98, "Kernel Audit Policy bereitgestellt"
	case "Installer":
		if state == "COMPLETE" {
			return 100, "Installation erfolgreich abgeschlossen"
		}
		return 38, "Installationstransaktion wird ausgeführt"
	default:
		return 0, ""
	}
}
