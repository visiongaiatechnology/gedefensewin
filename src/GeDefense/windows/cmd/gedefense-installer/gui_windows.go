// STATUS: DIAMANT VGT SUPREME
//go:build windows

package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/userlaunch"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// The 52 px mark is pre-composited on the installer tile colour, so it can be
// blitted with SRCCOPY and needs no runtime image decoder or material file.
//
//go:embed assets/gedefense-mark.png
var installerLogoPNG []byte

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

	defaultWidth  = 780
	defaultHeight = 540
	minWidth      = 700
	minHeight     = 480

	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwaBorderColor            = 34
	dwmwaCaptionColor           = 35
	dwmwaTextColor              = 36
	dwmwaSystemBackdropType     = 38

	dwmwcpRound           = 2
	dwmsbtMainWindow      = 2 // Mica
	dwmsbtTransientWindow = 3 // Acrylic Glass

	idcArrow  = 32512
	idcShield = 32518
	idcHand   = 32649
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
	procStretchDIBits          = gdi32.NewProc("StretchDIBits")

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

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type rgbQuad struct {
	Blue, Green, Red, Reserved byte
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]rgbQuad
}

func (w *setupWizard) drawInstallerLogo(hdc uintptr, left, top int32) bool {
	if len(w.logoPixels) == 0 || w.logoW <= 0 || w.logoH <= 0 {
		return false
	}
	info := bitmapInfo{Header: bitmapInfoHeader{
		Size:        40,
		Width:       w.logoW,
		Height:      -w.logoH,
		Planes:      1,
		BitCount:    32,
		Compression: 0,
	}}
	_, _, _ = procStretchDIBits.Call(
		hdc,
		uintptr(left), uintptr(top), uintptr(w.logoW), uintptr(w.logoH),
		0, 0, uintptr(w.logoW), uintptr(w.logoH),
		uintptr(unsafe.Pointer(&w.logoPixels[0])),
		uintptr(unsafe.Pointer(&info)),
		0,
		uintptr(srcCopy),
	)
	return true
}

func decodeInstallerLogo() (pixels []byte, width, height int32) {
	image, err := png.Decode(bytes.NewReader(installerLogoPNG))
	if err != nil || image == nil {
		return nil, 0, 0
	}
	bounds := image.Bounds()
	width = int32(bounds.Dx())
	height = int32(bounds.Dy())
	if width <= 0 || height <= 0 || width > 256 || height > 256 {
		return nil, 0, 0
	}
	pixels = make([]byte, int(width*height*4))
	for y := int32(0); y < height; y++ {
		for x := int32(0); x < width; x++ {
			r, g, b, _ := image.At(bounds.Min.X+int(x), bounds.Min.Y+int(y)).RGBA()
			offset := int((y*width + x) * 4)
			pixels[offset] = byte(b >> 8)
			pixels[offset+1] = byte(g >> 8)
			pixels[offset+2] = byte(r >> 8)
			pixels[offset+3] = 0xFF
		}
	}
	return pixels, width, height
}

type setupWizard struct {
	hwnd         uintptr
	hwndErrorBox uintptr

	fontBrand    uintptr
	fontTitle    uintptr
	fontBadge    uintptr
	fontHeader   uintptr
	fontHeadline uintptr
	fontMetric   uintptr
	fontStep     uintptr
	fontRegular  uintptr
	fontSmall    uintptr
	fontMono     uintptr

	logoPixels []byte
	logoW      int32
	logoH      int32

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
	brushGlow     uintptr
	brushHeader   uintptr
	brushStepIdle uintptr
	brushStepDone uintptr

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
	preview    bool
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

		borderColor := uint32(0x005A3A0F) // deep marine border RGB(15, 58, 90)
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaBorderColor, uintptr(unsafe.Pointer(&borderColor)), 4)

		// Windows 11 caption attributes. They keep the native title bar inside
		// the same navy material system rather than leaving a light strip above
		// the dark client area.
		captionColor := uint32(0x001B0F04) // RGB(4, 15, 27)
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaCaptionColor, uintptr(unsafe.Pointer(&captionColor)), 4)
		captionText := uint32(0x00FFF8F1) // RGB(241, 248, 255)
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaTextColor, uintptr(unsafe.Pointer(&captionText)), 4)

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
		if w != nil && !w.isDone() && !w.preview {
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

	btnW := int32(168)
	btnH := int32(40)
	btnX := curW - btnW - 30
	btnY := curH - 62
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
	defer func() {
		// EndPaint always returns nonzero; it has no failure channel.
		_, _, _ = procEndPaint.Call(w.hwnd, uintptr(unsafe.Pointer(&ps)))
	}()

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

	w.drawSceneV5(memDC, width, height)

	_, _, _ = procBitBlt.Call(hdc, 0, 0, uintptr(width), uintptr(height), memDC, 0, 0, srcCopy)

	_, _, _ = procSelectObject.Call(memDC, oldBmp)
	_, _, _ = procDeleteObject.Call(memBmp)
	_, _, _ = procDeleteDC.Call(memDC)
}

// drawSceneV5 renders the installer as a calm, high-trust VGT surface. It is
// deliberately painted with a small GDI vocabulary: deep navy planes, one ice
// signal, readable type and an explicit progress/step rail. No gradients or
// animation are required for hierarchy.
func (w *setupWizard) drawSceneV5(hdc uintptr, width, height int32) {
	w.mu.Lock()
	pct := w.percent
	status := w.statusText
	detail := w.detailText
	done := w.completed
	success := w.success
	isUninstall := w.uninstall
	hover := w.btnHover
	pressed := w.btnPressed
	errMessage := w.errMessage
	w.mu.Unlock()

	hasError := done && !success
	// The installer's client area is intentionally composed around a clear
	// header, one primary status plane and a persistent footer.
	headerH := int32(104)
	footerH := int32(84)
	cardX, cardY := int32(28), int32(118)
	cardW := width - 56
	cardBottom := height - footerH - 12
	if cardBottom < cardY+210 {
		cardBottom = cardY + 210
	}

	// Environment: a quiet pigment field with one controlled light zone.
	selectObj := func(obj uintptr) {
		_, _, _ = procSelectObject.Call(hdc, obj)
	}
	fillRect := func(left, top, right, bottom int32, brush, pen uintptr) {
		selectObj(brush)
		selectObj(pen)
		_, _, _ = procRectangle.Call(hdc, uintptr(left), uintptr(top), uintptr(right), uintptr(bottom))
	}
	fillRound := func(left, top, right, bottom, radius int32, brush, pen uintptr) {
		selectObj(brush)
		selectObj(pen)
		_, _, _ = procRoundRect.Call(hdc, uintptr(left), uintptr(top), uintptr(right), uintptr(bottom), uintptr(radius), uintptr(radius))
	}
	line := func(x1, y1, x2, y2 int32, pen uintptr) {
		selectObj(pen)
		_, _, _ = procMoveToEx.Call(hdc, uintptr(x1), uintptr(y1), 0)
		_, _, _ = procLineTo.Call(hdc, uintptr(x2), uintptr(y2))
	}
	text := func(value string, font, color uintptr, left, top, right, bottom int32, flags uintptr) {
		if value == "" {
			return
		}
		ptr, err := syscall.UTF16PtrFromString(value)
		if err != nil {
			return
		}
		selectObj(font)
		_, _, _ = procSetTextColor.Call(hdc, color)
		rc := rect{Left: left, Top: top, Right: right, Bottom: bottom}
		_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(ptr)), uintptr(^uint(0)), uintptr(unsafe.Pointer(&rc)), flags)
	}
	textLeft := func(value string, font, color uintptr, left, top, right, bottom int32) {
		text(value, font, color, left, top, right, bottom, dtLeft|dtVCenter|dtSingleLine|dtNoPrefix)
	}
	textWrapped := func(value string, font, color uintptr, left, top, right, bottom int32) {
		text(value, font, color, left, top, right, bottom, dtLeft|dtWordBreak|dtNoPrefix)
	}
	textRight := func(value string, font, color uintptr, left, top, right, bottom int32) {
		text(value, font, color, left, top, right, bottom, dtRight|dtVCenter|dtSingleLine|dtNoPrefix)
	}

	_, _, _ = procSetBkMode.Call(hdc, 1) // TRANSPARENT
	fillRect(0, 0, width, height, w.brushWindowBg, w.penDivider)
	// A restrained cool-light wash behind the wordmark. It has no semantic
	// role other than establishing the physical light source.
	fillRound(0, 0, width, 190, 32, w.brushGlow, w.penDivider)
	fillRect(0, 0, width, headerH, w.brushHeader, w.penDivider)
	line(0, headerH, width, headerH, w.penDivider)

	// Brand mark: the real GeDefense emblem, embedded and flattened onto the
	// header fill so it stays crisp without an external asset or alpha runtime.
	if !w.drawInstallerLogo(hdc, 28, 20) {
		fillRound(30, 25, 82, 77, 13, w.brushShieldBg, w.penCardRim)
		shield := []point{{X: 56, Y: 33}, {X: 68, Y: 39}, {X: 68, Y: 52}, {X: 56, Y: 66}, {X: 44, Y: 52}, {X: 44, Y: 39}}
		selectObj(w.brushHeader)
		selectObj(w.penShield)
		_, _, _ = procPolygon.Call(hdc, uintptr(unsafe.Pointer(&shield[0])), uintptr(len(shield)))
		selectObj(w.penShield)
		_, _, _ = procMoveToEx.Call(hdc, 51, 49, 0)
		_, _, _ = procLineTo.Call(hdc, 55, 54)
		_, _, _ = procLineTo.Call(hdc, 63, 44)
	}

	if isUninstall {
		textLeft("GeDefense", w.fontBrand, rgb(241, 248, 255), 96, 20, width-170, 48)
		textLeft("TITAN · SOVEREIGN INTEGRITY · DEINSTALLATION", w.fontSmall, rgb(137, 177, 201), 97, 48, width-170, 66)
	} else {
		textLeft("GeDefense", w.fontBrand, rgb(241, 248, 255), 96, 20, width-170, 48)
		textLeft("TITAN // KILLERDOM · SOVEREIGN ENDPOINT DEFENSE · SETUP", w.fontSmall, rgb(137, 177, 201), 97, 48, width-170, 66)
	}
	textLeft("Lokale Installation · keine Cloud-Abhängigkeit", w.fontSmall, rgb(104, 143, 166), 97, 67, width-170, 84)

	badgeW := int32(104)
	badgeX := width - badgeW - 30
	fillRound(badgeX, 27, badgeX+badgeW, 53, 13, w.brushBadgeBg, w.penBadgeRim)
	text("TITAN "+product.Version, w.fontBadge, rgb(242, 205, 157), badgeX, 27, badgeX+badgeW, 53, dtCenter|dtVCenter|dtSingleLine|dtNoPrefix)
	textRight("SIGNIERT · LOKAL", w.fontSmall, rgb(104, 143, 166), badgeX-40, 59, width-30, 77)

	// Primary plane.
	fillRound(cardX, cardY, cardX+cardW, cardBottom, 18, w.brushCardBg, w.penCardRim)
	leftX := cardX + 28
	leftRight := cardX + cardW - 248
	if leftRight < leftX+300 {
		leftRight = cardX + cardW - 28
	}
	sidecarW := int32(194)
	sidecarX := cardX + cardW - sidecarW - 24
	showSidecar := leftRight < sidecarX-20
	if showSidecar {
		line(sidecarX-24, cardY+22, sidecarX-24, cardBottom-22, w.penDivider)
	}

	eyebrow := "INSTALLATION"
	if isUninstall {
		eyebrow = "DEINSTALLATION"
	}
	textLeft(eyebrow, w.fontStep, rgb(76, 201, 255), leftX, cardY+22, leftRight, cardY+38)

	headline := status
	if headline == "" {
		headline = "Installation wird vorbereitet."
	}
	body := detail
	if done && success {
		if isUninstall {
			headline = "GeDefense Titan wurde entfernt."
			body = "Die Titan-Komponenten wurden vom Host entfernt."
		} else {
			headline = "GeDefense Titan ist bereit."
			body = "Dienst, Sensorik, Quarantäne und Evidenzkette sind verifiziert."
		}
	} else if hasError {
		headline = "Installation nicht abgeschlossen."
		body = "Die Transaktion wurde sicher abgebrochen. Details stehen unten."
	} else if body == "" {
		body = "Signatur, Payload und Systemvoraussetzungen werden lokal geprüft."
	}
	headlineColor := rgb(241, 248, 255)
	if hasError {
		headlineColor = rgb(255, 155, 174)
	}
	textWrapped(headline, w.fontHeadline, headlineColor, leftX, cardY+44, leftRight, cardY+84)
	textWrapped(body, w.fontRegular, rgb(151, 183, 203), leftX, cardY+88, leftRight, cardY+124)

	// The progress rail is a measurement, not a decorative shimmer.
	barY := cardY + 149
	barW := leftRight - leftX - 54
	if barW < 120 {
		barW = 120
	}
	fillRound(leftX, barY, leftX+barW, barY+6, 3, w.brushTrackBg, w.penTrackRim)
	fillW := int32(float64(barW) * float64(pct) / 100.0)
	if fillW < 4 && pct > 0 {
		fillW = 4
	}
	if fillW > barW {
		fillW = barW
	}
	if fillW > 0 {
		fillColor := w.brushProgFill
		if done && success {
			fillColor = w.brushProgDone
		}
		fillRound(leftX, barY, leftX+fillW, barY+6, 3, fillColor, w.penTrackRim)
	}
	textRight(fmt.Sprintf("%d%%", pct), w.fontMetric, rgb(186, 235, 255), leftRight-48, barY-15, leftRight, barY+10)
	textLeft("SIGNIERTE TRANSAKTION", w.fontSmall, rgb(93, 137, 160), leftX, barY+12, leftRight-58, barY+28)

	// Four explicit phases make the wait explainable without a fake log.
	stepActive := 1
	switch {
	case pct >= 82:
		stepActive = 4
	case pct >= 52:
		stepActive = 3
	case pct >= 22:
		stepActive = 2
	}
	if done && success {
		stepActive = 4
	}
	steps := []string{"Vorbereitung", "Schutzmodule", "Systemdienst", "Bereitschaft"}
	if isUninstall {
		steps = []string{"Prüfung", "Entfernung", "Bereinigung", "Abschluss"}
	}
	if !hasError {
		railY := cardBottom - 47
		railLeft := leftX + 16
		railRight := leftRight - 16
		stepGap := (railRight - railLeft) / int32(len(steps)-1)
		line(railLeft, railY, railRight, railY, w.penDivider)
		for index, label := range steps {
			centerX := railLeft + int32(index)*stepGap
			state := "idle"
			if done && success || index+1 < stepActive {
				state = "done"
			} else if index+1 == stepActive {
				state = "active"
			}
			dotBrush := w.brushStepIdle
			dotPen := w.penTrackRim
			labelColor := rgb(105, 139, 159)
			if state == "done" {
				dotBrush = w.brushStepDone
				dotPen = w.penTopRim
				labelColor = rgb(87, 218, 183)
			} else if state == "active" {
				dotBrush = w.brushProgFill
				dotPen = w.penTopRim
				labelColor = rgb(186, 235, 255)
			}
			fillRound(centerX-4, railY-4, centerX+4, railY+4, 4, dotBrush, dotPen)
			text(label, w.fontStep, labelColor, centerX-62, railY+9, centerX+62, railY+24, dtCenter|dtVCenter|dtSingleLine|dtNoPrefix)
		}
	}

	// A quiet trust sidecar. These are product properties, not invented live
	// telemetry, so the installer never claims a state it cannot observe.
	if showSidecar && !hasError {
		textLeft("INSTALLATIONSRAHMEN", w.fontStep, rgb(105, 151, 174), sidecarX, cardY+22, sidecarX+sidecarW, cardY+38)
		facts := [][2]string{
			{"VERSION", "v" + product.Version},
			{"ZIEL", "Windows 11 / 10 x64"},
			{"ENGINES", "Titan + Killerdom 4.1"},
			{"DEFENSE", "Zero-Trust & AMSI Guard"},
		}
		for index, fact := range facts {
			rowY := cardY + 54 + int32(index)*40
			line(sidecarX, rowY+29, sidecarX+sidecarW, rowY+29, w.penDivider)
			textLeft(fact[0], w.fontStep, rgb(91, 133, 154), sidecarX, rowY, sidecarX+sidecarW, rowY+12)
			textLeft(fact[1], w.fontRegular, rgb(212, 235, 247), sidecarX, rowY+12, sidecarX+sidecarW, rowY+29)
		}
		line(sidecarX, cardBottom-36, sidecarX+sidecarW, cardBottom-36, w.penDivider)
		textLeft("VGT RELEASE-KANAL", w.fontStep, rgb(91, 133, 154), sidecarX, cardBottom-28, sidecarX+sidecarW, cardBottom-14)
	}

	// Footer stays visually fixed while the main plane changes state.
	footerTop := height - footerH
	line(0, footerTop, width, height, w.penDivider)
	textLeft("VisionGaia Technology", w.fontStep, rgb(185, 215, 232), 30, footerTop+19, width/2, footerTop+35)
	textLeft("GeDefense Titan · SOVEREIGN INTEGRITY", w.fontSmall, rgb(151, 126, 96), 30, footerTop+35, width/2, footerTop+52)
	text("SIGNIERT · OFFLINE", w.fontSmall, rgb(85, 125, 147), width/2, footerTop+26, width-218, footerTop+44, dtRight|dtVCenter|dtSingleLine|dtNoPrefix)

	btnRc := w.getButtonRect()
	btnHovered := hover && done
	btnBg := w.brushBtnDis
	btnPen := w.penBtnDisRim
	btnTextColor := rgb(104, 136, 151)
	btnLabel := "Installation läuft"
	if done {
		btnBg = w.brushBtnNorm
		btnPen = w.penBtnRim
		btnTextColor = rgb(3, 18, 28)
		if success {
			if isUninstall {
				btnLabel = "Schließen"
			} else {
				btnLabel = "GeDefense öffnen"
			}
		} else {
			btnLabel = "Schließen"
		}
		if pressed {
			btnBg = w.brushBtnPress
		} else if btnHovered {
			btnBg = w.brushBtnHover
		}
	}
	fillRound(btnRc.Left, btnRc.Top, btnRc.Right, btnRc.Bottom, 9, btnBg, btnPen)
	text(btnLabel, w.fontHeader, btnTextColor, btnRc.Left, btnRc.Top, btnRc.Right, btnRc.Bottom, dtCenter|dtVCenter|dtSingleLine|dtNoPrefix)

	if hasError {
		textWrapped(errMessage, w.fontSmall, rgb(255, 178, 190), leftX, cardY+126, leftRight, cardY+160)
	}
}

func readDiagnosticLogTail(path string, maxLines int) (result []string, err error) {
	file, err := openSharedFileForRead(path)
	if err != nil {
		return nil, err
	}
	defer cleanup.CloseInto(&err, file)

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
			errX := int32(50)
			errY := int32(246)
			errW := width - 100
			errH := height - 348
			if errH < 70 {
				errH = 70
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
		programFiles := os.Getenv("ProgramFiles")
		if !filepath.IsAbs(programFiles) {
			return
		}
		centerPath := filepath.Join(filepath.Clean(programFiles), "VGT", "GeDefense", "bin", "GeDefenseCenter.exe")
		if _, err := os.Stat(centerPath); err == nil {
			// The auto-elevated Setup must not start the Center with the
			// administrator token: the Center is an unprivileged UI process.
			if isElevated() {
				if launchErr := userlaunch.LaunchAsShellUser(centerPath, nil); launchErr != nil {
					winapi.ReportError("setup security center launch", launchErr)
				}
				return
			}
			centerPtr, _ := syscall.UTF16PtrFromString(centerPath)
			openPtr, _ := syscall.UTF16PtrFromString("open")
			_, _, _ = procShellExecuteW.Call(0, uintptr(unsafe.Pointer(openPtr)), uintptr(unsafe.Pointer(centerPtr)), 0, 0, 1)
		}
	}
}

func (w *setupWizard) cleanup() {
	for _, font := range []uintptr{w.fontBrand, w.fontTitle, w.fontBadge, w.fontHeader, w.fontHeadline, w.fontMetric, w.fontStep, w.fontRegular, w.fontSmall, w.fontMono} {
		if font != 0 {
			_, _, _ = procDeleteObject.Call(font)
		}
	}

	// Pens
	for _, pen := range []uintptr{w.penTopRim, w.penDivider, w.penCardRim, w.penBadgeRim, w.penTrackRim, w.penBtnRim, w.penBtnDisRim, w.penShield, w.penErrorRim} {
		if pen != 0 {
			_, _, _ = procDeleteObject.Call(pen)
		}
	}

	// Brushes
	for _, b := range []uintptr{w.brushWindowBg, w.brushCardBg, w.brushBadgeBg, w.brushTrackBg, w.brushProgFill, w.brushProgDone, w.brushBtnNorm, w.brushBtnHover, w.brushBtnPress, w.brushBtnDis, w.brushErrorBg, w.brushShieldBg, w.brushGlow, w.brushHeader, w.brushStepIdle, w.brushStepDone} {
		if b != 0 {
			_, _, _ = procDeleteObject.Call(b)
		}
	}
}

func runSetupWizard(uninstall, elevated, preview bool) error {
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
	// Windows' standard shield is a better product anchor than the generic
	// application arrow and is available even when the executable has no
	// embedded resource section.
	icon, _, _ := procLoadIconW.Call(0, uintptr(idcShield))
	classNamePtr, _ := syscall.UTF16PtrFromString("VGTGeDefenseGlassWizardV5")

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

	title := "GeDefense Titan · Setup " + product.Version
	if uninstall {
		title = "GeDefense Titan · Deinstallation"
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

	// GDI Pens. One cold signal, quiet structural hairlines, semantic state only.
	penTopRim, _, _ := procCreatePen.Call(0, 1, rgb(76, 201, 255))
	penDivider, _, _ := procCreatePen.Call(0, 1, rgb(18, 42, 63))
	penCardRim, _, _ := procCreatePen.Call(0, 1, rgb(27, 63, 88))
	penBadgeRim, _, _ := procCreatePen.Call(0, 1, rgb(38, 90, 119))
	penTrackRim, _, _ := procCreatePen.Call(0, 1, rgb(20, 48, 69))
	penBtnRim, _, _ := procCreatePen.Call(0, 1, rgb(155, 238, 255))
	penBtnDisRim, _, _ := procCreatePen.Call(0, 1, rgb(28, 56, 74))
	penShield, _, _ := procCreatePen.Call(0, 2, rgb(76, 201, 255))
	penErrorRim, _, _ := procCreatePen.Call(0, 1, rgb(116, 46, 64))

	// GDI Brushes.
	brushWindowBg, _, _ := procCreateSolidBrush.Call(rgb(3, 8, 17))
	brushCardBg, _, _ := procCreateSolidBrush.Call(rgb(8, 22, 38))
	brushBadgeBg, _, _ := procCreateSolidBrush.Call(rgb(9, 30, 48))
	brushTrackBg, _, _ := procCreateSolidBrush.Call(rgb(4, 14, 25))
	brushProgFill, _, _ := procCreateSolidBrush.Call(rgb(76, 201, 255))
	brushProgDone, _, _ := procCreateSolidBrush.Call(rgb(49, 208, 170))
	brushBtnNorm, _, _ := procCreateSolidBrush.Call(rgb(76, 201, 255))
	brushBtnHover, _, _ := procCreateSolidBrush.Call(rgb(131, 224, 255))
	brushBtnPress, _, _ := procCreateSolidBrush.Call(rgb(42, 160, 208))
	brushBtnDis, _, _ := procCreateSolidBrush.Call(rgb(12, 30, 45))
	brushErrorBg, _, _ := procCreateSolidBrush.Call(rgb(25, 12, 20))
	brushShieldBg, _, _ := procCreateSolidBrush.Call(rgb(11, 39, 59))
	brushGlow, _, _ := procCreateSolidBrush.Call(rgb(7, 24, 41))
	brushHeader, _, _ := procCreateSolidBrush.Call(rgb(4, 15, 27))
	brushStepIdle, _, _ := procCreateSolidBrush.Call(rgb(15, 42, 61))
	brushStepDone, _, _ := procCreateSolidBrush.Call(rgb(49, 208, 170))

	logoPixels, logoW, logoH := decodeInstallerLogo()
	wizard := &setupWizard{
		hwnd:          hwnd,
		uninstall:     uninstall,
		preview:       preview,
		logoPixels:    logoPixels,
		logoW:         logoW,
		logoH:         logoH,
		currentW:      defaultWidth,
		currentH:      defaultHeight,
		cursorArrow:   cursorArrow,
		cursorHand:    cursorHand,
		fontBrand:     createFont("Segoe UI Variable Display", -27, 650),
		fontTitle:     createFont("Segoe UI", -20, 700),
		fontBadge:     createFont("Segoe UI", -10, 700),
		fontHeader:    createFont("Segoe UI", -13, 600),
		fontHeadline:  createFont("Segoe UI Variable Display", -20, 650),
		fontMetric:    createFont("Segoe UI Variable Display", -18, 700),
		fontStep:      createFont("Segoe UI", -9, 600),
		fontRegular:   createFont("Segoe UI", -12, 400),
		fontSmall:     createFont("Segoe UI", -10, 400),
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
		brushGlow:     brushGlow,
		brushHeader:   brushHeader,
		brushStepIdle: brushStepIdle,
		brushStepDone: brushStepDone,
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
	if preview {
		wizard.Update(40, "Administrator-Berechtigungen bestätigt", "Signatur, Payload und Systemvoraussetzungen werden lokal geprüft.")
	} else {
		go func() {
			workerErr = execute(uninstall, elevated, func(percent int, status, detail string) {
				wizard.Update(percent, status, detail)
			})
			wizard.Complete(workerErr)
		}()
	}

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
