// STATUS: DIAMANT VGT SUPREME
//go:build windows

package main

import (
	"bufio"
	"fmt"
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
	wmClose          = 0x0010
	wmSetFont        = 0x0030
	wmCommand        = 0x0111
	wmCtlColorStatic = 0x0138
	wmApp            = 0x8000
	wmSetupUpdate    = wmApp + 101
	wmSetupComplete  = wmApp + 102

	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsClipChildren = 0x02000000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsDisabled     = 0x08000000
	wsTabStop      = 0x00010000

	ssLeft       = 0x00000000
	ssRight      = 0x00000002
	ssEtchedHorz = 0x00000010
	ssNoPrefix   = 0x00000080

	bsDefPushButton = 0x00000001
	pbsSmooth       = 0x00000001

	pbmSetRange32 = 0x0406
	pbmSetPos     = 0x0402

	colorBtnFace = 15

	idActionButton = 201

	wizardWidth  = 540
	wizardHeight = 380
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

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
	procEnableWindow                  = user32.NewProc("EnableWindow")
	procGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	procLoadCursorW                   = user32.NewProc("LoadCursorW")
	procLoadIconW                     = user32.NewProc("LoadIconW")
	procGetSysColorBrush              = user32.NewProc("GetSysColorBrush")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")

	procCreateFontW  = gdi32.NewProc("CreateFontW")
	procDeleteObject = gdi32.NewProc("DeleteObject")
	procSetBkMode    = gdi32.NewProc("SetBkMode")

	procInitCommonControlsEx = comctl32.NewProc("InitCommonControlsEx")
	procShellExecuteW        = shell32.NewProc("ShellExecuteW")

	setupCallback = syscall.NewCallback(setupWindowProc)

	activeWizardMu sync.Mutex
	activeWizard   *setupWizard
)

type point struct{ X, Y int32 }

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
	hwndTitle    uintptr
	hwndSubtitle uintptr
	hwndStatus   uintptr
	hwndDetail   uintptr
	hwndProgress uintptr
	hwndPercent  uintptr
	hwndButton   uintptr

	fontTitle   uintptr
	fontHeader  uintptr
	fontRegular uintptr
	fontSmall   uintptr

	mu         sync.Mutex
	percent    int
	statusText string
	detailText string
	completed  bool
	success    bool
	errMessage string
	uninstall  bool
}

func initCommonControls() {
	icce := initCommonControlsEx{
		Size: uint32(unsafe.Sizeof(initCommonControlsEx{})),
		ICC:  0x00000020 | 0x00004000, // ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES
	}
	_, _, _ = procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icce)))
}

func setDPIAwareness() {
	if procSetProcessDpiAwarenessContext.Find() == nil {
		// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
		_, _, _ = procSetProcessDpiAwarenessContext.Call(^uintptr(3))
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
		1, // DEFAULT_CHARSET
		0, 0,
		5, // CLEARTYPE_QUALITY
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
	case wmSetupUpdate:
		if w != nil {
			w.handleUpdate()
		}
		return 0

	case wmSetupComplete:
		if w != nil {
			w.handleComplete()
		}
		return 0

	case wmCommand:
		ctrlID := uint16(wParam & 0xFFFF)
		if ctrlID == idActionButton {
			if w != nil && w.isDone() {
				w.onActionClicked()
				_, _, _ = procDestroyWindow.Call(hwnd)
			}
			return 0
		}

	case wmCtlColorStatic:
		hdc := wParam
		_, _, _ = procSetBkMode.Call(hdc, 1) // TRANSPARENT
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

func (w *setupWizard) handleUpdate() {
	w.mu.Lock()
	percent := w.percent
	status := w.statusText
	detail := w.detailText
	w.mu.Unlock()

	if w.hwndProgress != 0 {
		_, _, _ = procSendMessageW.Call(w.hwndProgress, pbmSetPos, uintptr(percent), 0)
	}
	if w.hwndStatus != 0 {
		ptr, _ := syscall.UTF16PtrFromString(status)
		_, _, _ = procSetWindowTextW.Call(w.hwndStatus, uintptr(unsafe.Pointer(ptr)))
	}
	if w.hwndDetail != 0 {
		ptr, _ := syscall.UTF16PtrFromString(detail)
		_, _, _ = procSetWindowTextW.Call(w.hwndDetail, uintptr(unsafe.Pointer(ptr)))
	}
	if w.hwndPercent != 0 {
		pctText := fmt.Sprintf("%d%%", percent)
		ptr, _ := syscall.UTF16PtrFromString(pctText)
		_, _, _ = procSetWindowTextW.Call(w.hwndPercent, uintptr(unsafe.Pointer(ptr)))
	}
}

func (w *setupWizard) handleComplete() {
	w.mu.Lock()
	success := w.success
	errMsg := w.errMessage
	isUninstall := w.uninstall
	w.mu.Unlock()

	if success {
		if w.hwndProgress != 0 {
			_, _, _ = procSendMessageW.Call(w.hwndProgress, pbmSetPos, 100, 0)
		}
		if w.hwndPercent != 0 {
			ptr, _ := syscall.UTF16PtrFromString("100%")
			_, _, _ = procSetWindowTextW.Call(w.hwndPercent, uintptr(unsafe.Pointer(ptr)))
		}
		if isUninstall {
			stPtr, _ := syscall.UTF16PtrFromString("Deinstallation erfolgreich abgeschlossen")
			_, _, _ = procSetWindowTextW.Call(w.hwndStatus, uintptr(unsafe.Pointer(stPtr)))
			dtPtr, _ := syscall.UTF16PtrFromString("GeDefense wurde sicher vom System entfernt.")
			_, _, _ = procSetWindowTextW.Call(w.hwndDetail, uintptr(unsafe.Pointer(dtPtr)))
			btnPtr, _ := syscall.UTF16PtrFromString("Schließen")
			_, _, _ = procSetWindowTextW.Call(w.hwndButton, uintptr(unsafe.Pointer(btnPtr)))
		} else {
			stPtr, _ := syscall.UTF16PtrFromString("Installation erfolgreich!")
			_, _, _ = procSetWindowTextW.Call(w.hwndStatus, uintptr(unsafe.Pointer(stPtr)))
			dtPtr, _ := syscall.UTF16PtrFromString("Das Security Center ist einsatzbereit und im Startmenü registriert.")
			_, _, _ = procSetWindowTextW.Call(w.hwndDetail, uintptr(unsafe.Pointer(dtPtr)))
			btnPtr, _ := syscall.UTF16PtrFromString("Fertigstellen")
			_, _, _ = procSetWindowTextW.Call(w.hwndButton, uintptr(unsafe.Pointer(btnPtr)))
		}
	} else {
		stPtr, _ := syscall.UTF16PtrFromString("Installation fehlgeschlagen")
		_, _, _ = procSetWindowTextW.Call(w.hwndStatus, uintptr(unsafe.Pointer(stPtr)))
		displayErr := errMsg
		if len(displayErr) > 280 {
			displayErr = displayErr[:280] + "..."
		}
		dtPtr, _ := syscall.UTF16PtrFromString(displayErr)
		_, _, _ = procSetWindowTextW.Call(w.hwndDetail, uintptr(unsafe.Pointer(dtPtr)))
		btnPtr, _ := syscall.UTF16PtrFromString("Schließen")
		_, _, _ = procSetWindowTextW.Call(w.hwndButton, uintptr(unsafe.Pointer(btnPtr)))
	}

	if w.hwndButton != 0 {
		_, _, _ = procEnableWindow.Call(w.hwndButton, 1)
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
	if w.fontHeader != 0 {
		_, _, _ = procDeleteObject.Call(w.fontHeader)
	}
	if w.fontRegular != 0 {
		_, _, _ = procDeleteObject.Call(w.fontRegular)
	}
	if w.fontSmall != 0 {
		_, _, _ = procDeleteObject.Call(w.fontSmall)
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

	cursor, _, _ := procLoadCursorW.Call(0, uintptr(32512)) // IDC_ARROW
	icon, _, _ := procLoadIconW.Call(0, uintptr(32512))     // IDI_APPLICATION
	classNamePtr, _ := syscall.UTF16PtrFromString("VGTGeDefenseSetupWizardV4")

	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		Style:      0x0003, // CS_HREDRAW | CS_VREDRAW
		WndProc:    setupCallback,
		Instance:   instance,
		Icon:       icon,
		Cursor:     cursor,
		Background: uintptr(colorBtnFace + 1),
		ClassName:  classNamePtr,
		IconSmall:  icon,
	}

	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 && regErr != syscall.Errno(1410) { // 1410 = ERROR_CLASS_ALREADY_EXISTS
		return fmt.Errorf("RegisterClassExW failed: %w", regErr)
	}

	screenWidth, _, _ := procGetSystemMetrics.Call(0)
	screenHeight, _, _ := procGetSystemMetrics.Call(1)
	x := (int32(screenWidth) - wizardWidth) / 2
	y := (int32(screenHeight) - wizardHeight) / 2
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
		wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox|wsClipChildren,
		uintptr(x),
		uintptr(y),
		uintptr(wizardWidth),
		uintptr(wizardHeight),
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %w", createErr)
	}

	wizard := &setupWizard{
		hwnd:        hwnd,
		uninstall:   uninstall,
		fontTitle:   createFont("Segoe UI", -20, 700),
		fontHeader:  createFont("Segoe UI", -14, 600),
		fontRegular: createFont("Segoe UI", -12, 400),
		fontSmall:   createFont("Segoe UI", -11, 400),
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

	staticClass, _ := syscall.UTF16PtrFromString("STATIC")
	buttonClass, _ := syscall.UTF16PtrFromString("BUTTON")
	progressClass, _ := syscall.UTF16PtrFromString("msctls_progress32")

	// Header Banner: Title
	headerText := "VGT GeDefense 4.1 Setup Wizard"
	subText := "Sovereign Endpoint Protection — DIAMANT VGT SUPREME"
	if uninstall {
		headerText = "VGT GeDefense Deinstallation"
		subText = "Entfernen von VGT GeDefense Security Center"
	}
	headerPtr, _ := syscall.UTF16PtrFromString(headerText)
	subPtr, _ := syscall.UTF16PtrFromString(subText)

	hTitle, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(headerPtr)),
		wsChild|wsVisible|ssLeft|ssNoPrefix,
		24, 18, 490, 26,
		hwnd, 101, instance, 0,
	)
	wizard.hwndTitle = hTitle
	if wizard.fontTitle != 0 && hTitle != 0 {
		_, _, _ = procSendMessageW.Call(hTitle, wmSetFont, wizard.fontTitle, 1)
	}

	hSub, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(subPtr)),
		wsChild|wsVisible|ssLeft|ssNoPrefix,
		24, 46, 490, 20,
		hwnd, 102, instance, 0,
	)
	wizard.hwndSubtitle = hSub
	if wizard.fontRegular != 0 && hSub != 0 {
		_, _, _ = procSendMessageW.Call(hSub, wmSetFont, wizard.fontRegular, 1)
	}

	// Separator 1
	emptyPtr, _ := syscall.UTF16PtrFromString("")
	_, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(emptyPtr)),
		wsChild|wsVisible|ssEtchedHorz,
		0, 72, uintptr(wizardWidth), 2,
		hwnd, 103, instance, 0,
	)

	// Status headline
	initStatus := "Vorbereitung..."
	if uninstall {
		initStatus = "Deinstallation wird vorbereitet..."
	}
	initStatusPtr, _ := syscall.UTF16PtrFromString(initStatus)
	hStatus, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(initStatusPtr)),
		wsChild|wsVisible|ssLeft|ssNoPrefix,
		28, 96, 480, 22,
		hwnd, 104, instance, 0,
	)
	wizard.hwndStatus = hStatus
	if wizard.fontHeader != 0 && hStatus != 0 {
		_, _, _ = procSendMessageW.Call(hStatus, wmSetFont, wizard.fontHeader, 1)
	}

	// Detail ticker
	initDetail := "Systemumgebung wird initialisiert..."
	initDetailPtr, _ := syscall.UTF16PtrFromString(initDetail)
	hDetail, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(initDetailPtr)),
		wsChild|wsVisible|ssLeft|ssNoPrefix,
		28, 122, 480, 38,
		hwnd, 105, instance, 0,
	)
	wizard.hwndDetail = hDetail
	if wizard.fontRegular != 0 && hDetail != 0 {
		_, _, _ = procSendMessageW.Call(hDetail, wmSetFont, wizard.fontRegular, 1)
	}

	// Progress bar
	hProgress, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(progressClass)), uintptr(unsafe.Pointer(emptyPtr)),
		wsChild|wsVisible|pbsSmooth,
		28, 168, 472, 24,
		hwnd, 106, instance, 0,
	)
	wizard.hwndProgress = hProgress
	if hProgress != 0 {
		_, _, _ = procSendMessageW.Call(hProgress, pbmSetRange32, 0, 100)
		_, _, _ = procSendMessageW.Call(hProgress, pbmSetPos, 0, 0)
	}

	// Percentage label
	pctZeroPtr, _ := syscall.UTF16PtrFromString("0%")
	hPct, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(pctZeroPtr)),
		wsChild|wsVisible|ssRight|ssNoPrefix,
		28, 198, 472, 18,
		hwnd, 107, instance, 0,
	)
	wizard.hwndPercent = hPct
	if wizard.fontRegular != 0 && hPct != 0 {
		_, _, _ = procSendMessageW.Call(hPct, wmSetFont, wizard.fontRegular, 1)
	}

	// Separator 2
	_, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(emptyPtr)),
		wsChild|wsVisible|ssEtchedHorz,
		0, 270, uintptr(wizardWidth), 2,
		hwnd, 108, instance, 0,
	)

	// Brand footer
	brandText := "VisionGaia Technology © 2026 | DIAMANT VGT SUPREME"
	brandPtr, _ := syscall.UTF16PtrFromString(brandText)
	hBrand, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(brandPtr)),
		wsChild|wsVisible|ssLeft|ssNoPrefix,
		28, 290, 340, 20,
		hwnd, 109, instance, 0,
	)
	if wizard.fontSmall != 0 && hBrand != 0 {
		_, _, _ = procSendMessageW.Call(hBrand, wmSetFont, wizard.fontSmall, 1)
	}

	// Action button
	btnWaitText := "Bitte warten..."
	btnWaitPtr, _ := syscall.UTF16PtrFromString(btnWaitText)
	hButton, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(buttonClass)), uintptr(unsafe.Pointer(btnWaitPtr)),
		wsChild|wsVisible|wsTabStop|bsDefPushButton|wsDisabled,
		390, 284, 110, 32,
		hwnd, idActionButton, instance, 0,
	)
	wizard.hwndButton = hButton
	if wizard.fontRegular != 0 && hButton != 0 {
		_, _, _ = procSendMessageW.Call(hButton, wmSetFont, wizard.fontRegular, 1)
	}

	// Show and update window
	_, _, _ = procShowWindow.Call(hwnd, 5) // SW_SHOW = 5
	_, _, _ = procUpdateWindow.Call(hwnd)

	// Background worker
	var workerErr error
	go func() {
		workerErr = execute(uninstall, elevated, func(percent int, status, detail string) {
			wizard.Update(percent, status, detail)
		})
		wizard.Complete(workerErr)
	}()

	// Message loop
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

func monitorDiagnosticLog(stop <-chan struct{}, update ProgressCallback) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return
	}
	logPath := filepath.Join(localAppData, "VGT", "InstallerDiagnostics", "latest-transaction.log")
	_ = os.Remove(logPath)

	ticker := time.NewTicker(80 * time.Millisecond)
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
				f, err := os.Open(logPath)
				if err != nil {
					continue
				}
				file = f
				reader = bufio.NewReader(file)
			}

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
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
