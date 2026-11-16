// STATUS: DIAMANT VGT SUPREME
package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/userlaunch"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

const (
	maxArchiveFiles   = 512
	maxExtractedBytes = 256 << 20

	// ShellExecuteExW flags for the elevation relaunch. The elevated child is
	// the same signed executable with --silent and is awaited so the original
	// process can report the transaction result instead of racing it.
	seeMaskNoCloseProcess = 0x00000040
	swHide                = 0
)

var (
	installerShell32    = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteExW = installerShell32.NewProc("ShellExecuteExW")
)

type ProgressCallback func(percent int, status, detail string)

func main() {
	uninstall := flag.Bool("uninstall", false, "remove GeDefense")
	silent := flag.Bool("silent", false, "silent execution without GUI dialogs")
	showVersion := flag.Bool("version", false, "show version")
	preview := flag.Bool("ui-preview", false, "render the installer surface without executing")
	flag.Parse()
	if *showVersion {
		if !*silent {
			notify("VGT GeDefense", product.Version, winapi.MBIconInformation)
		} else {
			fmt.Println(product.Version)
		}
		return
	}
	if *silent {
		if err := execute(*uninstall, isElevated(), nil); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := runSetupWizard(*uninstall, isElevated(), *preview); err != nil {
		os.Exit(1)
	}
}

func isElevated() bool {
	return winapi.IsProcessElevated()
}

func execute(uninstall, elevated bool, progress ProgressCallback) (err error) {
	report := func(percent int, status, detail string) {
		if progress != nil {
			progress(percent, status, detail)
		}
	}

	// FIND-WIN-013: elevation happens before any payload byte is extracted. The
	// previous flow extracted the embedded (and therefore attacker-writable)
	// payload into a per-user cache before UAC and let the elevated transaction
	// trust that user-writable staging path. The unprivileged process now only
	// requests elevation and waits for the elevated instance, which owns the
	// extraction into an Administrator/SYSTEM-only staging directory.
	if !elevated {
		report(5, "Administratorrechte werden angefordert...", "Die Installation wird erhöht fortgesetzt; der Payload wird erst nach der Elevation entpackt.")
		stopTail := make(chan struct{})
		var waitGroup sync.WaitGroup
		if progress != nil && !uninstall {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				monitorDiagnosticLog(stopTail, report)
			}()
		}
		elevatedErr := runElevatedSelf(uninstall)
		close(stopTail)
		waitGroup.Wait()
		if elevatedErr != nil {
			return elevatedErr
		}
		report(100, "Vorgang abgeschlossen", "Alle Komponenten wurden erfolgreich konfiguriert.")
		return nil
	}

	report(5, "Vorbereitung...", "Initialisiere Installer-Cache...")
	if err := enforceNoDowngrade(uninstall); err != nil {
		return err
	}
	staging, err := createInstallerStaging()
	if err != nil {
		return err
	}
	defer cleanup.RemoveTreeInto(&err, staging)

	report(10, "Dateien werden extrahiert...", "Lade eingebettetes Payload-Archiv...")
	archive, err := installerPayload()
	if err != nil {
		return err
	}
	if err := extractArchiveWithProgress(archive, staging, func(current, total int, entryName string) {
		pct := 10 + int(float64(current)/float64(total)*25.0)
		report(pct, "Dateien werden extrahiert...", entryName)
	}); err != nil {
		return err
	}
	payloadRoot := filepath.Join(staging, "payload")
	if _, err := os.Stat(filepath.Join(payloadRoot, "installer", "Bootstrap-GeDefense.ps1")); err != nil {
		if _, errNested := os.Stat(filepath.Join(payloadRoot, "GeDefense", "installer", "Bootstrap-GeDefense.ps1")); errNested == nil {
			payloadRoot = filepath.Join(payloadRoot, "GeDefense")
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	operation := "Install"
	if uninstall {
		operation = "Uninstall"
	}
	bootstrap := filepath.Join(payloadRoot, "installer", "Bootstrap-GeDefense.ps1")

	report(36, "Installationstransaktion wird gestartet...", "Prüfe Systemberechtigungen...")

	stopTail := make(chan struct{})
	var wg sync.WaitGroup
	if progress != nil && !uninstall {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitorDiagnosticLog(stopTail, report)
		}()
	}

	bootstrapErr := runBootstrap(bootstrap, "-PayloadRoot", payloadRoot, "-Operation", operation, "-InstallerPath", executable)
	close(stopTail)
	wg.Wait()

	if bootstrapErr != nil {
		return bootstrapErr
	}

	report(100, "Vorgang abgeschlossen", "Alle Komponenten wurden erfolgreich konfiguriert.")
	if !uninstall {
		startInstalledTray()
	}
	return nil
}

// startInstalledTray is deliberately detached from the installer's stdio. The
// tray is a long-running process; inheriting the setup pipe would keep the
// installer alive after it has already reported success. The Setup EXE is
// auto-elevated by the UAC installer detection, so an elevated installer must
// never spawn the tray directly: the tray is handed to the unprivileged desktop
// shell instead. No tray at all is better than an elevated tray that would later
// start an elevated Center/Chromium (UI-FIND-002 design boundary).
func startInstalledTray() {
	programFiles := os.Getenv("ProgramFiles")
	if !filepath.IsAbs(programFiles) {
		return
	}
	tray := filepath.Join(filepath.Clean(programFiles), "VGT", "GeDefense", "bin", "GeDefenseTray.exe")
	info, err := os.Lstat(tray)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	if isElevated() {
		if launchErr := userlaunch.LaunchAsShellUser(tray, nil); launchErr != nil {
			winapi.ReportError("setup tray launch", launchErr)
		}
		return
	}
	command := exec.Command(tray, "--tray")
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008}
	if err := command.Start(); err != nil {
		return
	}
	_ = command.Process.Release()
}

// installerCache returns the Administrator/SYSTEM-only staging parent. The
// installer always runs elevated before this path is used, so no user cache or
// user temp directory is ever a staging location (FIND-WIN-013).
func installerCache() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData ist nicht verfügbar")
	}
	return filepath.Join(programData, "VGT", "InstallerCache"), nil
}

// createInstallerStaging creates the extraction directory below ProgramData,
// proves that no path component is a reparse point/junction and applies an
// explicit Administrator/SYSTEM-only DACL before the embedded payload is
// extracted.
func createInstallerStaging() (string, error) {
	parent, err := installerCache()
	if err != nil {
		return "", err
	}
	if err := assertNoReparseComponents(parent); err != nil {
		return "", fmt.Errorf("Installations-Staging ist nicht vertrauenswürdig: %w", err)
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("kein beschreibbares Installations-Stagingverzeichnis: %w", err)
	}
	if err := hardenInstallerStagingDirectory(parent); err != nil {
		return "", err
	}
	if err := assertNoReparseComponents(parent); err != nil {
		return "", fmt.Errorf("Installations-Staging wurde während der Erstellung ersetzt: %w", err)
	}
	staging, err := os.MkdirTemp(parent, "setup-")
	if err != nil {
		return "", fmt.Errorf("kein beschreibbares Installations-Stagingverzeichnis: %w", err)
	}
	if err := hardenInstallerStagingDirectory(staging); err != nil {
		_ = os.RemoveAll(staging)
		return "", err
	}
	if err := assertNoReparseComponents(staging); err != nil {
		_ = os.RemoveAll(staging)
		return "", fmt.Errorf("Installations-Staging ist nicht vertrauenswürdig: %w", err)
	}
	return staging, nil
}

// assertNoReparseComponents rejects junctions/symlinks on the staged path and
// every ancestor so an unprivileged user cannot redirect the elevated
// extraction into a directory they control.
func assertNoReparseComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	if volume == "" || !filepath.IsAbs(absolute) {
		return errors.New("Staging-Pfad ist nicht absolut")
	}
	current := volume + string(os.PathSeparator)
	for _, component := range strings.Split(strings.TrimPrefix(absolute, volume), string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
			return fmt.Errorf("Pfadkomponente ist ein Reparse-Point: %s", current)
		}
	}
	return nil
}

// hardenInstallerStagingDirectory applies an inheritance-protected
// SYSTEM/Administrators-only DACL with the System32 icacls.exe (absolute,
// validated path) and fails closed when the native call fails.
func hardenInstallerStagingDirectory(path string) error {
	icacls, err := system32Executable("icacls.exe")
	if err != nil {
		return err
	}
	command := exec.Command(icacls, path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Staging-DACL konnte nicht gesetzt werden: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// system32Executable resolves an absolute, regular System32 executable.
func system32Executable(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `\/:`) {
		return "", errors.New("invalid System32 executable name")
	}
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" || !filepath.IsAbs(root) {
		root = `C:\Windows`
	}
	path := filepath.Join(filepath.Clean(root), "System32", name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("System32-Werkzeug nicht verfügbar: %s", name)
	}
	return path, nil
}

// shellExecuteInfo mirrors SHELLEXECUTEINFOW for ShellExecuteExW. Only the
// documented x64 layout is used (the installer is an x64 binary).
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         syscall.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     syscall.Handle
	lpIDList     unsafe.Pointer
	lpClass      *uint16
	hkeyClass    syscall.Handle
	dwHotKey     uint32
	hIcon        syscall.Handle
	hProcess     syscall.Handle
}

// runElevatedSelf relaunches the signed installer executable with the UAC
// "runas" verb, waits for the elevated transaction and propagates its exit
// code. The elevated instance runs headless (--silent) so the wizard is never
// duplicated, and the original process reports success/failure to the user.
func runElevatedSelf(uninstall bool) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Installationspfad nicht ermittelbar: %w", err)
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Installer-Executable ist keine reguläre Datei")
	}
	verbPointer, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	filePointer, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	parameters := "--silent"
	if uninstall {
		parameters += " --uninstall"
	}
	parameterPointer, err := syscall.UTF16PtrFromString(parameters)
	if err != nil {
		return err
	}
	var infoShell shellExecuteInfo
	infoShell.cbSize = uint32(unsafe.Sizeof(infoShell))
	infoShell.fMask = seeMaskNoCloseProcess
	infoShell.lpVerb = verbPointer
	infoShell.lpFile = filePointer
	infoShell.lpParameters = parameterPointer
	infoShell.nShow = swHide
	result, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&infoShell)))
	if result == 0 {
		var errno syscall.Errno
		if errors.As(callErr, &errno) && errno == 1223 {
			return errors.New("Administratorrechte wurden abgelehnt (UAC abgebrochen)")
		}
		if errno != 0 {
			return fmt.Errorf("erhöhter Installer konnte nicht gestartet werden: Windows-Fehler %d", uint32(errno))
		}
		return errors.New("erhöhter Installer konnte nicht gestartet werden")
	}
	if infoShell.hProcess == 0 {
		return errors.New("erhöhter Installer lieferte kein Prozesshandle")
	}
	defer func() { _ = syscall.CloseHandle(infoShell.hProcess) }()
	waitResult, waitErr := syscall.WaitForSingleObject(infoShell.hProcess, syscall.INFINITE)
	if waitErr != nil || waitResult != syscall.WAIT_OBJECT_0 {
		return errors.New("erhöhter Installer konnte nicht abgeschlossen werden")
	}
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(infoShell.hProcess, &exitCode); err != nil {
		return fmt.Errorf("Exitcode des erhöhten Installers nicht lesbar: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("erhöhte Installationstransaktion wurde mit Exitcode %d beendet", exitCode)
	}
	return nil
}

func extractArchive(raw []byte, destination string) error {
	return extractArchiveWithProgress(raw, destination, nil)
}

func extractArchiveWithProgress(raw []byte, destination string, onEntry func(current, total int, entryName string)) error {
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return errors.New("eingebettetes Payload-Archiv ist ungültig")
	}
	if len(reader.File) == 0 || len(reader.File) > maxArchiveFiles {
		return errors.New("Payload-Dateianzahl wurde abgelehnt")
	}
	root := filepath.Clean(destination) + string(os.PathSeparator)
	var total uint64
	seen := make(map[string]struct{}, len(reader.File))
	totalFiles := len(reader.File)
	for index, entry := range reader.File {
		if onEntry != nil {
			onEntry(index+1, totalFiles, entry.Name)
		}
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > maxExtractedBytes {
			return errors.New("unsicherer Payload-Eintrag wurde abgelehnt")
		}
		total += entry.UncompressedSize64
		if total > maxExtractedBytes {
			return errors.New("Payload-Größenlimit überschritten")
		}
		cleanName, err := safeArchiveRelativePath(entry.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, cleanName)
		cleanTarget := filepath.Clean(target)
		if !strings.HasPrefix(cleanTarget, root) {
			return errors.New("Payload-Pfad hat das Zielverzeichnis verlassen")
		}
		key := strings.ToLower(target)
		if _, exists := seen[key]; exists {
			return errors.New("doppelter Payload-Pfad wurde abgelehnt")
		}
		seen[key] = struct{}{}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := extractFile(entry, target); err != nil {
			return err
		}
	}
	return nil
}

func safeArchiveRelativePath(name string) (string, error) {
	if name == "" || len(name) > 4096 || strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("Payload-Pfad wurde abgelehnt")
	}
	normalized := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(normalized, "/") {
		return "", errors.New("Payload-Pfad wurde abgelehnt")
	}
	parts := strings.Split(normalized, "/")
	cleanParts := make([]string, 0, len(parts))
	for index, part := range parts {
		if part == "" && index == len(parts)-1 {
			continue
		}
		if part == "" || part == "." || part == ".." || len(part) > 255 || strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
			return "", errors.New("Payload-Pfad wurde abgelehnt")
		}
		for _, char := range part {
			if char < 0x20 || strings.ContainsRune(`<>:"|?*`, char) {
				return "", errors.New("Payload-Pfad wurde abgelehnt")
			}
		}
		device := strings.ToUpper(part)
		if dot := strings.IndexByte(device, '.'); dot >= 0 {
			device = device[:dot]
		}
		if device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" ||
			(len(device) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && device[3] >= '1' && device[3] <= '9') {
			return "", errors.New("Payload-Pfad wurde abgelehnt")
		}
		cleanParts = append(cleanParts, part)
	}
	if len(cleanParts) == 0 {
		return "", errors.New("Payload-Pfad wurde abgelehnt")
	}
	cleanName := filepath.Clean(filepath.Join(cleanParts...))
	if cleanName == "." || filepath.IsAbs(cleanName) || filepath.VolumeName(cleanName) != "" || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
		return "", errors.New("Payload-Pfad wurde abgelehnt")
	}
	return cleanName, nil
}

func extractFile(entry *zip.File, target string) (err error) {
	if entry.UncompressedSize64 > maxExtractedBytes {
		return errors.New("Payload-Dateigröße wurde abgelehnt")
	}
	source, err := entry.Open()
	if err != nil {
		return err
	}
	defer cleanup.CloseInto(&err, source)

	destination, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(target)
		}
	}()

	limit := int64(entry.UncompressedSize64) + 1
	written, copyErr := io.Copy(destination, io.LimitReader(source, limit))
	if copyErr == nil && uint64(written) != entry.UncompressedSize64 {
		copyErr = errors.New("Payload-Dateigröße stimmt nicht mit dem Archiv überein")
	}
	if copyErr == nil {
		copyErr = destination.Sync()
	}
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	committed = true
	return nil
}

func runBootstrap(script string, arguments ...string) error {
	if info, err := os.Lstat(script); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("signiertes Installationsskript fehlt")
	}
	commandArguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-File", script}
	commandArguments = append(commandArguments, arguments...)
	powerShell, err := winexec.PowerShell()
	if err != nil {
		return err
	}
	command := exec.Command(powerShell, commandArguments...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 2000 {
			message = message[:2000]
		}
		return fmt.Errorf("Installer-Transaktion fehlgeschlagen: %w: %s", err, message)
	}
	return nil
}

func notify(title, message string, style uint32) {
	_ = winapi.MessageBox(title, message, style)
}
