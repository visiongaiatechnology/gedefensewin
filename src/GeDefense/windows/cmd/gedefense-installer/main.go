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
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	version           = "2.3.2-vgt.win17"
	maxArchiveFiles   = 512
	maxExtractedBytes = 256 << 20
)

func main() {
	uninstall := flag.Bool("uninstall", false, "remove GeDefense")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		notify("VGT GeDefense", version, windows.MB_ICONINFORMATION)
		return
	}
	if err := execute(*uninstall, isElevated()); err != nil {
		notify("VGT GeDefense", "Operation fehlgeschlagen: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	if *uninstall {
		notify("VGT GeDefense", "GeDefense wurde entfernt. Lokale Evidenzdaten wurden zur forensischen Nachvollziehbarkeit beibehalten.", windows.MB_ICONINFORMATION)
		return
	}
	notify("VGT GeDefense", "Installation erfolgreich. Das Security Center ist jetzt im Startmenü verfügbar.", windows.MB_ICONINFORMATION)
}

func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func execute(uninstall, elevated bool) error {
	stagingParent, err := installerCache(elevated)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stagingParent, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(stagingParent, "setup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	archive, err := installerPayload()
	if err != nil {
		return err
	}
	if err := extractArchive(archive, staging); err != nil {
		return err
	}
	payloadRoot := filepath.Join(staging, "payload")
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if !elevated {
		operation := "Install"
		if uninstall {
			operation = "Uninstall"
		}
		bootstrap := filepath.Join(payloadRoot, "installer", "Bootstrap-GeDefense.ps1")
		return runPowerShell(bootstrap, "-PayloadRoot", payloadRoot, "-Operation", operation, "-InstallerPath", executable)
	}
	scriptName := "Install-GeDefense.ps1"
	if uninstall {
		scriptName = "Uninstall-GeDefense.ps1"
	}
	script := filepath.Join(payloadRoot, "installer", scriptName)
	arguments := []string{"-PayloadRoot", payloadRoot}
	if !uninstall {
		arguments = append(arguments, "-InstallerPath", executable)
	}
	return runPowerShell(script, arguments...)
}

func installerCache(elevated bool) (string, error) {
	if elevated {
		programData := os.Getenv("ProgramData")
		if programData == "" || !filepath.IsAbs(programData) {
			return "", errors.New("ProgramData ist nicht verfügbar")
		}
		return filepath.Join(programData, "VGT", "InstallerCache"), nil
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil || !filepath.IsAbs(cacheRoot) {
		return "", errors.New("Benutzer-Cache ist nicht verfügbar")
	}
	return filepath.Join(cacheRoot, "VGT", "InstallerCache"), nil
}

func extractArchive(raw []byte, destination string) error {
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
	for _, entry := range reader.File {
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > maxExtractedBytes {
			return errors.New("unsicherer Payload-Eintrag wurde abgelehnt")
		}
		total += entry.UncompressedSize64
		if total > maxExtractedBytes {
			return errors.New("Payload-Größenlimit überschritten")
		}
		cleanName := filepath.Clean(filepath.FromSlash(entry.Name))
		if cleanName == "." || filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
			return errors.New("Payload-Pfad wurde abgelehnt")
		}
		target := filepath.Join(destination, cleanName)
		if !strings.HasPrefix(filepath.Clean(target), root) {
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

func extractFile(entry *zip.File, target string) error {
	source, err := entry.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(destination, io.LimitReader(source, maxExtractedBytes+1))
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func runPowerShell(script string, arguments ...string) error {
	if info, err := os.Lstat(script); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("signiertes Installationsskript fehlt")
	}
	commandArguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}
	commandArguments = append(commandArguments, arguments...)
	command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), commandArguments...)
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
	caption, _ := windows.UTF16PtrFromString(title)
	text, _ := windows.UTF16PtrFromString(message)
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|style)
}
