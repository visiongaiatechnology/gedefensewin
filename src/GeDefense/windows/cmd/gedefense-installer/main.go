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

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

const (
	maxArchiveFiles   = 512
	maxExtractedBytes = 256 << 20
)

func main() {
	uninstall := flag.Bool("uninstall", false, "remove GeDefense")
	silent := flag.Bool("silent", false, "silent execution without GUI dialogs")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		if !*silent {
			notify("VGT GeDefense", product.Version, winapi.MBIconInformation)
		} else {
			fmt.Println(product.Version)
		}
		return
	}
	if err := execute(*uninstall, isElevated()); err != nil {
		if !*silent {
			notify("VGT GeDefense", "Operation fehlgeschlagen: "+err.Error(), winapi.MBIconError)
		}
		os.Exit(1)
	}
	if *uninstall {
		if !*silent {
			notify("VGT GeDefense", "GeDefense wurde entfernt. Lokale Evidenzdaten wurden zur forensischen Nachvollziehbarkeit beibehalten.", winapi.MBIconInformation)
		}
		return
	}
	if !*silent {
		notify("VGT GeDefense", "Installation erfolgreich. Das Security Center ist jetzt im Startmenü verfügbar.", winapi.MBIconInformation)
	}
}

func isElevated() bool {
	return winapi.IsProcessElevated()
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
	return runBootstrap(bootstrap, "-PayloadRoot", payloadRoot, "-Operation", operation, "-InstallerPath", executable)
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
	defer source.Close()

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
