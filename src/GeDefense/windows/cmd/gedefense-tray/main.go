// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/localhttp"
	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
	"github.com/visiongaiatechnology/gedefense/windows/internal/wintray"
)

func main() {
	showVersion := flag.Bool("version", false, "show version")
	_ = flag.Bool("tray", false, "start in notification-area mode")
	openAtStart := flag.Bool("open", false, "open the security center after tray initialization")
	flag.Parse()
	if *showVersion {
		return
	}
	primary, event, mutex, err := claimInstance()
	if err != nil {
		return
	}
	if !primary {
		_ = winapi.SetEvent(event)
		_ = winapi.CloseHandle(event)
		_ = winapi.CloseHandle(mutex)
		return
	}
	defer winapi.CloseHandle(event)
	defer winapi.CloseHandle(mutex)
	iconPath, err := trayIconPath()
	if err != nil {
		return
	}
	_ = wintray.Run(wintray.Config{
		Title:       "VGT GeDefense",
		Version:     product.Version,
		IconPath:    iconPath,
		Open:        func() { _ = startCenter() },
		Status:      protectionHealthy,
		OpenEvent:   uintptr(event),
		OpenAtStart: *openAtStart,
	})
}

func trayIconPath() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData is unavailable")
	}
	path := filepath.Join(filepath.Clean(programData), "VGT", "Branding", "gedefense.ico")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("GeDefense tray icon unavailable")
	}
	return path, nil
}

func claimInstance() (bool, winapi.Handle, winapi.Handle, error) {
	event, _, err := winapi.CreateEvent(`Local\VGT.GeDefense.Tray.Open.v4`, false, false)
	if err != nil {
		return false, 0, 0, err
	}
	mutex, existed, err := winapi.CreateMutex(`Local\VGT.GeDefense.Tray.Instance.v4`)
	if err != nil {
		_ = winapi.CloseHandle(event)
		return false, 0, 0, err
	}
	return !existed, event, mutex, nil
}

func startCenter() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	center := filepath.Join(filepath.Dir(executable), "GeDefenseCenter.exe")
	info, err := os.Lstat(center)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("GeDefense Center executable unavailable")
	}
	command := exec.Command(center)
	return command.Start()
}

func protectionHealthy() (bool, string) {
	programData := os.Getenv("ProgramData")
	if programData == "" || !filepath.IsAbs(programData) {
		return false, "Status nicht verfügbar"
	}
	rawToken, err := os.ReadFile(filepath.Join(programData, "VGT", "GeDefense", "dashboard.token"))
	if err != nil {
		return false, "Operatorzugriff erforderlich"
	}
	token := strings.TrimSpace(string(rawToken))
	if len(token) != 43 {
		return false, "Status nicht verfügbar"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:17831/api/v1/status", nil)
	if err != nil {
		return false, "Status nicht verfügbar"
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := localhttp.NewClient(8 * time.Second)
	response, err := client.Do(request)
	if err != nil {
		return false, "Dienst nicht erreichbar"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, "Prüfung erforderlich"
	}
	var result struct {
		Protection struct {
			Defender           bool `json:"Defender"`
			DefenderService    bool `json:"DefenderService"`
			RealTimeProtection bool `json:"RealTimeProtection"`
			CloudProtection    bool `json:"CloudProtection"`
			NetworkProtection  bool `json:"NetworkProtection"`
			Firewall           bool `json:"Firewall"`
			WindowsUpdate      bool `json:"WindowsUpdate"`
		} `json:"protection"`
		MHX struct {
			Realtime         bool   `json:"realtime"`
			ProtectionMode   string `json:"protectionMode"`
			ProtectionHealth string `json:"protectionHealth"`
		} `json:"mhx"`
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return false, "Status nicht verfügbar"
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, "Status nicht verfügbar"
	}
	p := result.Protection
	coreHealthy := p.Defender && p.DefenderService && p.RealTimeProtection && p.CloudProtection && p.NetworkProtection && p.Firewall && p.WindowsUpdate && result.MHX.Realtime && result.MHX.ProtectionHealth == "VERIFIED"
	if coreHealthy && result.MHX.ProtectionMode == "sovereign" {
		return true, "Sovereign aktiv"
	}
	if coreHealthy && result.MHX.ProtectionMode == "guarded" {
		return true, "Guarded aktiv"
	}
	if result.MHX.ProtectionMode == "monitor" {
		return false, "Nur Überwachung"
	}
	if coreHealthy {
		return true, "Schutz aktiv"
	}
	return false, "Prüfung erforderlich"
}
